pub mod implement;
#[cfg(test)]
mod tests;

use self::implement::RequestStreamMessage;
use crate::graphql::TIMESTAMP_SIZE;
use crate::ingest::{implement::EventFilter, NetworkKey, PacketSources, StreamDirectChannel};
use crate::server::{
    certificate_info, config_server, extract_cert_from_conn, SERVER_CONNNECTION_DELAY,
    SERVER_ENDPOINT_DELAY,
};
use crate::storage::{
    lower_closed_bound_key, upper_open_bound_key, Database, Direction, RawEventStore,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{TimeZone, Utc};
use giganto_client::{
    connection::server_handshake,
    frame,
    publish::{
        pcap_extract_request,
        range::{MessageCode, REconvergeKindType, RequestRange, RequestRawData, ResponseRangeData},
        receive_range_data_request, receive_stream_request, send_err,
        send_hog_stream_start_message, send_ok, send_range_data, send_raw_events,
        stream::{NodeType, RequestCrusherStream, RequestHogStream, RequestStreamRecord},
        PcapFilter,
    },
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use serde::{de::DeserializeOwned, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    select,
    sync::{mpsc::unbounded_channel, Notify},
    time::sleep,
};
use tracing::{debug, error, info};

const PUBLISH_VERSION_REQ: &str = ">=0.12.0,<0.13.0";

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

impl Server {
    pub fn new(
        addr: SocketAddr,
        certs: Vec<Certificate>,
        key: PrivateKey,
        files: Vec<Vec<u8>>,
    ) -> Self {
        let server_config = config_server(certs, key, files)
            .expect("server configuration error with cert, key or root");
        Server {
            server_config,
            server_address: addr,
        }
    }

    pub async fn run(
        self,
        db: Database,
        packet_sources: PacketSources,
        stream_direct_channel: StreamDirectChannel,
        wait_shutdown: Arc<Notify>,
    ) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        info!(
            "listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        loop {
            select! {
                Some(conn) = endpoint.accept()  => {
                    let db = db.clone();
                    let packet_sources = packet_sources.clone();
                    let stream_direct_channel = stream_direct_channel.clone();
                    let shutdown_notify = wait_shutdown.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            conn,
                            db,
                            packet_sources,
                            stream_direct_channel,
                            shutdown_notify
                        )
                        .await
                        {
                            error!("connection failed: {}", e);
                        }
                    });
                },
                _ = wait_shutdown.notified() => {
                    sleep(Duration::from_millis(SERVER_ENDPOINT_DELAY)).await;      // Wait time for channels,connection to be ready for shutdown.
                    endpoint.close(0_u32.into(), &[]);
                    info!("Shutting down publish");
                    break;
                },
            }
        }
    }
}

async fn handle_connection(
    conn: quinn::Connecting,
    db: Database,
    packet_sources: PacketSources,
    stream_direct_channel: StreamDirectChannel,
    wait_shutdown: Arc<Notify>,
) -> Result<()> {
    let connection = conn.await?;

    let (send, recv) = match server_handshake(&connection, PUBLISH_VERSION_REQ).await {
        Ok((send, recv)) => {
            info!("Compatible version");
            (send, recv)
        }
        Err(e) => {
            info!("Incompatible version");
            connection.close(quinn::VarInt::from_u32(0), e.to_string().as_bytes());
            bail!("{e}")
        }
    };
    let (_, source) = certificate_info(&extract_cert_from_conn(&connection)?)?;
    tokio::spawn(request_stream(
        connection.clone(),
        db.clone(),
        send,
        recv,
        source,
        packet_sources.clone(),
        stream_direct_channel.clone(),
    ));

    loop {
        select! {
            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                    Ok(s) => s,
                };

                let db = db.clone();
                let packet_sources = packet_sources.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(stream, db, packet_sources).await {
                        error!("failed: {}", e);
                    }
                });
            },
            _ = wait_shutdown.notified() => {
                // Wait time for channels to be ready for shutdown.
                sleep(Duration::from_millis(SERVER_CONNNECTION_DELAY)).await;
                connection.close(0_u32.into(), &[]);
                return Ok(())
            },
        }
    }
}

async fn request_stream(
    connection: Connection,
    stream_db: Database,
    mut send: SendStream,
    mut recv: RecvStream,
    conn_source: String,
    packet_sources: PacketSources,
    stream_direct_channel: StreamDirectChannel,
) -> Result<()> {
    loop {
        match receive_stream_request(&mut recv).await {
            Ok((node_type, record_type, raw_data)) => {
                let db = stream_db.clone();
                let conn = connection.clone();
                let source = conn_source.clone();
                let stream_direct_channel = stream_direct_channel.clone();
                if record_type == RequestStreamRecord::Pcap {
                    process_pcap_extract(&raw_data, packet_sources.clone(), &mut send).await?;
                } else {
                    tokio::spawn(async move {
                        match node_type {
                            NodeType::Hog => {
                                match bincode::deserialize::<RequestHogStream>(&raw_data) {
                                    Ok(msg) => {
                                        if let Err(e) = process_stream(
                                            db,
                                            conn,
                                            Some(source),
                                            node_type,
                                            record_type,
                                            msg,
                                            stream_direct_channel,
                                        )
                                        .await
                                        {
                                            error!("{}", e);
                                        }
                                    }
                                    Err(_) => {
                                        error!("Failed to deserialize hog message");
                                    }
                                }
                            }
                            NodeType::Crusher => {
                                match bincode::deserialize::<RequestCrusherStream>(&raw_data) {
                                    Ok(msg) => {
                                        if let Err(e) = process_stream(
                                            db,
                                            conn,
                                            None,
                                            node_type,
                                            record_type,
                                            msg,
                                            stream_direct_channel,
                                        )
                                        .await
                                        {
                                            error!("{}", e);
                                        }
                                    }
                                    Err(_) => {
                                        error!("Failed to deserialize crusher message");
                                    }
                                }
                            }
                        }
                    });
                }
            }
            Err(e) => {
                error!("{}", e);
                break;
            }
        }
    }
    Ok(())
}

async fn process_pcap_extract(
    filter_data: &[u8],
    packet_sources: PacketSources,
    resp_send: &mut SendStream,
) -> Result<()> {
    let mut buf = Vec::new();
    let filters = match bincode::deserialize::<Vec<PcapFilter>>(filter_data) {
        Ok(filters) => {
            send_ok(resp_send, &mut buf, ())
                .await
                .context("Failed to send ok")?;
            filters
        }
        Err(e) => {
            send_err(resp_send, &mut buf, e)
                .await
                .context("Failed to send err")?;
            bail!("Failed to deserialize Pcapfilters")
        }
    };

    tokio::spawn(async move {
        for filter in filters {
            if let Some(source_conn) = packet_sources.read().await.get(&filter.source) {
                // send/receive extract request from piglet
                match pcap_extract_request(source_conn, &filter).await {
                    Ok(_) => (),
                    Err(e) => debug!("failed to relay pcap request, {e}"),
                }
            } else {
                error!("Failed to get {}'s connection", filter.source);
            }
        }
    });
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn process_stream<T>(
    db: Database,
    conn: Connection,
    source: Option<String>,
    node_type: NodeType,
    record_type: RequestStreamRecord,
    request_msg: T,
    stream_direct_channel: StreamDirectChannel,
) -> Result<()>
where
    T: RequestStreamMessage,
{
    match record_type {
        RequestStreamRecord::Conn => {
            if let Ok(store) = db.conn_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open conn store");
            }
        }
        RequestStreamRecord::Dns => {
            if let Ok(store) = db.dns_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open dns store");
            }
        }
        RequestStreamRecord::Rdp => {
            if let Ok(store) = db.rdp_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open rdp store");
            }
        }
        RequestStreamRecord::Http => {
            if let Ok(store) = db.http_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open http store");
            }
        }
        RequestStreamRecord::Log => {
            if let Ok(store) = db.log_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open log store");
            }
        }
        RequestStreamRecord::Smtp => {
            if let Ok(store) = db.smtp_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open smtp store");
            }
        }
        RequestStreamRecord::Ntlm => {
            if let Ok(store) = db.ntlm_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open ntlm store");
            }
        }
        RequestStreamRecord::Kerberos => {
            if let Ok(store) = db.kerberos_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open kerberos store");
            }
        }
        RequestStreamRecord::Ssh => {
            if let Ok(store) = db.ssh_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open ssh store");
            }
        }
        RequestStreamRecord::DceRpc => {
            if let Ok(store) = db.dce_rpc_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open dce rpc store");
            }
        }
        RequestStreamRecord::Ftp => {
            if let Ok(store) = db.ftp_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open ftp store");
            }
        }
        RequestStreamRecord::Mqtt => {
            if let Ok(store) = db.mqtt_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open mqtt store");
            }
        }
        RequestStreamRecord::Ldap => {
            if let Ok(store) = db.ldap_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open ldap store");
            }
        }
        RequestStreamRecord::Tls => {
            if let Ok(store) = db.tls_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open tls store");
            }
        }
        RequestStreamRecord::Smb => {
            if let Ok(store) = db.smb_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open smb store");
            }
        }
        RequestStreamRecord::Nfs => {
            if let Ok(store) = db.nfs_store() {
                if let Err(e) = send_stream(
                    store,
                    conn,
                    record_type,
                    request_msg,
                    source,
                    node_type,
                    stream_direct_channel,
                )
                .await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open nfs store");
            }
        }
        RequestStreamRecord::Pcap => {}
    };
    Ok(())
}

pub async fn send_direct_stream(
    network_key: &NetworkKey,
    raw_event: &[u8],
    timestamp: i64,
    source: &str,
    stream_direct_channel: StreamDirectChannel,
) -> Result<()> {
    for (req_key, sender) in stream_direct_channel.read().await.iter() {
        if req_key.contains(&network_key.source_key) || req_key.contains(&network_key.all_key) {
            let raw_len = u32::try_from(raw_event.len())?.to_le_bytes();
            let mut send_buf: Vec<u8> = Vec::new();
            send_buf.extend_from_slice(&timestamp.to_le_bytes());

            if req_key.contains(NodeType::Hog.convert_to_str()) {
                let source_bytes = bincode::serialize(&source)?;
                let source_len = u32::try_from(source_bytes.len())?.to_le_bytes();
                send_buf.extend_from_slice(&source_len);
                send_buf.extend_from_slice(&source_bytes);
            }

            send_buf.extend_from_slice(&raw_len);
            send_buf.extend_from_slice(raw_event);
            sender.send(send_buf)?;
        }
    }
    Ok(())
}

async fn send_stream<T, N>(
    store: RawEventStore<'_, T>,
    conn: Connection,
    record_type: RequestStreamRecord,
    msg: N,
    source: Option<String>,
    node_type: NodeType,
    stream_direct_channel: StreamDirectChannel,
) -> Result<()>
where
    T: EventFilter + Serialize + DeserializeOwned,
    N: RequestStreamMessage,
{
    let mut sender = conn.open_uni().await?;
    let channel_keys = msg.channel_key(source, record_type.convert_to_str())?;

    let (send, mut recv) = unbounded_channel::<Vec<u8>>();
    let channel_remove_keys = channel_keys.clone();
    for c_key in channel_keys {
        stream_direct_channel
            .write()
            .await
            .insert(c_key, send.clone());
    }

    let mut last_ts = 0_i64;

    // send stored record raw data
    match node_type {
        NodeType::Hog => {
            send_hog_stream_start_message(&mut sender, record_type)
                .await
                .map_err(|e| anyhow!("Failed to write hog start message: {}", e))?;
            info!("start hog's publish Stream : {:?}", record_type);
        }
        NodeType::Crusher => {
            let db_key_prefix = msg.database_key()?;
            // crusher's policy Id always exists.
            let id = msg.source_id().unwrap();
            send_crusher_stream_start_message(&mut sender, id)
                .await
                .map_err(|e| anyhow!("Failed to write crusher start message: {}", e))?;
            info!("start crusher's publish Stream : {:?}", record_type);

            let iter = store.boundary_iter(
                &lower_closed_bound_key(
                    &db_key_prefix,
                    Some(Utc.timestamp_nanos(msg.start_time())),
                ),
                &upper_open_bound_key(&db_key_prefix, None),
                Direction::Forward,
            );

            for item in iter {
                let (key, val) = item.context("Failed to read Database")?;
                let (Some(orig_addr), Some(resp_addr)) = (val.orig_addr(), val.resp_addr()) else {
                    bail!("Failed to deserialize database data");
                };
                if msg.filter_ip(orig_addr, resp_addr) {
                    let timestamp =
                        i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
                    send_crusher_data(&mut sender, timestamp, val).await?;
                    last_ts = timestamp;
                }
            }
        }
    }

    // send realtime record raw data
    tokio::spawn(async move {
        loop {
            select! {
                Some(buf) = recv.recv() => {
                    let ts = i64::from_le_bytes(buf.get(..TIMESTAMP_SIZE).expect("timestamp_size").try_into().expect("timestamp"));
                    if last_ts > ts {
                        continue;
                    }
                    if frame::send_bytes(&mut sender, &buf).await.is_err(){
                        for r_key in channel_remove_keys{
                            stream_direct_channel
                            .write()
                            .await
                            .remove(&r_key);
                        }
                        break;
                    }
                }
                else => break,
            }
        }
    });
    Ok(())
}

/// Sends the crusher stream start message from giganto's publish module.
///
/// # Errors
///
/// Returns an error if the message could not be sent.
async fn send_crusher_stream_start_message(send: &mut SendStream, start_msg: String) -> Result<()> {
    frame::send_raw(send, start_msg.as_bytes()).await?;
    Ok(())
}

/// Sends the record data. (timestamp /record structure)
///
/// # Errors
///
/// Returns an error if the message could not be sent.
async fn send_crusher_data<T>(send: &mut SendStream, timestamp: i64, record_data: T) -> Result<()>
where
    T: Serialize,
{
    frame::send_bytes(send, &timestamp.to_le_bytes()).await?;
    let mut buf = Vec::new();
    frame::send(send, &mut buf, record_data).await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn handle_request(
    (mut send, mut recv): (SendStream, RecvStream),
    db: Database,
    packet_sources: PacketSources,
) -> Result<()> {
    let (msg_type, msg_buf) = receive_range_data_request(&mut recv).await?;
    match msg_type {
        MessageCode::ReqRange => {
            let msg = bincode::deserialize::<RequestRange>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deseralize message: {}", e))?;
            match REconvergeKindType::convert_type(&msg.kind) {
                REconvergeKindType::Conn => {
                    process_range_data(
                        &mut send,
                        db.conn_store().context("Failed to open conn store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Dns => {
                    process_range_data(
                        &mut send,
                        db.dns_store().context("Failed to open dns store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Rdp => {
                    process_range_data(
                        &mut send,
                        db.rdp_store().context("Failed to open rdp store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Http => {
                    process_range_data(
                        &mut send,
                        db.http_store().context("Failed to open http store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Smtp => {
                    process_range_data(
                        &mut send,
                        db.smtp_store().context("Failed to open smtp store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Log => {
                    process_range_data(
                        &mut send,
                        db.log_store().context("Failed to open log store")?,
                        msg,
                        true,
                    )
                    .await?;
                }
                REconvergeKindType::Ntlm => {
                    process_range_data(
                        &mut send,
                        db.ntlm_store().context("Failed to open ntlm store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Kerberos => {
                    process_range_data(
                        &mut send,
                        db.kerberos_store()
                            .context("Failed to open kerberos store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Ssh => {
                    process_range_data(
                        &mut send,
                        db.ssh_store().context("Failed to open ssh store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::DceRpc => {
                    process_range_data(
                        &mut send,
                        db.dce_rpc_store().context("Failed to open dce rpc store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Ftp => {
                    process_range_data(
                        &mut send,
                        db.ftp_store().context("Failed to open ftp store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Mqtt => {
                    process_range_data(
                        &mut send,
                        db.mqtt_store().context("Failed to open mqtt store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Timeseries => {
                    process_range_data(
                        &mut send,
                        db.periodic_time_series_store()
                            .context("Failed to open periodic time series storage")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Ldap => {
                    process_range_data(
                        &mut send,
                        db.ldap_store().context("Failed to open ldap store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Tls => {
                    process_range_data(
                        &mut send,
                        db.tls_store().context("Failed to open tls store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Smb => {
                    process_range_data(
                        &mut send,
                        db.smb_store().context("Failed to open smb store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Nfs => {
                    process_range_data(
                        &mut send,
                        db.nfs_store().context("Failed to open nfs store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
            }
        }
        MessageCode::Pcap => {
            process_pcap_extract(&msg_buf, packet_sources.clone(), &mut send).await?;
        }
        MessageCode::RawData => {
            let msg = bincode::deserialize::<RequestRawData>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deseralize message: {}", e))?;
            match REconvergeKindType::convert_type(&msg.kind) {
                REconvergeKindType::Conn => {
                    process_raw_events(&mut send, db.conn_store()?, msg.input).await?;
                }
                REconvergeKindType::Dns => {
                    process_raw_events(&mut send, db.dns_store()?, msg.input).await?;
                }
                REconvergeKindType::Rdp => {
                    process_raw_events(&mut send, db.rdp_store()?, msg.input).await?;
                }
                REconvergeKindType::Http => {
                    process_raw_events(&mut send, db.http_store()?, msg.input).await?;
                }
                REconvergeKindType::Smtp => {
                    process_raw_events(&mut send, db.smtp_store()?, msg.input).await?;
                }
                REconvergeKindType::Ntlm => {
                    process_raw_events(&mut send, db.ntlm_store()?, msg.input).await?;
                }
                REconvergeKindType::Kerberos => {
                    process_raw_events(&mut send, db.kerberos_store()?, msg.input).await?;
                }
                REconvergeKindType::Ssh => {
                    process_raw_events(&mut send, db.ssh_store()?, msg.input).await?;
                }
                REconvergeKindType::DceRpc => {
                    process_raw_events(&mut send, db.dce_rpc_store()?, msg.input).await?;
                }
                REconvergeKindType::Ftp => {
                    process_raw_events(&mut send, db.ftp_store()?, msg.input).await?;
                }
                REconvergeKindType::Mqtt => {
                    process_raw_events(&mut send, db.mqtt_store()?, msg.input).await?;
                }
                REconvergeKindType::Ldap => {
                    process_raw_events(&mut send, db.ldap_store()?, msg.input).await?;
                }
                REconvergeKindType::Tls => {
                    process_raw_events(&mut send, db.tls_store()?, msg.input).await?;
                }
                REconvergeKindType::Smb => {
                    process_raw_events(&mut send, db.smb_store()?, msg.input).await?;
                }
                REconvergeKindType::Nfs => {
                    process_raw_events(&mut send, db.nfs_store()?, msg.input).await?;
                }
                REconvergeKindType::Log => {
                    // For REconvergeKindType::LOG, the source_kind is required as the source.
                    process_raw_events(&mut send, db.log_store()?, msg.input).await?;
                }
                REconvergeKindType::Timeseries => {
                    process_raw_events(&mut send, db.periodic_time_series_store()?, msg.input)
                        .await?;
                }
            }
        }
    }
    Ok(())
}

async fn process_range_data<'c, T>(
    send: &mut SendStream,
    store: RawEventStore<'c, T>,
    msg: RequestRange,
    availd_kind: bool,
) -> Result<()>
where
    T: DeserializeOwned + ResponseRangeData,
{
    let mut key_prefix = Vec::new();
    key_prefix.extend_from_slice(msg.source.as_bytes());
    key_prefix.push(0);
    if availd_kind {
        key_prefix.extend_from_slice(msg.kind.as_bytes());
        key_prefix.push(0);
    }
    let iter = store.boundary_iter(
        &lower_closed_bound_key(&key_prefix, Some(Utc.timestamp_nanos(msg.start))),
        &upper_open_bound_key(&key_prefix, Some(Utc.timestamp_nanos(msg.end))),
        Direction::Forward,
    );

    for item in iter.take(msg.count) {
        let (key, val) = item.context("Failed to read Database")?;
        let timestamp = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        send_range_data(send, Some((val, timestamp, &msg.source))).await?;
    }
    send_range_data::<T>(send, None).await?;
    send.finish().await?;
    Ok(())
}

async fn process_raw_events<'c, T>(
    send: &mut SendStream,
    store: RawEventStore<'c, T>,
    msg: Vec<(String, Vec<i64>)>,
) -> Result<()>
where
    T: DeserializeOwned,
{
    let mut output: Vec<(i64, String, Vec<u8>)> = Vec::new();

    for (source, timestamps) in msg {
        output.extend_from_slice(&store.multi_get_with_source(&source, &timestamps));
    }
    send_raw_events(send, output).await?;

    Ok(())
}
