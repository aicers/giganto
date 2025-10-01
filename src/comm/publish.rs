pub mod implement;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{TimeZone, Utc};
use giganto_client::connection::client_handshake;
use giganto_client::frame::send_raw;
use giganto_client::ingest::log::Log;
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use giganto_client::ingest::network::{
    Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Kerberos, Ldap, MalformedDns, Mqtt, Nfs, Ntlm,
    Radius, Rdp, Smb, Smtp, Ssh, Tls,
};
use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};
use giganto_client::ingest::timeseries::PeriodicTimeSeries;
use giganto_client::publish::{
    PublishError, receive_range_data, recv_ack_response, send_range_data_request,
};
use giganto_client::{
    RawEventKind,
    connection::server_handshake,
    frame,
    publish::{
        PcapFilter, pcap_extract_request,
        range::{MessageCode, RequestRange, RequestRawData, ResponseRangeData},
        receive_range_data_request, receive_stream_request, send_err, send_ok, send_range_data,
        send_semi_supervised_stream_start_message,
        stream::{RequestStreamRecord, StreamRequestPayload},
    },
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig, VarInt};
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    select,
    sync::{Notify, mpsc::unbounded_channel},
};
use tracing::{debug, error, info, warn};

use self::implement::RequestStreamMessage;
use crate::bincode_utils::{decode_legacy, encode_legacy};
use crate::comm::{
    IngestSensors, PcapSensors, StreamDirectChannels,
    ingest::{NetworkKey, implement::EventFilter},
    peer::{PeerIdents, Peers},
};
use crate::graphql::TIMESTAMP_SIZE;
use crate::server::{
    Certs, config_client, config_server, extract_cert_from_conn, subject_from_cert_verbose,
};
use crate::storage::{Database, Direction, RawEventStore, StorageKey};

const PUBLISH_VERSION_REQ: &str = ">=0.26.0-alpha.6,<0.26.0-alpha.7";

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

impl Server {
    pub fn new(addr: SocketAddr, certs: &Certs) -> Self {
        let server_config =
            config_server(certs).expect("server configuration error with cert, key or root");
        Server {
            server_config,
            server_address: addr,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        self,
        db: Database,
        pcap_sensors: PcapSensors,
        stream_direct_channels: StreamDirectChannels,
        ingest_sensors: IngestSensors,
        peers: Peers,
        peer_idents: PeerIdents,
        certs: Arc<Certs>,
        notify_shutdown: Arc<Notify>,
    ) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        info!(
            "Publish listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        let mut conn_hdl: Option<tokio::task::JoinHandle<()>> = None;
        loop {
            select! {
                Some(conn) = endpoint.accept()  => {
                    let db = db.clone();
                    let pcap_sensors = pcap_sensors.clone();
                    let stream_direct_channels = stream_direct_channels.clone();
                    let notify_shutdown = notify_shutdown.clone();
                    let ingest_sensors = ingest_sensors.clone();
                    let peers = peers.clone();
                    let peer_idents = peer_idents.clone();
                    let certs = certs.clone();
                    conn_hdl = Some(tokio::spawn(async move {
                        let remote = conn.remote_address();
                        if let Err(e) = handle_connection(
                            conn,
                            db,
                            pcap_sensors,
                            stream_direct_channels,
                            ingest_sensors,
                            peers,
                            peer_idents,
                            certs,
                            notify_shutdown
                        )
                        .await
                        {
                            error!("Connection to {remote} failed: {}", e);
                        }
                    }));
                },
                () = notify_shutdown.notified() => {
                    endpoint.close(0_u32.into(), &[]);
                    if let Some(handle) = conn_hdl {
                        info!("Shutting down connections");
                        let _ = tokio::join!(handle);
                    }
                    info!("Shutting down publish");
                    break;
                },
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    conn: quinn::Incoming,
    db: Database,
    pcap_sensors: PcapSensors,
    stream_direct_channels: StreamDirectChannels,
    ingest_sensors: IngestSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    certs: Arc<Certs>,
    notify_shutdown: Arc<Notify>,
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
    let (agent, sensor) = subject_from_cert_verbose(&extract_cert_from_conn(&connection)?)?;

    let req_stream_hdl: tokio::task::JoinHandle<std::result::Result<(), anyhow::Error>> =
        tokio::spawn({
            let certs = certs.clone();
            request_stream(
                connection.clone(),
                db.clone(),
                send,
                recv,
                sensor,
                pcap_sensors.clone(),
                stream_direct_channels.clone(),
                peers.clone(),
                peer_idents.clone(),
                certs,
                notify_shutdown.clone(),
            )
        });

    loop {
        select! {
            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        info!("{agent} has disconnected from publish");
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                    Ok(s) => s,
                };

                let db = db.clone();
                let pcap_sensors = pcap_sensors.clone();
                let ingest_sensors = ingest_sensors.clone();
                let peers = peers.clone();
                let peer_idents = peer_idents.clone();
                let certs = certs.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(stream, db, pcap_sensors, ingest_sensors, peers, peer_idents, certs).await {
                        error!("Failed: {}", e);
                    }
                });
            },
            () = notify_shutdown.notified() => {
                connection.close(0_u32.into(), &[]);
                req_stream_hdl.await??;
                return Ok(())
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn request_stream(
    connection: Connection,
    stream_db: Database,
    mut send: SendStream,
    mut recv: RecvStream,
    conn_sensor: String,
    pcap_sensors: PcapSensors,
    stream_direct_channels: StreamDirectChannels,
    peers: Peers,
    peer_idents: PeerIdents,
    certs: Arc<Certs>,
    notify_shutdown: Arc<Notify>,
) -> Result<()> {
    loop {
        match receive_stream_request(&mut recv).await {
            Ok(stream_payload) => {
                let db = stream_db.clone();
                let conn = connection.clone();
                let sensor = conn_sensor.clone();
                let stream_direct_channels = stream_direct_channels.clone();

                match stream_payload {
                    StreamRequestPayload::PcapExtraction { filter } => {
                        process_pcap_extract_filters(
                            filter,
                            pcap_sensors.clone(),
                            peers.clone(),
                            peer_idents.clone(),
                            certs.clone(),
                            &mut send,
                        )
                        .await?;
                    }
                    StreamRequestPayload::SemiSupervised {
                        record_type,
                        request,
                    } => {
                        let notify_shutdown = notify_shutdown.clone();
                        tokio::spawn(async move {
                            if let Err(e) = process_stream(
                                db,
                                conn,
                                Some(sensor),
                                None,
                                record_type,
                                request,
                                stream_direct_channels,
                                notify_shutdown,
                            )
                            .await
                            {
                                error!("{}", e);
                            }
                        });
                    }
                    StreamRequestPayload::TimeSeriesGenerator {
                        record_type,
                        request,
                    } => {
                        let notify_shutdown = notify_shutdown.clone();
                        tokio::spawn(async move {
                            if let Err(e) = process_stream(
                                db,
                                conn,
                                None,
                                None,
                                record_type,
                                request,
                                stream_direct_channels,
                                notify_shutdown,
                            )
                            .await
                            {
                                error!("{}", e);
                            }
                        });
                    }
                }
            }
            Err(e) => {
                error!("Publish error {}", e);
                let _ = recv.stop(VarInt::from_u32(0));
                break;
            }
        }
    }
    Ok(())
}

async fn process_pcap_extract_filters(
    filters: Vec<PcapFilter>,
    pcap_sensors: PcapSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    certs: Arc<Certs>,
    resp_send: &mut SendStream,
) -> Result<()> {
    let mut buf = Vec::new();
    send_ok(resp_send, &mut buf, ())
        .await
        .context("Failed to send ok")?;

    let certs = certs.clone();
    tokio::spawn(async move {
        for filter in filters {
            if let Some(sensor_conn) =
                get_pcap_conn_if_current_giganto_in_charge(pcap_sensors.clone(), &filter.sensor)
                    .await
            {
                // send/receive extract request from the Sensor
                match pcap_extract_request(&sensor_conn, &filter).await {
                    Ok(()) => (),
                    Err(e) => debug!("Failed to relay pcap request: {e}"),
                }
            } else if let Some(peer_addr) =
                peer_in_charge_publish_addr(peers.clone(), &filter.sensor).await
            {
                let peer_name: String = {
                    let peer_idents_guard = peer_idents.read().await;
                    let peer_ident = peer_idents_guard
                        .iter()
                        .find(|idents| idents.addr.eq(&peer_addr));

                    if let Some(peer_ident) = peer_ident {
                        peer_ident.hostname.clone()
                    } else {
                        error!(
                            "Peer's server name cannot be identitified. addr: {peer_addr}, sensor: {}",
                            filter.sensor
                        );
                        continue;
                    }
                };
                if let Ok((mut _peer_send, mut peer_recv)) = request_range_data_to_peer(
                    peer_addr,
                    peer_name.as_str(),
                    &certs,
                    MessageCode::Pcap,
                    filter,
                )
                .await
                {
                    if let Err(e) = recv_ack_response(&mut peer_recv).await {
                        error!(
                            "Failed to receive ack response from peer. addr: {peer_addr} name: {peer_name} {e}"
                        );
                    }
                } else {
                    error!(
                        "Failed to connect to peer's publish module. addr: {peer_addr} name: {peer_name}"
                    );
                }
            } else {
                error!(
                    "Neither this node nor peers are in charge of requested pcap sensor {}",
                    filter.sensor
                );
            }
        }
    });

    Ok(())
}

async fn get_pcap_conn_if_current_giganto_in_charge(
    pcap_sensors: PcapSensors,
    sensor: &str,
) -> Option<Connection> {
    pcap_sensors
        .read()
        .await
        .get(sensor)
        .and_then(|connections| connections.last().cloned())
}

#[allow(clippy::too_many_arguments)]
async fn process_stream<T>(
    db: Database,
    conn: Connection,
    sensor: Option<String>,
    kind: Option<String>,
    record_type: RequestStreamRecord,
    request_msg: T,
    stream_direct_channels: StreamDirectChannels,
    notify_shutdown: Arc<Notify>,
) -> Result<()>
where
    T: RequestStreamMessage,
{
    macro_rules! handle_store {
        ($store_fn:ident, $store_name:expr) => {
            match db.$store_fn() {
                Ok(store) => {
                    if let Err(e) = send_stream(
                        store,
                        conn,
                        record_type,
                        request_msg,
                        sensor,
                        kind,
                        stream_direct_channels,
                        notify_shutdown,
                    )
                    .await
                    {
                        error!("Failed to send network stream : {}", e);
                    }
                }
                Err(_) => {
                    error!("Failed to open {} store", $store_name);
                }
            }
        };
    }

    match record_type {
        RequestStreamRecord::Conn => handle_store!(conn_store, "conn"),
        RequestStreamRecord::Dns => handle_store!(dns_store, "dns"),
        RequestStreamRecord::Rdp => handle_store!(rdp_store, "rdp"),
        RequestStreamRecord::Http => handle_store!(http_store, "http"),
        RequestStreamRecord::Log => handle_store!(log_store, "log"),
        RequestStreamRecord::Smtp => handle_store!(smtp_store, "smtp"),
        RequestStreamRecord::Ntlm => handle_store!(ntlm_store, "ntlm"),
        RequestStreamRecord::Kerberos => handle_store!(kerberos_store, "kerberos"),
        RequestStreamRecord::Ssh => handle_store!(ssh_store, "ssh"),
        RequestStreamRecord::DceRpc => handle_store!(dce_rpc_store, "dce rpc"),
        RequestStreamRecord::Ftp => handle_store!(ftp_store, "ftp"),
        RequestStreamRecord::Mqtt => handle_store!(mqtt_store, "mqtt"),
        RequestStreamRecord::Ldap => handle_store!(ldap_store, "ldap"),
        RequestStreamRecord::Tls => handle_store!(tls_store, "tls"),
        RequestStreamRecord::Smb => handle_store!(smb_store, "smb"),
        RequestStreamRecord::Nfs => handle_store!(nfs_store, "nfs"),
        RequestStreamRecord::Bootp => handle_store!(bootp_store, "bootp"),
        RequestStreamRecord::Dhcp => handle_store!(dhcp_store, "dhcp"),
        RequestStreamRecord::Radius => handle_store!(radius_store, "radius"),
        RequestStreamRecord::FileCreate => handle_store!(file_create_store, "file_create"),
        RequestStreamRecord::FileDelete => handle_store!(file_delete_store, "file_delete"),
        RequestStreamRecord::MalformedDns => {
            handle_store!(malformed_dns_store, "malformed_dns");
        }
        RequestStreamRecord::Pcap => {}
    }
    Ok(())
}

pub async fn send_direct_stream(
    network_key: &NetworkKey,
    raw_event: &[u8],
    timestamp: i64,
    sensor: &str,
    stream_direct_channels: StreamDirectChannels,
) -> Result<()> {
    for (req_key, sender) in &*stream_direct_channels.read().await {
        if req_key.contains(&network_key.sensor_key) || req_key.contains(&network_key.all_key) {
            let raw_len = u32::try_from(raw_event.len())?.to_le_bytes();
            let mut send_buf: Vec<u8> = Vec::new();
            send_buf.extend_from_slice(&timestamp.to_le_bytes());

            if req_key.contains("SemiSupervised") {
                let sensor_bytes = encode_legacy(sensor)?;
                let sensor_len = u32::try_from(sensor_bytes.len())?.to_le_bytes();
                send_buf.extend_from_slice(&sensor_len);
                send_buf.extend_from_slice(&sensor_bytes);
            }

            send_buf.extend_from_slice(&raw_len);
            send_buf.extend_from_slice(raw_event);
            sender.send(send_buf)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_stream<T, N>(
    store: RawEventStore<'_, T>,
    conn: Connection,
    record_type: RequestStreamRecord,
    msg: N,
    sensor: Option<String>,
    kind: Option<String>,
    stream_direct_channels: StreamDirectChannels,
    notify_shutdown: Arc<Notify>,
) -> Result<()>
where
    T: EventFilter + Serialize + DeserializeOwned + Display,
    N: RequestStreamMessage,
{
    let mut sender = conn.open_uni().await?;
    let channel_keys = msg.channel_key(sensor, &record_type.to_string())?;

    let (send, mut recv) = unbounded_channel::<Vec<u8>>();
    let channel_remove_keys = channel_keys.clone();
    for c_key in channel_keys {
        stream_direct_channels
            .write()
            .await
            .insert(c_key, send.clone());
    }

    let mut last_ts = 0_i64;

    // send stored record raw data
    if msg.is_semi_supervised() {
        send_semi_supervised_stream_start_message(&mut sender, record_type)
            .await
            .map_err(|e| {
                anyhow!("Failed to write the semi-supervised engine start message: {e}")
            })?;
        info!(
            "Start the semi-supervised engine's publish stream : {:?}",
            record_type
        );
    } else if msg.is_time_series_generator() {
        let id = msg.id().expect("The time series generator always sends RequestTimeSeriesGeneratorStream with an id, so this value is guaranteed to exist.");
        send_time_series_generator_stream_start_message(&mut sender, id)
            .await
            .map_err(|e| anyhow!("Failed to write the time series generator start message: {e}"))?;
        info!(
            "Start time series generator's publish stream : {:?}",
            record_type
        );

        let key_builder = StorageKey::builder()
            .start_key(&msg.sensor()?)
            .mid_key(kind.map(|s| s.as_bytes().to_vec()));
        let from_key = key_builder
            .clone()
            .lower_closed_bound_end_key(Some(Utc.timestamp_nanos(msg.start_time())))
            .build();
        let to_key = key_builder.upper_open_bound_end_key(None).build();
        let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);

        for item in iter {
            let (key, val) = item.context("Failed to read database")?;
            let (Some(orig_addr), Some(resp_addr)) = (val.orig_addr(), val.resp_addr()) else {
                bail!("Failed to deserialize database data");
            };
            if msg.filter_ip(orig_addr, resp_addr) {
                let timestamp = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
                send_time_series_generator_data(&mut sender, timestamp, val).await?;
                last_ts = timestamp;
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
                            stream_direct_channels
                            .write()
                            .await
                            .remove(&r_key);
                        }
                        break;
                    }
                }
                () = notify_shutdown.notified() => {
                    break;
                }
            }
        }
    });
    Ok(())
}

/// Sends the Time Series Generator stream start message from giganto's publish module.
///
/// # Errors
///
/// Returns an error if the message could not be sent.
async fn send_time_series_generator_stream_start_message(
    send: &mut SendStream,
    start_msg: String,
) -> Result<()> {
    frame::send_raw(send, start_msg.as_bytes()).await?;
    Ok(())
}

/// Sends the record data. (timestamp /record structure)
///
/// # Errors
///
/// Returns an error if the message could not be sent.
async fn send_time_series_generator_data<T>(
    send: &mut SendStream,
    timestamp: i64,
    record_data: T,
) -> Result<()>
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
    pcap_sensors: PcapSensors,
    ingest_sensors: IngestSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    certs: Arc<Certs>,
) -> Result<()> {
    let (msg_type, msg_buf) = receive_range_data_request(&mut recv).await?;
    match msg_type {
        MessageCode::ReqRange => {
            let msg: RequestRange =
                decode_legacy(&msg_buf).map_err(PublishError::DeserializationError)?;

            match RawEventKind::from_str(msg.kind.as_str()).unwrap_or_default() {
                RawEventKind::Conn => {
                    process_range_data::<Conn, u8>(
                        &mut send,
                        db.conn_store().context("Failed to open conn store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Dns => {
                    process_range_data::<Dns, u8>(
                        &mut send,
                        db.dns_store().context("Failed to open dns store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Rdp => {
                    process_range_data::<Rdp, u8>(
                        &mut send,
                        db.rdp_store().context("Failed to open rdp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Http => {
                    process_range_data::<Http, u8>(
                        &mut send,
                        db.http_store().context("Failed to open http store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Smtp => {
                    process_range_data::<Smtp, u8>(
                        &mut send,
                        db.smtp_store().context("Failed to open smtp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Log => {
                    process_range_data::<Log, u8>(
                        &mut send,
                        db.log_store().context("Failed to open log store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        true,
                    )
                    .await?;
                }
                RawEventKind::Ntlm => {
                    process_range_data::<Ntlm, u8>(
                        &mut send,
                        db.ntlm_store().context("Failed to open ntlm store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Kerberos => {
                    process_range_data::<Kerberos, u8>(
                        &mut send,
                        db.kerberos_store()
                            .context("Failed to open kerberos store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Ssh => {
                    process_range_data::<Ssh, u8>(
                        &mut send,
                        db.ssh_store().context("Failed to open ssh store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::DceRpc => {
                    process_range_data::<DceRpc, u8>(
                        &mut send,
                        db.dce_rpc_store().context("Failed to open dce rpc store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Ftp => {
                    process_range_data::<Ftp, u8>(
                        &mut send,
                        db.ftp_store().context("Failed to open ftp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Mqtt => {
                    process_range_data::<Mqtt, u8>(
                        &mut send,
                        db.mqtt_store().context("Failed to open mqtt store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::PeriodicTimeSeries => {
                    process_range_data::<PeriodicTimeSeries, f64>(
                        &mut send,
                        db.periodic_time_series_store()
                            .context("Failed to open periodic time series storage")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Ldap => {
                    process_range_data::<Ldap, u8>(
                        &mut send,
                        db.ldap_store().context("Failed to open ldap store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Tls => {
                    process_range_data::<Tls, u8>(
                        &mut send,
                        db.tls_store().context("Failed to open tls store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Smb => {
                    process_range_data::<Smb, u8>(
                        &mut send,
                        db.smb_store().context("Failed to open smb store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Nfs => {
                    process_range_data::<Nfs, u8>(
                        &mut send,
                        db.nfs_store().context("Failed to open nfs store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Bootp => {
                    process_range_data::<Bootp, u8>(
                        &mut send,
                        db.bootp_store().context("Failed to open bootp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Dhcp => {
                    process_range_data::<Dhcp, u8>(
                        &mut send,
                        db.dhcp_store().context("Failed to open dhcp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Radius => {
                    process_range_data::<Radius, u8>(
                        &mut send,
                        db.radius_store().context("Failed to open radius store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::ProcessCreate => {
                    process_range_data::<ProcessCreate, u8>(
                        &mut send,
                        db.process_create_store()
                            .context("Failed to open process_create store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileCreateTime => {
                    process_range_data::<FileCreationTimeChanged, u8>(
                        &mut send,
                        db.file_create_time_store()
                            .context("Failed to open file_create_time store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::NetworkConnect => {
                    process_range_data::<NetworkConnection, u8>(
                        &mut send,
                        db.network_connect_store()
                            .context("Failed to open network_connect store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::ProcessTerminate => {
                    process_range_data::<ProcessTerminated, u8>(
                        &mut send,
                        db.process_terminate_store()
                            .context("Failed to open process_terminate store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::ImageLoad => {
                    process_range_data::<ImageLoaded, u8>(
                        &mut send,
                        db.image_load_store()
                            .context("Failed to open image_load store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileCreate => {
                    process_range_data::<FileCreate, u8>(
                        &mut send,
                        db.file_create_store()
                            .context("Failed to open file_create store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::RegistryValueSet => {
                    process_range_data::<RegistryValueSet, u8>(
                        &mut send,
                        db.registry_value_set_store()
                            .context("Failed to open registry_value_set store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::RegistryKeyRename => {
                    process_range_data::<RegistryKeyValueRename, u8>(
                        &mut send,
                        db.registry_key_rename_store()
                            .context("Failed to open registry_key_rename store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileCreateStreamHash => {
                    process_range_data::<FileCreateStreamHash, u8>(
                        &mut send,
                        db.file_create_stream_hash_store()
                            .context("Failed to open file_create_stream_hash store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::PipeEvent => {
                    process_range_data::<PipeEvent, u8>(
                        &mut send,
                        db.pipe_event_store()
                            .context("Failed to open pipe_event store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::DnsQuery => {
                    process_range_data::<DnsEvent, u8>(
                        &mut send,
                        db.dns_query_store()
                            .context("Failed to open dns_query store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileDelete => {
                    process_range_data::<FileDelete, u8>(
                        &mut send,
                        db.file_delete_store()
                            .context("Failed to open file_delete store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::ProcessTamper => {
                    process_range_data::<ProcessTampering, u8>(
                        &mut send,
                        db.process_tamper_store()
                            .context("Failed to open process_tamper store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileDeleteDetected => {
                    process_range_data::<FileDeleteDetected, u8>(
                        &mut send,
                        db.file_delete_detected_store()
                            .context("Failed to open file_delete_detected store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Netflow5 => {
                    process_range_data::<Netflow5, u8>(
                        &mut send,
                        db.netflow5_store()
                            .context("Failed to open netflow5 store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Netflow9 => {
                    process_range_data::<Netflow9, u8>(
                        &mut send,
                        db.netflow9_store()
                            .context("Failed to open netflow9 store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                RawEventKind::MalformedDns => {
                    process_range_data::<MalformedDns, u8>(
                        &mut send,
                        db.malformed_dns_store()
                            .context("Failed to open malformed dns store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                        false,
                    )
                    .await?;
                }
                _ => {
                    // do nothing
                    warn!("Not expected to reach here");
                }
            }
        }
        MessageCode::Pcap => {
            let filters = match decode_legacy::<Vec<PcapFilter>>(&msg_buf) {
                Ok(filters) => filters,
                Err(e) => {
                    let mut buf = Vec::new();
                    send_err(&mut send, &mut buf, &e)
                        .await
                        .context("Failed to send err")?;
                    let err = PublishError::DeserializationError(e);
                    return Err(err.into());
                }
            };

            process_pcap_extract_filters(
                filters,
                pcap_sensors.clone(),
                peers,
                peer_idents.clone(),
                certs.clone(),
                &mut send,
            )
            .await?;
        }
        MessageCode::RawData => {
            let msg: RequestRawData =
                decode_legacy(&msg_buf).map_err(PublishError::DeserializationError)?;
            match RawEventKind::from_str(msg.kind.as_str()).unwrap_or_default() {
                RawEventKind::Conn => {
                    process_raw_events::<Conn, u8>(
                        &mut send,
                        db.conn_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Dns => {
                    process_raw_events::<Dns, u8>(
                        &mut send,
                        db.dns_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Rdp => {
                    process_raw_events::<Rdp, u8>(
                        &mut send,
                        db.rdp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Http => {
                    process_raw_events::<Http, u8>(
                        &mut send,
                        db.http_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Smtp => {
                    process_raw_events::<Smtp, u8>(
                        &mut send,
                        db.smtp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Ntlm => {
                    process_raw_events::<Ntlm, u8>(
                        &mut send,
                        db.ntlm_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Kerberos => {
                    process_raw_events::<Kerberos, u8>(
                        &mut send,
                        db.kerberos_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Ssh => {
                    process_raw_events::<Ssh, u8>(
                        &mut send,
                        db.ssh_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::DceRpc => {
                    process_raw_events::<DceRpc, u8>(
                        &mut send,
                        db.dce_rpc_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Ftp => {
                    process_raw_events::<Ftp, u8>(
                        &mut send,
                        db.ftp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Mqtt => {
                    process_raw_events::<Mqtt, u8>(
                        &mut send,
                        db.mqtt_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Ldap => {
                    process_raw_events::<Ldap, u8>(
                        &mut send,
                        db.ldap_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Tls => {
                    process_raw_events::<Tls, u8>(
                        &mut send,
                        db.tls_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Smb => {
                    process_raw_events::<Smb, u8>(
                        &mut send,
                        db.smb_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Nfs => {
                    process_raw_events::<Nfs, u8>(
                        &mut send,
                        db.nfs_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Bootp => {
                    process_raw_events::<Bootp, u8>(
                        &mut send,
                        db.bootp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Dhcp => {
                    process_raw_events::<Dhcp, u8>(
                        &mut send,
                        db.dhcp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Radius => {
                    process_raw_events::<Radius, u8>(
                        &mut send,
                        db.radius_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Log => {
                    // For RawEventKind::LOG, the kind is required as the sensor.
                    process_raw_events::<Log, u8>(
                        &mut send,
                        db.log_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::PeriodicTimeSeries => {
                    process_raw_events::<PeriodicTimeSeries, f64>(
                        &mut send,
                        db.periodic_time_series_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::ProcessCreate => {
                    process_raw_events::<ProcessCreate, u8>(
                        &mut send,
                        db.process_create_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::FileCreateTime => {
                    process_raw_events::<FileCreationTimeChanged, u8>(
                        &mut send,
                        db.file_create_time_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::NetworkConnect => {
                    process_raw_events::<NetworkConnection, u8>(
                        &mut send,
                        db.network_connect_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::ProcessTerminate => {
                    process_raw_events::<ProcessTerminated, u8>(
                        &mut send,
                        db.process_terminate_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::ImageLoad => {
                    process_raw_events::<ImageLoaded, u8>(
                        &mut send,
                        db.image_load_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::FileCreate => {
                    process_raw_events::<FileCreate, u8>(
                        &mut send,
                        db.file_create_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::RegistryValueSet => {
                    process_raw_events::<RegistryValueSet, u8>(
                        &mut send,
                        db.registry_value_set_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::RegistryKeyRename => {
                    process_raw_events::<RegistryKeyValueRename, u8>(
                        &mut send,
                        db.registry_key_rename_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::FileCreateStreamHash => {
                    process_raw_events::<FileCreateStreamHash, u8>(
                        &mut send,
                        db.file_create_stream_hash_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::PipeEvent => {
                    process_raw_events::<PipeEvent, u8>(
                        &mut send,
                        db.pipe_event_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::DnsQuery => {
                    process_raw_events::<DnsEvent, u8>(
                        &mut send,
                        db.dns_query_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::FileDelete => {
                    process_raw_events::<FileDelete, u8>(
                        &mut send,
                        db.file_delete_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::ProcessTamper => {
                    process_raw_events::<ProcessTampering, u8>(
                        &mut send,
                        db.process_tamper_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::FileDeleteDetected => {
                    process_raw_events::<FileDeleteDetected, u8>(
                        &mut send,
                        db.file_delete_detected_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Netflow5 => {
                    process_raw_events::<Netflow5, u8>(
                        &mut send,
                        db.netflow5_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::Netflow9 => {
                    process_raw_events::<Netflow9, u8>(
                        &mut send,
                        db.netflow9_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                RawEventKind::MalformedDns => {
                    process_raw_events::<MalformedDns, u8>(
                        &mut send,
                        db.malformed_dns_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &certs,
                    )
                    .await?;
                }
                _ => {
                    // do nothing
                    warn!("Not expected to reach here");
                }
            }
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn process_range_data<T, I>(
    send: &mut SendStream,
    store: RawEventStore<'_, T>,
    request_range: RequestRange,
    ingest_sensors: IngestSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    certs: &Certs,
    availed_kind: bool,
) -> Result<()>
where
    T: DeserializeOwned + ResponseRangeData,
    I: DeserializeOwned + Serialize,
{
    if is_current_giganto_in_charge(ingest_sensors, &request_range.sensor).await {
        process_range_data_in_current_giganto(send, store, request_range, availed_kind).await?;
    } else if let Some(peer_addr) = peer_in_charge_publish_addr(peers, &request_range.sensor).await
    {
        process_range_data_in_peer_giganto::<I>(send, peer_idents, peer_addr, certs, request_range)
            .await?;
    } else {
        bail!(
            "Neither current nor peer gigantos are in charge of requested sensor {}",
            &request_range.sensor
        )
    }
    send_range_data::<T>(send, None).await?;
    send.finish()?;
    Ok(())
}

async fn is_current_giganto_in_charge(ingest_sensors: IngestSensors, sensor: &str) -> bool {
    ingest_sensors.read().await.contains(sensor)
}

async fn peer_in_charge_publish_addr(peers: Peers, sensor: &str) -> Option<SocketAddr> {
    peers.read().await.iter().find_map(|(addr_to_peers, peer_info)| {
        peer_info
            .ingest_sensors
            .contains(sensor)
            .then(|| {
                SocketAddr::new(
                    addr_to_peers.parse::<IpAddr>().expect("Peer's IP address must be valid, because it is validated when peer giganto started."),
                    peer_info.publish_port.expect("Peer's publish port must be valid, because it is validated when peer giganto started."),
                )
            })
    })
}

async fn process_range_data_in_current_giganto<T>(
    send: &mut SendStream,
    store: RawEventStore<'_, T>,
    request_range: RequestRange,
    availed_kind: bool,
) -> Result<()>
where
    T: DeserializeOwned + ResponseRangeData,
{
    let key_builder = StorageKey::builder().start_key(&request_range.sensor);
    let key_builder = if availed_kind {
        key_builder.mid_key(Some(request_range.kind.as_bytes().to_vec()))
    } else {
        key_builder
    };

    let from_key = key_builder
        .clone()
        .lower_closed_bound_end_key(Some(Utc.timestamp_nanos(request_range.start)))
        .build();
    let to_key = key_builder
        .upper_open_bound_end_key(Some(Utc.timestamp_nanos(request_range.end)))
        .build();

    let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);

    for item in iter.take(request_range.count) {
        let (key, val) = item.context("Failed to read Database")?;
        let timestamp = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        send_range_data(send, Some((val, timestamp, &request_range.sensor))).await?;
    }

    Ok(())
}

async fn process_range_data_in_peer_giganto<I>(
    send: &mut SendStream,
    peer_idents: PeerIdents,
    peer_addr: SocketAddr,
    certs: &Certs,
    request_range: RequestRange,
) -> Result<()>
where
    I: DeserializeOwned + Serialize,
{
    let peer_name = peer_name(peer_idents, &peer_addr).await?;
    let (_peer_send, mut peer_recv) = request_range_data_to_peer(
        peer_addr,
        peer_name.as_str(),
        certs,
        MessageCode::ReqRange,
        request_range,
    )
    .await?;
    loop {
        let event: Option<(i64, String, Vec<I>)> = receive_range_data(&mut peer_recv).await?;
        if let Some(event_data) = event {
            let event_data_again: Option<(i64, String, Vec<I>)> = Some(event_data);
            let send_buf =
                encode_legacy(&event_data_again).map_err(PublishError::SerializationError)?;
            send_raw(send, &send_buf).await?;
        } else {
            break;
        }
    }
    Ok(())
}

async fn request_range_data_to_peer<T>(
    peer_addr: SocketAddr,
    peer_name: &str,
    certs: &Certs,
    message_code: MessageCode,
    request_data: T,
) -> Result<(SendStream, RecvStream)>
where
    T: Serialize,
{
    let connection = connect(peer_addr, peer_name, certs).await?;

    let (mut send, recv) = connection.open_bi().await?;
    send_range_data_request(&mut send, message_code, request_data).await?;

    Ok((send, recv))
}

async fn process_raw_events<T, I>(
    send: &mut SendStream,
    store: RawEventStore<'_, T>,
    req: RequestRawData,
    ingest_sensors: IngestSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    certs: &Certs,
) -> Result<()>
where
    T: DeserializeOwned + ResponseRangeData,
    I: DeserializeOwned + Serialize + Clone,
{
    let (handle_by_current_giganto, handle_by_peer_gigantos) =
        req_inputs_by_gigantos_in_charge(ingest_sensors, req.input).await;

    if !handle_by_current_giganto.is_empty() {
        process_raw_event_in_current_giganto(send, store, handle_by_current_giganto).await?;
    }

    if !handle_by_peer_gigantos.is_empty() {
        process_raw_event_in_peer_gigantos::<I>(
            send,
            req.kind,
            certs,
            peers,
            peer_idents,
            handle_by_peer_gigantos,
        )
        .await?;
    }

    send_range_data::<T>(send, None).await?;
    send.finish()?;
    Ok(())
}

async fn req_inputs_by_gigantos_in_charge(
    ingest_sensors: IngestSensors,
    req_inputs: Vec<(String, Vec<i64>)>,
) -> (Vec<(String, Vec<i64>)>, Vec<(String, Vec<i64>)>) {
    let mut handle_by_current_giganto = Vec::with_capacity(req_inputs.len());
    let mut handle_by_peer_gigantos = Vec::with_capacity(req_inputs.len());
    for req_input in req_inputs {
        if ingest_sensors.read().await.contains(&req_input.0) {
            handle_by_current_giganto.push(req_input);
        } else {
            handle_by_peer_gigantos.push(req_input);
        }
    }

    (handle_by_current_giganto, handle_by_peer_gigantos)
}

async fn process_raw_event_in_current_giganto<T>(
    send: &mut SendStream,
    store: RawEventStore<'_, T>,
    handle_by_current_giganto: Vec<(String, Vec<i64>)>,
) -> Result<()>
where
    T: DeserializeOwned + ResponseRangeData,
{
    let mut output: Vec<(i64, String, Vec<u8>)> = Vec::new();
    for (sensor, timestamps) in handle_by_current_giganto {
        output.extend_from_slice(&store.batched_multi_get_with_sensor(&sensor, &timestamps));
    }

    for (timestamp, sensor, value) in output {
        let val: T = decode_legacy(&value).map_err(PublishError::DeserializationError)?;
        send_range_data(send, Some((val, timestamp, &sensor))).await?;
    }

    Ok(())
}

async fn process_raw_event_in_peer_gigantos<I>(
    send: &mut SendStream,
    kind: String,
    certs: &Certs,
    peers: Peers,
    peer_idents: PeerIdents,
    handle_by_peer_gigantos: Vec<(String, Vec<i64>)>,
) -> Result<()>
where
    I: DeserializeOwned + Serialize,
{
    let peer_gigantos_by_sensor: HashMap<String, Vec<(String, Vec<i64>)>> = handle_by_peer_gigantos
        .into_iter()
        .fold(HashMap::new(), |mut acc, (sensor, timestamps)| {
            acc.entry(sensor.clone())
                .or_default()
                .push((sensor, timestamps));
            acc
        });

    for (sensor, input) in peer_gigantos_by_sensor {
        if let Some(peer_addr) = peer_in_charge_publish_addr(peers.clone(), &sensor).await {
            let peer_name = peer_name(peer_idents.clone(), &peer_addr).await?;

            let connection = connect(peer_addr, peer_name.as_str(), certs).await?;
            let (mut peer_send, mut peer_recv) = connection.open_bi().await?;

            send_range_data_request(
                &mut peer_send,
                MessageCode::RawData,
                RequestRawData {
                    kind: kind.clone(),
                    input,
                },
            )
            .await?;

            while let Some(event) =
                receive_range_data::<Option<(i64, String, Vec<I>)>>(&mut peer_recv).await?
            {
                let send_buf =
                    encode_legacy(&Some(event)).map_err(PublishError::SerializationError)?;
                send_raw(send, &send_buf).await?;
            }
        }
    }

    Ok(())
}

async fn connect(server_addr: SocketAddr, server_name: &str, certs: &Certs) -> Result<Connection> {
    let client_addr = if server_addr.is_ipv6() {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };

    let mut endpoint = Endpoint::client(SocketAddr::new(client_addr, 0))?;
    endpoint.set_default_client_config(config_client(certs)?);

    let conn = connect_repeatedly(&endpoint, server_addr, server_name).await;

    client_handshake(&conn, env!("CARGO_PKG_VERSION")).await?;
    Ok(conn)
}

async fn connect_repeatedly(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
) -> Connection {
    let max_delay = Duration::from_secs(30);
    let mut delay = Duration::from_millis(500);

    loop {
        match endpoint.connect(server_addr, server_name) {
            Ok(connecting) => match connecting.await {
                Ok(conn) => {
                    info!("Connected to {}", server_addr);
                    return conn;
                }
                Err(e) => warn!("Cannot connect to controller: {:#}, retrying", e),
            },
            Err(e) => {
                warn!("Cannot connect: {:#}, retrying", e);
            }
        }
        delay = std::cmp::min(max_delay, delay * 2);
        tokio::time::sleep(delay).await;
    }
}

async fn peer_name(peer_idents: PeerIdents, peer_addr: &SocketAddr) -> Result<String> {
    let peer_idents_guard = peer_idents.read().await;
    let peer_ident = peer_idents_guard
        .iter()
        .find(|idents| idents.addr.eq(peer_addr));

    match peer_ident {
        Some(peer_ident) => Ok(peer_ident.hostname.clone()),
        None => bail!("Peer giganto's server name cannot be identitified"),
    }
}
