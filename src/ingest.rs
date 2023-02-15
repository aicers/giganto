pub mod implement;
#[cfg(test)]
mod tests;

use crate::publish::send_direct_stream;
use crate::server::{certificate_info, config_server};
use crate::storage::{Database, RawEventStore};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use giganto_client::{
    connection::server_handshake,
    frame::RecvError,
    ingest::{
        log::{Log, Oplog},
        receive_event, receive_record_header, send_ack_timestamp,
        timeseries::PeriodicTimeSeries,
        Packet, RecordType,
    },
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicI64, AtomicU8, Ordering},
        Arc,
    },
};
use tokio::{
    select,
    sync::{
        mpsc::{channel, Receiver, Sender, UnboundedSender},
        Mutex, RwLock,
    },
    task, time,
};
use tracing::{error, info};
use x509_parser::nom::AsBytes;

const ACK_ROTATION_CNT: u8 = 128;
const ACK_INTERVAL_TIME: u64 = 60;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const ITV_RESET: bool = true;
const NO_TIMESTAMP: i64 = 0;
const SOURCE_INTERVAL: u64 = 60 * 60 * 24;
const INGEST_VERSION_REQ: &str = "0.8.0-alpha.1";

type SourceInfo = (String, DateTime<Utc>, bool);
pub type PacketSources = Arc<RwLock<HashMap<String, Connection>>>;
pub type Sources = Arc<RwLock<HashMap<String, DateTime<Utc>>>>;
pub type StreamDirectChannel = Arc<RwLock<HashMap<String, UnboundedSender<Vec<u8>>>>>;

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
        sources: Sources,
        stream_direct_channel: StreamDirectChannel,
    ) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        info!(
            "listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        let (tx, rx): (Sender<SourceInfo>, Receiver<SourceInfo>) = channel(100);
        let source_db = db.clone();
        task::spawn(check_sources_conn(
            source_db,
            packet_sources.clone(),
            sources,
            rx,
        ));

        while let Some(conn) = endpoint.accept().await {
            let sender = tx.clone();
            let db = db.clone();
            let packet_sources = packet_sources.clone();
            let stream_direct_channel = stream_direct_channel.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_connection(conn, db, packet_sources, sender, stream_direct_channel).await
                {
                    error!("connection failed: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    conn: quinn::Connecting,
    db: Database,
    packet_sources: PacketSources,
    sender: Sender<SourceInfo>,
    stream_direct_channel: StreamDirectChannel,
) -> Result<()> {
    let rep: bool;
    let connection = conn.await?;
    match server_handshake(&connection, INGEST_VERSION_REQ).await {
        Ok((mut send, _, is_reproduce)) => {
            info!("Compatible version");
            rep = is_reproduce;
            send.finish().await?;
        }
        Err(e) => {
            info!("Incompatible version");
            connection.close(quinn::VarInt::from_u32(0), e.to_string().as_bytes());
            bail!("{e}")
        }
    };

    let source = certificate_info(&connection)?;

    if !rep {
        packet_sources
            .write()
            .await
            .insert(source.clone(), connection.clone());
    }

    if let Err(error) = sender.send((source.clone(), Utc::now(), false)).await {
        error!("Failed to send channel data : {}", error);
    }

    async {
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(conn_err) => {
                    if let Err(error) = sender.send((source, Utc::now(), true)).await {
                        error!("Failed to send internal channel data : {}", error);
                    }
                    match conn_err {
                        quinn::ConnectionError::ApplicationClosed(_) => {
                            info!("application closed");
                            return Ok(());
                        }
                        _ => return Err(conn_err),
                    }
                }
                Ok(s) => s,
            };
            let source = source.clone();
            let db = db.clone();
            let stream_direct_channel = stream_direct_channel.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_request(source, stream, db, stream_direct_channel).await {
                    error!("failed: {}", e);
                }
            });
        }
    }
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn handle_request(
    source: String,
    (send, mut recv): (SendStream, RecvStream),
    db: Database,
    stream_direct_channel: StreamDirectChannel,
) -> Result<()> {
    let mut buf = [0; 4];
    receive_record_header(&mut recv, &mut buf)
        .await
        .map_err(|e| anyhow!("failed to read record type: {}", e))?;
    match RecordType::try_from(u32::from_le_bytes(buf)).context("unknown record type")? {
        RecordType::Conn => {
            handle_data(
                send,
                recv,
                RecordType::Conn,
                Some(gen_network_key(&source, "conn")),
                source,
                db.conn_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Dns => {
            handle_data(
                send,
                recv,
                RecordType::Dns,
                Some(gen_network_key(&source, "dns")),
                source,
                db.dns_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Log => {
            handle_data(
                send,
                recv,
                RecordType::Log,
                Some(gen_network_key(&source, "log")),
                source,
                db.log_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Http => {
            handle_data(
                send,
                recv,
                RecordType::Http,
                Some(gen_network_key(&source, "http")),
                source,
                db.http_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Rdp => {
            handle_data(
                send,
                recv,
                RecordType::Rdp,
                Some(gen_network_key(&source, "rdp")),
                source,
                db.rdp_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::PeriodicTimeSeries => {
            handle_data(
                send,
                recv,
                RecordType::PeriodicTimeSeries,
                None,
                source,
                db.periodic_time_series_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Smtp => {
            handle_data(
                send,
                recv,
                RecordType::Smtp,
                Some(gen_network_key(&source, "smtp")),
                source,
                db.smtp_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Ntlm => {
            handle_data(
                send,
                recv,
                RecordType::Ntlm,
                Some(gen_network_key(&source, "ntlm")),
                source,
                db.ntlm_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Kerberos => {
            handle_data(
                send,
                recv,
                RecordType::Kerberos,
                Some(gen_network_key(&source, "kerberos")),
                source,
                db.kerberos_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Ssh => {
            handle_data(
                send,
                recv,
                RecordType::Ssh,
                Some(gen_network_key(&source, "ssh")),
                source,
                db.ssh_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::DceRpc => {
            handle_data(
                send,
                recv,
                RecordType::DceRpc,
                Some(gen_network_key(&source, "dce rpc")),
                source,
                db.dce_rpc_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Statistics => {
            handle_data(
                send,
                recv,
                RecordType::Statistics,
                None,
                source,
                db.statistics_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Oplog => {
            handle_data(
                send,
                recv,
                RecordType::Oplog,
                None,
                source,
                db.oplog_store()?,
                stream_direct_channel,
            )
            .await?;
        }
        RecordType::Packet => {
            handle_data(
                send,
                recv,
                RecordType::Packet,
                None,
                source,
                db.packet_store()?,
                stream_direct_channel,
            )
            .await?;
        }
    };
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_data<T>(
    send: SendStream,
    mut recv: RecvStream,
    record_type: RecordType,
    network_key: Option<NetworkKey>,
    source: String,
    store: RawEventStore<'_, T>,
    stream_direct_channel: StreamDirectChannel,
) -> Result<()> {
    let sender_rotation = Arc::new(Mutex::new(send));
    let sender_interval = Arc::clone(&sender_rotation);

    let ack_cnt_rotation = Arc::new(AtomicU8::new(0));
    let ack_cnt_interval = Arc::clone(&ack_cnt_rotation);

    let ack_time_rotation = Arc::new(AtomicI64::new(NO_TIMESTAMP));
    let ack_time_interval = Arc::clone(&ack_time_rotation);

    let mut itv = time::interval(time::Duration::from_secs(ACK_INTERVAL_TIME));
    itv.reset();
    let (tx, mut rx) = channel(100);

    let handler = task::spawn(async move {
        loop {
            select! {
                _ = itv.tick() => {
                    let last_timestamp = ack_time_interval.load(Ordering::SeqCst);
                    if last_timestamp !=  NO_TIMESTAMP {
                        if send_ack_timestamp(&mut (*sender_interval.lock().await),last_timestamp).await.is_err()
                        {
                            break;
                        }

                        ack_cnt_interval.store(0, Ordering::SeqCst);
                    }
                }

                Some(_) = rx.recv() => {
                    itv.reset();
                }
            }
        }
    });
    loop {
        match receive_event(&mut recv).await {
            Ok((raw_event, timestamp)) => {
                if (timestamp == CHANNEL_CLOSE_TIMESTAMP)
                    && (raw_event.as_bytes() == CHANNEL_CLOSE_MESSAGE)
                {
                    send_ack_timestamp(&mut (*sender_rotation.lock().await), timestamp).await?;
                    continue;
                }
                let mut key: Vec<u8> = Vec::new();
                key.extend_from_slice(source.as_bytes());
                key.push(0);
                match record_type {
                    RecordType::Log => {
                        key.extend_from_slice(
                            bincode::deserialize::<Log>(&raw_event)?.kind.as_bytes(),
                        );
                        key.push(0);
                        key.extend_from_slice(&timestamp.to_be_bytes());
                    }
                    RecordType::PeriodicTimeSeries => {
                        let periodic_time_series =
                            bincode::deserialize::<PeriodicTimeSeries>(&raw_event)?;
                        key.clear();
                        key.extend_from_slice(periodic_time_series.id.as_bytes());
                        key.push(0);
                        key.extend_from_slice(&timestamp.to_be_bytes());
                    }
                    RecordType::Oplog => {
                        let oplog = bincode::deserialize::<Oplog>(&raw_event)?;
                        let agent_id = format!("{}@{source}", oplog.agent_name);
                        key.clear();
                        key.extend_from_slice(agent_id.as_bytes());
                        key.push(0);
                        key.extend_from_slice(&timestamp.to_be_bytes());
                    }
                    RecordType::Packet => {
                        let packet = bincode::deserialize::<Packet>(&raw_event)?;
                        key.extend_from_slice(&timestamp.to_be_bytes());
                        key.push(0);
                        key.extend_from_slice(&packet.packet_timestamp.to_be_bytes());
                    }
                    _ => key.extend_from_slice(&timestamp.to_be_bytes()),
                }
                store.append(&key, &raw_event)?;
                if let Some(network_key) = network_key.as_ref() {
                    send_direct_stream(
                        network_key,
                        &raw_event,
                        timestamp,
                        &source,
                        stream_direct_channel.clone(),
                    )
                    .await?;
                }
                if store.flush().is_ok() {
                    ack_cnt_rotation.fetch_add(1, Ordering::SeqCst);
                    ack_time_rotation.store(timestamp, Ordering::SeqCst);
                    if ACK_ROTATION_CNT <= ack_cnt_rotation.load(Ordering::SeqCst) {
                        send_ack_timestamp(&mut (*sender_rotation.lock().await), timestamp).await?;
                        ack_cnt_rotation.store(0, Ordering::SeqCst);
                        tx.send(ITV_RESET).await?;
                    }
                }
            }
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly)) => {
                handler.abort();
                break;
            }
            Err(e) => {
                handler.abort();
                bail!("handle {:?} error: {}", record_type, e)
            }
        }
    }

    Ok(())
}

async fn check_sources_conn(
    source_db: Database,
    packet_sources: PacketSources,
    sources: Sources,
    mut rx: Receiver<SourceInfo>,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(SOURCE_INTERVAL));
    itv.reset();
    let source_store = source_db
        .sources_store()
        .expect("Failed to open source store");
    loop {
        select! {
            _ = itv.tick() => {
                let mut sources = sources.write().await;
                let keys: Vec<String> = sources.keys().map(std::borrow::ToOwned::to_owned).collect();

                for source_key in keys {
                    let timestamp = Utc::now();
                    if source_store.insert(&source_key, timestamp).is_err(){
                        error!("Failed to append Source store");
                    }
                    sources.insert(source_key, timestamp);
                }
            }

            Some((source_key,timestamp_val,is_close)) = rx.recv() => {
                if is_close {
                    if source_store.insert(&source_key, timestamp_val).is_err(){
                        error!("Failed to append Source store");
                    }
                    sources.write().await.remove(&source_key);
                    packet_sources.write().await.remove(&source_key);
                } else {
                    if source_store.insert(&source_key, timestamp_val).is_err(){
                        error!("Failed to append Source store");
                    }
                    sources.write().await.insert(source_key, timestamp_val);
                }

            }
        }
    }
}

pub struct NetworkKey {
    pub(crate) source_key: String,
    pub(crate) all_key: String,
}

pub fn gen_network_key(source: &str, protocol: &str) -> NetworkKey {
    let source_key = format!("{source}\0{protocol}");
    let all_key = format!("all\0{protocol}");

    NetworkKey {
        source_key,
        all_key,
    }
}
