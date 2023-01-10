pub(crate) mod log;
mod network;
#[cfg(test)]
mod tests;

pub(crate) use self::log::{Log, Oplog};
pub(crate) use self::network::{
    Conn, DceRpc, Dns, Http, Kerberos, Ntlm, Qclass, Qtype, Rdp, Smtp, Ssh,
};
use crate::graphql::network::NetworkFilter;
use crate::publish::{send_direct_network_stream, PubMessage};
use crate::server::{certificate_info, config_server, server_handshake};
use crate::storage::{Database, RawEventStore};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use num_enum::TryFromPrimitive;
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::{
    collections::HashMap,
    fmt::Debug,
    mem,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicI64, AtomicU8, Ordering},
        Arc,
    },
};
use tokio::{
    select,
    sync::mpsc::{channel, Receiver, Sender},
    sync::{Mutex, RwLock},
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

pub trait EventFilter {
    fn orig_addr(&self) -> Option<IpAddr>;
    fn resp_addr(&self) -> Option<IpAddr>;
    fn orig_port(&self) -> Option<u16>;
    fn resp_port(&self) -> Option<u16>;
    fn log_level(&self) -> Option<String>;
    fn log_contents(&self) -> Option<String>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeriodicTimeSeries {
    pub id: String,
    pub data: Vec<f64>,
}

impl EventFilter for PeriodicTimeSeries {
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
}

impl Display for PeriodicTimeSeries {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.data)
    }
}

impl PubMessage for PeriodicTimeSeries {
    fn message(&self, timestamp: i64, _source: &str) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&Some((timestamp, &self.data)))?)
    }
    fn done() -> Result<Vec<u8>> {
        Ok(bincode::serialize::<Option<(i64, Vec<f64>)>>(&None)?)
    }
}

#[derive(Debug, Deserialize)]
pub struct Statistics {
    period: u16,
    stats: Vec<(RecordType, u64, u64)>, // protocol, packet count, packet size
}

impl Display for Statistics {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        for stat in &self.stats {
            writeln!(f, "{:?}\t{}\t{}\t{}", stat.0, stat.1, stat.2, self.period)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, PartialEq, Deserialize)]
#[repr(u32)]
enum RecordType {
    Conn = 0,
    Dns = 1,
    Log = 2,
    Http = 3,
    Rdp = 4,
    PeriodicTimeSeries = 5,
    Smtp = 6,
    Ntlm = 7,
    Kerberos = 8,
    Ssh = 9,
    DceRpc = 10,
    Statistics = 11,
    Oplog = 12,
}

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

    pub async fn run(self, db: Database, packet_sources: PacketSources, sources: Sources) {
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
            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, db, packet_sources, sender).await {
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
) -> Result<()> {
    let connection = conn.await?;

    let stream = connection.accept_bi().await;
    let (mut send, mut recv) = stream?;
    if let Err(e) = server_handshake(&mut send, &mut recv, INGEST_VERSION_REQ).await {
        let err = format!("Handshake fail: {e}");
        send.finish().await?;
        connection.close(quinn::VarInt::from_u32(0), err.as_bytes());
        bail!(err);
    }
    send.finish().await?;

    let source = certificate_info(&connection)?;

    packet_sources
        .write()
        .await
        .insert(source.clone(), connection.clone());

    if let Err(error) = sender.send((source.clone(), Utc::now(), false)).await {
        error!("Faild to send channel data : {}", error);
    }

    async {
        loop {
            let stream = connection.accept_bi().await;
            let source = source.clone();
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    if let Err(error) = sender.send((source, Utc::now(), true)).await {
                        error!("Faild to send channel data : {}", error);
                    }
                    return Ok(());
                }
                Err(e) => {
                    if let Err(error) = sender.send((source, Utc::now(), true)).await {
                        error!("Faild to send channel data : {}", error);
                    }
                    return Err(e);
                }
                Ok(s) => s,
            };

            let source = source.clone();
            let db = db.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_request(source, stream, db).await {
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
) -> Result<()> {
    let mut buf = [0; 4];
    recv.read_exact(&mut buf)
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
            )
            .await?;
        }
        RecordType::Statistics => {
            handle_data(
                send,
                recv,
                RecordType::Statistics,
                Some(gen_network_key(&source, "statistics")),
                source,
                db.statistics_store()?,
            )
            .await?;
        }
        RecordType::Oplog => {
            handle_data(
                send,
                recv,
                RecordType::Oplog,
                Some(gen_network_key(&source, "oplog")),
                source,
                db.oplog_store()?,
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
                        if sender_interval
                            .lock()
                            .await
                            .write_all(&last_timestamp.to_be_bytes())
                            .await
                            .is_err()
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
        match handle_body(&mut recv).await {
            Ok((raw_event, timestamp)) => {
                if (timestamp == CHANNEL_CLOSE_TIMESTAMP)
                    && (raw_event.as_bytes() == CHANNEL_CLOSE_MESSAGE)
                {
                    sender_rotation
                        .lock()
                        .await
                        .write_all(&timestamp.to_be_bytes())
                        .await?;
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
                    _ => key.extend_from_slice(&timestamp.to_be_bytes()),
                }
                store.append(&key, &raw_event)?;
                if let Some(network_key) = network_key.as_ref() {
                    send_direct_network_stream(network_key, &raw_event, timestamp).await?;
                }
                if store.flush().is_ok() {
                    ack_cnt_rotation.fetch_add(1, Ordering::SeqCst);
                    ack_time_rotation.store(timestamp, Ordering::SeqCst);
                    if ACK_ROTATION_CNT <= ack_cnt_rotation.load(Ordering::SeqCst) {
                        sender_rotation
                            .lock()
                            .await
                            .write_all(&timestamp.to_be_bytes())
                            .await?;
                        ack_cnt_rotation.store(0, Ordering::SeqCst);
                        tx.send(ITV_RESET).await?;
                    }
                }
            }
            Err(quinn::ReadExactError::FinishedEarly) => {
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

async fn handle_body(recv: &mut RecvStream) -> Result<(Vec<u8>, i64), quinn::ReadExactError> {
    let mut ts_buf = [0; mem::size_of::<u64>()];
    let mut len_buf = [0; mem::size_of::<u32>()];
    let mut body_buf = Vec::new();

    recv.read_exact(&mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;

    body_buf.resize(len, 0);
    recv.read_exact(body_buf.as_mut_slice()).await?;

    Ok((body_buf, timestamp))
}

pub async fn request_packets(
    connection: &quinn::Connection,
    filter: NetworkFilter,
) -> Result<Vec<String>> {
    let (mut send, mut recv) = connection.open_bi().await?;
    let record = bincode::serialize(&filter)?;
    let record_len = u64::try_from(record.len())?.to_le_bytes();
    let mut send_buf = Vec::with_capacity(record_len.len() + record.len());
    send_buf.extend_from_slice(&record_len);
    send_buf.extend_from_slice(&record);
    send.write_all(&send_buf)
        .await
        .map_err(|e| anyhow!("Failed to write record: {}", e))?;
    let mut req_len = [0; std::mem::size_of::<u64>()];
    let mut req_buf = Vec::new();
    recv.read_exact(&mut req_len).await?;
    let len = u64::from_le_bytes(req_len);

    req_buf.resize(len.try_into()?, 0);
    recv.read_exact(&mut req_buf).await?;
    let packets = bincode::deserialize::<Vec<String>>(&req_buf)?;
    Ok(packets)
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
                    sources.insert(source_key.clone(), timestamp);
                    if source_store.insert(&source_key, timestamp).is_err(){
                        error!("Failed to append Source store");
                    }
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
                    sources.write().await.insert(source_key.to_string(), timestamp_val);
                    if source_store.insert(&source_key, timestamp_val).is_err(){
                        error!("Failed to append Source store");
                    }
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
