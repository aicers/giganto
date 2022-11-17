#[cfg(test)]
mod tests;

use crate::graphql::network::NetworkFilter;
use crate::publish::{send_direct_network_stream, PubMessage};
use crate::server::{certificate_info, config_server, server_handshake};
use crate::storage::{Database, RawEventStore};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use num_enum::TryFromPrimitive;
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
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
    sync::Mutex,
    task, time,
};
use tracing::{error, info};
use x509_parser::nom::AsBytes;

const ACK_ROTATION_CNT: u8 = 128;
const ACK_INTERVAL_TIME: u64 = 60 * 60;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const ITV_RESET: bool = true;
const NO_TIMESTAMP: i64 = 0;
const SOURCE_INTERVAL: u64 = 60 * 60 * 24;
const INGESTION_VERSION_REQ: &str = "0.5";

type Sources = (String, DateTime<Utc>, bool);

lazy_static! {
    pub static ref SOURCES: Mutex<HashMap<String, DateTime<Utc>>> = Mutex::new(HashMap::new());
    pub static ref PACKET_SOURCES: Mutex<HashMap<String, Connection>> = Mutex::new(HashMap::new());
}

pub trait EventFilter {
    fn orig_addr(&self) -> Option<IpAddr>;
    fn resp_addr(&self) -> Option<IpAddr>;
    fn orig_port(&self) -> Option<u16>;
    fn resp_port(&self) -> Option<u16>;
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Conn {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
}

impl EventFilter for Conn {
    fn orig_addr(&self) -> Option<IpAddr> {
        Some(self.orig_addr)
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        Some(self.resp_addr)
    }
    fn orig_port(&self) -> Option<u16> {
        Some(self.orig_port)
    }
    fn resp_port(&self) -> Option<u16> {
        Some(self.resp_port)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsConn {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub proto: u8,
    pub query: String,
    pub answer: Vec<IpAddr>,
}

impl EventFilter for DnsConn {
    fn orig_addr(&self) -> Option<IpAddr> {
        Some(self.orig_addr)
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        Some(self.resp_addr)
    }
    fn orig_port(&self) -> Option<u16> {
        Some(self.orig_port)
    }
    fn resp_port(&self) -> Option<u16> {
        Some(self.resp_port)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpConn {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
    pub user_agent: String,
    pub status_code: u16,
}

impl EventFilter for HttpConn {
    fn orig_addr(&self) -> Option<IpAddr> {
        Some(self.orig_addr)
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        Some(self.resp_addr)
    }
    fn orig_port(&self) -> Option<u16> {
        Some(self.orig_port)
    }
    fn resp_port(&self) -> Option<u16> {
        Some(self.resp_port)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RdpConn {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub cookie: String,
}

impl EventFilter for RdpConn {
    fn orig_addr(&self) -> Option<IpAddr> {
        Some(self.orig_addr)
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        Some(self.resp_addr)
    }
    fn orig_port(&self) -> Option<u16> {
        Some(self.orig_port)
    }
    fn resp_port(&self) -> Option<u16> {
        Some(self.resp_port)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub kind: String,
    pub log: Vec<u8>,
}

impl EventFilter for Log {
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
}

impl PubMessage for Log {
    fn message(&self, timestamp: i64) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&Some((timestamp, &self.log)))?)
    }
    fn done() -> Result<Vec<u8>> {
        Ok(bincode::serialize::<Option<(i64, Vec<u8>)>>(&None)?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeriodicTimeSeries {
    kind: String,
    start: i64,
    data: PeriodicTimeSeriesData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeriodicTimeSeriesData {
    period: i64,
    data: Vec<f64>,
}

impl PubMessage for PeriodicTimeSeriesData {
    fn message(&self, timestamp: i64) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&Some((timestamp, &self.data)))?)
    }
    fn done() -> Result<Vec<u8>> {
        Ok(bincode::serialize::<Option<(i64, Vec<f64>)>>(&None)?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SmtpConn {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
}

impl EventFilter for SmtpConn {
    fn orig_addr(&self) -> Option<IpAddr> {
        Some(self.orig_addr)
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        Some(self.resp_addr)
    }
    fn orig_port(&self) -> Option<u16> {
        Some(self.orig_port)
    }
    fn resp_port(&self) -> Option<u16> {
        Some(self.resp_port)
    }
}

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, PartialEq)]
#[repr(u32)]
enum RecordType {
    Conn = 0,
    Dns = 1,
    Log = 2,
    Http = 3,
    Rdp = 4,
    PeriodicTimeSeries = 5,
    Smtp = 6,
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

    pub async fn run(self, db: Database) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        info!(
            "listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        let (tx, rx): (Sender<Sources>, Receiver<Sources>) = channel(100);
        let source_db = db.clone();
        task::spawn(check_sources_conn(source_db, rx));

        while let Some(conn) = endpoint.accept().await {
            let sender = tx.clone();
            let db = db.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, db, sender).await {
                    error!("connection failed: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    conn: quinn::Connecting,
    db: Database,
    sender: Sender<Sources>,
) -> Result<()> {
    let connection = conn.await?;

    let stream = connection.accept_bi().await;
    let (mut send, mut recv) = stream?;
    if let Err(e) = server_handshake(&mut send, &mut recv, INGESTION_VERSION_REQ).await {
        let err = format!("Handshake fail: {}", e);
        send.finish().await?;
        connection.close(quinn::VarInt::from_u32(0), err.as_bytes());
        bail!(err);
    }
    send.finish().await?;

    let source = certificate_info(&connection)?;

    PACKET_SOURCES
        .lock()
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
            handle_data(send, recv, RecordType::Log, None, source, db.log_store()?).await?;
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
    };
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_data<T>(
    send: SendStream,
    mut recv: RecvStream,
    record_type: RecordType,
    network_key: Option<String>,
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
            Ok((mut raw_event, timestamp)) => {
                let mut key: Vec<u8> = Vec::new();
                key.extend_from_slice(source.as_bytes());
                key.push(0);
                match record_type {
                    RecordType::Log => {
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
                        key.extend_from_slice(
                            bincode::deserialize::<Log>(&raw_event)?.kind.as_bytes(),
                        );
                        key.push(0);
                        key.extend_from_slice(&timestamp.to_be_bytes());
                    }
                    RecordType::PeriodicTimeSeries => {
                        let periodic_time_series =
                            bincode::deserialize::<PeriodicTimeSeries>(&raw_event)?;
                        key.extend_from_slice(periodic_time_series.kind.as_bytes());
                        key.push(0);
                        key.extend_from_slice(&periodic_time_series.start.to_be_bytes());
                        raw_event = bincode::serialize(&(
                            periodic_time_series.data.period,
                            periodic_time_series.data.data,
                        ))?;
                    }
                    _ => key.extend_from_slice(&timestamp.to_be_bytes()),
                }
                store.append(&key, &raw_event)?;
                if let Some(key) = network_key.as_ref() {
                    send_direct_network_stream(key, &raw_event, timestamp).await?;
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

async fn check_sources_conn(source_db: Database, mut rx: Receiver<Sources>) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(SOURCE_INTERVAL));
    itv.reset();
    let source_store = source_db
        .sources_store()
        .expect("Failed to open source store");
    loop {
        select! {
            _ = itv.tick() => {
                let mut sources = SOURCES.lock().await;
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
                if is_close{
                    if source_store.insert(&source_key, timestamp_val).is_err(){
                        error!("Failed to append Source store");
                    }
                    SOURCES.lock().await.remove(&source_key);
                    PACKET_SOURCES.lock().await.remove(&source_key);
                }else{
                    SOURCES.lock().await.insert(source_key.to_string(), timestamp_val);
                    if source_store.insert(&source_key, timestamp_val).is_err(){
                        error!("Failed to append Source store");
                    }
                }

            }
        }
    }
}

pub fn gen_network_key(source: &str, record: &str) -> String {
    let mut network_key = String::new();
    network_key.push_str(source);
    network_key.push('\0');
    network_key.push_str(record);
    network_key
}
