#[cfg(test)]
mod tests;

use crate::graphql::TIMESTAMP_SIZE;
use crate::ingestion::{EventFilter, NetworkKey};
use crate::server::{certificate_info, config_server, server_handshake};
use crate::storage::{
    lower_closed_bound_key, upper_open_bound_key, Database, Direction, RawEventStore,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{NaiveDateTime, TimeZone, Utc};
use lazy_static::lazy_static;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Debug,
    mem,
    net::{IpAddr, SocketAddr},
};
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        RwLock,
    },
};
use tracing::{error, info};

const PUBLISH_VERSION_REQ: &str = ">=0.7.0-alpha.1 , <=0.7.0-alpha.2";

lazy_static! {
    pub static ref HOG_DIRECT_CHANNEL: RwLock<HashMap<String, UnboundedSender<Vec<u8>>>> =
        RwLock::new(HashMap::new());
}

enum REconvergeKindType {
    Conn,
    Dns,
    Rdp,
    Http,
    Log,
    Smtp,
    Ntlm,
    Kerberos,
    Ssh,
    DceRpc,
}

impl REconvergeKindType {
    fn convert_type(input: &str) -> REconvergeKindType {
        match input {
            "conn" => REconvergeKindType::Conn,
            "dns" => REconvergeKindType::Dns,
            "rdp" => REconvergeKindType::Rdp,
            "http" => REconvergeKindType::Http,
            "smtp" => REconvergeKindType::Smtp,
            "ntlm" => REconvergeKindType::Ntlm,
            "kerberos" => REconvergeKindType::Kerberos,
            "ssh" => REconvergeKindType::Ssh,
            "dce rpc" => REconvergeKindType::DceRpc,
            _ => REconvergeKindType::Log,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u32)]
enum StreamMessageCode {
    Conn = 0,
    Dns = 1,
    Rdp = 2,
    Http = 3,
    Log = 4,
    Smtp = 5,
    Ntlm = 6,
    Kerberos = 7,
    Ssh = 8,
    DceRpc = 9,
}

impl StreamMessageCode {
    fn convert_type(input: &str) -> Result<StreamMessageCode> {
        match input {
            "conn" => Ok(StreamMessageCode::Conn),
            "dns" => Ok(StreamMessageCode::Dns),
            "rdp" => Ok(StreamMessageCode::Rdp),
            "http" => Ok(StreamMessageCode::Http),
            "log" => Ok(StreamMessageCode::Log),
            "smtp" => Ok(StreamMessageCode::Smtp),
            "ntlm" => Ok(StreamMessageCode::Ntlm),
            "kerberos" => Ok(StreamMessageCode::Kerberos),
            "ssh" => Ok(StreamMessageCode::Ssh),
            "dce rpc" => Ok(StreamMessageCode::DceRpc),
            _ => Err(anyhow!("Faied to convert stream message code")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, PartialEq)]
#[repr(u8)]
enum NodeType {
    Hog = 0,
    Crusher = 1,
}

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, PartialEq)]
#[repr(u32)]
enum MessageCode {
    Log = 0,
    PeriodicTimeSeries = 1,
}

pub trait PubMessage {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>>;
    fn done() -> Result<Vec<u8>> {
        Ok(bincode::serialize::<Option<(i64, Vec<u8>)>>(&None)?)
    }
    fn convert_time_format(timestamp: i64) -> String {
        const A_BILLION: i64 = 1_000_000_000;
        let nsecs = u32::try_from(timestamp % A_BILLION).unwrap_or_default();
        NaiveDateTime::from_timestamp_opt(timestamp / A_BILLION, nsecs)
            .map_or("-".to_string(), |s| s.format("%s%.6f").to_string())
    }
}

trait StreamMessage {
    fn database_key(&self) -> Result<Vec<u8>>;
    fn channel_key(&self, source: Option<String>, msg_type: &str) -> Result<String>;
    fn start_time(&self) -> i64;
    fn filter_ip(&self, orig_addr: IpAddr, resp_addr: IpAddr) -> bool;
    fn source_id(&self) -> Option<String>;
}

#[derive(Debug, Serialize, Deserialize)]
struct HogStreamMessage {
    start: i64,
    source: Option<String>,
}

impl StreamMessage for HogStreamMessage {
    fn database_key(&self) -> Result<Vec<u8>> {
        if let Some(ref target_source) = self.source {
            let mut key_prefix: Vec<u8> = Vec::new();
            key_prefix.extend_from_slice(target_source.as_bytes());
            key_prefix.push(0);
            return Ok(key_prefix);
        }
        bail!("Failed to generate hog key, source is required.");
    }

    fn channel_key(&self, source: Option<String>, msg_type: &str) -> Result<String> {
        if let Some(ref target_source) = self.source {
            let mut hog_key = String::new();
            hog_key.push_str(&source.unwrap());
            hog_key.push('\0');
            hog_key.push_str(target_source);
            hog_key.push('\0');
            hog_key.push_str(msg_type);
            return Ok(hog_key);
        }
        bail!("Failed to generate hog channel key, source is required.");
    }

    fn start_time(&self) -> i64 {
        self.start
    }

    fn filter_ip(&self, _orig_addr: IpAddr, _resp_addr: IpAddr) -> bool {
        true
    }

    fn source_id(&self) -> Option<String> {
        self.source.clone()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CrusherStreamMessage {
    start: i64,
    id: String,
    src_ip: Option<IpAddr>,
    des_ip: Option<IpAddr>,
    source: Option<String>,
}

impl StreamMessage for CrusherStreamMessage {
    fn database_key(&self) -> Result<Vec<u8>> {
        if let Some(ref target_source) = self.source {
            let mut key_prefix: Vec<u8> = Vec::new();
            key_prefix.extend_from_slice(target_source.as_bytes());
            key_prefix.push(0);
            return Ok(key_prefix);
        }
        bail!("Failed to generate crusher key, source is required.");
    }

    fn channel_key(&self, _source: Option<String>, msg_type: &str) -> Result<String> {
        if let Some(ref target_source) = self.source {
            let mut crusher_key = String::new();
            crusher_key.push_str(&self.id);
            crusher_key.push('\0');
            crusher_key.push_str(target_source);
            crusher_key.push('\0');
            crusher_key.push_str(msg_type);
            return Ok(crusher_key);
        }
        bail!("Failed to generate crusher channel key, source is required.");
    }

    fn start_time(&self) -> i64 {
        self.start
    }

    fn filter_ip(&self, orig_addr: IpAddr, resp_addr: IpAddr) -> bool {
        match (self.src_ip, self.des_ip) {
            (Some(c_orig_addr), Some(c_resp_addr)) => {
                if c_orig_addr == orig_addr && c_resp_addr == resp_addr {
                    return true;
                }
            }
            (None, Some(c_resp_addr)) => {
                if c_resp_addr == resp_addr {
                    return true;
                }
            }
            (Some(c_orig_addr), None) => {
                if c_orig_addr == orig_addr {
                    return true;
                }
            }
            (None, None) => {
                return true;
            }
        }
        false
    }

    fn source_id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

pub trait RequestMessage {
    fn source(&self) -> &str;
    fn kind(&self) -> &str;
    fn start(&self) -> i64;
    fn end(&self) -> i64;
    fn count(&self) -> usize;
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    source: String, //certification name
    kind: String,
    start: i64,
    end: i64,
    count: usize,
}

impl RequestMessage for Message {
    fn source(&self) -> &str {
        &self.source
    }
    fn kind(&self) -> &str {
        &self.kind
    }
    fn start(&self) -> i64 {
        self.start
    }
    fn end(&self) -> i64 {
        self.end
    }
    fn count(&self) -> usize {
        self.count
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TimeSeriesMessage {
    source: String, //sampling policy id
    start: i64,
    end: i64,
    count: usize,
}

impl RequestMessage for TimeSeriesMessage {
    fn source(&self) -> &str {
        &self.source
    }
    fn kind(&self) -> &str {
        ""
    }
    fn start(&self) -> i64 {
        self.start
    }
    fn end(&self) -> i64 {
        self.end
    }
    fn count(&self) -> usize {
        self.count
    }
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

        while let Some(conn) = endpoint.accept().await {
            let db = db.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, db).await {
                    error!("connection failed: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(conn: quinn::Connecting, db: Database) -> Result<()> {
    let connection = conn.await?;
    let stream = connection.accept_bi().await;

    let (mut send, mut recv) = stream?;
    if let Err(e) = server_handshake(&mut send, &mut recv, PUBLISH_VERSION_REQ).await {
        let err = format!("Handshake fail: {}", e);
        send.finish().await?;
        connection.close(quinn::VarInt::from_u32(0), err.as_bytes());
        bail!(err);
    }

    let source = certificate_info(&connection)?;
    tokio::spawn(request_network_stream(
        connection.clone(),
        db.clone(),
        recv,
        source,
    ));

    async {
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };

            let db = db.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_request(stream, db).await {
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
    (mut send, mut recv): (SendStream, RecvStream),
    db: Database,
) -> Result<()> {
    let (msg_type, msg_buf) = handle_request_message(&mut recv).await?;
    match msg_type {
        MessageCode::Log => {
            let msg = bincode::deserialize::<Message>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deseralize message: {}", e))?;
            match REconvergeKindType::convert_type(&msg.kind) {
                REconvergeKindType::Conn => {
                    process_response_message(
                        &mut send,
                        db.conn_store().context("Failed to open conn store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Dns => {
                    process_response_message(
                        &mut send,
                        db.dns_store().context("Failed to open dns store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Rdp => {
                    process_response_message(
                        &mut send,
                        db.rdp_store().context("Failed to open rdp store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Http => {
                    process_response_message(
                        &mut send,
                        db.http_store().context("Failed to open http store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Smtp => {
                    process_response_message(
                        &mut send,
                        db.smtp_store().context("Failed to open smtp store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Log => {
                    process_response_message(
                        &mut send,
                        db.log_store().context("Failed to open log store")?,
                        msg,
                        true,
                    )
                    .await?;
                }
                REconvergeKindType::Ntlm => {
                    process_response_message(
                        &mut send,
                        db.ntlm_store().context("Failed to open ntlm store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Kerberos => {
                    process_response_message(
                        &mut send,
                        db.kerberos_store()
                            .context("Failed to open kerberos store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::Ssh => {
                    process_response_message(
                        &mut send,
                        db.ssh_store().context("Failed to open ssh store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
                REconvergeKindType::DceRpc => {
                    process_response_message(
                        &mut send,
                        db.dce_rpc_store().context("Failed to open dce rpc store")?,
                        msg,
                        false,
                    )
                    .await?;
                }
            }
        }
        MessageCode::PeriodicTimeSeries => {
            let msg = bincode::deserialize::<TimeSeriesMessage>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deseralize timeseries message: {}", e))?;
            process_response_message(
                &mut send,
                db.periodic_time_series_store()
                    .context("Failed to open periodic time series storage")?,
                msg,
                false,
            )
            .await?;
        }
    }
    Ok(())
}

async fn handle_request_message(recv: &mut RecvStream) -> Result<(MessageCode, Vec<u8>)> {
    let mut buf = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow!("Failed to read message code: {}", e))?;

    let msg_type = MessageCode::try_from(u32::from_le_bytes(buf)).context("unknown record type")?;

    let mut frame_length = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut frame_length)
        .await
        .map_err(|e| anyhow!("Failed to read frame length: {}", e))?;
    let len = u32::from_le_bytes(frame_length);

    let mut rest_buf = vec![0; len.try_into()?];
    recv.read_exact(&mut rest_buf)
        .await
        .map_err(|e| anyhow!("Failed to read rest of request: {}", e))?;

    Ok((msg_type, rest_buf))
}

async fn handle_response_message(send: &mut SendStream, record: Vec<u8>) -> Result<()> {
    let record_len = u32::try_from(record.len())?.to_le_bytes();
    let mut send_buf = Vec::with_capacity(record_len.len() + record.len());
    send_buf.extend_from_slice(&record_len);
    send_buf.extend_from_slice(&record);
    send.write_all(&send_buf)
        .await
        .map_err(|e| anyhow!("Failed to write record: {}", e))?;
    Ok(())
}

async fn process_response_message<'c, T, K>(
    send: &mut SendStream,
    store: RawEventStore<'c, T>,
    msg: K,
    availd_kind: bool,
) -> Result<()>
where
    T: DeserializeOwned + PubMessage,
    K: RequestMessage,
{
    let mut key_prefix = Vec::new();
    key_prefix.extend_from_slice(msg.source().as_bytes());
    key_prefix.push(0);
    if availd_kind {
        key_prefix.extend_from_slice(msg.kind().as_bytes());
        key_prefix.push(0);
    }
    let iter = store.boundary_iter(
        &lower_closed_bound_key(&key_prefix, Some(Utc.timestamp_nanos(msg.start()))),
        &upper_open_bound_key(&key_prefix, Some(Utc.timestamp_nanos(msg.end()))),
        Direction::Forward,
    );

    for item in iter.take(msg.count()) {
        let (key, val) = item.context("Failed to read Database")?;
        let timestamp = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        handle_response_message(send, val.message(timestamp, msg.source())?).await?;
    }
    handle_response_message(send, T::done()?).await?;
    send.finish().await?;
    Ok(())
}

async fn handle_stream_request(
    recv: &mut RecvStream,
) -> Result<(NodeType, StreamMessageCode, Vec<u8>)> {
    let mut type_buf = [0; mem::size_of::<u8>()];
    recv.read_exact(&mut type_buf)
        .await
        .map_err(|e| anyhow!("Failed to read Node Type: {}", e))?;
    let node_type = NodeType::try_from(u8::from_le_bytes(type_buf)).context("unknown Node type")?;

    let mut code_buf = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut code_buf)
        .await
        .map_err(|e| anyhow!("Failed to read message code: {}", e))?;

    let msg_type =
        StreamMessageCode::try_from(u32::from_le_bytes(code_buf)).context("unknown record type")?;

    let mut frame_length = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut frame_length)
        .await
        .map_err(|e| anyhow!("Failed to read frame length: {}", e))?;
    let len = u32::from_le_bytes(frame_length);

    let mut rest_buf = vec![0; len.try_into()?];
    recv.read_exact(&mut rest_buf)
        .await
        .map_err(|e| anyhow!("Failed to read rest of request: {}", e))?;
    Ok((node_type, msg_type, rest_buf))
}

pub async fn send_direct_network_stream(
    network_key: &NetworkKey,
    raw_event: &Vec<u8>,
    timestamp: i64,
) -> Result<()> {
    for (req_key, sender) in HOG_DIRECT_CHANNEL.read().await.iter() {
        if req_key.contains(&network_key.source_key) || req_key.contains(&network_key.all_key) {
            let raw_len = u32::try_from(raw_event.len())?.to_le_bytes();
            let mut send_buf: Vec<u8> = Vec::new();
            send_buf.extend_from_slice(&timestamp.to_le_bytes());
            send_buf.extend_from_slice(&raw_len);
            send_buf.extend_from_slice(raw_event);
            sender.send(send_buf)?;
        }
    }
    Ok(())
}

async fn send_network_stream<T, N>(
    store: RawEventStore<'_, T>,
    conn: Connection,
    msg_type: &str,
    msg: N,
    source: Option<String>,
    node_type: NodeType,
) -> Result<()>
where
    T: EventFilter + Serialize + DeserializeOwned,
    N: StreamMessage,
{
    let mut sender = conn.open_uni().await?;
    let db_key_prefix = msg.database_key()?;
    let channel_key = msg.channel_key(source, msg_type)?;

    let (send, mut recv) = unbounded_channel::<Vec<u8>>();
    let channel_remove_key = channel_key.clone();

    HOG_DIRECT_CHANNEL.write().await.insert(channel_key, send);
    let mut last_ts = 0_i64;

    match node_type {
        NodeType::Hog => {
            let proto: u32 = StreamMessageCode::convert_type(msg_type)?.into();
            sender
                .write_all(&proto.to_le_bytes())
                .await
                .map_err(|e| anyhow!("Failed to write hog start mesaage: {}", e))?;
            info!("start hog's publish Stream : {:?}", msg_type);
        }
        NodeType::Crusher => {
            // crusher's policy Id always exists.
            let id = msg.source_id().unwrap();
            let id = id.as_bytes();
            let id_len = u32::try_from(id.len())?.to_le_bytes();
            let mut send_buf = Vec::with_capacity(id_len.len() + id.len());
            send_buf.extend_from_slice(&id_len);
            send_buf.extend_from_slice(id);

            sender
                .write_all(&send_buf)
                .await
                .map_err(|e| anyhow!("Failed to write crusher start mesaage: {}", e))?;
            info!("start cruhser's publish Stream : {:?}", msg_type);

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
                    let stream_data = bincode::serialize(&val)?;
                    let stream_len = u32::try_from(stream_data.len())?.to_le_bytes();

                    let mut send_buf: Vec<u8> = Vec::new();
                    send_buf.extend_from_slice(&timestamp.to_le_bytes());
                    send_buf.extend_from_slice(&stream_len);
                    send_buf.extend_from_slice(&stream_data);
                    sender.write_all(&send_buf).await?;
                    last_ts = timestamp;
                }
            }
        }
    }

    tokio::spawn(async move {
        loop {
            select! {
                Some(buf) = recv.recv() => {
                    let ts = i64::from_le_bytes(buf.get(..TIMESTAMP_SIZE).expect("timestamp_size").try_into().expect("timestamp"));
                    if last_ts > ts {
                        continue;
                    }
                    if sender.write_all(&buf).await.is_err(){
                        HOG_DIRECT_CHANNEL
                        .write()
                        .await
                        .remove(&channel_remove_key);
                        break;
                    }
                }
                else => break,
            }
        }
    });
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn process_network_stream<T>(
    db: Database,
    conn: Connection,
    source: Option<String>,
    node_type: NodeType,
    msg_type: StreamMessageCode,
    msg: T,
) -> Result<()>
where
    T: StreamMessage,
{
    match msg_type {
        StreamMessageCode::Conn => {
            if let Ok(store) = db.conn_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "conn", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open conn store");
            }
        }
        StreamMessageCode::Dns => {
            if let Ok(store) = db.dns_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "dns", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open dns store");
            }
        }
        StreamMessageCode::Rdp => {
            if let Ok(store) = db.rdp_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "rdp", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open rdp store");
            }
        }
        StreamMessageCode::Http => {
            if let Ok(store) = db.http_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "http", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open http store");
            }
        }
        StreamMessageCode::Log => {
            if let Ok(store) = db.log_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "log", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open log store");
            }
        }
        StreamMessageCode::Smtp => {
            if let Ok(store) = db.smtp_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "smtp", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open smtp store");
            }
        }
        StreamMessageCode::Ntlm => {
            if let Ok(store) = db.ntlm_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "ntlm", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open ntlm store");
            }
        }
        StreamMessageCode::Kerberos => {
            if let Ok(store) = db.kerberos_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "kerberos", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open kerberos store");
            }
        }
        StreamMessageCode::Ssh => {
            if let Ok(store) = db.ssh_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "ssh", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open ssh store");
            }
        }
        StreamMessageCode::DceRpc => {
            if let Ok(store) = db.dce_rpc_store() {
                if let Err(e) =
                    send_network_stream(store, conn, "dce rpc", msg, source, node_type).await
                {
                    error!("Failed to send network stream : {}", e);
                }
            } else {
                error!("Failed to open dce rpc store");
            }
        }
    };
    Ok(())
}

async fn request_network_stream(
    connection: Connection,
    stream_db: Database,
    mut recv: RecvStream,
    conn_source: String,
) -> Result<()> {
    loop {
        match handle_stream_request(&mut recv).await {
            Ok((node_type, msg_type, raw_data)) => {
                let db = stream_db.clone();
                let conn = connection.clone();
                let source = conn_source.clone();
                tokio::spawn(async move {
                    match node_type {
                        NodeType::Hog => {
                            match bincode::deserialize::<HogStreamMessage>(&raw_data) {
                                Ok(msg) => {
                                    if let Err(e) = process_network_stream(
                                        db,
                                        conn,
                                        Some(source),
                                        node_type,
                                        msg_type,
                                        msg,
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
                            match bincode::deserialize::<CrusherStreamMessage>(&raw_data) {
                                Ok(msg) => {
                                    if let Err(e) = process_network_stream(
                                        db, conn, None, node_type, msg_type, msg,
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
            Err(e) => {
                error!("{}", e);
                break;
            }
        }
    }
    Ok(())
}
