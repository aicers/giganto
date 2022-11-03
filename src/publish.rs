#[cfg(test)]
mod tests;

use crate::graphql::TIMESTAMP_SIZE;
use crate::server::{certificate_info, config_server, server_handshake};
use crate::storage::{
    lower_closed_bound_key, upper_open_bound_key, Database, Direction, RawEventStore,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{TimeZone, Utc};
use lazy_static::lazy_static;
use num_enum::TryFromPrimitive;
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::{mem, net::SocketAddr};
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        RwLock,
    },
};
use tracing::{error, info};

const PUBLISH_COMPATIBLE_MIN_VERSION: &str = "0.4.0";
const PUBLISH_COMPATIBLE_MAX_VERSION: &str = "0.5.0";

lazy_static! {
    pub static ref HOG_DIRECT_CHANNEL: RwLock<HashMap<String, UnboundedSender<Vec<u8>>>> =
        RwLock::new(HashMap::new());
}

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, PartialEq)]
#[repr(u32)]
enum StreamMessageCode {
    Conn = 0,
    Dns = 1,
    Rdp = 2,
    Http = 3,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamMessage {
    source: String,
    start: i64,
}

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, PartialEq)]
#[repr(u32)]
enum MessageCode {
    Log = 0,
    PeriodicTimeSeries = 1,
}

pub trait PubMessage {
    fn message(&self, timestamp: i64) -> Result<Vec<u8>>;
    fn done() -> Result<Vec<u8>>;
}

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    source: String,
    kind: String,
    start: i64,
    end: i64,
    count: usize,
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
    if let Err(e) = server_handshake(
        &mut send,
        &mut recv,
        PUBLISH_COMPATIBLE_MIN_VERSION,
        PUBLISH_COMPATIBLE_MAX_VERSION,
    )
    .await
    {
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

async fn handle_request(
    (mut send, mut recv): (SendStream, RecvStream),
    db: Database,
) -> Result<()> {
    let (msg_type, msg) = handle_request_message(&mut recv).await?;
    match msg_type {
        MessageCode::Log => {
            process_response_message(
                &mut send,
                db.log_store().context("Failed to open log store")?,
                msg,
            )
            .await?;
        }
        MessageCode::PeriodicTimeSeries => {
            process_response_message(
                &mut send,
                db.periodic_time_series_store()
                    .context("Failed to open periodic time series storage")?,
                msg,
            )
            .await?;
        }
    }
    Ok(())
}

async fn handle_request_message(recv: &mut RecvStream) -> Result<(MessageCode, Message)> {
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

    let msg = bincode::deserialize::<Message>(&rest_buf)
        .map_err(|e| anyhow!("Failed to deseralize message: {}", e))?;
    Ok((msg_type, msg))
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

async fn process_response_message<'c, T>(
    send: &mut SendStream,
    store: RawEventStore<'c, T>,
    msg: Message,
) -> Result<()>
where
    T: DeserializeOwned + PubMessage,
{
    let mut key_prefix = Vec::with_capacity(msg.source.len() + msg.kind.len() + 2);
    key_prefix.extend_from_slice(msg.source.as_bytes());
    key_prefix.push(0);
    key_prefix.extend_from_slice(msg.kind.as_bytes());
    key_prefix.push(0);

    let mut iter = store.boundary_iter(
        &lower_closed_bound_key(&key_prefix, Some(Utc.timestamp_nanos(msg.start))),
        &upper_open_bound_key(&key_prefix, Some(Utc.timestamp_nanos(msg.end))),
        Direction::Forward,
    );

    let mut size = msg.count;
    for item in &mut iter {
        let (key, val) = item.context("Failed to read Database")?;
        let timestamp = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        handle_response_message(send, val.message(timestamp)?).await?;
        size -= 1;
        if size == 0 {
            break;
        }
    }
    handle_response_message(send, T::done()?).await?;
    send.finish().await?;
    Ok(())
}

async fn handle_stream_request(
    recv: &mut RecvStream,
) -> Result<(StreamMessageCode, StreamMessage)> {
    let mut buf = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow!("Failed to read message code: {}", e))?;

    let msg_type =
        StreamMessageCode::try_from(u32::from_le_bytes(buf)).context("unknown record type")?;

    let mut frame_length = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut frame_length)
        .await
        .map_err(|e| anyhow!("Failed to read frame length: {}", e))?;
    let len = u32::from_le_bytes(frame_length);

    let mut rest_buf = vec![0; len.try_into()?];
    recv.read_exact(&mut rest_buf)
        .await
        .map_err(|e| anyhow!("Failed to read rest of request: {}", e))?;

    let msg = bincode::deserialize::<StreamMessage>(&rest_buf)
        .map_err(|e| anyhow!("Failed to deseralize message: {}", e))?;
    Ok((msg_type, msg))
}

pub async fn send_direct_network_stream(
    network_key: &str,
    raw_event: &Vec<u8>,
    timestamp: i64,
) -> Result<()> {
    for (key, sender) in HOG_DIRECT_CHANNEL.read().await.iter() {
        if key.contains(network_key) {
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

async fn send_network_stream<T>(
    store: RawEventStore<'_, T>,
    conn: Connection,
    msg_type: &str,
    msg: StreamMessage,
    hog_source: String,
) -> Result<()>
where
    T: DeserializeOwned,
{
    let mut sender = conn.open_uni().await?;
    let mut key_prefix = Vec::with_capacity(&msg.source.len() + 1);
    key_prefix.extend_from_slice(msg.source.as_bytes());
    key_prefix.push(0);

    let mut hog_key = String::new();
    hog_key.push_str(&hog_source);
    hog_key.push('\0');
    hog_key.push_str(&msg.source);
    hog_key.push('\0');
    hog_key.push_str(msg_type);

    let (send, mut recv) = unbounded_channel::<Vec<u8>>();
    let hog_remove_key = hog_key.clone();
    tokio::spawn(async move {
        loop {
            select! {
                Some(buf) = recv.recv() => {
                    if sender.write_all(&buf).await.is_err(){
                        HOG_DIRECT_CHANNEL
                        .write()
                        .await
                        .remove(&hog_remove_key);
                        break;
                    }
                }
            }
        }
    });

    HOG_DIRECT_CHANNEL
        .write()
        .await
        .insert(hog_key, send.clone());

    let iter = store.iter(&lower_closed_bound_key(
        &key_prefix,
        Some(Utc.timestamp_nanos(msg.start)),
    ));

    for item in iter {
        let (key, val) = item.context("Failed to read Database")?;
        let timestamp = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        let stream_data = val.to_vec();

        let stream_len = u32::try_from(stream_data.len())?.to_le_bytes();

        let mut send_buf: Vec<u8> = Vec::new();
        send_buf.extend_from_slice(&timestamp.to_le_bytes());
        send_buf.extend_from_slice(&stream_len);
        send_buf.extend_from_slice(&stream_data);
        send.send(send_buf)?;
    }
    Ok(())
}

async fn request_network_stream(
    connection: Connection,
    stream_db: Database,
    mut recv: RecvStream,
    hog_source: String,
) -> Result<()> {
    loop {
        match handle_stream_request(&mut recv).await {
            Ok((msg_type, msg)) => {
                let db = stream_db.clone();
                let conn = connection.clone();
                let source = hog_source.clone();
                tokio::spawn(async move {
                    match msg_type {
                        StreamMessageCode::Conn => {
                            if let Ok(store) = db.conn_store() {
                                if let Err(e) =
                                    send_network_stream(store, conn, "conn", msg, source).await
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
                                    send_network_stream(store, conn, "dns", msg, source).await
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
                                    send_network_stream(store, conn, "rdp", msg, source).await
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
                                    send_network_stream(store, conn, "http", msg, source).await
                                {
                                    error!("Failed to send network stream : {}", e);
                                }
                            } else {
                                error!("Failed to open http store");
                            }
                        }
                    };
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
