use crate::graphql::TIMESTAMP_SIZE;
use crate::ingestion::server_handshake;
use crate::storage::{
    lower_closed_bound_key, upper_open_bound_key, Database, Direction, RawEventStore,
};
use anyhow::{anyhow, Context, Result};
use chrono::{TimeZone, Utc};
use futures_util::StreamExt;
use num_enum::TryFromPrimitive;
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use std::{mem, net::SocketAddr, sync::Arc};
use tracing::{error, info};

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
        let (endpoint, mut incoming) =
            Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        info!(
            "listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        while let Some(conn) = incoming.next().await {
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
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;

    server_handshake(&connection, &mut bi_streams).await?;

    async {
        while let Some(stream) = bi_streams.next().await {
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
        Ok(())
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
                RawEventStore::log_iter,
                msg,
            )
            .await?;
        }
        MessageCode::PeriodicTimeSeries => {
            process_response_message(
                &mut send,
                db.periodic_time_series_store()
                    .context("Failed to open periodic time series storage")?,
                RawEventStore::period_time_iter,
                msg,
            )
            .await?;
        }
    }
    Ok(())
}

fn config_server(
    certs: Vec<Certificate>,
    key: PrivateKey,
    files: Vec<Vec<u8>>,
) -> Result<ServerConfig> {
    let mut client_auth_roots = rustls::RootCertStore::empty();
    for file in files {
        let root_cert: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*file)
            .context("invalid PEM-encoded certificate")?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        if let Some(cert) = root_cert.get(0) {
            client_auth_roots.add(cert)?;
        }
    }
    let client_auth = rustls::server::AllowAnyAuthenticatedClient::new(client_auth_roots);
    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs, key)?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
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

async fn process_response_message<'c, I, T>(
    send: &mut SendStream,
    store: RawEventStore<'c>,
    iter_builder: fn(&RawEventStore<'c>, &[u8], &[u8], Direction) -> I,
    msg: Message,
) -> Result<()>
where
    I: Iterator<Item = anyhow::Result<(Box<[u8]>, T)>> + 'c,
    T: PubMessage,
{
    let mut key_prefix = Vec::with_capacity(msg.source.len() + msg.kind.len() + 2);
    key_prefix.extend_from_slice(msg.source.as_bytes());
    key_prefix.push(0);
    key_prefix.extend_from_slice(msg.kind.as_bytes());
    key_prefix.push(0);

    let mut iter = iter_builder(
        &store,
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
