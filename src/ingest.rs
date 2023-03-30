pub mod implement;
#[cfg(test)]
mod tests;

use crate::publish::send_direct_stream;
use crate::server::{
    certificate_info, config_server, SERVER_CONNNECTION_DELAY, SERVER_ENDPOINT_DELAY,
};
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
        atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    select,
    sync::{
        mpsc::{channel, Receiver, Sender, UnboundedSender},
        Mutex, Notify, RwLock,
    },
    task, time,
    time::sleep,
};
use tracing::{error, info};
use x509_parser::nom::AsBytes;

const ACK_ROTATION_CNT: u8 = 128;
const ACK_INTERVAL_TIME: u64 = 60;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const NO_TIMESTAMP: i64 = 0;
const SOURCE_INTERVAL: u64 = 60 * 60 * 24;
const INGEST_VERSION_REQ: &str = ">=0.8.0-reproduce, <0.9.0";

type SourceInfo = (String, DateTime<Utc>, ConnState, bool);
pub type PacketSources = Arc<RwLock<HashMap<String, Connection>>>;
pub type Sources = Arc<RwLock<HashMap<String, DateTime<Utc>>>>;
pub type StreamDirectChannel = Arc<RwLock<HashMap<String, UnboundedSender<Vec<u8>>>>>;

enum ConnState {
    Connected,
    Disconnected,
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

    pub async fn run(
        self,
        db: Database,
        packet_sources: PacketSources,
        sources: Sources,
        stream_direct_channel: StreamDirectChannel,
        wait_shutdown: Arc<Notify>,
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

        let shutdown_signal = Arc::new(AtomicBool::new(false));

        loop {
            select! {
                Some(conn) = endpoint.accept()  => {
                    let sender = tx.clone();
                    let db = db.clone();
                    let packet_sources = packet_sources.clone();
                    let stream_direct_channel = stream_direct_channel.clone();
                    let shutdown_notify = wait_shutdown.clone();
                    let shutdown_sig = shutdown_signal.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(conn, db, packet_sources, sender, stream_direct_channel,shutdown_notify,shutdown_sig).await
                        {
                            error!("connection failed: {}", e);
                        }
                    });
                },
                _ = wait_shutdown.notified() => {
                    shutdown_signal.store(true,Ordering::SeqCst); // Setting signal to handle termination on each channel.
                    sleep(Duration::from_millis(SERVER_ENDPOINT_DELAY)).await;      // Wait time for channels,connection to be ready for shutdown.
                    endpoint.close(0_u32.into(), &[]);
                    info!("Shutting down ingest");
                    wait_shutdown.notify_one();
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
    sender: Sender<SourceInfo>,
    stream_direct_channel: StreamDirectChannel,
    wait_shutdown: Arc<Notify>,
    shutdown_signal: Arc<AtomicBool>,
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

    if let Err(error) = sender
        .send((source.clone(), Utc::now(), ConnState::Connected, rep))
        .await
    {
        error!("Failed to send channel data : {}", error);
    }
    loop {
        select! {
            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(conn_err) => {
                        if let Err(error) = sender
                            .send((source, Utc::now(), ConnState::Disconnected, rep))
                            .await
                        {
                            error!("Failed to send internal channel data : {}", error);
                        }
                        match conn_err {
                            quinn::ConnectionError::ApplicationClosed(_) => {
                                info!("application closed");
                                return Ok(());
                            }
                            _ => return Err(conn_err.into()),
                        }
                    }
                    Ok(s) => s,
                };
                let source = source.clone();
                let db = db.clone();
                let stream_direct_channel = stream_direct_channel.clone();
                let shutdown_signal = shutdown_signal.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(source, stream, db, stream_direct_channel,shutdown_signal).await {
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

#[allow(clippy::too_many_lines)]
async fn handle_request(
    source: String,
    (send, mut recv): (SendStream, RecvStream),
    db: Database,
    stream_direct_channel: StreamDirectChannel,
    shutdown_signal: Arc<AtomicBool>,
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
                Some(NetworkKey::new(&source, "conn")),
                source,
                db.conn_store()?,
                stream_direct_channel,
                shutdown_signal,
            )
            .await?;
        }
        RecordType::Dns => {
            handle_data(
                send,
                recv,
                RecordType::Dns,
                Some(NetworkKey::new(&source, "dns")),
                source,
                db.dns_store()?,
                stream_direct_channel,
                shutdown_signal,
            )
            .await?;
        }
        RecordType::Log => {
            handle_data(
                send,
                recv,
                RecordType::Log,
                Some(NetworkKey::new(&source, "log")),
                source,
                db.log_store()?,
                stream_direct_channel,
                shutdown_signal,
            )
            .await?;
        }
        RecordType::Http => {
            handle_data(
                send,
                recv,
                RecordType::Http,
                Some(NetworkKey::new(&source, "http")),
                source,
                db.http_store()?,
                stream_direct_channel,
                shutdown_signal,
            )
            .await?;
        }
        RecordType::Rdp => {
            handle_data(
                send,
                recv,
                RecordType::Rdp,
                Some(NetworkKey::new(&source, "rdp")),
                source,
                db.rdp_store()?,
                stream_direct_channel,
                shutdown_signal,
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
                shutdown_signal,
            )
            .await?;
        }
        RecordType::Smtp => {
            handle_data(
                send,
                recv,
                RecordType::Smtp,
                Some(NetworkKey::new(&source, "smtp")),
                source,
                db.smtp_store()?,
                stream_direct_channel,
                shutdown_signal,
            )
            .await?;
        }
        RecordType::Ntlm => {
            handle_data(
                send,
                recv,
                RecordType::Ntlm,
                Some(NetworkKey::new(&source, "ntlm")),
                source,
                db.ntlm_store()?,
                stream_direct_channel,
                shutdown_signal,
            )
            .await?;
        }
        RecordType::Kerberos => {
            handle_data(
                send,
                recv,
                RecordType::Kerberos,
                Some(NetworkKey::new(&source, "kerberos")),
                source,
                db.kerberos_store()?,
                stream_direct_channel,
                shutdown_signal,
            )
            .await?;
        }
        RecordType::Ssh => {
            handle_data(
                send,
                recv,
                RecordType::Ssh,
                Some(NetworkKey::new(&source, "ssh")),
                source,
                db.ssh_store()?,
                stream_direct_channel,
                shutdown_signal,
            )
            .await?;
        }
        RecordType::DceRpc => {
            handle_data(
                send,
                recv,
                RecordType::DceRpc,
                Some(NetworkKey::new(&source, "dce rpc")),
                source,
                db.dce_rpc_store()?,
                stream_direct_channel,
                shutdown_signal,
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
                shutdown_signal,
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
                shutdown_signal,
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
                shutdown_signal,
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
    shutdown_signal: Arc<AtomicBool>,
) -> Result<()> {
    let sender_rotation = Arc::new(Mutex::new(send));
    let sender_interval = Arc::clone(&sender_rotation);

    let ack_cnt_rotation = Arc::new(AtomicU8::new(0));
    let ack_cnt_interval = Arc::clone(&ack_cnt_rotation);

    let ack_time_rotation = Arc::new(AtomicI64::new(NO_TIMESTAMP));
    let ack_time_interval = Arc::clone(&ack_time_rotation);

    let mut itv = time::interval(time::Duration::from_secs(ACK_INTERVAL_TIME));
    itv.reset();
    let ack_time_notify = Arc::new(Notify::new());
    let ack_time_notified = ack_time_notify.clone();

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

                _ = ack_time_notified.notified() => {
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
                        ack_time_notify.notify_one();
                    }
                }
                if shutdown_signal.load(Ordering::SeqCst) {
                    handler.abort();
                    break;
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

            Some((source_key,timestamp_val,conn_state, rep)) = rx.recv() => {
                match conn_state {
                    ConnState::Connected => {
                        if source_store.insert(&source_key, timestamp_val).is_err() {
                            error!("Failed to append Source store");
                        }
                        if !rep {
                            sources.write().await.insert(source_key, timestamp_val);
                        }
                    }
                    ConnState::Disconnected => {
                        if source_store.insert(&source_key, timestamp_val).is_err() {
                            error!("Failed to append Source store");
                        }
                        if !rep {
                            sources.write().await.remove(&source_key);
                            packet_sources.write().await.remove(&source_key);
                        }
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

impl NetworkKey {
    pub fn new(source: &str, protocol: &str) -> Self {
        let source_key = format!("{source}\0{protocol}");
        let all_key = format!("all\0{protocol}");

        Self {
            source_key,
            all_key,
        }
    }
}
