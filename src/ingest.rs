pub mod implement;
#[cfg(test)]
mod tests;

use crate::publish::send_direct_stream;
use crate::server::{
    certificate_info, config_server, extract_cert_from_conn, Certs, SERVER_CONNNECTION_DELAY,
    SERVER_ENDPOINT_DELAY,
};
use crate::storage::{Database, RawEventStore, StorageKey, StorageKeyBuilder};
use crate::{AckTransmissionCount, IngestSources, PcapSources, StreamDirectChannels};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use giganto_client::{
    connection::server_handshake,
    frame::{self, RecvError, SendError},
    ingest::{receive_event, receive_record_header},
    RawEventKind,
};
use log_broker::{error, info, LogLocation};
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use std::sync::atomic::AtomicU16;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    select,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, Notify,
    },
    task, time,
    time::sleep,
};
use x509_parser::nom::AsBytes;

const ACK_INTERVAL_TIME: u64 = 60;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const NO_TIMESTAMP: i64 = 0;
const SOURCE_INTERVAL: u64 = 60 * 60 * 24;
const INGEST_VERSION_REQ: &str = ">=0.15.0,<0.17.0";

type SourceInfo = (String, DateTime<Utc>, ConnState, bool);

enum ConnState {
    Connected,
    Disconnected,
}

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

impl Server {
    pub fn new(addr: SocketAddr, certs: &Arc<Certs>) -> Self {
        let server_config =
            config_server(certs).expect("server configuration error with cert, key or root");
        Server {
            server_config,
            server_address: addr,
        }
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub async fn run(
        self,
        db: Database,
        pcap_sources: PcapSources,
        ingest_sources: IngestSources,
        stream_direct_channels: StreamDirectChannels,
        notify_shutdown: Arc<Notify>,
        notify_source: Option<Arc<Notify>>,
        ack_transmission_cnt: AckTransmissionCount,
    ) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        info!(
            LogLocation::Both,
            "listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        let (tx, rx): (Sender<SourceInfo>, Receiver<SourceInfo>) = channel(100);
        let source_db = db.clone();
        task::spawn(check_sources_conn(
            source_db,
            pcap_sources.clone(),
            ingest_sources,
            rx,
            notify_source,
        ));

        let shutdown_signal = Arc::new(AtomicBool::new(false));

        loop {
            select! {
                Some(conn) = endpoint.accept()  => {
                    let sender = tx.clone();
                    let db = db.clone();
                    let pcap_sources = pcap_sources.clone();
                    let stream_direct_channels = stream_direct_channels.clone();
                    let notify_shutdown = notify_shutdown.clone();
                    let shutdown_sig = shutdown_signal.clone();
                    let ack_trans_cnt= ack_transmission_cnt.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(conn, db, pcap_sources, sender, stream_direct_channels,notify_shutdown,shutdown_sig,ack_trans_cnt).await
                        {
                            error!(LogLocation::Both, "connection failed: {}", e);
                        }
                    });
                },
                () = notify_shutdown.notified() => {
                    shutdown_signal.store(true,Ordering::SeqCst); // Setting signal to handle termination on each channel.
                    sleep(Duration::from_millis(SERVER_ENDPOINT_DELAY)).await;      // Wait time for channels,connection to be ready for shutdown.
                    endpoint.close(0_u32.into(), &[]);
                    info!(LogLocation::Both, "Shutting down ingest");
                    notify_shutdown.notify_one();
                    break;
                },
            }
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_connection(
    conn: quinn::Connecting,
    db: Database,
    pcap_sources: PcapSources,
    sender: Sender<SourceInfo>,
    stream_direct_channels: StreamDirectChannels,
    notify_shutdown: Arc<Notify>,
    shutdown_signal: Arc<AtomicBool>,
    ack_trans_cnt: AckTransmissionCount,
) -> Result<()> {
    let connection = conn.await?;
    match server_handshake(&connection, INGEST_VERSION_REQ).await {
        Ok((mut send, _)) => {
            info!(LogLocation::Both, "Compatible version");
            send.finish().await?;
        }
        Err(e) => {
            info!(LogLocation::Both, "Incompatible version");
            connection.close(quinn::VarInt::from_u32(0), e.to_string().as_bytes());
            bail!("{e}")
        }
    };

    let (agent, source) = certificate_info(&extract_cert_from_conn(&connection)?)?;
    let rep = agent.contains("reproduce");

    if !rep {
        pcap_sources
            .write()
            .await
            .insert(source.clone(), connection.clone());
    }

    if let Err(error) = sender
        .send((source.clone(), Utc::now(), ConnState::Connected, rep))
        .await
    {
        error!(LogLocation::Both, "Failed to send channel data : {}", error);
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
                            error!(LogLocation::Both, "Failed to send internal channel data : {}", error);
                        }
                        match conn_err {
                            quinn::ConnectionError::ApplicationClosed(_) => {
                                info!(LogLocation::Both, "application closed");
                                return Ok(());
                            }
                            _ => return Err(conn_err.into()),
                        }
                    }
                    Ok(s) => s,
                };
                let source = source.clone();
                let db = db.clone();
                let stream_direct_channels = stream_direct_channels.clone();
                let shutdown_signal = shutdown_signal.clone();
                let ack_trans_cnt = ack_trans_cnt.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(source, stream, db, stream_direct_channels,shutdown_signal,ack_trans_cnt).await {
                        error!(LogLocation::Both, "failed: {}", e);
                    }
                });
            },
            () = notify_shutdown.notified() => {
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
    stream_direct_channels: StreamDirectChannels,
    shutdown_signal: Arc<AtomicBool>,
    ack_trans_cnt: AckTransmissionCount,
) -> Result<()> {
    let mut buf = [0; 4];
    receive_record_header(&mut recv, &mut buf)
        .await
        .map_err(|e| anyhow!("failed to read record type: {}", e))?;
    match RawEventKind::try_from(u32::from_le_bytes(buf)).context("unknown raw event kind")? {
        RawEventKind::Conn => {
            handle_data(
                send,
                recv,
                RawEventKind::Conn,
                Some(NetworkKey::new(&source, "conn")),
                source,
                db.conn_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Dns => {
            handle_data(
                send,
                recv,
                RawEventKind::Dns,
                Some(NetworkKey::new(&source, "dns")),
                source,
                db.dns_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Log => {
            handle_data(
                send,
                recv,
                RawEventKind::Log,
                Some(NetworkKey::new(&source, "log")),
                source,
                db.log_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Http => {
            handle_data(
                send,
                recv,
                RawEventKind::Http,
                Some(NetworkKey::new(&source, "http")),
                source,
                db.http_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Rdp => {
            handle_data(
                send,
                recv,
                RawEventKind::Rdp,
                Some(NetworkKey::new(&source, "rdp")),
                source,
                db.rdp_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::PeriodicTimeSeries => {
            handle_data(
                send,
                recv,
                RawEventKind::PeriodicTimeSeries,
                None,
                source,
                db.periodic_time_series_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Smtp => {
            handle_data(
                send,
                recv,
                RawEventKind::Smtp,
                Some(NetworkKey::new(&source, "smtp")),
                source,
                db.smtp_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Ntlm => {
            handle_data(
                send,
                recv,
                RawEventKind::Ntlm,
                Some(NetworkKey::new(&source, "ntlm")),
                source,
                db.ntlm_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Kerberos => {
            handle_data(
                send,
                recv,
                RawEventKind::Kerberos,
                Some(NetworkKey::new(&source, "kerberos")),
                source,
                db.kerberos_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Ssh => {
            handle_data(
                send,
                recv,
                RawEventKind::Ssh,
                Some(NetworkKey::new(&source, "ssh")),
                source,
                db.ssh_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::DceRpc => {
            handle_data(
                send,
                recv,
                RawEventKind::DceRpc,
                Some(NetworkKey::new(&source, "dce rpc")),
                source,
                db.dce_rpc_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Statistics => {
            handle_data(
                send,
                recv,
                RawEventKind::Statistics,
                None,
                source,
                db.statistics_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::OpLog => {
            handle_data(
                send,
                recv,
                RawEventKind::OpLog,
                None,
                source,
                db.op_log_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Packet => {
            handle_data(
                send,
                recv,
                RawEventKind::Packet,
                None,
                source,
                db.packet_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Ftp => {
            handle_data(
                send,
                recv,
                RawEventKind::Ftp,
                Some(NetworkKey::new(&source, "ftp")),
                source,
                db.ftp_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Mqtt => {
            handle_data(
                send,
                recv,
                RawEventKind::Mqtt,
                Some(NetworkKey::new(&source, "mqtt")),
                source,
                db.mqtt_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Ldap => {
            handle_data(
                send,
                recv,
                RawEventKind::Ldap,
                Some(NetworkKey::new(&source, "ldap")),
                source,
                db.ldap_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Tls => {
            handle_data(
                send,
                recv,
                RawEventKind::Tls,
                Some(NetworkKey::new(&source, "tls")),
                source,
                db.tls_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Smb => {
            handle_data(
                send,
                recv,
                RawEventKind::Smb,
                Some(NetworkKey::new(&source, "smb")),
                source,
                db.smb_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Nfs => {
            handle_data(
                send,
                recv,
                RawEventKind::Nfs,
                Some(NetworkKey::new(&source, "nfs")),
                source,
                db.nfs_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::ProcessCreate => {
            handle_data(
                send,
                recv,
                RawEventKind::ProcessCreate,
                None,
                source,
                db.process_create_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::FileCreateTime => {
            handle_data(
                send,
                recv,
                RawEventKind::FileCreateTime,
                None,
                source,
                db.file_create_time_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::NetworkConnect => {
            handle_data(
                send,
                recv,
                RawEventKind::NetworkConnect,
                None,
                source,
                db.network_connect_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::ProcessTerminate => {
            handle_data(
                send,
                recv,
                RawEventKind::ProcessTerminate,
                None,
                source,
                db.process_terminate_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::ImageLoad => {
            handle_data(
                send,
                recv,
                RawEventKind::ImageLoad,
                None,
                source,
                db.image_load_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::FileCreate => {
            handle_data(
                send,
                recv,
                RawEventKind::FileCreate,
                None,
                source,
                db.file_create_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::RegistryValueSet => {
            handle_data(
                send,
                recv,
                RawEventKind::RegistryValueSet,
                None,
                source,
                db.registry_value_set_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::RegistryKeyRename => {
            handle_data(
                send,
                recv,
                RawEventKind::RegistryKeyRename,
                None,
                source,
                db.registry_key_rename_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::FileCreateStreamHash => {
            handle_data(
                send,
                recv,
                RawEventKind::FileCreateStreamHash,
                None,
                source,
                db.file_create_stream_hash_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::PipeEvent => {
            handle_data(
                send,
                recv,
                RawEventKind::PipeEvent,
                None,
                source,
                db.pipe_event_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::DnsQuery => {
            handle_data(
                send,
                recv,
                RawEventKind::DnsQuery,
                None,
                source,
                db.dns_query_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::FileDelete => {
            handle_data(
                send,
                recv,
                RawEventKind::FileDelete,
                None,
                source,
                db.file_delete_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::ProcessTamper => {
            handle_data(
                send,
                recv,
                RawEventKind::ProcessTamper,
                None,
                source,
                db.process_tamper_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::FileDeleteDetected => {
            handle_data(
                send,
                recv,
                RawEventKind::FileDeleteDetected,
                None,
                source,
                db.file_delete_detected_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Netflow5 => {
            handle_data(
                send,
                recv,
                RawEventKind::Netflow5,
                None,
                source,
                db.netflow5_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Netflow9 => {
            handle_data(
                send,
                recv,
                RawEventKind::Netflow9,
                None,
                source,
                db.netflow9_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::SecuLog => {
            handle_data(
                send,
                recv,
                RawEventKind::SecuLog,
                None,
                source,
                db.secu_log_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::PeFile => {
            handle_data(
                send,
                recv,
                RawEventKind::PeFile,
                None,
                source,
                db.pe_file_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        _ => {
            error!(
                LogLocation::Both,
                "The record type message could not be processed."
            );
        }
    };
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_data<T>(
    send: SendStream,
    mut recv: RecvStream,
    raw_event_kind: RawEventKind,
    network_key: Option<NetworkKey>,
    source: String,
    store: RawEventStore<'_, T>,
    stream_direct_channels: StreamDirectChannels,
    shutdown_signal: Arc<AtomicBool>,
    ack_trans_cnt: AckTransmissionCount,
) -> Result<()> {
    let sender_rotation = Arc::new(Mutex::new(send));
    let sender_interval = Arc::clone(&sender_rotation);

    let ack_cnt_rotation = Arc::new(AtomicU16::new(0));
    let ack_cnt_interval = Arc::clone(&ack_cnt_rotation);

    let ack_time_rotation = Arc::new(AtomicI64::new(NO_TIMESTAMP));
    let ack_time_interval = Arc::clone(&ack_time_rotation);

    let mut itv = time::interval(time::Duration::from_secs(ACK_INTERVAL_TIME));
    itv.reset();
    let ack_time_notify = Arc::new(Notify::new());
    let ack_time_notified = ack_time_notify.clone();

    let mut err_msg = None;

    #[cfg(all(feature = "edge", feature = "benchmark"))]
    let mut count = 0_usize;
    #[cfg(all(feature = "edge", feature = "benchmark"))]
    let mut size = 0_usize;
    #[cfg(all(feature = "edge", feature = "benchmark"))]
    let mut packet_size = 0_u64;
    #[cfg(all(feature = "edge", feature = "benchmark"))]
    let mut packet_count = 0_u64;
    #[cfg(all(feature = "edge", feature = "benchmark"))]
    let mut start = std::time::Instant::now();

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

                () = ack_time_notified.notified() => {
                    itv.reset();
                }
            }
        }
    });
    loop {
        match receive_event(&mut recv).await {
            Ok((mut raw_event, timestamp)) => {
                if (timestamp == CHANNEL_CLOSE_TIMESTAMP)
                    && (raw_event.as_bytes() == CHANNEL_CLOSE_MESSAGE)
                {
                    if let Err(e) =
                        send_ack_timestamp(&mut (*sender_rotation.lock().await), timestamp).await
                    {
                        err_msg = Some(format!("Failed to send ack timestamp: {e}"));
                        break;
                    }
                    continue;
                }

                #[cfg(all(feature = "edge", feature = "benchmark"))]
                let key_builder = {
                    match process_edge_raw_event(
                        raw_event_kind,
                        &source,
                        &mut raw_event,
                        timestamp,
                        &mut packet_size,
                        &mut packet_count,
                    ) {
                        Ok(builder) => builder,
                        Err(e) => {
                            err_msg = Some(format!("{e}"));
                            break;
                        }
                    }
                };
                #[cfg(all(feature = "edge", not(feature = "benchmark")))]
                let key_builder = {
                    match process_edge_raw_event(raw_event_kind, &source, &mut raw_event, timestamp)
                    {
                        Ok(builder) => builder,
                        Err(e) => {
                            err_msg = Some(format!("{e}"));
                            break;
                        }
                    }
                };

                #[cfg(feature = "central")]
                let key_builder = {
                    match process_central_raw_event(raw_event_kind, &mut raw_event, timestamp) {
                        Ok(builder) => {
                            if let Some(builder) = builder {
                                builder
                            } else {
                                continue;
                            }
                        }
                        Err(e) => {
                            err_msg = Some(format!("{e}"));
                            break;
                        }
                    }
                };

                let storage_key = key_builder.build();
                store.append(&storage_key.key(), &raw_event)?;
                if let Some(network_key) = network_key.as_ref() {
                    if let Err(e) = send_direct_stream(
                        network_key,
                        &raw_event,
                        timestamp,
                        &source,
                        stream_direct_channels.clone(),
                    )
                    .await
                    {
                        err_msg = Some(format!("Failed to send stream events: {e}"));
                        break;
                    }
                }
                ack_cnt_rotation.fetch_add(1, Ordering::SeqCst);
                ack_time_rotation.store(timestamp, Ordering::SeqCst);
                if *ack_trans_cnt.read().await <= ack_cnt_rotation.load(Ordering::SeqCst) {
                    send_ack_timestamp(&mut (*sender_rotation.lock().await), timestamp).await?;
                    ack_cnt_rotation.store(0, Ordering::SeqCst);
                    ack_time_notify.notify_one();
                    store.flush()?;
                }
                #[cfg(all(feature = "edge", feature = "benchmark"))]
                {
                    if raw_event_kind == RawEventKind::Statistics {
                        count += usize::try_from(packet_count).unwrap_or_default();
                        size += usize::try_from(packet_size).unwrap_or_default();
                    } else {
                        count += 1;
                        size += raw_event.len();
                    }
                    if start.elapsed().as_secs() > 3600 {
                        info!(LogLocation::Both,
                            "Ingest: source = {source} type = {raw_event_kind:?} count = {count} size = {size}, duration = {}",
                            start.elapsed().as_secs()
                        );
                        count = 0;
                        size = 0;
                        start = std::time::Instant::now();
                    }
                }

                if shutdown_signal.load(Ordering::SeqCst) {
                    store.flush()?;
                    handler.abort();
                    break;
                }
            }
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly)) => {
                store.flush()?;
                handler.abort();
                break;
            }
            Err(e) => {
                store.flush()?;
                handler.abort();
                bail!("handle {:?} error: {}", raw_event_kind, e)
            }
        }
    }
    store.flush()?;
    if let Some(msg) = err_msg {
        bail!(msg);
    }
    Ok(())
}

/// Sends a cumulative acknowledgement message up to the given timestamp over the given send
/// stream.
///
/// # Errors
///
/// Returns a `SendError` if an error occurs while sending the acknowledgement.
async fn send_ack_timestamp(send: &mut SendStream, timestamp: i64) -> Result<(), SendError> {
    frame::send_bytes(send, &timestamp.to_be_bytes()).await?;
    Ok(())
}

async fn check_sources_conn(
    source_db: Database,
    pcap_sources: PcapSources,
    ingest_sources: IngestSources,
    mut rx: Receiver<SourceInfo>,
    notify_source: Option<Arc<Notify>>,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(SOURCE_INTERVAL));
    itv.reset();
    let source_store = source_db
        .sources_store()
        .expect("Failed to open source store");
    loop {
        select! {
            _ = itv.tick() => {
                let mut sources = ingest_sources.write().await;
                let keys: Vec<String> = sources.keys().map(std::borrow::ToOwned::to_owned).collect();

                for source_key in keys {
                    let timestamp = Utc::now();
                    if source_store.insert(&source_key, timestamp).is_err(){
                        error!(LogLocation::Both, "Failed to append source store");
                    }
                    sources.insert(source_key, timestamp);
                }
            }

            Some((source_key,timestamp_val,conn_state, rep)) = rx.recv() => {
                match conn_state {
                    ConnState::Connected => {
                        if source_store.insert(&source_key, timestamp_val).is_err() {
                            error!(LogLocation::Both, "Failed to append source store");
                        }
                        ingest_sources.write().await.insert(source_key, timestamp_val);
                        if let Some(ref notify) = notify_source {
                            notify.notify_one();
                        }
                    }
                    ConnState::Disconnected => {
                        if source_store.insert(&source_key, timestamp_val).is_err() {
                            error!(LogLocation::Both, "Failed to append source store");
                        }
                        if !rep {
                            ingest_sources.write().await.remove(&source_key);
                            pcap_sources.write().await.remove(&source_key);
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

#[cfg(feature = "edge")]
fn process_edge_raw_event(
    raw_event_kind: RawEventKind,
    source: &str,
    raw_event: &mut Vec<u8>,
    timestamp: i64,
    #[cfg(feature = "benchmark")] packet_size: &mut u64,
    #[cfg(feature = "benchmark")] packet_count: &mut u64,
) -> Result<StorageKeyBuilder>
where
{
    use giganto_client::ingest::{
        log::{Log, OpLog, SecuLog},
        netflow::{Netflow5, Netflow9},
        statistics::Statistics,
        timeseries::PeriodicTimeSeries,
        Packet,
    };

    let key_builder = StorageKey::builder().start_key(source);
    let key_builder = match raw_event_kind {
        RawEventKind::Log => {
            let Ok(log) = bincode::deserialize::<Log>(raw_event) else {
                bail!("Failed to deserialize Log".to_string());
            };
            key_builder
                .mid_key(Some(log.kind.as_bytes().to_vec()))
                .end_key(timestamp)
        }
        RawEventKind::PeriodicTimeSeries => {
            let Ok(time_series) = bincode::deserialize::<PeriodicTimeSeries>(raw_event) else {
                bail!("Failed to deserialize PeriodicTimeSeries".to_string());
            };
            StorageKey::builder()
                .start_key(&time_series.id)
                .end_key(timestamp)
        }
        RawEventKind::OpLog => {
            let Ok(op_log) = bincode::deserialize::<OpLog>(raw_event) else {
                bail!("Failed to deserialize OpLog".to_string());
            };
            let agent_id = format!("{}@{source}", op_log.agent_name);
            StorageKey::builder()
                .start_key(&agent_id)
                .end_key(timestamp)
        }
        RawEventKind::Packet => {
            let Ok(packet) = bincode::deserialize::<Packet>(raw_event) else {
                bail!("Failed to deserialize Packet".to_string());
            };
            key_builder
                .mid_key(Some(timestamp.to_be_bytes().to_vec()))
                .end_key(packet.packet_timestamp)
        }
        RawEventKind::Statistics => {
            let Ok(statistics) = bincode::deserialize::<Statistics>(raw_event) else {
                bail!("Failed to deserialize Statistics".to_string());
            };
            #[cfg(feature = "benchmark")]
            {
                (*packet_count, *packet_size) = statistics
                    .stats
                    .iter()
                    .fold((0, 0), |(sumc, sums), c| (sumc + c.1, sums + c.2));
            }
            key_builder
                .mid_key(Some(statistics.core.to_be_bytes().to_vec()))
                .end_key(timestamp)
        }
        RawEventKind::Netflow5 => {
            let Ok(mut netflow5) = bincode::deserialize::<Netflow5>(raw_event) else {
                bail!("Failed to deserialize Netflow5".to_string());
            };

            netflow5.source = source.to_string();
            let Ok(serde_data) = bincode::serialize(&netflow5) else {
                bail!("Failed to serialize Netflow5".to_string());
            };
            *raw_event = serde_data;
            StorageKey::builder()
                .start_key("netflow5")
                .end_key(timestamp)
        }
        RawEventKind::Netflow9 => {
            let Ok(mut netflow9) = bincode::deserialize::<Netflow9>(raw_event) else {
                bail!("Failed to deserialize Netflow9".to_string());
            };

            netflow9.source = source.to_string();
            let Ok(serde_data) = bincode::serialize(&netflow9) else {
                bail!("Failed to serialize Netflow9".to_string());
            };
            *raw_event = serde_data;
            StorageKey::builder()
                .start_key("netflow9")
                .end_key(timestamp)
        }
        RawEventKind::SecuLog => {
            let Ok(mut secu_log) = bincode::deserialize::<SecuLog>(raw_event) else {
                bail!("Failed to deserialize SecuLog".to_string());
            };

            secu_log.source = source.to_string();
            let Ok(serde_data) = bincode::serialize(&secu_log) else {
                bail!("Failed to serialize SecuLog".to_string());
            };
            *raw_event = serde_data;
            StorageKey::builder()
                .start_key(&secu_log.kind)
                .end_key(timestamp)
        }
        _ => key_builder.end_key(timestamp),
    };
    Ok(key_builder)
}

#[cfg(feature = "central")]
#[allow(clippy::too_many_lines)]
fn process_central_raw_event(
    raw_event_kind: RawEventKind,
    raw_event: &mut Vec<u8>,
    timestamp: i64,
) -> Result<Option<StorageKeyBuilder>>
where
{
    use giganto_client::ingest::sysmon::{
        DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
        FileDeleteDetected, ImageLoaded, NetworkConnection, PEFile, PipeEvent, ProcessCreate,
        ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
    };
    use giganto_client::ingest::{
        network::{
            Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
        },
        Packet,
    };

    let key_builder = StorageKey::builder();
    let key_builder = match raw_event_kind {
        RawEventKind::Conn => {
            let (source, data) = parse_central_data::<Conn>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Dns => {
            let (source, data) = parse_central_data::<Dns>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Http => {
            let (source, data) = parse_central_data::<Http>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Rdp => {
            let (source, data) = parse_central_data::<Rdp>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Smtp => {
            let (source, data) = parse_central_data::<Smtp>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Ntlm => {
            let (source, data) = parse_central_data::<Ntlm>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Kerberos => {
            let (source, data) = parse_central_data::<Kerberos>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Ssh => {
            let (source, data) = parse_central_data::<Ssh>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::DceRpc => {
            let (source, data) = parse_central_data::<DceRpc>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Ftp => {
            let (source, data) = parse_central_data::<Ftp>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Mqtt => {
            let (source, data) = parse_central_data::<Mqtt>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Ldap => {
            let (source, data) = parse_central_data::<Ldap>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Tls => {
            let (source, data) = parse_central_data::<Tls>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Smb => {
            let (source, data) = parse_central_data::<Smb>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Nfs => {
            let (source, data) = parse_central_data::<Nfs>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::ProcessCreate => {
            let (source, data) = parse_central_data::<ProcessCreate>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::FileCreateTime => {
            let (source, data) = parse_central_data::<FileCreationTimeChanged>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::NetworkConnect => {
            let (source, data) = parse_central_data::<NetworkConnection>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::ProcessTerminate => {
            let (source, data) = parse_central_data::<ProcessTerminated>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::ImageLoad => {
            let (source, data) = parse_central_data::<ImageLoaded>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::FileCreate => {
            let (source, data) = parse_central_data::<FileCreate>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::RegistryValueSet => {
            let (source, data) = parse_central_data::<RegistryValueSet>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::RegistryKeyRename => {
            let (source, data) = parse_central_data::<RegistryKeyValueRename>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::FileCreateStreamHash => {
            let (source, data) = parse_central_data::<FileCreateStreamHash>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::PipeEvent => {
            let (source, data) = parse_central_data::<PipeEvent>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::DnsQuery => {
            let (source, data) = parse_central_data::<DnsEvent>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::FileDelete => {
            let (source, data) = parse_central_data::<FileDelete>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::ProcessTamper => {
            let (source, data) = parse_central_data::<ProcessTampering>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::FileDeleteDetected => {
            let (source, data) = parse_central_data::<FileDeleteDetected>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::PeFile => {
            let (source, data) = parse_central_data::<PEFile>(raw_event)?;
            *raw_event = data;
            key_builder.start_key(&source).end_key(timestamp)
        }
        RawEventKind::Packet => {
            let Ok((source, packet)) = bincode::deserialize::<(String, Packet)>(raw_event) else {
                bail!("Failed to deserialize packet".to_string());
            };
            let key_builder = key_builder
                .start_key(&source)
                .mid_key(Some(timestamp.to_be_bytes().to_vec()))
                .end_key(packet.packet_timestamp);

            let Ok(serde_data) = bincode::serialize(&packet) else {
                bail!("Failed to serialize packet".to_string());
            };
            *raw_event = serde_data;
            key_builder
        }
        _ => return Ok(None),
    };
    Ok(Some(key_builder))
}

#[cfg(feature = "central")]
fn parse_central_data<T>(raw_event: &[u8]) -> Result<(String, Vec<u8>)>
where
    T: serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    let Ok((source, event)) = bincode::deserialize::<(String, T)>(raw_event) else {
        bail!("Failed to deserialize raw event".to_string());
    };
    let Ok(serde_data) = bincode::serialize(&event) else {
        bail!("Failed to serialize raw event".to_string());
    };
    Ok((source, serde_data))
}
