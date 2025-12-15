pub mod generation;
pub mod implement;
#[cfg(test)]
mod tests;

use std::sync::OnceLock;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU16, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use generation::SequenceGenerator;
use giganto_client::frame::recv_raw;
use giganto_client::{
    RawEventKind,
    connection::server_handshake,
    frame::{self, RecvError, SendError},
    ingest::{
        Packet,
        log::{Log, OpLog, SecuLog},
        receive_record_header,
        statistics::Statistics,
        timeseries::PeriodicTimeSeries,
    },
};
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use tokio::{
    select,
    sync::{
        Mutex, Notify,
        mpsc::{Receiver, Sender, channel},
    },
    task, time,
    time::sleep,
};
use tracing::{error, info};
use x509_parser::nom::AsBytes;

use crate::comm::publish::send_direct_stream;
use crate::comm::{IngestSensors, PcapSensors, RunTimeIngestSensors, StreamDirectChannels};
use crate::server::{
    Certs, SERVER_CONNNECTION_DELAY, SERVER_ENDPOINT_DELAY, config_server, extract_cert_from_conn,
    subject_from_cert_verbose,
};
use crate::storage::{Database, RawEventStore, StorageKey};

const ACK_INTERVAL_TIME: u64 = 60;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const NO_TIMESTAMP: i64 = 0;
const SENSOR_INTERVAL: u64 = 60 * 60 * 24;
const INGEST_VERSION_REQ: &str = ">=0.26.0,<0.27.0";

type SensorInfo = (String, DateTime<Utc>, ConnState, bool);

static GENERATOR: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();

enum ConnState {
    Connected,
    Disconnected,
}

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

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub async fn run(
        self,
        db: Database,
        pcap_sensors: PcapSensors,
        ingest_sensors: IngestSensors,
        runtime_ingest_sensors: RunTimeIngestSensors,
        stream_direct_channels: StreamDirectChannels,
        notify_shutdown: Arc<Notify>,
        notify_sensor: Option<Arc<Notify>>,
        ack_transmission_cnt: u16,
    ) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        info!(
            "Ingest listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        let (tx, rx): (Sender<SensorInfo>, Receiver<SensorInfo>) = channel(100);
        let sensor_db = db.clone();
        task::spawn(check_sensors_conn(
            sensor_db,
            pcap_sensors.clone(),
            ingest_sensors,
            runtime_ingest_sensors,
            rx,
            notify_sensor,
            notify_shutdown.clone(),
        ));

        let shutdown_signal = Arc::new(AtomicBool::new(false));

        loop {
            select! {
                Some(conn) = endpoint.accept()  => {
                    let sender = tx.clone();
                    let db = db.clone();
                    let pcap_sensors = pcap_sensors.clone();
                    let stream_direct_channels = stream_direct_channels.clone();
                    let notify_shutdown = notify_shutdown.clone();
                    let shutdown_sig = shutdown_signal.clone();
                    tokio::spawn(async move {
                        let remote = conn.remote_address();
                        if let Err(e) =
                            handle_connection(conn, db, pcap_sensors, sender, stream_direct_channels,notify_shutdown,shutdown_sig,ack_transmission_cnt).await
                        {
                            error!("Connection to {remote} failed: {e}");
                        }
                    });
                },
                () = notify_shutdown.notified() => {
                    shutdown_signal.store(true,Ordering::SeqCst); // Setting signal to handle termination on each channel.
                    sleep(Duration::from_millis(SERVER_ENDPOINT_DELAY)).await;      // Wait time for channels,connection to be ready for shutdown.
                    endpoint.close(0_u32.into(), &[]);
                    info!("Shutting down ingest");
                    notify_shutdown.notify_one();
                    break;
                },
            }
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_connection(
    conn: quinn::Incoming,
    db: Database,
    pcap_sensors: PcapSensors,
    sender: Sender<SensorInfo>,
    stream_direct_channels: StreamDirectChannels,
    notify_shutdown: Arc<Notify>,
    shutdown_signal: Arc<AtomicBool>,
    ack_trans_cnt: u16,
) -> Result<()> {
    let connection = conn.await?;
    match server_handshake(&connection, INGEST_VERSION_REQ).await {
        Ok((mut send, _)) => {
            info!("Compatible version");
            send.finish()?;
        }
        Err(e) => {
            info!("Incompatible version");
            connection.close(quinn::VarInt::from_u32(0), e.to_string().as_bytes());
            bail!("{e}")
        }
    }

    let (agent, sensor) = subject_from_cert_verbose(&extract_cert_from_conn(&connection)?)?;
    let is_pcap_sensor = agent.contains("piglet");

    if is_pcap_sensor {
        pcap_sensors
            .write()
            .await
            .entry(sensor.clone())
            .or_insert_with(Vec::new)
            .push(connection.clone());
    }

    if let Err(error) = sender
        .send((
            sensor.clone(),
            Utc::now(),
            ConnState::Connected,
            is_pcap_sensor,
        ))
        .await
    {
        error!("Failed to send channel data : {error}");
    }

    loop {
        select! {
            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(conn_err) => {
                        if let Err(error) = sender
                            .send((sensor, Utc::now(), ConnState::Disconnected, is_pcap_sensor))
                            .await
                        {
                            error!("Failed to send internal channel data: {error}");
                        }
                        match conn_err {
                            quinn::ConnectionError::ApplicationClosed(_) => {
                                info!("{agent} has disconnected from ingest");
                                return Ok(());
                            }
                            _ => return Err(conn_err.into()),
                        }
                    }
                    Ok(s) => s,
                };
                let sensor = sensor.clone();
                let db = db.clone();
                let stream_direct_channels = stream_direct_channels.clone();
                let shutdown_signal = shutdown_signal.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(sensor, stream, db, stream_direct_channels,shutdown_signal,ack_trans_cnt).await {
                        error!("Failed: {e}");
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
    sensor: String,
    (send, mut recv): (SendStream, RecvStream),
    db: Database,
    stream_direct_channels: StreamDirectChannels,
    shutdown_signal: Arc<AtomicBool>,
    ack_trans_cnt: u16,
) -> Result<()> {
    let mut buf = [0; 4];
    receive_record_header(&mut recv, &mut buf)
        .await
        .map_err(|e| anyhow!("failed to read record type: {e}"))?;
    match RawEventKind::try_from(u32::from_le_bytes(buf)).context("unknown raw event kind")? {
        RawEventKind::Conn => {
            handle_data(
                send,
                recv,
                RawEventKind::Conn,
                Some(NetworkKey::new(&sensor, "conn")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "dns")),
                sensor,
                db.dns_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::MalformedDns => {
            handle_data(
                send,
                recv,
                RawEventKind::MalformedDns,
                Some(NetworkKey::new(&sensor, "malformed_dns")),
                sensor,
                db.malformed_dns_store()?,
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
                Some(NetworkKey::new(&sensor, "log")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "http")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "rdp")),
                sensor,
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
                sensor,
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
                Some(NetworkKey::new(&sensor, "smtp")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "ntlm")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "kerberos")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "ssh")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "dce rpc")),
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                Some(NetworkKey::new(&sensor, "ftp")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "mqtt")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "ldap")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "tls")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "smb")),
                sensor,
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
                Some(NetworkKey::new(&sensor, "nfs")),
                sensor,
                db.nfs_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Bootp => {
            handle_data(
                send,
                recv,
                RawEventKind::Bootp,
                Some(NetworkKey::new(&sensor, "bootp")),
                sensor,
                db.bootp_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Dhcp => {
            handle_data(
                send,
                recv,
                RawEventKind::Dhcp,
                Some(NetworkKey::new(&sensor, "dhcp")),
                sensor,
                db.dhcp_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Radius => {
            handle_data(
                send,
                recv,
                RawEventKind::Radius,
                Some(NetworkKey::new(&sensor, "radius")),
                sensor,
                db.radius_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Icmp => {
            handle_data(
                send,
                recv,
                RawEventKind::Icmp,
                Some(NetworkKey::new(&sensor, "icmp")),
                sensor,
                db.icmp_store()?,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
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
                sensor,
                db.secu_log_store()?,
                stream_direct_channels,
                shutdown_signal,
                ack_trans_cnt,
            )
            .await?;
        }
        _ => {
            error!("The record type message could not be processed.");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_data<T>(
    send: SendStream,
    mut recv: RecvStream,
    raw_event_kind: RawEventKind,
    network_key: Option<NetworkKey>,
    sensor: String,
    store: RawEventStore<'_, T>,
    stream_direct_channels: StreamDirectChannels,
    shutdown_signal: Arc<AtomicBool>,
    ack_trans_cnt: u16,
) -> Result<()> {
    info!("Raw event {raw_event_kind:?} has been connected");
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
    #[cfg(feature = "benchmark")]
    let stream_id = recv.id();

    #[cfg(feature = "benchmark")]
    let mut count = 0_usize;
    #[cfg(feature = "benchmark")]
    let mut size = 0_usize;
    #[cfg(feature = "benchmark")]
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
    let mut buf: Vec<u8> = Vec::new();
    let mut last_timestamp = 0;
    loop {
        buf.clear();
        match recv_raw(&mut recv, &mut buf).await {
            Ok(()) => {
                let Ok(recv_buf) = bincode::deserialize::<Vec<(i64, Vec<u8>)>>(&buf) else {
                    err_msg = Some("Failed to deserialize received message".to_string());
                    break;
                };
                let mut recv_events_cnt: u16 = 0;
                #[cfg(feature = "benchmark")]
                let mut recv_events_len = 0;
                #[cfg(feature = "benchmark")]
                let mut packet_size = 0_u64;
                #[cfg(feature = "benchmark")]
                let mut packet_count = 0_u64;
                for (timestamp, mut raw_event) in recv_buf {
                    last_timestamp = timestamp;
                    if (timestamp == CHANNEL_CLOSE_TIMESTAMP)
                        && (raw_event.as_bytes() == CHANNEL_CLOSE_MESSAGE)
                    {
                        if let Err(e) =
                            send_ack_timestamp(&mut (*sender_rotation.lock().await), timestamp)
                                .await
                        {
                            err_msg = Some(format!("Failed to send ack timestamp: {e}"));
                            break;
                        }
                        continue;
                    }
                    let storage_key = match raw_event_kind {
                        RawEventKind::Log => {
                            let Ok(log) = bincode::deserialize::<Log>(&raw_event) else {
                                err_msg = Some("Failed to deserialize Log".to_string());
                                break;
                            };
                            StorageKey::builder()
                                .start_key(&sensor)
                                .mid_key(Some(log.kind.as_bytes().to_vec()))
                                .end_key(timestamp)
                                .build()
                        }
                        RawEventKind::PeriodicTimeSeries => {
                            let Ok(time_series) =
                                bincode::deserialize::<PeriodicTimeSeries>(&raw_event)
                            else {
                                err_msg =
                                    Some("Failed to deserialize PeriodicTimeSeries".to_string());
                                break;
                            };
                            StorageKey::builder()
                                .start_key(&time_series.id)
                                .end_key(timestamp)
                                .build()
                        }
                        RawEventKind::OpLog => {
                            let Ok(mut op_log) = bincode::deserialize::<OpLog>(&raw_event) else {
                                err_msg = Some("Failed to deserialize OpLog".to_string());
                                break;
                            };
                            op_log.sensor.clone_from(&sensor);
                            let Ok(op_log) = bincode::serialize(&op_log) else {
                                err_msg = Some("Failed to serialize OpLog".to_string());
                                break;
                            };
                            raw_event.clone_from(&op_log);

                            let generator =
                                GENERATOR.get_or_init(SequenceGenerator::init_generator);
                            let sequence_number = generator.generate_sequence_number();
                            StorageKey::timestamp_builder()
                                .start_key(timestamp)
                                .mid_key(sequence_number)
                                .build()
                        }
                        RawEventKind::Packet => {
                            let Ok(packet) = bincode::deserialize::<Packet>(&raw_event) else {
                                err_msg = Some("Failed to deserialize Packet".to_string());
                                break;
                            };
                            StorageKey::builder()
                                .start_key(&sensor)
                                .mid_key(Some(timestamp.to_be_bytes().to_vec()))
                                .end_key(packet.packet_timestamp)
                                .build()
                        }
                        RawEventKind::Statistics => {
                            let Ok(statistics) = bincode::deserialize::<Statistics>(&raw_event)
                            else {
                                err_msg = Some("Failed to deserialize Statistics".to_string());
                                break;
                            };
                            #[cfg(feature = "benchmark")]
                            {
                                let (t_packet_count, t_packet_size) = statistics
                                    .stats
                                    .iter()
                                    .fold((0, 0), |(sumc, sums), c| (sumc + c.1, sums + c.2));
                                packet_count += t_packet_count;
                                packet_size += t_packet_size;
                            }
                            StorageKey::builder()
                                .start_key(&sensor)
                                .mid_key(Some(statistics.core.to_be_bytes().to_vec()))
                                .end_key(timestamp)
                                .build()
                        }
                        RawEventKind::SecuLog => {
                            let Ok(secu_log) = bincode::deserialize::<SecuLog>(&raw_event) else {
                                err_msg = Some("Failed to deserialize SecuLog".to_string());
                                break;
                            };
                            StorageKey::builder()
                                .start_key(&sensor)
                                .mid_key(Some(secu_log.kind.as_bytes().to_vec()))
                                .end_key(timestamp)
                                .build()
                        }
                        _ => StorageKey::builder()
                            .start_key(&sensor)
                            .end_key(timestamp)
                            .build(),
                    };

                    recv_events_cnt += 1;
                    #[cfg(feature = "benchmark")]
                    {
                        recv_events_len += raw_event.len();
                    }
                    store.append(&storage_key.key(), &raw_event)?;
                    if let Some(network_key) = network_key.as_ref()
                        && let Err(e) = send_direct_stream(
                            network_key,
                            &raw_event,
                            timestamp,
                            &sensor,
                            stream_direct_channels.clone(),
                        )
                        .await
                    {
                        err_msg = Some(format!("Failed to send stream events: {e}"));
                        break;
                    }
                }

                if err_msg.is_some() {
                    break;
                }

                ack_cnt_rotation.fetch_add(recv_events_cnt, Ordering::SeqCst);
                ack_time_rotation.store(last_timestamp, Ordering::SeqCst);
                if ack_trans_cnt <= ack_cnt_rotation.load(Ordering::SeqCst) {
                    send_ack_timestamp(&mut (*sender_rotation.lock().await), last_timestamp)
                        .await?;
                    ack_cnt_rotation.store(0, Ordering::SeqCst);
                    ack_time_notify.notify_one();
                    store.flush()?;
                }

                #[cfg(feature = "benchmark")]
                {
                    if raw_event_kind == RawEventKind::Statistics {
                        count += usize::try_from(packet_count).unwrap_or_default();
                        size += usize::try_from(packet_size).unwrap_or_default();
                    } else {
                        count += usize::from(recv_events_cnt);
                        size += recv_events_len;
                    }
                    if start.elapsed().as_secs() > 3600 {
                        info!(
                            "{sensor:?}, {stream_id:?}, {raw_event_kind:?}, count = {count}, size = {size}, duration = {}",
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
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_))) => {
                store.flush()?;
                handler.abort();
                break;
            }
            Err(e) => {
                store.flush()?;
                handler.abort();
                bail!("handle {raw_event_kind:?} error: {e}");
            }
        }
    }
    store.flush()?;
    info!("Raw event {raw_event_kind:?} has been disconnected");
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

async fn check_sensors_conn(
    sensor_db: Database,
    pcap_sensors: PcapSensors,
    ingest_sensors: IngestSensors,
    runtime_ingest_sensors: RunTimeIngestSensors,
    mut rx: Receiver<SensorInfo>,
    notify_sensor: Option<Arc<Notify>>,
    notify_shutdown: Arc<Notify>,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(SENSOR_INTERVAL));
    itv.reset();
    let sensor_store = sensor_db
        .sensors_store()
        .expect("Failed to open sensor store");

    loop {
        select! {
            _ = itv.tick() => {
                let mut runtime_sensors = runtime_ingest_sensors.write().await;
                let keys: Vec<String> = runtime_sensors.keys().map(std::borrow::ToOwned::to_owned).collect();

                for sensor_key in keys {
                    let time = Utc::now();
                    if sensor_store.insert(&sensor_key, time).is_err(){
                        error!("Failed to append sensor store");
                    }
                    runtime_sensors.insert(sensor_key, time);
                }
            }

            Some((sensor_key, time_val, conn_state, is_pcap_sensor)) = rx.recv() => {
                match conn_state {
                    ConnState::Connected => {
                        if sensor_store.insert(&sensor_key, time_val).is_err() {
                            error!("Failed to append sensor store");
                        }
                        runtime_ingest_sensors.write().await.insert(sensor_key.clone(), time_val);
                        ingest_sensors.write().await.insert(sensor_key);
                        if let Some(ref notify) = notify_sensor {
                            notify.notify_one();
                        }
                    }
                    ConnState::Disconnected => {
                        if sensor_store.insert(&sensor_key, time_val).is_err() {
                            error!("Failed to append sensor store");
                        }
                        runtime_ingest_sensors.write().await.remove(&sensor_key);
                        if is_pcap_sensor
                            && let Some(connections) = pcap_sensors.write().await.get_mut(&sensor_key).filter(|connection_vec| !connection_vec.is_empty()) {
                                connections.remove(0);
                        }
                    }
                }
            }

            () = notify_shutdown.notified() => {
                break;
            },
        }
    }

    Ok(())
}

pub struct NetworkKey {
    pub(crate) sensor_key: String,
    pub(crate) all_key: String,
}

impl NetworkKey {
    pub fn new(sensor: &str, protocol: &str) -> Self {
        let sensor_key = format!("{sensor}\0{protocol}");
        let all_key = format!("all\0{protocol}");

        Self {
            sensor_key,
            all_key,
        }
    }
}
