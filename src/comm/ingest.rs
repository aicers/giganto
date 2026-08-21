//! Ingest: the QUIC listener sensors push raw events into.
//!
//! # Shutdown loss tolerance
//!
//! Ingest acknowledges by timestamp, and an ACK means the events up to that
//! timestamp were appended to their store — not that the store was flushed to
//! durable storage. So the guarantee cancellation has to keep is that
//! everything already appended survives: every handler flushes its store
//! before it returns, and the ingest entry task returns only after the drain
//! has collected every handler. What cancellation may drop is input that has
//! not made it that far — a frame half read off a stream, a batch that failed
//! to decode, a stream a sensor was about to open. None of it was
//! acknowledged, so the sensor resends it to the next generation. Shutdown
//! sends no extra ACK of its own; the only ACKs on the wire are the ones the
//! steady-state batching and interval rules would have sent anyway.
//!
//! Sensor-state updates follow the same rule from the other side: once
//! cancellation closes admission, no newly accepted connection can produce
//! one, but every update already handed to the sensor-state channel is applied
//! before that task returns.

pub mod generation;
pub mod implement;
#[cfg(test)]
mod tests;

use std::sync::OnceLock;
use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
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
    publish::stream::RequestStreamRecord,
};
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use tokio::{
    select,
    sync::{
        Notify,
        mpsc::{Receiver, Sender, channel},
    },
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use x509_parser::nom::AsBytes;

use crate::cancellation::{DRAIN_REPORT_INTERVAL, TaskTracker, drain_with_report};
use crate::comm::publish::send_direct_stream;
use crate::comm::{IngestSensors, PcapSensors, RunTimeIngestSensors, StreamDirectChannels};
use crate::datetime::DateTime;
use crate::server::{
    Certs, config_server, connected_client_display_from_cert, extract_cert_from_conn,
    host_fqdn_from_cert, service_fqdn_from_cert,
};
use crate::storage::{Database, RawEventStore, SensorStore, StorageKey};
use crate::tls_reload::TlsWatch;

const ACK_INTERVAL_TIME: u64 = 60;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const NO_TIMESTAMP: i64 = 0;
const SENSOR_INTERVAL: u64 = 60 * 60 * 24;
const INGEST_VERSION_REQ: &str = ">=0.27.0,<0.29.0";
/// Names the ingest subsystem tracker in the drain progress log.
const INGEST_DRAIN_LABEL: &str = "ingest";

type SensorInfo = (String, DateTime, ConnState, bool);

static GENERATOR: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();

enum ConnState {
    Connected,
    Disconnected,
}

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

pub(crate) struct BoundServer {
    endpoint: Endpoint,
    local_addr: SocketAddr,
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

    pub(crate) fn bind(self) -> Result<BoundServer> {
        let endpoint = Endpoint::server(self.server_config, self.server_address)?;
        let local_addr = endpoint.local_addr()?;
        Ok(BoundServer {
            endpoint,
            local_addr,
        })
    }

    /// Binds the ingest listener and serves it until `token` is cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot be bound, if the ingest task
    /// tracker rejects one of the subsystem's own tasks, or if the
    /// sensor-state task did not return cleanly.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        self,
        db: Database,
        pcap_sensors: PcapSensors,
        ingest_sensors: IngestSensors,
        runtime_ingest_sensors: RunTimeIngestSensors,
        stream_direct_channels: StreamDirectChannels,
        notify_sensor: Option<Arc<Notify>>,
        ack_transmission_cnt: u16,
        tls_watch: TlsWatch,
        token: CancellationToken,
    ) -> Result<()> {
        self.bind()
            .context("failed to bind the ingest listener")?
            .run(
                db,
                pcap_sensors,
                ingest_sensors,
                runtime_ingest_sensors,
                stream_direct_channels,
                notify_sensor,
                ack_transmission_cnt,
                tls_watch,
                token,
            )
            .await
    }
}

impl BoundServer {
    #[must_use]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves the bound ingest listener until `token` is cancelled, then
    /// drains every task it admitted.
    ///
    /// Ingest owns a subsystem tracker built from `token`, so the top-level
    /// tracker's cancellation reaches the sensor-state task, every connection
    /// handler, and every request handler those connections spawn in turn.
    /// Cancellation ends admission on both sides: this loop stops accepting,
    /// and closing the tracker stops the handlers from registering more work.
    /// The entry task returns only once the drain is empty, so no ingest task
    /// is left holding a database handle when the generation moves on.
    ///
    /// # Errors
    ///
    /// Returns an error if the ingest task tracker rejects one of the
    /// subsystem's own tasks, if a tracker lock is poisoned, or if the
    /// sensor-state task did not return cleanly.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub(crate) async fn run(
        self,
        db: Database,
        pcap_sensors: PcapSensors,
        ingest_sensors: IngestSensors,
        runtime_ingest_sensors: RunTimeIngestSensors,
        stream_direct_channels: StreamDirectChannels,
        notify_sensor: Option<Arc<Notify>>,
        ack_transmission_cnt: u16,
        mut tls_watch: TlsWatch,
        token: CancellationToken,
    ) -> Result<()> {
        let local_addr = self.local_addr();
        let endpoint = self.endpoint;
        info!("Ingest listening on {local_addr}");

        // Built from the token handed down by `main`, so the top-level
        // `cancel_children` reaches everything registered here. Building it
        // with `TaskTracker::new()` would start a fresh root and cut ingest
        // off from process shutdown without the compiler noticing.
        let tracker = TaskTracker::with_token(token.clone());

        let (tx, rx): (Sender<SensorInfo>, Receiver<SensorInfo>) = channel(100);
        let sensor_state_handle = tracker
            .spawn("ingest-sensor-state", {
                let sensor_db = db.clone();
                let pcap_sensors = pcap_sensors.clone();
                move |token| {
                    check_sensors_conn(
                        sensor_db,
                        pcap_sensors,
                        ingest_sensors,
                        runtime_ingest_sensors,
                        rx,
                        notify_sensor,
                        token,
                    )
                }
            })
            .context("failed to register the ingest sensor-state task")?;

        // A `TlsWatch` whose sender is gone reports the closure on every poll,
        // which would spin this loop, so the reload arm is switched off for
        // good the first time that happens.
        let mut tls_watch_live = true;

        loop {
            select! {
                biased;

                // Cancellation branch. Nothing admitted is dropped here: the
                // arms below hold only a handshake that has not produced a
                // connection yet and a TLS update that changes nothing for
                // connections already up. Leaving the loop is where ingest
                // stops accepting; closing the tracker below is what stops the
                // handlers from admitting streams in turn.
                () = token.cancelled() => {
                    info!("Shutting down ingest");
                    break;
                }

                // Reload TLS server config when new material is available.
                // Existing connections remain alive; only new handshakes use
                // the refreshed certificate. Polled ahead of the accept arm
                // because a `biased` select takes the first ready arm, and a
                // steady stream of incoming connections would otherwise keep
                // a reload waiting.
                changed = tls_watch.changed(), if tls_watch_live => {
                    if changed.is_err() {
                        warn!(
                            "Ingest listener: TLS watch closed, \
                             keeping the current server config"
                        );
                        tls_watch_live = false;
                        continue;
                    }
                    let tls = tls_watch.borrow_and_update().clone();
                    match config_server(&tls.certs) {
                        Ok(new_config) => {
                            endpoint.set_server_config(Some(new_config));
                            info!("Ingest listener: server config reloaded");
                        }
                        Err(e) => {
                            error!(
                                "Ingest listener: failed to build server config \
                                 from reloaded TLS material, keeping current config: {e:#}"
                            );
                        }
                    }
                },

                Some(conn) = endpoint.accept() => {
                    let remote = conn.remote_address();
                    let sender = tx.clone();
                    let db = db.clone();
                    let pcap_sensors = pcap_sensors.clone();
                    let stream_direct_channels = stream_direct_channels.clone();
                    let connection_tracker = tracker.clone();
                    let spawned = tracker.spawn(
                        format!("ingest-conn-{remote}"),
                        move |token| async move {
                            if let Err(e) = handle_connection(
                                conn,
                                db,
                                pcap_sensors,
                                sender,
                                stream_direct_channels,
                                connection_tracker,
                                token,
                                ack_transmission_cnt,
                            )
                            .await
                            {
                                error!("Connection to {remote} failed: {e}");
                            }
                        },
                    );
                    // The handle is dropped: a connection handler logs its own
                    // domain errors and the tracker reports any task that
                    // vanishes without returning, so there is no outcome left
                    // for the entry task to observe. Admission only closes
                    // after cancellation, so a rejected connection means
                    // shutdown has begun and the sensor will reconnect to the
                    // next generation.
                    if let Err(e) = spawned {
                        warn!("Rejected ingest connection from {remote}: {e}");
                    }
                },
            }
        }

        // Admission rejection, the half the accept loop cannot do on its own:
        // a closed tracker turns away every connection and stream handler a
        // still-running handler might try to register.
        tracker
            .close()
            .context("failed to close the ingest task tracker")?;
        // The entry task holds the only sender outside the handlers, so
        // dropping it here lets the sensor-state task see the channel close
        // once the handlers still holding clones have returned.
        drop(tx);
        // Same policy as the top level: report every round and keep waiting.
        // `drain_with_report` closes and cancels again, both idempotent.
        drain_with_report(&tracker, DRAIN_REPORT_INTERVAL, INGEST_DRAIN_LABEL)
            .await
            .context("failed to drain the ingest task tracker")?;

        // Only now, with every handler returned, is the listener torn down.
        // Closing it earlier would kill the connections the handlers are
        // still cleaning up on.
        endpoint.close(0_u32.into(), b"shutting down");
        endpoint.wait_idle().await;

        // The drain already waited for this task; this reads back the result
        // it returned, which the drain does not look at.
        match sensor_state_handle.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.context("ingest sensor-state task failed")),
            Err(e) => Err(anyhow!("ingest sensor-state task did not join: {e}")),
        }
    }
}

/// Serves one ingest connection: handshake, sensor bookkeeping, and one
/// request handler per bi-directional stream the sensor opens.
///
/// `tracker` is the ingest subsystem tracker, carried in so the request
/// handlers spawned here land in the same registry as this task rather than
/// escaping it, and `token` is this task's own child of that tracker's root.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_connection(
    conn: quinn::Incoming,
    db: Database,
    pcap_sensors: PcapSensors,
    sender: Sender<SensorInfo>,
    stream_direct_channels: StreamDirectChannels,
    tracker: TaskTracker,
    token: CancellationToken,
    ack_trans_cnt: u16,
) -> Result<()> {
    // Cancellation branch. The QUIC handshake is dropped before it yields a
    // connection, so nothing has been admitted and nothing is lost. Without
    // this arm a peer that opens a connection and then stalls would hold the
    // ingest drain open for as long as it cared to.
    let connection = select! {
        biased;
        () = token.cancelled() => return Ok(()),
        connection = conn => connection?,
    };

    // Cancellation branch. Same story one step further in: the version
    // handshake is dropped and the connection is closed. The sensor has sent
    // no events yet, and the connect below has not been recorded, so there is
    // no state to undo.
    let handshake = select! {
        biased;
        () = token.cancelled() => {
            connection.close(0_u32.into(), b"shutting down");
            return Ok(());
        }
        handshake = server_handshake(&connection, INGEST_VERSION_REQ) => handshake,
    };
    match handshake {
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

    let cert_chain = extract_cert_from_conn(&connection)?;
    log_connected_client(&cert_chain)?;
    let (service_name, sensor) = service_fqdn_from_cert(&cert_chain)?;
    let host_fqdn = host_fqdn_from_cert(&cert_chain)?;
    let is_pcap_sensor = service_name.contains("piglet");

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
            DateTime::now(),
            ConnState::Connected,
            is_pcap_sensor,
        ))
        .await
    {
        error!("Failed to send channel data : {error}");
    }

    loop {
        select! {
            biased;

            // Cancellation branch. The pending `accept_bi` is dropped, so a
            // stream the sensor was in the middle of opening is lost — nothing
            // on it was received, let alone acknowledged, and the sensor
            // reopens it against the next generation.
            //
            // Streams already admitted are still tracked and drained on their
            // own, but this connection is theirs, so closing it here does end
            // their reads: a handler that has not yet observed its own
            // cancellation sees the read fail instead. That costs no appended
            // data — every exit from the receive loop flushes the store before
            // it returns — and nothing it drops was acknowledged. Leaving the
            // connection open instead would mean it closed by drop, with no
            // close frame for the sensor to see.
            //
            // The disconnect recorded below is the cleanup this branch owes,
            // and it balances the connect recorded above so runtime sensor and
            // pcap connection state do not keep this connection after it is
            // gone.
            () = token.cancelled() => {
                if let Err(error) = sender
                    .send((sensor, DateTime::now(), ConnState::Disconnected, is_pcap_sensor))
                    .await
                {
                    error!("Failed to send internal channel data: {error}");
                }
                connection.close(0_u32.into(), b"shutting down");
                return Ok(())
            },

            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(conn_err) => {
                        if let Err(error) = sender
                            .send((sensor, DateTime::now(), ConnState::Disconnected, is_pcap_sensor))
                            .await
                        {
                            error!("Failed to send internal channel data: {error}");
                        }
                        match conn_err {
                            quinn::ConnectionError::ApplicationClosed(_) => {
                                info!("{service_name} has disconnected from ingest");
                                return Ok(());
                            }
                            _ => return Err(conn_err.into()),
                        }
                    }
                    Ok(s) => s,
                };
                let task_name = format!("ingest-stream-{sensor}-{}", stream.1.id());
                let error_label = task_name.clone();
                let sensor = sensor.clone();
                let host_fqdn = host_fqdn.clone();
                let db = db.clone();
                let stream_direct_channels = stream_direct_channels.clone();
                let spawned = tracker.spawn(task_name.clone(), move |token| async move {
                    if let Err(e) = handle_request(sensor, host_fqdn, stream, db, stream_direct_channels, token, ack_trans_cnt).await {
                        error!("{error_label} failed: {e}");
                    }
                });
                // The handle is dropped for the same reason the entry task
                // drops this connection's: the handler names itself in its own
                // error log, and the tracker reports it if it ends without
                // returning. A rejected stream means admission has already
                // closed, so the cancellation branch takes over on the next
                // round and closes the connection.
                if let Err(e) = spawned {
                    warn!("Rejected {task_name}: {e}");
                }
            },
        }
    }
}

fn log_connected_client(cert_chain: &[rustls::pki_types::CertificateDer<'_>]) -> Result<()> {
    let client_display = connected_client_display_from_cert(cert_chain)?;
    info!("Connected client (ingest) name : {}", client_display);
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn handle_request(
    sensor: String,
    host_fqdn: String,
    (send, mut recv): (SendStream, RecvStream),
    db: Database,
    stream_direct_channels: StreamDirectChannels,
    token: CancellationToken,
    ack_trans_cnt: u16,
) -> Result<()> {
    let mut buf = [0; 4];
    select! {
        biased;

        // Cancellation branch. The record header is dropped half-read, which
        // abandons the stream before a single event has been decoded or
        // appended. Nothing on it was acknowledged, so the sensor resends the
        // whole stream to the next generation.
        () = token.cancelled() => return Ok(()),

        header = receive_record_header(&mut recv, &mut buf) => {
            header.map_err(|e| anyhow!("failed to read record type: {e}"))?;
        }
    }
    match RawEventKind::try_from(u32::from_le_bytes(buf)).context("unknown raw event kind")? {
        RawEventKind::Conn => {
            handle_data(
                send,
                recv,
                RawEventKind::Conn,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Conn)),
                sensor,
                db.conn_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Dns => {
            handle_data(
                send,
                recv,
                RawEventKind::Dns,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Dns)),
                sensor,
                db.dns_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::MalformedDns => {
            handle_data(
                send,
                recv,
                RawEventKind::MalformedDns,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::MalformedDns)),
                sensor,
                db.malformed_dns_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Log => {
            handle_data(
                send,
                recv,
                RawEventKind::Log,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Log)),
                sensor,
                db.log_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Http => {
            handle_data(
                send,
                recv,
                RawEventKind::Http,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Http)),
                sensor,
                db.http_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Rdp => {
            handle_data(
                send,
                recv,
                RawEventKind::Rdp,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Rdp)),
                sensor,
                db.rdp_store()?,
                stream_direct_channels,
                &token,
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
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Smtp => {
            handle_data(
                send,
                recv,
                RawEventKind::Smtp,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Smtp)),
                sensor,
                db.smtp_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Ntlm => {
            handle_data(
                send,
                recv,
                RawEventKind::Ntlm,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Ntlm)),
                sensor,
                db.ntlm_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Kerberos => {
            handle_data(
                send,
                recv,
                RawEventKind::Kerberos,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Kerberos)),
                sensor,
                db.kerberos_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Ssh => {
            handle_data(
                send,
                recv,
                RawEventKind::Ssh,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Ssh)),
                sensor,
                db.ssh_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::DceRpc => {
            handle_data(
                send,
                recv,
                RawEventKind::DceRpc,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::DceRpc)),
                sensor,
                db.dce_rpc_store()?,
                stream_direct_channels,
                &token,
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
                &token,
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
                host_fqdn,
                db.op_log_store()?,
                stream_direct_channels,
                &token,
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
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Ftp => {
            handle_data(
                send,
                recv,
                RawEventKind::Ftp,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Ftp)),
                sensor,
                db.ftp_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Mqtt => {
            handle_data(
                send,
                recv,
                RawEventKind::Mqtt,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Mqtt)),
                sensor,
                db.mqtt_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Ldap => {
            handle_data(
                send,
                recv,
                RawEventKind::Ldap,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Ldap)),
                sensor,
                db.ldap_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Tls => {
            handle_data(
                send,
                recv,
                RawEventKind::Tls,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Tls)),
                sensor,
                db.tls_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Smb => {
            handle_data(
                send,
                recv,
                RawEventKind::Smb,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Smb)),
                sensor,
                db.smb_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Nfs => {
            handle_data(
                send,
                recv,
                RawEventKind::Nfs,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Nfs)),
                sensor,
                db.nfs_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Bootp => {
            handle_data(
                send,
                recv,
                RawEventKind::Bootp,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Bootp)),
                sensor,
                db.bootp_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Dhcp => {
            handle_data(
                send,
                recv,
                RawEventKind::Dhcp,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Dhcp)),
                sensor,
                db.dhcp_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Radius => {
            handle_data(
                send,
                recv,
                RawEventKind::Radius,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Radius)),
                sensor,
                db.radius_store()?,
                stream_direct_channels,
                &token,
                ack_trans_cnt,
            )
            .await?;
        }
        RawEventKind::Icmp => {
            handle_data(
                send,
                recv,
                RawEventKind::Icmp,
                Some(NetworkKey::new(&sensor, RequestStreamRecord::Icmp)),
                sensor,
                db.icmp_store()?,
                stream_direct_channels,
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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
                &token,
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

/// Receives one raw frame, handing `recv` and `buf` back to the caller.
///
/// [`recv_raw`] is not cancel-safe: it reads a length header and then the body
/// it announces, so a future dropped in between has already taken bytes off
/// the stream and the next read starts mid-frame. The receive loop therefore
/// keeps one of these futures alive across `select!` rounds instead of
/// starting a fresh read each round, and ownership has to travel through the
/// future for that to work — a borrow would be held for as long as the future
/// lives, leaving the loop unable to touch either value between frames.
async fn recv_frame(
    mut recv: RecvStream,
    mut buf: Vec<u8>,
) -> (RecvStream, Vec<u8>, Result<(), RecvError>) {
    buf.clear();
    let result = recv_raw(&mut recv, &mut buf).await;
    (recv, buf, result)
}

/// Receives one stream's raw events, appends them, and acknowledges them.
///
/// The handler owns the send stream, the ACK counter, and the ACK timestamp
/// outright. They used to be shared with a ticker task through a
/// `Mutex<SendStream>` and two atomics, which held a lock across the ACK write
/// and left a task the handler could only get rid of by aborting it. One owner
/// removes both: the interval is an arm of this loop, so it stops when the
/// loop does, and there is nothing left to abort at shutdown.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_data<T>(
    mut send: SendStream,
    recv: RecvStream,
    raw_event_kind: RawEventKind,
    network_key: Option<NetworkKey>,
    sensor: String,
    store: RawEventStore<'_, T>,
    stream_direct_channels: StreamDirectChannels,
    token: &CancellationToken,
    ack_trans_cnt: u16,
) -> Result<()> {
    info!("Raw event {raw_event_kind:?} has been connected");

    let mut ack_cnt: u16 = 0;
    let mut ack_time: i64 = NO_TIMESTAMP;
    let mut itv = time::interval(time::Duration::from_secs(ACK_INTERVAL_TIME));
    itv.reset();
    // The ticker task used to leave its loop when a periodic ACK failed to
    // send, while the receive loop carried on. Disabling the arm keeps that:
    // a broken send stream stops the periodic ACKs, and the receive side
    // reports the failure on its own terms.
    let mut ack_interval_live = true;

    let mut err_msg = None;
    #[cfg(feature = "benchmark")]
    let stream_id = recv.id();

    #[cfg(feature = "benchmark")]
    let mut count = 0_usize;
    #[cfg(feature = "benchmark")]
    let mut size = 0_usize;
    #[cfg(feature = "benchmark")]
    let mut start = std::time::Instant::now();

    let mut frame = Box::pin(recv_frame(recv, Vec::new()));
    let mut last_timestamp = 0;
    loop {
        select! {
            biased;

            // Cancellation branch. The frame being read is dropped, so input
            // that was not fully received, decoded, and appended is lost. It
            // was never acknowledged either, so the sensor resends it. What
            // was appended stays: the flush below runs before this handler
            // returns, and the ingest entry task does not return until the
            // drain has collected it. No final ACK is sent — shutdown puts
            // nothing on the wire that the batching and interval rules would
            // not have sent anyway.
            () = token.cancelled() => break,

            // The periodic ACK, polled ahead of the receive arm: a `biased`
            // select takes the first ready arm, and a stream with a frame
            // always waiting would otherwise never let the deadline through.
            // Cancel-safe either way — `Interval::tick` only records that a
            // deadline passed, so a round another arm wins costs nothing.
            _ = itv.tick(), if ack_interval_live => {
                if ack_time != NO_TIMESTAMP {
                    if let Err(e) = send_ack_timestamp(&mut send, ack_time).await {
                        error!(
                            "Raw event {raw_event_kind:?} from {sensor}: periodic ack \
                             failed, no more will be sent on this stream: {e}"
                        );
                        ack_interval_live = false;
                    } else {
                        ack_cnt = 0;
                    }
                }
            }

            (stream, buf, result) = &mut frame => {
                match result {
                    Ok(()) => {}
                    // The sensor finished the stream: everything it sent has
                    // been received, so there is nothing left to read.
                    Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_))) => break,
                    Err(e) => {
                        err_msg = Some(format!("handle {raw_event_kind:?} error: {e}"));
                        break;
                    }
                }

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
                // Compute date_key once per batch for OpLog sequence generation.
                // This avoids repeated DateTime::now() calls on the hot path.
                let date_key =
                    (raw_event_kind == RawEventKind::OpLog).then(SequenceGenerator::get_date_key);

                for (timestamp, mut raw_event) in recv_buf {
                    last_timestamp = timestamp;
                    if (timestamp == CHANNEL_CLOSE_TIMESTAMP)
                        && (raw_event.as_bytes() == CHANNEL_CLOSE_MESSAGE)
                    {
                        if let Err(e) = send_ack_timestamp(&mut send, timestamp).await {
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
                            let sequence_number = generator.generate_sequence_number(
                                date_key.expect("date_key must exist for OpLog"),
                            );
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
                    // Reported through `err_msg` rather than `?` for the same
                    // reason as the ACK below: the flush on the way out is what
                    // everything appended before this event depends on, and
                    // returning here would skip it.
                    if let Err(e) = store.append(&storage_key.key(), &raw_event) {
                        err_msg = Some(format!("Failed to append {raw_event_kind:?} event: {e}"));
                        break;
                    }
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

                ack_cnt = ack_cnt.saturating_add(recv_events_cnt);
                ack_time = last_timestamp;
                if ack_trans_cnt <= ack_cnt {
                    // Reported through `err_msg` rather than `?` so the flush
                    // below still runs. The connection handler closes the
                    // connection as soon as it observes cancellation, which
                    // breaks this send while the events behind it are already
                    // appended; returning here would leave them unflushed.
                    if let Err(e) = send_ack_timestamp(&mut send, last_timestamp).await {
                        err_msg = Some(format!("Failed to send ack timestamp: {e}"));
                        break;
                    }
                    ack_cnt = 0;
                    // The interval measures time since the last ACK, so one
                    // sent on the count restarts it.
                    itv.reset();
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

                frame.set(recv_frame(stream, buf));
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

/// Applies one sensor-state update to the sensor store and the runtime maps.
///
/// Shared by the steady-state loop and the post-cancellation drain below, so
/// an update admitted to the channel is applied the same way whichever side
/// takes it off.
async fn apply_sensor_update(
    (sensor_key, time_val, conn_state, is_pcap_sensor): SensorInfo,
    sensor_store: &SensorStore<'_>,
    pcap_sensors: &PcapSensors,
    ingest_sensors: &IngestSensors,
    runtime_ingest_sensors: &RunTimeIngestSensors,
    notify_sensor: Option<&Arc<Notify>>,
) {
    match conn_state {
        ConnState::Connected => {
            if sensor_store.insert(&sensor_key, time_val).is_err() {
                error!("Failed to append sensor store");
            }
            runtime_ingest_sensors
                .write()
                .await
                .insert(sensor_key.clone(), time_val);
            ingest_sensors.write().await.insert(sensor_key);
            if let Some(notify) = notify_sensor {
                notify.notify_one();
            }
        }
        ConnState::Disconnected => {
            if sensor_store.insert(&sensor_key, time_val).is_err() {
                error!("Failed to append sensor store");
            }
            runtime_ingest_sensors.write().await.remove(&sensor_key);
            if is_pcap_sensor
                && let Some(connections) = pcap_sensors
                    .write()
                    .await
                    .get_mut(&sensor_key)
                    .filter(|connection_vec| !connection_vec.is_empty())
            {
                connections.remove(0);
            }
        }
    }
}

/// Keeps the sensor store and the runtime sensor maps in step with the
/// connect/disconnect updates the connection handlers report.
///
/// # Errors
///
/// Returns an error only through the caller's `Result`; every per-update
/// failure is logged and the task keeps going, because one sensor whose row
/// could not be written must not take the rest of the subsystem's bookkeeping
/// down with it.
async fn check_sensors_conn(
    sensor_db: Database,
    pcap_sensors: PcapSensors,
    ingest_sensors: IngestSensors,
    runtime_ingest_sensors: RunTimeIngestSensors,
    mut rx: Receiver<SensorInfo>,
    notify_sensor: Option<Arc<Notify>>,
    token: CancellationToken,
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
                    let time = DateTime::now();
                    if sensor_store.insert(&sensor_key, time).is_err(){
                        error!("Failed to append sensor store");
                    }
                    runtime_sensors.insert(sensor_key, time);
                }
            }

            Some(update) = rx.recv() => {
                apply_sensor_update(
                    update,
                    &sensor_store,
                    &pcap_sensors,
                    &ingest_sensors,
                    &runtime_ingest_sensors,
                    notify_sensor.as_ref(),
                )
                .await;
            }

            // Cancellation branch. The periodic refresh is dropped, and with
            // it at most one round of last-seen timestamps that the next tick
            // would have rewritten anyway. Updates are not dropped: the drain
            // below takes over from this arm and applies every one still in
            // the channel.
            () = token.cancelled() => break,
        }
    }

    // Cancellation closed ingest admission, so no newly accepted connection
    // can produce an update from here on. What the handlers already sent, and
    // what the ones still cleaning up are about to send, is applied before
    // this task returns: the entry task dropped its own sender, so the channel
    // closes as the last handler returns.
    while let Some(update) = rx.recv().await {
        apply_sensor_update(
            update,
            &sensor_store,
            &pcap_sensors,
            &ingest_sensors,
            &runtime_ingest_sensors,
            notify_sensor.as_ref(),
        )
        .await;
    }

    Ok(())
}

pub(crate) struct NetworkKey {
    pub(crate) sensor: String,
    pub(crate) record_type: RequestStreamRecord,
}

impl NetworkKey {
    pub(crate) fn new(sensor: &str, record_type: RequestStreamRecord) -> Self {
        Self {
            sensor: sensor.to_string(),
            record_type,
        }
    }
}
