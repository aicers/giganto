pub mod implement;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::connection::client_handshake;
use giganto_client::ingest::log::Log;
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use giganto_client::ingest::network::{
    Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Icmp, Kerberos, Ldap, MalformedDns, Mqtt, Nfs, Ntlm,
    Radius, Rdp, Smb, Smtp, Ssh, Tls,
};
use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};
use giganto_client::ingest::timeseries::PeriodicTimeSeries;
use giganto_client::publish::{
    PublishError, receive_range_data, recv_ack_response, send_range_data_request,
};
use giganto_client::{
    RawEventKind,
    connection::server_handshake,
    frame::{self, send_raw},
    publish::{
        PcapFilter, pcap_extract_request,
        range::{MessageCode, RequestRange, RequestRawData, ResponseRangeData},
        receive_range_data_request, receive_stream_request, send_err, send_ok, send_range_data,
        send_semi_supervised_stream_start_message,
        stream::{RequestStreamRecord, StreamRequestPayload},
    },
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig, VarInt};
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use self::implement::RequestStreamMessage;
use crate::cancellation::{DRAIN_REPORT_INTERVAL, TaskTracker, drain_with_report};
use crate::comm::{
    IngestSensors, PcapSensors, StreamDirectChannels,
    ingest::{NetworkKey, implement::EventFilter},
    peer::{PeerIdents, Peers},
    stream_channel_key::StreamChannelKey,
};
use crate::datetime::DateTime;
use crate::graphql::TIMESTAMP_SIZE;
use crate::server::{
    Certs, config_client, config_server, connected_client_display_from_cert,
    extract_cert_from_conn, service_fqdn_from_cert,
};
use crate::storage::{Database, Direction, RawEventStore, StorageKey};
use crate::tls_reload::{self, TlsWatch};

const PUBLISH_VERSION_REQ: &str = ">=0.28.0,<0.29.0";
/// Names the publish subsystem tracker in the drain progress log.
const PUBLISH_DRAIN_LABEL: &str = "publish";

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

    /// Binds the publish listener and serves it until `token` is cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot be bound, if the publish task
    /// tracker rejects one of the subsystem's own tasks, or if a tracker lock
    /// is poisoned. A bind failure used to panic a detached task; it is
    /// reported to the caller now that the entry task is tracked.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        self,
        db: Database,
        pcap_sensors: PcapSensors,
        stream_direct_channels: StreamDirectChannels,
        ingest_sensors: IngestSensors,
        peers: Peers,
        peer_idents: PeerIdents,
        tls_watch: TlsWatch,
        token: CancellationToken,
    ) -> Result<()> {
        self.bind()
            .context("failed to bind the publish listener")?
            .run(
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
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

    /// Serves the bound publish listener until `token` is cancelled, then
    /// drains every task it admitted.
    ///
    /// Publish owns a subsystem tracker built from `token`, so the top-level
    /// tracker's cancellation reaches every connection handler, every request
    /// handler, every stream subscription, and every background PCAP relay it
    /// started. Cancellation ends admission on both sides: this loop stops
    /// accepting, and closing the tracker stops the handlers from registering
    /// more work. The entry task returns only once the drain is empty, so no
    /// publish task is left writing to a client when the generation moves on.
    /// What runs after the loop is [`shutdown_publish`], called
    /// unconditionally as the last statement here.
    ///
    /// # Errors
    ///
    /// Returns an error if the publish task tracker rejects one of the
    /// subsystem's own tasks or if a tracker lock is poisoned.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(crate) async fn run(
        self,
        db: Database,
        pcap_sensors: PcapSensors,
        stream_direct_channels: StreamDirectChannels,
        ingest_sensors: IngestSensors,
        peers: Peers,
        peer_idents: PeerIdents,
        mut tls_watch: TlsWatch,
        token: CancellationToken,
    ) -> Result<()> {
        let local_addr = self.local_addr();
        let endpoint = self.endpoint;
        info!("Publish listening on {local_addr}");

        // Built from the token handed down by `main`, so the top-level
        // `cancel_children` reaches everything registered here. Building it
        // with `TaskTracker::new()` would start a fresh root and cut publish
        // off from process shutdown without the compiler noticing.
        let tracker = TaskTracker::with_token(token.clone());

        loop {
            select! {
                biased;

                // Cancellation branch. Nothing admitted is lost here: the arms
                // below hold only a QUIC handshake that has not produced a
                // connection yet and a TLS update that changes nothing for
                // connections already up. A client that connects from now on
                // is neither admitted nor rejected — `accept()` is simply no
                // longer polled — and it ends when the endpoint is closed
                // after the drain. `biased` is what keeps a steady stream of
                // arrivals from starving this arm.
                () = token.cancelled() => {
                    info!("Shutting down publish");
                    break;
                }

                // Reload TLS server config when new material is available.
                // Existing connections remain alive; only new handshakes
                // use the refreshed certificate. Polled ahead of the accept
                // arm because a `biased` select takes the first ready arm, and
                // a steady stream of incoming connections would otherwise keep
                // a reload waiting.
                Ok(()) = tls_watch.changed() => {
                    let tls = tls_watch.borrow_and_update().clone();
                    match config_server(&tls.certs) {
                        Ok(new_config) => {
                            endpoint.set_server_config(Some(new_config));
                            info!("Publish listener: server config reloaded");
                        }
                        Err(e) => {
                            error!(
                                "Publish listener: failed to build server config \
                                 from reloaded TLS material, keeping current config: {e:#}"
                            );
                        }
                    }
                },

                Some(conn) = endpoint.accept() => {
                    let remote = conn.remote_address();
                    let db = db.clone();
                    let pcap_sensors = pcap_sensors.clone();
                    let stream_direct_channels = stream_direct_channels.clone();
                    let ingest_sensors = ingest_sensors.clone();
                    let peers = peers.clone();
                    let peer_idents = peer_idents.clone();
                    let tls_watch = tls_watch.clone();
                    let connection_tracker = tracker.clone();
                    let spawned = tracker.spawn(
                        format!("publish-conn-{remote}"),
                        move |token| async move {
                            if let Err(e) = handle_connection(
                                conn,
                                db,
                                pcap_sensors,
                                stream_direct_channels,
                                ingest_sensors,
                                peers,
                                peer_idents,
                                tls_watch,
                                connection_tracker,
                                token,
                            )
                            .await
                            {
                                error!("Publish connection to {remote} failed: {e:#}");
                            }
                        },
                    );
                    // The handle is dropped: a connection handler logs its own
                    // domain errors and the tracker reports any task that
                    // vanishes without returning, so there is no outcome left
                    // for the entry task to observe. The rejection branch is
                    // defensive — the loop leaves on cancellation before the
                    // tracker is closed, so nothing in the shutdown sequence
                    // makes it fire — but the `Result` has to be handled and
                    // the branch records the invariant.
                    if let Err(e) = spawned {
                        warn!("Rejected publish connection from {remote}: {e}");
                    }
                },
            }
        }

        shutdown_publish(&tracker, &endpoint).await
    }
}

/// Everything the publish entry task does after it has left its accept loop.
///
/// Extracted from [`BoundServer::run`] purely so a test can drive it over a
/// tracker of its own — a tracker built inside `run` is reachable from
/// nowhere else, and the recovery a poisoned drain performs is what these
/// statements have to survive. `run` calls it unconditionally as its last
/// statement, so the two are the same sequence.
///
/// # Errors
///
/// Returns an error if the drain reported a poisoned tracker lock. The
/// listener has been torn down first either way, so the address publish was
/// pinned to is released for the next generation on the failing path exactly
/// as on the healthy one.
async fn shutdown_publish(tracker: &TaskTracker, endpoint: &Endpoint) -> Result<()> {
    // Admission rejection, the half the accept loop cannot do on its own:
    // a closed tracker turns away every request handler, subscription, and
    // relay a still-running handler might try to register. Failing here is no
    // longer fatal: `drain_with_report` closes the tracker itself, through a
    // poisoned admission lock if it has to, so this close only shuts
    // admission a little earlier than the drain would.
    if let Err(e) = tracker.close() {
        error!("failed to close the publish task tracker: {e}");
    }
    // Same policy as the top level: report every round and keep waiting.
    // `drain_with_report` closes and cancels again, both idempotent. Its
    // error is captured rather than propagated on the spot, because it means
    // the tracker is empty and the teardown below still has to run.
    let drained = drain_with_report(tracker, DRAIN_REPORT_INTERVAL, PUBLISH_DRAIN_LABEL)
        .await
        .context("failed to drain the publish task tracker");

    // Only now, with every handler returned, is the listener torn down.
    // Closing it earlier would kill the connections the subscriptions and
    // request handlers are still writing their last frames on, and it is
    // also what ends the connections that arrived after the accept loop
    // left.
    endpoint.close(0_u32.into(), &[]);
    endpoint.wait_idle().await;

    drained
}

/// Serves one publish connection: the version handshake, the request-stream
/// task, and one request handler per bi-directional stream the client opens.
///
/// Cancelled by explicit branches. This task owns the connection every task it
/// spawns writes on, so it must not die by drop: the two branches that fire
/// before any work is admitted close the connection, and every branch after
/// that leaves it open for the post-drain endpoint close.
///
/// `tracker` is the publish subsystem tracker, carried in so the request
/// stream and the request handlers spawned here land in the same registry as
/// this task rather than escaping it, and `token` is this task's own child of
/// that tracker's root.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_connection(
    conn: quinn::Incoming,
    db: Database,
    pcap_sensors: PcapSensors,
    stream_direct_channels: StreamDirectChannels,
    ingest_sensors: IngestSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    tls_watch: TlsWatch,
    tracker: TaskTracker,
    token: CancellationToken,
) -> Result<()> {
    let remote = conn.remote_address();

    // Cancellation branch. The QUIC handshake is dropped before it yields a
    // connection, so nothing has been admitted and there is nothing to clean
    // up. Without this arm a client that opens a connection and then stalls
    // would hold the publish drain open for as long as it cared to.
    let connection = select! {
        biased;
        () = token.cancelled() => return Ok(()),
        connection = conn => connection?,
    };

    // Cancellation branch. Same story one step further in: the version
    // handshake is dropped and the connection is closed. A client can finish
    // QUIC transport setup and never send its version message, so this wait
    // is the one a stalled client would otherwise park the drain on. Nothing
    // has been admitted on this connection yet, and the client has been told
    // nothing, so closing it here gives it a close frame instead of a
    // connection that dies by drop.
    let handshake = select! {
        biased;
        () = token.cancelled() => {
            connection.close(0_u32.into(), b"shutting down");
            return Ok(());
        }
        handshake = server_handshake(&connection, PUBLISH_VERSION_REQ) => handshake,
    };
    let (send, recv) = match handshake {
        Ok((send, recv)) => {
            info!("Compatible version");
            (send, recv)
        }
        Err(e) => {
            info!("Incompatible version");
            connection.close(quinn::VarInt::from_u32(0), e.to_string().as_bytes());
            bail!("{e}")
        }
    };
    let cert_chain = extract_cert_from_conn(&connection)?;
    log_connected_client(&cert_chain)?;
    let (service_name, sensor) = service_fqdn_from_cert(&cert_chain)?;

    let req_stream_name = format!("publish-req-stream-{sensor}-{remote}");
    let spawned = tracker.spawn(req_stream_name.clone(), {
        let error_label = req_stream_name.clone();
        let connection = connection.clone();
        let db = db.clone();
        let sensor = sensor.clone();
        let pcap_sensors = pcap_sensors.clone();
        let stream_direct_channels = stream_direct_channels.clone();
        let peers = peers.clone();
        let peer_idents = peer_idents.clone();
        let tls_watch = tls_watch.clone();
        let stream_tracker = tracker.clone();
        move |token| async move {
            if let Err(e) = request_stream(
                connection,
                db,
                send,
                recv,
                sensor,
                pcap_sensors,
                stream_direct_channels,
                peers,
                peer_idents,
                tls_watch,
                stream_tracker,
                token,
            )
            .await
            {
                error!("{error_label} failed: {e:#}");
            }
        }
    });
    // The handle is dropped rather than joined on the way out: the
    // request-stream task names itself in its own error log, the tracker
    // reports it if it ends without returning, and the drain is what waits for
    // it now. A rejection means admission has already closed, so the
    // subscription work this stream would have carried stays unrun.
    if let Err(e) = spawned {
        warn!("Rejected {req_stream_name}: {e}");
    }

    loop {
        select! {
            biased;

            // Cancellation branch. The pending `accept_bi` is dropped, so a
            // stream the client was in the middle of opening is lost; nothing
            // was written on it, and the client detects the missing response
            // and retries.
            //
            // This connection has admitted work by now, so it is deliberately
            // left open: the request-stream task, the subscriptions it
            // started, and the request handlers below are all still writing
            // and cleaning up on it, and they observe their own tokens. The
            // endpoint close at the end of the entry task's shutdown sequence
            // delivers the close frame to every remaining connection at once.
            () = token.cancelled() => return Ok(()),

            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        info!("{service_name} has disconnected from publish");
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                    Ok(s) => s,
                };

                let task_name = format!("publish-request-{sensor}-{}", stream.1.id());
                let error_label = task_name.clone();
                let request_label = task_name.clone();
                let db = db.clone();
                let pcap_sensors = pcap_sensors.clone();
                let ingest_sensors = ingest_sensors.clone();
                let peers = peers.clone();
                let peer_idents = peer_idents.clone();
                let tls_watch = tls_watch.clone();
                let request_tracker = tracker.clone();
                let spawned = tracker.spawn(task_name.clone(), move |token| async move {
                    // Cancelled by drop, at the task level. Everything a
                    // request handler holds is a QUIC stream and a store
                    // iterator, and the only loss is a response the client
                    // sees truncated and retries, so the body is dropped
                    // wherever it happens to be awaiting rather than carrying
                    // a branch at each of its many response writes. Dropping
                    // the inner future does not trip the tracker's
                    // completion warning: the tracked future is this wrapper,
                    // and the wrapper returns normally.
                    let request_token = token.clone();
                    select! {
                        biased;
                        () = token.cancelled() => {}
                        result = handle_request(
                            stream,
                            db,
                            pcap_sensors,
                            ingest_sensors,
                            peers,
                            peer_idents,
                            tls_watch,
                            request_tracker,
                            request_label,
                            request_token,
                        ) => {
                            if let Err(e) = result {
                                error!("{error_label} failed: {e:#}");
                            }
                        }
                    }
                });
                // The handle is dropped for the same reason the entry task
                // drops this connection's: the handler names itself in its own
                // error log, and the tracker reports it if it ends without
                // returning. A rejected request means admission has already
                // closed, so the request stays unrun and the cancellation
                // branch takes over on the next round.
                if let Err(e) = spawned {
                    warn!("Rejected {task_name}: {e}");
                }
            },
        }
    }
}

fn log_connected_client(cert_chain: &[rustls::pki_types::CertificateDer<'_>]) -> Result<()> {
    let client_display = connected_client_display_from_cert(cert_chain)?;
    info!("Connected client (publish) name : {}", client_display);
    Ok(())
}

/// Reads stream requests off a publish connection's control stream and starts
/// one task per subscription, plus one background relay task per accepted PCAP
/// extraction request.
///
/// Cancelled by explicit branches. It owns no shared state of its own — the
/// subscriptions it starts own theirs — but it does own the control stream's
/// receive side, so it stops reading rather than dying by drop.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn request_stream(
    connection: Connection,
    stream_db: Database,
    mut send: SendStream,
    mut recv: RecvStream,
    conn_sensor: String,
    pcap_sensors: PcapSensors,
    stream_direct_channels: StreamDirectChannels,
    peers: Peers,
    peer_idents: PeerIdents,
    tls_watch: TlsWatch,
    tracker: TaskTracker,
    token: CancellationToken,
) -> Result<()> {
    loop {
        // Cancellation branch. A stream request that was half-read off the
        // control stream is dropped; nothing was started for it and nothing
        // was answered, so the client sees the connection end without a start
        // message and re-subscribes to the next generation. Subscriptions and
        // relays already started are tracked and drained on their own.
        let request = select! {
            biased;
            () = token.cancelled() => return Ok(()),
            request = receive_stream_request(&mut recv) => request,
        };

        match request {
            Ok(stream_payload) => {
                let db = stream_db.clone();
                let conn = connection.clone();
                let sensor = conn_sensor.clone();
                let stream_direct_channels = stream_direct_channels.clone();

                match stream_payload {
                    StreamRequestPayload::PcapExtraction { filter } => {
                        process_pcap_extract_filters(
                            filter,
                            pcap_sensors.clone(),
                            peers.clone(),
                            peer_idents.clone(),
                            tls_watch.clone(),
                            &mut send,
                            &conn_sensor,
                            &tracker,
                            &token,
                        )
                        .await?;
                    }
                    StreamRequestPayload::SemiSupervised {
                        record_type,
                        request,
                    } => {
                        let task_name = stream_task_name(Some(&conn_sensor), record_type, &request);
                        let error_label = task_name.clone();
                        let spawned = tracker.spawn(task_name.clone(), move |token| async move {
                            if let Err(e) = process_stream(
                                db,
                                conn,
                                Some(sensor),
                                None,
                                record_type,
                                request,
                                stream_direct_channels,
                                token,
                            )
                            .await
                            {
                                error!("{error_label} failed: {e:#}");
                            }
                        });
                        // The handle is dropped: the subscription reports its
                        // own errors under the name above, and the drain is
                        // what waits for it. A rejection means admission has
                        // already closed, so the subscription stays unrun
                        // rather than escaping the tracker.
                        if let Err(e) = spawned {
                            warn!("Rejected {task_name}: {e}");
                        }
                    }
                    StreamRequestPayload::TimeSeriesGenerator {
                        record_type,
                        request,
                    } => {
                        let task_name = stream_task_name(None, record_type, &request);
                        let error_label = task_name.clone();
                        let spawned = tracker.spawn(task_name.clone(), move |token| async move {
                            if let Err(e) = process_stream(
                                db,
                                conn,
                                None,
                                None,
                                record_type,
                                request,
                                stream_direct_channels,
                                token,
                            )
                            .await
                            {
                                error!("{error_label} failed: {e:#}");
                            }
                        });
                        // Dropped and logged for the same reasons as the
                        // semi-supervised subscription above.
                        if let Err(e) = spawned {
                            warn!("Rejected {task_name}: {e}");
                        }
                    }
                }
            }
            Err(e) => {
                error!("Publish stream request from {conn_sensor} failed: {e:#}");
                let _ = recv.stop(VarInt::from_u32(0));
                break;
            }
        }
    }
    Ok(())
}

/// Names one subscription task after the sensor it serves and, for a time
/// series generator, the stream id its request carries.
///
/// Only the time series generator request implements `sensor` and `id`; the
/// semi-supervised one panics on both, so its name comes from the connection's
/// sensor instead. Neither is required to answer: a request that carries no
/// sensor or no id still has to be named, so what it does not supply is left
/// out of the name rather than failing it.
fn stream_task_name<T: RequestStreamMessage>(
    conn_sensor: Option<&str>,
    record_type: RequestStreamRecord,
    request: &T,
) -> String {
    if request.is_time_series_generator() {
        let sensor = request.sensor().unwrap_or_else(|_| "unknown".to_string());
        let id = request.id().map_or_else(String::new, |id| format!("-{id}"));
        return format!("publish-stream-{sensor}-{record_type:?}{id}");
    }
    let sensor = conn_sensor.unwrap_or("unknown");
    format!("publish-stream-{sensor}-{record_type:?}")
}

/// Acknowledges a PCAP extraction request and starts the background relay that
/// carries it to the sensors and peers in charge.
///
/// The acknowledgement means the request was accepted for background
/// processing, not that the relay completed, so the relay is best-effort: it
/// stays tracked, observes cancellation, and reports what it could not deliver
/// through the log rather than gaining a durable-retry guarantee.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn process_pcap_extract_filters(
    filters: Vec<PcapFilter>,
    pcap_sensors: PcapSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    tls_watch: TlsWatch,
    resp_send: &mut SendStream,
    owner: &str,
    tracker: &TaskTracker,
    token: &CancellationToken,
) -> Result<()> {
    let mut buf = Vec::new();
    // Cancellation branch. The acknowledgement is abandoned unwritten, so the
    // request is never accepted and no relay is started for it; the client
    // sees no ack and can retry against the next generation.
    let acked = select! {
        biased;
        () = token.cancelled() => return Ok(()),
        acked = send_ok(resp_send, &mut buf, ()) => acked,
    };
    acked.context("Failed to send ok")?;

    let task_name = format!("publish-pcap-relay-{owner}");
    let error_label = task_name.clone();
    let spawned = tracker.spawn(task_name.clone(), move |token| async move {
        // Cancelled by explicit branches. The relay owns outbound peer
        // connections, so a branch that fires with one up closes it rather
        // than letting it die by drop.
        for filter in filters {
            if token.is_cancelled() {
                // The filters left unrelayed are reported rather than
                // retried: the ack promised acceptance, not delivery.
                warn!("{error_label} gave up a pcap filter on shutdown");
                break;
            }
            if let Some(sensor_conn) =
                get_pcap_conn_if_current_giganto_in_charge(pcap_sensors.clone(), &filter.sensor)
                    .await
            {
                // send/receive extract request from the Sensor.
                //
                // Cancellation branch. The exchange with the sensor is
                // dropped; the sensor owns that connection, so there is
                // nothing here to close.
                let Some(relayed) = token
                    .run_until_cancelled(pcap_extract_request(&sensor_conn, &filter))
                    .await
                else {
                    warn!("{error_label} gave up relaying a pcap request to a sensor");
                    break;
                };
                if let Err(e) = relayed {
                    debug!("{error_label}: Failed to relay pcap request: {e}");
                }
            } else if let Some(peer_addr) =
                peer_in_charge_publish_addr(peers.clone(), &filter.sensor).await
            {
                let peer_name: String = {
                    let peer_idents_guard = peer_idents.read().await;
                    let peer_ident = peer_idents_guard
                        .iter()
                        .find(|idents| idents.addr.eq(&peer_addr));

                    if let Some(peer_ident) = peer_ident {
                        peer_ident.hostname.clone()
                    } else {
                        error!(
                            "{error_label}: Peer's server name cannot be identitified. addr: {peer_addr}, sensor: {}",
                            filter.sensor
                        );
                        continue;
                    }
                };
                match request_range_data_to_peer(
                    peer_addr,
                    peer_name.as_str(),
                    &tls_watch,
                    MessageCode::Pcap,
                    filter,
                    &token,
                )
                .await
                {
                    // Cancelled while dialing, handshaking, or writing the
                    // request. Whatever was up has already been closed by
                    // `request_range_data_to_peer`.
                    Ok(None) => {
                        warn!(
                            "{error_label} gave up relaying a pcap request to peer {peer_addr}"
                        );
                        break;
                    }
                    Ok(Some((endpoint, connection, mut peer_send, mut peer_recv))) => {
                        // Cancellation branch. The peer has the request and
                        // may still act on it; only our wait for its
                        // acknowledgement is abandoned. The connection is
                        // closed below either way, so the peer is told.
                        match token
                            .run_until_cancelled(recv_ack_response(&mut peer_recv))
                            .await
                        {
                            Some(Ok(())) => {}
                            Some(Err(e)) => error!(
                                "{error_label}: Failed to receive ack response from peer. addr: {peer_addr} name: {peer_name} {e}"
                            ),
                            None => warn!(
                                "{error_label} gave up waiting for peer {peer_addr} to acknowledge a pcap request"
                            ),
                        }
                        peer_send.finish().ok();
                        drop(peer_recv);
                        close_peer_connection(&endpoint, &connection).await;
                        if token.is_cancelled() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!(
                            "{error_label}: Failed to connect to peer's publish module. addr: {peer_addr} name: {peer_name}: {e}"
                        );
                    }
                }
            } else {
                error!(
                    "{error_label}: Neither this node nor peers are in charge of requested pcap sensor {}",
                    filter.sensor
                );
            }
        }
    });
    // The handle is dropped: the relay reports every filter it could not
    // deliver under the name above, and the drain waits for it. A rejection
    // means admission has already closed, so the relay stays unrun — the
    // acknowledgement already written promised acceptance, not delivery.
    if let Err(e) = spawned {
        warn!("Rejected {task_name}: {e}");
    }

    Ok(())
}

/// Closes an outbound peer connection and lets the close frame go out.
///
/// `wait_idle` is the one remote-dependent await in publish that needs no
/// cancellation branch: it follows a local `close`, so QUIC's drain period
/// bounds it rather than the peer.
async fn close_peer_connection(endpoint: &Endpoint, connection: &Connection) {
    connection.close(0_u32.into(), &[]);
    endpoint.wait_idle().await;
}

async fn get_pcap_conn_if_current_giganto_in_charge(
    pcap_sensors: PcapSensors,
    sensor: &str,
) -> Option<Connection> {
    pcap_sensors
        .read()
        .await
        .get(sensor)
        .and_then(|connections| connections.last().cloned())
}

/// Runs one stream subscription against the store its record type lives in.
///
/// Cancelled by explicit branches, never by drop: the subscription registers
/// entries in `stream_direct_channels` and owes their removal on every exit
/// path, which a dropped future could not perform.
///
/// # Errors
///
/// Returns an error if the record type's store cannot be opened or if the
/// subscription fails. Both are reported by the caller's spawn wrapper, which
/// is what names the subscription they came from; logging them here would
/// leave a reader unable to tell which of several live subscriptions failed.
#[allow(clippy::too_many_arguments)]
async fn process_stream<T>(
    db: Database,
    conn: Connection,
    sensor: Option<String>,
    kind: Option<String>,
    record_type: RequestStreamRecord,
    request_msg: T,
    stream_direct_channels: StreamDirectChannels,
    token: CancellationToken,
) -> Result<()>
where
    T: RequestStreamMessage,
{
    macro_rules! handle_store {
        ($store_fn:ident, $store_name:expr) => {
            send_stream(
                db.$store_fn()
                    .with_context(|| format!("Failed to open {} store", $store_name))?,
                conn,
                record_type,
                request_msg,
                sensor,
                kind,
                stream_direct_channels,
                token,
            )
            .await?
        };
    }

    match record_type {
        RequestStreamRecord::Conn => handle_store!(conn_store, "conn"),
        RequestStreamRecord::Dns => handle_store!(dns_store, "dns"),
        RequestStreamRecord::Rdp => handle_store!(rdp_store, "rdp"),
        RequestStreamRecord::Http => handle_store!(http_store, "http"),
        RequestStreamRecord::Log => handle_store!(log_store, "log"),
        RequestStreamRecord::Smtp => handle_store!(smtp_store, "smtp"),
        RequestStreamRecord::Ntlm => handle_store!(ntlm_store, "ntlm"),
        RequestStreamRecord::Kerberos => handle_store!(kerberos_store, "kerberos"),
        RequestStreamRecord::Ssh => handle_store!(ssh_store, "ssh"),
        RequestStreamRecord::DceRpc => handle_store!(dce_rpc_store, "dce rpc"),
        RequestStreamRecord::Ftp => handle_store!(ftp_store, "ftp"),
        RequestStreamRecord::Mqtt => handle_store!(mqtt_store, "mqtt"),
        RequestStreamRecord::Ldap => handle_store!(ldap_store, "ldap"),
        RequestStreamRecord::Tls => handle_store!(tls_store, "tls"),
        RequestStreamRecord::Smb => handle_store!(smb_store, "smb"),
        RequestStreamRecord::Nfs => handle_store!(nfs_store, "nfs"),
        RequestStreamRecord::Bootp => handle_store!(bootp_store, "bootp"),
        RequestStreamRecord::Dhcp => handle_store!(dhcp_store, "dhcp"),
        RequestStreamRecord::Radius => handle_store!(radius_store, "radius"),
        RequestStreamRecord::Icmp => handle_store!(icmp_store, "icmp"),
        RequestStreamRecord::FileCreate => handle_store!(file_create_store, "file_create"),
        RequestStreamRecord::FileDelete => handle_store!(file_delete_store, "file_delete"),
        RequestStreamRecord::MalformedDns => handle_store!(malformed_dns_store, "malformed_dns"),
        RequestStreamRecord::Pcap => {}
    }
    Ok(())
}

pub async fn send_direct_stream(
    network_key: &NetworkKey,
    raw_event: &[u8],
    timestamp: i64,
    sensor: &str,
    stream_direct_channels: StreamDirectChannels,
) -> Result<()> {
    for (req_key, sender) in &*stream_direct_channels.read().await {
        if !req_key.matches_network_key(network_key) {
            continue;
        }

        let raw_len = u32::try_from(raw_event.len())?.to_le_bytes();
        let mut send_buf: Vec<u8> = Vec::new();
        send_buf.extend_from_slice(&timestamp.to_le_bytes());

        if req_key.embeds_publisher_sensor_in_payload() {
            let sensor_bytes = bincode::serialize(&sensor)?;
            let sensor_len = u32::try_from(sensor_bytes.len())?.to_le_bytes();
            send_buf.extend_from_slice(&sensor_len);
            send_buf.extend_from_slice(&sensor_bytes);
        }

        send_buf.extend_from_slice(&raw_len);
        send_buf.extend_from_slice(raw_event);
        sender.send(send_buf)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_stream<T, N>(
    store: RawEventStore<'_, T>,
    conn: Connection,
    record_type: RequestStreamRecord,
    msg: N,
    sensor: Option<String>,
    kind: Option<String>,
    stream_direct_channels: StreamDirectChannels,
    token: CancellationToken,
) -> Result<()>
where
    T: EventFilter + Serialize + DeserializeOwned + Display,
    N: RequestStreamMessage,
{
    // The same name the caller registered this subscription under, rebuilt
    // from the same inputs. A send failure below is reported here rather than
    // returned, so without it that line would be the one thing in the
    // subscription path that cannot be traced back to which of a connection's
    // live subscriptions it came from.
    let subscription = stream_task_name(sensor.as_deref(), record_type, &msg);

    // Cancellation branch. The subscription's outbound stream has not been
    // opened yet and nothing has been registered in `stream_direct_channels`,
    // so there is no cleanup to run and the client sees no start message.
    let mut sender = select! {
        biased;
        () = token.cancelled() => return Ok(()),
        sender = conn.open_uni() => sender?,
    };
    let channel_keys = msg.channel_keys(sensor.as_deref(), record_type)?;

    let (send, mut recv) = unbounded_channel::<Vec<u8>>();
    {
        let mut channels = stream_direct_channels.write().await;
        for c_key in &channel_keys {
            channels.insert(c_key.clone(), send.clone());
        }
    }

    // The entries just registered belong to this task from here on, so every
    // exit path below has to run through `remove_owned_channel_keys`. The
    // removal cannot be left to a `Drop` implementation because it needs the
    // async write guard, and it is why this task is never cancelled by drop.
    let result: Result<()> = async {
        // Cancellation branch. The start message and the records replayed
        // ahead of the realtime stream are QUIC writes a client that stopped
        // reading can stall; dropping them truncates a stream the client can
        // detect. The cleanup below still runs, because only this inner
        // future is dropped, not the task.
        let last_ts = select! {
            biased;
            () = token.cancelled() => return Ok(()),
            last_ts = start_stream(&mut sender, &store, &msg, record_type, kind) => last_ts?,
        };
        forward_realtime_records(
            &mut sender,
            &mut recv,
            &conn,
            &token,
            last_ts,
            &subscription,
        )
        .await;
        Ok(())
    }
    .await;

    remove_owned_channel_keys(&stream_direct_channels, &channel_keys, &send).await;
    result
}

/// Writes the subscription's stream start message and, for a time series
/// generator, replays the stored records that precede the realtime stream.
///
/// Returns the timestamp of the last replayed record, or `0` when nothing was
/// replayed.
async fn start_stream<T, N>(
    sender: &mut SendStream,
    store: &RawEventStore<'_, T>,
    msg: &N,
    record_type: RequestStreamRecord,
    kind: Option<String>,
) -> Result<i64>
where
    T: EventFilter + Serialize + DeserializeOwned + Display,
    N: RequestStreamMessage,
{
    let mut last_ts = 0_i64;

    // send stored record raw data
    if msg.is_semi_supervised() {
        send_semi_supervised_stream_start_message(sender, record_type)
            .await
            .map_err(|e| {
                anyhow!("Failed to write the semi-supervised engine start message: {e}")
            })?;
        info!(
            "Start the semi-supervised engine's publish stream : {:?}",
            record_type
        );
    } else if msg.is_time_series_generator() {
        let id = msg.id().expect("The time series generator always sends RequestTimeSeriesGeneratorStream with an id, so this value is guaranteed to exist.");
        send_time_series_generator_stream_start_message(sender, id)
            .await
            .map_err(|e| anyhow!("Failed to write the time series generator start message: {e}"))?;
        info!(
            "Start time series generator's publish stream : {:?}",
            record_type
        );

        let key_builder = StorageKey::builder()
            .start_key(&msg.sensor()?)
            .mid_key(kind.map(|s| s.as_bytes().to_vec()));
        let from_key = key_builder
            .clone()
            .lower_closed_bound_end_key(Some(DateTime::from_timestamp_nanos(msg.start_time())))
            .build();
        let to_key = key_builder.upper_open_bound_end_key(None).build();
        let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);

        for item in iter {
            let (key, val) = item.context("Failed to read database")?;
            let (Some(orig_addr), Some(resp_addr)) = (val.orig_addr(), val.resp_addr()) else {
                bail!("Failed to deserialize database data");
            };
            if msg.filter_ip(orig_addr, resp_addr) {
                let timestamp = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
                send_time_series_generator_data(sender, timestamp, val).await?;
                last_ts = timestamp;
            }
        }
    }

    Ok(last_ts)
}

/// Forwards realtime record raw data to the subscribing client until the
/// subscription ends.
///
/// The loop ends on cancellation, on a failure to write to the client's QUIC
/// stream, or on the client disconnecting. It deliberately does not end on
/// the channel closing: the caller keeps the original `UnboundedSender` alive
/// for the whole subscription, so `recv` stays pending even once the last map
/// entry naming this subscription is gone.
///
/// Returning is what lets the caller run the subscription's cleanup, so both
/// awaits that depend on a remote party — the channel receive that only a
/// matching record ends, and the QUIC write a client that stopped reading can
/// stall — carry their own cancellation branch.
async fn forward_realtime_records(
    sender: &mut SendStream,
    recv: &mut UnboundedReceiver<Vec<u8>>,
    conn: &Connection,
    token: &CancellationToken,
    last_ts: i64,
    subscription: &str,
) {
    loop {
        let buf = select! {
            biased;

            // Cancellation branch. The subscription stops forwarding; a
            // record that arrives from here on is lost, and the client
            // re-subscribes to the next generation. The caller removes this
            // subscription's routing entries as soon as this returns.
            () = token.cancelled() => break,

            Some(buf) = recv.recv() => buf,
            _ = conn.closed() => break,
        };

        let ts = i64::from_le_bytes(
            buf.get(..TIMESTAMP_SIZE)
                .expect("timestamp_size")
                .try_into()
                .expect("timestamp"),
        );
        if last_ts > ts {
            continue;
        }

        // Cancellation branch. The record being written is dropped
        // mid-frame; the client detects the truncated stream, and the
        // cleanup the caller owes still runs.
        let sent = select! {
            biased;
            () = token.cancelled() => break,
            sent = frame::send_bytes(sender, &buf) => sent,
        };
        if let Err(e) = sent {
            debug!(
                "{subscription}: Failed to send a realtime record to the subscribing client: {e}"
            );
            break;
        }
    }
}

/// Removes the `stream_direct_channels` entries a subscription still owns.
///
/// Registration is last-insert-wins and nothing in a `StreamChannelKey`
/// identifies the subscription that registered it, so a key may since have been
/// taken over by a newer subscription. Such a key is left alone; removing it
/// would silently stop the newer subscription's client while
/// `send_direct_stream` kept reporting success.
async fn remove_owned_channel_keys(
    stream_direct_channels: &StreamDirectChannels,
    channel_keys: &[StreamChannelKey],
    owned_sender: &UnboundedSender<Vec<u8>>,
) {
    let mut channels = stream_direct_channels.write().await;
    for c_key in channel_keys {
        if channels
            .get(c_key)
            .is_some_and(|sender| sender.same_channel(owned_sender))
        {
            channels.remove(c_key);
        }
    }
}

/// Sends the Time Series Generator stream start message from giganto's publish module.
///
/// # Errors
///
/// Returns an error if the message could not be sent.
async fn send_time_series_generator_stream_start_message(
    send: &mut SendStream,
    start_msg: String,
) -> Result<()> {
    frame::send_raw(send, start_msg.as_bytes()).await?;
    Ok(())
}

/// Sends the record data. (timestamp /record structure)
///
/// # Errors
///
/// Returns an error if the message could not be sent.
async fn send_time_series_generator_data<T>(
    send: &mut SendStream,
    timestamp: i64,
    record_data: T,
) -> Result<()>
where
    T: Serialize,
{
    frame::send_bytes(send, &timestamp.to_le_bytes()).await?;
    let mut buf = Vec::new();
    frame::send(send, &mut buf, record_data).await?;
    Ok(())
}

/// Answers one range or raw-data request off a publish connection.
///
/// The caller runs this as one branch of a `select!` against the task's token,
/// so cancellation drops it wherever it happens to be awaiting; see the
/// comment at that spawn site for why cancel-by-drop is safe here. `token` is
/// still threaded through the peer relay paths below, because the awaits those
/// reach — a dial against an unreachable peer, its retry sleep, an outbound
/// handshake, and a peer that has gone quiet — are shared with the PCAP relay
/// task, which is not cancelled by drop.
///
/// `tracker` is the publish subsystem tracker, needed because a PCAP
/// extraction request arriving on this stream starts a background relay task
/// that has to be registered rather than detached, and `label` names this
/// request in that relay's task name and in the rejection log.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_request(
    (mut send, mut recv): (SendStream, RecvStream),
    db: Database,
    pcap_sensors: PcapSensors,
    ingest_sensors: IngestSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    tls_watch: TlsWatch,
    tracker: TaskTracker,
    label: String,
    token: CancellationToken,
) -> Result<()> {
    let (msg_type, msg_buf) = receive_range_data_request(&mut recv).await?;
    match msg_type {
        MessageCode::ReqRange => {
            let msg = bincode::deserialize::<RequestRange>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deserialize message: {e}"))?;

            match RawEventKind::from_str(msg.kind.as_str()).unwrap_or_default() {
                RawEventKind::Conn => {
                    process_range_data::<Conn, u8>(
                        &mut send,
                        db.conn_store().context("Failed to open conn store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Dns => {
                    process_range_data::<Dns, u8>(
                        &mut send,
                        db.dns_store().context("Failed to open dns store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::MalformedDns => {
                    process_range_data::<MalformedDns, u8>(
                        &mut send,
                        db.malformed_dns_store()
                            .context("Failed to open malformed_dns store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Rdp => {
                    process_range_data::<Rdp, u8>(
                        &mut send,
                        db.rdp_store().context("Failed to open rdp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Http => {
                    process_range_data::<Http, u8>(
                        &mut send,
                        db.http_store().context("Failed to open http store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Smtp => {
                    process_range_data::<Smtp, u8>(
                        &mut send,
                        db.smtp_store().context("Failed to open smtp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Log => {
                    process_range_data::<Log, u8>(
                        &mut send,
                        db.log_store().context("Failed to open log store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        true,
                    )
                    .await?;
                }
                RawEventKind::Ntlm => {
                    process_range_data::<Ntlm, u8>(
                        &mut send,
                        db.ntlm_store().context("Failed to open ntlm store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Kerberos => {
                    process_range_data::<Kerberos, u8>(
                        &mut send,
                        db.kerberos_store()
                            .context("Failed to open kerberos store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Ssh => {
                    process_range_data::<Ssh, u8>(
                        &mut send,
                        db.ssh_store().context("Failed to open ssh store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::DceRpc => {
                    process_range_data::<DceRpc, u8>(
                        &mut send,
                        db.dce_rpc_store().context("Failed to open dce rpc store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Ftp => {
                    process_range_data::<Ftp, u8>(
                        &mut send,
                        db.ftp_store().context("Failed to open ftp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Mqtt => {
                    process_range_data::<Mqtt, u8>(
                        &mut send,
                        db.mqtt_store().context("Failed to open mqtt store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::PeriodicTimeSeries => {
                    process_range_data::<PeriodicTimeSeries, f64>(
                        &mut send,
                        db.periodic_time_series_store()
                            .context("Failed to open periodic time series storage")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Ldap => {
                    process_range_data::<Ldap, u8>(
                        &mut send,
                        db.ldap_store().context("Failed to open ldap store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Tls => {
                    process_range_data::<Tls, u8>(
                        &mut send,
                        db.tls_store().context("Failed to open tls store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Smb => {
                    process_range_data::<Smb, u8>(
                        &mut send,
                        db.smb_store().context("Failed to open smb store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Nfs => {
                    process_range_data::<Nfs, u8>(
                        &mut send,
                        db.nfs_store().context("Failed to open nfs store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Bootp => {
                    process_range_data::<Bootp, u8>(
                        &mut send,
                        db.bootp_store().context("Failed to open bootp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Dhcp => {
                    process_range_data::<Dhcp, u8>(
                        &mut send,
                        db.dhcp_store().context("Failed to open dhcp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Radius => {
                    process_range_data::<Radius, u8>(
                        &mut send,
                        db.radius_store().context("Failed to open radius store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Icmp => {
                    process_range_data::<Icmp, u8>(
                        &mut send,
                        db.icmp_store().context("Failed to open icmp store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::ProcessCreate => {
                    process_range_data::<ProcessCreate, u8>(
                        &mut send,
                        db.process_create_store()
                            .context("Failed to open process_create store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileCreateTime => {
                    process_range_data::<FileCreationTimeChanged, u8>(
                        &mut send,
                        db.file_create_time_store()
                            .context("Failed to open file_create_time store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::NetworkConnect => {
                    process_range_data::<NetworkConnection, u8>(
                        &mut send,
                        db.network_connect_store()
                            .context("Failed to open network_connect store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::ProcessTerminate => {
                    process_range_data::<ProcessTerminated, u8>(
                        &mut send,
                        db.process_terminate_store()
                            .context("Failed to open process_terminate store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::ImageLoad => {
                    process_range_data::<ImageLoaded, u8>(
                        &mut send,
                        db.image_load_store()
                            .context("Failed to open image_load store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileCreate => {
                    process_range_data::<FileCreate, u8>(
                        &mut send,
                        db.file_create_store()
                            .context("Failed to open file_create store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::RegistryValueSet => {
                    process_range_data::<RegistryValueSet, u8>(
                        &mut send,
                        db.registry_value_set_store()
                            .context("Failed to open registry_value_set store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::RegistryKeyRename => {
                    process_range_data::<RegistryKeyValueRename, u8>(
                        &mut send,
                        db.registry_key_rename_store()
                            .context("Failed to open registry_key_rename store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileCreateStreamHash => {
                    process_range_data::<FileCreateStreamHash, u8>(
                        &mut send,
                        db.file_create_stream_hash_store()
                            .context("Failed to open file_create_stream_hash store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::PipeEvent => {
                    process_range_data::<PipeEvent, u8>(
                        &mut send,
                        db.pipe_event_store()
                            .context("Failed to open pipe_event store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::DnsQuery => {
                    process_range_data::<DnsEvent, u8>(
                        &mut send,
                        db.dns_query_store()
                            .context("Failed to open dns_query store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileDelete => {
                    process_range_data::<FileDelete, u8>(
                        &mut send,
                        db.file_delete_store()
                            .context("Failed to open file_delete store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::ProcessTamper => {
                    process_range_data::<ProcessTampering, u8>(
                        &mut send,
                        db.process_tamper_store()
                            .context("Failed to open process_tamper store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::FileDeleteDetected => {
                    process_range_data::<FileDeleteDetected, u8>(
                        &mut send,
                        db.file_delete_detected_store()
                            .context("Failed to open file_delete_detected store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Netflow5 => {
                    process_range_data::<Netflow5, u8>(
                        &mut send,
                        db.netflow5_store()
                            .context("Failed to open netflow5 store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                RawEventKind::Netflow9 => {
                    process_range_data::<Netflow9, u8>(
                        &mut send,
                        db.netflow9_store()
                            .context("Failed to open netflow9 store")?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                        false,
                    )
                    .await?;
                }
                _ => {
                    // do nothing
                    warn!("Not expected to reach here");
                }
            }
        }
        MessageCode::Pcap => {
            let filters = match bincode::deserialize::<Vec<PcapFilter>>(&msg_buf) {
                Ok(filters) => filters,
                Err(e) => {
                    let mut buf = Vec::new();
                    send_err(&mut send, &mut buf, e)
                        .await
                        .context("Failed to send err")?;
                    bail!("Failed to deserialize Pcapfilters")
                }
            };

            process_pcap_extract_filters(
                filters,
                pcap_sensors.clone(),
                peers,
                peer_idents.clone(),
                tls_watch.clone(),
                &mut send,
                &label,
                &tracker,
                &token,
            )
            .await?;
        }
        MessageCode::RawData => {
            let msg: RequestRawData = bincode::deserialize::<RequestRawData>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deserialize message: {e}"))?;
            match RawEventKind::from_str(msg.kind.as_str()).unwrap_or_default() {
                RawEventKind::Conn => {
                    process_raw_events::<Conn, u8>(
                        &mut send,
                        db.conn_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Dns => {
                    process_raw_events::<Dns, u8>(
                        &mut send,
                        db.dns_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::MalformedDns => {
                    process_raw_events::<MalformedDns, u8>(
                        &mut send,
                        db.malformed_dns_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Rdp => {
                    process_raw_events::<Rdp, u8>(
                        &mut send,
                        db.rdp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Http => {
                    process_raw_events::<Http, u8>(
                        &mut send,
                        db.http_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Smtp => {
                    process_raw_events::<Smtp, u8>(
                        &mut send,
                        db.smtp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Ntlm => {
                    process_raw_events::<Ntlm, u8>(
                        &mut send,
                        db.ntlm_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Kerberos => {
                    process_raw_events::<Kerberos, u8>(
                        &mut send,
                        db.kerberos_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Ssh => {
                    process_raw_events::<Ssh, u8>(
                        &mut send,
                        db.ssh_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::DceRpc => {
                    process_raw_events::<DceRpc, u8>(
                        &mut send,
                        db.dce_rpc_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Ftp => {
                    process_raw_events::<Ftp, u8>(
                        &mut send,
                        db.ftp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Mqtt => {
                    process_raw_events::<Mqtt, u8>(
                        &mut send,
                        db.mqtt_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Ldap => {
                    process_raw_events::<Ldap, u8>(
                        &mut send,
                        db.ldap_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Tls => {
                    process_raw_events::<Tls, u8>(
                        &mut send,
                        db.tls_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Smb => {
                    process_raw_events::<Smb, u8>(
                        &mut send,
                        db.smb_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Nfs => {
                    process_raw_events::<Nfs, u8>(
                        &mut send,
                        db.nfs_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Bootp => {
                    process_raw_events::<Bootp, u8>(
                        &mut send,
                        db.bootp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Dhcp => {
                    process_raw_events::<Dhcp, u8>(
                        &mut send,
                        db.dhcp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Radius => {
                    process_raw_events::<Radius, u8>(
                        &mut send,
                        db.radius_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Icmp => {
                    process_raw_events::<Icmp, u8>(
                        &mut send,
                        db.icmp_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Log => {
                    // For RawEventKind::LOG, the kind is required as the sensor.
                    process_raw_events::<Log, u8>(
                        &mut send,
                        db.log_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::PeriodicTimeSeries => {
                    process_raw_events::<PeriodicTimeSeries, f64>(
                        &mut send,
                        db.periodic_time_series_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::ProcessCreate => {
                    process_raw_events::<ProcessCreate, u8>(
                        &mut send,
                        db.process_create_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::FileCreateTime => {
                    process_raw_events::<FileCreationTimeChanged, u8>(
                        &mut send,
                        db.file_create_time_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::NetworkConnect => {
                    process_raw_events::<NetworkConnection, u8>(
                        &mut send,
                        db.network_connect_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::ProcessTerminate => {
                    process_raw_events::<ProcessTerminated, u8>(
                        &mut send,
                        db.process_terminate_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::ImageLoad => {
                    process_raw_events::<ImageLoaded, u8>(
                        &mut send,
                        db.image_load_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::FileCreate => {
                    process_raw_events::<FileCreate, u8>(
                        &mut send,
                        db.file_create_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::RegistryValueSet => {
                    process_raw_events::<RegistryValueSet, u8>(
                        &mut send,
                        db.registry_value_set_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::RegistryKeyRename => {
                    process_raw_events::<RegistryKeyValueRename, u8>(
                        &mut send,
                        db.registry_key_rename_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::FileCreateStreamHash => {
                    process_raw_events::<FileCreateStreamHash, u8>(
                        &mut send,
                        db.file_create_stream_hash_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::PipeEvent => {
                    process_raw_events::<PipeEvent, u8>(
                        &mut send,
                        db.pipe_event_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::DnsQuery => {
                    process_raw_events::<DnsEvent, u8>(
                        &mut send,
                        db.dns_query_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::FileDelete => {
                    process_raw_events::<FileDelete, u8>(
                        &mut send,
                        db.file_delete_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::ProcessTamper => {
                    process_raw_events::<ProcessTampering, u8>(
                        &mut send,
                        db.process_tamper_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::FileDeleteDetected => {
                    process_raw_events::<FileDeleteDetected, u8>(
                        &mut send,
                        db.file_delete_detected_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Netflow5 => {
                    process_raw_events::<Netflow5, u8>(
                        &mut send,
                        db.netflow5_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                RawEventKind::Netflow9 => {
                    process_raw_events::<Netflow9, u8>(
                        &mut send,
                        db.netflow9_store()?,
                        msg,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        &tls_watch,
                        &token,
                    )
                    .await?;
                }
                _ => {
                    // do nothing
                    warn!("Not expected to reach here");
                }
            }
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn process_range_data<T, I>(
    send: &mut SendStream,
    store: RawEventStore<'_, T>,
    request_range: RequestRange,
    ingest_sensors: IngestSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    tls_watch: &TlsWatch,
    token: &CancellationToken,
    availed_kind: bool,
) -> Result<()>
where
    T: DeserializeOwned + ResponseRangeData,
    I: DeserializeOwned + Serialize,
{
    if is_current_giganto_in_charge(ingest_sensors, &request_range.sensor).await {
        process_range_data_in_current_giganto(send, store, request_range, availed_kind).await?;
    } else if let Some(peer_addr) = peer_in_charge_publish_addr(peers, &request_range.sensor).await
    {
        process_range_data_in_peer_giganto::<I>(
            send,
            peer_idents,
            peer_addr,
            tls_watch,
            request_range,
            token,
        )
        .await?;
    } else {
        bail!(
            "Neither current nor peer gigantos are in charge of requested sensor {}",
            request_range.sensor
        )
    }
    // A peer relay that gave up on cancellation returns normally with only
    // part of the peer's response written, and the missing terminator is the
    // only thing that tells the client the response is incomplete. Writing it
    // here would say the opposite, so a cancelled request leaves the stream
    // unterminated and the client retries against the next generation.
    if token.is_cancelled() {
        return Ok(());
    }
    send_range_data::<T>(send, None).await?;
    send.finish()?;
    Ok(())
}

async fn is_current_giganto_in_charge(ingest_sensors: IngestSensors, sensor: &str) -> bool {
    ingest_sensors.read().await.contains(sensor)
}

async fn peer_in_charge_publish_addr(peers: Peers, sensor: &str) -> Option<SocketAddr> {
    peers.read().await.iter().find_map(|(peer_addr, peer_info)| {
        peer_info
            .ingest_sensors
            .contains(sensor)
            .then(|| {
                SocketAddr::new(
                    peer_addr.parse::<IpAddr>().expect("Peer's IP address must be valid, because it is validated when peer giganto started."),
                    peer_info.publish_port.expect("Peer's publish port must be valid, because it is validated when peer giganto started."),
                )
            })
    })
}

async fn process_range_data_in_current_giganto<T>(
    send: &mut SendStream,
    store: RawEventStore<'_, T>,
    request_range: RequestRange,
    availed_kind: bool,
) -> Result<()>
where
    T: DeserializeOwned + ResponseRangeData,
{
    let key_builder = StorageKey::builder().start_key(&request_range.sensor);
    let key_builder = if availed_kind {
        key_builder.mid_key(Some(request_range.kind.as_bytes().to_vec()))
    } else {
        key_builder
    };

    let from_key = key_builder
        .clone()
        .lower_closed_bound_end_key(Some(DateTime::from_timestamp_nanos(request_range.start)))
        .build();
    let to_key = key_builder
        .upper_open_bound_end_key(Some(DateTime::from_timestamp_nanos(request_range.end)))
        .build();

    let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);

    for item in iter.take(request_range.count) {
        let (key, val) = item.context("Failed to read Database")?;
        let timestamp = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        send_range_data(send, Some((val, timestamp, &request_range.sensor))).await?;
    }

    Ok(())
}

async fn process_range_data_in_peer_giganto<I>(
    send: &mut SendStream,
    peer_idents: PeerIdents,
    peer_addr: SocketAddr,
    tls_watch: &TlsWatch,
    request_range: RequestRange,
    token: &CancellationToken,
) -> Result<()>
where
    I: DeserializeOwned + Serialize,
{
    let peer_name = peer_name(peer_idents, &peer_addr).await?;
    let Some((endpoint, connection, mut peer_send, mut peer_recv)) = request_range_data_to_peer(
        peer_addr,
        peer_name.as_str(),
        tls_watch,
        MessageCode::ReqRange,
        request_range,
        token,
    )
    .await?
    else {
        // Cancelled while dialing, handshaking, or writing the request.
        // Whatever was up has already been closed; the client sees a range
        // response that ends without its terminator and retries.
        return Ok(());
    };
    loop {
        // Cancellation branch. A peer that accepted the request and then went
        // quiet would otherwise hold this read, and the drain behind it, open
        // for as long as it stayed quiet. What is lost is the rest of the
        // peer's response, which the client detects as incomplete.
        let Some(event) = token
            .run_until_cancelled(receive_range_data::<Option<(i64, String, Vec<I>)>>(
                &mut peer_recv,
            ))
            .await
        else {
            break;
        };
        if let Some(event_data) = event? {
            let event_data_again: Option<(i64, String, Vec<I>)> = Some(event_data);
            let send_buf = bincode::serialize(&event_data_again)
                .map_err(PublishError::SerialDeserialFailure)?;
            send_raw(send, &send_buf).await?;
        } else {
            break;
        }
    }
    peer_send.finish().ok();
    drop(peer_recv);
    close_peer_connection(&endpoint, &connection).await;
    Ok(())
}

/// Dials the peer in charge and writes one request to it.
///
/// Returns `Ok(None)` when `token` fires before the request is on the wire.
/// Cancellation past the dial closes the connection rather than letting it die
/// by drop, so the peer is told instead of being left to time it out.
async fn request_range_data_to_peer<T>(
    peer_addr: SocketAddr,
    peer_name: &str,
    tls_watch: &TlsWatch,
    message_code: MessageCode,
    request_data: T,
    token: &CancellationToken,
) -> Result<Option<(Endpoint, Connection, SendStream, RecvStream)>>
where
    T: Serialize,
{
    let Some((endpoint, connection)) = connect(peer_addr, peer_name, tls_watch, token).await?
    else {
        return Ok(None);
    };

    // Cancellation branch. A peer that never accepts the stream would hold
    // this open indefinitely. Nothing has been requested yet, so the loss is
    // the request itself.
    let Some(opened) = token.run_until_cancelled(connection.open_bi()).await else {
        close_peer_connection(&endpoint, &connection).await;
        return Ok(None);
    };
    let (mut send, recv) = opened?;

    // Cancellation branch. Same loss one step further in: the request is
    // abandoned half-written, and the peer is told by the close below.
    let Some(requested) = token
        .run_until_cancelled(send_range_data_request(
            &mut send,
            message_code,
            request_data,
        ))
        .await
    else {
        close_peer_connection(&endpoint, &connection).await;
        return Ok(None);
    };
    requested?;

    Ok(Some((endpoint, connection, send, recv)))
}

#[allow(clippy::too_many_arguments)]
async fn process_raw_events<T, I>(
    send: &mut SendStream,
    store: RawEventStore<'_, T>,
    req: RequestRawData,
    ingest_sensors: IngestSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    tls_watch: &TlsWatch,
    token: &CancellationToken,
) -> Result<()>
where
    T: DeserializeOwned + ResponseRangeData,
    I: DeserializeOwned + Serialize + Clone,
{
    let (handle_by_current_giganto, handle_by_peer_gigantos) =
        req_inputs_by_gigantos_in_charge(ingest_sensors, req.input).await;

    if !handle_by_current_giganto.is_empty() {
        process_raw_event_in_current_giganto(send, store, handle_by_current_giganto).await?;
    }

    if !handle_by_peer_gigantos.is_empty() {
        process_raw_event_in_peer_gigantos::<I>(
            send,
            req.kind,
            tls_watch,
            peers,
            peer_idents,
            handle_by_peer_gigantos,
            token,
        )
        .await?;
    }

    // Same reason as the range path: a relay that stopped on cancellation
    // owes the client an unterminated stream, not a terminator that claims a
    // partial answer is the whole one.
    if token.is_cancelled() {
        return Ok(());
    }
    send_range_data::<T>(send, None).await?;
    send.finish()?;
    Ok(())
}

async fn req_inputs_by_gigantos_in_charge(
    ingest_sensors: IngestSensors,
    req_inputs: Vec<(String, Vec<i64>)>,
) -> (Vec<(String, Vec<i64>)>, Vec<(String, Vec<i64>)>) {
    let mut handle_by_current_giganto = Vec::with_capacity(req_inputs.len());
    let mut handle_by_peer_gigantos = Vec::with_capacity(req_inputs.len());
    for req_input in req_inputs {
        if ingest_sensors.read().await.contains(&req_input.0) {
            handle_by_current_giganto.push(req_input);
        } else {
            handle_by_peer_gigantos.push(req_input);
        }
    }

    (handle_by_current_giganto, handle_by_peer_gigantos)
}

async fn process_raw_event_in_current_giganto<T>(
    send: &mut SendStream,
    store: RawEventStore<'_, T>,
    handle_by_current_giganto: Vec<(String, Vec<i64>)>,
) -> Result<()>
where
    T: DeserializeOwned + ResponseRangeData,
{
    let mut output: Vec<(i64, String, Vec<u8>)> = Vec::new();
    for (sensor, timestamps) in handle_by_current_giganto {
        output.extend_from_slice(&store.batched_multi_get_with_sensor(&sensor, &timestamps));
    }

    for (timestamp, sensor, value) in output {
        let val = bincode::deserialize::<T>(&value)?;
        send_range_data(send, Some((val, timestamp, &sensor))).await?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_raw_event_in_peer_gigantos<I>(
    send: &mut SendStream,
    kind: String,
    tls_watch: &TlsWatch,
    peers: Peers,
    peer_idents: PeerIdents,
    handle_by_peer_gigantos: Vec<(String, Vec<i64>)>,
    token: &CancellationToken,
) -> Result<()>
where
    I: DeserializeOwned + Serialize,
{
    let peer_gigantos_by_sensor: HashMap<String, Vec<(String, Vec<i64>)>> = handle_by_peer_gigantos
        .into_iter()
        .fold(HashMap::new(), |mut acc, (sensor, timestamps)| {
            acc.entry(sensor.clone())
                .or_default()
                .push((sensor, timestamps));
            acc
        });

    for (sensor, input) in peer_gigantos_by_sensor {
        if let Some(peer_addr) = peer_in_charge_publish_addr(peers.clone(), &sensor).await {
            let peer_name = peer_name(peer_idents.clone(), &peer_addr).await?;

            let Some((endpoint, connection)) =
                connect(peer_addr, peer_name.as_str(), tls_watch, token).await?
            else {
                // Cancelled while dialing or handshaking. The client sees a
                // raw-data response that ends without its terminator.
                break;
            };

            // Cancellation branch. A peer that never accepts the stream would
            // hold this open indefinitely; the loss is the request itself,
            // and the close below tells the peer.
            let Some(opened) = token.run_until_cancelled(connection.open_bi()).await else {
                close_peer_connection(&endpoint, &connection).await;
                break;
            };
            let (mut peer_send, mut peer_recv) = opened?;

            // Cancellation branch. Same loss one step further in: the request
            // is abandoned half-written.
            let Some(requested) = token
                .run_until_cancelled(send_range_data_request(
                    &mut peer_send,
                    MessageCode::RawData,
                    RequestRawData {
                        kind: kind.clone(),
                        input,
                    },
                ))
                .await
            else {
                close_peer_connection(&endpoint, &connection).await;
                break;
            };
            requested?;

            loop {
                // Cancellation branch. A peer that accepted the request and
                // then went quiet would otherwise hold this read, and the
                // drain behind it, open. What is lost is the rest of the
                // peer's response, which the client detects as incomplete.
                let Some(event) = token
                    .run_until_cancelled(receive_range_data::<Option<(i64, String, Vec<I>)>>(
                        &mut peer_recv,
                    ))
                    .await
                else {
                    break;
                };
                let Some(event) = event? else {
                    break;
                };
                let send_buf = bincode::serialize(&Some(event))
                    .map_err(PublishError::SerialDeserialFailure)?;
                send_raw(send, &send_buf).await?;
            }
            peer_send.finish().ok();
            drop(peer_recv);
            close_peer_connection(&endpoint, &connection).await;
            if token.is_cancelled() {
                break;
            }
        }
    }

    Ok(())
}

/// Dials a peer's publish listener and completes the version handshake.
///
/// Returns `Ok(None)` when `token` fires first. The retry loop below never
/// gives up on its own, so this is the only thing that ends a dial against a
/// peer that is not coming back — and a dial nothing ended is exactly what a
/// drain cannot tolerate.
async fn connect(
    server_addr: SocketAddr,
    server_name: &str,
    tls_watch: &TlsWatch,
    token: &CancellationToken,
) -> Result<Option<(Endpoint, Connection)>> {
    let client_addr = if server_addr.is_ipv6() {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };

    let endpoint = Endpoint::client(SocketAddr::new(client_addr, 0))?;
    let Some(conn) =
        connect_repeatedly(&endpoint, server_addr, server_name, tls_watch, token).await?
    else {
        return Ok(None);
    };

    // Cancellation branch. A peer that completes QUIC transport setup and then
    // never answers the version exchange would hold this open indefinitely.
    // The connection is up but the peer has been told nothing, so it is closed
    // rather than left to die by drop.
    let Some(handshake) = token
        .run_until_cancelled(client_handshake(&conn, env!("CARGO_PKG_VERSION")))
        .await
    else {
        close_peer_connection(&endpoint, &conn).await;
        return Ok(None);
    };
    handshake?;
    Ok(Some((endpoint, conn)))
}

/// Retries the dial until it succeeds or `token` fires, returning `Ok(None)`
/// in the latter case.
///
/// The exponential backoff is unchanged; what is new is that both awaits it
/// contains — the dial attempt and the wait between attempts — lose a race
/// against cancellation, so a caller parked on an unreachable peer returns
/// instead of retrying through the drain.
async fn connect_repeatedly(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
    tls_watch: &TlsWatch,
    token: &CancellationToken,
) -> Result<Option<Connection>> {
    let max_delay = Duration::from_secs(30);
    let mut delay = Duration::from_millis(500);

    loop {
        if token.is_cancelled() {
            return Ok(None);
        }
        // Re-snapshot the latest TLS material on every attempt so a reload
        // that completes mid-retry is picked up by the next connect.
        let tls = tls_reload::get_current_tls_material(tls_watch);
        match config_client(&tls.certs) {
            Ok(client_config) => {
                match endpoint.connect_with(client_config, server_addr, server_name) {
                    // Cancellation branch. One dial attempt is lost. Nothing
                    // has been opened on the connection, so there is nothing
                    // to close and nothing to clean up.
                    Ok(connecting) => match token.run_until_cancelled(connecting).await {
                        None => return Ok(None),
                        Some(Ok(conn)) => {
                            info!("Connected to {}", server_addr);
                            return Ok(Some(conn));
                        }
                        Some(Err(e)) => warn!("Cannot connect to controller: {:#}, retrying", e),
                    },
                    Err(e) => {
                        warn!("Cannot connect: {:#}, retrying", e);
                    }
                }
            }
            Err(e) => warn!("Cannot build client TLS config: {:#}, retrying", e),
        }
        delay = std::cmp::min(max_delay, delay * 2);
        // Cancellation branch. The wait between attempts is abandoned and the
        // dial is given up; the same nothing is lost as above.
        if token
            .run_until_cancelled(tokio::time::sleep(delay))
            .await
            .is_none()
        {
            return Ok(None);
        }
    }
}

async fn peer_name(peer_idents: PeerIdents, peer_addr: &SocketAddr) -> Result<String> {
    let peer_idents_guard = peer_idents.read().await;
    let peer_ident = peer_idents_guard
        .iter()
        .find(|idents| idents.addr.eq(peer_addr));

    match peer_ident {
        Some(peer_ident) => Ok(peer_ident.hostname.clone()),
        None => bail!("Peer giganto's server name cannot be identitified"),
    }
}
