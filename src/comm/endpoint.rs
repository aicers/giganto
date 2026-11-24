//! The endpoint entry: the port Clumit Endpoint sends host telemetry to.
//!
//! The entry is separate from the module ports in both code path and client
//! verification. It is TCP with TLS 1.3, configured by
//! [`endpoint_server_config`], and each connection runs senta-protocol's
//! [`ServerConnection`], which does the framing, the `hello` handshake and
//! liveness; this module feeds it bytes and times and carries out what it
//! asks for.
//!
//! Which endpoints the entry takes telemetry from is the node's active list,
//! [`EndpointList`], which REview pushes over GraphQL and keeps alive with a
//! lease. Until the node has a full list and an `entry_id` it is
//! [`Standing::Unready`], and every connection is closed at its `hello`
//! without anything sent back. A connection is judged once, at its first
//! `hello`; later changes reach it only by the list closing it.
//!
//! Once ready, the entry announces in its `hello_ack` the record kinds it
//! accepts: exactly those [`convert`] turns into Giganto structs.
//!
//! An admitted connection's telemetry messages go, one at a time and in
//! order, to the generation's telemetry streams, [`EndpointFlows`], which
//! store each batch's records together with the stream's state in one synced
//! write before the batch is acknowledged. An endpoint whose records are
//! stored joins the generation's sensor sets under its endpoint id.

mod active_list;
mod convert;
mod receiver;
mod sensors;

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::Duration,
};

use anyhow::{Context, Result};
use jiff::Timestamp;
use senta_protocol::{
    auth::{
        active_list::{Standing, allowed},
        tls::{TELEMETRY_ALPN, alpn_matches, peer_spki_hash},
    },
    connection::{
        ConnectionKind, Envelope, Frame, IDLE_TIMEOUT, ServerAction, ServerChannel, ServerConfig,
        ServerConnection, StandingVerdict,
    },
    telemetry::{
        ReceiverConnection, ReceiverOutput, TELEMETRY_MESSAGE_KINDS, TelemetryDecodeError,
        TelemetryMessage,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    time::Instant,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

pub(crate) use self::active_list::{ApplyFailure, ApplyRefusal, EndpointList, ListAck, ListState};
use self::active_list::{CloseCommand, PendingConnection, store_duplicate_key};
use self::receiver::{Delivered, Handled};
pub(crate) use self::{receiver::EndpointFlows, sensors::EndpointSensors};
use crate::{
    cancellation::{TaskTracker, drain_with_report},
    datetime::DateTime,
    server::endpoint_server_config,
    storage::Database,
    tls_reload::{TlsMaterial, TlsWatch},
};

/// Names the endpoint entry's tracker in the drain progress log.
const ENDPOINT_DRAIN_LABEL: &str = "endpoint";

/// The size of the buffer each connection reads into.
const READ_BUFFER_SIZE: usize = 16 * 1024;

/// How often the entry forgets the telemetry streams closed long enough ago.
const PRUNE_INTERVAL: Duration = Duration::from_hours(24);

/// How long closing a connection may spend writing what is left to write, the
/// frames the protocol sent before it closed and then TLS `close_notify`,
/// before the connection is dropped without them, as it is to a peer that has
/// stopped reading.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// The endpoint entry's TLS configuration last built successfully in this
/// process.
///
/// It outlives generations: when the chain cannot be chosen from the current
/// TLS material, the entry keeps serving the configuration built last — that
/// chain together with the private key that goes with it — rather than
/// pairing an old chain with a new key or closing the port.
#[derive(Default)]
pub(crate) struct EndpointTls {
    last_built: Mutex<Option<Arc<rustls::ServerConfig>>>,
}

impl EndpointTls {
    /// Builds the configuration from `material` and, on success, records it
    /// as the one built last.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint certificate chain cannot be chosen
    /// from `material` or the configuration cannot be built from it; the
    /// configuration built last is then left as it was.
    pub(crate) fn build(&self, material: &TlsMaterial) -> Result<Arc<rustls::ServerConfig>> {
        let config = endpoint_server_config(&material.certs, &material.ca_pem)?;
        *self
            .last_built
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&config));
        Ok(config)
    }

    /// Returns the configuration built last, if any was.
    pub(crate) fn last_built(&self) -> Option<Arc<rustls::ServerConfig>> {
        self.last_built
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Returns the configuration a generation starts the entry with: one built
    /// from `material`, or else the one built last.
    ///
    /// Either failure is logged here. `None` means there is no configuration
    /// at all, and the entry stays closed for the generation.
    pub(crate) fn for_generation(
        &self,
        material: &TlsMaterial,
    ) -> Option<Arc<rustls::ServerConfig>> {
        match self.build(material) {
            Ok(config) => Some(config),
            Err(e) => {
                let previous = self.last_built();
                if previous.is_some() {
                    error!(
                        "Endpoint entry: {e:#}; serving the TLS configuration built last, \
                         with its own certificate chain and private key"
                    );
                } else {
                    error!(
                        "Endpoint entry: {e:#}; no earlier TLS configuration exists, \
                         so the endpoint port stays closed for this generation"
                    );
                }
                previous
            }
        }
    }
}

/// What every connection of the entry shares: the node's active list, the
/// generation's database, where duplicate keys are recorded, its telemetry
/// streams and its sensor sets.
#[derive(Clone)]
struct Entry {
    list: Arc<EndpointList>,
    database: Database,
    flows: Arc<EndpointFlows>,
    sensors: Arc<EndpointSensors>,
}

/// The endpoint entry before its listener is bound.
pub(crate) struct Server {
    address: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    endpoint_tls: Arc<EndpointTls>,
    entry: Entry,
}

/// The endpoint entry with its listener bound.
pub(crate) struct BoundServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    endpoint_tls: Arc<EndpointTls>,
    entry: Entry,
}

impl Server {
    /// Creates the entry at `address`, serving `tls_config` until a TLS
    /// reload replaces it through `endpoint_tls`, admitting connections by
    /// `list`, handing their telemetry to `flows`, and adding the endpoints
    /// whose records are stored to `sensors`.
    pub(crate) fn new(
        address: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
        endpoint_tls: Arc<EndpointTls>,
        list: Arc<EndpointList>,
        database: Database,
        flows: Arc<EndpointFlows>,
        sensors: EndpointSensors,
    ) -> Self {
        Self {
            address,
            tls_config,
            endpoint_tls,
            entry: Entry {
                list,
                database,
                flows,
                sensors: Arc::new(sensors),
            },
        }
    }

    /// Binds the entry's listener.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be bound.
    pub(crate) async fn bind(self) -> Result<BoundServer> {
        let listener = TcpListener::bind(self.address).await?;
        let local_addr = listener.local_addr()?;
        Ok(BoundServer {
            listener,
            local_addr,
            tls_config: self.tls_config,
            endpoint_tls: self.endpoint_tls,
            entry: self.entry,
        })
    }

    /// Binds the listener and serves it until `token` is cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot be bound or the entry's tracker
    /// cannot be drained cleanly.
    pub(crate) async fn run(
        self,
        tls_watch: TlsWatch,
        token: CancellationToken,
        drain_report_interval: Duration,
    ) -> Result<()> {
        self.bind()
            .await
            .context("failed to bind the endpoint listener")?
            .run(tls_watch, token, drain_report_interval)
            .await
    }
}

impl BoundServer {
    #[must_use]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves the bound listener until `token` is cancelled, then drains every
    /// connection task it started, the lease timer and the stream pruning.
    ///
    /// Each connection runs in its own task, the TLS handshake included, so a
    /// slow or stalled handshake holds up no other connection. When
    /// `tls_watch` publishes reloaded TLS material, the chain is chosen again
    /// from it: on success new handshakes use the new chain and key, and on
    /// failure the configuration in use is kept whole. Established
    /// connections are kept either way.
    ///
    /// # Errors
    ///
    /// Returns an error if a tracker lock was poisoned during the drain.
    pub(crate) async fn run(
        self,
        mut tls_watch: TlsWatch,
        token: CancellationToken,
        drain_report_interval: Duration,
    ) -> Result<()> {
        let Self {
            listener,
            local_addr,
            tls_config,
            endpoint_tls,
            entry,
        } = self;
        info!("Endpoint entry listening on {local_addr}");

        let tracker = TaskTracker::with_token(token.clone());
        // The lease timer runs while the entry does: without the entry there
        // is no connection for an expiry to close.
        let list = Arc::clone(&entry.list);
        let timer = tracker.spawn("endpoint-lease-timer", move |token| {
            list.run_lease_timer(token)
        });
        // The tracker's drain waits for the timer, so its handle is not kept.
        if let Err(e) = timer {
            warn!("Endpoint entry: the lease timer was not started: {e}");
        }
        let flows = Arc::clone(&entry.flows);
        let pruning = tracker.spawn("endpoint-stream-pruning", move |token| {
            run_pruning(flows, token)
        });
        // Drained with the tracker too.
        if let Err(e) = pruning {
            warn!("Endpoint entry: closed telemetry streams will not be forgotten: {e}");
        }
        let mut acceptor = TlsAcceptor::from(tls_config);
        // A `TlsWatch` whose sender is gone reports the closure on every poll,
        // which would spin this loop, so the reload arm is switched off for
        // good the first time that happens.
        let mut tls_watch_live = true;

        loop {
            select! {
                biased;

                () = token.cancelled() => {
                    info!("Shutting down the endpoint entry");
                    break;
                }

                // Ahead of the accept arm, so a steady stream of connections
                // cannot keep a reload waiting.
                changed = tls_watch.changed(), if tls_watch_live => {
                    if changed.is_err() {
                        warn!("Endpoint entry: TLS watch closed, keeping the current TLS configuration");
                        tls_watch_live = false;
                        continue;
                    }
                    let material = tls_watch.borrow_and_update().clone();
                    match endpoint_tls.build(&material) {
                        Ok(config) => {
                            acceptor = TlsAcceptor::from(config);
                            info!("Endpoint entry: TLS configuration reloaded");
                        }
                        Err(e) => error!(
                            "Endpoint entry: {e:#}; keeping the previous TLS configuration, \
                             with its own certificate chain and private key"
                        ),
                    }
                }

                accepted = listener.accept() => {
                    let (stream, remote) = match accepted {
                        Ok(accepted) => accepted,
                        Err(e) => {
                            warn!("Endpoint entry: failed to accept a connection: {e}");
                            continue;
                        }
                    };
                    let acceptor = acceptor.clone();
                    let entry = entry.clone();
                    let spawned = tracker.spawn(
                        format!("endpoint-conn-{remote}"),
                        move |token| handle_connection(stream, remote, acceptor, entry, token),
                    );
                    // A connection task reports its own outcome, so the handle
                    // is not kept. Admission closes only once shutdown has
                    // begun, so a rejected connection is one the endpoint
                    // retries against the next generation.
                    if let Err(e) = spawned {
                        warn!("Rejected endpoint connection from {remote}: {e}");
                    }
                }
            }
        }

        // Closing the listener before the drain refuses new connections while
        // the open ones end.
        drop(listener);
        drain_with_report(&tracker, drain_report_interval, ENDPOINT_DRAIN_LABEL)
            .await
            .context("failed to drain the endpoint entry's task tracker")
    }
}

/// Forgets the telemetry streams closed long enough ago, when the entry starts
/// and every [`PRUNE_INTERVAL`] after, until `token` is cancelled.
async fn run_pruning(flows: Arc<EndpointFlows>, token: CancellationToken) {
    let mut interval = tokio::time::interval(PRUNE_INTERVAL);
    loop {
        select! {
            biased;
            () = token.cancelled() => return,
            _ = interval.tick() => {
                let flows = Arc::clone(&flows);
                // Run to the end once started: it holds the streams' lock and
                // writes, neither of which an abort could stop.
                let pruned =
                    tokio::task::spawn_blocking(move || flows.prune(Timestamp::now())).await;
                if let Err(e) = pruned {
                    error!("Endpoint entry: forgetting closed telemetry streams failed: {e}");
                }
            }
        }
    }
}

/// Runs one endpoint connection: the TLS handshake, bounded by
/// [`IDLE_TIMEOUT`], the ALPN check, then the protocol until either side
/// closes, the active list closes it, or `token` is cancelled.
async fn handle_connection(
    stream: TcpStream,
    remote: SocketAddr,
    acceptor: TlsAcceptor,
    entry: Entry,
    token: CancellationToken,
) {
    // A handshake not finished within the bound is dropped: the same bound
    // liveness puts on a connection that falls silent after it.
    let handshake = select! {
        biased;
        () = token.cancelled() => return,
        handshake = tokio::time::timeout(IDLE_TIMEOUT, acceptor.accept(stream)) => handshake,
    };
    let mut tls = match handshake {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            warn!("TLS handshake from {remote} failed: {e}");
            return;
        }
        Err(_) => {
            warn!("TLS handshake from {remote} did not finish within {IDLE_TIMEOUT:?}");
            return;
        }
    };

    if !alpn_matches(tls.get_ref().1.alpn_protocol(), TELEMETRY_ALPN) {
        warn!("Endpoint connection from {remote} negotiated no telemetry ALPN; closing");
        close(&mut tls, &token).await;
        return;
    }
    let spki_sha256 = match peer_spki_hash(tls.get_ref().1) {
        Ok(hash) => hash,
        Err(e) => {
            warn!("Endpoint connection from {remote}: no endpoint key: {e}; closing");
            close(&mut tls, &token).await;
            return;
        }
    };

    run_admitted_by_list(&mut tls, remote, spki_sha256, entry, &token).await;
    close(&mut tls, &token).await;
}

/// Runs the protocol on a connection whose TLS handshake has completed, from
/// the key whose SPKI hash is `spki_sha256`, under the active list, until
/// either side closes it, the list closes it, or `token` is cancelled.
///
/// A connection the list closes is told why, when its new standing calls for
/// it, after the rest of any frame being written when the list closed it.
async fn run_admitted_by_list<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut S,
    remote: SocketAddr,
    spki_sha256: [u8; 32],
    entry: Entry,
    token: &CancellationToken,
) {
    // The active list stops the connection through its own token; shutdown
    // reaches it through the parent.
    let stop = token.child_token();
    let pending = entry
        .list
        .open_connection(spki_sha256, remote.ip(), stop.clone());
    let registration = pending.registration();
    let admitted = Arc::new(OnceLock::new());
    let config = server_config(pending, entry.database, Arc::clone(&admitted));
    let mut session = Session {
        flows: entry.flows,
        sensors: Arc::clone(&entry.sensors),
        admitted,
        receiver: None,
        sensor: None,
        stop: stop.clone(),
    };
    let ended = serve(tls, remote, config, &stop, &mut session).await;
    let command = registration.command();
    // The connection has stopped processing messages, its last call on the
    // telemetry streams included: it leaves the list, and an update waiting
    // for it may answer.
    drop(registration);
    if let Some(sensor) = session.sensor.take() {
        entry.sensors.remove(&sensor).await;
    }
    if let Ended::Stopped { unsent } = ended {
        let error = match &command {
            Some(CloseCommand::Error(frame)) => Some(frame),
            Some(CloseCommand::Silent) | None => None,
        };
        send_closing_frames(tls, &unsent, error, remote, token).await;
    }
}

/// Builds a connection's protocol configuration.
///
/// Its `hello_ack` carries the `entry_id` stored when the connection was
/// built. The first `hello` is judged by the active list, which admits the
/// connection or refuses it as its standing calls for; the endpoint id of an
/// admitted connection is put in `admitted`. Every later message of an
/// admitted connection is taken as from [`Standing::Active`], and the
/// telemetry messages are delivered to the caller. The entry accepts the
/// kinds of [`convert::ACCEPTED_KINDS`], each at schema version 1.
fn server_config(
    pending: PendingConnection,
    database: Database,
    admitted: Arc<OnceLock<Uuid>>,
) -> ServerConfig {
    let channel = ServerChannel::Telemetry {
        entry_id: pending.hello_ack_entry_id(),
        accepted_kinds: convert::accepted_kinds(),
    };
    ServerConfig::new(channel, Standing::Unready.receive_limit())
        .with_known_kinds(TELEMETRY_MESSAGE_KINDS)
        .with_standing(move |t| {
            if admitted.get().is_some() {
                return allowed(&Standing::Active, ConnectionKind::Telemetry, t)
                    .to_standing_verdict();
            }
            let admission = pending.admit();
            if let Some((at, duplicate_key)) = admission.duplicate_key {
                store_duplicate_key(&database, at, duplicate_key);
            }
            if admission.verdict == StandingVerdict::Accept {
                match admission.endpoint_id {
                    Some(endpoint_id) => {
                        let _ = admitted.set(endpoint_id);
                    }
                    None => return StandingVerdict::Close,
                }
            }
            admission.verdict
        })
}

/// What a connection's telemetry needs beside its protocol state.
struct Session {
    flows: Arc<EndpointFlows>,
    sensors: Arc<EndpointSensors>,
    /// The endpoint id the active list admitted the connection as, set at
    /// its `hello`.
    admitted: Arc<OnceLock<Uuid>>,
    /// The connection's stream state, made when its `hello` is admitted.
    receiver: Option<ReceiverConnection>,
    /// The sensor the connection added to the sensor sets, once its records
    /// were first stored.
    sensor: Option<String>,
    /// The token the active list stops the connection through.
    stop: CancellationToken,
}

/// What [`Session::deliver`] asks [`serve`] to do next.
enum Next {
    /// Send these frames, then handle the frames received after the message.
    Reply(Vec<Frame>),
    /// The connection was stopped before its message was handled.
    Stopped,
    /// Close the connection without a word.
    Close,
}

impl Session {
    /// Handles a delivered telemetry message on a blocking thread, holding
    /// the `ReceiverStream` lock, and waits for it to end: once started, the
    /// call runs to its end whatever happens to the connection meanwhile.
    async fn deliver(&mut self, envelope: &Envelope, remote: SocketAddr) -> Next {
        let delivered = match TelemetryMessage::decode(envelope.t(), envelope.body()) {
            Ok(message) => Delivered::Message(message),
            Err(TelemetryDecodeError::BatchTooLarge { stream }) => Delivered::BatchTooLarge(stream),
            Err(e) => {
                debug!("Endpoint connection from {remote}: {e}; closing");
                return Next::Close;
            }
        };
        let Some(mut receiver) = self.receiver.take() else {
            warn!("Endpoint connection from {remote}: a telemetry message before admission");
            return Next::Close;
        };
        let flows = Arc::clone(&self.flows);
        let stop = self.stop.clone();
        let handled = tokio::task::spawn_blocking(move || {
            let handled = flows.handle(&stop, &mut receiver, delivered);
            (receiver, handled)
        })
        .await;
        let (receiver, handled) = match handled {
            Ok(handled) => handled,
            Err(e) => {
                error!(
                    "Endpoint connection from {remote}: handling a telemetry message failed: {e}"
                );
                return Next::Close;
            }
        };
        let endpoint_id = receiver.endpoint_id();
        self.receiver = Some(receiver);
        let (output, stored_at) = match handled {
            Handled::Stopped => return Next::Stopped,
            Handled::Done { output, stored_at } => (output, stored_at),
        };
        if let Some(received) = stored_at
            && self.sensor.is_none()
        {
            let sensor = endpoint_id.to_string();
            self.sensors.add(&sensor, DateTime::from(received)).await;
            self.sensor = Some(sensor);
        }
        match output {
            ReceiverOutput::Disconnect => {
                debug!("Endpoint connection from {remote}: closed by its telemetry stream");
                Next::Close
            }
            ReceiverOutput::Reply(messages) => {
                let mut frames = Vec::with_capacity(messages.len());
                for message in messages {
                    match message.to_frame() {
                        Ok(frame) => frames.push(frame),
                        Err(e) => {
                            error!("Endpoint connection from {remote}: cannot encode a reply: {e}");
                            return Next::Close;
                        }
                    }
                }
                Next::Reply(frames)
            }
        }
    }
}

/// How [`serve`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ended {
    /// `token` was cancelled. `unsent` is the rest of a frame whose writing
    /// the cancellation interrupted, empty when it came between frames;
    /// written first, it leaves the stream on a frame boundary, where a
    /// closing frame can follow.
    Stopped { unsent: Vec<u8> },
    /// The connection ended any other way.
    Closed,
}

/// Runs the protocol on an established TLS stream, configured by `config`,
/// until the connection closes or `token` is cancelled, handing the telemetry
/// messages to `session`.
#[allow(clippy::too_many_lines)] // One arm per action, each short.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut S,
    remote: SocketAddr,
    config: ServerConfig,
    token: &CancellationToken,
    session: &mut Session,
) -> Ended {
    let origin = Instant::now();
    let mut connection = ServerConnection::new(config, Duration::ZERO);
    let mut buf = vec![0_u8; READ_BUFFER_SIZE];

    while let Some(deadline) = connection.next_deadline() {
        // Every branch is cancel safe: a read that loses the race has
        // consumed nothing, the TLS layer keeping what it decrypted.
        let mut actions: VecDeque<ServerAction> = select! {
            biased;
            () = token.cancelled() => return Ended::Stopped { unsent: Vec::new() },
            () = tokio::time::sleep_until(origin + deadline) => {
                connection.poll(Timestamp::now(), origin.elapsed()).into_iter().collect()
            }
            read = tls.read(&mut buf) => match read {
                Ok(0) => {
                    debug!("Endpoint connection from {remote} closed by the peer");
                    return Ended::Closed;
                }
                // A read never reports more bytes than the buffer holds.
                Ok(n) => receive(
                    &mut connection,
                    buf.get(..n).unwrap_or_default(),
                    origin.elapsed(),
                ),
                Err(e) => {
                    debug!("Endpoint connection from {remote} failed to read: {e}");
                    return Ended::Closed;
                }
            },
        };
        while let Some(action) = actions.pop_front() {
            match action {
                // `receive` has already raised the receive limit.
                ServerAction::Handshake(handshake) => {
                    info!(
                        "Endpoint connection from {remote} established, protocol version {}, \
                         endpoint crate version {}",
                        handshake.version, handshake.hello.crate_version
                    );
                    session.receiver = session.admitted.get().map(|endpoint_id| {
                        ReceiverConnection::new(*endpoint_id, convert::accepted_kinds())
                    });
                }
                ServerAction::Send(frame) => {
                    let mut liveness = Liveness {
                        connection: &mut connection,
                        origin,
                        due: &mut actions,
                    };
                    match send(tls, frame.as_bytes(), &mut liveness, remote, token).await {
                        Sent::Written => {}
                        Sent::Stopped { unsent } => return Ended::Stopped { unsent },
                        Sent::Failed => return Ended::Closed,
                    }
                }
                ServerAction::SendThenClose { frame, reason } => {
                    debug!("Endpoint connection from {remote} closed: {reason}");
                    let mut due = VecDeque::new();
                    let mut liveness = Liveness {
                        connection: &mut connection,
                        origin,
                        due: &mut due,
                    };
                    // A connection the list admitted, refused afterwards (a
                    // `hello` with no common version), is registered while
                    // this frame goes out, so a list change can stop it
                    // midway; the rest then goes out before the error.
                    return match send(tls, frame.as_bytes(), &mut liveness, remote, token).await {
                        Sent::Stopped { unsent } => Ended::Stopped { unsent },
                        Sent::Written | Sent::Failed => Ended::Closed,
                    };
                }
                ServerAction::Close(reason) => {
                    debug!("Endpoint connection from {remote} closed: {reason}");
                    return Ended::Closed;
                }
                ServerAction::Unsupported(unsupported) => debug!(
                    "Endpoint connection from {remote} refused {:?}",
                    unsupported.kind
                ),
                // A telemetry message. The frames received after it wait
                // until it has been handled and its replies sent.
                ServerAction::Deliver(envelope) => {
                    match session.deliver(&envelope, remote).await {
                        Next::Reply(frames) => {
                            for frame in frames {
                                let mut liveness = Liveness {
                                    connection: &mut connection,
                                    origin,
                                    due: &mut actions,
                                };
                                match send(tls, frame.as_bytes(), &mut liveness, remote, token)
                                    .await
                                {
                                    Sent::Written => {}
                                    Sent::Stopped { unsent } => return Ended::Stopped { unsent },
                                    Sent::Failed => return Ended::Closed,
                                }
                            }
                        }
                        Next::Stopped => return Ended::Stopped { unsent: Vec::new() },
                        Next::Close => {
                            let reason = connection.reject_body();
                            debug!("Endpoint connection from {remote} closed: {reason:?}");
                            return Ended::Closed;
                        }
                    }
                    actions.extend(connection.accept_body(Timestamp::now(), origin.elapsed()));
                }
            }
        }
    }
    Ended::Closed
}

/// Hands `bytes`, just read, to `connection` and returns what to do about
/// them.
///
/// The connection takes frames of the size an active endpoint may send from
/// the moment its `hello` is admitted. [`ServerConnection::receive`] decodes
/// every frame the bytes complete before it returns, so until the handshake
/// the bytes go in one at a time: it then stops at the last byte of the
/// admitting `hello`, and the limit is raised before the length prefix of
/// the frame after it is read, however the endpoint's writes were split
/// into reads. The first frame is the `hello` or the connection closes, and
/// before admission it is no larger than
/// [`SERVER_OTHER_RECEIVE_LIMIT`](senta_protocol::connection::SERVER_OTHER_RECEIVE_LIMIT),
/// so this takes at most that many calls, and four more for its length.
fn receive(
    connection: &mut ServerConnection,
    bytes: &[u8],
    now: Duration,
) -> VecDeque<ServerAction> {
    let mut actions = VecDeque::new();
    let mut rest = bytes;
    if !connection.is_established() {
        while !connection.is_established() && !connection.is_closed() {
            let Some((byte, tail)) = rest.split_first() else {
                return actions;
            };
            actions.extend(connection.receive(std::slice::from_ref(byte), Timestamp::now(), now));
            rest = tail;
        }
        if connection.is_established() {
            connection.set_receive_limit(Standing::Active.receive_limit());
        }
    }
    if !rest.is_empty() {
        actions.extend(connection.receive(rest, Timestamp::now(), now));
    }
    actions
}

/// Writes what a connection the active list stopped has left to write: the
/// rest of the frame the stop interrupted, then the error it is told why
/// with, if any. Gives up when `token` is cancelled or [`CLOSE_TIMEOUT`]
/// passes, as it does when the peer has stopped reading.
async fn send_closing_frames<S: AsyncWrite + Unpin>(
    tls: &mut S,
    unsent: &[u8],
    error: Option<&Frame>,
    remote: SocketAddr,
    token: &CancellationToken,
) {
    let write = async {
        tls.write_all(unsent).await?;
        if let Some(frame) = error {
            tls.write_all(frame.as_bytes()).await?;
        }
        tls.flush().await
    };
    select! {
        biased;
        () = token.cancelled() => {}
        written = tokio::time::timeout(CLOSE_TIMEOUT, write) => match written {
            Ok(Ok(())) => {}
            Ok(Err(e)) => debug!("Endpoint connection from {remote}: closing frame not sent: {e}"),
            Err(_) => debug!(
                "Endpoint connection from {remote}: closing frame not written within \
                 {CLOSE_TIMEOUT:?}"
            ),
        },
    }
}

/// A connection's liveness, kept running while [`send`] writes.
struct Liveness<'a> {
    connection: &'a mut ServerConnection,
    origin: Instant,
    /// Where a `ping` that falls due during the write is queued, to go out
    /// after the frame being written.
    due: &'a mut VecDeque<ServerAction>,
}

/// How [`send`] ended.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    /// Every byte was written and flushed.
    Written,
    /// `token` was cancelled. `unsent` holds the bytes the stream had not
    /// taken yet; the ones it took may still await a flush.
    Stopped { unsent: Vec<u8> },
    /// The write failed, or liveness or the bound after closing gave it up.
    Failed,
}

/// Writes `bytes` to `tls`, or gives up when liveness closes the connection
/// or `token` is cancelled.
///
/// A peer that stops reading leaves the write pending, and nothing is read
/// meanwhile. Liveness keeps running over it, so the write is bounded by the
/// same [`IDLE_TIMEOUT`] since the last frame received that bounds a silent
/// connection, rather than lasting as long as the peer keeps its socket open.
///
/// A connection the protocol has already closed has no liveness deadline left,
/// yet may still have frames to write: one sent along with its closing, or
/// replies to frames that arrived in the same read as the one that closed it.
/// Such a write is bounded by [`CLOSE_TIMEOUT`] instead.
async fn send<S: AsyncWrite + Unpin>(
    tls: &mut S,
    bytes: &[u8],
    liveness: &mut Liveness<'_>,
    remote: SocketAddr,
    token: &CancellationToken,
) -> Sent {
    let mut rest = bytes;
    let mut closing_until = None;
    loop {
        let deadline = liveness.connection.next_deadline();
        let wake = match deadline {
            Some(deadline) => liveness.origin + deadline,
            None => *closing_until.get_or_insert_with(|| Instant::now() + CLOSE_TIMEOUT),
        };
        // Each step, a `write` or the final `flush`, is cancel safe: a
        // `write` that loses the race has taken no byte, so `rest` is
        // exactly what is left, and a `flush` resumes where it stopped. A
        // liveness `ping` therefore loses nothing, and a stop by the active
        // list hands the rest over to be finished before the closing frame.
        let step = async {
            if rest.is_empty() {
                tls.flush().await.map(|()| 0)
            } else {
                tls.write(rest).await
            }
        };
        select! {
            biased;
            () = token.cancelled() => return Sent::Stopped { unsent: rest.to_vec() },
            written = step => match written {
                Ok(0) if rest.is_empty() => return Sent::Written,
                Ok(0) => {
                    debug!("Endpoint connection from {remote}: send failed: the stream took no bytes");
                    return Sent::Failed;
                }
                Ok(n) => rest = rest.get(n..).unwrap_or_default(),
                Err(e) => {
                    debug!("Endpoint connection from {remote}: send failed: {e}");
                    return Sent::Failed;
                }
            },
            () = tokio::time::sleep_until(wake) => {
                if deadline.is_none() {
                    debug!(
                        "Endpoint connection from {remote}: the frames left after closing were \
                         not written within {CLOSE_TIMEOUT:?}"
                    );
                    return Sent::Failed;
                }
                match liveness.connection.poll(Timestamp::now(), liveness.origin.elapsed()) {
                    Some(ServerAction::Close(reason)) => {
                        debug!("Endpoint connection from {remote} closed: {reason}");
                        return Sent::Failed;
                    }
                    action => liveness.due.extend(action),
                }
            }
        }
    }
}

/// Closes `tls`, sending TLS `close_notify`, or gives up when `token` is
/// cancelled or [`CLOSE_TIMEOUT`] passes, as it does when the peer has stopped
/// reading.
async fn close<S: AsyncWrite + Unpin>(tls: &mut S, token: &CancellationToken) {
    select! {
        biased;
        () = token.cancelled() => {}
        _ = tokio::time::timeout(CLOSE_TIMEOUT, tls.shutdown()) => {}
    }
}

#[cfg(test)]
impl Entry {
    /// Returns an entry over `list`, `database` and `flows`, with sensor sets
    /// of its own.
    fn for_test(list: &Arc<EndpointList>, database: &Database, flows: &Arc<EndpointFlows>) -> Self {
        Self {
            list: Arc::clone(list),
            database: database.clone(),
            flows: Arc::clone(flows),
            sensors: Arc::new(EndpointSensors::new(
                database.clone(),
                crate::comm::new_ingest_sensors(database),
                crate::comm::new_runtime_ingest_sensors(),
                None,
            )),
        }
    }
}

#[cfg(test)]
impl Session {
    /// Returns the session of a connection no list admits, over `database`.
    fn for_test(database: &Database) -> Self {
        let flows = Arc::new(EndpointFlows::new(database.clone()));
        let list = Arc::new(EndpointList::new(Duration::from_secs(60)));
        let entry = Entry::for_test(&list, database, &flows);
        Self {
            flows,
            sensors: entry.sensors,
            admitted: Arc::new(OnceLock::new()),
            receiver: None,
            sensor: None,
            stop: CancellationToken::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    mod telemetry;

    use std::{
        net::Ipv4Addr,
        pin::Pin,
        task::{Context as TaskContext, Poll},
    };

    use senta_protocol::{
        auth::{
            active_list::{DEFAULT_LEASE_LENGTH, EntryState, ListUpdate},
            tls::CONTROL_ALPN,
        },
        connection::{
            AcceptedKind, ENDPOINT_RECEIVE_LIMIT, EndpointAction, EndpointChannel, EndpointConfig,
            EndpointConnection, Envelope, Frame, FrameDecoder, Hello, HelloAck, Message,
            PING_INTERVAL, PROTOCOL_VERSION, Ping, Pong, SERVER_ACTIVE_RECEIVE_LIMIT,
            SERVER_OTHER_RECEIVE_LIMIT, TelemetryEntry, Unsupported, VersionRange,
        },
        telemetry::ErrorMessage,
        telemetry_codes::TelemetryError,
    };
    use tempfile::TempDir;
    use tokio::{
        io::ReadBuf,
        sync::{Notify, watch},
        task::JoinHandle,
    };
    use uuid::Uuid;

    use super::*;
    use crate::{
        comm::{
            IngestSensors, RunTimeIngestSensors,
            endpoint::active_list::tests::{
                ENTRY_ID, diff, encode, entry, error_of, full, suspended,
            },
        },
        storage::DbOptions,
        test_bootroot::{
            CaGeneration, ENDPOINT_SEED, NodeCert, capture_logs, endpoint_client_config_for,
            endpoint_client_config_over, endpoint_client_config_trusting, endpoint_connect,
            endpoint_spki, init_crypto, presented_chain, wait_for_log, write_node_files,
            x25519_only_provider,
        },
        tls_reload::{load_tls_material, test_tls_watch},
    };

    const NODE: &str = "001.giganto.node1.example.test";
    const IO_TIMEOUT: Duration = Duration::from_secs(10);

    type EndpointStream = tokio_rustls::client::TlsStream<TcpStream>;

    /// A node whose certificate the first CA generation issued.
    struct Node {
        dir: TempDir,
        ca: CaGeneration,
        cert: NodeCert,
    }

    impl Node {
        fn new() -> Self {
            init_crypto();
            let ca = CaGeneration::new("Endpoint");
            let cert = ca.issue_node_cert(NODE);
            Self {
                dir: tempfile::tempdir().expect("tempdir"),
                ca,
                cert,
            }
        }

        /// Writes `cert` with `bundle` as the node's files and loads them.
        fn material(&self, cert: &NodeCert, bundle: &str) -> Arc<TlsMaterial> {
            let paths = write_node_files(self.dir.path(), cert, bundle);
            Arc::new(load_tls_material(&paths).expect("load the TLS material"))
        }
    }

    /// An endpoint entry served by a task of the test.
    struct Running {
        addr: SocketAddr,
        token: CancellationToken,
        handle: JoinHandle<Result<()>>,
        tls_tx: Option<watch::Sender<Arc<TlsMaterial>>>,
        list: Arc<EndpointList>,
        db: Database,
        flows: Arc<EndpointFlows>,
        ingest_sensors: IngestSensors,
        runtime_ingest_sensors: RunTimeIngestSensors,
        sensor_change: Arc<Notify>,
        /// The database's directory, when the entry made the database.
        db_dir: Option<TempDir>,
    }

    impl Running {
        /// Starts an entry whose node is ready with `entry_id` when one is
        /// given: a full list listing the fake endpoint's key as active is
        /// applied with it.
        async fn start(material: Arc<TlsMaterial>, entry_id: Option<Uuid>) -> Self {
            let running = Self::start_with_lease(material, DEFAULT_LEASE_LENGTH).await;
            if let Some(entry_id) = entry_id {
                running
                    .apply(
                        &full(
                            1,
                            vec![entry(1, endpoint_spki(&ENDPOINT_SEED), EntryState::Active)],
                        ),
                        entry_id,
                    )
                    .await
                    .expect("the full list applies");
            }
            running
        }

        /// Starts an unready entry whose lease is `lease` long.
        async fn start_with_lease(material: Arc<TlsMaterial>, lease: Duration) -> Self {
            let db_dir = tempfile::tempdir().expect("tempdir");
            let db =
                Database::open(db_dir.path(), &DbOptions::default()).expect("open the database");
            let ingest_sensors = crate::comm::new_ingest_sensors(&db);
            let mut running = Self::start_on(material, lease, db, ingest_sensors).await;
            running.db_dir = Some(db_dir);
            running
        }

        /// Starts an unready entry whose lease is `lease` long, over `db`
        /// and `ingest_sensors`.
        async fn start_on(
            material: Arc<TlsMaterial>,
            lease: Duration,
            db: Database,
            ingest_sensors: IngestSensors,
        ) -> Self {
            let endpoint_tls = Arc::new(EndpointTls::default());
            let tls_config = endpoint_tls
                .build(&material)
                .expect("the endpoint TLS configuration is built");
            let (tls_tx, tls_watch) = test_tls_watch(material);
            let list = Arc::new(EndpointList::new(lease));
            list.load_entry_id(&db);
            let flows = Arc::new(EndpointFlows::new(db.clone()));
            let runtime_ingest_sensors = crate::comm::new_runtime_ingest_sensors();
            let sensor_change = Arc::new(Notify::new());
            let server = Server::new(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                tls_config,
                endpoint_tls,
                Arc::clone(&list),
                db.clone(),
                Arc::clone(&flows),
                EndpointSensors::new(
                    db.clone(),
                    ingest_sensors.clone(),
                    runtime_ingest_sensors.clone(),
                    Some(Arc::clone(&sensor_change)),
                ),
            )
            .bind()
            .await
            .expect("bind the endpoint listener");
            let addr = server.local_addr();
            let token = CancellationToken::new();
            let handle = tokio::spawn(server.run(tls_watch, token.clone(), Duration::from_secs(5)));
            Self {
                addr,
                token,
                handle,
                tls_tx: Some(tls_tx),
                list,
                db,
                flows,
                ingest_sensors,
                runtime_ingest_sensors,
                sensor_change,
                db_dir: None,
            }
        }

        /// Waits until the entry has built `count` connections in all: in
        /// TLS 1.3 the client finishes its handshake before the server does.
        async fn wait_opened(&self, count: u64) {
            tokio::time::timeout(IO_TIMEOUT, async {
                while self.list.connections_opened() < count {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("the entry builds the connection in time");
        }

        /// Applies `update` with `entry_id`, as REview does.
        async fn apply(
            &self,
            update: &ListUpdate,
            entry_id: Uuid,
        ) -> Result<ListAck, ApplyRefusal> {
            self.list
                .apply(&encode(update), &entry_id.to_string(), &self.flows)
                .await
        }

        /// Publishes `material` as reloaded TLS material.
        fn reload(&self, material: Arc<TlsMaterial>) {
            self.tls_tx
                .as_ref()
                .expect("the TLS watch is open")
                .send(material)
                .expect("the entry watches the TLS material");
        }

        async fn connect(&self, root_pem: String) -> EndpointStream {
            self.connect_with_key(root_pem, &ENDPOINT_SEED).await
        }

        /// Connects a fake endpoint holding the key `seed`.
        async fn connect_with_key(&self, root_pem: String, seed: &[u8; 32]) -> EndpointStream {
            tokio::time::timeout(
                IO_TIMEOUT,
                endpoint_connect(
                    self.addr,
                    endpoint_client_config_for(&[root_pem], seed),
                    NODE,
                ),
            )
            .await
            .expect("the handshake finishes in time")
            .expect("the endpoint completes the TLS handshake")
        }

        async fn stop(self) {
            self.token.cancel();
            self.handle
                .await
                .expect("the endpoint entry task joins")
                .expect("the endpoint entry stops cleanly");
        }
    }

    /// An endpoint on blocking I/O, for tests on a paused clock: while its
    /// thread works, the clock does not advance on its own.
    struct BlockingEndpoint {
        tls: rustls::ClientConnection,
        tcp: std::net::TcpStream,
        decoder: FrameDecoder,
    }

    impl BlockingEndpoint {
        /// Connects to `addr` and completes the TLS handshake.
        fn connect(addr: SocketAddr, config: rustls::ClientConfig) -> Self {
            let server_name = rustls::pki_types::ServerName::try_from(NODE).expect("server name");
            let mut tls = rustls::ClientConnection::new(Arc::new(config), server_name)
                .expect("client connection");
            let mut tcp = std::net::TcpStream::connect(addr).expect("connect the endpoint");
            tcp.set_read_timeout(Some(IO_TIMEOUT))
                .expect("read timeout");
            while tls.is_handshaking() {
                tls.complete_io(&mut tcp).expect("the TLS handshake");
            }
            Self {
                tls,
                tcp,
                decoder: FrameDecoder::new(ENDPOINT_RECEIVE_LIMIT),
            }
        }

        fn send(&mut self, frame: &Frame) {
            let mut stream = rustls::Stream::new(&mut self.tls, &mut self.tcp);
            std::io::Write::write_all(&mut stream, frame.as_bytes()).expect("send a frame");
            std::io::Write::flush(&mut stream).expect("flush");
        }

        /// Sends `ping`s, reading none of the `pong`s, until no more can be
        /// written for a while: the entry has stopped reading, which it does
        /// only while a write to this endpoint is pending.
        fn send_pings_until_the_entry_stops_reading(&mut self) {
            const PINGS_PER_WRITE: usize = 1024;
            const STALLED_AFTER: Duration = Duration::from_secs(2);

            let ping = Frame::from_message(&Ping {
                sent_at: Timestamp::now(),
            })
            .expect("encode a ping");
            let batch = ping.as_bytes().repeat(PINGS_PER_WRITE);
            self.tcp
                .set_write_timeout(Some(STALLED_AFTER))
                .expect("write timeout");
            let stalled = loop {
                let mut stream = rustls::Stream::new(&mut self.tls, &mut self.tcp);
                if let Err(e) = std::io::Write::write_all(&mut stream, &batch) {
                    break e;
                }
            };
            assert!(
                matches!(
                    stalled.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "send pings to the entry: {stalled}"
            );
        }

        /// Returns the kind of the next frame the entry sends, or `None` once
        /// it has closed the connection.
        fn next_kind(&mut self) -> Option<String> {
            let mut buf = vec![0_u8; READ_BUFFER_SIZE];
            loop {
                if let Some(payload) = self.decoder.next_frame().expect("a frame within the limit")
                {
                    let envelope = Envelope::parse(&payload).expect("an envelope");
                    return Some(envelope.t().to_owned());
                }
                let mut stream = rustls::Stream::new(&mut self.tls, &mut self.tcp);
                match std::io::Read::read(&mut stream, &mut buf) {
                    Ok(0) => return None,
                    Ok(n) => self.decoder.push(&buf[..n]),
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        return None;
                    }
                    Err(e) => panic!("read from the entry: {e}"),
                }
            }
        }
    }

    /// A connection that hands the entry one scripted chunk per read, then
    /// nothing more, and takes what the entry writes only until it has read
    /// the last chunk: from then on its peer reads nothing.
    struct Scripted {
        reads: VecDeque<Vec<u8>>,
        written: Vec<u8>,
    }

    impl AsyncRead for Scripted {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.reads.pop_front() {
                Some(chunk) => {
                    buf.put_slice(&chunk);
                    Poll::Ready(Ok(()))
                }
                None => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for Scripted {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.reads.is_empty() {
                return Poll::Pending;
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.reads.is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    fn hello(expected_entry_id: Uuid) -> (EndpointConnection, Frame) {
        EndpointConnection::new(
            EndpointConfig::new(EndpointChannel::Telemetry { expected_entry_id }, "0.1.0"),
            Timestamp::now(),
            Duration::ZERO,
        )
        .expect("encode the hello")
    }

    async fn send(stream: &mut EndpointStream, frame: &Frame) {
        stream
            .write_all(frame.as_bytes())
            .await
            .expect("send a frame");
        stream.flush().await.expect("flush");
    }

    /// Reads until the server closes the connection, and returns what it sent.
    async fn read_until_closed(stream: &mut EndpointStream) -> Vec<u8> {
        let mut received = Vec::new();
        tokio::time::timeout(IO_TIMEOUT, stream.read_to_end(&mut received))
            .await
            .expect("the server closes the connection in time")
            .expect("the server closes the connection cleanly");
        received
    }

    /// Completes the protocol handshake on `stream` and returns what the
    /// entry announced.
    async fn handshake(stream: &mut EndpointStream) -> (EndpointConnection, TelemetryEntry) {
        handshake_expecting(stream, ENTRY_ID).await
    }

    /// The same, from an endpoint that expects `expected_entry_id`.
    async fn handshake_expecting(
        stream: &mut EndpointStream,
        expected_entry_id: Uuid,
    ) -> (EndpointConnection, TelemetryEntry) {
        let (mut endpoint, hello) = hello(expected_entry_id);
        send(stream, &hello).await;
        let mut buf = vec![0_u8; READ_BUFFER_SIZE];
        loop {
            let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut buf))
                .await
                .expect("the hello_ack arrives in time")
                .expect("read the hello_ack");
            assert_ne!(n, 0, "the entry closed instead of answering the hello");
            for action in endpoint.receive(&buf[..n], Timestamp::now(), Duration::ZERO) {
                match action {
                    EndpointAction::Handshake(handshake) => {
                        let entry = handshake
                            .telemetry
                            .expect("a telemetry hello_ack announces the entry");
                        return (endpoint, entry);
                    }
                    EndpointAction::ClockMeasured(_) => {}
                    other => panic!("unexpected action before the handshake: {other:?}"),
                }
            }
        }
    }

    /// Sends a `ping` on an established connection and waits for its `pong`.
    async fn ping_pong(stream: &mut EndpointStream) {
        let ping = Frame::from_message(&Ping {
            sent_at: Timestamp::now(),
        })
        .expect("encode a ping");
        send(stream, &ping).await;
        let mut decoder = FrameDecoder::new(SERVER_ACTIVE_RECEIVE_LIMIT);
        let mut buf = vec![0_u8; READ_BUFFER_SIZE];
        loop {
            let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut buf))
                .await
                .expect("the pong arrives in time")
                .expect("read the pong");
            assert_ne!(
                n, 0,
                "the connection was closed instead of answering the ping"
            );
            decoder.push(&buf[..n]);
            if let Some(payload) = decoder.next_frame().expect("a frame within the limit") {
                let envelope = Envelope::parse(&payload).expect("an envelope");
                assert_eq!(envelope.t(), Pong::T);
                return;
            }
        }
    }

    #[tokio::test]
    async fn a_root_only_endpoint_sees_the_leaf_and_its_intermediate() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, None).await;

        let stream = running.connect(node.ca.root.pem()).await;
        assert_eq!(
            presented_chain(&stream),
            vec![node.cert.der.clone(), node.ca.intermediate.der().clone()],
            "the entry presents the leaf and its intermediate, never the root"
        );
        drop(stream);
        running.stop().await;
    }

    #[tokio::test]
    async fn an_unready_entry_closes_a_hello_with_nothing_sent() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, None).await;

        let mut stream = running.connect(node.ca.root.pem()).await;
        let (_endpoint, hello) = hello(Uuid::nil());
        send(&mut stream, &hello).await;
        assert!(
            read_until_closed(&mut stream).await.is_empty(),
            "an unready entry sends nothing back"
        );
        running.stop().await;
    }

    #[tokio::test]
    async fn a_ready_entry_answers_with_its_entry_id_and_accepted_kinds() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;

        let mut stream = running.connect(node.ca.root.pem()).await;
        let (_endpoint, entry) = handshake(&mut stream).await;
        let expected_kinds: Vec<AcceptedKind> = [
            1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 22, 23, 25, 26, 1000, 1100, 1101,
        ]
        .into_iter()
        .map(|kind| AcceptedKind {
            kind,
            schema_min: 1,
            schema_max: 1,
        })
        .collect();
        assert_eq!(
            entry,
            TelemetryEntry {
                entry_id: ENTRY_ID,
                accepted_kinds: expected_kinds,
            }
        );
        assert!(
            entry
                .accepted_kinds
                .windows(2)
                .all(|pair| pair[0].kind < pair[1].kind),
            "the kinds are announced in ascending order"
        );
        ping_pong(&mut stream).await;

        // An endpoint refusing a message leaves the connection open.
        let refusal = Frame::from_message(&Unsupported::version()).expect("encode a refusal");
        send(&mut stream, &refusal).await;
        ping_pong(&mut stream).await;

        // A second `hello` closes the connection, with no error sent.
        let (_again, hello) = hello(ENTRY_ID);
        send(&mut stream, &hello).await;
        assert!(
            read_until_closed(&mut stream).await.is_empty(),
            "a repeated hello is closed without a word"
        );
        running.stop().await;
    }

    #[tokio::test]
    async fn an_endpoint_that_closes_is_closed_in_turn() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;

        let mut stream = running.connect(node.ca.root.pem()).await;
        handshake(&mut stream).await;
        stream.shutdown().await.expect("send close_notify");
        assert!(
            read_until_closed(&mut stream).await.is_empty(),
            "the entry closes its side without sending anything"
        );
        running.stop().await;
    }

    #[tokio::test]
    async fn a_first_message_other_than_hello_closes_without_an_error() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;

        let mut stream = running.connect(node.ca.root.pem()).await;
        let ping = Frame::from_message(&Ping {
            sent_at: Timestamp::now(),
        })
        .expect("encode a ping");
        send(&mut stream, &ping).await;
        assert!(
            read_until_closed(&mut stream).await.is_empty(),
            "a first message other than hello is closed without a word"
        );
        running.stop().await;
    }

    #[tokio::test]
    async fn the_alpn_and_the_key_exchange_are_enforced() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;
        let roots = [node.ca.root.pem()];
        let provider = Arc::new(crate::server::server_crypto_provider());

        // The control ALPN is not this port's.
        let control = endpoint_client_config_over(Arc::clone(&provider), &roots, CONTROL_ALPN);
        assert!(
            endpoint_connect(running.addr, control, NODE).await.is_err(),
            "a client offering only the control ALPN cannot connect"
        );

        // A client offering no ALPN completes the TLS handshake, but the
        // connection is closed before any frame is read.
        let mut no_alpn = endpoint_client_config_trusting(&roots);
        no_alpn.alpn_protocols.clear();
        let mut stream = endpoint_connect(running.addr, no_alpn, NODE)
            .await
            .expect("the TLS handshake completes without ALPN");
        assert_eq!(stream.get_ref().1.alpn_protocol(), None);
        assert!(
            read_until_closed(&mut stream).await.is_empty(),
            "a connection without the telemetry ALPN is closed with nothing sent"
        );

        // Classical X25519 alone is refused.
        let x25519 = endpoint_client_config_over(x25519_only_provider(), &roots, TELEMETRY_ALPN);
        assert!(
            endpoint_connect(running.addr, x25519, NODE).await.is_err(),
            "a client offering only X25519 fails the handshake"
        );

        // The entry still serves a well-behaved endpoint.
        let mut stream = running.connect(node.ca.root.pem()).await;
        handshake(&mut stream).await;
        running.stop().await;
    }

    #[tokio::test]
    async fn a_reload_serves_the_new_chain_and_keeps_established_connections() {
        let (logs, _guard) = capture_logs();
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;
        let mut established = running.connect(node.ca.root.pem()).await;
        handshake(&mut established).await;

        // A CA rotation: the bundle holds both generations, and the node
        // certificate and key come from the new one.
        let next = CaGeneration::new("Next");
        let rotated = next.issue_node_cert(NODE);
        let bundle = format!("{}{}", node.ca.bundle_pem(), next.bundle_pem());
        running.reload(node.material(&rotated, &bundle));
        wait_for_log(&logs, "Endpoint entry: TLS configuration reloaded").await;

        let stream = running.connect(next.root.pem()).await;
        assert_eq!(
            presented_chain(&stream),
            vec![rotated.der.clone(), next.intermediate.der().clone()]
        );
        ping_pong(&mut established).await;
        drop(stream);
        drop(established);
        running.stop().await;
    }

    #[tokio::test]
    async fn a_reload_without_the_new_intermediate_keeps_the_previous_chain_and_key() {
        let (logs, _guard) = capture_logs();
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;

        let next = CaGeneration::new("Next");
        let rotated = next.issue_node_cert(NODE);
        let bundle = format!("{}{}", node.ca.bundle_pem(), next.root.pem());
        running.reload(node.material(&rotated, &bundle));
        wait_for_log(&logs, "keeping the previous TLS configuration").await;

        // The previous leaf, with the previous key: a handshake proves the
        // key matches the certificate presented.
        let mut stream = running.connect(node.ca.root.pem()).await;
        assert_eq!(
            presented_chain(&stream),
            vec![node.cert.der.clone(), node.ca.intermediate.der().clone()]
        );
        handshake(&mut stream).await;
        running.stop().await;
    }

    /// A TCP client that never starts its TLS handshake holds up nobody, and
    /// is dropped once [`IDLE_TIMEOUT`] has passed.
    ///
    /// The clock is paused and advanced by hand. The second client runs on a
    /// blocking thread, which keeps the paused clock from advancing on its
    /// own while that client's handshake is in flight.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_handshake_is_dropped_after_the_idle_timeout() {
        use std::io::Read;

        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, None).await;
        let addr = running.addr;

        let mut stalled = std::net::TcpStream::connect(addr).expect("connect the stalled client");
        let config = endpoint_client_config_trusting(&[node.ca.root.pem()]);
        let completed = tokio::task::spawn_blocking(move || {
            BlockingEndpoint::connect(addr, config)
                .tls
                .alpn_protocol()
                .map(<[u8]>::to_vec)
        })
        .await
        .expect("the second client's thread joins");
        assert_eq!(completed.as_deref(), Some(TELEMETRY_ALPN));

        // Nothing has been sent on the stalled connection, and it is still
        // open: a read would block rather than see the end of the stream.
        stalled.set_nonblocking(true).expect("non-blocking");
        let mut byte = [0_u8; 1];
        assert_eq!(
            stalled.read(&mut byte).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::WouldBlock),
            "the stalled connection is still open before the idle timeout"
        );
        stalled.set_nonblocking(false).expect("blocking");

        tokio::time::advance(IDLE_TIMEOUT).await;
        let closed = tokio::task::spawn_blocking(move || {
            stalled
                .set_read_timeout(Some(IO_TIMEOUT))
                .expect("read timeout");
            stalled.read(&mut byte)
        })
        .await
        .expect("the stalled client's thread joins");
        assert!(
            matches!(closed, Ok(0))
                || closed.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset),
            "the stalled connection is dropped after the idle timeout"
        );
        running.stop().await;
    }

    #[tokio::test]
    async fn a_hello_with_no_common_version_is_refused_then_closed() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;

        let mut stream = running.connect(node.ca.root.pem()).await;
        let next = PROTOCOL_VERSION + 1;
        let hello = Frame::from_message(&Hello {
            crate_version: "0.1.0".to_owned(),
            versions: VersionRange::new(next, next),
            sent_at: Timestamp::now(),
        })
        .expect("encode the hello");
        send(&mut stream, &hello).await;

        let received = read_until_closed(&mut stream).await;
        let mut decoder = FrameDecoder::new(ENDPOINT_RECEIVE_LIMIT);
        decoder.push(&received);
        let payload = decoder
            .next_frame()
            .expect("a frame within the limit")
            .expect("the entry sends its refusal before closing");
        let envelope = Envelope::parse(&payload).expect("an envelope");
        assert_eq!(envelope.t(), Unsupported::T);
        let refusal: Unsupported = envelope.body().decode().expect("decode the refusal");
        assert!(refusal.is_version(), "the refusal names the version");
        assert_eq!(
            decoder.next_frame().expect("a frame within the limit"),
            None,
            "nothing follows the refusal"
        );
        running.stop().await;
    }

    #[tokio::test]
    async fn a_closed_tls_watch_keeps_the_configuration_in_use() {
        let (logs, _guard) = capture_logs();
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let mut running = Running::start(material, Some(ENTRY_ID)).await;

        running.tls_tx = None;
        wait_for_log(&logs, "Endpoint entry: TLS watch closed").await;

        let mut stream = running.connect(node.ca.root.pem()).await;
        assert_eq!(
            presented_chain(&stream),
            vec![node.cert.der.clone(), node.ca.intermediate.der().clone()]
        );
        handshake(&mut stream).await;
        running.stop().await;
    }

    /// Stopping the entry ends a connection still in its TLS handshake and an
    /// established one alike, without waiting for either endpoint.
    #[tokio::test]
    async fn stopping_the_entry_ends_handshakes_and_established_connections() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;

        let mut stalled = TcpStream::connect(running.addr)
            .await
            .expect("connect the stalled client");
        let mut established = running.connect(node.ca.root.pem()).await;
        handshake(&mut established).await;

        // `stop` returns once every connection task has ended.
        tokio::time::timeout(IO_TIMEOUT, running.stop())
            .await
            .expect("the entry stops without waiting for its endpoints");

        let mut received = Vec::new();
        let read = tokio::time::timeout(IO_TIMEOUT, established.read_to_end(&mut received))
            .await
            .expect("the established connection ends in time");
        assert!(
            received.is_empty(),
            "nothing is sent to an established connection at shutdown"
        );
        assert!(
            read.is_ok() || read.is_err_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof),
            "the established connection is closed"
        );

        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(IO_TIMEOUT, stalled.read(&mut byte))
            .await
            .expect("the stalled connection ends in time");
        assert!(
            matches!(read, Ok(0))
                || read.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset),
            "the connection still in its handshake is closed"
        );
    }

    /// Liveness pings an established connection after [`PING_INTERVAL`] and
    /// closes it once it has been silent for [`IDLE_TIMEOUT`].
    ///
    /// The clock is paused and advanced by hand; the endpoint runs on a
    /// blocking thread, which keeps the paused clock from advancing on its own
    /// while the endpoint waits for the entry.
    #[tokio::test(start_paused = true)]
    async fn liveness_pings_a_silent_connection_then_closes_it() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;
        let addr = running.addr;
        let config = endpoint_client_config_trusting(&[node.ca.root.pem()]);

        let endpoint = tokio::task::spawn_blocking(move || {
            let mut endpoint = BlockingEndpoint::connect(addr, config);
            let (_endpoint, hello) = hello(ENTRY_ID);
            endpoint.send(&hello);
            let ack = endpoint.next_kind();
            (endpoint, ack)
        });
        let (endpoint, ack) = endpoint.await.expect("the endpoint's thread joins");
        assert_eq!(ack.as_deref(), Some(HelloAck::T));

        tokio::time::advance(PING_INTERVAL).await;
        let ping = tokio::task::spawn_blocking(move || {
            let mut endpoint = endpoint;
            let ping = endpoint.next_kind();
            (endpoint, ping)
        });
        let (mut endpoint, ping) = ping.await.expect("the endpoint's thread joins");
        assert_eq!(
            ping.as_deref(),
            Some(Ping::T),
            "the entry pings after the interval"
        );

        tokio::time::advance(IDLE_TIMEOUT).await;
        let closed = tokio::task::spawn_blocking(move || endpoint.next_kind())
            .await
            .expect("the endpoint's thread joins");
        assert_eq!(closed, None, "the entry closes a silent connection");
        running.stop().await;
    }

    /// An endpoint that stops reading while it keeps sending is closed once
    /// [`IDLE_TIMEOUT`] has passed since the entry last read from it, though
    /// the entry's write to it, and then its `close_notify`, never finish.
    ///
    /// The endpoint sends `ping`s and reads no `pong` until the entry is stuck
    /// writing and so reads no more. The clock is paused: the endpoint runs on
    /// a blocking thread, which keeps the clock from advancing on its own while
    /// it fills the buffers, and the clock then advances through the entry's
    /// timers on its own.
    #[tokio::test(start_paused = true)]
    async fn an_endpoint_that_stops_reading_is_closed_after_the_idle_timeout() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;
        let addr = running.addr;
        let config = endpoint_client_config_trusting(&[node.ca.root.pem()]);

        let endpoint = tokio::task::spawn_blocking(move || {
            let mut endpoint = BlockingEndpoint::connect(addr, config);
            let (_endpoint, hello) = hello(ENTRY_ID);
            endpoint.send(&hello);
            assert_eq!(endpoint.next_kind().as_deref(), Some(HelloAck::T));
            endpoint.send_pings_until_the_entry_stops_reading();
            endpoint
        });
        let endpoint = endpoint.await.expect("the endpoint's thread joins");

        // Past the idle timeout and then the bound on closing.
        tokio::time::sleep(IDLE_TIMEOUT + CLOSE_TIMEOUT + Duration::from_secs(1)).await;

        // The entry has dropped the connection with the endpoint's `ping`s
        // unread, which resets it; a write still blocked on full buffers
        // would instead time out.
        // The write timeout set while sending the `ping`s still applies; a
        // reset socket refuses a new one on some systems.
        let written = tokio::task::spawn_blocking(move || {
            let mut tcp = endpoint.tcp;
            std::io::Write::write_all(&mut tcp, &[0_u8; READ_BUFFER_SIZE])
        })
        .await
        .expect("the endpoint's thread joins");
        let kind = written.map_err(|e| e.kind());
        assert!(
            matches!(
                kind,
                Err(std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe)
            ),
            "the entry drops a connection it cannot write to: {kind:?}"
        );
        running.stop().await;
    }

    /// A reply left to write after the protocol has closed, here the `pong`
    /// to a `ping` that arrived in the same read as the repeated `hello`
    /// that closed the connection, is given up after [`CLOSE_TIMEOUT`] when
    /// the endpoint has stopped reading, though no liveness deadline is left
    /// to bound it. Closing the connection afterwards, whose TLS
    /// `close_notify` that endpoint does not read either, is bounded the same
    /// way.
    #[tokio::test(start_paused = true)]
    async fn a_reply_left_after_closing_is_bounded_when_the_endpoint_stops_reading() {
        let (_endpoint, hello) = hello(ENTRY_ID);
        let ping = Frame::from_message(&Ping {
            sent_at: Timestamp::now(),
        })
        .expect("encode a ping");
        let mut ping_then_hello = ping.as_bytes().to_vec();
        ping_then_hello.extend_from_slice(hello.as_bytes());
        let mut stream = Scripted {
            reads: VecDeque::from([hello.as_bytes().to_vec(), ping_then_hello]),
            written: Vec::new(),
        };
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let db_dir = tempfile::tempdir().expect("tempdir");
        let database =
            Database::open(db_dir.path(), &DbOptions::default()).expect("open the database");

        let started = Instant::now();
        let channel = ServerChannel::Telemetry {
            entry_id: ENTRY_ID,
            accepted_kinds: Vec::new(),
        };
        let config = ServerConfig::new(channel, Standing::Active.receive_limit());
        let served = tokio::time::timeout(
            IDLE_TIMEOUT,
            serve(
                &mut stream,
                remote,
                config,
                &CancellationToken::new(),
                &mut Session::for_test(&database),
            ),
        )
        .await;
        assert!(
            served.is_ok(),
            "the entry gives up a reply it cannot write after closing"
        );
        assert_eq!(started.elapsed(), CLOSE_TIMEOUT);

        let mut decoder = FrameDecoder::new(ENDPOINT_RECEIVE_LIMIT);
        decoder.push(&stream.written);
        let mut kinds = Vec::new();
        while let Some(payload) = decoder.next_frame().expect("a frame within the limit") {
            let envelope = Envelope::parse(&payload).expect("an envelope");
            kinds.push(envelope.t().to_owned());
        }
        assert_eq!(kinds, [HelloAck::T], "only the hello_ack was written");

        let closing = Instant::now();
        let closed =
            tokio::time::timeout(IDLE_TIMEOUT, close(&mut stream, &CancellationToken::new())).await;
        assert!(
            closed.is_ok(),
            "the entry gives up a close_notify it cannot write"
        );
        assert_eq!(closing.elapsed(), CLOSE_TIMEOUT);
    }

    /// A message of a kind the entry does not handle, as large as wanted.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Bulky {
        padding: String,
    }

    impl Message for Bulky {
        const T: &'static str = "bulky_test";
    }

    fn other_entry_id() -> Uuid {
        Uuid::from_u128(0x00ab_cdef)
    }

    /// Reads until the entry closes the connection, and returns the kind and
    /// payload of every frame it sent.
    async fn frames_until_closed(stream: &mut EndpointStream) -> Vec<(String, Vec<u8>)> {
        let received = read_until_closed(stream).await;
        let mut decoder = FrameDecoder::new(ENDPOINT_RECEIVE_LIMIT);
        decoder.push(&received);
        let mut frames = Vec::new();
        while let Some(payload) = decoder.next_frame().expect("a frame within the limit") {
            let envelope = Envelope::parse(&payload).expect("an envelope");
            frames.push((envelope.t().to_owned(), payload));
        }
        frames
    }

    /// Asserts that the entry sent `error` alone, then closed.
    async fn assert_closed_with(stream: &mut EndpointStream, error: TelemetryError) {
        let frames = frames_until_closed(stream).await;
        let kinds: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(kinds, [ErrorMessage::T], "the error alone, no hello_ack");
        let (_, payload) = frames.first().expect("one frame");
        let mut whole_frame = Vec::new();
        whole_frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        whole_frame.extend_from_slice(payload);
        assert_eq!(error_of(&whole_frame), error);
    }

    const KEY_PENDING: [u8; 32] = [1; 32];
    const KEY_SUSPENDED: [u8; 32] = [2; 32];
    const KEY_ACTIVE: [u8; 32] = [3; 32];
    const KEY_UNLISTED: [u8; 32] = [4; 32];
    const KEY_OTHER: [u8; 32] = [5; 32];

    #[tokio::test]
    async fn each_standing_is_answered_at_hello() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, None).await;
        running
            .apply(
                &full(
                    1,
                    vec![
                        entry(1, endpoint_spki(&KEY_PENDING), EntryState::LicensePending),
                        entry(2, endpoint_spki(&KEY_SUSPENDED), suspended()),
                        entry(3, endpoint_spki(&KEY_ACTIVE), EntryState::Active),
                    ],
                ),
                ENTRY_ID,
            )
            .await
            .expect("the full list applies");

        for (key, error) in [
            (KEY_PENDING, TelemetryError::NotListed),
            (KEY_UNLISTED, TelemetryError::NotListed),
            (KEY_SUSPENDED, TelemetryError::Suspended),
        ] {
            let mut stream = running.connect_with_key(node.ca.root.pem(), &key).await;
            let (_endpoint, hello) = hello(ENTRY_ID);
            send(&mut stream, &hello).await;
            assert_closed_with(&mut stream, error).await;
        }

        let mut stream = running
            .connect_with_key(node.ca.root.pem(), &KEY_ACTIVE)
            .await;
        let (_endpoint, entry) = handshake(&mut stream).await;
        assert_eq!(entry.entry_id, ENTRY_ID);
        ping_pong(&mut stream).await;
        drop(stream);
        running.stop().await;
    }

    #[tokio::test]
    async fn an_expired_lease_is_answered_at_hello_whatever_the_standing() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        // Expired by the time any endpoint can say `hello`.
        let running = Running::start_with_lease(material, Duration::from_millis(1)).await;
        running
            .apply(
                &full(
                    1,
                    vec![entry(1, endpoint_spki(&KEY_ACTIVE), EntryState::Active)],
                ),
                ENTRY_ID,
            )
            .await
            .expect("the full list applies");
        for key in [KEY_ACTIVE, KEY_UNLISTED] {
            let mut stream = running.connect_with_key(node.ca.root.pem(), &key).await;
            let (_endpoint, hello) = hello(ENTRY_ID);
            send(&mut stream, &hello).await;
            assert_closed_with(&mut stream, TelemetryError::LeaseExpired).await;
        }
        running.stop().await;
    }

    #[tokio::test]
    async fn a_list_change_tells_and_closes_the_connections_it_changes() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, None).await;
        running
            .apply(
                &full(
                    1,
                    vec![
                        entry(1, endpoint_spki(&KEY_SUSPENDED), EntryState::Active),
                        entry(2, endpoint_spki(&KEY_UNLISTED), EntryState::Active),
                        entry(3, endpoint_spki(&KEY_OTHER), EntryState::Active),
                        entry(4, endpoint_spki(&KEY_ACTIVE), EntryState::Active),
                    ],
                ),
                ENTRY_ID,
            )
            .await
            .expect("the full list applies");
        let mut streams = Vec::new();
        for key in [KEY_SUSPENDED, KEY_UNLISTED, KEY_OTHER, KEY_ACTIVE] {
            let mut stream = running.connect_with_key(node.ca.root.pem(), &key).await;
            handshake(&mut stream).await;
            streams.push(stream);
        }
        let [mut to_suspend, mut to_remove, mut to_reassign, mut kept] =
            <[EndpointStream; 4]>::try_from(streams).expect("four connections");

        running
            .apply(
                &diff(
                    1,
                    2,
                    vec![
                        entry(1, endpoint_spki(&KEY_SUSPENDED), suspended()),
                        entry(9, endpoint_spki(&KEY_OTHER), EntryState::Active),
                    ],
                    vec![2, 3],
                ),
                ENTRY_ID,
            )
            .await
            .expect("the diff applies");
        // The answer came after the three closed connections stopped.
        assert_eq!(running.list.registered(), (1, 1));

        assert_closed_with(&mut to_suspend, TelemetryError::Suspended).await;
        assert_closed_with(&mut to_remove, TelemetryError::NotListed).await;
        assert!(
            frames_until_closed(&mut to_reassign).await.is_empty(),
            "an entry given to another endpoint closes without an error"
        );
        ping_pong(&mut kept).await;
        drop(kept);
        running.stop().await;
    }

    #[tokio::test]
    async fn a_connection_built_before_its_entry_id_is_closed_at_hello() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, None).await;
        let entries = vec![entry(1, endpoint_spki(&ENDPOINT_SEED), EntryState::Active)];

        // The TLS handshake completes before the first full list.
        let mut early = running.connect(node.ca.root.pem()).await;
        running.wait_opened(1).await;
        running
            .apply(&full(1, entries.clone()), ENTRY_ID)
            .await
            .expect("the full list applies");
        let (_endpoint, hello_frame) = hello(Uuid::nil());
        send(&mut early, &hello_frame).await;
        assert!(
            read_until_closed(&mut early).await.is_empty(),
            "a connection built with no entry_id is closed with nothing sent"
        );
        let mut again = running.connect(node.ca.root.pem()).await;
        assert_eq!(handshake(&mut again).await.1.entry_id, ENTRY_ID);

        // The TLS handshake completes before the entry_id changes; the
        // change closes the established one.
        let mut before_change = running.connect(node.ca.root.pem()).await;
        running.wait_opened(3).await;
        running
            .apply(&full(2, entries), other_entry_id())
            .await
            .expect("the full list applies");
        assert_eq!(read_until_closed(&mut again).await, Vec::<u8>::new());
        let (_endpoint, hello_frame) = hello(ENTRY_ID);
        send(&mut before_change, &hello_frame).await;
        assert!(
            read_until_closed(&mut before_change).await.is_empty(),
            "a connection built with a superseded entry_id is closed with nothing sent"
        );
        let mut current = running.connect(node.ca.root.pem()).await;
        let (_endpoint, entry) = handshake_expecting(&mut current, other_entry_id()).await;
        assert_eq!(entry.entry_id, other_entry_id());
        running.stop().await;
    }

    #[tokio::test]
    async fn a_new_entry_id_closes_every_connection_and_reconnects_see_it() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, None).await;
        let entries = vec![
            entry(1, endpoint_spki(&KEY_ACTIVE), EntryState::Active),
            entry(2, endpoint_spki(&KEY_OTHER), EntryState::Active),
        ];
        running
            .apply(&full(1, entries.clone()), ENTRY_ID)
            .await
            .expect("the full list applies");
        let mut first = running
            .connect_with_key(node.ca.root.pem(), &KEY_ACTIVE)
            .await;
        handshake(&mut first).await;
        let mut second = running
            .connect_with_key(node.ca.root.pem(), &KEY_OTHER)
            .await;
        handshake(&mut second).await;

        running
            .apply(&full(2, entries), other_entry_id())
            .await
            .expect("the full list applies");
        assert_eq!(running.list.registered(), (0, 0));
        assert_eq!(read_until_closed(&mut first).await, Vec::<u8>::new());
        assert_eq!(read_until_closed(&mut second).await, Vec::<u8>::new());

        let mut again = running
            .connect_with_key(node.ca.root.pem(), &KEY_ACTIVE)
            .await;
        let (_endpoint, entry) = handshake_expecting(&mut again, other_entry_id()).await;
        assert_eq!(entry.entry_id, other_entry_id());
        running.stop().await;
    }

    #[tokio::test]
    async fn the_receive_limit_rises_once_the_hello_is_admitted() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;
        let over_limit = usize::try_from(SERVER_OTHER_RECEIVE_LIMIT).unwrap() + 1;

        // A `hello` over the limit, which would be answered if it were taken.
        let mut stream = running.connect(node.ca.root.pem()).await;
        let large_hello = Frame::from_message(&Hello {
            crate_version: "0".repeat(over_limit),
            versions: VersionRange::new(PROTOCOL_VERSION, PROTOCOL_VERSION),
            sent_at: Timestamp::now(),
        })
        .expect("encode the hello");
        send(&mut stream, &large_hello).await;
        assert!(
            read_until_closed(&mut stream).await.is_empty(),
            "before admission a frame over the limit closes the connection"
        );

        let mut stream = running.connect(node.ca.root.pem()).await;
        handshake(&mut stream).await;
        let bulky = Frame::from_message(&Bulky {
            padding: "0".repeat(over_limit),
        })
        .expect("encode the bulky frame");
        send(&mut stream, &bulky).await;
        let mut decoder = FrameDecoder::new(ENDPOINT_RECEIVE_LIMIT);
        let mut buf = vec![0_u8; READ_BUFFER_SIZE];
        let payload = loop {
            if let Some(payload) = decoder.next_frame().expect("a frame within the limit") {
                break payload;
            }
            let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut buf))
                .await
                .expect("the refusal arrives in time")
                .expect("read the refusal");
            assert_ne!(
                n, 0,
                "the connection was closed instead of refusing the frame"
            );
            decoder.push(&buf[..n]);
        };
        let envelope = Envelope::parse(&payload).expect("an envelope");
        assert_eq!(envelope.t(), Unsupported::T);
        let refusal: Unsupported = envelope.body().decode().expect("decode the refusal");
        assert_eq!(refusal.kind, Bulky::T);
        ping_pong(&mut stream).await;
        running.stop().await;
    }

    /// Reads `stream` until it ends, and returns the kind and payload of
    /// every whole frame on it, then the bytes left over, which no whole
    /// frame holds.
    async fn frames_of<R: AsyncRead + Unpin>(stream: &mut R) -> (Vec<(String, Vec<u8>)>, usize) {
        let mut received = Vec::new();
        tokio::time::timeout(IO_TIMEOUT, stream.read_to_end(&mut received))
            .await
            .expect("the stream ends in time")
            .expect("read the stream");
        let mut decoder = FrameDecoder::new(ENDPOINT_RECEIVE_LIMIT);
        decoder.push(&received);
        let mut frames = Vec::new();
        let mut taken = 0;
        while let Some(payload) = decoder.next_frame().expect("a frame within the limit") {
            taken += 4 + payload.len();
            let envelope = Envelope::parse(&payload).expect("an envelope");
            frames.push((envelope.t().to_owned(), payload));
        }
        (frames, received.len() - taken)
    }

    /// Reads from `stream` until a whole frame is in, and returns its kind
    /// and payload.
    async fn next_frame_of<R: AsyncRead + Unpin>(
        stream: &mut R,
        decoder: &mut FrameDecoder,
    ) -> (String, Vec<u8>) {
        let mut buf = vec![0_u8; READ_BUFFER_SIZE];
        loop {
            if let Some(payload) = decoder.next_frame().expect("a frame within the limit") {
                let envelope = Envelope::parse(&payload).expect("an envelope");
                return (envelope.t().to_owned(), payload);
            }
            let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut buf))
                .await
                .expect("a frame arrives in time")
                .expect("read a frame");
            assert_ne!(n, 0, "the stream ended before a whole frame");
            decoder.push(&buf[..n]);
        }
    }

    /// A frame over the limit taken before admission, which arrives in the
    /// same read as the `hello` that admits the connection, is decoded
    /// under the limit the admission sets, as it would be in a read of its
    /// own.
    #[tokio::test]
    async fn a_frame_read_with_the_admitting_hello_takes_the_raised_limit() {
        let over_limit = usize::try_from(SERVER_OTHER_RECEIVE_LIMIT).unwrap() + 1;
        let (_endpoint, hello) = hello(ENTRY_ID);
        let bulky = Frame::from_message(&Bulky {
            padding: "0".repeat(over_limit),
        })
        .expect("encode the bulky frame");
        let mut both = hello.as_bytes().to_vec();
        both.extend_from_slice(bulky.as_bytes());
        // `both` is written whole before the entry reads, so the entry's
        // first read holds the `hello` and the bulky frame's length prefix.
        let capacity = usize::try_from(SERVER_ACTIVE_RECEIVE_LIMIT).unwrap();
        let (mut endpoint_side, mut entry_side) = tokio::io::duplex(capacity);
        endpoint_side
            .write_all(&both)
            .await
            .expect("write the hello and the bulky frame");

        let token = CancellationToken::new();
        let channel = ServerChannel::Telemetry {
            entry_id: ENTRY_ID,
            accepted_kinds: Vec::new(),
        };
        let config = ServerConfig::new(channel, Standing::Unready.receive_limit());
        let db_dir = tempfile::tempdir().expect("tempdir");
        let database =
            Database::open(db_dir.path(), &DbOptions::default()).expect("open the database");
        let mut session = Session::for_test(&database);
        let serving = tokio::spawn({
            let token = token.clone();
            async move {
                let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
                serve(&mut entry_side, remote, config, &token, &mut session).await
            }
        });

        let mut decoder = FrameDecoder::new(ENDPOINT_RECEIVE_LIMIT);
        let (kind, _) = next_frame_of(&mut endpoint_side, &mut decoder).await;
        assert_eq!(kind, HelloAck::T);
        let (kind, payload) = next_frame_of(&mut endpoint_side, &mut decoder).await;
        assert_eq!(
            kind,
            Unsupported::T,
            "the bulky frame is refused, not fatal"
        );
        let envelope = Envelope::parse(&payload).expect("an envelope");
        let refusal: Unsupported = envelope.body().decode().expect("decode the refusal");
        assert_eq!(refusal.kind, Bulky::T);

        let ping = Frame::from_message(&Ping {
            sent_at: Timestamp::now(),
        })
        .expect("encode a ping");
        endpoint_side
            .write_all(ping.as_bytes())
            .await
            .expect("send a ping");
        let (kind, _) = next_frame_of(&mut endpoint_side, &mut decoder).await;
        assert_eq!(kind, Pong::T, "the connection stays open");

        token.cancel();
        let ended = serving.await.expect("the connection task joins");
        assert_eq!(ended, Ended::Stopped { unsent: Vec::new() });
    }

    /// A list change that stops a connection while the entry is writing to
    /// it, here a `hello_ack` the endpoint has not read yet, still tells it
    /// its new standing: the rest of the frame goes out first, then the error.
    /// The update answers without waiting for those writes.
    #[tokio::test]
    async fn a_list_change_during_a_write_finishes_the_frame_then_sends_the_error() {
        let (_endpoint, hello) = hello(ENTRY_ID);
        stop_while_writing_the_reply_to(&hello, HelloAck::T).await;
    }

    /// The same holds for a frame the entry closes the connection after: a
    /// listed endpoint is admitted, and so registered, before its `hello`'s
    /// versions are compared, and stays registered while the version
    /// refusal goes out.
    #[tokio::test]
    async fn a_list_change_during_a_version_refusal_finishes_it_then_sends_the_error() {
        let next = PROTOCOL_VERSION + 1;
        let hello = Frame::from_message(&Hello {
            crate_version: "0.1.0".to_owned(),
            versions: VersionRange::new(next, next),
            sent_at: Timestamp::now(),
        })
        .expect("encode the hello");
        stop_while_writing_the_reply_to(&hello, Unsupported::T).await;
    }

    /// Sends `hello` from a listed endpoint over a pipe narrower than any
    /// frame, suspends the endpoint's entry while the entry is writing its
    /// reply, of kind `reply`, and checks that the endpoint receives the
    /// whole reply, then `suspended`, and nothing cut short.
    async fn stop_while_writing_the_reply_to(hello: &Frame, reply: &str) {
        // Narrower than any frame, so every write waits for the endpoint to
        // read.
        const PIPE_CAPACITY: usize = 16;

        let db_dir = tempfile::tempdir().expect("tempdir");
        let database =
            Database::open(db_dir.path(), &DbOptions::default()).expect("open the database");
        let list = Arc::new(EndpointList::new(DEFAULT_LEASE_LENGTH));
        list.load_entry_id(&database);
        let flows = Arc::new(EndpointFlows::new(database.clone()));
        let entries = vec![entry(1, KEY_ACTIVE, EntryState::Active)];
        list.apply(&encode(&full(1, entries)), &ENTRY_ID.to_string(), &flows)
            .await
            .expect("the full list applies");

        let (mut endpoint_side, mut entry_side) = tokio::io::duplex(PIPE_CAPACITY);
        let token = CancellationToken::new();
        let running = tokio::spawn({
            let entry = Entry::for_test(&list, &database, &flows);
            let token = token.clone();
            async move {
                let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
                run_admitted_by_list(&mut entry_side, remote, KEY_ACTIVE, entry, &token).await;
            }
        });
        endpoint_side
            .write_all(hello.as_bytes())
            .await
            .expect("send the hello");
        // Admitted, and so writing its reply, which the endpoint does not
        // read until the update has answered.
        tokio::time::timeout(IO_TIMEOUT, async {
            while list.registered() != (1, 1) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the hello is admitted in time");

        list.apply(
            &encode(&diff(1, 2, vec![entry(1, KEY_ACTIVE, suspended())], vec![])),
            &ENTRY_ID.to_string(),
            &flows,
        )
        .await
        .expect("the diff applies");
        assert_eq!(list.registered(), (0, 0));

        let (frames, left_over) = frames_of(&mut endpoint_side).await;
        let kinds: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(kinds, [reply, ErrorMessage::T]);
        assert_eq!(left_over, 0, "no frame is cut short");
        let (_, payload) = frames.last().expect("the error frame");
        let mut whole_frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        whole_frame.extend_from_slice(payload);
        assert_eq!(error_of(&whole_frame), TelemetryError::Suspended);
        running.await.expect("the connection task joins");
    }

    #[tokio::test]
    async fn a_second_connection_with_the_same_key_closes_the_first_silently() {
        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start(material, Some(ENTRY_ID)).await;
        let mut first = running.connect(node.ca.root.pem()).await;
        handshake(&mut first).await;
        let mut second = running.connect(node.ca.root.pem()).await;
        handshake(&mut second).await;
        assert!(
            read_until_closed(&mut first).await.is_empty(),
            "a replaced connection is closed without an error"
        );
        ping_pong(&mut second).await;
        assert_eq!(running.list.registered(), (1, 1));
        running.stop().await;
    }

    /// With no confirmation, the lease timer alone closes an open connection
    /// with `lease_expired`.
    #[tokio::test(start_paused = true)]
    async fn the_lease_timer_closes_open_connections_with_lease_expired() {
        const LEASE: Duration = Duration::from_secs(30);

        let node = Node::new();
        let material = node.material(&node.cert, &node.ca.bundle_pem());
        let running = Running::start_with_lease(material, LEASE).await;
        running
            .apply(
                &full(
                    1,
                    vec![entry(1, endpoint_spki(&ENDPOINT_SEED), EntryState::Active)],
                ),
                ENTRY_ID,
            )
            .await
            .expect("the full list applies");
        let addr = running.addr;
        let config = endpoint_client_config_trusting(&[node.ca.root.pem()]);
        let endpoint = tokio::task::spawn_blocking(move || {
            let mut endpoint = BlockingEndpoint::connect(addr, config);
            let (_endpoint, hello) = hello(ENTRY_ID);
            endpoint.send(&hello);
            let ack = endpoint.next_kind();
            (endpoint, ack)
        });
        let (endpoint, ack) = endpoint.await.expect("the endpoint's thread joins");
        assert_eq!(ack.as_deref(), Some(HelloAck::T));

        tokio::time::advance(LEASE).await;
        let kinds = tokio::task::spawn_blocking(move || {
            let mut endpoint = endpoint;
            (endpoint.next_kind(), endpoint.next_kind())
        })
        .await
        .expect("the endpoint's thread joins");
        assert_eq!(kinds, (Some(ErrorMessage::T.to_owned()), None));
        running.stop().await;
    }
}
