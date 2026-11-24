//! The endpoint entry: the port Clumit Endpoint sends host telemetry to.
//!
//! The entry is separate from the module ports in both code path and client
//! verification. It is TCP with TLS 1.3, configured by
//! [`endpoint_server_config`], and each connection runs senta-protocol's
//! [`ServerConnection`], which does the framing, the `hello` handshake and
//! liveness; this module feeds it bytes and times and carries out what it
//! asks for.
//!
//! The node accepts telemetry only once it has an `entry_id`. Until then it is
//! [`Standing::Unready`], and every connection is closed without anything sent
//! back. Nothing in this release gives the node an `entry_id`, so in
//! production every connection is closed that way.
//!
//! Once ready, the entry announces in its `hello_ack` the record kinds it
//! accepts: exactly those [`convert`] turns into Giganto structs.

mod convert;

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use anyhow::{Context, Result};
use jiff::Timestamp;
use senta_protocol::{
    auth::{
        active_list::{Standing, allowed},
        tls::{TELEMETRY_ALPN, alpn_matches},
    },
    connection::{
        ConnectionKind, IDLE_TIMEOUT, ServerAction, ServerChannel, ServerConfig, ServerConnection,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    sync::watch,
    time::Instant,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    cancellation::{TaskTracker, drain_with_report},
    server::endpoint_server_config,
    tls_reload::{TlsMaterial, TlsWatch},
};

/// Names the endpoint entry's tracker in the drain progress log.
const ENDPOINT_DRAIN_LABEL: &str = "endpoint";

/// The size of the buffer each connection reads into.
const READ_BUFFER_SIZE: usize = 16 * 1024;

/// How long closing a connection may spend writing what is left to write, the
/// frames the protocol sent before it closed and then TLS `close_notify`,
/// before the connection is dropped without them, as it is to a peer that has
/// stopped reading.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// The `entry_id` the node holds, or `None` until it has one.
///
/// The entry reads it as each connection starts. Nothing in this release
/// sends a value into it.
pub(crate) type EntryReadiness = watch::Receiver<Option<Uuid>>;

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

/// The endpoint entry before its listener is bound.
pub(crate) struct Server {
    address: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    endpoint_tls: Arc<EndpointTls>,
    readiness: EntryReadiness,
}

/// The endpoint entry with its listener bound.
pub(crate) struct BoundServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    endpoint_tls: Arc<EndpointTls>,
    readiness: EntryReadiness,
}

impl Server {
    /// Creates the entry at `address`, serving `tls_config` until a TLS
    /// reload replaces it through `endpoint_tls`.
    pub(crate) fn new(
        address: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
        endpoint_tls: Arc<EndpointTls>,
        readiness: EntryReadiness,
    ) -> Self {
        Self {
            address,
            tls_config,
            endpoint_tls,
            readiness,
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
            readiness: self.readiness,
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
    /// connection task it started.
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
            readiness,
        } = self;
        info!("Endpoint entry listening on {local_addr}");

        let tracker = TaskTracker::with_token(token.clone());
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
                    let entry_id = *readiness.borrow();
                    let spawned = tracker.spawn(
                        format!("endpoint-conn-{remote}"),
                        move |token| handle_connection(stream, remote, acceptor, entry_id, token),
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

/// Runs one endpoint connection: the TLS handshake, bounded by
/// [`IDLE_TIMEOUT`], the ALPN check, then the protocol until either side
/// closes or `token` is cancelled.
async fn handle_connection(
    stream: TcpStream,
    remote: SocketAddr,
    acceptor: TlsAcceptor,
    entry_id: Option<Uuid>,
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

    serve(&mut tls, remote, entry_id, &token).await;
    close(&mut tls, &token).await;
}

/// Builds the connection's protocol configuration from the node's readiness.
///
/// While the node has no `entry_id` its standing is [`Standing::Unready`],
/// which closes the connection on its first message, before any `hello_ack`
/// could carry the nil `entry_id` put here. Once it has one, every endpoint
/// is [`Standing::Active`]: no list narrows that down yet. The entry accepts
/// the kinds of [`convert::ACCEPTED_KINDS`], each at schema version 1.
fn server_config(entry_id: Option<Uuid>) -> ServerConfig {
    let standing = if entry_id.is_some() {
        Standing::Active
    } else {
        Standing::Unready
    };
    let channel = ServerChannel::Telemetry {
        entry_id: entry_id.unwrap_or_else(Uuid::nil),
        accepted_kinds: convert::accepted_kinds(),
    };
    let receive_limit = standing.receive_limit();
    ServerConfig::new(channel, receive_limit).with_standing(move |t| {
        allowed(&standing, ConnectionKind::Telemetry, t).to_standing_verdict()
    })
}

/// Runs the protocol on an established TLS stream until the connection
/// closes or `token` is cancelled.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut S,
    remote: SocketAddr,
    entry_id: Option<Uuid>,
    token: &CancellationToken,
) {
    let origin = Instant::now();
    let mut connection = ServerConnection::new(server_config(entry_id), Duration::ZERO);
    let mut buf = vec![0_u8; READ_BUFFER_SIZE];

    while let Some(deadline) = connection.next_deadline() {
        // Every branch is cancel safe: a read that loses the race has
        // consumed nothing, the TLS layer keeping what it decrypted.
        let mut actions: VecDeque<ServerAction> = select! {
            biased;
            () = token.cancelled() => return,
            () = tokio::time::sleep_until(origin + deadline) => {
                connection.poll(Timestamp::now(), origin.elapsed()).into_iter().collect()
            }
            read = tls.read(&mut buf) => match read {
                Ok(0) => {
                    debug!("Endpoint connection from {remote} closed by the peer");
                    return;
                }
                // A read never reports more bytes than the buffer holds.
                Ok(n) => connection
                    .receive(buf.get(..n).unwrap_or_default(), Timestamp::now(), origin.elapsed())
                    .into(),
                Err(e) => {
                    debug!("Endpoint connection from {remote} failed to read: {e}");
                    return;
                }
            },
        };
        while let Some(action) = actions.pop_front() {
            match action {
                ServerAction::Handshake(handshake) => info!(
                    "Endpoint connection from {remote} established, protocol version {}, \
                     endpoint crate version {}",
                    handshake.version, handshake.hello.crate_version
                ),
                ServerAction::Send(frame) => {
                    let mut liveness = Liveness {
                        connection: &mut connection,
                        origin,
                        due: &mut actions,
                    };
                    if !send(tls, frame.as_bytes(), &mut liveness, remote, token).await {
                        return;
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
                    send(tls, frame.as_bytes(), &mut liveness, remote, token).await;
                    return;
                }
                ServerAction::Close(reason) => {
                    debug!("Endpoint connection from {remote} closed: {reason}");
                    return;
                }
                ServerAction::Unsupported(unsupported) => debug!(
                    "Endpoint connection from {remote} refused {:?}",
                    unsupported.kind
                ),
                // No message kind of this entry's own is registered, so the
                // helper answers every other `t` with `unsupported` and never
                // delivers one. Should it, the body cannot be handled here.
                ServerAction::Deliver(envelope) => {
                    let reason = connection.reject_body();
                    debug!(
                        "Endpoint connection from {remote} delivered unhandled {:?}: {reason:?}",
                        envelope.t()
                    );
                    return;
                }
            }
        }
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

/// Writes `bytes` to `tls`, or gives up when liveness closes the connection
/// or `token` is cancelled. Returns whether every byte was written.
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
) -> bool {
    let write = async {
        tls.write_all(bytes).await?;
        tls.flush().await
    };
    tokio::pin!(write);
    let mut closing_until = None;
    loop {
        let deadline = liveness.connection.next_deadline();
        let wake = match deadline {
            Some(deadline) => liveness.origin + deadline,
            None => *closing_until.get_or_insert_with(|| Instant::now() + CLOSE_TIMEOUT),
        };
        // `write_all` is not cancel safe, but the branches that cancel it,
        // shutdown, a liveness close and the bound on a closed connection,
        // close the connection anyway. The write is pinned outside the loop,
        // so a liveness `ping` does not cancel it.
        select! {
            biased;
            () = token.cancelled() => return false,
            written = &mut write => {
                return written
                    .inspect_err(|e| debug!("Endpoint connection from {remote}: send failed: {e}"))
                    .is_ok();
            }
            () = tokio::time::sleep_until(wake) => {
                if deadline.is_none() {
                    debug!(
                        "Endpoint connection from {remote}: the frames left after closing were \
                         not written within {CLOSE_TIMEOUT:?}"
                    );
                    return false;
                }
                match liveness.connection.poll(Timestamp::now(), liveness.origin.elapsed()) {
                    Some(ServerAction::Close(reason)) => {
                        debug!("Endpoint connection from {remote} closed: {reason}");
                        return false;
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
mod tests {
    use std::{
        net::Ipv4Addr,
        pin::Pin,
        task::{Context as TaskContext, Poll},
    };

    use senta_protocol::{
        auth::tls::CONTROL_ALPN,
        connection::{
            AcceptedKind, ENDPOINT_RECEIVE_LIMIT, EndpointAction, EndpointChannel, EndpointConfig,
            EndpointConnection, Envelope, Frame, FrameDecoder, Hello, HelloAck, Message,
            PING_INTERVAL, PROTOCOL_VERSION, Ping, Pong, SERVER_ACTIVE_RECEIVE_LIMIT,
            TelemetryEntry, Unsupported, VersionRange,
        },
    };
    use tempfile::TempDir;
    use tokio::{io::ReadBuf, task::JoinHandle};

    use super::*;
    use crate::{
        test_bootroot::{
            CaGeneration, NodeCert, capture_logs, endpoint_client_config_over,
            endpoint_client_config_trusting, endpoint_connect, init_crypto, presented_chain,
            wait_for_log, write_node_files, x25519_only_provider,
        },
        tls_reload::{load_tls_material, test_tls_watch},
    };

    const NODE: &str = "001.giganto.node1.example.test";
    const ENTRY_ID: Uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
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
    }

    impl Running {
        async fn start(material: Arc<TlsMaterial>, entry_id: Option<Uuid>) -> Self {
            let endpoint_tls = Arc::new(EndpointTls::default());
            let tls_config = endpoint_tls
                .build(&material)
                .expect("the endpoint TLS configuration is built");
            let (tls_tx, tls_watch) = test_tls_watch(material);
            let (_readiness_tx, readiness) = watch::channel(entry_id);
            let server = Server::new(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                tls_config,
                endpoint_tls,
                readiness,
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
            }
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
            tokio::time::timeout(
                IO_TIMEOUT,
                endpoint_connect(
                    self.addr,
                    endpoint_client_config_trusting(&[root_pem]),
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
        let (mut endpoint, hello) = hello(ENTRY_ID);
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

        let started = Instant::now();
        let served = tokio::time::timeout(
            IDLE_TIMEOUT,
            serve(
                &mut stream,
                remote,
                Some(ENTRY_ID),
                &CancellationToken::new(),
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
}
