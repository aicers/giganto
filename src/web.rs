use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll, ready},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use async_graphql::{
    Executor,
    http::{GraphQLPlaygroundConfig, playground_source},
};
use async_graphql_poem::GraphQL;
use poem::{
    Response, Route, Server,
    endpoint::make_sync,
    http::uri::Scheme,
    listener::{Acceptor, Listener, TcpAcceptor, TcpListener},
    web::{LocalAddr, RemoteAddr},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::oneshot,
    task::{self, JoinHandle},
    time::{MissedTickBehavior, interval},
};
use tokio_rustls::{Accept, TlsAcceptor, server::TlsStream};
use tracing::{info, warn};

use crate::server::{Certs, graphql_server_config};

/// How often [`WebController::shutdown`] reports that web shutdown is still
/// pending while it waits for the web task to finish.
///
/// Reporting is diagnostic only: it never shortens the wait and never aborts
/// the task. The task is bounded instead by the graceful-shutdown timeout
/// handed to [`serve`], which caps how long an already-accepted in-flight
/// request may keep the server running.
const SHUTDOWN_REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// Lifecycle handle for a running HTTPS GraphQL server.
///
/// Allows callers to initiate a graceful shutdown and wait for the
/// underlying task to finish, so that reload flows can observe
/// shutdown completion before starting a replacement server.
pub struct WebController {
    shutdown_tx: oneshot::Sender<()>,
    handle: JoinHandle<()>,
}

impl WebController {
    /// Initiates graceful shutdown and awaits the web task's completion.
    ///
    /// While the web task winds down, this reports the still-pending shutdown
    /// on [`SHUTDOWN_REPORT_INTERVAL`] rather than aborting the task: web
    /// shutdown is cooperative, so an accepted in-flight request is allowed to
    /// finish, bounded only by the graceful-shutdown timeout given to
    /// [`serve`]. That timeout is what guarantees this returns — and thus that
    /// subsystem cancellation and drain can proceed — even if a request is
    /// stuck, so the task is never force-aborted here.
    ///
    /// # Errors
    ///
    /// Returns an error if the spawned task failed to join (e.g. it
    /// panicked or was aborted).
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        await_with_pending_reports(self.handle, SHUTDOWN_REPORT_INTERVAL).await
    }
}

/// Awaits the web task, reporting that shutdown is still pending on
/// `report_interval` until it finishes.
///
/// Split out from [`WebController::shutdown`] so the reporting loop can be
/// driven with a short interval in tests without a real server. It never aborts
/// the handle: the task's runtime is bounded by the graceful-shutdown timeout
/// baked into the server, and this only observes and reports.
async fn await_with_pending_reports(
    mut handle: JoinHandle<()>,
    report_interval: Duration,
) -> Result<()> {
    let mut ticker = interval(report_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Consume the immediate first tick so the first report only fires after a
    // full interval of the shutdown remaining pending.
    ticker.tick().await;
    loop {
        tokio::select! {
            joined = &mut handle => {
                return joined.map_err(|e| anyhow!("web task join error: {e}"));
            }
            _ = ticker.tick() => {
                info!(
                    "web server shutdown still pending; waiting for in-flight requests to \
                     finish (bounded by the graceful-shutdown timeout)"
                );
            }
        }
    }
}

/// Starts the GraphQL server with mTLS client authentication.
///
/// The listener is bound eagerly so bind failures surface as errors
/// before the spawned task begins accepting connections.
///
/// # Arguments
///
/// * `schema` - The GraphQL schema executor
/// * `addr` - The socket address to bind to
/// * `certs` - The server certificate chain, its private key, and the root
///   store client certificates are verified against. Callers pass the
///   already-validated material produced by the common TLS reload path, the
///   same material the QUIC servers use; this function does not re-read
///   anything from disk, so restart consumes the validated state without
///   reopening a TOCTOU window.
/// * `shutdown_timeout` - Graceful-shutdown budget applied to in-flight
///   requests once shutdown begins. After the signal is raised the server
///   stops accepting new connections and waits up to this duration for
///   already-accepted requests to finish before terminating them, so a stuck
///   request cannot block the caller — and therefore subsystem cancellation
///   and drain — indefinitely.
///
/// # Errors
///
/// Returns an error if the TLS configuration cannot be built from `certs`,
/// or if the listener cannot bind to `addr`.
pub async fn serve<S: Executor>(
    schema: S,
    addr: SocketAddr,
    certs: Arc<Certs>,
    shutdown_timeout: Duration,
) -> Result<WebController> {
    let graphql = GraphQL::new(schema);

    let playground = make_sync(move |_| {
        Response::builder()
            .content_type("text/html")
            .body(playground_source(GraphQLPlaygroundConfig::new("/graphql")))
    });

    let home = make_sync(move |_| Response::builder().body(""));

    let app = Route::new()
        .at("/graphql", graphql)
        .at("/graphql/playground", playground)
        .at("/", home);

    let tls_config =
        graphql_server_config(&certs).context("failed to build GraphQL TLS configuration")?;

    // Bind eagerly so the caller observes bind failures before the
    // background task is spawned.
    let tcp = TcpListener::bind(addr)
        .into_acceptor()
        .await
        .with_context(|| format!("failed to bind HTTPS listener on {addr}"))?;
    let acceptor = GraphqlTlsAcceptor {
        inner: tcp,
        tls: TlsAcceptor::from(tls_config),
    };

    info!("GraphQL web server is starting on https://{addr:?} with mTLS enabled");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = task::spawn(async move {
        let server = Server::new_with_acceptor(acceptor).run_with_graceful_shutdown(
            app,
            async move {
                let _ = shutdown_rx.await;
            },
            Some(shutdown_timeout),
        );

        if let Err(e) = server.await {
            tracing::error!("Server error: {e}");
        }
    });

    Ok(WebController {
        shutdown_tx,
        handle,
    })
}

/// The TLS acceptor of the GraphQL HTTPS server.
///
/// It stands in for poem's `RustlsAcceptor`, which builds its configuration
/// from the process default and reports a failed handshake only to the
/// connection, whose result poem discards. This one serves
/// [`graphql_server_config`] and logs every failed handshake.
struct GraphqlTlsAcceptor {
    inner: TcpAcceptor,
    tls: TlsAcceptor,
}

impl Acceptor for GraphqlTlsAcceptor {
    type Io = GraphqlTlsStream;

    fn local_addr(&self) -> Vec<LocalAddr> {
        self.inner.local_addr()
    }

    /// Returns as soon as a TCP connection is accepted. The handshake runs
    /// on the connection's first poll, so a slow client cannot stall the
    /// accept loop.
    async fn accept(&mut self) -> io::Result<(Self::Io, LocalAddr, RemoteAddr, Scheme)> {
        let (stream, local_addr, remote_addr, _) = self.inner.accept().await?;
        let peer = *remote_addr
            .as_socket_addr()
            .ok_or_else(|| io::Error::other("TCP acceptor returned a non-socket peer address"))?;
        let io = GraphqlTlsStream {
            state: HandshakeState::Handshaking(self.tls.accept(stream)),
            peer,
        };
        Ok((io, local_addr, remote_addr, Scheme::HTTPS))
    }
}

enum HandshakeState {
    Handshaking(Accept<TcpStream>),
    Ready(TlsStream<TcpStream>),
    Failed,
}

/// A GraphQL connection that drives its TLS handshake on the first read,
/// write, flush or shutdown poll.
struct GraphqlTlsStream {
    state: HandshakeState,
    peer: SocketAddr,
}

impl GraphqlTlsStream {
    /// Completes the handshake if it is still running, then returns the TLS
    /// stream. The first failure is logged and returned; every later poll
    /// returns an error without logging again.
    fn poll_stream(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<Pin<&mut TlsStream<TcpStream>>>> {
        if let HandshakeState::Handshaking(accept) = &mut self.state {
            match ready!(Pin::new(accept).poll(cx)) {
                Ok(stream) => self.state = HandshakeState::Ready(stream),
                Err(error) => {
                    warn!("TLS handshake from {} failed: {error}", self.peer);
                    self.state = HandshakeState::Failed;
                    return Poll::Ready(Err(error));
                }
            }
        }
        match &mut self.state {
            HandshakeState::Ready(stream) => Poll::Ready(Ok(Pin::new(stream))),
            HandshakeState::Handshaking(_) | HandshakeState::Failed => Poll::Ready(Err(
                io::Error::new(io::ErrorKind::InvalidData, "TLS handshake failed"),
            )),
        }
    }
}

impl AsyncRead for GraphqlTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.get_mut().poll_stream(cx))?.poll_read(cx, buf)
    }
}

impl AsyncWrite for GraphqlTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.get_mut().poll_stream(cx))?.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        ready!(self.get_mut().poll_stream(cx))?.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        ready!(self.get_mut().poll_stream(cx))?.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{Arc, Once},
        time::Duration,
    };

    use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema};
    use tempfile::tempdir;
    use tokio::{net::TcpListener as TokioTcpListener, time::sleep};

    use super::*;
    use crate::test_bootroot::{
        TlsClientBuilder, assert_tls_refused_with_one_warning, capture_logs, tls_handshake,
        x25519_only_tls_client,
    };

    static INSTALL_PROVIDER: Once = Once::new();

    fn install_crypto_provider() {
        INSTALL_PROVIDER.call_once(|| {
            let _ = crate::server::server_crypto_provider().install_default();
        });
    }

    /// Fires once, the first time the `slow` resolver is entered, so a test can
    /// prove an in-flight request actually reached the resolver before it begins
    /// shutdown — rather than relying on a wall-clock sleep that a slow connect
    /// could outrun.
    #[derive(Clone)]
    struct SlowEntered(std::sync::Arc<tokio::sync::Notify>);

    struct Query;

    #[Object]
    impl Query {
        async fn hello(&self) -> &'static str {
            "world"
        }

        /// Sleeps `millis` before answering, standing in for an in-flight
        /// request that is still running when web shutdown begins.
        ///
        /// If a [`SlowEntered`] signal is present in the schema data, it is
        /// notified on entry so the caller can synchronize on the request
        /// reaching this resolver.
        async fn slow(&self, ctx: &Context<'_>, millis: i32) -> &'static str {
            if let Ok(entered) = ctx.data::<SlowEntered>() {
                entered.0.notify_one();
            }
            let millis = u64::try_from(millis).unwrap_or(0);
            sleep(Duration::from_millis(millis)).await;
            "slept"
        }
    }

    fn test_schema() -> Schema<Query, EmptyMutation, EmptySubscription> {
        Schema::build(Query, EmptyMutation, EmptySubscription).finish()
    }

    /// A schema whose `slow` resolver notifies `entered` on entry.
    fn test_schema_signaling_entry(
        entered: std::sync::Arc<tokio::sync::Notify>,
    ) -> Schema<Query, EmptyMutation, EmptySubscription> {
        Schema::build(Query, EmptyMutation, EmptySubscription)
            .data(SlowEntered(entered))
            .finish()
    }

    /// Builds an mTLS-capable reqwest client that presents the given client
    /// cert/key and trusts only the given CA bytes.
    ///
    /// The test PKI is a single self-signed certificate reused as server cert,
    /// client identity, and CA, so the client cert validates against the CA the
    /// server requires — enough to complete the mTLS handshake `serve` demands.
    fn build_mtls_client(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8]) -> reqwest::Client {
        let identity =
            reqwest::Identity::from_pem(&[cert_pem, key_pem].concat()).expect("identity");
        let ca = reqwest::Certificate::from_pem(ca_pem).expect("ca cert");
        reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(ca)
            .tls_sni(false)
            .danger_accept_invalid_hostnames(true)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("build mTLS client")
    }

    async fn run_query(
        client: &reqwest::Client,
        addr: SocketAddr,
        query: &str,
    ) -> Result<String, reqwest::Error> {
        let url = format!("https://{addr}/graphql");
        let body = format!(r#"{{"query":"{query}"}}"#);
        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;
        resp.error_for_status()?.text().await
    }

    fn write_pki(_dir: &std::path::Path) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate self-signed cert");
        let cert_pem = ck.cert.pem();
        let key_pem = ck.signing_key.serialize_pem();
        let ca_pem = cert_pem.clone();
        (
            cert_pem.into_bytes(),
            key_pem.into_bytes(),
            ca_pem.into_bytes(),
        )
    }

    /// Parses the PEM the test PKI produces into the `Certs` `serve` takes,
    /// the way the TLS reload path does.
    fn certs_from_pem(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8]) -> Arc<Certs> {
        let mut root = rustls::RootCertStore::empty();
        for cert in crate::comm::to_cert_chain(ca_pem).expect("parse CA cert") {
            root.add(cert).expect("add CA cert");
        }
        Arc::new(Certs {
            certs: crate::comm::to_cert_chain(cert_pem).expect("parse cert"),
            key: crate::comm::to_private_key(key_pem).expect("parse key"),
            root,
        })
    }

    fn free_addr() -> SocketAddr {
        // Bind a kernel-assigned port, release it, and return the address.
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
        listener.local_addr().expect("local addr")
    }

    #[tokio::test]
    async fn serve_returns_error_when_bind_fails() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());

        // Hold the port so the HTTPS bind conflicts.
        let blocker = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("hold port");
        let addr = blocker.local_addr().expect("addr");

        let result = serve(
            test_schema(),
            addr,
            certs_from_pem(&cert, &key, &ca),
            Duration::from_secs(30),
        )
        .await;
        assert!(result.is_err(), "bind on occupied port should fail");
    }

    #[tokio::test]
    async fn shutdown_completes_when_requested() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        let controller = serve(
            test_schema(),
            addr,
            certs_from_pem(&cert, &key, &ca),
            Duration::from_secs(30),
        )
        .await
        .expect("serve should start");

        // Give the spawned task a moment to enter its accept loop.
        sleep(Duration::from_millis(50)).await;

        controller.shutdown().await.expect("graceful shutdown");
    }

    #[tokio::test]
    async fn serve_can_rebind_after_shutdown() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        let controller = serve(
            test_schema(),
            addr,
            certs_from_pem(&cert, &key, &ca),
            Duration::from_secs(30),
        )
        .await
        .expect("initial serve");
        sleep(Duration::from_millis(50)).await;
        controller.shutdown().await.expect("shutdown");

        // The same address must be re-bindable after shutdown completes.
        let controller = serve(
            test_schema(),
            addr,
            certs_from_pem(&cert, &key, &ca),
            Duration::from_secs(30),
        )
        .await
        .expect("second serve should rebind");
        controller.shutdown().await.expect("second shutdown");
    }

    #[tokio::test]
    async fn accepted_ordinary_request_finishes_before_timeout() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        // A generous timeout: the accepted request is well within it.
        let controller = serve(
            test_schema(),
            addr,
            certs_from_pem(&cert, &key, &ca),
            Duration::from_secs(10),
        )
        .await
        .expect("serve should start");
        sleep(Duration::from_millis(50)).await;

        // Start an in-flight request, then let it run into the shutdown window.
        let client = build_mtls_client(&cert, &key, &ca);
        let inflight =
            tokio::spawn(async move { run_query(&client, addr, "{ slow(millis: 800) }").await });
        sleep(Duration::from_millis(150)).await;

        // Shutdown waits for the accepted request rather than cutting it off.
        controller.shutdown().await.expect("graceful shutdown");

        let body = inflight
            .await
            .expect("join the in-flight request")
            .expect("an accepted ordinary request must finish before the timeout");
        assert!(
            body.contains("slept"),
            "the in-flight request should have completed normally, got: {body}"
        );
    }

    #[tokio::test]
    async fn new_requests_rejected_after_shutdown_begins() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        let controller = serve(
            test_schema(),
            addr,
            certs_from_pem(&cert, &key, &ca),
            Duration::from_secs(10),
        )
        .await
        .expect("serve should start");
        sleep(Duration::from_millis(50)).await;

        // Confirm the server serves before shutdown begins.
        let client = build_mtls_client(&cert, &key, &ca);
        run_query(&client, addr, "{ hello }")
            .await
            .expect("pre-shutdown request should succeed");

        // Hold the server open with an in-flight request so shutdown is still
        // in progress while we try a new one.
        let hold_client = build_mtls_client(&cert, &key, &ca);
        let hold =
            tokio::spawn(
                async move { run_query(&hold_client, addr, "{ slow(millis: 1500) }").await },
            );
        sleep(Duration::from_millis(150)).await;

        // Begin shutdown; the acceptor stops taking new connections and the
        // server stops admitting new requests.
        let shutdown = tokio::spawn(controller.shutdown());
        sleep(Duration::from_millis(250)).await;

        // A brand-new connection must be refused now that shutdown has begun and
        // the acceptor is closed. Rejection on an *already-established*
        // keep-alive connection — the harder half of "stop new requests, not
        // just new connections" — is proved deterministically over a raw TLS
        // socket in `established_keepalive_connection_rejects_new_request`; a
        // pooled `reqwest::Client` cannot establish that here because it may
        // silently open a fresh connection instead of reusing its idle one.
        let new_client = build_mtls_client(&cert, &key, &ca);
        let rejected = run_query(&new_client, addr, "{ hello }").await;
        assert!(
            rejected.is_err(),
            "a new request on a fresh connection must be rejected once web shutdown has begun"
        );

        let _ = hold.await.expect("join the holding request");
        shutdown
            .await
            .expect("join shutdown")
            .expect("graceful shutdown");
    }

    #[tokio::test]
    async fn stuck_web_request_cutoff_lets_the_top_level_drain_reach_drained() {
        use crate::cancellation::{DrainOutcome, TaskTracker};

        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        // A short timeout so a stuck request is cut off quickly. The schema
        // notifies `entered` when the slow request reaches its resolver, so the
        // test can begin shutdown only once the request is genuinely in-flight.
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let controller = serve(
            test_schema_signaling_entry(std::sync::Arc::clone(&entered)),
            addr,
            certs_from_pem(&cert, &key, &ca),
            Duration::from_millis(300),
        )
        .await
        .expect("serve should start");
        sleep(Duration::from_millis(50)).await;

        // A populated top-level tracker standing in for the per-generation
        // tasks whose drain runs after web shutdown returns, exactly as
        // `shutdown_generation` orders it. Its lone task parks until cancelled,
        // so the drain reaches `Drained` only once it actually runs — which it
        // cannot until web shutdown has stopped blocking on the stuck request.
        let tracker = TaskTracker::new();
        tracker
            .spawn("synthetic-top", |token| async move {
                token.cancelled().await;
            })
            .expect("spawn should succeed");

        // An in-flight request that would run far past the timeout. Wait for the
        // resolver to signal entry — with a bound — before starting shutdown, so
        // the cutoff is exercised against a request that was truly accepted and
        // running. A wall-clock sleep here could let shutdown begin before the
        // request connects, in which case the controller would return on an empty
        // server and the drain would pass even if the cutoff were broken.
        let hold_client = build_mtls_client(&cert, &key, &ca);
        let hold =
            tokio::spawn(
                async move { run_query(&hold_client, addr, "{ slow(millis: 10000) }").await },
            );
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("the slow request must reach the resolver before shutdown begins");

        // The production tail — web shutdown, then the top-level drain — must
        // finish within a bounded window. Web shutdown returns once the 300ms
        // timeout cuts the request off, not after the 10s request would have
        // finished; only then does the populated tracker drain. If the web
        // graceful-shutdown timeout no longer cut off the stuck request, web
        // shutdown would block for the full 10s and this bounded window would
        // expire, failing the test rather than letting the drain run.
        let outcome = tokio::time::timeout(Duration::from_secs(5), async {
            controller.shutdown().await.expect("graceful shutdown");
            tracker
                .cancel_and_drain(Duration::from_secs(5))
                .await
                .expect("drain should not report a poisoned lock")
        })
        .await
        .expect("web shutdown and the top-level drain must finish within the bounded window");
        assert_eq!(
            outcome,
            DrainOutcome::Drained,
            "the top-level drain must complete once web shutdown has returned"
        );

        // The stuck request was cut off rather than served to completion.
        let cut_off = hold.await.expect("join the stuck request");
        assert!(
            cut_off.is_err(),
            "a request exceeding the timeout must be cut off, not completed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_reports_each_pending_round_without_aborting_the_web_task() {
        use std::sync::atomic::{AtomicBool, Ordering};

        use tokio::sync::oneshot;

        const REPORT_INTERVAL: Duration = Duration::from_millis(25);

        // The spawned stand-in task and the reporting loop are polled on this
        // thread, so their events land in the captured buffer.
        let (logs, _guard) = capture_logs();

        // A stand-in web task that stays pending until released, then finishes
        // on its own. Deferring completion past several report intervals is what
        // lets this prove the loop reports each round and never aborts the task:
        // the release flag is set only if the task runs to its end, so an
        // aborted task would leave it `false`.
        let completed = Arc::new(AtomicBool::new(false));
        let completed_task = Arc::clone(&completed);
        let (release_tx, release_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = release_rx.await;
            completed_task.store(true, Ordering::SeqCst);
        });

        let await_task = tokio::spawn(await_with_pending_reports(handle, REPORT_INTERVAL));

        // Virtual time only advances while every task is idle, so this lets
        // exactly two report rounds expire while the web task remains pending,
        // with no wall-clock wait.
        sleep(REPORT_INTERVAL * 2 + REPORT_INTERVAL / 2).await;
        assert!(
            !completed.load(Ordering::SeqCst),
            "the web task must still be pending before it is released"
        );

        release_tx
            .send(())
            .expect("the reporting loop should still be awaiting the web task");

        tokio::time::timeout(Duration::from_secs(5), await_task)
            .await
            .expect("the reporting loop should return once the web task finishes")
            .expect("await task should not panic")
            .expect("await should observe the task's normal completion");

        assert!(
            completed.load(Ordering::SeqCst),
            "the web task must finish on its own; it must not be aborted"
        );
        let logs = logs.contents();
        let reports = logs.matches("shutdown still pending").count();
        assert_eq!(
            reports, 2,
            "each pending round should be reported while the web task stays pending, logs: {logs}"
        );
    }

    /// Opens a raw mTLS TLS connection to `addr`, presenting the client identity
    /// and trusting the given CA. The connection speaks HTTP/1.1 by hand (no
    /// ALPN is offered, so the server keeps HTTP/1.1), which lets a test drive a
    /// single, known keep-alive connection and send a second request over it
    /// after shutdown — something a pooled `reqwest::Client` cannot guarantee.
    async fn raw_mtls_connection(
        addr: SocketAddr,
        cert_pem: &[u8],
        key_pem: &[u8],
        ca_pem: &[u8],
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let config = rustls::ClientConfig::builder();
        let (_, result) =
            tls_handshake(addr, config, &certs_from_pem(cert_pem, key_pem, ca_pem)).await;
        result.expect("TLS handshake")
    }

    /// A client builder that offers only TLS 1.2. It is built on the crate's
    /// default provider, because the process default carries no TLS 1.2
    /// suite and would refuse to build it at all.
    fn tls12_only_client() -> TlsClientBuilder {
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 client config")
    }

    /// Sends one HTTP/1.1 `{ hello }` request over `stream` and reads the first
    /// chunk of the response. Returns the raw response text, or an error if the
    /// connection is closed (write fails, or the read returns EOF) — which is how
    /// the server refuses a new request on a surviving keep-alive connection.
    async fn http1_hello_over(
        stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    ) -> std::io::Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let body = r#"{"query":"{ hello }"}"#;
        let request = format!(
            "POST /graphql HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    /// A second request on an *already-established* keep-alive connection must be
    /// refused once web shutdown has begun — the requirement is to stop new
    /// *requests*, not only new connections. This drives a raw TLS socket so the
    /// second request is demonstrably sent over the same connection the first
    /// succeeded on, closing the gap a pooled HTTP client leaves open.
    #[tokio::test]
    async fn established_keepalive_connection_rejects_new_request() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        let controller = serve(
            test_schema(),
            addr,
            certs_from_pem(&cert, &key, &ca),
            Duration::from_secs(10),
        )
        .await
        .expect("serve should start");
        sleep(Duration::from_millis(50)).await;

        // Establish one keep-alive connection and confirm it serves a request
        // before shutdown begins.
        let mut conn = raw_mtls_connection(addr, &cert, &key, &ca).await;
        let first = http1_hello_over(&mut conn)
            .await
            .expect("pre-shutdown request over the established connection");
        assert!(
            first.contains("200") && first.contains("world"),
            "the established connection should serve a request before shutdown, got: {first}"
        );

        // Keep the server alive with a separate in-flight request so shutdown is
        // still in progress when the second request goes out on `conn`.
        let hold_client = build_mtls_client(&cert, &key, &ca);
        let hold =
            tokio::spawn(
                async move { run_query(&hold_client, addr, "{ slow(millis: 1500) }").await },
            );
        sleep(Duration::from_millis(150)).await;

        let shutdown = tokio::spawn(controller.shutdown());
        sleep(Duration::from_millis(250)).await;

        // The second request is sent over the *same* connection the first
        // succeeded on. Graceful shutdown closes the idle keep-alive connection,
        // so this must not be served: either the write/read fails outright, or no
        // `200` response comes back.
        let second = http1_hello_over(&mut conn).await;
        let refused = match second {
            Err(_) => true,
            Ok(resp) => !resp.contains("200"),
        };
        assert!(
            refused,
            "a new request on an already-established keep-alive connection must be rejected \
             once web shutdown has begun"
        );

        let _ = hold.await.expect("join the holding request");
        shutdown
            .await
            .expect("join shutdown")
            .expect("graceful shutdown");
    }

    /// A client built from the process default provider, as
    /// `tls_client_config` is, and the GraphQL listener agree on the hybrid
    /// post-quantum key exchange.
    #[tokio::test]
    async fn graphql_listener_negotiates_hybrid_post_quantum_key_exchange() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        let controller = serve(
            test_schema(),
            addr,
            certs_from_pem(&cert, &key, &ca),
            Duration::from_secs(10),
        )
        .await
        .expect("serve should start");

        let conn = raw_mtls_connection(addr, &cert, &key, &ca).await;
        assert_eq!(
            conn.get_ref()
                .1
                .negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name),
            Some(rustls::NamedGroup::X25519MLKEM768),
        );

        drop(conn);
        controller.shutdown().await.expect("graceful shutdown");
    }

    /// A client that offers only the classical X25519 group is refused, and
    /// the refusal is logged once at WARN with the client's address.
    #[tokio::test]
    async fn graphql_listener_refuses_x25519_only_client() {
        install_crypto_provider();
        let (logs, _guard) = capture_logs();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let certs = certs_from_pem(&cert, &key, &ca);
        let addr = free_addr();

        let controller = serve(
            test_schema(),
            addr,
            Arc::clone(&certs),
            Duration::from_secs(10),
        )
        .await
        .expect("serve should start");

        assert_tls_refused_with_one_warning(
            addr,
            x25519_only_tls_client(),
            &certs,
            &logs,
            "NoKxGroupsInCommon",
        )
        .await;

        controller.shutdown().await.expect("graceful shutdown");
    }

    /// Once its handshake has failed, a connection returns an error on every
    /// later read, write, flush and shutdown, and logs nothing more: the one
    /// WARN line was written when the handshake failed.
    #[tokio::test]
    async fn failed_handshake_stream_keeps_failing_without_logging_again() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (logs, _guard) = capture_logs();
        let mut stream = GraphqlTlsStream {
            state: HandshakeState::Failed,
            peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        };

        let errors = [
            stream.read(&mut [0; 1]).await.expect_err("read"),
            stream.write(b"x").await.expect_err("write"),
            stream.flush().await.expect_err("flush"),
            stream.shutdown().await.expect_err("shutdown"),
        ];
        assert!(
            errors
                .iter()
                .all(|error| error.kind() == io::ErrorKind::InvalidData)
        );
        let contents = logs.contents();
        assert!(
            !contents.contains("TLS handshake from"),
            "no further WARN line, got: {contents}"
        );
    }

    /// A client that offers only TLS 1.2 is refused, and the refusal is logged
    /// once at WARN with the client's address.
    #[tokio::test]
    async fn graphql_listener_refuses_tls12_only_client() {
        install_crypto_provider();
        let (logs, _guard) = capture_logs();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let certs = certs_from_pem(&cert, &key, &ca);
        let addr = free_addr();

        let controller = serve(
            test_schema(),
            addr,
            Arc::clone(&certs),
            Duration::from_secs(10),
        )
        .await
        .expect("serve should start");

        assert_tls_refused_with_one_warning(
            addr,
            tls12_only_client(),
            &certs,
            &logs,
            "Tls12NotOfferedOrEnabled",
        )
        .await;

        controller.shutdown().await.expect("graceful shutdown");
    }

    /// The web graceful-shutdown timeout the server runs with must be the one the
    /// configuration resolves — including the 30s default when the field is
    /// omitted — not just a value the deserializer produces. This starts the web
    /// lifecycle from settings with `web_shutdown_timeout` omitted and drives an
    /// ordinary request and a graceful shutdown under the resolved default,
    /// proving the default budget is what reaches `serve`. (The cutoff *timing*
    /// of a stuck request is value-independent and is covered with a short
    /// configured timeout by
    /// `stuck_web_request_cutoff_lets_the_top_level_drain_reach_drained`, so
    /// this need not wait the full 30s to exercise the default.)
    #[tokio::test]
    async fn default_timeout_from_settings_is_applied_to_web_lifecycle() {
        use crate::settings::Settings;

        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        // A config that omits `web_shutdown_timeout`, loaded through the real
        // settings path so the field resolves to its serde default.
        let data_dir = tempdir().expect("data dir");
        let export_dir = tempdir().expect("export dir");
        let config_contents = format!(
            "data_dir = \"{}\"\nexport_dir = \"{}\"\n",
            data_dir.path().display(),
            export_dir.path().display()
        );
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, config_contents).expect("write config");
        let settings =
            Settings::load(config_path.to_str().expect("config path utf8")).expect("load settings");

        let resolved_timeout = settings.config.web_shutdown_timeout;
        assert_eq!(
            resolved_timeout,
            Duration::from_secs(30),
            "omitting web_shutdown_timeout must resolve to the 30s default"
        );

        // Run the web lifecycle under the resolved default and confirm an
        // ordinary request completes and graceful shutdown returns.
        let controller = serve(
            test_schema(),
            addr,
            certs_from_pem(&cert, &key, &ca),
            resolved_timeout,
        )
        .await
        .expect("serve should start under the default timeout");
        sleep(Duration::from_millis(50)).await;

        let client = build_mtls_client(&cert, &key, &ca);
        let body = run_query(&client, addr, "{ hello }")
            .await
            .expect("request under the default timeout should succeed");
        assert!(
            body.contains("world"),
            "the request should complete normally under the default budget, got: {body}"
        );

        controller
            .shutdown()
            .await
            .expect("graceful shutdown under the default timeout");
    }
}
