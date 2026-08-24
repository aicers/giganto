use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, anyhow};
use async_graphql::{
    Executor,
    http::{GraphQLPlaygroundConfig, playground_source},
};
use async_graphql_poem::GraphQL;
use poem::{
    Response, Route, Server,
    endpoint::make_sync,
    listener::{Listener, RustlsCertificate, RustlsConfig, TcpListener},
};
use tokio::{
    sync::oneshot,
    task::{self, JoinHandle},
    time::{MissedTickBehavior, interval},
};
use tracing::info;

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
/// Note that `key` is not compatible with the DER-encoded key extracted
/// by `rustls-pemfile`.
///
/// # Arguments
///
/// * `schema` - The GraphQL schema executor
/// * `addr` - The socket address to bind to
/// * `cert` - Server certificate in PEM format
/// * `key` - Server private key in PEM format
/// * `ca_pem` - Concatenated CA PEM bytes used for client verification.
///   Callers must pass the already-validated bytes produced by the
///   common TLS reload path; this function does not re-read the CA
///   files from disk so that restart consumes the validated state
///   without reopening a TOCTOU window.
/// * `shutdown_timeout` - Graceful-shutdown budget applied to in-flight
///   requests once shutdown begins. After the signal is raised the server
///   stops accepting new connections and waits up to this duration for
///   already-accepted requests to finish before terminating them, so a stuck
///   request cannot block the caller — and therefore subsystem cancellation
///   and drain — indefinitely.
///
/// # Errors
///
/// Returns an error if the TLS listener cannot bind to `addr`.
pub async fn serve<S: Executor>(
    schema: S,
    addr: SocketAddr,
    cert: Vec<u8>,
    key: Vec<u8>,
    ca_pem: Vec<u8>,
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

    let certificate = RustlsCertificate::new().cert(cert).key(key);

    let listener = TcpListener::bind(addr).rustls(
        RustlsConfig::new()
            .fallback(certificate)
            .client_auth_required(ca_pem),
    );

    // Bind eagerly so the caller observes bind failures before the
    // background task is spawned.
    let acceptor = listener
        .into_acceptor()
        .await
        .with_context(|| format!("failed to bind HTTPS listener on {addr}"))?;

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

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Once,
        time::Duration,
    };

    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
    use tempfile::tempdir;
    use tokio::{net::TcpListener as TokioTcpListener, time::sleep};

    use super::*;

    static INSTALL_PROVIDER: Once = Once::new();

    fn install_crypto_provider() {
        INSTALL_PROVIDER.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    struct Query;

    #[Object]
    impl Query {
        async fn hello(&self) -> &'static str {
            "world"
        }

        /// Sleeps `millis` before answering, standing in for an in-flight
        /// request that is still running when web shutdown begins.
        async fn slow(&self, millis: i32) -> &'static str {
            let millis = u64::try_from(millis).unwrap_or(0);
            sleep(Duration::from_millis(millis)).await;
            "slept"
        }
    }

    fn test_schema() -> Schema<Query, EmptyMutation, EmptySubscription> {
        Schema::build(Query, EmptyMutation, EmptySubscription).finish()
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

        let result = serve(test_schema(), addr, cert, key, ca, Duration::from_secs(30)).await;
        assert!(result.is_err(), "bind on occupied port should fail");
    }

    #[tokio::test]
    async fn shutdown_completes_when_requested() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        let controller = serve(test_schema(), addr, cert, key, ca, Duration::from_secs(30))
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
            cert.clone(),
            key.clone(),
            ca.clone(),
            Duration::from_secs(30),
        )
        .await
        .expect("initial serve");
        sleep(Duration::from_millis(50)).await;
        controller.shutdown().await.expect("shutdown");

        // The same address must be re-bindable after shutdown completes.
        let controller = serve(test_schema(), addr, cert, key, ca, Duration::from_secs(30))
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
            cert.clone(),
            key.clone(),
            ca.clone(),
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
            cert.clone(),
            key.clone(),
            ca.clone(),
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
    async fn request_exceeding_timeout_does_not_block_drain() {
        use std::time::Instant;

        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        // A short timeout so a stuck request is cut off quickly.
        let controller = serve(
            test_schema(),
            addr,
            cert.clone(),
            key.clone(),
            ca.clone(),
            Duration::from_millis(300),
        )
        .await
        .expect("serve should start");
        sleep(Duration::from_millis(50)).await;

        // An in-flight request that would run far past the timeout.
        let hold_client = build_mtls_client(&cert, &key, &ca);
        let hold =
            tokio::spawn(
                async move { run_query(&hold_client, addr, "{ slow(millis: 10000) }").await },
            );
        sleep(Duration::from_millis(150)).await;

        // Shutdown must return once the timeout elapses, not after the stuck
        // request would have finished — otherwise it could block subsystem
        // cancellation and drain forever.
        let started = Instant::now();
        controller.shutdown().await.expect("graceful shutdown");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "shutdown must not wait for the stuck request; it took {elapsed:?}"
        );

        // The stuck request was cut off rather than served to completion.
        let cut_off = hold.await.expect("join the stuck request");
        assert!(
            cut_off.is_err(),
            "a request exceeding the timeout must be cut off, not completed"
        );
    }

    #[tokio::test]
    async fn shutdown_reports_pending_without_aborting_the_web_task() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        };

        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone)]
        struct CaptureBuf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for CaptureBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("capture lock").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for CaptureBuf {
            type Writer = CaptureBuf;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        // `#[tokio::test]` runs on a current-thread runtime, so the spawned
        // stand-in task and the reporting loop are polled on this thread and
        // their events land in this thread-local subscriber's buffer.
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(CaptureBuf(Arc::clone(&buf)))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        // A stand-in web task that finishes on its own after several report
        // intervals, proving the loop reports repeatedly and never aborts it.
        let completed = Arc::new(AtomicBool::new(false));
        let completed_task = Arc::clone(&completed);
        let handle = tokio::spawn(async move {
            sleep(Duration::from_millis(120)).await;
            completed_task.store(true, Ordering::SeqCst);
        });

        await_with_pending_reports(handle, Duration::from_millis(25))
            .await
            .expect("await should observe the task's normal completion");

        assert!(
            completed.load(Ordering::SeqCst),
            "the web task must finish on its own; it must not be aborted"
        );
        let logs = String::from_utf8(buf.lock().expect("capture lock").clone()).expect("utf8 logs");
        let reports = logs.matches("shutdown still pending").count();
        assert!(
            reports >= 1,
            "expected at least one pending-shutdown report while waiting, logs: {logs}"
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
        use std::sync::Arc;

        use tokio_rustls::rustls::{
            ClientConfig, RootCertStore,
            pki_types::{CertificateDer, PrivateKeyDer, ServerName},
        };

        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
            roots
                .add(cert.expect("parse CA cert"))
                .expect("add CA cert");
        }
        let client_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
            .map(|c| c.expect("parse client cert"))
            .collect();
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &key_pem[..])
            .expect("parse client key")
            .expect("client key present");
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certs, key)
            .expect("build client TLS config");

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("TCP connect");
        // The server certificate's SAN is `localhost`; connecting by IP would
        // fail hostname verification, so hand rustls the name it certifies.
        let server_name = ServerName::try_from("localhost").expect("server name");
        connector
            .connect(server_name, tcp)
            .await
            .expect("TLS handshake")
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
            cert.clone(),
            key.clone(),
            ca.clone(),
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

    /// The web graceful-shutdown timeout the server runs with must be the one the
    /// configuration resolves — including the 30s default when the field is
    /// omitted — not just a value the deserializer produces. This starts the web
    /// lifecycle from settings with `web_shutdown_timeout` omitted and drives an
    /// ordinary request and a graceful shutdown under the resolved default,
    /// proving the default budget is what reaches `serve`. (The cutoff *timing*
    /// of a stuck request is value-independent and is covered with a short
    /// configured timeout by `request_exceeding_timeout_does_not_block_drain`, so
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
            cert.clone(),
            key.clone(),
            ca.clone(),
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
