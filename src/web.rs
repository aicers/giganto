use std::net::SocketAddr;

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
};
use tracing::info;

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
    /// # Errors
    ///
    /// Returns an error if the spawned task failed to join (e.g. it
    /// panicked or was aborted).
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        self.handle
            .await
            .map_err(|e| anyhow!("web task join error: {e}"))
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
/// * `ca_certs` - Paths to CA certificate files for client verification
///
/// # Errors
///
/// This function will return an error if:
/// * CA certificates cannot be read
/// * The TLS listener cannot bind to `addr`
pub async fn serve<S: Executor>(
    schema: S,
    addr: SocketAddr,
    cert: Vec<u8>,
    key: Vec<u8>,
    ca_certs: &[String],
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

    let mut ca_cert_data = Vec::new();
    for ca_path in ca_certs {
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("failed to read CA certificate {ca_path}"))?;
        ca_cert_data.extend_from_slice(&ca_pem);
    }

    let certificate = RustlsCertificate::new().cert(cert).key(key);

    let listener = TcpListener::bind(addr).rustls(
        RustlsConfig::new()
            .fallback(certificate)
            .client_auth_required(ca_cert_data),
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
            None,
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
    }

    fn test_schema() -> Schema<Query, EmptyMutation, EmptySubscription> {
        Schema::build(Query, EmptyMutation, EmptySubscription).finish()
    }

    fn write_pki(dir: &std::path::Path) -> (Vec<u8>, Vec<u8>, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate self-signed cert");
        let cert_pem = ck.cert.pem();
        let key_pem = ck.signing_key.serialize_pem();
        let ca_path = dir.join("ca.pem");
        std::fs::write(&ca_path, cert_pem.as_bytes()).expect("write ca");
        (
            cert_pem.into_bytes(),
            key_pem.into_bytes(),
            ca_path.to_str().expect("path").to_string(),
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

        let result = serve(test_schema(), addr, cert, key, &[ca]).await;
        assert!(result.is_err(), "bind on occupied port should fail");
    }

    #[tokio::test]
    async fn serve_returns_error_when_ca_cert_missing() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, _) = write_pki(dir.path());
        let addr = free_addr();

        let result = serve(
            test_schema(),
            addr,
            cert,
            key,
            &["/nonexistent/ca.pem".to_string()],
        )
        .await;

        assert!(result.is_err(), "missing CA file should fail");
    }

    #[tokio::test]
    async fn shutdown_completes_when_requested() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_pki(dir.path());
        let addr = free_addr();

        let controller = serve(test_schema(), addr, cert, key, &[ca])
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
            std::slice::from_ref(&ca),
        )
        .await
        .expect("initial serve");
        sleep(Duration::from_millis(50)).await;
        controller.shutdown().await.expect("shutdown");

        // The same address must be re-bindable after shutdown completes.
        let controller = serve(test_schema(), addr, cert, key, std::slice::from_ref(&ca))
            .await
            .expect("second serve should rebind");
        controller.shutdown().await.expect("second shutdown");
    }
}
