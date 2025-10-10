use std::{net::SocketAddr, sync::Arc};

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
use tokio::{sync::Notify, task};
use tracing::info;

/// Runs the GraphQL server with mTLS client authentication.
///
/// Note that `key` is not compatible with the DER-encoded key extracted by
/// rustls-pemfile.
///
/// # Arguments
///
/// * `schema` - The GraphQL schema executor
/// * `addr` - The socket address to bind to
/// * `cert` - Server certificate in PEM format
/// * `key` - Server private key in PEM format
/// * `ca_certs` - Paths to CA certificate files for client verification
/// * `notify_shutdown` - Notification channel for graceful shutdown
///
/// # Errors
///
/// This function will return an error if:
/// * The TLS configuration fails
/// * The server fails to start
/// * The CA certificates cannot be read
pub fn serve<S: Executor>(
    schema: S,
    addr: SocketAddr,
    cert: Vec<u8>,
    key: Vec<u8>,
    ca_certs: &[String],
    notify_shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
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

    // Read CA certificates for client authentication
    let mut ca_cert_data = Vec::new();
    for ca_path in ca_certs {
        let ca_pem = std::fs::read(ca_path)
            .map_err(|e| anyhow::anyhow!("failed to read CA certificate {ca_path}: {e}"))?;
        ca_cert_data.extend_from_slice(&ca_pem);
    }

    let certificate = RustlsCertificate::new().cert(cert).key(key);

    let listener = TcpListener::bind(addr).rustls(
        RustlsConfig::new()
            .fallback(certificate)
            .client_auth_required(ca_cert_data),
    );

    info!("GraphQL web server is starting on https://{addr:?} with mTLS enabled");

    task::spawn(async move {
        let server = Server::new(listener).run_with_graceful_shutdown(
            app,
            async move { notify_shutdown.notified().await },
            None,
        );

        if let Err(e) = server.await {
            tracing::error!("Server error: {}", e);
        }
    });

    Ok(())
}
