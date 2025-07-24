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

/// Runs the GraphQL server.
///
/// Note that `key` is not compatible with the DER-encoded key extracted by
/// rustls-pemfile.
#[allow(clippy::unused_async)]
pub async fn serve<S: Executor>(
    schema: S,
    addr: SocketAddr,
    cert: Vec<u8>,
    key: Vec<u8>,
    notify_shutdown: Arc<Notify>,
) {
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

    let listener = TcpListener::bind(addr).rustls(RustlsConfig::new().fallback(certificate));

    info!("Listening on https://{addr:?}");

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
}
