use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use async_graphql::{
    Executor,
    http::{GraphQLPlaygroundConfig, playground_source},
};
use tokio::{sync::Notify, task};
use tracing::info;
use warp::{Filter, http::Response as HttpResponse};

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
    let filter = async_graphql_warp::graphql(schema).and_then(
        |(schema, request): (S, async_graphql::Request)| async move {
            let resp = schema.execute(request).await;

            Ok::<_, Infallible>(async_graphql_warp::GraphQLResponse::from(resp))
        },
    );

    let graphql_playground = warp::path!("graphql" / "playground").map(|| {
        HttpResponse::builder()
            .header("content-type", "text/html")
            .body(playground_source(GraphQLPlaygroundConfig::new("/graphql")))
    });

    let route_graphql = warp::path("graphql").and(warp::any()).and(filter);
    let route_home = warp::path::end().map(|| "");

    let routes = graphql_playground.or(warp::any().and(route_graphql.or(route_home)));
    let (_, server) = warp::serve(routes)
        .tls()
        .cert(cert)
        .key(key)
        .bind_with_graceful_shutdown(addr, async move { notify_shutdown.notified().await });

    // start Graphql Server
    info!("listening on https://{addr:?}");
    task::spawn(server);
}
