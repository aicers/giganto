use crate::graphql::Schema;
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use std::{convert::Infallible, net::SocketAddr};
use warp::{http::Response as HttpResponse, Filter};

/// Runs the GraphQL server.
///
/// Note that `key` is not compatible with the DER-encoded key extracted by
/// rustls-pemfile.
pub async fn serve(schema: Schema, addr: SocketAddr, cert: Vec<u8>, key: Vec<u8>) {
    let filter = async_graphql_warp::graphql(schema).and_then(
        |(schema, request): (Schema, async_graphql::Request)| async move {
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

    warp::serve(routes)
        .tls()
        .cert(cert)
        .key(key)
        .run(addr)
        .await;
}
