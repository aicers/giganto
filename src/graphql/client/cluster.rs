use std::{collections::HashSet, net::IpAddr, net::SocketAddr};

use async_graphql::{
    Context, Error, OutputType, Result,
    connection::{Connection, Edge, EmptyFields},
};
use graphql_client::Response as GraphQlResponse;
use num_traits::AsPrimitive;
use serde::Deserialize;
use serde::Serialize;

use crate::{
    comm::{IngestSensors, peer::Peers},
    graphql::MAXIMUM_PAGE_SIZE,
};

pub trait ClusterSortKey {
    fn secondary(&self) -> Option<&str>;
}

#[allow(unused)]
#[derive(PartialEq)]
enum TakeDirection {
    First,
    Last,
}

#[allow(unused)]
fn sort_and_trunk_edges<N>(
    mut edges: Vec<Edge<String, N, EmptyFields>>,
    before: Option<&str>,
    first: Option<i32>,
    last: Option<i32>,
) -> Vec<Edge<String, N, EmptyFields>>
where
    N: OutputType + ClusterSortKey,
{
    let (take_direction, get_len) = if before.is_some() || last.is_some() {
        (
            TakeDirection::Last,
            last.map_or(MAXIMUM_PAGE_SIZE, |l| MAXIMUM_PAGE_SIZE.min(l.as_())),
        )
    } else {
        (
            TakeDirection::First,
            first.map_or(MAXIMUM_PAGE_SIZE, |f| MAXIMUM_PAGE_SIZE.min(f.as_())),
        )
    };

    // Sort by `cursor`, and then `sensor`. Since each node in giganto may have
    // conflicting `cursor` values, we need a secondary sort key.
    edges.sort_unstable_by(|a, b| {
        a.cursor.cmp(&b.cursor).then_with(|| {
            a.node
                .secondary()
                .unwrap_or_default()
                .cmp(b.node.secondary().unwrap_or_default())
        })
    });

    if take_direction == TakeDirection::First {
        edges.truncate(get_len);
    } else {
        let drain_start = edges.len().saturating_sub(get_len);
        edges = edges.drain(drain_start..).collect();
    }

    edges
}

#[allow(unused)]
fn combine_results<N>(
    current_giganto_result: Connection<String, N>,
    peer_results: Vec<Connection<String, N>>,
    before: Option<&str>,
    first: Option<i32>,
    last: Option<i32>,
) -> Connection<String, N>
where
    N: OutputType + ClusterSortKey,
{
    let (has_next_page_combined, has_prev_page_combined) = peer_results.iter().fold(
        (
            current_giganto_result.has_previous_page,
            current_giganto_result.has_next_page,
        ),
        |(has_prev_page, has_next_page), result| {
            (
                has_prev_page || result.has_previous_page,
                has_next_page || result.has_next_page,
            )
        },
    );

    let edges_combined = peer_results
        .into_iter()
        .flat_map(|fpr| fpr.edges)
        .chain(current_giganto_result.edges)
        .collect();
    let edges_combined = sort_and_trunk_edges(edges_combined, before, first, last);

    let mut connection_to_return = Connection::new(has_prev_page_combined, has_next_page_combined);
    connection_to_return.edges = edges_combined;

    connection_to_return
}

pub(crate) async fn is_current_giganto_in_charge(ctx: &Context<'_>, sensor_filter: &str) -> bool {
    let ingest_sensors = ctx.data_opt::<IngestSensors>();
    match ingest_sensors {
        Some(ingest_sensors) => ingest_sensors.read().await.contains(sensor_filter),
        None => false,
    }
}

pub(crate) async fn peer_in_charge_graphql_addr(
    ctx: &Context<'_>,
    sensor_filter: &str,
) -> Option<SocketAddr> {
    let peers = ctx.data_opt::<Peers>();
    match peers {
        Some(peers) => {
            peers
                .read()
                .await
                .iter()
                .find_map(|(addr_to_peers, peer_info)| {
                    peer_info
                        .ingest_sensors
                        .contains(sensor_filter)
                        .then(|| {
                            SocketAddr::new(
                                addr_to_peers.parse::<IpAddr>().expect("Peer's IP address must be valid, because it is validated when peer giganto started."),
                                peer_info.graphql_port.expect("Peer's graphql port must be valid, because it is validated when peer giganto started."),
                            )
                        })
                })
        }
        None => None,
    }
}

pub(crate) async fn find_who_are_in_charge(
    ctx: &Context<'_>,
    sensors: &HashSet<&str>,
) -> (Vec<String>, Vec<SocketAddr>) {
    let ingest_sensors = ctx.data_opt::<IngestSensors>();

    let sensors_to_handle_by_current_giganto: Vec<String> = match ingest_sensors {
        Some(ingest_sensors) => {
            let ingest_sensors = ingest_sensors.read().await;
            let ingest_sensors_set = ingest_sensors
                .iter()
                .map(std::string::String::as_str)
                .collect::<HashSet<_>>();

            sensors
                .intersection(&ingest_sensors_set)
                .map(ToString::to_string)
                .collect()
        }
        None => Vec::new(),
    };

    let peers = ctx.data_opt::<Peers>();
    let peers_in_charge_graphql_addrs: Vec<SocketAddr> = match peers {
        Some(peers) => peers
            .read()
            .await
            .iter()
            .filter(|&(_addr_to_peers, peer_info)| {
                peer_info
                    .ingest_sensors
                    .iter()
                    .any(|ingest_sensor| sensors.contains(&ingest_sensor.as_str()))
            })
            .map(|(addr_to_peers, peer_info)| {
                SocketAddr::new(
                    addr_to_peers
                        .parse::<IpAddr>()
                        .expect("Peer's IP address must be valid, because it is validated when peer giganto started."),
                    peer_info
                        .graphql_port
                        .expect("Peer's graphql port must be valid, because it is validated when peer giganto started."),
                )
            })
            .collect(),
        None => Vec::new(),
    };

    (
        sensors_to_handle_by_current_giganto,
        peers_in_charge_graphql_addrs,
    )
}

pub async fn request_peer<QueryBodyType, ResponseDataType, ResultDataType, F>(
    ctx: &Context<'_>,
    peer_graphql_addr: SocketAddr,
    req_body: graphql_client::QueryBody<QueryBodyType>,
    response_to_result_converter: F,
) -> Result<ResultDataType>
where
    QueryBodyType: Serialize,
    ResponseDataType: for<'a> Deserialize<'a>,
    F: 'static + FnOnce(Option<ResponseDataType>) -> ResultDataType,
{
    let client = ctx.data::<reqwest::Client>()?;
    let req = client
        .post(format!(
            "{}://{}/graphql",
            if cfg!(test) { "http" } else { "https" },
            peer_graphql_addr
        ))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&req_body);

    let resp = req
        .send()
        .await
        .map_err(|e| Error::new(format!("Peer giganto did not respond {e}")))?;

    resp.error_for_status()
        .map_err(|e| {
            Error::new(format!(
                "Peer giganto's response status is not success. {e}"
            ))
        })?
        .json::<GraphQlResponse<ResponseDataType>>()
        .await
        .map_err(|_| Error::new("Peer giganto's response failed to deserialize."))
        .map(|graphql_res| response_to_result_converter(graphql_res.data))
}

// This macro helps to reduce boilerplate for handling
// `search_[something]_events` APIs in giganto cluster. If the current giganto
// is in charge of the given `filter.sensor`, it will execute the handler
// locally. Otherwise, it will forward the request to a peer giganto in charge
// of the given `filter.sensor`. Peer giganto's response will be converted to
// the return type of the current giganto.
//
// Below is detailed explanation of arguments:
// * `$ctx` - The context of the GraphQL query.
// * `$filter` - The filter of the query.
// * `$sensor` - The sensor of the query.
// * `$handler` - The handler to be carried out by the current giganto if it is
//   in charge.
// * `$graphql_query_type` - Name of the struct that derives `GraphQLQuery`.
// * `$variables_type` - Query variable type generated by `graphql_client`. For
//   example, `search_conn_raw_events::Variables`.
// * `$response_data_type` - Response data type generated by `graphql_client`.
//   For example, `search_conn_raw_events::ResponseData`.
// * `$field_name` - Name of the field in the response data that contains the
//   result. For example, `search_conn_raw_events`.
// * `$result_type` - The type to which the response data will be converted.
// * `with_extra_handler_args ($($handler_arg:expr ),* )` - Extra arguments to
//  be passed to the handler. For example, `with_extra_handler_args (after,
//  before, first, last)`.
// * `with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* )` -
//  Extra arguments to be passed to the GraphQL query variables. For example,
//  `with_extra_query_args (after := after, before := before, first := first,
//  last := last)`.
//
// For your information, `$variables_type`, `$response_data_type`, `$field_name`
// are generated by `graphql_client` macro. You can `cargo expand` to see the
// generated code.
macro_rules! events_in_cluster {
    ($ctx:expr,
     $filter:expr,
     $sensor:expr,
     $handler:ident,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident,
     $result_type:tt
     $(, with_extra_handler_args ($($handler_arg:expr ),* ))?
     $(, with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* ))? ) => {{
        type QueryVariables = $variables_type;
        if crate::graphql::client::cluster::is_current_giganto_in_charge($ctx, &$sensor).await {
            $handler($ctx, &$filter, $($($handler_arg)*)*)
        } else {
            let peer_addr = crate::graphql::client::cluster::peer_in_charge_graphql_addr($ctx, &$sensor).await;

            match peer_addr {
                Some(peer_addr) => {
                    #[allow(clippy::redundant_field_names)]
                    let request_body = $graphql_query_type::build_query(QueryVariables {
                        filter: $filter.into(),
                        $($($query_arg: $query_arg_from),*)*
                    });
                    let response_to_result_converter = |resp_data: Option<$response_data_type>| {
                        resp_data.map_or_else($result_type::new, |resp_data| {
                            resp_data.$field_name.into()
                        })
                    };
                    crate::graphql::client::cluster::request_peer(
                        $ctx,
                        peer_addr,
                        request_body,
                        response_to_result_converter,
                    )
                    .await
                }
                None => Ok($result_type::new()),
            }
        }
    }};

    // This variant of the macro is for the case where API request comes with
    // multiple sensors. In this case, current giganto will figure out which
    // gigantos are in charge of requested `sensors`, including itself. If
    // current giganto is in charge of any of the requested `sensors`, it will
    // handle the request locally, and if peer gigantos are in charge of any of
    // the requested `sensors`, it will forward the request to them.
    //
    // This macro has the same arguments as the primary macro variant, except
    // these arguments:
    // * `$sensors` - The sensors of the query. It should be iterable.
    // * `$request_from_peer` - Whether the request comes from a peer giganto.
    (multiple_sensors
     $ctx:expr,
     $sensors:expr,
     $request_from_peer:expr,
     $handler:ident,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident,
     $result_type:path
     $(, with_extra_handler_args ($($handler_arg:expr ),* ))?
     $(, with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* ))? ) => {{
        if $request_from_peer.unwrap_or_default() {
            return $handler($ctx, $sensors.as_ref(), $($($handler_arg,)*)*).await;
        }

        let sensors_set: HashSet<_> = $sensors.iter().map(|s| s.as_str()).collect();
        let (sensors_to_handle_by_current_giganto, peers_in_charge_graphql_addrs)
            = crate::graphql::client::cluster::find_who_are_in_charge(&$ctx, &sensors_set).await;

        match (
            !sensors_to_handle_by_current_giganto.is_empty(),
            !peers_in_charge_graphql_addrs.is_empty(),
        ) {
            (true, true) => {
                let current_giganto_result_fut = $handler($ctx, sensors_to_handle_by_current_giganto.as_ref(), $($($handler_arg,)*)*);

                let peer_results_fut = crate::graphql::client::cluster::request_selected_peers_for_events_fut!(
                    $ctx,
                    $sensors,
                    peers_in_charge_graphql_addrs,
                    $response_data_type,
                    $field_name,
                    $variables_type,
                    $graphql_query_type,
                    $($($query_arg := $query_arg_from),*)*
                );

                let (current_giganto_result, peer_results) = tokio::join!(current_giganto_result_fut, peer_results_fut);

                let current_giganto_result = current_giganto_result
                    .map_err(|_| async_graphql::Error::new("Current giganto failed to get result"))?;

                let peer_results = peer_results
                    .into_iter()
                    .map(|peer_result| match peer_result {
                        Ok(result) => Ok(result),
                        Err(e) => Err(async_graphql::Error::new(format!("Peer giganto failed to respond {e:?}"))),
                    })
                    .collect::<Result<Vec<$result_type>>>()?;

                let combined = peer_results
                    .into_iter()
                    .flatten()
                    .chain(current_giganto_result)
                    .collect();

                Ok(combined)
            }
            (false, true) => {
                let peer_results = crate::graphql::client::cluster::request_selected_peers_for_events_fut!(
                    $ctx,
                    $sensors,
                    peers_in_charge_graphql_addrs,
                    $response_data_type,
                    $field_name,
                    $variables_type,
                    $graphql_query_type,
                    $($($query_arg := $query_arg_from),*)*
                ).await;

                let peer_results = peer_results
                    .into_iter()
                    .map(|result| result.map_err(|e| async_graphql::Error::new(format!("Peer giganto failed to respond {e:?}"))))
                    .collect::<Result<Vec<$result_type>, _>>()?;

                Ok(peer_results.into_iter().flatten().collect())
            }
            (true, false) => {
                $handler($ctx, sensors_to_handle_by_current_giganto.as_ref(), $($($handler_arg,)*)*).await
            }
            (false, false) => Ok(Vec::new()),
        }
    }};
}
pub(crate) use events_in_cluster;

// This macro helps to reduce boilerplate for handling
// `[something]_events_connection` APIs in giganto cluster. If the current
// giganto is in charge of the given `filter.sensor`, it will execute the
// handler locally. Otherwise, it will forward the request to a peer giganto in
// charge of the given `filter.sensor`. Peer giganto's response will be
// converted to the return type of the current giganto.
//
// Below is detailed explanation of arguments:
// * `$ctx` - The context of the GraphQL query.
// * `$filter` - The filter of the query.
// * `$sensor` - The sensor of the query.
// * `$after` - The cursor of the last edge of the previous page.
// * `$before` - The cursor of the first edge of the next page.
// * `$first` - The number of edges to be returned from the first edge of the
//   next page.
// * `$last` - The number of edges to be returned from the last edge of the
//   previous page.
// * `$handler` - The handler to be carried out by the current giganto if it is
//   in charge.
// * `$graphql_query_type` - Name of the struct that derives `GraphQLQuery`.
// * `$variables_type` - Query variable type generated by `graphql_client`. For
//   example, `conn_raw_events::Variables`.
// * `$response_data_type` - Response data type generated by `graphql_client`.
//   For example, `conn_raw_events::ResponseData`.
// * `$field_name` - Name of the field in the response data that contains the
//   result. For example, `conn_raw_events`.
// * `with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* )` -
//  Extra arguments to be passed to the GraphQL query variables.
//
// For your information, `$variables_type`, `$response_data_type`, `$field_name`
// are generated by `graphql_client` macro. You can `cargo expand` to see the
// generated code.
macro_rules! paged_events_in_cluster {
    ($ctx:expr,
     $filter:expr,
     $sensor:expr,
     $after:expr,
     $before:expr,
     $first:expr,
     $last:expr,
     $handler:expr,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident
     $(, with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* ))? ) => {{
        if crate::graphql::client::cluster::is_current_giganto_in_charge($ctx, &$sensor).await {
            $handler($ctx, $filter, $after, $before, $first, $last).await
        } else {
            let peer_addr = crate::graphql::client::cluster::peer_in_charge_graphql_addr($ctx, &$sensor).await;

            match peer_addr {
                Some(peer_addr) => {
                    type QueryVariables = $variables_type;
                    let request_body = $graphql_query_type::build_query(QueryVariables {
                        filter: $filter.into(),
                        after: $after,
                        before: $before,
                        first: $first.map(std::convert::Into::into),
                        last: $last.map(std::convert::Into::into),
                        $($($query_arg: $query_arg_from),*)*
                    });

                    let response_to_result_converter = |resp_data: Option<$response_data_type>| {
                        if let Some(data) = resp_data {
                            let page_info = data.$field_name.page_info;

                            let mut connection = async_graphql::connection::Connection::new(
                                page_info.has_previous_page,
                                page_info.has_next_page,
                            );

                            connection.edges = data
                                .$field_name
                                .edges
                                .into_iter()
                                .map(|e| {
                                    async_graphql::connection::Edge::new(e.cursor, e.node.into())
                                })
                                .collect();

                            connection
                        } else {
                            async_graphql::connection::Connection::new(false, false)
                        }
                    };

                    crate::graphql::client::cluster::request_peer(
                        $ctx,
                        peer_addr,
                        request_body,
                        response_to_result_converter,
                    )
                    .await
                }
                None => Ok(Connection::new(false, false)),
            }
        }
    }};

    // This macro variant is for the case where user does not specify `sensor`
    // in the filter. In this case, the current giganto will request all peers
    // for the result and combine them.
    //
    // This macro has the same arguments as the primary macro variant, except
    // these arguments:
    // * `$request_from_peer` - Whether the request comes from a peer giganto.
    (request_all_peers_if_sensor_is_none
     $ctx:expr,
     $filter:expr,
     $after:expr,
     $before:expr,
     $first:expr,
     $last:expr,
     $request_from_peer:expr,
     $handler:expr,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident) => {{
        if $request_from_peer.unwrap_or_default() {
            return $handler($ctx, $filter, $after, $before, $first, $last).await;
        }

        match &$filter.sensor {
            Some(sensor) => {
                paged_events_in_cluster!(
                    $ctx,
                    $filter,
                    sensor,
                    $after,
                    $before,
                    $first,
                    $last,
                    $handler,
                    $graphql_query_type,
                    $variables_type,
                    $response_data_type,
                    $field_name,
                    with_extra_query_args (request_from_peer := Some(true))

                )
            }
            None => {
                let current_giganto_result_fut = $handler(
                    $ctx,
                    $filter.clone(),
                    $after.clone(),
                    $before.clone(),
                    $first,
                    $last,
                );

                let peer_results_fut = crate::graphql::client::cluster::request_all_peers_for_paged_events_fut!(
                    $ctx,
                    $filter,
                    $after,
                    $before,
                    $first,
                    $last,
                    $request_from_peer,
                    $graphql_query_type,
                    $variables_type,
                    $response_data_type,
                    $field_name
                );

                let (current_giganto_result, peer_results) =
                    tokio::join!(current_giganto_result_fut, peer_results_fut);

                let current_giganto_result = current_giganto_result
                    .map_err(|_| Error::new("Current giganto failed to get result"))?;

                let peer_results: Vec<_> = peer_results
                    .into_iter()
                    .map(|result| result.map_err(|e| Error::new(format!("Peer giganto failed to respond {e:?}"))))
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(crate::graphql::client::cluster::combine_results(
                    current_giganto_result,
                    peer_results,
                    &$before,
                    $first,
                    $last,
                ))
            }
        }
    }};

    (request_all_peers
        $ctx:expr,
        $filter:expr,
        $after:expr,
        $before:expr,
        $first:expr,
        $last:expr,
        $request_from_peer:expr,
        $handler:expr,
        $graphql_query_type:ident,
        $variables_type:ty,
        $response_data_type:path,
        $field_name:ident) => {{
            if $request_from_peer.unwrap_or_default() {
               return $handler($ctx, $filter, $after, $before, $first, $last).await;
            }

            let current_giganto_result_fut = $handler(
                $ctx,
                $filter.clone(),
                $after.clone(),
                $before.clone(),
                $first,
                $last,
            );

            let peer_results_fut = crate::graphql::client::cluster::request_all_peers_for_paged_events_fut!(
                $ctx,
                $filter,
                $after,
                $before,
                $first,
                $last,
                $request_from_peer,
                $graphql_query_type,
                $variables_type,
                $response_data_type,
                $field_name
            );

            let (current_giganto_result, peer_results) =
                tokio::join!(current_giganto_result_fut, peer_results_fut);

            let current_giganto_result = current_giganto_result
                .map_err(|_| async_graphql::Error::new("Current giganto failed to get result"))?;

            let peer_results: Vec<_> = peer_results
                .into_iter()
                .map(|result| result.map_err(|e| async_graphql::Error::new(format!("Peer giganto failed to respond {e:?}"))))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(crate::graphql::client::cluster::combine_results(
                current_giganto_result,
                peer_results,
                &$before,
                $first,
                $last,
            ))
       }};
}
pub(crate) use paged_events_in_cluster;

// This macro is a specialized macro. It calls `events_in_cluster` macro with
// `Vec` as the `$result_type` type, without extra args. It is one of the most
// common cases, so this macro is provided for convenience.
macro_rules! events_vec_in_cluster {
    ($ctx:expr,
     $filter:expr,
     $sensor:expr,
     $handler:ident,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident) => {{
        crate::graphql::client::cluster::events_in_cluster!(
            $ctx,
            $filter,
            $sensor,
            $handler,
            $graphql_query_type,
            $variables_type,
            $response_data_type,
            $field_name,
            Vec
        )
    }};
}
pub(crate) use events_vec_in_cluster;

#[allow(unused_macros)]
macro_rules! request_all_peers_for_paged_events_fut {
    ($ctx:expr,
     $filter:expr,
     $after:expr,
     $before:expr,
     $first:expr,
     $last:expr,
     $request_from_peer:expr,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident) => {{
        let peer_graphql_endpoints = match $ctx.data_opt::<crate::peer::Peers>() {
            Some(peers) => {
                peers
                    .read()
                    .await
                    .iter()
                    .map(|(addr_to_peers, peer_info)| {
                        std::net::SocketAddr::new(
                            addr_to_peers.parse::<IpAddr>().expect("Peer's IP address must be valid, because it is validated when peer giganto started."),
                            peer_info.graphql_port.expect("Peer's graphql port must be valid, because it is validated when peer giganto started."),
                        )
                    }).collect()
            }
            None => Vec::new(),
        };

        let response_to_result_converter = |resp_data: Option<$response_data_type>| {
            if let Some(data) = resp_data {
                let page_info = data.$field_name.page_info;

                let mut connection = async_graphql::connection::Connection::new(
                    page_info.has_previous_page,
                    page_info.has_next_page,
                );

                connection.edges = data
                    .$field_name
                    .edges
                    .into_iter()
                    .map(|e| async_graphql::connection::Edge::new(e.cursor, e.node.into()))
                    .collect();

                connection
            } else {
                Connection::new(false, false)
            }
        };

        let peer_requests = peer_graphql_endpoints
        .into_iter()
        .map(|peer_endpoint| {
                type QueryVariables = $variables_type;
                let request_body = $graphql_query_type::build_query(QueryVariables {
                    filter: $filter.clone().into(),
                    after: $after.clone(),
                    before: $before.clone(),
                    first: $first.map(std::convert::Into::into),
                    last: $last.map(std::convert::Into::into),
                    request_from_peer: $request_from_peer.into(),
                });
                crate::graphql::client::cluster::request_peer(
                    $ctx,
                    peer_endpoint,
                    request_body,
                    response_to_result_converter,
                )
            });

        futures_util::future::join_all(peer_requests)
    }};
}
#[allow(unused_imports)]
pub(crate) use request_all_peers_for_paged_events_fut;

macro_rules! request_selected_peers_for_events_fut {
    ($ctx:expr,
     $sensors:expr,
     $peers_in_charge_graphql_addrs:expr,
     $response_data_type:path,
     $field_name:ident,
     $variables_type:ty,
     $graphql_query_type:ident,
     $($query_arg:tt := $query_arg_from:expr),*) => {{
        let response_to_result_converter = |resp_data: Option<$response_data_type>| {
            resp_data.map_or_else(Vec::new, |resp_data| {
                resp_data.$field_name.into_iter().map(Into::into).collect()
            })
        };

        let peer_requests = $peers_in_charge_graphql_addrs
            .into_iter()
            .map(|peer_endpoint| {
                type QueryVariables = $variables_type;
                let request_body = $graphql_query_type::build_query(QueryVariables {
                    sensors: $sensors.clone(),
                    request_from_peer: Some(true),
                    $($query_arg: $query_arg_from),*
                });
                crate::graphql::client::cluster::request_peer(
                    $ctx,
                    peer_endpoint,
                    request_body,
                    response_to_result_converter,
                )
            });
        futures_util::future::join_all(peer_requests)
    }};
}
pub(crate) use request_selected_peers_for_events_fut;

macro_rules! impl_from_giganto_time_range_struct_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<crate::graphql::TimeRange> for $autogen_mod::TimeRange {
                fn from(range: crate::graphql::TimeRange) -> Self {
                    Self {
                        start: range.start,
                        end: range.end,
                    }
                }
            }
        )*
    };
}
pub(crate) use impl_from_giganto_time_range_struct_for_graphql_client;

macro_rules! impl_from_giganto_range_structs_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            crate::graphql::client::cluster::impl_from_giganto_time_range_struct_for_graphql_client!($autogen_mod);

            impl From<crate::graphql::IpRange> for $autogen_mod::IpRange {
                fn from(range: crate::graphql::IpRange) -> Self {
                    Self {
                        start: range.start,
                        end: range.end,
                    }
                }
            }
            impl From<crate::graphql::PortRange> for $autogen_mod::PortRange {
                fn from(range: crate::graphql::PortRange) -> Self {
                    Self {
                        start: range.start.map(Into::into),
                        end: range.end.map(Into::into),
                    }
                }
            }
        )*
    };
}
pub(crate) use impl_from_giganto_range_structs_for_graphql_client;

macro_rules! impl_from_giganto_network_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<NetworkFilter> for $autogen_mod::NetworkFilter {
                fn from(filter: NetworkFilter) -> Self {
                    Self {
                        time: filter.time.map(Into::into),
                        sensor: filter.sensor,
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                        log_level: filter.log_level,
                        log_contents: filter.log_contents,
                        agent_id: filter.agent_id,
                    }
                }
            }
        )*
    };
}
pub(crate) use impl_from_giganto_network_filter_for_graphql_client;

macro_rules! impl_from_giganto_search_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<SearchFilter> for $autogen_mod::SearchFilter {
                fn from(filter: SearchFilter) -> Self {
                    Self {
                        time: filter.time.map(Into::into),
                        sensor: filter.sensor,
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                        log_level: filter.log_level,
                        log_contents: filter.log_contents,
                        times: filter.times,
                        keyword: filter.keyword,
                        agent_id: filter.agent_id,
                    }
                }
            }
        )*
    };
}
pub(crate) use impl_from_giganto_search_filter_for_graphql_client;

#[cfg(test)]
mod tests {
    use async_graphql::{
        SimpleObject,
        connection::{Edge, EmptyFields},
    };
    use chrono::{DateTime, Utc};

    use super::{ClusterSortKey, sort_and_trunk_edges};

    #[derive(SimpleObject, Debug)]
    struct TestNode {
        time: DateTime<Utc>,
    }

    impl ClusterSortKey for TestNode {
        fn secondary(&self) -> Option<&str> {
            None
        }
    }

    fn edges_fixture() -> Vec<Edge<String, TestNode, EmptyFields>> {
        vec![
            Edge::new("warn_001".to_string(), TestNode { time: Utc::now() }),
            Edge::new("danger_001".to_string(), TestNode { time: Utc::now() }),
            Edge::new("danger_002".to_string(), TestNode { time: Utc::now() }),
            Edge::new("info_001".to_string(), TestNode { time: Utc::now() }),
            Edge::new("info_002".to_string(), TestNode { time: Utc::now() }),
            Edge::new("info_003".to_string(), TestNode { time: Utc::now() }),
        ]
    }

    #[test]
    fn test_sort_and_trunk_edges() {
        let empty_vec = Vec::<Edge<String, TestNode, EmptyFields>>::new();
        let result = sort_and_trunk_edges(empty_vec, None, None, None);
        assert!(result.is_empty());

        let result = sort_and_trunk_edges(edges_fixture(), None, None, None);
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), None, Some(5), None);
        assert_eq!(result.len(), 5);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "info_003".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), None, Some(10), None);
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), None, None, Some(5));
        assert_eq!(result.len(), 5);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_002".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), None, None, Some(10));
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), Some("zebra_001"), None, None);
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), Some("zebra_001"), None, Some(5));
        assert_eq!(result.len(), 5);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_002".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), Some("zebra_001"), None, Some(10));
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());
    }
}
