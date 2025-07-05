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
        $handler($ctx, &$filter, $($($handler_arg)*)*)
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
        $handler($ctx, $sensors.as_ref(), $($($handler_arg,)*)*).await
    }};
}
pub(crate) use events_in_cluster;

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
     $(, with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* ))? ) => {{ $handler($ctx, $filter, $after, $before, $first, $last).await }};
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
        crate::graphql::standalone::events_in_cluster!(
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
