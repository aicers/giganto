use std::{fmt::Debug, net::IpAddr};

use async_graphql::{Context, InputObject, Object, Result, SimpleObject, connection::Connection};
use giganto_client::ingest::log::SecuLog;
#[cfg(feature = "cluster")]
use giganto_proc_macro::ConvertGraphQLEdgesNode;
#[cfg(feature = "cluster")]
use graphql_client::GraphQLQuery;

use super::DateTime;
use super::{
    FromKeyValue, IpRange, PortRange, check_address, check_contents, check_port, get_time_from_key,
    handle_paged_events, paged_events_in_cluster,
};
#[cfg(feature = "cluster")]
use crate::graphql::client::{
    cluster::impl_from_giganto_range_structs_for_graphql_client,
    derives::{SecuLogRawEvents, secu_log_raw_events},
};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    storage::{Database, KeyExtractor},
};

#[derive(Default)]
pub(super) struct SecurityLogQuery;

#[derive(InputObject, Clone)]
pub struct SecuLogFilter {
    time: Option<TimeRange>,
    sensor: String,
    kind: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    log: Option<String>,
}

impl KeyExtractor for SecuLogFilter {
    fn get_start_key(&self) -> &str {
        &self.sensor
    }

    fn get_mid_key(&self) -> Option<Vec<u8>> {
        Some(self.kind.as_bytes().to_vec())
    }

    fn get_range_end_key(&self) -> (Option<DateTime>, Option<DateTime>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }
}

impl RawEventFilter for SecuLogFilter {
    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
        _log_level: Option<String>,
        log_contents: Option<String>,
        _text: Option<String>,
        _sensor: Option<String>,
        _agent_id: Option<String>,
    ) -> Result<bool> {
        if check_address(self.orig_addr.as_ref(), orig_addr)?
            && check_address(self.resp_addr.as_ref(), resp_addr)?
            && check_port(self.orig_port.as_ref(), orig_port)
            && check_port(self.resp_port.as_ref(), resp_port)
            && check_contents(self.log.as_deref(), log_contents)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    secu_log_raw_events::SecuLogRawEventsSecuLogRawEventsEdgesNode
]))]
struct SecuLogRawEvent {
    time: DateTime,
    log_type: String,
    version: String,
    orig_addr: Option<String>,
    orig_port: Option<u16>,
    resp_addr: Option<String>,
    resp_port: Option<u16>,
    proto: Option<u8>,
    contents: String,
}

impl FromKeyValue<SecuLog> for SecuLogRawEvent {
    fn from_key_value(key: &[u8], sl: SecuLog) -> Result<Self> {
        Ok(SecuLogRawEvent {
            time: get_time_from_key(key)?,
            log_type: sl.log_type,
            version: sl.version,
            orig_addr: sl.orig_addr.map(|addr| addr.to_string()),
            orig_port: sl.orig_port,
            resp_addr: sl.resp_addr.map(|addr| addr.to_string()),
            resp_port: sl.resp_port,
            proto: sl.proto,
            contents: sl.contents,
        })
    }
}

async fn handle_secu_log_raw_events(
    ctx: &Context<'_>,
    filter: SecuLogFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, SecuLogRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.secu_log_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

#[Object]
impl SecurityLogQuery {
    #[allow(clippy::too_many_arguments)]
    async fn secu_log_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SecuLogFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, SecuLogRawEvent>> {
        let handler = handle_secu_log_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            SecuLogRawEvents,
            secu_log_raw_events::Variables,
            secu_log_raw_events::ResponseData,
            secu_log_raw_events
        )
    }
}

#[cfg(feature = "cluster")]
macro_rules! impl_from_giganto_secu_log_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<SecuLogFilter> for $autogen_mod::SecuLogFilter {
                fn from(filter: SecuLogFilter) -> Self {
                    Self {
                        time : filter.time.map(Into::into),
                        sensor : filter.sensor,
                        kind : filter.kind,
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                        log : filter.log,
                    }
                }
            }
        )*
    };
}

#[cfg(feature = "cluster")]
impl_from_giganto_range_structs_for_graphql_client!(secu_log_raw_events);
#[cfg(feature = "cluster")]
impl_from_giganto_secu_log_filter_for_graphql_client!(secu_log_raw_events);

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use giganto_client::ingest::log::SecuLog;

    use crate::graphql::tests::TestSchema;
    use crate::storage::RawEventStore;

    #[tokio::test]
    async fn test_secu_log_event() {
        let schema = TestSchema::new();
        let store = schema.db.secu_log_store().unwrap();

        insert_secu_log_event(&store, "device", "src1", 1);
        insert_secu_log_event(&store, "device", "src 1", 2);

        let query = r#"
        {
            secuLogRawEvents(
                filter: {
                    kind: "device",
                    sensor: "src1"
                }
            ) {
                edges {
                    node {
                        contents,
                        version
                    }
                }
            }
        }"#;

        let res = schema.execute(query).await;

        assert_eq!(
            res.data.to_string(),
            "{secuLogRawEvents: {edges: [{node: {contents: \"secu_log_contents 1\", version: \"V3\"}}]}}"
        );
    }

    #[tokio::test]
    async fn test_secu_log_event_giganto_cluster() {
        let query = r#"
        {
            secuLogRawEvents(
                filter: {
                    kind: "device",
                    sensor: "src2"
                }
            ) {
                edges {
                    node {
                        contents,
                        version
                    }
                }
            }
        }"#;

        let mut peer_server = mockito::Server::new_async().await;
        let peer_response_mock_data = r#"
        {
            "data": {
                "secuLogRawEvents": {
                    "pageInfo": {
                        "hasPreviousPage": false,
                        "hasNextPage": false
                    },
                    "edges": [
                        {
                            "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                            "node": {
                                "time": "2023-11-16T15:03:45.291779203+00:00",
                                "sensor": "src2",
                                "logType": "cisco",
                                "version": "V3",
                                "proto": 6,
                                "contents": "peer_giganto_contents 1"
                            }
                        }
                    ]
                }
            }
        }
        "#;

        let mock = peer_server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_body(peer_response_mock_data)
            .create();

        let peer_port = peer_server
            .host_with_port()
            .parse::<SocketAddr>()
            .expect("Port must exist")
            .port();
        let schema = TestSchema::new_with_graphql_peer(peer_port);

        let res = schema.execute(query).await;

        assert_eq!(
            res.data.to_string(),
            "{secuLogRawEvents: {edges: [{node: {contents: \"peer_giganto_contents 1\", version: \"V3\"}}]}}"
        );

        mock.assert_async().await;
    }

    fn insert_secu_log_event(
        store: &RawEventStore<SecuLog>,
        kind: &str,
        sensor: &str,
        timestamp: i64,
    ) {
        let mut key: Vec<u8> = Vec::new();
        key.extend_from_slice(sensor.as_bytes());
        key.push(0);
        key.extend_from_slice(kind.as_bytes());
        key.push(0);
        key.extend_from_slice(&timestamp.to_be_bytes());

        let secu_log_body = SecuLog {
            kind: kind.to_string(),
            log_type: "cisco".to_string(),
            version: "V3".to_string(),
            orig_addr: None,
            orig_port: None,
            resp_addr: None,
            resp_port: None,
            proto: None,
            contents: format!("secu_log_contents {timestamp}").to_string(),
        };
        let value = bincode::serialize(&secu_log_body).unwrap();

        store.append(&key, &value).unwrap();
    }
}
