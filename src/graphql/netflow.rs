use std::{fmt::Debug, net::IpAddr};

use async_graphql::{Context, InputObject, Object, Result, SimpleObject, connection::Connection};
use chrono::{DateTime, Utc};
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
#[cfg(feature = "cluster")]
use giganto_proc_macro::ConvertGraphQLEdgesNode;
#[cfg(feature = "cluster")]
use graphql_client::GraphQLQuery;

use super::{
    FromKeyValue, IpRange, PortRange, check_address, check_contents, check_port, get_time_from_key,
    handle_paged_events, paged_events_in_cluster,
};
#[cfg(feature = "cluster")]
use crate::graphql::client::{
    cluster::impl_from_giganto_range_structs_for_graphql_client,
    derives::{Netflow5RawEvents, Netflow9RawEvents, netflow5_raw_events, netflow9_raw_events},
};
use crate::{
    graphql::{RawEventFilter, StringNumberU32, TimeRange},
    storage::{Database, KeyExtractor},
};

static TCP_FLAGS: [(u8, &str); 8] = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x08, "CWR"),
];

#[derive(Default)]
pub(super) struct NetflowQuery;

#[derive(InputObject, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct NetflowFilter {
    time: Option<TimeRange>,
    sensor: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    contents: Option<String>,
}

impl KeyExtractor for NetflowFilter {
    fn get_start_key(&self) -> &str {
        &self.sensor
    }

    fn get_mid_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_range_end_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }
}

impl RawEventFilter for NetflowFilter {
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
            && check_contents(self.contents.as_deref(), log_contents)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    netflow5_raw_events::Netflow5RawEventsNetflow5RawEventsEdgesNode
]))]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow5RawEvent {
    time: DateTime<Utc>,
    src_addr: String,
    dst_addr: String,
    next_hop: String,
    input: u16,
    output: u16,
    d_pkts: StringNumberU32,
    d_octets: StringNumberU32,
    first: String, // milliseconds
    last: String,  // milliseconds
    src_port: u16,
    dst_port: u16,
    tcp_flags: String,
    prot: u8,
    tos: String, // Hex
    src_as: u16,
    dst_as: u16,
    src_mask: u8,
    dst_mask: u8,
    sequence: StringNumberU32,
    engine_type: u8,
    engine_id: u8,
    sampling_mode: String,
    sampling_rate: u16,
}

impl FromKeyValue<Netflow5> for Netflow5RawEvent {
    fn from_key_value(key: &[u8], val: Netflow5) -> Result<Self> {
        Ok(Netflow5RawEvent {
            time: get_time_from_key(key)?,
            src_addr: val.src_addr.to_string(),
            dst_addr: val.dst_addr.to_string(),
            next_hop: val.next_hop.to_string(),
            input: val.input,
            output: val.output,
            d_pkts: val.d_pkts.into(),
            d_octets: val.d_octets.into(),
            first: millis_to_secs(val.first),
            last: millis_to_secs(val.last),
            src_port: val.src_port,
            dst_port: val.dst_port,
            tcp_flags: tcp_flags(val.tcp_flags),
            prot: val.prot,
            tos: format!("{:x}", val.tos),
            src_as: val.src_as,
            dst_as: val.dst_as,
            src_mask: val.src_mask,
            dst_mask: val.dst_mask,
            sequence: val.sequence.into(),
            engine_type: val.engine_type,
            engine_id: val.engine_id,
            sampling_mode: format!("{:x}", val.sampling_mode),
            sampling_rate: val.sampling_rate,
        })
    }
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    netflow9_raw_events::Netflow9RawEventsNetflow9RawEventsEdgesNode
]))]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow9RawEvent {
    time: DateTime<Utc>,
    sequence: StringNumberU32,
    source_id: StringNumberU32,
    template_id: u16,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    contents: String,
}

impl FromKeyValue<Netflow9> for Netflow9RawEvent {
    fn from_key_value(key: &[u8], val: Netflow9) -> Result<Self> {
        Ok(Netflow9RawEvent {
            time: get_time_from_key(key)?,
            sequence: val.sequence.into(),
            source_id: val.source_id.into(),
            template_id: val.template_id,
            orig_addr: val.orig_addr.to_string(),
            orig_port: val.orig_port,
            resp_addr: val.resp_addr.to_string(),
            resp_port: val.resp_port,
            proto: val.proto,
            contents: val.contents,
        })
    }
}

pub(crate) fn millis_to_secs(millis: u32) -> String {
    format!("{}.{}", millis / 1000, millis - (millis / 1000) * 1000)
}

pub(crate) fn tcp_flags(b: u8) -> String {
    let mut res = String::new();
    for e in &TCP_FLAGS {
        if b & e.0 == e.0 {
            res.push_str(e.1);
            res.push('-');
        }
    }
    if res.is_empty() {
        res.push_str("None");
    }

    if res.ends_with('-') {
        res.pop();
    }
    res
}

async fn handle_netflow5_raw_events(
    ctx: &Context<'_>,
    filter: NetflowFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, Netflow5RawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.netflow5_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_netflow9_raw_events(
    ctx: &Context<'_>,
    filter: NetflowFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, Netflow9RawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.netflow9_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

#[Object]
impl NetflowQuery {
    #[allow(clippy::too_many_arguments)]
    async fn netflow5_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetflowFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Netflow5RawEvent>> {
        let handler = handle_netflow5_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            Netflow5RawEvents,
            netflow5_raw_events::Variables,
            netflow5_raw_events::ResponseData,
            netflow5_raw_events
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn netflow9_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetflowFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Netflow9RawEvent>> {
        let handler = handle_netflow9_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            Netflow9RawEvents,
            netflow9_raw_events::Variables,
            netflow9_raw_events::ResponseData,
            netflow9_raw_events
        )
    }
}

#[cfg(feature = "cluster")]
macro_rules! impl_from_giganto_netflow_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<NetflowFilter> for $autogen_mod::NetflowFilter {
                fn from(filter: NetflowFilter) -> Self {
                    Self {
                        time: filter.time.map(Into::into),
                        sensor: filter.sensor,
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                        contents: filter.contents,
                    }
                }
            }
        )*
    };
}
#[cfg(feature = "cluster")]
impl_from_giganto_range_structs_for_graphql_client!(netflow5_raw_events, netflow9_raw_events);
#[cfg(feature = "cluster")]
impl_from_giganto_netflow_filter_for_graphql_client!(netflow5_raw_events, netflow9_raw_events);

#[cfg(test)]
mod tests {
    use std::{
        mem,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use chrono::{DateTime, TimeZone, Utc};
    use giganto_client::ingest::netflow::{Netflow5, Netflow9};
    use serde::Serialize;
    use serde_json::{Value, json};

    use super::{millis_to_secs, tcp_flags};
    use crate::{bincode_utils::encode_legacy, graphql::tests::TestSchema, storage::RawEventStore};

    const SENSOR: &str = "src 1";
    const NETFLOW5_NODE_FIELDS: &str = r"
                        time
                        srcAddr
                        dstAddr
                        nextHop
                        input
                        output
                        dPkts
                        dOctets
                        first
                        last
                        srcPort
                        dstPort
                        tcpFlags
                        prot
                        tos
                        srcAs
                        dstAs
                        srcMask
                        dstMask
                        sequence
                        engineType
                        engineId
                        samplingMode
                        samplingRate
    ";
    const NETFLOW9_NODE_FIELDS: &str = r"
                        time
                        sequence
                        sourceId
                        templateId
                        origAddr
                        origPort
                        respAddr
                        respPort
                        proto
                        contents
    ";

    fn timestamp_ns(timestamp: DateTime<Utc>) -> i64 {
        timestamp.timestamp_nanos_opt().unwrap()
    }

    fn sample_timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 0).unwrap()
    }

    fn append_event<T: Serialize>(
        store: &RawEventStore<'_, T>,
        sensor: &str,
        timestamp: i64,
        event: &T,
    ) {
        let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(sensor.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let serialized = encode_legacy(event).unwrap();
        store.append(&key, &serialized).unwrap();
        store.flush().unwrap();
    }

    fn sample_netflow5() -> Netflow5 {
        Netflow5 {
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            input: 1,
            output: 2,
            d_pkts: 42,
            d_octets: 2048,
            first: 1_500,
            last: 2_000,
            src_port: 1_500,
            dst_port: 80,
            tcp_flags: 0x12,
            prot: 6,
            tos: 0x1e,
            src_as: 10,
            dst_as: 20,
            src_mask: 24,
            dst_mask: 24,
            sequence: 7,
            engine_type: 0,
            engine_id: 1,
            sampling_mode: 0x01,
            sampling_rate: 512,
        }
    }

    fn sample_netflow9() -> Netflow9 {
        Netflow9 {
            sequence: 11,
            source_id: 22,
            template_id: 256,
            orig_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            orig_port: 5_000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)),
            resp_port: 53,
            proto: 17,
            contents: "dns query response allowed".to_string(),
        }
    }

    fn insert_netflow5_event(store: &RawEventStore<'_, Netflow5>, sensor: &str, timestamp: i64) {
        append_event(store, sensor, timestamp, &sample_netflow5());
    }

    fn insert_netflow9_event(store: &RawEventStore<'_, Netflow9>, sensor: &str, timestamp: i64) {
        append_event(store, sensor, timestamp, &sample_netflow9());
    }

    fn netflow_query(root_field: &str, filter_block: &str, node_fields: &str) -> String {
        format!(
            r"
            {{
                {root_field}(
                    filter: {{
                        {filter_block}
                    }}
                    first: 1
                ) {{
                    edges {{
                        node {{
                            {node_fields}
                        }}
                    }}
                }}
            }}
            "
        )
    }

    fn first_node(data: &Value, root: &str) -> Value {
        data[root]["edges"][0]["node"].clone()
    }

    fn expected_netflow5_node(time: &str) -> Value {
        let event = sample_netflow5();
        json!({
            "time": time,
            "srcAddr": event.src_addr.to_string(),
            "dstAddr": event.dst_addr.to_string(),
            "nextHop": event.next_hop.to_string(),
            "input": event.input,
            "output": event.output,
            "dPkts": event.d_pkts.to_string(),
            "dOctets": event.d_octets.to_string(),
            "first": millis_to_secs(event.first),
            "last": millis_to_secs(event.last),
            "srcPort": event.src_port,
            "dstPort": event.dst_port,
            "tcpFlags": tcp_flags(event.tcp_flags),
            "prot": event.prot,
            "tos": format!("{:x}", event.tos),
            "srcAs": event.src_as,
            "dstAs": event.dst_as,
            "srcMask": event.src_mask,
            "dstMask": event.dst_mask,
            "sequence": event.sequence.to_string(),
            "engineType": event.engine_type,
            "engineId": event.engine_id,
            "samplingMode": format!("{:x}", event.sampling_mode),
            "samplingRate": event.sampling_rate,
        })
    }

    fn expected_netflow9_node(time: &str) -> Value {
        let event = sample_netflow9();
        json!({
            "time": time,
            "sequence": event.sequence.to_string(),
            "sourceId": event.source_id.to_string(),
            "templateId": event.template_id,
            "origAddr": event.orig_addr.to_string(),
            "origPort": event.orig_port,
            "respAddr": event.resp_addr.to_string(),
            "respPort": event.resp_port,
            "proto": event.proto,
            "contents": event.contents,
        })
    }

    #[tokio::test]
    async fn netflow5_empty() {
        let schema = TestSchema::new();
        let query = netflow_query(
            "netflow5RawEvents",
            r#"
                    time: { start: "2020-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" }
                    sensor: "src 1"
                    origAddr: { start: "192.168.0.1", end: "192.168.0.255" }
                    respAddr: { start: "203.0.113.1", end: "203.0.113.255" }
                    origPort: { start: 1500, end: 1600 }
                    respPort: { start: 80, end: 90 }
            "#,
            NETFLOW5_NODE_FIELDS,
        );
        let res = schema.execute(&query).await;
        let data = res.data.into_json().unwrap();
        assert!(
            data["netflow5RawEvents"]["edges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn netflow5_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.netflow5_store().unwrap();

        let sample_time = sample_timestamp();
        let expected_time = sample_time.to_rfc3339();
        insert_netflow5_event(&store, SENSOR, timestamp_ns(sample_time));

        let query = netflow_query(
            "netflow5RawEvents",
            r#"
                    time: { start: "2020-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" }
                    sensor: "src 1"
                    origAddr: { start: "192.168.0.1", end: "192.168.0.255" }
                    respAddr: { start: "203.0.113.1", end: "203.0.113.255" }
                    origPort: { start: 1400, end: 1600 }
                    respPort: { start: 70, end: 90 }
            "#,
            NETFLOW5_NODE_FIELDS,
        );

        let res = schema.execute(&query).await;
        let data = res.data.into_json().unwrap();
        let node = first_node(&data, "netflow5RawEvents");
        assert_eq!(node, expected_netflow5_node(&expected_time));
    }

    #[tokio::test]
    async fn netflow5_time_precision() {
        use chrono::Duration;
        let schema = TestSchema::new();
        let store = schema.db.netflow5_store().unwrap();

        let ts = sample_timestamp() + Duration::nanoseconds(123_456_789);
        let expected_time = ts.to_rfc3339();
        insert_netflow5_event(&store, SENSOR, timestamp_ns(ts));

        let query = netflow_query(
            "netflow5RawEvents",
            r#"
                    time: { start: "2020-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" }
                    sensor: "src 1"
                    "#,
            "time",
        );

        let res = schema.execute(&query).await;
        let data = res.data.into_json().unwrap();
        let node = first_node(&data, "netflow5RawEvents");
        assert_eq!(node["time"], json!(expected_time));
    }

    #[tokio::test]
    async fn netflow5_with_data_giganto_cluster() {
        let query = netflow_query(
            "netflow5RawEvents",
            r#"
                    time: { start: "2020-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" }
                    sensor: "ingest src 2"
            "#,
            NETFLOW5_NODE_FIELDS,
        );

        let mut peer_server = mockito::Server::new_async().await;
        let peer_response_mock_data = r#"
        {
            "data": {
                "netflow5RawEvents": {
                    "pageInfo": {
                        "hasPreviousPage": false,
                        "hasNextPage": false
                    },
                    "edges": [
                        {
                            "cursor": "Y3Vyc29y",
                            "node": {
                                "time": "2023-10-11T00:00:00+00:00",
                                "srcAddr": "192.168.0.20",
                                "dstAddr": "203.0.113.10",
                                "nextHop": "192.168.0.1",
                                "input": 1,
                                "output": 2,
                                "dPkts": "10",
                                "dOctets": "1000",
                                "first": "1.0",
                                "last": "2.0",
                                "srcPort": 1234,
                                "dstPort": 8080,
                                "tcpFlags": "SYN",
                                "prot": 6,
                                "tos": "1a",
                                "srcAs": 64512,
                                "dstAs": 64513,
                                "srcMask": 24,
                                "dstMask": 24,
                                "sequence": "99",
                                "engineType": 1,
                                "engineId": 2,
                                "samplingMode": "1",
                                "samplingRate": 128
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

        let res = schema.execute(&query).await;
        let data = res.data.into_json().unwrap();
        let node = first_node(&data, "netflow5RawEvents");
        assert_eq!(
            node,
            json!({
                "time": "2023-10-11T00:00:00+00:00",
                "srcAddr": "192.168.0.20",
                "dstAddr": "203.0.113.10",
                "nextHop": "192.168.0.1",
                "input": 1,
                "output": 2,
                "dPkts": "10",
                "dOctets": "1000",
                "first": "1.0",
                "last": "2.0",
                "srcPort": 1234,
                "dstPort": 8080,
                "tcpFlags": "SYN",
                "prot": 6,
                "tos": "1a",
                "srcAs": 64512,
                "dstAs": 64513,
                "srcMask": 24,
                "dstMask": 24,
                "sequence": "99",
                "engineType": 1,
                "engineId": 2,
                "samplingMode": "1",
                "samplingRate": 128
            })
        );

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn netflow9_empty() {
        let schema = TestSchema::new();
        let query = netflow_query(
            "netflow9RawEvents",
            r#"
                    time: { start: "2020-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" }
                    sensor: "src 1"
                    origAddr: { start: "10.0.0.1", end: "10.0.0.255" }
                    respAddr: { start: "198.51.100.1", end: "198.51.100.255" }
                    origPort: { start: 4000, end: 6000 }
                    respPort: { start: 50, end: 60 }
                    contents: "dns"
            "#,
            NETFLOW9_NODE_FIELDS,
        );
        let res = schema.execute(&query).await;
        let data = res.data.into_json().unwrap();
        assert!(
            data["netflow9RawEvents"]["edges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn netflow9_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.netflow9_store().unwrap();

        let sample_time = sample_timestamp();
        let expected_time = sample_time.to_rfc3339();
        insert_netflow9_event(&store, SENSOR, timestamp_ns(sample_time));

        let query = netflow_query(
            "netflow9RawEvents",
            r#"
                    time: { start: "2020-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" }
                    sensor: "src 1"
                    origAddr: { start: "10.0.0.1", end: "10.0.0.255" }
                    respAddr: { start: "198.51.100.1", end: "198.51.100.255" }
                    origPort: { start: 4000, end: 6000 }
                    respPort: { start: 50, end: 60 }
                    contents: "dns query"
            "#,
            NETFLOW9_NODE_FIELDS,
        );

        let res = schema.execute(&query).await;
        let data = res.data.into_json().unwrap();
        let node = first_node(&data, "netflow9RawEvents");
        assert_eq!(node, expected_netflow9_node(&expected_time));
    }

    #[tokio::test]
    async fn netflow9_time_precision() {
        use chrono::Duration;
        let schema = TestSchema::new();
        let store = schema.db.netflow9_store().unwrap();

        let ts = sample_timestamp() + Duration::nanoseconds(987_654_321);
        let expected_time = ts.to_rfc3339();
        insert_netflow9_event(&store, SENSOR, timestamp_ns(ts));

        let query = netflow_query(
            "netflow9RawEvents",
            r#"
                    time: { start: "2020-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" }
                    sensor: "src 1"
            "#,
            "time",
        );

        let res = schema.execute(&query).await;
        let data = res.data.into_json().unwrap();
        let node = first_node(&data, "netflow9RawEvents");
        assert_eq!(node["time"], json!(expected_time));
    }

    #[tokio::test]
    async fn netflow9_with_data_giganto_cluster() {
        let query = netflow_query(
            "netflow9RawEvents",
            r#"
                    time: { start: "2020-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" }
                    sensor: "ingest src 2"
            "#,
            NETFLOW9_NODE_FIELDS,
        );

        let mut peer_server = mockito::Server::new_async().await;
        let peer_response_mock_data = r#"
        {
            "data": {
                "netflow9RawEvents": {
                    "pageInfo": {
                        "hasPreviousPage": false,
                        "hasNextPage": false
                    },
                    "edges": [
                        {
                            "cursor": "Y3Vyc29y",
                            "node": {
                                "time": "2023-10-11T00:00:00+00:00",
                                "sequence": "123",
                                "sourceId": "456",
                                "templateId": 512,
                                "origAddr": "10.0.1.1",
                                "origPort": 5001,
                                "respAddr": "198.51.100.10",
                                "respPort": 53,
                                "proto": 17,
                                "contents": "cluster dns summary"
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

        let res = schema.execute(&query).await;
        let data = res.data.into_json().unwrap();
        let node = first_node(&data, "netflow9RawEvents");
        assert_eq!(
            node,
            json!({
                "time": "2023-10-11T00:00:00+00:00",
                "sequence": "123",
                "sourceId": "456",
                "templateId": 512,
                "origAddr": "10.0.1.1",
                "origPort": 5001,
                "respAddr": "198.51.100.10",
                "respPort": 53,
                "proto": 17,
                "contents": "cluster dns summary"
            })
        );

        mock.assert_async().await;
    }
}
