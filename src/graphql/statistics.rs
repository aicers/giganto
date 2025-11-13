#![allow(clippy::module_name_repetitions)]

use std::{
    collections::{HashMap, HashSet},
    iter::Peekable,
    str::FromStr,
};

use anyhow::anyhow;
#[cfg(feature = "count_events")]
use async_graphql::Enum;
use async_graphql::{Context, Object, Result, SimpleObject};
use giganto_client::{RawEventKind, ingest::statistics::Statistics};
#[cfg(feature = "cluster")]
use giganto_proc_macro::ConvertGraphQLEdgesNode;
#[cfg(feature = "cluster")]
use graphql_client::GraphQLQuery;
use num_traits::NumCast;
use rocksdb::Direction;
use serde::de::DeserializeOwned;
use tracing::warn;

use super::TIMESTAMP_SIZE;
#[cfg(feature = "cluster")]
use crate::graphql::client::{
    cluster::impl_from_giganto_time_range_struct_for_graphql_client,
    derives::{Statistics as Stats, statistics as stats},
};
use crate::{
    graphql::{StringNumberI64, TimeRange, events_in_cluster},
    storage::{Database, RawEventStore, StatisticsIter, StorageKey},
};

pub const MAX_CORE_SIZE: u32 = 16; // Number of queues on the collect device's NIC
const BYTE_TO_BIT: u64 = 8;
const STATS_ALLOWED_KINDS: [RawEventKind; 20] = [
    RawEventKind::Conn,
    RawEventKind::Dns,
    RawEventKind::MalformedDns,
    RawEventKind::Radius,
    RawEventKind::Rdp,
    RawEventKind::Http,
    RawEventKind::Smtp,
    RawEventKind::Ntlm,
    RawEventKind::Kerberos,
    RawEventKind::Ssh,
    RawEventKind::DceRpc,
    RawEventKind::Ftp,
    RawEventKind::Mqtt,
    RawEventKind::Ldap,
    RawEventKind::Tls,
    RawEventKind::Smb,
    RawEventKind::Nfs,
    RawEventKind::Bootp,
    RawEventKind::Dhcp,
    RawEventKind::Statistics,
];

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    stats::StatisticsStatistics
]))]
pub struct StatisticsRawEvent {
    pub sensor: String,
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    pub stats: Vec<StatisticsInfo>,
}

#[derive(SimpleObject, Debug, Clone)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    stats::StatisticsStatisticsStats
]))]
pub struct StatisticsInfo {
    pub timestamp: StringNumberI64,
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    pub detail: Vec<StatisticsDetail>,
}

#[derive(SimpleObject, Debug, Default, Clone)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    stats::StatisticsStatisticsStatsDetail
]))]
pub struct StatisticsDetail {
    pub protocol: String,
    pub bps: Option<f64>,
    pub pps: Option<f64>,
    pub eps: Option<f64>,
}

#[cfg(feature = "count_events")]
#[derive(Enum, Copy, Clone, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// Session(connection) events
    Session,
    /// DNS events
    Dns,
    /// HTTP events
    Http,
}

#[derive(Default)]
pub(super) struct StatisticsQuery;

async fn handle_statistics(
    ctx: &Context<'_>,
    sensors: &Vec<String>,
    time: Option<&TimeRange>,
    protocols: Option<&Vec<String>>,
) -> Result<Vec<StatisticsRawEvent>> {
    let db = ctx.data::<Database>()?;
    let mut total_stats: Vec<StatisticsRawEvent> = Vec::new();
    let mut stats_iters: Vec<Peekable<StatisticsIter<'_, Statistics>>> = Vec::new();

    // Configure the protocol HashSet for which statistics output is allowed.
    let raw_event_kinds = if let Some(protocols) = protocols {
        let mut records = HashSet::new();
        for proto in protocols {
            records.insert(convert_to_stats_allowed_type(proto)?);
        }
        records
    } else {
        STATS_ALLOWED_KINDS.into_iter().collect()
    };

    // Configure statistics results by sensor.
    for sensor in sensors {
        for core in 0..MAX_CORE_SIZE {
            let stats_iter = get_statistics_iter(&db.statistics_store()?, core, sensor, time);
            let mut peek_stats_iter = stats_iter.peekable();
            if peek_stats_iter.peek().is_some() {
                stats_iters.push(peek_stats_iter);
            }
        }
        let stats = gen_statistics(&mut stats_iters, sensor, time.is_none(), &raw_event_kinds)?;
        total_stats.push(stats);
    }
    Ok(total_stats)
}

#[Object]
impl StatisticsQuery {
    async fn statistics(
        &self,
        ctx: &Context<'_>,
        sensors: Vec<String>,
        time: Option<TimeRange>,
        protocols: Option<Vec<String>>,
        #[allow(unused_variables)] request_from_peer: Option<bool>,
    ) -> Result<Vec<StatisticsRawEvent>> {
        let handler = handle_statistics;

        events_in_cluster!(
            multiple_sensors
            ctx,
            sensors,
            request_from_peer,
            handler,
            Stats,
            stats::Variables,
            stats::ResponseData,
            statistics,
            Vec<StatisticsRawEvent>,
            with_extra_handler_args (time.as_ref(), protocols.as_ref()),
            with_extra_query_args (time := time.clone().map(Into::into), protocols := protocols.clone() )
        )
    }

    /// Returns the exact number of events stored for the given protocol.
    ///
    /// This API is intended for quality checks and testing, not for production hot paths.
    /// It may take significant time on large datasets as it iterates over all keys.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The database connection fails
    /// * The specified column family is not found
    /// * The feature flag `count_events` is not enabled
    #[cfg(feature = "count_events")]
    #[allow(clippy::unused_async)]
    async fn count_by_protocol(&self, ctx: &Context<'_>, protocol: Protocol) -> Result<i32> {
        tracing::info!("Counting events for protocol: {protocol:?}");
        let db = ctx.data::<Database>()?;
        let n = count_cf_snapshot(db, protocol)?;
        Ok(n)
    }
}

#[cfg(feature = "cluster")]
impl_from_giganto_time_range_struct_for_graphql_client!(stats);

/// Counts the exact number of keys in a column family using a snapshot.
///
/// This function creates a database snapshot and iterates over all keys in the specified
/// protocol's column family to return an exact count. This operation can be expensive
/// on large datasets and is intended for testing and quality assurance purposes.
///
/// # Arguments
///
/// * `db` - The database instance
/// * `protocol` - The protocol type to count events for
///
/// # Returns
///
/// Returns the exact count of events for the specified protocol.
///
/// # Errors
///
/// This function will return an error if:
/// * The column family for the specified protocol is not found
/// * Database access fails during snapshot creation or iteration
#[cfg(feature = "count_events")]
fn count_cf_snapshot(db: &Database, protocol: Protocol) -> Result<i32> {
    let cf_name = match protocol {
        Protocol::Session => "conn",
        Protocol::Dns => "dns",
        Protocol::Http => "http",
    };

    Ok(db.count_cf_entries(cf_name)?)
}

fn get_statistics_iter<'c, T>(
    store: &RawEventStore<'c, T>,
    core_id: u32,
    sensor: &str,
    time: Option<&TimeRange>,
) -> StatisticsIter<'c, T>
where
    T: DeserializeOwned,
{
    let (start, end) = if let Some(time) = &time {
        (time.start, time.end)
    } else {
        (None, None)
    };

    let key_builder = StorageKey::builder()
        .start_key(sensor)
        .mid_key(Some(core_id.to_be_bytes().to_vec()));
    let from_key = key_builder.clone().upper_closed_bound_end_key(end).build();
    let to_key = key_builder.lower_closed_bound_end_key(start).build();
    let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Reverse);
    StatisticsIter::new(iter)
}

fn gen_statistics(
    stats_iters: &mut Vec<Peekable<StatisticsIter<'_, Statistics>>>,
    sensor: &str,
    latest_flag: bool,
    allowed_raw_event_kinds: &HashSet<RawEventKind>,
) -> Result<StatisticsRawEvent> {
    let mut stats_info_vec: Vec<StatisticsInfo> = Vec::new();
    let mut stats_detail_vec: Vec<StatisticsDetail> = Vec::new();
    let mut iter_next_values: Vec<(Box<[u8]>, Statistics)> = Vec::with_capacity(stats_iters.len());

    for iter in &mut *stats_iters {
        if let Some(item) = iter.next() {
            iter_next_values.push(item);
        }
    }

    loop {
        let mut next_candidate = Vec::new();

        // Find the most recent statistics in iter by core.
        let check_latest_values = iter_next_values.clone();
        let Some((latest_key, latest_stats)) = check_latest_values
            .iter()
            .max_by_key(|(key, _)| &key[(key.len() - TIMESTAMP_SIZE)..])
        else {
            break;
        };

        let latest_key_timestamp =
            i64::from_be_bytes(latest_key[(latest_key.len() - TIMESTAMP_SIZE)..].try_into()?);
        let mut total_stats: HashMap<RawEventKind, (u64, u64)> = HashMap::new();

        // Collect statistics formed at the same timestamp as the most recent statistics into a HashMap.
        for (idx, (key, value)) in iter_next_values.clone().iter().enumerate() {
            let compare_key_timestamp =
                i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
            if latest_key_timestamp == compare_key_timestamp {
                for (record, count, size) in &value.stats {
                    if allowed_raw_event_kinds.contains(record) {
                        total_stats
                            .entry(*record)
                            .and_modify(|(stats_count, stats_size)| {
                                *stats_count += count;
                                *stats_size += size;
                            })
                            .or_insert((*count, *size));
                    }
                }
                next_candidate.push(idx);
            }
        }
        next_candidate.reverse();

        // Change the value of the selected iter to the following value.
        for idx in next_candidate {
            if let Some(iter) = stats_iters.get_mut(idx) {
                if let Some(item) = iter.next() {
                    *iter_next_values.get_mut(idx).expect("`next_candidate` is generated during iteration over `iter_next_values`, ensuring all its indices are valid within the latter.") = item;
                } else {
                    // No value to call with the iterator.
                    let _ = stats_iters.remove(idx);
                    let _ = iter_next_values.remove(idx);
                }
            }
        }

        // Generates StatisticsDetail by calculating the bps/pps/eps.
        for (r_type, (count, size)) in total_stats {
            let mut stats_detail = StatisticsDetail {
                protocol: format!("{r_type:?}"),
                ..Default::default()
            };
            if r_type == RawEventKind::Statistics {
                stats_detail.bps = Some(calculate_ps(latest_stats.period, size * BYTE_TO_BIT)); // convert to bit size
                stats_detail.pps = Some(calculate_ps(latest_stats.period, count));
            } else {
                stats_detail.eps = Some(calculate_ps(latest_stats.period, count));
            }
            stats_detail_vec.push(stats_detail);
        }

        stats_info_vec.push(StatisticsInfo {
            timestamp: latest_key_timestamp.into(),
            detail: stats_detail_vec.clone(),
        });
        stats_detail_vec.clear();

        // If there is no time condition, only the most recent statistics are passed.
        if latest_flag {
            break;
        }
    }

    Ok(StatisticsRawEvent {
        sensor: sensor.to_string(),
        stats: stats_info_vec,
    })
}

fn convert_to_stats_allowed_type(input: &str) -> Result<RawEventKind> {
    let raw_event_kind = RawEventKind::from_str(input).unwrap_or_default();
    if STATS_ALLOWED_KINDS.contains(&raw_event_kind) {
        Ok(raw_event_kind)
    } else {
        Err(anyhow!("not allowed RawEventKind string: {input}").into())
    }
}

fn calculate_ps(period: u16, len: u64) -> f64 {
    if let (Some(len), Some(period)) = (NumCast::from(len), NumCast::from(period)) {
        let cal_len: f64 = len;
        let cal_period: f64 = period;
        let cal_result = format!("{:.2}", cal_len / cal_period);
        if let Ok(result) = cal_result.parse::<f64>() {
            return result;
        }
    }
    warn!("Failed to convert period/len to f64, using default value");
    0.0
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use chrono::Utc;
    use giganto_client::{RawEventKind, ingest::statistics::Statistics};

    #[cfg(feature = "count_events")]
    use crate::graphql::network::tests::{
        insert_conn_raw_event, insert_dns_raw_event, insert_http_raw_event,
    };
    use crate::{bincode_utils, graphql::tests::TestSchema, storage::RawEventStore};

    #[tokio::test]
    async fn test_statistics() {
        let schema = TestSchema::new();
        let store = schema.db.statistics_store().unwrap();
        let now = Utc::now().timestamp_nanos_opt().unwrap();
        let expected_timestamp = now.to_string();
        insert_statistics_raw_event(&store, now, "src 1", 0, 600, 1_000_000, 300_000_000);
        insert_statistics_raw_event(&store, now, "src 1", 1, 600, 2_000_000, 600_000_000);
        insert_statistics_raw_event(&store, now, "src 1", 2, 600, 3_000_000, 900_000_000);

        let query = r#"
    {
        statistics(
            sensors: ["src 1"]
        ) {
            sensor,
            stats {
                timestamp,
                detail {
                    protocol,
                    bps,
                    pps,
                }
            }
        }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            format!(
                "{{statistics: [{{sensor: \"src 1\", stats: [{{timestamp: \"{expected_timestamp}\", detail: \
                 [{{protocol: \"Statistics\", bps: 24000000.0, pps: 10000.0}}]}}]}}]}}"
            )
        );
    }

    fn insert_statistics_raw_event(
        store: &RawEventStore<Statistics>,
        timestamp: i64,
        sensor: &str,
        core: u32,
        period: u16,
        count: u64,
        size: u64,
    ) {
        let mut key = Vec::with_capacity(sensor.len() + 1 + std::mem::size_of::<i64>());
        key.extend_from_slice(sensor.as_bytes());
        key.push(0);
        key.extend_from_slice(&core.to_be_bytes());
        key.push(0);
        key.extend_from_slice(&timestamp.to_be_bytes());

        let msg = Statistics {
            core,
            period,
            stats: vec![(RawEventKind::Statistics, count, size)],
        };
        let msg = bincode_utils::encode_legacy(&msg).unwrap();
        store.append(&key, &msg).unwrap();
    }

    #[tokio::test]
    async fn test_statistics_giganto_cluster() {
        // given
        let query = r#"
        {
            statistics(
                sensors: ["src 2"]
            ) {
                sensor,
                stats {
                    timestamp,
                    detail {
                        protocol,
                        bps,
                        pps,
                    }
                }
            }
        }"#;

        let mut peer_server = mockito::Server::new_async().await;
        let peer_response_mock_data = r#"
        {
            "data": {
                "statistics": [
                    {
                        "sensor": "src 2",
                        "stats": [
                            {
                                "timestamp": "1702272566",
                                "detail": [
                                    {
                                        "protocol": "Statistics",
                                        "bps": 24000000.0,
                                        "pps": 10000.0,
                                        "eps": 12413.1
                                    }
                                ]
                            }
                        ]
                    }
                ]
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

        // when
        let res = schema.execute(query).await;

        // then
        assert_eq!(
            res.data.to_string(),
            "{statistics: [{sensor: \"src 2\", stats: [{timestamp: \"1702272566\", detail: [{protocol: \"Statistics\", bps: 24000000.0, pps: 10000.0}]}]}]}"
        );

        mock.assert_async().await;
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_statistics_giganto_cluster_combined() {
        // given
        let query = r#"
        {
            statistics(
                sensors: ["src 2", "src2", "ingest src 2", "src 1"]
            ) {
                sensor,
                stats {
                    timestamp
                    detail {
                        protocol,
                        bps,
                        pps,
                    }
                }
            }
        }"#;

        let mut peer_server = mockito::Server::new_async().await;
        let peer_response_mock_data = r#"
        {
            "data": {
                "statistics": [
                    {
                        "sensor": "src2",
                        "stats": [
                            {
                                "timestamp": "1702272560",
                                "detail": [
                                    {
                                        "protocol": "Statistics",
                                        "bps": 24000000.0,
                                        "pps": 10000.0,
                                        "eps": 12413.1
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "sensor": "ingest src 2",
                        "stats": [
                            {
                                "timestamp": "1702272560",
                                "detail": [
                                    {
                                        "protocol": "Statistics",
                                        "bps": 24000000.0,
                                        "pps": 10000.0,
                                        "eps": 12413.1
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "sensor": "src 2",
                        "stats": [
                            {
                                "timestamp": "1702272560",
                                "detail": [
                                    {
                                        "protocol": "Statistics",
                                        "bps": 24000000.0,
                                        "pps": 10000.0,
                                        "eps": 12413.1
                                    }
                                ]
                            }
                        ]
                    }
                ]
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

        let store = schema.db.statistics_store().unwrap();
        let timestamp: i64 = 1_702_272_560;

        insert_statistics_raw_event(&store, timestamp, "src 1", 0, 600, 1_000_000, 300_000_000);
        insert_statistics_raw_event(&store, timestamp, "src 1", 1, 600, 2_000_000, 600_000_000);
        insert_statistics_raw_event(&store, timestamp, "src 1", 2, 600, 3_000_000, 900_000_000);

        // when
        let res = schema.execute(query).await;

        // then
        assert_eq!(
            res.data.to_string(),
            "{statistics: [{sensor: \"src2\", stats: [{timestamp: \"1702272560\", detail: \
            [{protocol: \"Statistics\", bps: 24000000.0, pps: 10000.0}]}]}, {sensor: \"ingest src \
             2\", stats: [{timestamp: \"1702272560\", detail: [{protocol: \"Statistics\", \
             bps: 24000000.0, pps: 10000.0}]}]}, {sensor: \"src 2\", stats: [{timestamp: \
             \"1702272560\", detail: [{protocol: \"Statistics\", bps: 24000000.0, pps: 10000.0}]}]}\
             , {sensor: \"src 1\", stats: [{timestamp: \"1702272560\", detail: [{protocol: \
             \"Statistics\", bps: 24000000.0, pps: 10000.0}]}]}]}"
        );

        mock.assert_async().await;
    }

    #[cfg(feature = "count_events")]
    #[tokio::test]
    async fn test_count_by_protocol_empty_db() {
        let schema = TestSchema::new();

        let query = r"
            query {
                countByProtocol(protocol: SESSION)
            }";

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);

        let json = serde_json::to_value(&res.data).unwrap();
        let count_result = json
            .get("countByProtocol")
            .and_then(serde_json::Value::as_i64)
            .expect("countByProtocol should be an integer");

        assert_eq!(count_result, 0, "SESSION on empty DB must be 0");

        let query = r"
            query {
                countByProtocol(protocol: DNS)
            }";

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);

        let json = serde_json::to_value(&res.data).unwrap();
        let count_result = json
            .get("countByProtocol")
            .and_then(serde_json::Value::as_i64)
            .expect("countByProtocol should be an integer");

        assert_eq!(count_result, 0, "DNS on empty DB must be 0");

        let query = r"
            query {
                countByProtocol(protocol: HTTP)
            }
        ";

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);

        let json = serde_json::to_value(&res.data).unwrap();
        let count_result = json
            .get("countByProtocol")
            .and_then(serde_json::Value::as_i64)
            .expect("countByProtocol should be an integer");

        assert_eq!(count_result, 0, "HTTP on empty DB must be 0");
    }

    #[cfg(feature = "count_events")]
    #[tokio::test]
    async fn test_count_by_protocol_basic() {
        let schema = TestSchema::new();

        let conn_store = schema.db.conn_store().unwrap();
        let dns_store = schema.db.dns_store().unwrap();
        let http_store = schema.db.http_store().unwrap();

        let now = Utc::now().timestamp_nanos_opt().unwrap();

        // Insert into each CF:
        //   SESSION -> 5 events
        //   DNS     -> 7 events
        //   HTTP    -> 9 events
        for i in 0..5 {
            let sensor = format!("sensor{i}");
            insert_conn_raw_event(&conn_store, &sensor, now + i);
        }

        for i in 0..7 {
            let sensor = format!("sensor{i}");
            insert_dns_raw_event(&dns_store, &sensor, now + i);
        }

        for i in 0..9 {
            let sensor = format!("sensor{i}");
            insert_http_raw_event(&http_store, &sensor, now + i);
        }

        let query = r"
            query {
                countByProtocol(protocol: SESSION)
            }";

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        let json = serde_json::to_value(&res.data).unwrap();
        let count_result = json
            .get("countByProtocol")
            .and_then(serde_json::Value::as_i64)
            .expect("countByProtocol should be an integer");
        assert_eq!(count_result, 5, "SESSION count must be 5");

        let query = r"
            query {
                countByProtocol(protocol: DNS)
            }";

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        let json = serde_json::to_value(&res.data).unwrap();
        let count_result = json
            .get("countByProtocol")
            .and_then(serde_json::Value::as_i64)
            .expect("countByProtocol should be an integer");
        assert_eq!(count_result, 7, "DNS count must be 7");

        let query = r"
            query {
                countByProtocol(protocol: HTTP)
            }";

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        let json = serde_json::to_value(&res.data).unwrap();
        let count_result = json
            .get("countByProtocol")
            .and_then(serde_json::Value::as_i64)
            .expect("countByProtocol should be an integer");
        assert_eq!(count_result, 9, "HTTP count must be 9");
    }
}
