use std::sync::{Arc, OnceLock};

use async_graphql::connection::Connection;
use base64::Engine;
use chrono::DateTime;
use giganto_client::ingest::log::{Log, OpLog, OpLogLevel};
use serde_json::json;

use super::{LogFilter, LogRawEvent, OpLogFilter, OpLogRawEvent, base64_engine};
use crate::comm::ingest::generation::SequenceGenerator;
use crate::graphql::load_connection;
use crate::{
    bincode_utils::encode_legacy,
    graphql::{TimeRange, tests::TestSchema},
    storage::RawEventStore,
};

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn load_time_range() {
    let schema = TestSchema::new();
    let store = schema.db.log_store().unwrap();

    insert_log_raw_event(&store, "src1", 1, "kind1", b"log1");
    insert_log_raw_event(&store, "src1", 2, "kind1", b"log2");
    insert_log_raw_event(&store, "src1", 3, "kind1", b"log3");
    insert_log_raw_event(&store, "src1", 4, "kind1", b"log4");
    insert_log_raw_event(&store, "src1", 5, "kind1", b"log5");

    let sensor = "src1";
    let kind = "kind1";

    let expected_1_2 = [b"log1".as_slice(), b"log2".as_slice()];
    let expected_2_3 = [b"log2".as_slice(), b"log3".as_slice()];
    let expected_1_3 = [b"log1".as_slice(), b"log2".as_slice(), b"log3".as_slice()];
    let expected_3_5 = [b"log3".as_slice(), b"log4".as_slice(), b"log5".as_slice()];
    let expected_4_5 = [b"log4".as_slice(), b"log5".as_slice()];
    let expected_1_5 = [
        b"log1".as_slice(),
        b"log2".as_slice(),
        b"log3".as_slice(),
        b"log4".as_slice(),
        b"log5".as_slice(),
    ];

    let cases = vec![
        LogPaginationCase::new(
            "backward start..end",
            (Some(1), Some(3)),
            None,
            None,
            None,
            Some(3),
            &expected_1_2,
        ),
        LogPaginationCase::new(
            "backward start..",
            (Some(3), None),
            None,
            None,
            None,
            Some(3),
            &expected_3_5,
        ),
        LogPaginationCase::new(
            "backward ..end",
            (None, Some(4)),
            None,
            None,
            None,
            Some(3),
            &expected_1_3,
        ),
        LogPaginationCase::new(
            "forward start..end",
            (Some(1), Some(3)),
            None,
            None,
            Some(3),
            None,
            &expected_1_2,
        ),
        LogPaginationCase::new(
            "forward start..",
            (Some(3), None),
            None,
            None,
            Some(3),
            None,
            &expected_3_5,
        ),
        LogPaginationCase::new(
            "forward ..end",
            (None, Some(3)),
            None,
            None,
            Some(3),
            None,
            &expected_1_2,
        ),
        LogPaginationCase::new(
            "backward start..end before cursor",
            (Some(1), Some(3)),
            None,
            Some(log_storage_key(sensor, kind, 3)),
            None,
            Some(3),
            &expected_1_2,
        ),
        LogPaginationCase::new(
            "backward start.. before cursor",
            (Some(2), None),
            None,
            Some(log_storage_key(sensor, kind, 4)),
            None,
            Some(3),
            &expected_2_3,
        ),
        LogPaginationCase::new(
            "backward ..end before cursor",
            (None, Some(5)),
            None,
            Some(log_storage_key(sensor, kind, 4)),
            None,
            Some(3),
            &expected_1_3,
        ),
        LogPaginationCase::new(
            "forward start..end after cursor",
            (Some(1), Some(4)),
            Some(log_storage_key(sensor, kind, 1)),
            None,
            Some(3),
            None,
            &expected_2_3,
        ),
        LogPaginationCase::new(
            "forward start.. after cursor",
            (Some(2), None),
            Some(log_storage_key(sensor, kind, 3)),
            None,
            None,
            None,
            &expected_4_5,
        ),
        LogPaginationCase::new(
            "forward ..end after cursor",
            (None, Some(4)),
            Some(log_storage_key(sensor, kind, 1)),
            None,
            None,
            None,
            &expected_2_3,
        ),
        LogPaginationCase::new(
            "forward ..",
            (None, None),
            None,
            None,
            None,
            None,
            &expected_1_5,
        ),
    ];

    for case in &cases {
        run_log_case(&store, sensor, kind, case);
    }
}

#[tokio::test]
async fn log_empty() {
    let schema = TestSchema::new();
    let query = r#"
        {
            logRawEvents (filter: {sensor: "cluml", kind: "Hello"}, first: 1) {
                edges {
                    node {
                        log
                    }
                }
            }
        }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{logRawEvents: {edges: []}}");
}

#[tokio::test]
async fn log_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.log_store().unwrap();

    insert_log_raw_event(&store, "src 1", 1, "kind 1", b"log 1");
    insert_log_raw_event(&store, "src 1", 2, "kind 2", b"log 2");

    let query = r#"
        {
            logRawEvents (filter: {sensor: "src 1", kind: "kind 1"}, first: 1) {
                edges {
                    node {
                        log,
                        time
                    }
                }
                pageInfo {
                    hasPreviousPage
                }
        }
    }"#;
    let res = schema.execute(query).await;
    let data = res.data.into_json().unwrap();
    let node = &data["logRawEvents"]["edges"][0]["node"];
    assert_eq!(
        node,
        &json!({
            "log": base64_engine.encode("log 1"),
            "time": chrono::DateTime::from_timestamp_nanos(1).to_rfc3339()
        })
    );
    assert_eq!(
        data["logRawEvents"]["pageInfo"]["hasPreviousPage"],
        json!(false)
    );
}

#[tokio::test]
async fn oplog_empty() {
    let schema = TestSchema::new();
    let query = r#"
        {
            opLogRawEvents (filter: {agentId: "giganto@src 1", logLevel: "Info", contents: ""}, first: 1) {
                edges {
                    node {
                        level,
                        contents
                    }
                }
            }
        }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{opLogRawEvents: {edges: []}}");
}

#[tokio::test]
async fn oplog_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.op_log_store().unwrap();
    let generator: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();
    insert_oplog_raw_event(&store, "giganto", "src1", 1, &generator);

    let query = r#"
        {
            opLogRawEvents (filter: {agentId: "giganto@src 1", logLevel: "Info"}, first: 1) {
                edges {
                    node {
                        level,
                        contents,
                        time,
                        agentName,
                        sensor
                    }
                }
            }
        }"#;
    let res = schema.execute(query).await;
    let data = res.data.into_json().unwrap();
    let node = &data["opLogRawEvents"]["edges"][0]["node"];
    assert_eq!(
        node,
        &json!({
            "level": "Info",
            "contents": "oplog",
            "time": chrono::DateTime::from_timestamp_nanos(1).to_rfc3339(),
            "agentName": "giganto@src 1",
            "sensor": "src1"
        })
    );
}

#[tokio::test]
async fn load_oplog() {
    let schema = TestSchema::new();
    let store = schema.db.op_log_store().unwrap();
    let generator: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();

    insert_oplog_raw_event(&store, "giganto", "src1", 1, &generator);
    insert_oplog_raw_event(&store, "giganto", "src1", 2, &generator);
    insert_oplog_raw_event(&store, "manager", "src1", 2, &generator);
    insert_oplog_raw_event(&store, "manager", "src1", 3, &generator);
    insert_oplog_raw_event(&store, "giganto", "src1", 3, &generator);
    insert_oplog_raw_event(&store, "giganto", "src1", 4, &generator);
    insert_oplog_raw_event(&store, "giganto", "src1", 5, &generator);
    insert_oplog_raw_event(&store, "manager", "src1", 5, &generator);
    insert_oplog_raw_event(&store, "aice", "src1", 5, &generator);

    let range_filter = op_log_filter((Some(5), Some(7)), None, None);
    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        &store,
        &range_filter,
        None,
        None,
        Some(5),
        None,
    )
    .unwrap();
    assert_oplog_payloads(connection, 3, "window 5..7 without cursors");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn load_connection_by_prefix_timestamp_key() {
    let schema = TestSchema::new();
    let store = schema.db.op_log_store().unwrap();
    let generator: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();
    let key_list: Vec<Vec<u8>> = vec![
        insert_oplog_raw_event(&store, "sensor", "src1", 1, &generator),
        insert_oplog_raw_event(&store, "sensor", "src1", 2, &generator),
        insert_oplog_raw_event(&store, "manager", "src1", 2, &generator),
        insert_oplog_raw_event(&store, "manager", "src1", 3, &generator),
        insert_oplog_raw_event(&store, "sensor", "src1", 3, &generator),
        insert_oplog_raw_event(&store, "sensor", "src1", 4, &generator),
        insert_oplog_raw_event(&store, "sensor", "src2", 5, &generator),
        insert_oplog_raw_event(&store, "sensor", "src2", 6, &generator),
        insert_oplog_raw_event(&store, "manager", "src1", 4, &generator),
        insert_oplog_raw_event(&store, "manager", "src2", 5, &generator),
    ];

    let manager_src1_filter = op_log_filter((Some(1), Some(10)), Some("manager"), Some("src1"));
    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        &store,
        &manager_src1_filter,
        None,
        None,
        Some(10),
        None,
    )
    .unwrap();
    assert_oplog_payloads(connection, 3, "manager@src1 without cursors");

    let after = key_list.get(3).unwrap();
    let after = base64_engine.encode(after);
    let manager_src1_filter = op_log_filter((Some(1), Some(10)), Some("manager"), Some("src1"));
    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        &store,
        &manager_src1_filter,
        Some(after),
        None,
        Some(10),
        None,
    )
    .unwrap();
    assert_oplog_payloads(connection, 1, "manager@src1 after cursor");

    let before = key_list.get(8).unwrap();
    let before = base64_engine.encode(before);
    let manager_src1_filter = op_log_filter((Some(1), Some(10)), Some("manager"), Some("src1"));
    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        &store,
        &manager_src1_filter,
        None,
        Some(before),
        None,
        Some(10),
    )
    .unwrap();
    assert_oplog_payloads(connection, 2, "manager@src1 before cursor");

    let sensor_src2_filter = op_log_filter((Some(1), Some(10)), Some("sensor"), Some("src2"));
    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        &store,
        &sensor_src2_filter,
        None,
        None,
        None,
        Some(10),
    )
    .unwrap();
    assert_oplog_payloads(connection, 2, "sensor@src2 full range");
}

struct LogPaginationCase<'a> {
    name: &'a str,
    range: (Option<i64>, Option<i64>),
    after: Option<Vec<u8>>,
    before: Option<Vec<u8>>,
    first: Option<usize>,
    last: Option<usize>,
    expected: &'a [&'a [u8]],
}

impl<'a> LogPaginationCase<'a> {
    fn new(
        name: &'a str,
        range: (Option<i64>, Option<i64>),
        after: Option<Vec<u8>>,
        before: Option<Vec<u8>>,
        first: Option<usize>,
        last: Option<usize>,
        expected: &'a [&'a [u8]],
    ) -> Self {
        Self {
            name,
            range,
            after,
            before,
            first,
            last,
            expected,
        }
    }
}

fn run_log_case(
    store: &RawEventStore<Log>,
    sensor: &str,
    kind: &str,
    case: &LogPaginationCase<'_>,
) {
    let (start, end) = case.range;
    let filter = LogFilter {
        time: Some(make_time_range(start, end)),
        sensor: sensor.to_string(),
        kind: Some(kind.to_string()),
    };

    let after_cursor = case
        .after
        .as_ref()
        .map(|cursor| base64_engine.encode(cursor));
    let before_cursor = case
        .before
        .as_ref()
        .map(|cursor| base64_engine.encode(cursor));

    let connection = load_connection::<LogRawEvent, _>(
        store,
        &filter,
        after_cursor,
        before_cursor,
        case.first,
        case.last,
    )
    .expect(case.name);

    assert_log_payloads(connection, case.expected, case.name);
}

fn assert_log_payloads(
    connection: Connection<String, LogRawEvent>,
    expected: &[&[u8]],
    label: &str,
) {
    let actual: Vec<Vec<u8>> = connection
        .edges
        .into_iter()
        .map(|edge| base64_engine.decode(edge.node.log).unwrap())
        .collect();
    let expected_payloads: Vec<Vec<u8>> = expected.iter().map(|payload| payload.to_vec()).collect();
    assert_eq!(actual, expected_payloads, "case: {label}");
}

fn assert_oplog_payloads(
    connection: Connection<String, OpLogRawEvent>,
    expected_len: usize,
    label: &str,
) {
    assert_eq!(connection.edges.len(), expected_len, "case: {label}");
    for edge in connection.edges {
        assert_eq!(edge.node.level.as_str(), "Info", "case: {label}");
        assert_eq!(edge.node.contents.as_str(), "oplog", "case: {label}");
    }
}

fn make_time_range(start: Option<i64>, end: Option<i64>) -> TimeRange {
    TimeRange {
        start: start.map(DateTime::from_timestamp_nanos),
        end: end.map(DateTime::from_timestamp_nanos),
    }
}

fn op_log_filter(
    range: (Option<i64>, Option<i64>),
    agent_id: Option<&str>,
    sensor: Option<&str>,
) -> OpLogFilter {
    OpLogFilter {
        time: Some(make_time_range(range.0, range.1)),
        agent_id: agent_id.map(std::string::ToString::to_string),
        log_level: Some("Info".to_string()),
        contents: Some("oplog".to_string()),
        sensor: sensor.map(std::string::ToString::to_string),
    }
}

fn log_storage_key(sensor: &str, kind: &str, timestamp: i64) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(sensor.len() + kind.len() + 10);
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend_from_slice(kind.as_bytes());
    key.push(0);
    key.extend_from_slice(&timestamp.to_be_bytes());
    key
}

fn insert_log_raw_event(
    store: &RawEventStore<Log>,
    sensor: &str,
    timestamp: i64,
    kind: &str,
    body: &[u8],
) {
    let key = log_storage_key(sensor, kind, timestamp);
    let log_body = Log {
        kind: kind.to_string(),
        log: body.to_vec(),
    };
    let value = encode_legacy(&log_body).unwrap();
    store.append(&key, &value).unwrap();
}

fn insert_oplog_raw_event(
    store: &RawEventStore<'_, OpLog>,
    agent_name: &str,
    sensor: &str,
    timestamp: i64,
    generator: &OnceLock<Arc<SequenceGenerator>>,
) -> Vec<u8> {
    let generator = generator.get_or_init(SequenceGenerator::init_generator);
    let sequence_number = generator.generate_sequence_number();

    let mut key: Vec<u8> = Vec::new();
    let agent_id = format!("{agent_name}@src 1");
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.extend_from_slice(&sequence_number.to_be_bytes());

    let oplog_body = OpLog {
        sensor: sensor.to_string(),
        agent_name: agent_id,
        log_level: OpLogLevel::Info,
        contents: "oplog".to_string(),
    };

    let value = encode_legacy(&oplog_body).unwrap();
    store.append(&key, &value).unwrap();
    key
}
