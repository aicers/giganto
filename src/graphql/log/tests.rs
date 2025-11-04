use std::sync::{Arc, OnceLock};

use chrono::DateTime;
use giganto_client::ingest::log::{Log, OpLog, OpLogLevel};

use super::{Engine, LogFilter, LogRawEvent, OpLogFilter, OpLogRawEvent, base64_engine};
use crate::comm::ingest::generation::SequenceGenerator;
use crate::graphql::load_connection;
use crate::{
    graphql::{TimeRange, tests::TestSchema},
    storage::WritableRawEventStore,
};

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn load_time_range() {
    let schema = TestSchema::new();
    let store = schema.db.log_store_writable().unwrap();

    insert_log_raw_event(store.as_ref(), "src1", 1, "kind1", b"log1");
    insert_log_raw_event(store.as_ref(), "src1", 2, "kind1", b"log2");
    insert_log_raw_event(store.as_ref(), "src1", 3, "kind1", b"log3");
    insert_log_raw_event(store.as_ref(), "src1", 4, "kind1", b"log4");
    insert_log_raw_event(store.as_ref(), "src1", 5, "kind1", b"log5");

    // backward traversal in `start..end`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(3)),
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        None,
        None,
        Some(3),
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log1"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log2"
    );

    // backward traversal in `start..`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(3)),
                end: None,
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        None,
        None,
        Some(3),
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 3);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log3"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log4"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[2].node.log).unwrap(),
        b"log5"
    );

    // backward traversal in `..end`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: Some(DateTime::from_timestamp_nanos(4)),
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        None,
        None,
        Some(3),
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 3);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log1"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log2"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[2].node.log).unwrap(),
        b"log3"
    );

    // forward traversal in `start..end`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(3)),
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        None,
        Some(3),
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log1"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log2"
    );

    // forward traversal `start..`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(3)),
                end: None,
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        None,
        Some(3),
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 3);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log3"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log4"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[2].node.log).unwrap(),
        b"log5"
    );

    // forward traversal `..end`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: Some(DateTime::from_timestamp_nanos(3)),
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        None,
        Some(3),
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log1"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log2"
    );

    // backward traversal in `start..end` and `before cursor`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(3)),
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        Some(base64_engine.encode(b"src1\x00kind1\x00\x00\x00\x00\x00\x00\x00\x00\x03")),
        None,
        Some(3),
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log1"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log2"
    );

    // backward traversal in `start..` and `before cursor`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(2)),
                end: None,
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        Some(base64_engine.encode(b"src1\x00kind1\x00\x00\x00\x00\x00\x00\x00\x00\x04")),
        None,
        Some(3),
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log2"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log3"
    );

    // backward traversal in `..end` and `before cursor`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: Some(DateTime::from_timestamp_nanos(5)),
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        Some(base64_engine.encode(b"src1\x00kind1\x00\x00\x00\x00\x00\x00\x00\x00\x04")),
        None,
        Some(3),
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 3);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log1"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log2"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[2].node.log).unwrap(),
        b"log3"
    );

    // forward traversal in `start..end` and `after cursor`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(4)),
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        Some(base64_engine.encode(b"src1\x00kind1\x00\x00\x00\x00\x00\x00\x00\x00\x01")),
        None,
        Some(3),
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log2"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log3"
    );

    // forward traversal `start..` and `after cursor`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(2)),
                end: None,
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        Some(base64_engine.encode(b"src1\x00kind1\x00\x00\x00\x00\x00\x00\x00\x00\x03")),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log4"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log5"
    );

    // forward traversal `..end` and `after cursor`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: Some(DateTime::from_timestamp_nanos(4)),
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        Some(base64_engine.encode(b"src1\x00kind1\x00\x00\x00\x00\x00\x00\x00\x00\x01")),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log2"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[1].node.log).unwrap(),
        b"log3"
    );

    // forward traversal `..`
    let connection = load_connection::<LogRawEvent, _>(
        store.as_ref(),
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: None,
            }),
            sensor: "src1".to_string(),
            kind: Some("kind1".to_string()),
        },
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 5);
    assert_eq!(
        base64_engine.decode(&connection.edges[0].node.log).unwrap(),
        b"log1"
    );
    assert_eq!(
        base64_engine.decode(&connection.edges[4].node.log).unwrap(),
        b"log5"
    );
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
    let store = schema.db.log_store_writable().unwrap();

    insert_log_raw_event(store.as_ref(), "src 1", 1, "kind 1", b"log 1");
    insert_log_raw_event(store.as_ref(), "src 1", 2, "kind 2", b"log 2");

    let query = r#"
        {
            logRawEvents (filter: {sensor: "src 1", kind: "kind 1"}, first: 1) {
                edges {
                    node {
                        log
                    }
                }
                pageInfo {
                    hasPreviousPage
                }
            }
        }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        format!(
            "{{logRawEvents: {{edges: [{{node: {{log: \"{}\"}}}}], pageInfo: {{hasPreviousPage: false}}}}}}",
            base64_engine.encode("log 1")
        )
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
    let store = schema.db.op_log_store_writable().unwrap();
    let generator: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();
    insert_oplog_raw_event(store.as_ref(), "giganto", "src1", 1, &generator);

    let query = r#"
        {
            opLogRawEvents (filter: {agentId: "giganto@src 1", logLevel: "Info"}, first: 1) {
                edges {
                    node {
                        level,
                        contents
                    }
                }
            }
        }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{opLogRawEvents: {edges: [{node: {level: \"Info\", contents: \"oplog\"}}]}}"
    );
}

#[tokio::test]
async fn load_oplog() {
    let schema = TestSchema::new();
    let store = schema.db.op_log_store_writable().unwrap();
    let generator: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();

    insert_oplog_raw_event(store.as_ref(), "giganto", "src1", 1, &generator);
    insert_oplog_raw_event(store.as_ref(), "giganto", "src1", 2, &generator);
    insert_oplog_raw_event(store.as_ref(), "manager", "src1", 2, &generator);
    insert_oplog_raw_event(store.as_ref(), "manager", "src1", 3, &generator);
    insert_oplog_raw_event(store.as_ref(), "giganto", "src1", 3, &generator);
    insert_oplog_raw_event(store.as_ref(), "giganto", "src1", 4, &generator);
    insert_oplog_raw_event(store.as_ref(), "giganto", "src1", 5, &generator);
    insert_oplog_raw_event(store.as_ref(), "manager", "src1", 5, &generator);
    insert_oplog_raw_event(store.as_ref(), "aice", "src1", 5, &generator);

    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        store.as_ref(),
        &OpLogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(5)),
                end: Some(DateTime::from_timestamp_nanos(7)),
            }),
            agent_id: None,
            log_level: Some("Info".to_string()),
            contents: Some("oplog".to_string()),
            sensor: None,
        },
        None,
        None,
        Some(5),
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 3);
    assert_eq!(connection.edges[0].node.level.as_str(), "Info");
    assert_eq!(connection.edges[0].node.contents.as_str(), "oplog");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn load_connection_by_prefix_timestamp_key() {
    let schema = TestSchema::new();
    let store = schema.db.op_log_store_writable().unwrap();
    let generator: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();
    let key_list: Vec<Vec<u8>> = vec![
        insert_oplog_raw_event(store.as_ref(), "sensor", "src1", 1, &generator),
        insert_oplog_raw_event(store.as_ref(), "sensor", "src1", 2, &generator),
        insert_oplog_raw_event(store.as_ref(), "manager", "src1", 2, &generator),
        insert_oplog_raw_event(store.as_ref(), "manager", "src1", 3, &generator),
        insert_oplog_raw_event(store.as_ref(), "sensor", "src1", 3, &generator),
        insert_oplog_raw_event(store.as_ref(), "sensor", "src1", 4, &generator),
        insert_oplog_raw_event(store.as_ref(), "sensor", "src2", 5, &generator),
        insert_oplog_raw_event(store.as_ref(), "sensor", "src2", 6, &generator),
        insert_oplog_raw_event(store.as_ref(), "manager", "src1", 4, &generator),
        insert_oplog_raw_event(store.as_ref(), "manager", "src2", 5, &generator),
    ];

    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        store.as_ref(),
        &OpLogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(10)),
            }),
            agent_id: Some("manager".to_string()),
            log_level: Some("Info".to_string()),
            contents: Some("oplog".to_string()),
            sensor: Some("src1".to_string()),
        },
        None,
        None,
        Some(10),
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 3);
    assert_eq!(connection.edges[0].node.level.as_str(), "Info");
    assert_eq!(connection.edges[0].node.contents.as_str(), "oplog");

    let after = key_list.get(3).unwrap();
    let after = base64_engine.encode(after);
    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        store.as_ref(),
        &OpLogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(10)),
            }),
            agent_id: Some("manager".to_string()),
            log_level: Some("Info".to_string()),
            contents: Some("oplog".to_string()),
            sensor: Some("src1".to_string()),
        },
        Some(after),
        None,
        Some(10),
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 1);
    assert_eq!(connection.edges[0].node.level.as_str(), "Info");
    assert_eq!(connection.edges[0].node.contents.as_str(), "oplog");

    let before = key_list.get(8).unwrap();
    let before = base64_engine.encode(before);
    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        store.as_ref(),
        &OpLogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(10)),
            }),
            agent_id: Some("manager".to_string()),
            log_level: Some("Info".to_string()),
            contents: Some("oplog".to_string()),
            sensor: Some("src1".to_string()),
        },
        None,
        Some(before),
        None,
        Some(10),
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(connection.edges[0].node.level.as_str(), "Info");
    assert_eq!(connection.edges[1].node.contents.as_str(), "oplog");

    let connection = super::load_connection_by_prefix_timestamp_key::<OpLogRawEvent, _>(
        store.as_ref(),
        &OpLogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(10)),
            }),
            agent_id: Some("sensor".to_string()),
            log_level: Some("Info".to_string()),
            contents: Some("oplog".to_string()),
            sensor: Some("src2".to_string()),
        },
        None,
        None,
        None,
        Some(10),
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(connection.edges[0].node.level.as_str(), "Info");
    assert_eq!(connection.edges[0].node.contents.as_str(), "oplog");
}

fn insert_log_raw_event(
    store: &dyn WritableRawEventStore<'_, Log>,
    sensor: &str,
    timestamp: i64,
    kind: &str,
    body: &[u8],
) {
    let mut key: Vec<u8> = Vec::new();
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend_from_slice(kind.as_bytes());
    key.push(0);
    key.extend_from_slice(&timestamp.to_be_bytes());
    let log_body = Log {
        kind: kind.to_string(),
        log: body.to_vec(),
    };
    let value = bincode::serialize(&log_body).unwrap();
    store.append(&key, &value).unwrap();
}

fn insert_oplog_raw_event(
    store: &dyn WritableRawEventStore<'_, OpLog>,
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
        agent_name: agent_id.clone(),
        log_level: OpLogLevel::Info,
        contents: "oplog".to_string(),
    };

    let value = bincode::serialize(&oplog_body).unwrap();
    store.append(&key, &value).unwrap();
    key
}
