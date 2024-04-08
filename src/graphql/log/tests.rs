use super::{base64_engine, Engine, LogFilter, LogRawEvent, OpLogFilter, OpLogRawEvent};
use crate::{
    graphql::{tests::TestSchema, TimeRange},
    storage::RawEventStore,
};
use chrono::DateTime;
use giganto_client::ingest::log::{Log, OpLog, OpLogLevel};

#[tokio::test]
async fn load_time_range() {
    let schema = TestSchema::new();
    let store = schema.db.log_store().unwrap();

    insert_log_raw_event(&store, "src1", 1, "kind1", b"log1");
    insert_log_raw_event(&store, "src1", 2, "kind1", b"log2");
    insert_log_raw_event(&store, "src1", 3, "kind1", b"log3");
    insert_log_raw_event(&store, "src1", 4, "kind1", b"log4");
    insert_log_raw_event(&store, "src1", 5, "kind1", b"log5");

    // backward traversal in `start..end`
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(3)),
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(3)),
                end: None,
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: Some(DateTime::from_timestamp_nanos(4)),
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(3)),
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(3)),
                end: None,
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: Some(DateTime::from_timestamp_nanos(3)),
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(3)),
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(2)),
                end: None,
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: Some(DateTime::from_timestamp_nanos(5)),
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(4)),
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(2)),
                end: None,
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: Some(DateTime::from_timestamp_nanos(4)),
            }),
            source: "src1".to_string(),
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
    let connection = super::load_connection::<LogRawEvent, _>(
        &store,
        &LogFilter {
            time: Some(TimeRange {
                start: None,
                end: None,
            }),
            source: "src1".to_string(),
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
            logRawEvents (filter: {source: "einsis", kind: "Hello"}, first: 1) {
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
            logRawEvents (filter: {source: "src 1", kind: "kind 1"}, first: 1) {
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
            format!("{{logRawEvents: {{edges: [{{node: {{log: \"{}\"}}}}], pageInfo: {{hasPreviousPage: false}}}}}}", base64_engine.encode("log 1"))
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

    insert_oplog_raw_event(&store, "giganto", 1);

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
    let store = schema.db.op_log_store().unwrap();

    insert_oplog_raw_event(&store, "giganto", 1);
    insert_oplog_raw_event(&store, "giganto", 2);
    insert_oplog_raw_event(&store, "giganto", 3);
    insert_oplog_raw_event(&store, "giganto", 4);
    insert_oplog_raw_event(&store, "giganto", 5);

    let connection = super::load_connection::<OpLogRawEvent, _>(
        &store,
        &OpLogFilter {
            time: Some(TimeRange {
                start: Some(DateTime::from_timestamp_nanos(1)),
                end: Some(DateTime::from_timestamp_nanos(3)),
            }),
            agent_id: "giganto@src 1".to_string(),
            log_level: Some("Info".to_string()),
            contents: Some("oplog".to_string()),
        },
        None,
        None,
        Some(3),
        None,
    )
    .unwrap();
    assert_eq!(connection.edges.len(), 2);
    assert_eq!(connection.edges[0].node.level.as_str(), "Info");
    assert_eq!(connection.edges[1].node.contents.as_str(), "oplog");
}

fn insert_log_raw_event(
    store: &RawEventStore<Log>,
    source: &str,
    timestamp: i64,
    kind: &str,
    body: &[u8],
) {
    let mut key: Vec<u8> = Vec::new();
    key.extend_from_slice(source.as_bytes());
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

fn insert_oplog_raw_event(store: &RawEventStore<OpLog>, agent_name: &str, timestamp: i64) {
    let mut key: Vec<u8> = Vec::new();
    let agent_id = format!("{agent_name}@src 1");
    key.extend_from_slice(agent_id.as_bytes());
    key.push(0);
    key.extend_from_slice(&timestamp.to_be_bytes());

    let oplog_body = OpLog {
        agent_name: agent_id.to_string(),
        log_level: OpLogLevel::Info,
        contents: "oplog".to_string(),
    };

    let value = bincode::serialize(&oplog_body).unwrap();

    store.append(&key, &value).unwrap();
}
