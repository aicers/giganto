use super::{base64_engine, get_timestamp_from_key, load_connection, Engine, FromKeyValue};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    storage::{Database, KeyExtractor},
};
use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::log::{Log, OpLog};
use std::{fmt::Debug, net::IpAddr};

#[derive(Default)]
pub(super) struct LogQuery;

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject)]
pub struct LogFilter {
    time: Option<TimeRange>,
    source: String,
    kind: Option<String>,
}

impl KeyExtractor for LogFilter {
    fn get_start_key(&self) -> &str {
        &self.source
    }

    fn get_mid_key(&self) -> Option<Vec<u8>> {
        self.kind.as_ref().map(|kind| kind.as_bytes().to_vec())
    }

    fn get_range_end_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }
}

impl RawEventFilter for LogFilter {
    fn check(
        &self,
        _orig_addr: Option<IpAddr>,
        _resp_addr: Option<IpAddr>,
        _orig_port: Option<u16>,
        _resp_port: Option<u16>,
        _log_level: Option<String>,
        _log_contents: Option<String>,
        _text: Option<String>,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[derive(InputObject)]
pub struct OpLogFilter {
    time: Option<TimeRange>,
    agent_id: String,
    log_level: Option<String>,
    contents: Option<String>,
}

impl KeyExtractor for OpLogFilter {
    fn get_start_key(&self) -> &str {
        &self.agent_id
    }

    // oplog event don't use mid key
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

impl RawEventFilter for OpLogFilter {
    fn check(
        &self,
        _orig_addr: Option<IpAddr>,
        _resp_addr: Option<IpAddr>,
        _orig_port: Option<u16>,
        _resp_port: Option<u16>,
        log_level: Option<String>,
        log_contents: Option<String>,
        _text: Option<String>,
    ) -> Result<bool> {
        if let Some(filter_level) = &self.log_level {
            let log_level = if let Some(log_level) = log_level {
                filter_level != &log_level
            } else {
                false
            };
            if log_level {
                return Ok(false);
            }
        }
        if let Some(filter_str) = &self.contents {
            let contents = if let Some(contents) = log_contents {
                !contents.contains(filter_str)
            } else {
                false
            };
            if contents {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(SimpleObject, Debug)]
struct LogRawEvent {
    timestamp: DateTime<Utc>,
    log: String,
}

impl FromKeyValue<Log> for LogRawEvent {
    fn from_key_value(key: &[u8], l: Log) -> Result<Self> {
        Ok(LogRawEvent {
            timestamp: get_timestamp_from_key(key)?,
            log: base64_engine.encode(l.log),
        })
    }
}

#[derive(SimpleObject, Debug)]
struct OpLogRawEvent {
    timestamp: DateTime<Utc>,
    level: String,
    contents: String,
}

impl FromKeyValue<OpLog> for OpLogRawEvent {
    fn from_key_value(key: &[u8], l: OpLog) -> Result<Self> {
        Ok(OpLogRawEvent {
            timestamp: get_timestamp_from_key(key)?,
            level: format!("{:?}", l.log_level),
            contents: l.contents,
        })
    }
}

#[Object]
impl LogQuery {
    async fn log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: LogFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, LogRawEvent>> {
        if filter.kind.is_none() {
            return Err(anyhow!("log query failed: kind is required").into());
        }
        let db = ctx.data::<Database>()?;
        let store = db.log_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn op_log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: OpLogFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, OpLogRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.op_log_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{base64_engine, Engine, LogFilter, LogRawEvent, OpLogFilter, OpLogRawEvent};
    use crate::{
        graphql::{TestSchema, TimeRange},
        storage::RawEventStore,
    };
    use chrono::{DateTime, NaiveDateTime, Utc};
    use giganto_client::ingest::log::{Log, OpLog, OpLogLevel};

    #[test]
    fn load_time_range() {
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
                    start: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 1).expect("valid value"),
                        Utc,
                    )),
                    end: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 3).expect("valid value"),
                        Utc,
                    )),
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
                    start: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 3).expect("valid value"),
                        Utc,
                    )),
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
                    end: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 4).expect("valid value"),
                        Utc,
                    )),
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
                    start: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 1).expect("valid value"),
                        Utc,
                    )),
                    end: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 3).expect("valid value"),
                        Utc,
                    )),
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
                    start: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 3).expect("valid value"),
                        Utc,
                    )),
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
                    end: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 3).expect("valid value"),
                        Utc,
                    )),
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
                    start: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 1).expect("valid value"),
                        Utc,
                    )),
                    end: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 3).expect("valid value"),
                        Utc,
                    )),
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
                    start: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 2).expect("valid value"),
                        Utc,
                    )),
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
                    end: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 5).expect("valid value"),
                        Utc,
                    )),
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
                    start: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 1).expect("valid value"),
                        Utc,
                    )),
                    end: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 4).expect("valid value"),
                        Utc,
                    )),
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
                    start: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 2).expect("valid value"),
                        Utc,
                    )),
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
                    end: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 4).expect("valid value"),
                        Utc,
                    )),
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
            format!("{{logRawEvents: {{edges: [{{node: {{log: \"{}\"}}}}],pageInfo: {{hasPreviousPage: false}}}}}}", base64_engine.encode("log 1"))
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
            "{opLogRawEvents: {edges: [{node: {level: \"Info\",contents: \"oplog\"}}]}}"
        );
    }

    #[test]
    fn load_oplog() {
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
                    start: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 1).expect("valid value"),
                        Utc,
                    )),
                    end: Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(0, 3).expect("valid value"),
                        Utc,
                    )),
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
}
