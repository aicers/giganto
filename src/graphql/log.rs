use super::load_connection;
use crate::{
    ingestion,
    storage::{Database, RawEventStore},
};
use async_graphql::{
    connection::{query, Connection},
    Context, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};

use std::fmt::Debug;

#[derive(SimpleObject, Debug)]
struct LogRawEvent {
    log: String,
}

#[derive(Default)]
pub(super) struct LogQuery;

impl From<ingestion::Log> for LogRawEvent {
    fn from(l: ingestion::Log) -> LogRawEvent {
        let (_, log) = l.log;
        LogRawEvent {
            log: base64::encode(log),
        }
    }
}

#[Object]
impl LogQuery {
    #[allow(clippy::too_many_arguments)]
    async fn log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        kind: String,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, LogRawEvent>> {
        let mut key_prefix = Vec::with_capacity(source.len() + kind.len() + 2);
        key_prefix.extend_from_slice(source.as_bytes());
        key_prefix.push(0);
        key_prefix.extend_from_slice(kind.as_bytes());
        key_prefix.push(0);

        let db = ctx.data::<Database>()?;
        let store = db.log_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(
                    &store,
                    &key_prefix,
                    RawEventStore::log_iter,
                    start,
                    end,
                    after,
                    before,
                    first,
                    last,
                )
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::LogRawEvent;
    use crate::{graphql::TestSchema, storage::RawEventStore};
    use chrono::{DateTime, NaiveDateTime, Utc};
    use std::mem;

    #[test]
    #[should_panic] // TODO: this should not panic
    fn load_time_range() {
        let schema = TestSchema::new();
        let store = schema.db.log_store().unwrap();

        insert_raw_event(&store, "src1", 1, "kind1", b"log1");
        insert_raw_event(&store, "src1", 2, "kind1", b"log2");
        insert_raw_event(&store, "src1", 3, "kind1", b"log3");

        // backward traversal in `start..end`
        let connection = super::load_connection::<LogRawEvent, _, _>(
            &store,
            b"src1\x00kind1\x00",
            RawEventStore::log_iter,
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(0, 1),
                Utc,
            )),
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(0, 3),
                Utc,
            )),
            None,
            None,
            None,
            Some(3),
        )
        .unwrap();
        assert_eq!(connection.edges.len(), 2);
        assert_eq!(
            base64::decode(&connection.edges[0].node.log).unwrap(),
            b"log1"
        );
        assert_eq!(
            base64::decode(&connection.edges[1].node.log).unwrap(),
            b"log2"
        );

        // backward traversal in `start..`
        let connection = super::load_connection::<LogRawEvent, _, _>(
            &store,
            b"src1\x00kind1\x00",
            RawEventStore::log_iter,
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(0, 2),
                Utc,
            )),
            None,
            None,
            None,
            None,
            Some(3),
        )
        .unwrap();
        assert_eq!(connection.edges.len(), 2);
        assert_eq!(
            base64::decode(&connection.edges[0].node.log).unwrap(),
            b"log2"
        );
        assert_eq!(
            base64::decode(&connection.edges[1].node.log).unwrap(),
            b"log3"
        );

        // backward traversal in `..end`
        let connection = super::load_connection::<LogRawEvent, _, _>(
            &store,
            b"src1\x00kind1\x00",
            RawEventStore::log_iter,
            None,
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(0, 3),
                Utc,
            )),
            None,
            None,
            None,
            Some(3),
        )
        .unwrap();
        assert_eq!(connection.edges.len(), 2);
        assert_eq!(
            base64::decode(&connection.edges[0].node.log).unwrap(),
            b"log1"
        );
        assert_eq!(
            base64::decode(&connection.edges[1].node.log).unwrap(),
            b"log2"
        );

        // forward traversal in `start..end`
        let connection = super::load_connection::<LogRawEvent, _, _>(
            &store,
            b"src1\x00kind1\x00",
            RawEventStore::log_iter,
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(0, 1),
                Utc,
            )),
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(0, 2),
                Utc,
            )),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(connection.edges.len(), 1);
        assert_eq!(
            base64::decode(&connection.edges[0].node.log).unwrap(),
            b"log1"
        );

        // forward traversal `start..`
        let connection = super::load_connection::<LogRawEvent, _, _>(
            &store,
            b"src1\x00kind1\x00",
            RawEventStore::log_iter,
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(0, 2),
                Utc,
            )),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(connection.edges.len(), 2);
        assert_eq!(
            base64::decode(&connection.edges[0].node.log).unwrap(),
            b"log2"
        );
        assert_eq!(
            base64::decode(&connection.edges[1].node.log).unwrap(),
            b"log3"
        );

        // forward traversal `..end`
        let connection = super::load_connection::<LogRawEvent, _, _>(
            &store,
            b"src1\x00kind1\x00",
            RawEventStore::log_iter,
            None,
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(0, 3),
                Utc,
            )),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(connection.edges.len(), 2);
        assert_eq!(
            base64::decode(&connection.edges[0].node.log).unwrap(),
            b"log1"
        );
        assert_eq!(
            base64::decode(&connection.edges[1].node.log).unwrap(),
            b"log2"
        );
    }

    #[tokio::test]
    async fn log_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            logRawEvents (source: "einsis", kind: "Hello", first: 0) {
                edges {
                    node {
                        log
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(res.data.to_string(), "{logRawEvents: {edges: []}}");
    }

    #[tokio::test]
    async fn log_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.log_store().unwrap();

        insert_raw_event(&store, "src 1", 1, "kind 1", b"log 1");
        insert_raw_event(&store, "src 1", 2, "kind 2", b"log 2");

        let query = r#"
        {
            logRawEvents (source: "src 1", kind: "kind 1", first: 2) {
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
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            format!("{{logRawEvents: {{edges: [{{node: {{log: \"{}\"}}}}],pageInfo: {{hasPreviousPage: false}}}}}}", base64::encode("log 1"))
        );
    }

    fn insert_raw_event(
        store: &RawEventStore,
        source: &str,
        timestamp: i64,
        kind: &str,
        body: &[u8],
    ) {
        let mut key = Vec::with_capacity(source.len() + kind.len() + 2 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend_from_slice(kind.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());
        let value = bincode::serialize(&(kind, body)).unwrap();
        store.append(&key, &value).unwrap();
    }
}
