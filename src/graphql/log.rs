use super::load_connection;
use crate::{
    ingestion,
    storage::{Database, RawEventStore},
};
use async_graphql::{
    connection::{query, Connection},
    Context, Object, Result, SimpleObject,
};

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
                    None,
                    None,
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
    use crate::graphql::TestSchema;
    use chrono::Utc;

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

        let mut source_kind = b"einsis\x00Hello\x00".to_vec();
        source_kind.extend(Utc::now().timestamp_nanos().to_be_bytes());

        let log_body = (
            String::from("Hello"),
            base64::decode("aGVsbG8gd29ybGQ=").unwrap(),
        );
        let ser_log_body = bincode::serialize(&log_body).unwrap();

        schema
            .db
            .log_store()
            .unwrap()
            .append(&source_kind[..], &ser_log_body)
            .unwrap();

        let query = r#"
        {
            logRawEvents (source: "einsis", kind: "Hello", first: 1) {
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
            "{logRawEvents: {edges: [{node: {log: \"aGVsbG8gd29ybGQ=\"}}],pageInfo: {hasPreviousPage: false}}}"
        );
    }
}
