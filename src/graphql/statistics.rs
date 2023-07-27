use super::{get_timestamp, load_connection, FromKeyValue, RawEventFilter};
use crate::{graphql::TimeRange, storage::Database};
use async_graphql::{
    connection::{query, Connection},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::statistics::Statistics;
use serde::Serialize;
use std::net::IpAddr;

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct StatisticsFilter {
    time: Option<TimeRange>,
    #[serde(skip)]
    pub source: String,
    core: u32,
}

impl RawEventFilter for StatisticsFilter {
    fn time(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }

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

#[derive(SimpleObject, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct StatisticsRawEvent {
    timestamp: DateTime<Utc>,
    core: u32,
    period: u16,
    stats: Vec<String>,
}

impl FromKeyValue<Statistics> for StatisticsRawEvent {
    fn from_key_value(key: &[u8], val: Statistics) -> Result<Self> {
        let stats = val
            .stats
            .iter()
            .map(|(rt, cnt, size)| format!("{rt:?}/{size}/{cnt}"))
            .collect::<Vec<_>>();
        Ok(StatisticsRawEvent {
            timestamp: get_timestamp(key)?,
            core: val.core,
            period: val.period,
            stats,
        })
    }
}

#[derive(Default)]
pub(super) struct StatisticsQuery;

#[Object]
impl StatisticsQuery {
    #[allow(clippy::unused_async)]
    async fn statistics<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: StatisticsFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, StatisticsRawEvent>> {
        let mut key_prefix = Vec::with_capacity(filter.source.len() + 2);
        key_prefix.extend_from_slice(filter.source.as_bytes());
        key_prefix.push(0);
        key_prefix.extend_from_slice(&filter.core.to_be_bytes());
        key_prefix.push(0);

        let db = ctx.data::<Database>()?;
        let store = db.statistics_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &key_prefix, &filter, after, before, first, last)
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::{graphql::TestSchema, storage::RawEventStore};
    use chrono::Utc;
    use giganto_client::ingest::{statistics::Statistics, RecordType};

    #[tokio::test]
    async fn test_statistics() {
        let schema = TestSchema::new();
        let store = schema.db.statistics_store().unwrap();
        let now = Utc::now().timestamp_nanos();
        insert_statistics_raw_event(&store, now, "src 1", 0, 600, 100, 1000);
        insert_statistics_raw_event(&store, now, "src 1", 1, 601, 101, 1001);
        insert_statistics_raw_event(&store, now, "src 1", 2, 602, 102, 1002);

        let query = r#"
    {
        statistics(
            filter: {
                source: "src 1"
                core: 2
            }
            last: 1
        ) {
            edges {
                node {core, period, stats}
            }
        }
    }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{statistics: {edges: [{node: {core: 2,period: 602,stats: [\"Statistics/1002/102\"]}}]}}"
        );
    }

    fn insert_statistics_raw_event(
        store: &RawEventStore<Statistics>,
        timestamp: i64,
        source: &str,
        core: u32,
        period: u16,
        count: u64,
        size: u64,
    ) {
        let mut key = Vec::with_capacity(source.len() + 1 + std::mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend_from_slice(&core.to_be_bytes());
        key.push(0);
        key.extend_from_slice(&timestamp.to_be_bytes());

        let msg = Statistics {
            core,
            period,
            stats: vec![(RecordType::Statistics, count, size)],
        };
        let msg = bincode::serialize(&msg).unwrap();
        store.append(&key, &msg).unwrap();
    }
}
