use super::{get_timestamp, load_connection, FromKeyValue};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    ingestion,
    storage::Database,
};
use async_graphql::{
    connection::{query, Connection},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use std::{fmt::Debug, net::IpAddr};

#[derive(Default)]
pub(super) struct TimeSeriesQuery;

// #[allow(clippy::module_name_repetitions)]
#[derive(InputObject)]
pub struct TimeSeriesFilter {
    time: Option<TimeRange>,
    id: String,
}

impl RawEventFilter for TimeSeriesFilter {
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
    ) -> Result<bool> {
        Ok(true)
    }
}

#[derive(SimpleObject, Debug)]
struct TimeSeries {
    start: DateTime<Utc>,
    id: String,
    data: Vec<f64>,
}

impl FromKeyValue<ingestion::PeriodicTimeSeries> for TimeSeries {
    fn from_key_value(key: &[u8], p: ingestion::PeriodicTimeSeries) -> Result<Self> {
        Ok(TimeSeries {
            start: get_timestamp(key)?,
            id: p.id,
            data: p.data,
        })
    }
}

#[Object]
impl TimeSeriesQuery {
    async fn periodic_time_series<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: TimeSeriesFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, TimeSeries>> {
        let mut key_prefix = Vec::with_capacity(filter.id.len() + 2);
        key_prefix.extend_from_slice(filter.id.as_bytes());
        key_prefix.push(0);

        let db = ctx.data::<Database>()?;
        let store = db.periodic_time_series_store()?;

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
    use crate::ingestion::PeriodicTimeSeries;
    use crate::{graphql::TestSchema, storage::RawEventStore};

    #[tokio::test]
    async fn time_series_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            periodicTimeSeries (filter: {id: "-1"}, first: 1) {
                edges {
                    node {
                        id
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{periodicTimeSeries: {edges: []}}");
    }

    #[tokio::test]
    async fn time_series_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.periodic_time_series_store().unwrap();

        insert_time_series(&store, "src 1", 1, vec![0.0; 12]);
        insert_time_series(&store, "src 1", 2, vec![0.0; 12]);

        let query = r#"
        {
            periodicTimeSeries (filter: {id: "src 1"}, first: 1) {
                edges {
                    node {
                        id
                        data
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
            "{periodicTimeSeries: {edges: [{node: {id: \"src 1\",data: [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0]}}],pageInfo: {hasPreviousPage: false}}}"
        );
    }

    fn insert_time_series(
        store: &RawEventStore<PeriodicTimeSeries>,
        id: &str,
        start: i64,
        data: Vec<f64>,
    ) {
        let mut key: Vec<u8> = Vec::new();
        key.extend_from_slice(id.as_bytes());
        key.push(0);
        key.extend_from_slice(&start.to_be_bytes());
        let time_series_data = PeriodicTimeSeries {
            id: id.to_string(),
            data,
        };
        let value = bincode::serialize(&time_series_data).unwrap();
        store.append(&key, &value).unwrap();
    }
}
