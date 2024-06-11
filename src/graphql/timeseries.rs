use std::{fmt::Debug, net::IpAddr};

use async_graphql::{
    connection::{query, Connection},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::timeseries::PeriodicTimeSeries;

use super::{get_timestamp_from_key, load_connection, FromKeyValue};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    storage::{Database, KeyExtractor},
};

#[derive(Default)]
pub(super) struct TimeSeriesQuery;

// #[allow(clippy::module_name_repetitions)]
#[derive(InputObject)]
pub struct TimeSeriesFilter {
    time: Option<TimeRange>,
    id: String,
}

impl KeyExtractor for TimeSeriesFilter {
    fn get_start_key(&self) -> &str {
        &self.id
    }

    // timeseries event don't use mid key
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

impl RawEventFilter for TimeSeriesFilter {
    fn check(
        &self,
        _orig_addr: Option<IpAddr>,
        _resp_addr: Option<IpAddr>,
        _orig_port: Option<u16>,
        _resp_port: Option<u16>,
        _log_level: Option<String>,
        _log_contents: Option<String>,
        _text: Option<String>,
        _source: Option<String>,
        _agent_id: Option<String>,
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

impl FromKeyValue<PeriodicTimeSeries> for TimeSeries {
    fn from_key_value(key: &[u8], p: PeriodicTimeSeries) -> Result<Self> {
        Ok(TimeSeries {
            start: get_timestamp_from_key(key)?,
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
        let db = ctx.data::<Database>()?;
        let store = db.periodic_time_series_store()?;

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
    use giganto_client::ingest::timeseries::PeriodicTimeSeries;

    use crate::{graphql::tests::TestSchema, storage::RawEventStore};

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
            "{periodicTimeSeries: {edges: [{node: {id: \"src 1\", data: [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}}], pageInfo: {hasPreviousPage: false}}}"
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
