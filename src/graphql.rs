mod log;
pub mod network;
mod packet;
mod timeseries;

use crate::{
    ingestion::{EventFilter, PacketSources},
    storage::{
        lower_closed_bound_key, upper_closed_bound_key, upper_open_bound_key, Database, Direction,
        FilteredIter, KeyValue, RawEventStore,
    },
};
use anyhow::anyhow;
use async_graphql::{
    connection::{Connection, Edge},
    EmptyMutation, EmptySubscription, InputObject, MergedObject, OutputType, Result,
};
use chrono::{DateTime, TimeZone, Utc};
use serde::{de::DeserializeOwned, Serialize};
use std::net::IpAddr;

use self::network::NetworkFilter;

pub const TIMESTAMP_SIZE: usize = 8;

#[derive(Default, MergedObject)]
pub struct Query(
    log::LogQuery,
    network::NetworkQuery,
    packet::PacketQuery,
    timeseries::TimeSeriesQuery,
);

#[derive(InputObject, Serialize)]
pub struct TimeRange {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}

pub trait RawEventFilter {
    fn time(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
    ) -> Result<bool>;
}

pub trait FromKeyValue<T>: Sized {
    fn from_key_value(key: &[u8], value: T) -> Result<Self>;
}

pub type Schema = async_graphql::Schema<Query, EmptyMutation, EmptySubscription>;
type ConnArgs<T> = (Vec<(Box<[u8]>, T)>, bool, bool);

pub fn schema(database: Database, packet_sources: PacketSources) -> Schema {
    Schema::build(Query::default(), EmptyMutation, EmptySubscription)
        .data(database)
        .data(packet_sources)
        .finish()
}

/// The default page size for connections when neither `first` nor `last` is
/// provided.
/// Maximum size: 100.
const MAXIMUM_PAGE_SIZE: usize = 100;

fn get_connection<'c, T>(
    store: &RawEventStore<'c, T>,
    key_prefix: &[u8],
    filter: &impl RawEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<ConnArgs<T>>
where
    T: DeserializeOwned + EventFilter,
{
    let (records, has_previous, has_next) = if let Some(before) = before {
        if after.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if first.is_some() {
            return Err("'before' and 'first' cannot be specified simultaneously".into());
        }
        let (start, end) = filter.time();

        let last = last.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64::decode(before)?;
        let time = upper_closed_bound_key(key_prefix, end);
        if cursor.cmp(&time) == std::cmp::Ordering::Greater {
            return Err("invalid cursor".into());
        }
        let mut iter = store
            .boundary_iter(
                &cursor,
                &lower_closed_bound_key(key_prefix, start),
                Direction::Reverse,
            )
            .peekable();
        if let Some(Ok((key, _))) = iter.peek() {
            if key.as_ref() == cursor {
                iter.next();
            }
        }
        let (mut records, has_previous) = collect_records(iter, last, filter)?;
        records.reverse();
        (records, has_previous, false)
    } else if let Some(after) = after {
        if before.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if last.is_some() {
            return Err("'after' and 'last' cannot be specified simultaneously".into());
        }
        let (start, end) = filter.time();

        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64::decode(after)?;
        let time = lower_closed_bound_key(key_prefix, start);
        if cursor.cmp(&time) == std::cmp::Ordering::Less {
            return Err("invalid cursor".into());
        }
        let mut iter = store
            .boundary_iter(
                &cursor,
                &upper_open_bound_key(key_prefix, end),
                Direction::Forward,
            )
            .peekable();
        if let Some(Ok((key, _))) = iter.peek() {
            if key.as_ref() == cursor {
                iter.next();
            }
        }
        let (records, has_next) = collect_records(iter, first, filter)?;
        (records, false, has_next)
    } else if let Some(last) = last {
        if first.is_some() {
            return Err("first and last cannot be used together".into());
        }
        let (start, end) = filter.time();

        let last = last.min(MAXIMUM_PAGE_SIZE);
        let iter = store.boundary_iter(
            &upper_open_bound_key(key_prefix, end),
            &lower_closed_bound_key(key_prefix, start),
            Direction::Reverse,
        );
        let (mut records, has_previous) = collect_records(iter, last, filter)?;
        records.reverse();
        (records, has_previous, false)
    } else {
        let (start, end) = filter.time();

        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let iter = store.boundary_iter(
            &lower_closed_bound_key(key_prefix, start),
            &upper_open_bound_key(key_prefix, end),
            Direction::Forward,
        );
        let (records, has_next) = collect_records(iter, first, filter)?;
        (records, false, has_next)
    };
    Ok((records, has_previous, has_next))
}

fn load_connection<'c, N, T>(
    store: &RawEventStore<'c, T>,
    key_prefix: &[u8],
    filter: &impl RawEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, N>>
where
    N: FromKeyValue<T> + OutputType,
    T: DeserializeOwned + EventFilter,
{
    let (records, has_previous, has_next) =
        get_connection(store, key_prefix, filter, after, before, first, last)?;

    let mut connection: Connection<String, N> = Connection::new(has_previous, has_next);
    connection.edges = records
        .into_iter()
        .map(|(key, node)| {
            Edge::new(
                base64::encode(&key),
                N::from_key_value(&key, node).expect("failed to convert value"),
            )
        })
        .collect();
    Ok(connection)
}

fn collect_records<I, T>(
    mut iter: I,
    size: usize,
    filter: &impl RawEventFilter,
) -> Result<(Vec<KeyValue<T>>, bool)>
where
    I: Iterator<Item = anyhow::Result<(Box<[u8]>, T)>>,
    T: EventFilter,
{
    let mut records = Vec::with_capacity(size);
    let mut has_more = false;
    while let Some(item) = iter.next() {
        let item = item.map_err(|e| format!("failed to read database: {}", e))?;
        match filter.check(
            item.1.orig_addr(),
            item.1.resp_addr(),
            item.1.orig_port(),
            item.1.resp_port(),
        ) {
            Ok(true) => records.push(item),
            Ok(false) | Err(_) => {}
        }
        if records.len() == size {
            has_more = iter.next().is_some();
            break;
        }
    }
    Ok((records, has_more))
}

fn get_timestamp(key: &[u8]) -> Result<DateTime<Utc>, anyhow::Error> {
    if key.len() > TIMESTAMP_SIZE {
        let nanos = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        return Ok(Utc.timestamp_nanos(nanos));
    }
    Err(anyhow!("invalid database key length"))
}

fn get_filtered_iter<'c, T>(
    store: &RawEventStore<'c, T>,
    key_prefix: &[u8],
    filter: &'c NetworkFilter,
    after: &Option<String>,
    before: &Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(FilteredIter<'c, T>, Option<Vec<u8>>, usize)>
where
    T: DeserializeOwned + EventFilter,
{
    let (iter, cursor, size) = if let Some(before) = before {
        if after.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if first.is_some() {
            return Err("'before' and 'first' cannot be specified simultaneously".into());
        }
        let (start, end) = filter.time();

        let last = last.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64::decode(before)?;
        let time = upper_closed_bound_key(key_prefix, end);
        if cursor.cmp(&time) == std::cmp::Ordering::Greater {
            return Err("invalid cursor".into());
        }
        let iter = store.boundary_iter(
            &cursor,
            &lower_closed_bound_key(key_prefix, start),
            Direction::Reverse,
        );

        (FilteredIter::new(iter, filter), Some(cursor), last)
    } else if let Some(after) = after {
        if before.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if last.is_some() {
            return Err("'after' and 'last' cannot be specified simultaneously".into());
        }
        let (start, end) = filter.time();

        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64::decode(after)?;
        let time = lower_closed_bound_key(key_prefix, start);
        if cursor.cmp(&time) == std::cmp::Ordering::Less {
            return Err("invalid cursor".into());
        }
        let iter = store.boundary_iter(
            &cursor,
            &upper_open_bound_key(key_prefix, end),
            Direction::Forward,
        );
        (FilteredIter::new(iter, filter), Some(cursor), first)
    } else if let Some(last) = last {
        if first.is_some() {
            return Err("first and last cannot be used together".into());
        }
        let (start, end) = filter.time();

        let last = last.min(MAXIMUM_PAGE_SIZE);
        let iter = store.boundary_iter(
            &upper_open_bound_key(key_prefix, end),
            &lower_closed_bound_key(key_prefix, start),
            Direction::Reverse,
        );
        (FilteredIter::new(iter, filter), None, last)
    } else {
        let (start, end) = filter.time();

        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let iter = store.boundary_iter(
            &lower_closed_bound_key(key_prefix, start),
            &upper_open_bound_key(key_prefix, end),
            Direction::Forward,
        );
        (FilteredIter::new(iter, filter), None, first)
    };

    Ok((iter, cursor, size))
}

#[cfg(test)]
struct TestSchema {
    _dir: tempfile::TempDir, // to prevent the data directory from being deleted while the test is running
    db: Database,
    schema: Schema,
}

#[cfg(test)]
impl TestSchema {
    fn new() -> Self {
        use std::{collections::HashMap, sync::Arc};
        use tokio::sync::RwLock;

        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path()).unwrap();
        let packet_sources = Arc::new(RwLock::new(HashMap::new()));
        let schema = schema(db.clone(), packet_sources);
        Self {
            _dir: db_dir,
            db,
            schema,
        }
    }
    async fn execute(&self, query: &str) -> async_graphql::Response {
        let request: async_graphql::Request = query.into();
        self.schema.execute(request).await
    }
}
