mod log;
mod network;

use std::net::IpAddr;

use crate::{
    ingestion::EventFilter,
    storage::{
        lower_closed_bound_key, upper_closed_bound_key, upper_open_bound_key, Database, Direction,
        KeyValue, RawEventStore,
    },
};
use anyhow::anyhow;
use async_graphql::{
    connection::{Connection, Edge},
    EmptyMutation, EmptySubscription, InputObject, MergedObject, OutputType, Result,
};
use chrono::{DateTime, TimeZone, Utc};

pub const TIMESTAMP_SIZE: usize = 8;

#[derive(Default, MergedObject)]
pub struct Query(log::LogQuery, network::NetworkQuery);

#[derive(InputObject)]
pub struct RawEventFilterInput {
    time: Option<TimeRange>,
    source: String,
    kind: Option<String>,
    pub orig_addr: Option<IpRange>,
    pub resp_addr: Option<IpRange>,
    pub orig_port: Option<PortRange>,
    pub resp_port: Option<PortRange>,
}

impl RawEventFilterInput {
    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
    ) -> Result<bool> {
        if let Some(ip_range) = &self.orig_addr {
            if let Some(orig_addr) = orig_addr {
                let end = if let Some(end) = &ip_range.end {
                    orig_addr >= end.parse::<IpAddr>()?
                } else {
                    false
                };

                let start = if let Some(start) = &ip_range.start {
                    orig_addr < start.parse::<IpAddr>()?
                } else {
                    false
                };
                if end || start {
                    return Ok(false);
                };
            }
        }
        if let Some(ip_range) = &self.resp_addr {
            if let Some(resp_addr) = resp_addr {
                let end = if let Some(end) = &ip_range.end {
                    resp_addr >= end.parse::<IpAddr>()?
                } else {
                    false
                };

                let start = if let Some(start) = &ip_range.start {
                    resp_addr < start.parse::<IpAddr>()?
                } else {
                    false
                };
                if end || start {
                    return Ok(false);
                };
            }
        }
        if let Some(port_range) = &self.orig_port {
            if let Some(orig_port) = orig_port {
                let end = if let Some(end) = port_range.end {
                    orig_port >= end
                } else {
                    false
                };
                let start = if let Some(start) = port_range.start {
                    orig_port < start
                } else {
                    false
                };
                if end || start {
                    return Ok(false);
                };
            }
        }
        if let Some(port_range) = &self.resp_port {
            if let Some(resp_port) = resp_port {
                let end = if let Some(end) = port_range.end {
                    resp_port >= end
                } else {
                    false
                };
                let start = if let Some(start) = port_range.start {
                    resp_port < start
                } else {
                    false
                };
                if end || start {
                    return Ok(false);
                };
            }
        }
        Ok(true)
    }
}

#[derive(InputObject)]
struct TimeRange {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}

#[derive(InputObject)]
pub struct IpRange {
    pub start: Option<String>,
    pub end: Option<String>,
}

#[derive(InputObject)]
pub struct PortRange {
    pub start: Option<u16>,
    pub end: Option<u16>,
}

pub trait FromKeyValue<T>: Sized {
    fn from_key_value(key: &[u8], value: T) -> Result<Self>;
}

pub type Schema = async_graphql::Schema<Query, EmptyMutation, EmptySubscription>;

pub fn schema(database: Database) -> Schema {
    Schema::build(Query::default(), EmptyMutation, EmptySubscription)
        .data(database)
        .finish()
}

/// The default page size for connections when neither `first` nor `last` is
/// provided.
/// Maximum size: 100.
const MAXIMUM_PAGE_SIZE: usize = 100;

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn load_connection<'c, N, I, T>(
    store: &RawEventStore<'c>,
    key_prefix: &[u8],
    iter_builder: fn(&RawEventStore<'c>, &[u8], &[u8], Direction) -> I,
    filter: &RawEventFilterInput,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, N>>
where
    N: FromKeyValue<T> + OutputType,
    I: Iterator<Item = anyhow::Result<(Box<[u8]>, T)>> + 'c,
    T: EventFilter,
{
    let (records, has_previous, has_next) = if let Some(before) = before {
        if after.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if first.is_some() {
            return Err("'before' and 'first' cannot be specified simultaneously".into());
        }
        let (start, end) = if let Some(ref time) = filter.time {
            (time.start, time.end)
        } else {
            (None, None)
        };

        let last = last.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64::decode(before)?;
        let time = upper_closed_bound_key(key_prefix, end);
        if cursor.cmp(&time) == std::cmp::Ordering::Greater {
            return Err("invalid cursor".into());
        }
        let mut iter = iter_builder(
            store,
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
        let (start, end) = if let Some(ref time) = filter.time {
            (time.start, time.end)
        } else {
            (None, None)
        };

        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64::decode(after)?;
        let time = lower_closed_bound_key(key_prefix, start);
        if cursor.cmp(&time) == std::cmp::Ordering::Less {
            return Err("invalid cursor".into());
        }
        let mut iter = iter_builder(
            store,
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
        let (start, end) = if let Some(ref time) = filter.time {
            (time.start, time.end)
        } else {
            (None, None)
        };

        let last = last.min(MAXIMUM_PAGE_SIZE);
        let iter = iter_builder(
            store,
            &upper_open_bound_key(key_prefix, end),
            &lower_closed_bound_key(key_prefix, start),
            Direction::Reverse,
        );
        let (mut records, has_previous) = collect_records(iter, last, filter)?;
        records.reverse();
        (records, has_previous, false)
    } else {
        let (start, end) = if let Some(ref time) = filter.time {
            (time.start, time.end)
        } else {
            (None, None)
        };

        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let iter = iter_builder(
            store,
            &lower_closed_bound_key(key_prefix, start),
            &upper_open_bound_key(key_prefix, end),
            Direction::Forward,
        );
        let (records, has_next) = collect_records(iter, first, filter)?;
        (records, false, has_next)
    };

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
    filter: &RawEventFilterInput,
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

#[cfg(test)]
struct TestSchema {
    _dir: tempfile::TempDir, // to prevent the data directory from being deleted while the test is running
    db: Database,
    schema: Schema,
}

#[cfg(test)]
impl TestSchema {
    fn new() -> Self {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path()).unwrap();
        let schema = schema(db.clone());
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
