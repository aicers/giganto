mod log;
mod network;

use crate::storage::{
    lower_open_bound_key, upper_closed_bound_key, upper_open_bound_key, Database, Direction,
    KeyValue, RawEventStore,
};
use async_graphql::{
    connection::{Connection, Edge},
    EmptyMutation, EmptySubscription, MergedObject, OutputType, Result,
};
use chrono::{DateTime, Utc};

#[derive(Default, MergedObject)]
pub struct Query(log::LogQuery, network::NetworkQuery);

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

#[allow(clippy::too_many_arguments)]
fn load_connection<'c, N, I, T>(
    store: &RawEventStore<'c>,
    key_prefix: &[u8],
    iter_builder: fn(&RawEventStore<'c>, &[u8], &[u8], Direction) -> I,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, N>>
where
    N: From<T> + OutputType,
    I: Iterator<Item = anyhow::Result<(Box<[u8]>, T)>> + 'c,
{
    let (records, has_previous, has_next) = if let Some(before) = before {
        if after.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if first.is_some() {
            return Err("'before' and 'first' cannot be specified simultaneously".into());
        }
        let last = last.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64::decode(before)?;
        let mut iter = iter_builder(
            store,
            &cursor,
            &lower_open_bound_key(key_prefix, start),
            Direction::Reverse,
        )
        .peekable();
        if let Some(Ok((key, _))) = iter.peek() {
            if key.as_ref() == cursor {
                iter.next();
            }
        }
        let (mut records, has_previous) = collect_records(iter, last)?;
        records.reverse();
        (records, has_previous, false)
    } else if let Some(after) = after {
        if before.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if last.is_some() {
            return Err("'after' and 'last' cannot be specified simultaneously".into());
        }
        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64::decode(after)?;
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
        let (records, has_next) = collect_records(iter, first)?;
        (records, false, has_next)
    } else if let Some(last) = last {
        if first.is_some() {
            return Err("first and last cannot be used together".into());
        }
        let last = last.min(MAXIMUM_PAGE_SIZE);
        let iter = iter_builder(
            store,
            &upper_closed_bound_key(key_prefix, None),
            &lower_open_bound_key(key_prefix, start),
            Direction::Reverse,
        );
        let (mut records, has_previous) = collect_records(iter, last)?;
        records.reverse();
        (records, has_previous, false)
    } else {
        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let iter = iter_builder(
            store,
            key_prefix,
            &upper_open_bound_key(key_prefix, end),
            Direction::Forward,
        );
        let (records, has_next) = collect_records(iter, first)?;
        (records, false, has_next)
    };

    let mut connection: Connection<String, N> = Connection::new(has_previous, has_next);
    connection.edges = records
        .into_iter()
        .map(|(key, node)| Edge::new(base64::encode(key), N::from(node)))
        .collect();
    Ok(connection)
}

fn collect_records<I, T>(mut iter: I, size: usize) -> Result<(Vec<KeyValue<T>>, bool)>
where
    I: Iterator<Item = anyhow::Result<(Box<[u8]>, T)>>,
{
    let mut records = Vec::with_capacity(size);
    let mut has_more = false;
    while let Some(item) = iter.next() {
        let item = item.map_err(|e| format!("failed to read database: {}", e))?;
        records.push(item);
        if records.len() == size {
            has_more = iter.next().is_some();
            break;
        }
    }
    Ok((records, has_more))
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
