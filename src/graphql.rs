mod log;
mod network;

use crate::storage::Database;
use async_graphql::{EmptyMutation, EmptySubscription, MergedObject};

#[derive(Default, MergedObject)]
pub struct Query(log::LogQuery, network::NetworkQuery);

pub enum PagingType {
    First(usize),
    Last(usize),
    AfterFirst(String, usize),
    BeforeLast(String, usize),
}
pub type Schema = async_graphql::Schema<Query, EmptyMutation, EmptySubscription>;

pub fn schema(database: Database) -> Schema {
    Schema::build(Query::default(), EmptyMutation, EmptySubscription)
        .data(database)
        .finish()
}

fn check_paging_type(
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> anyhow::Result<PagingType> {
    if let Some(val) = first {
        if let Some(cursor) = after {
            return Ok(PagingType::AfterFirst(cursor, val));
        }
        return Ok(PagingType::First(val));
    }
    if let Some(val) = last {
        if let Some(cursor) = before {
            return Ok(PagingType::BeforeLast(cursor, val));
        }
        return Ok(PagingType::Last(val));
    }
    Err(anyhow::anyhow!("Invalid paging type"))
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
