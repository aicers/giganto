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
