mod log;
mod network;

use crate::storage::{Database, RawEventStore};
use async_graphql::{EmptyMutation, EmptySubscription, MergedObject, Result};
use serde::de::DeserializeOwned;
use std::fmt::Debug;

#[derive(Default, MergedObject)]
pub struct Query(log::LogQuery, network::NetworkQuery);

pub enum PagingType {
    First(usize),
    Last(usize),
    AfterFirst(String, usize),
    BeforeLast(String, usize),
}

pub type Schema = async_graphql::Schema<Query, EmptyMutation, EmptySubscription>;

fn response_raw_events<'a, T, K>(source: &str, store: &RawEventStore<'a>) -> Result<Vec<K>>
where
    T: Debug + DeserializeOwned,
    K: From<T>,
{
    let mut raw_vec = Vec::new();
    for raw_data in store.src_raw_events(source) {
        let de_data = bincode::deserialize::<T>(&raw_data)?;
        raw_vec.push(K::from(de_data));
    }
    Ok(raw_vec)
}

pub fn schema(database: Database) -> Schema {
    Schema::build(Query::default(), EmptyMutation, EmptySubscription)
        .data(database)
        .finish()
}
