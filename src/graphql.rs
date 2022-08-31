use crate::{ingestion, storage::Database};
use anyhow::{bail, Result};
use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema, SimpleObject};

pub struct Query;

#[derive(SimpleObject, Debug)]
pub struct ConnRawEvents {
    pub orig_addr: String,
    pub resp_addr: String,
    pub orig_port: u16,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
}

impl From<ingestion::Conn> for ConnRawEvents {
    fn from(c: ingestion::Conn) -> ConnRawEvents {
        ConnRawEvents {
            orig_addr: c.orig_addr.to_string(),
            resp_addr: c.resp_addr.to_string(),
            orig_port: c.orig_port,
            resp_port: c.resp_port,
            proto: c.proto,
            duration: c.duration,
            orig_bytes: c.orig_bytes,
            resp_bytes: c.resp_bytes,
            orig_pkts: c.orig_pkts,
            resp_pkts: c.resp_pkts,
        }
    }
}

#[Object]
impl Query {
    pub async fn conn_raw_events<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Vec<ConnRawEvents>> {
        let mut raw_vec = Vec::new();
        let db = match ctx.data::<Database>() {
            Ok(r) => r,
            Err(e) => bail!("{:?}", e),
        };
        for raw_data in db.conn_store()?.all_raw_event() {
            let de_conn = bincode::deserialize::<ingestion::Conn>(&raw_data)?;
            raw_vec.push(ConnRawEvents::from(de_conn));
        }

        Ok(raw_vec)
    }
}

pub fn schema(database: Database) -> Schema<Query, EmptyMutation, EmptySubscription> {
    Schema::build(Query, EmptyMutation, EmptySubscription)
        .data(database)
        .finish()
}
