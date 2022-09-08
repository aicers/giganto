use crate::{ingestion, storage::Database};
use anyhow::{bail, Result};
use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema, SimpleObject};

pub struct Query;

#[derive(SimpleObject, Debug)]
pub struct ConnRawEvent {
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    duration: i64,
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
}

#[derive(SimpleObject, Debug)]
pub struct DnsRawEvent {
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    query: String,
}

impl From<ingestion::Conn> for ConnRawEvent {
    fn from(c: ingestion::Conn) -> ConnRawEvent {
        ConnRawEvent {
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

impl From<ingestion::DnsConn> for DnsRawEvent {
    fn from(d: ingestion::DnsConn) -> DnsRawEvent {
        DnsRawEvent {
            orig_addr: d.orig_addr.to_string(),
            resp_addr: d.resp_addr.to_string(),
            orig_port: d.orig_port,
            resp_port: d.resp_port,
            proto: d.proto,
            query: d.query,
        }
    }
}

#[Object]
impl Query {
    pub async fn conn_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
    ) -> Result<Vec<ConnRawEvent>> {
        let mut raw_vec = Vec::new();
        let db = match ctx.data::<Database>() {
            Ok(r) => r,
            Err(e) => bail!("{:?}", e),
        };
        for raw_data in db.conn_store()?.src_raw_events(&source) {
            let de_conn = bincode::deserialize::<ingestion::Conn>(&raw_data)?;
            raw_vec.push(ConnRawEvent::from(de_conn));
        }

        Ok(raw_vec)
    }

    pub async fn log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        kind: String,
    ) -> Result<Vec<String>> {
        let mut raw_vec = Vec::new();
        let db = match ctx.data::<Database>() {
            Ok(r) => r,
            Err(e) => bail!("{:?}", e),
        };
        for raw_data in db.log_store()?.src_raw_events(&source) {
            let de_log = bincode::deserialize::<ingestion::Log>(&raw_data)?;
            let (k, r) = de_log.log;
            if k == kind {
                raw_vec.push(base64::encode(r));
            }
        }
        Ok(raw_vec)
    }

    pub async fn dns_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
    ) -> Result<Vec<DnsRawEvent>> {
        let mut raw_vec = Vec::new();
        let db = match ctx.data::<Database>() {
            Ok(r) => r,
            Err(e) => bail!("{:?}", e),
        };
        for raw_data in db.dns_store()?.src_raw_events(&source) {
            let de_dns = bincode::deserialize::<ingestion::DnsConn>(&raw_data)?;
            raw_vec.push(DnsRawEvent::from(de_dns));
        }

        Ok(raw_vec)
    }
}

pub fn schema(database: Database) -> Schema<Query, EmptyMutation, EmptySubscription> {
    Schema::build(Query, EmptyMutation, EmptySubscription)
        .data(database)
        .finish()
}
