use crate::{
    ingestion,
    storage::{gen_key, Database, RawEventStore},
};
use anyhow::{bail, Result};
use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, SimpleObject};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use std::fmt::Debug;

pub struct Query;

pub type Schema = async_graphql::Schema<Query, EmptyMutation, EmptySubscription>;

#[derive(SimpleObject, Debug)]
struct ConnRawEvent {
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
struct DnsRawEvent {
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    query: String,
}

#[derive(SimpleObject, Debug)]
struct HttpRawEvent {
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    method: String,
    host: String,
    uri: String,
    referrer: String,
    user_agent: String,
    status_code: u16,
}

#[derive(SimpleObject, Debug)]
struct RdpRawEvent {
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    cookie: String,
}

#[derive(SimpleObject, Debug)]
struct LogRawEvent {
    log: String,
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

impl From<ingestion::HttpConn> for HttpRawEvent {
    fn from(h: ingestion::HttpConn) -> HttpRawEvent {
        HttpRawEvent {
            orig_addr: h.orig_addr.to_string(),
            resp_addr: h.resp_addr.to_string(),
            orig_port: h.orig_port,
            resp_port: h.resp_port,
            method: h.method,
            host: h.host,
            uri: h.uri,
            referrer: h.referrer,
            user_agent: h.user_agent,
            status_code: h.status_code,
        }
    }
}

impl From<ingestion::RdpConn> for RdpRawEvent {
    fn from(r: ingestion::RdpConn) -> RdpRawEvent {
        RdpRawEvent {
            orig_addr: r.orig_addr.to_string(),
            resp_addr: r.resp_addr.to_string(),
            orig_port: r.orig_port,
            resp_port: r.resp_port,
            cookie: r.cookie,
        }
    }
}

impl From<ingestion::Log> for LogRawEvent {
    fn from(l: ingestion::Log) -> LogRawEvent {
        let (_, log) = l.log;
        LogRawEvent {
            log: base64::encode(log),
        }
    }
}

#[Object]
impl Query {
    async fn conn_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
    ) -> Result<Vec<ConnRawEvent>> {
        let db = match ctx.data::<Database>() {
            Ok(r) => r,
            Err(e) => bail!("{:?}", e),
        };

        response_raw_events::<ingestion::Conn, ConnRawEvent>(&source, &db.conn_store()?)
    }

    async fn log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        kind: String,
    ) -> Result<Vec<LogRawEvent>> {
        let db = match ctx.data::<Database>() {
            Ok(r) => r,
            Err(e) => bail!("{:?}", e),
        };

        let args: Vec<Vec<u8>> = vec![source.as_bytes().to_vec(), kind.as_bytes().to_vec()];
        let source = String::from_utf8(gen_key(args))?;

        response_raw_events::<ingestion::Log, LogRawEvent>(&source, &db.log_store()?)
    }

    async fn dns_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<DnsRawEvent>> {
        let mut raw_vec = Vec::new();
        let db = match ctx.data::<Database>() {
            Ok(r) => r,
            Err(e) => bail!("{:?}", e),
        };

        for raw_data in db.dns_store()?.dns_time_events(&source, &start, &end) {
            let de_dns = bincode::deserialize::<ingestion::DnsConn>(&raw_data)?;
            raw_vec.push(DnsRawEvent::from(de_dns));
        }

        Ok(raw_vec)
    }

    async fn http_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
    ) -> Result<Vec<HttpRawEvent>> {
        let db = match ctx.data::<Database>() {
            Ok(r) => r,
            Err(e) => bail!("{:?}", e),
        };

        response_raw_events::<ingestion::HttpConn, HttpRawEvent>(&source, &db.http_store()?)
    }

    async fn rdp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
    ) -> Result<Vec<RdpRawEvent>> {
        let db = match ctx.data::<Database>() {
            Ok(r) => r,
            Err(e) => bail!("{:?}", e),
        };

        response_raw_events::<ingestion::RdpConn, RdpRawEvent>(&source, &db.rdp_store()?)
    }
}

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
    Schema::build(Query, EmptyMutation, EmptySubscription)
        .data(database)
        .finish()
}
