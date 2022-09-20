use crate::{
    ingestion,
    storage::{gen_key, Database, RawEventStore},
};
use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection, Edge},
    Context, EmptyMutation, EmptySubscription, Object, Result, SimpleObject,
};
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

pub enum PagingType {
    First(usize),
    Last(usize),
    AfterFirst(String, usize),
    BeforeLast(String, usize),
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
        let db = ctx.data::<Database>()?;
        response_raw_events::<ingestion::Conn, ConnRawEvent>(&source, &db.conn_store()?)
    }

    #[allow(clippy::too_many_arguments)]
    async fn log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        kind: String,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, LogRawEvent>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_paging_type(ctx, &source, &kind, after, before, first, last)
            },
        )
        .await
    }

    async fn dns_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<DnsRawEvent>> {
        let mut raw_vec = Vec::new();
        let db = ctx.data::<Database>()?;

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
        let db = ctx.data::<Database>()?;
        response_raw_events::<ingestion::HttpConn, HttpRawEvent>(&source, &db.http_store()?)
    }

    async fn rdp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
    ) -> Result<Vec<RdpRawEvent>> {
        let db = ctx.data::<Database>()?;
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
    Err(anyhow!("Invalid paging type"))
}

fn load_paging_type(
    ctx: &Context<'_>,
    source: &str,
    kind: &str,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, LogRawEvent>> {
    let db = ctx.data::<Database>()?;
    let paging_type = check_paging_type(after, before, first, last)?;

    let args: Vec<Vec<u8>> = vec![source.as_bytes().to_vec(), kind.as_bytes().to_vec()];
    let source_kind = String::from_utf8(gen_key(args))?;

    let (logs, prev, next) = db.log_store()?.log_events(&source_kind, paging_type);
    let mut connection: Connection<String, LogRawEvent> = Connection::new(prev, next);
    for log_data in logs {
        let (key, raw_data) = log_data;
        let de_log = bincode::deserialize::<ingestion::Log>(&raw_data)?;
        connection
            .edges
            .push(Edge::new(base64::encode(key), LogRawEvent::from(de_log)));
    }
    Ok(connection)
}

pub fn schema(database: Database) -> Schema {
    Schema::build(Query, EmptyMutation, EmptySubscription)
        .data(database)
        .finish()
}
