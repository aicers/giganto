use super::load_connection;
use crate::{
    ingestion,
    storage::{Database, RawEventStore},
};
use async_graphql::{
    connection::{query, Connection},
    Context, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use std::fmt::Debug;

#[derive(Default)]
pub(super) struct NetworkQuery;

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

#[Object]
impl NetworkQuery {
    async fn conn_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ConnRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.conn_store()?;
        let key_prefix = key_prefix(&source);

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(
                    &store,
                    &key_prefix,
                    RawEventStore::conn_iter,
                    None,
                    None,
                    after,
                    before,
                    first,
                    last,
                )
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn dns_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DnsRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.dns_store()?;
        let key_prefix = key_prefix(&source);

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(
                    &store,
                    &key_prefix,
                    RawEventStore::dns_iter,
                    Some(start),
                    Some(end),
                    after,
                    before,
                    first,
                    last,
                )
            },
        )
        .await
    }

    async fn http_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, HttpRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.http_store()?;
        let key_prefix = key_prefix(&source);

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(
                    &store,
                    &key_prefix,
                    RawEventStore::http_iter,
                    None,
                    None,
                    after,
                    before,
                    first,
                    last,
                )
            },
        )
        .await
    }

    async fn rdp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RdpRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.rdp_store()?;
        let key_prefix = key_prefix(&source);

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(
                    &store,
                    &key_prefix,
                    RawEventStore::rdp_iter,
                    None,
                    None,
                    after,
                    before,
                    first,
                    last,
                )
            },
        )
        .await
    }
}

fn key_prefix(source: &str) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(source.len() + 1);
    prefix.extend_from_slice(source.as_bytes());
    prefix.push(0);
    prefix
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    use crate::ingestion::{Conn, DnsConn, HttpConn, RdpConn};
    use crate::storage::RawEventStore;
    use chrono::{Duration, Utc};
    use std::mem;
    use std::net::IpAddr;

    #[tokio::test]
    async fn conn_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            connRawEvents (source: "einsis", first: 0) {
                edges {
                    node {
                        origAddr
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(res.data.to_string(), "{connRawEvents: {edges: []}}");
    }

    #[tokio::test]
    async fn conn_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.conn_store().unwrap();

        insert_conn_raw_event(&store, "src 1", 1);
        insert_conn_raw_event(&store, "src 1", 2);

        let query = r#"
        {
            connRawEvents (source: "src 1", last: 1) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                        respPort,
                        proto,
                        duration,
                        origBytes,
                        respBytes,
                        origPkts,
                        respPkts,
                    }
                }
                pageInfo {
                    hasPreviousPage
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378,respPort: 80,proto: 6,duration: 12345,origBytes: 77,respBytes: 295,origPkts: 397,respPkts: 511}}],pageInfo: {hasPreviousPage: true}}}"
        );
    }

    fn insert_conn_raw_event(store: &RawEventStore, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let tmp_dur = Duration::nanoseconds(12345);
        let conn_body = Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            proto: 6,
            duration: tmp_dur.num_nanoseconds().unwrap(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
        };
        let ser_conn_body = bincode::serialize(&conn_body).unwrap();

        store.append(&key, &ser_conn_body).unwrap();
    }

    #[tokio::test]
    async fn dns_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            dnsRawEvents (source: "einsis", start:"1998-07-01T00:00:00Z", end:"2023-07-01T00:00:00Z", first: 0) {
                edges {
                    node {
                        origAddr
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(res.data.to_string(), "{dnsRawEvents: {edges: []}}");
    }

    #[tokio::test]
    async fn dns_with_data() {
        let schema = TestSchema::new();

        let mut key = b"einsis\x00".to_vec();
        key.extend(Utc::now().timestamp_nanos().to_be_bytes());

        let dns_body = DnsConn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            proto: 17,
            query: "Hello Server Hello Server Hello Server".to_string(),
        };
        let ser_dns_body = bincode::serialize(&dns_body).unwrap();

        schema
            .db
            .dns_store()
            .unwrap()
            .append(&key[..], &ser_dns_body)
            .unwrap();

        let query = r#"
        {
            dnsRawEvents (source: "einsis", start:"1998-07-01T00:00:00Z", end:"2023-07-01T00:00:00Z", first: 1) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                        respPort,
                        proto,
                        query,
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{dnsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"31.3.245.133\",origPort: 46378,respPort: 80,proto: 17,query: \"Hello Server Hello Server Hello Server\"}}]}}"
        );
    }

    #[tokio::test]
    async fn http_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            httpRawEvents (source: "einsis", first: 0) {
                edges {
                    node {
                        origAddr
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(res.data.to_string(), "{httpRawEvents: {edges: []}}");
    }

    #[tokio::test]
    async fn http_with_data() {
        let schema = TestSchema::new();

        let mut key = b"einsis\x00".to_vec();
        key.extend(Utc::now().timestamp_nanos().to_be_bytes());

        let http_body = HttpConn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            method: "POST".to_string(),
            host: "einsis".to_string(),
            uri: "/einsis.gif".to_string(),
            referrer: "einsis.com".to_string(),
            user_agent: "giganto".to_string(),
            status_code: 200,
        };
        let ser_http_body = bincode::serialize(&http_body).unwrap();

        schema
            .db
            .http_store()
            .unwrap()
            .append(&key[..], &ser_http_body)
            .unwrap();

        let query = r#"
        {
            httpRawEvents (source: "einsis", first: 1) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                        respPort,
                        method,
                        host,
                        uri,
                        referrer,
                        userAgent,
                        statusCode,
                    }
                }
                pageInfo {
                    hasPreviousPage
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{httpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378,respPort: 80,method: \"POST\",host: \"einsis\",uri: \"/einsis.gif\",referrer: \"einsis.com\",userAgent: \"giganto\",statusCode: 200}}],pageInfo: {hasPreviousPage: false}}}"
        );
    }

    #[tokio::test]
    async fn rdp_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            rdpRawEvents (source: "einsis", first: 0) {
                edges {
                    node {
                        origAddr
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(res.data.to_string(), "{rdpRawEvents: {edges: []}}");
    }

    #[tokio::test]
    async fn rdp_with_data() {
        let schema = TestSchema::new();

        let mut key = b"einsis\x00".to_vec();
        key.extend(Utc::now().timestamp_nanos().to_be_bytes());

        let rdp_body = RdpConn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            cookie: "rdp_test".to_string(),
        };
        let ser_rdp_body = bincode::serialize(&rdp_body).unwrap();

        schema
            .db
            .rdp_store()
            .unwrap()
            .append(&key[..], &ser_rdp_body)
            .unwrap();

        let query = r#"
        {
            rdpRawEvents (source: "einsis", first: 1) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                        respPort,
                        cookie,
                    }
                }
                pageInfo {
                    hasPreviousPage
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{rdpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378,respPort: 80,cookie: \"rdp_test\"}}],pageInfo: {hasPreviousPage: false}}}"
        );
    }
}
