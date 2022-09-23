use crate::{
    ingestion,
    storage::{gen_key, Database},
};
use async_graphql::{
    connection::{query, Connection, Edge},
    Context, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use std::fmt::Debug;

use super::PagingType;

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
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_paging_type_conn(ctx, &source, after, before, first, last)
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
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_paging_type_dns(ctx, &source, start, end, after, before, first, last)
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
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_paging_type_http(ctx, &source, after, before, first, last)
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
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_paging_type_rdp(ctx, &source, after, before, first, last)
            },
        )
        .await
    }
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

fn load_paging_type_conn(
    ctx: &Context<'_>,
    source: &str,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, ConnRawEvent>> {
    let db = ctx.data::<Database>()?;
    let paging_type = check_paging_type(after, before, first, last)?;

    let args: Vec<Vec<u8>> = vec![source.as_bytes().to_vec()];
    let source = String::from_utf8(gen_key(args))?;

    let (conn, prev, next) = db.conn_store()?.conn_events(&source, paging_type);
    let mut connection: Connection<String, ConnRawEvent> = Connection::new(prev, next);
    for conn_data in conn {
        let (key, raw_data) = conn_data;
        let de_conn = bincode::deserialize::<ingestion::Conn>(&raw_data)?;
        connection
            .edges
            .push(Edge::new(base64::encode(key), ConnRawEvent::from(de_conn)));
    }
    Ok(connection)
}

#[allow(clippy::too_many_arguments)]
fn load_paging_type_dns(
    ctx: &Context<'_>,
    source: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, DnsRawEvent>> {
    let db = ctx.data::<Database>()?;
    let paging_type = check_paging_type(after, before, first, last)?;

    let args: Vec<Vec<u8>> = vec![source.as_bytes().to_vec()];
    let source = String::from_utf8(gen_key(args))?;

    let (dns, prev, next) = db
        .dns_store()?
        .dns_time_events(&source, &start, &end, paging_type);
    let mut connection: Connection<String, DnsRawEvent> = Connection::new(prev, next);
    for dns_data in dns {
        let (key, raw_data) = dns_data;
        let de_dns = bincode::deserialize::<ingestion::DnsConn>(&raw_data)?;
        connection
            .edges
            .push(Edge::new(base64::encode(key), DnsRawEvent::from(de_dns)));
    }
    Ok(connection)
}

fn load_paging_type_http(
    ctx: &Context<'_>,
    source: &str,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, HttpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let paging_type = check_paging_type(after, before, first, last)?;

    let args: Vec<Vec<u8>> = vec![source.as_bytes().to_vec()];
    let source = String::from_utf8(gen_key(args))?;

    let (http, prev, next) = db.http_store()?.http_events(&source, paging_type);
    let mut connection: Connection<String, HttpRawEvent> = Connection::new(prev, next);
    for http_data in http {
        let (key, raw_data) = http_data;
        let de_http = bincode::deserialize::<ingestion::HttpConn>(&raw_data)?;
        connection
            .edges
            .push(Edge::new(base64::encode(key), HttpRawEvent::from(de_http)));
    }
    Ok(connection)
}

fn load_paging_type_rdp(
    ctx: &Context<'_>,
    source: &str,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, RdpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let paging_type = check_paging_type(after, before, first, last)?;

    let args: Vec<Vec<u8>> = vec![source.as_bytes().to_vec()];
    let source = String::from_utf8(gen_key(args))?;

    let (rdp, prev, next) = db.rdp_store()?.rdp_events(&source, paging_type);
    let mut connection: Connection<String, RdpRawEvent> = Connection::new(prev, next);
    for rdp_data in rdp {
        let (key, raw_data) = rdp_data;
        let de_rdp = bincode::deserialize::<ingestion::RdpConn>(&raw_data)?;
        connection
            .edges
            .push(Edge::new(base64::encode(key), RdpRawEvent::from(de_rdp)));
    }
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    use crate::ingestion::{Conn, DnsConn, HttpConn, RdpConn};
    use chrono::{Duration, Utc};
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

        let mut key = b"einsis\x00".to_vec();
        key.extend(Utc::now().timestamp_nanos().to_be_bytes());

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

        schema
            .db
            .conn_store()
            .unwrap()
            .append(&key[..], &ser_conn_body)
            .unwrap();

        let query = r#"
        {
            connRawEvents (source: "einsis", first: 1) {
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
            "{httpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378,respPort: 80,method: \"POST\",host: \"einsis\",uri: \"/einsis.gif\",referrer: \"einsis.com\",userAgent: \"giganto\",statusCode: 200}}],pageInfo: {hasPreviousPage: true}}}"
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
            "{rdpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378,respPort: 80,cookie: \"rdp_test\"}}],pageInfo: {hasPreviousPage: true}}}"
        );
    }
}
