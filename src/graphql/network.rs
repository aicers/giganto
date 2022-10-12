use super::{get_timestamp, load_connection, FromKeyValue};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    ingestion,
    storage::{Database, RawEventStore},
};
use async_graphql::{
    connection::{query, Connection},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{fmt::Debug, net::IpAddr};

#[derive(Default)]
pub(super) struct NetworkQuery;

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct NetworkFilter {
    time: Option<TimeRange>,
    #[serde(skip)]
    pub source: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
}

#[derive(InputObject, Serialize)]
pub struct IpRange {
    start: Option<String>,
    end: Option<String>,
}

#[derive(InputObject, Serialize)]
pub struct PortRange {
    start: Option<u16>,
    end: Option<u16>,
}

impl RawEventFilter for NetworkFilter {
    fn time(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }

    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
    ) -> Result<bool> {
        if let Some(ip_range) = &self.orig_addr {
            if let Some(orig_addr) = orig_addr {
                let end = if let Some(end) = &ip_range.end {
                    orig_addr >= end.parse::<IpAddr>()?
                } else {
                    false
                };

                let start = if let Some(start) = &ip_range.start {
                    orig_addr < start.parse::<IpAddr>()?
                } else {
                    false
                };
                if end || start {
                    return Ok(false);
                };
            }
        }
        if let Some(ip_range) = &self.resp_addr {
            if let Some(resp_addr) = resp_addr {
                let end = if let Some(end) = &ip_range.end {
                    resp_addr >= end.parse::<IpAddr>()?
                } else {
                    false
                };

                let start = if let Some(start) = &ip_range.start {
                    resp_addr < start.parse::<IpAddr>()?
                } else {
                    false
                };
                if end || start {
                    return Ok(false);
                };
            }
        }
        if let Some(port_range) = &self.orig_port {
            if let Some(orig_port) = orig_port {
                let end = if let Some(end) = port_range.end {
                    orig_port >= end
                } else {
                    false
                };
                let start = if let Some(start) = port_range.start {
                    orig_port < start
                } else {
                    false
                };
                if end || start {
                    return Ok(false);
                };
            }
        }
        if let Some(port_range) = &self.resp_port {
            if let Some(resp_port) = resp_port {
                let end = if let Some(end) = port_range.end {
                    resp_port >= end
                } else {
                    false
                };
                let start = if let Some(start) = port_range.start {
                    resp_port < start
                } else {
                    false
                };
                if end || start {
                    return Ok(false);
                };
            }
        }
        Ok(true)
    }
}

#[derive(SimpleObject, Debug)]
struct ConnRawEvent {
    timestamp: DateTime<Utc>,
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
    timestamp: DateTime<Utc>,
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    query: String,
}

#[derive(SimpleObject, Debug)]
struct HttpRawEvent {
    timestamp: DateTime<Utc>,
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
    timestamp: DateTime<Utc>,
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    cookie: String,
}

impl FromKeyValue<ingestion::Conn> for ConnRawEvent {
    fn from_key_value(key: &[u8], c: ingestion::Conn) -> Result<Self> {
        let timestamp = get_timestamp(key)?;
        Ok(ConnRawEvent {
            timestamp,
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
        })
    }
}

impl FromKeyValue<ingestion::DnsConn> for DnsRawEvent {
    fn from_key_value(key: &[u8], d: ingestion::DnsConn) -> Result<Self> {
        let timestamp = get_timestamp(key)?;
        Ok(DnsRawEvent {
            timestamp,
            orig_addr: d.orig_addr.to_string(),
            resp_addr: d.resp_addr.to_string(),
            orig_port: d.orig_port,
            resp_port: d.resp_port,
            proto: d.proto,
            query: d.query,
        })
    }
}

impl FromKeyValue<ingestion::HttpConn> for HttpRawEvent {
    fn from_key_value(key: &[u8], h: ingestion::HttpConn) -> Result<Self> {
        let timestamp = get_timestamp(key)?;
        Ok(HttpRawEvent {
            timestamp,
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
        })
    }
}

impl FromKeyValue<ingestion::RdpConn> for RdpRawEvent {
    fn from_key_value(key: &[u8], r: ingestion::RdpConn) -> Result<Self> {
        let timestamp = get_timestamp(key)?;
        Ok(RdpRawEvent {
            timestamp,
            orig_addr: r.orig_addr.to_string(),
            resp_addr: r.resp_addr.to_string(),
            orig_port: r.orig_port,
            resp_port: r.resp_port,
            cookie: r.cookie,
        })
    }
}

#[Object]
impl NetworkQuery {
    async fn conn_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ConnRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.conn_store()?;
        let key_prefix = key_prefix(&filter.source);

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
                    &filter,
                    after,
                    before,
                    first,
                    last,
                )
            },
        )
        .await
    }

    async fn dns_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DnsRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.dns_store()?;
        let key_prefix = key_prefix(&filter.source);

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
                    &filter,
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
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, HttpRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.http_store()?;
        let key_prefix = key_prefix(&filter.source);

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
                    &filter,
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
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RdpRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.rdp_store()?;
        let key_prefix = key_prefix(&filter.source);

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
                    &filter,
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
            connRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                    source: "a"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 50, end: 200 }
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
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

        insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            connRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46378, end: 46379 }
                    respPort: { start: 50, end: 200 }
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
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
            dnsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                    source: "einsis"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "31.3.245.123", end: "31.3.245.143" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 100, end: 200 }
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
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
            "{dnsRawEvents: {edges: [],pageInfo: {hasPreviousPage: false}}}"
        );
    }

    #[tokio::test]
    async fn dns_with_data() {
        let schema = TestSchema::new();

        let mut key = b"einsis\x00".to_vec();
        let timestamp = Utc::now().timestamp_nanos();
        key.extend(timestamp.to_be_bytes());

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
            dnsRawEvents(
                filter: {
                    source: "einsis"
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                last: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{dnsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"31.3.245.133\",origPort: 46378}}]}}"
        );
    }

    #[tokio::test]
    async fn http_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            httpRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2024-09-22T00:00:00Z" }
                    source: "einsis"
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
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
        let timestamp = Utc::now().timestamp_nanos();
        key.extend(timestamp.to_be_bytes());

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
            httpRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                    source: "einsis"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{httpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
        );
    }

    #[tokio::test]
    async fn rdp_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            rdpRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                    source: "einsis"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respPort: { start: 0, end: 200 }
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
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
        let timestamp = Utc::now().timestamp_nanos();
        key.extend(timestamp.to_be_bytes());

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
            rdpRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                    source: "einsis"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
            first: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{rdpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
        );
    }

    #[tokio::test]
    async fn conn_with_start_or_end() {
        let schema = TestSchema::new();
        let store = schema.db.conn_store().unwrap();

        insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            connRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75" }
                    origPort: { end: 46380 }
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                        respPort,
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378,respPort: 80}}]}}"
        );
    }
}
