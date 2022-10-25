use super::{get_filtered_iter, get_timestamp, load_connection, FromKeyValue};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    ingestion::{Conn, DnsConn, HttpConn, RdpConn},
    storage::{Database, FilteredIter},
};
use async_graphql::{
    connection::{query, Connection, Edge},
    Context, InputObject, Object, Result, SimpleObject, Union,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{fmt::Debug, iter::Peekable, net::IpAddr};

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

#[allow(clippy::enum_variant_names)]
#[derive(Union)]
enum NetworkRawEvents {
    ConnRawEvent(ConnRawEvent),
    DnsRawEvent(DnsRawEvent),
    HttpRawEvent(HttpRawEvent),
    RdpRawEvent(RdpRawEvent),
}

macro_rules! from_key_value {
    ($to:ty, $from:ty, $($fields:ident),*) => {
        impl FromKeyValue<$from> for $to {
            fn from_key_value(key: &[u8], val: $from) -> Result<Self> {
                let timestamp = get_timestamp(key)?;
                Ok(Self {
                    timestamp,
                    orig_addr: val.orig_addr.to_string(),
                    resp_addr: val.resp_addr.to_string(),
                    orig_port: val.orig_port,
                    resp_port: val.resp_port,
                    $(
                        $fields: val.$fields,
                    )*
                })
            }
        }
    };
}

from_key_value!(
    ConnRawEvent,
    Conn,
    proto,
    duration,
    orig_bytes,
    resp_bytes,
    orig_pkts,
    resp_pkts
);
from_key_value!(DnsRawEvent, DnsConn, proto, query);
from_key_value!(
    HttpRawEvent,
    HttpConn,
    method,
    host,
    uri,
    referrer,
    user_agent,
    status_code
);
from_key_value!(RdpRawEvent, RdpConn, cookie);

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
                load_connection(&store, &key_prefix, &filter, after, before, first, last)
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
                load_connection(&store, &key_prefix, &filter, after, before, first, last)
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
                load_connection(&store, &key_prefix, &filter, after, before, first, last)
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
                load_connection(&store, &key_prefix, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn network_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, NetworkRawEvents>> {
        let db = ctx.data::<Database>()?;
        let key_prefix = key_prefix(&filter.source);
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let (conn_iter, cursor, size) = get_filtered_iter(
                    &db.conn_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut conn_iter = conn_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = conn_iter.peek() {
                        if key.as_ref() == cursor {
                            conn_iter.next();
                        }
                    }
                }

                let (dns_iter, cursor, _) = get_filtered_iter(
                    &db.dns_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut dns_iter = dns_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = dns_iter.peek() {
                        if key.as_ref() == cursor {
                            dns_iter.next();
                        }
                    }
                }

                let (http_iter, cursor, _) = get_filtered_iter(
                    &db.http_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut http_iter = http_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = http_iter.peek() {
                        if key.as_ref() == cursor {
                            http_iter.next();
                        }
                    }
                }

                let (rdp_iter, cursor, _) = get_filtered_iter(
                    &db.rdp_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut rdp_iter = rdp_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = rdp_iter.peek() {
                        if key.as_ref() == cursor {
                            rdp_iter.next();
                        }
                    }
                }

                let mut is_forward: bool = true;
                if before.is_some() || last.is_some() {
                    is_forward = false;
                }

                network_connection(conn_iter, dns_iter, http_iter, rdp_iter, size, is_forward)
            },
        )
        .await
    }
}

fn network_connection(
    mut conn_iter: Peekable<FilteredIter<Conn>>,
    mut dns_iter: Peekable<FilteredIter<DnsConn>>,
    mut http_iter: Peekable<FilteredIter<HttpConn>>,
    mut rdp_iter: Peekable<FilteredIter<RdpConn>>,
    size: usize,
    is_forward: bool,
) -> Result<Connection<String, NetworkRawEvents>> {
    let timestamp = Utc::now();
    let mut result_vec: Vec<Edge<String, NetworkRawEvents, _>> = Vec::new();
    let mut has_previous_page: bool = false;
    let mut has_next_page: bool = false;
    let mut has_next_value: bool = false;

    let mut conn_data = conn_iter.next();
    let mut dns_data = dns_iter.next();
    let mut http_data = http_iter.next();
    let mut rdp_data = rdp_iter.next();

    loop {
        let conn_ts = if let Some((ref key, _)) = conn_data {
            get_timestamp(key)?
        } else {
            Utc::now()
        };

        let dns_ts = if let Some((ref key, _)) = dns_data {
            get_timestamp(key)?
        } else {
            Utc::now()
        };

        let http_ts = if let Some((ref key, _)) = http_data {
            get_timestamp(key)?
        } else {
            Utc::now()
        };

        let rdp_ts = if let Some((ref key, _)) = rdp_data {
            get_timestamp(key)?
        } else {
            Utc::now()
        };
        let selected = if is_forward {
            timestamp.min(dns_ts.min(conn_ts.min(http_ts.min(rdp_ts))))
        } else {
            timestamp.max(dns_ts.max(conn_ts.max(http_ts.max(rdp_ts))))
        };
        if selected == conn_ts {
            if let Some((key, value)) = conn_data {
                result_vec.push(Edge::new(
                    base64::encode(&key),
                    NetworkRawEvents::ConnRawEvent(ConnRawEvent::from_key_value(&key, value)?),
                ));
                conn_data = conn_iter.next();
            } else {
            };
        } else if selected == dns_ts {
            if let Some((key, value)) = dns_data {
                result_vec.push(Edge::new(
                    base64::encode(&key),
                    NetworkRawEvents::DnsRawEvent(DnsRawEvent::from_key_value(&key, value)?),
                ));
                dns_data = dns_iter.next();
            } else {
            };
        } else if selected == http_ts {
            if let Some((key, value)) = http_data {
                result_vec.push(Edge::new(
                    base64::encode(&key),
                    NetworkRawEvents::HttpRawEvent(HttpRawEvent::from_key_value(&key, value)?),
                ));
                http_data = http_iter.next();
            } else {
            };
        } else if selected == rdp_ts {
            if let Some((key, value)) = rdp_data {
                result_vec.push(Edge::new(
                    base64::encode(&key),
                    NetworkRawEvents::RdpRawEvent(RdpRawEvent::from_key_value(&key, value)?),
                ));
                rdp_data = rdp_iter.next();
            } else {
            };
        }
        if (result_vec.len() >= size)
            || (conn_data.is_none()
                && dns_data.is_none()
                && http_data.is_none()
                && rdp_data.is_none())
        {
            if conn_data.is_some()
                || dns_data.is_some()
                || http_data.is_some()
                || rdp_data.is_some()
            {
                has_next_value = true;
            }
            if is_forward {
                has_next_page = has_next_value;
            } else {
                result_vec.reverse();
                has_previous_page = has_next_value;
            }
            break;
        }
    }
    let mut connection: Connection<String, NetworkRawEvents> =
        Connection::new(has_previous_page, has_next_page);
    connection.edges.extend(result_vec.into_iter());

    Ok(connection)
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
    use chrono::{Duration, TimeZone, Utc};
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

    fn insert_conn_raw_event(store: &RawEventStore<Conn>, source: &str, timestamp: i64) {
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
        let store = schema.db.dns_store().unwrap();

        insert_dns_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_dns_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            dnsRawEvents(
                filter: {
                    source: "src 1"
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

    fn insert_dns_raw_event(store: &RawEventStore<DnsConn>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
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

        store.append(&key, &ser_dns_body).unwrap();
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
        let store = schema.db.http_store().unwrap();

        insert_http_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_http_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            httpRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                    source: "src 1"
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

    fn insert_http_raw_event(store: &RawEventStore<HttpConn>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
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

        store.append(&key, &ser_http_body).unwrap();
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
        let store = schema.db.rdp_store().unwrap();

        insert_rdp_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_rdp_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            rdpRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                    source: "src 1"
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

    fn insert_rdp_raw_event(store: &RawEventStore<RdpConn>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let rdp_body = RdpConn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            cookie: "rdp_test".to_string(),
        };
        let ser_rdp_body = bincode::serialize(&rdp_body).unwrap();

        store.append(&key, &ser_rdp_body).unwrap();
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

    #[tokio::test]
    async fn union() {
        let schema = TestSchema::new();
        let conn_store = schema.db.conn_store().unwrap();
        let dns_store = schema.db.dns_store().unwrap();
        let http_store = schema.db.http_store().unwrap();
        let rdp_store = schema.db.rdp_store().unwrap();

        insert_conn_raw_event(
            &conn_store,
            "src 1",
            Utc.ymd(2020, 1, 1).and_hms(0, 1, 1).timestamp_nanos(),
        );
        insert_dns_raw_event(
            &dns_store,
            "src 1",
            Utc.ymd(2021, 1, 1).and_hms(0, 1, 1).timestamp_nanos(),
        );
        insert_http_raw_event(
            &http_store,
            "src 1",
            Utc.ymd(2020, 6, 1).and_hms(0, 1, 1).timestamp_nanos(),
        );
        insert_rdp_raw_event(
            &rdp_store,
            "src 1",
            Utc.ymd(2020, 1, 5).and_hms(0, 1, 1).timestamp_nanos(),
        );

        let query = r#"
        {
            networkRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                    source: "src 1"
                }
                first: 4
              ) {
                edges {
                    node {
                        ... on ConnRawEvent {
                            timestamp
                        }
                        ... on DnsRawEvent {
                            timestamp
                        }
                        ... on HttpRawEvent {
                            timestamp
                        }
                        ... on RdpRawEvent {
                            timestamp
                        }
                        __typename
                    }
                }
            }
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(res.data.to_string(), "{networkRawEvents: {edges: [{node: {timestamp: \"2020-01-01T00:01:01+00:00\",__typename: \"ConnRawEvent\"}},{node: {timestamp: \"2020-01-05T00:01:01+00:00\",__typename: \"RdpRawEvent\"}},{node: {timestamp: \"2020-06-01T00:01:01+00:00\",__typename: \"HttpRawEvent\"}},{node: {timestamp: \"2021-01-01T00:01:01+00:00\",__typename: \"DnsRawEvent\"}}]}}");
    }
}
