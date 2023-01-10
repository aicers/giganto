use super::{get_filtered_iter, get_timestamp, load_connection, FromKeyValue};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    ingest::{Conn, DceRpc, Dns, Http, Kerberos, Ntlm, Rdp, Smtp, Ssh},
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
    log_level: Option<String>,
    log_contents: Option<String>,
}

#[derive(InputObject, Serialize)]
pub struct IpRange {
    pub start: Option<String>,
    pub end: Option<String>,
}

#[derive(InputObject, Serialize)]
pub struct PortRange {
    pub start: Option<u16>,
    pub end: Option<u16>,
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
        _log_level: Option<String>,
        _log_contents: Option<String>,
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
    service: String,
    duration: i64,
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(SimpleObject, Debug)]
struct DnsRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    query: String,
    answer: Vec<String>,
    trans_id: u16,
    rtt: i64,
    qclass: u16,
    qtype: u16,
    rcode: u16,
    aa_flag: bool,
    tc_flag: bool,
    rd_flag: bool,
    ra_flag: bool,
    ttl: Vec<i32>,
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

#[derive(SimpleObject, Debug)]
struct SmtpRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    mailfrom: String,
    date: String,
    from: String,
    to: String,
    subject: String,
    agent: String,
}

#[derive(SimpleObject, Debug)]
struct NtlmRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    username: String,
    hostname: String,
    domainname: String,
    server_nb_computer_name: String,
    server_dns_computer_name: String,
    server_tree_name: String,
    success: String,
}

#[derive(SimpleObject, Debug)]
struct KerberosRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    request_type: String,
    client: String,
    service: String,
    success: String,
    error_msg: String,
    from: i64,
    till: i64,
    cipher: String,
    forwardable: String,
    renewable: String,
    client_cert_subject: String,
    server_cert_subject: String,
}

#[derive(SimpleObject, Debug)]
struct SshRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    version: i64,
    auth_success: String,
    auth_attempts: i64,
    direction: String,
    client: String,
    server: String,
    cipher_alg: String,
    mac_alg: String,
    compression_alg: String,
    kex_alg: String,
    host_key_alg: String,
    host_key: String,
}

#[derive(SimpleObject, Debug)]
struct DceRpcRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    resp_addr: String,
    orig_port: u16,
    resp_port: u16,
    rtt: i64,
    named_pipe: String,
    endpoint: String,
    operation: String,
}

#[allow(clippy::enum_variant_names)]
#[derive(Union)]
enum NetworkRawEvents {
    ConnRawEvent(ConnRawEvent),
    DnsRawEvent(DnsRawEvent),
    HttpRawEvent(HttpRawEvent),
    RdpRawEvent(RdpRawEvent),
    NtlmRawEvent(NtlmRawEvent),
    KerberosRawEvent(KerberosRawEvent),
    SshRawEvent(SshRawEvent),
    DceRpcRawEvent(DceRpcRawEvent),
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
    service,
    duration,
    orig_bytes,
    resp_bytes,
    orig_pkts,
    resp_pkts
);
from_key_value!(
    HttpRawEvent,
    Http,
    method,
    host,
    uri,
    referrer,
    user_agent,
    status_code
);
from_key_value!(RdpRawEvent, Rdp, cookie);

from_key_value!(
    DnsRawEvent,
    Dns,
    proto,
    query,
    answer,
    trans_id,
    rtt,
    qclass,
    qtype,
    rcode,
    aa_flag,
    tc_flag,
    rd_flag,
    ra_flag,
    ttl
);

from_key_value!(SmtpRawEvent, Smtp, mailfrom, date, from, to, subject, agent);

from_key_value!(
    NtlmRawEvent,
    Ntlm,
    username,
    hostname,
    domainname,
    server_nb_computer_name,
    server_dns_computer_name,
    server_tree_name,
    success
);

from_key_value!(
    KerberosRawEvent,
    Kerberos,
    request_type,
    client,
    service,
    success,
    error_msg,
    from,
    till,
    cipher,
    forwardable,
    renewable,
    client_cert_subject,
    server_cert_subject
);

from_key_value!(
    SshRawEvent,
    Ssh,
    version,
    auth_success,
    auth_attempts,
    direction,
    client,
    server,
    cipher_alg,
    mac_alg,
    compression_alg,
    kex_alg,
    host_key_alg,
    host_key
);

from_key_value!(DceRpcRawEvent, DceRpc, rtt, named_pipe, endpoint, operation);

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

    async fn smtp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, SmtpRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.smtp_store()?;
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

    async fn ntlm_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, NtlmRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.ntlm_store()?;
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

    async fn kerberos_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, KerberosRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.kerberos_store()?;
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

    async fn ssh_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, SshRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.ssh_store()?;
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

    async fn dce_rpc_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DceRpcRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.dce_rpc_store()?;
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
    mut dns_iter: Peekable<FilteredIter<Dns>>,
    mut http_iter: Peekable<FilteredIter<Http>>,
    mut rdp_iter: Peekable<FilteredIter<Rdp>>,
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

pub(crate) fn key_prefix(source: &str) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(source.len() + 1);
    prefix.extend_from_slice(source.as_bytes());
    prefix.push(0);
    prefix
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    use crate::ingest::{Conn, DceRpc, Dns, Http, Kerberos, Ntlm, Rdp, Smtp, Ssh};
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
        let res = schema.execute(query).await;
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
        let res = schema.execute(query).await;
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
            service: "-".to_string(),
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
        let res = schema.execute(query).await;
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
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{dnsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"31.3.245.133\",origPort: 46378}}]}}"
        );
    }

    fn insert_dns_raw_event(store: &RawEventStore<Dns>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let dns_body = Dns {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            proto: 17,
            query: "Hello Server Hello Server Hello Server".to_string(),
            answer: vec!["1.1.1.1".to_string()],
            trans_id: 1,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1; 5],
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
        let res = schema.execute(query).await;
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
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{httpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
        );
    }

    fn insert_http_raw_event(store: &RawEventStore<Http>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let http_body = Http {
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
        let res = schema.execute(query).await;
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
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{rdpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
        );
    }

    fn insert_rdp_raw_event(store: &RawEventStore<Rdp>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let rdp_body = Rdp {
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
    async fn smtp_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.smtp_store().unwrap();

        insert_smtp_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_smtp_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            smtpRawEvents(
                filter: {
                    source: "src 1"
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{smtpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
        );
    }

    fn insert_smtp_raw_event(store: &RawEventStore<Smtp>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let smtp_body = Smtp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            mailfrom: "mailfrom".to_string(),
            date: "date".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            subject: "subject".to_string(),
            agent: "agent".to_string(),
        };
        let ser_smtp_body = bincode::serialize(&smtp_body).unwrap();

        store.append(&key, &ser_smtp_body).unwrap();
    }

    #[tokio::test]
    async fn ntlm_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.ntlm_store().unwrap();

        insert_ntlm_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_ntlm_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            ntlmRawEvents(
                filter: {
                    source: "src 1"
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{ntlmRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
        );
    }

    fn insert_ntlm_raw_event(store: &RawEventStore<Ntlm>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let ntlm_body = Ntlm {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            username: "bly".to_string(),
            hostname: "host".to_string(),
            domainname: "domain".to_string(),
            server_nb_computer_name: "NB".to_string(),
            server_dns_computer_name: "dns".to_string(),
            server_tree_name: "tree".to_string(),
            success: "tf".to_string(),
        };
        let ser_ntlm_body = bincode::serialize(&ntlm_body).unwrap();

        store.append(&key, &ser_ntlm_body).unwrap();
    }

    #[tokio::test]
    async fn kerberos_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.kerberos_store().unwrap();

        insert_kerberos_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_kerberos_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            kerberosRawEvents(
                filter: {
                    source: "src 1"
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{kerberosRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
        );
    }

    fn insert_kerberos_raw_event(store: &RawEventStore<Kerberos>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let kerberos_body = Kerberos {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            request_type: "req_type".to_string(),
            client: "client".to_string(),
            service: "service".to_string(),
            success: "tf".to_string(),
            error_msg: "err_msg".to_string(),
            from: 5454,
            till: 2345,
            cipher: "cipher".to_string(),
            forwardable: "forwardable".to_string(),
            renewable: "renewable".to_string(),
            client_cert_subject: "client_cert".to_string(),
            server_cert_subject: "server_cert".to_string(),
        };
        let ser_kerberos_body = bincode::serialize(&kerberos_body).unwrap();

        store.append(&key, &ser_kerberos_body).unwrap();
    }

    #[tokio::test]
    async fn ssh_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.ssh_store().unwrap();

        insert_ssh_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_ssh_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            sshRawEvents(
                filter: {
                    source: "src 1"
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{sshRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
        );
    }

    fn insert_ssh_raw_event(store: &RawEventStore<Ssh>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let ssh_body = Ssh {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            version: 01,
            auth_success: "auth_success".to_string(),
            auth_attempts: 3,
            direction: "direction".to_string(),
            client: "client".to_string(),
            server: "server".to_string(),
            cipher_alg: "cipher_alg".to_string(),
            mac_alg: "mac_alg".to_string(),
            compression_alg: "compression_alg".to_string(),
            kex_alg: "kex_alg".to_string(),
            host_key_alg: "host_key_alg".to_string(),
            host_key: "host_key".to_string(),
        };
        let ser_ssh_body = bincode::serialize(&ssh_body).unwrap();

        store.append(&key, &ser_ssh_body).unwrap();
    }

    #[tokio::test]
    async fn dce_rpc_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.dce_rpc_store().unwrap();

        insert_dce_rpc_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_dce_rpc_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            dceRpcRawEvents(
                filter: {
                    source: "src 1"
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{dceRpcRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
        );
    }

    fn insert_dce_rpc_raw_event(store: &RawEventStore<DceRpc>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let dce_rpc_body = DceRpc {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            rtt: 3,
            named_pipe: "named_pipe".to_string(),
            endpoint: "endpoint".to_string(),
            operation: "operation".to_string(),
        };
        let ser_dce_rpc_body = bincode::serialize(&dce_rpc_body).unwrap();

        store.append(&key, &ser_dce_rpc_body).unwrap();
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
        let res = schema.execute(query).await;
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
            Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_dns_raw_event(
            &dns_store,
            "src 1",
            Utc.with_ymd_and_hms(2021, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_http_raw_event(
            &http_store,
            "src 1",
            Utc.with_ymd_and_hms(2020, 6, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_rdp_raw_event(
            &rdp_store,
            "src 1",
            Utc.with_ymd_and_hms(2020, 1, 5, 0, 1, 1)
                .unwrap()
                .timestamp_nanos(),
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
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{networkRawEvents: {edges: [{node: {timestamp: \"2020-01-01T00:01:01+00:00\",__typename: \"ConnRawEvent\"}},{node: {timestamp: \"2020-01-05T00:01:01+00:00\",__typename: \"RdpRawEvent\"}},{node: {timestamp: \"2020-06-01T00:01:01+00:00\",__typename: \"HttpRawEvent\"}},{node: {timestamp: \"2021-01-01T00:01:01+00:00\",__typename: \"DnsRawEvent\"}}]}}");
    }
}
