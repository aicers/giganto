#![allow(clippy::unused_async)]
use super::{
    base64_engine, check_address, check_port, collect_exist_timestamp, get_filtered_iter,
    get_timestamp, load_connection, Engine, FromKeyValue,
};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    storage::{Database, FilteredIter},
};
use async_graphql::{
    connection::{query, Connection, Edge},
    Context, InputObject, Object, Result, SimpleObject, Union,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::network::{
    Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Ntlm, Rdp, Smtp, Ssh, Tls,
};
use serde::Serialize;
use std::{collections::BTreeSet, fmt::Debug, iter::Peekable, net::IpAddr};

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
pub struct SearchFilter {
    time: Option<TimeRange>,
    #[serde(skip)]
    pub source: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    log_level: Option<String>,
    log_contents: Option<String>,
    timestamps: Vec<DateTime<Utc>>,
    keyword: Option<String>,
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
        _text: Option<String>,
    ) -> Result<bool> {
        if check_address(&self.orig_addr, orig_addr)?
            && check_address(&self.resp_addr, resp_addr)?
            && check_port(&self.orig_port, orig_port)
            && check_port(&self.resp_port, resp_port)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

impl RawEventFilter for SearchFilter {
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
        text: Option<String>,
    ) -> Result<bool> {
        if let Some(keyword) = &self.keyword {
            if let Some(text) = text {
                if !text.to_lowercase().contains(&keyword.to_lowercase()) {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }
        if check_address(&self.orig_addr, orig_addr)?
            && check_address(&self.resp_addr, resp_addr)?
            && check_port(&self.orig_port, orig_port)
            && check_port(&self.resp_port, resp_port)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(SimpleObject, Debug)]
struct ConnRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    duration: i64,
    service: String,
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
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
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
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    method: String,
    host: String,
    uri: String,
    referrer: String,
    version: String,
    user_agent: String,
    request_len: usize,
    response_len: usize,
    status_code: u16,
    status_msg: String,
    username: String,
    password: String,
    cookie: String,
    content_encoding: String,
    content_type: String,
    cache_control: String,
    orig_filenames: Vec<String>,
    orig_mime_types: Vec<String>,
    resp_filenames: Vec<String>,
    resp_mime_types: Vec<String>,
}

#[derive(SimpleObject, Debug)]
struct RdpRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    cookie: String,
}

#[derive(SimpleObject, Debug)]
struct SmtpRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
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
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
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
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
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
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
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
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    rtt: i64,
    named_pipe: String,
    endpoint: String,
    operation: String,
}

#[derive(SimpleObject, Debug)]
struct FtpRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    user: String,
    password: String,
    data_passive: bool,
    data_orig_addr: String,
    data_resp_addr: String,
    data_resp_port: u16,
    file: String,
    file_id: String,
}

#[derive(SimpleObject, Debug)]
struct MqttRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    protocol: String,
    version: u8,
    client_id: String,
    connack_reason: u8,
    subscribe: Vec<String>,
    suback_reason: Vec<u8>,
}

#[derive(SimpleObject, Debug)]
struct LdapRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    message_id: u32,
    version: u8,
    opcode: Vec<String>,
    result: Vec<String>,
    diagnostic_message: Vec<String>,
    object: Vec<String>,
    argument: Vec<String>,
}

#[derive(SimpleObject, Debug)]
struct TlsRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    server_name: String,
    alpn_protocol: String,
    ja3: String,
    version: String,
    cipher: u16,
    ja3s: String,
    serial: String,
    subject_country: String,
    subject_org_name: String,
    subject_common_name: String,
    validity_not_before: i64,
    validity_not_after: i64,
    subject_alt_name: String,
    issuer_country: String,
    issuer_org_name: String,
    issuer_org_unit_name: String,
    issuer_common_name: String,
    last_alert: u8,
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
    FtpRawEvent(FtpRawEvent),
    MqttRawEvent(MqttRawEvent),
    LdapRawEvent(LdapRawEvent),
    TlsRawEvent(TlsRawEvent),
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
                    proto: val.proto,
                    last_time: val.last_time,
                    $(
                        $fields: val.$fields,
                    )*
                })
            }
        }
    };
}

impl FromKeyValue<Conn> for ConnRawEvent {
    fn from_key_value(key: &[u8], val: Conn) -> Result<Self> {
        Ok(ConnRawEvent {
            timestamp: get_timestamp(key)?,
            orig_addr: val.orig_addr.to_string(),
            resp_addr: val.resp_addr.to_string(),
            orig_port: val.orig_port,
            resp_port: val.resp_port,
            proto: val.proto,
            duration: val.duration,
            service: val.service,
            orig_bytes: val.orig_bytes,
            resp_bytes: val.resp_bytes,
            orig_pkts: val.orig_pkts,
            resp_pkts: val.resp_pkts,
        })
    }
}

impl FromKeyValue<Ftp> for FtpRawEvent {
    fn from_key_value(key: &[u8], val: Ftp) -> Result<Self> {
        Ok(FtpRawEvent {
            timestamp: get_timestamp(key)?,
            orig_addr: val.orig_addr.to_string(),
            resp_addr: val.resp_addr.to_string(),
            orig_port: val.orig_port,
            resp_port: val.resp_port,
            proto: val.proto,
            last_time: val.last_time,
            user: val.user,
            password: val.password,
            data_passive: val.data_passive,
            data_orig_addr: val.data_orig_addr.to_string(),
            data_resp_addr: val.data_resp_addr.to_string(),
            data_resp_port: val.data_resp_port,
            file: val.file,
            file_id: val.file_id,
        })
    }
}

from_key_value!(
    HttpRawEvent,
    Http,
    method,
    host,
    uri,
    referrer,
    version,
    user_agent,
    request_len,
    response_len,
    status_code,
    status_msg,
    username,
    password,
    cookie,
    content_encoding,
    content_type,
    cache_control,
    orig_filenames,
    orig_mime_types,
    resp_filenames,
    resp_mime_types
);
from_key_value!(RdpRawEvent, Rdp, cookie);

from_key_value!(
    DnsRawEvent,
    Dns,
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

from_key_value!(
    MqttRawEvent,
    Mqtt,
    protocol,
    version,
    client_id,
    connack_reason,
    subscribe,
    suback_reason
);

from_key_value!(
    LdapRawEvent,
    Ldap,
    message_id,
    version,
    opcode,
    result,
    diagnostic_message,
    object,
    argument
);

from_key_value!(
    TlsRawEvent,
    Tls,
    server_name,
    alpn_protocol,
    ja3,
    version,
    cipher,
    ja3s,
    serial,
    subject_country,
    subject_org_name,
    subject_common_name,
    validity_not_before,
    validity_not_after,
    subject_alt_name,
    issuer_country,
    issuer_org_name,
    issuer_org_unit_name,
    issuer_common_name,
    last_alert
);

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

    async fn ftp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FtpRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.ftp_store()?;
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

    async fn mqtt_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, MqttRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.mqtt_store()?;
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

    async fn ldap_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, LdapRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.ldap_store()?;
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

    async fn tls_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, TlsRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.tls_store()?;
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

    #[allow(clippy::too_many_lines)]
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

                let (ntlm_iter, cursor, _) = get_filtered_iter(
                    &db.ntlm_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut ntlm_iter = ntlm_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = ntlm_iter.peek() {
                        if key.as_ref() == cursor {
                            ntlm_iter.next();
                        }
                    }
                }

                let (kerberos_iter, cursor, _) = get_filtered_iter(
                    &db.kerberos_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut kerberos_iter = kerberos_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = kerberos_iter.peek() {
                        if key.as_ref() == cursor {
                            kerberos_iter.next();
                        }
                    }
                }

                let (ssh_iter, cursor, _) = get_filtered_iter(
                    &db.ssh_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut ssh_iter = ssh_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = ssh_iter.peek() {
                        if key.as_ref() == cursor {
                            ssh_iter.next();
                        }
                    }
                }

                let (dce_rpc_iter, cursor, _) = get_filtered_iter(
                    &db.dce_rpc_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut dce_rpc_iter = dce_rpc_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = dce_rpc_iter.peek() {
                        if key.as_ref() == cursor {
                            dce_rpc_iter.next();
                        }
                    }
                }

                let (ftp_iter, cursor, _) = get_filtered_iter(
                    &db.ftp_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut ftp_iter = ftp_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = ftp_iter.peek() {
                        if key.as_ref() == cursor {
                            ftp_iter.next();
                        }
                    }
                }

                let (mqtt_iter, cursor, _) = get_filtered_iter(
                    &db.mqtt_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut mqtt_iter = mqtt_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = mqtt_iter.peek() {
                        if key.as_ref() == cursor {
                            mqtt_iter.next();
                        }
                    }
                }

                let (ldap_iter, cursor, _) = get_filtered_iter(
                    &db.ldap_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut ldap_iter = ldap_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = ldap_iter.peek() {
                        if key.as_ref() == cursor {
                            ldap_iter.next();
                        }
                    }
                }

                let (tls_iter, cursor, _) = get_filtered_iter(
                    &db.tls_store()?,
                    &key_prefix,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut tls_iter = tls_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = tls_iter.peek() {
                        if key.as_ref() == cursor {
                            tls_iter.next();
                        }
                    }
                }

                let mut is_forward: bool = true;
                if before.is_some() || last.is_some() {
                    is_forward = false;
                }

                network_connection(
                    conn_iter,
                    dns_iter,
                    http_iter,
                    rdp_iter,
                    ntlm_iter,
                    kerberos_iter,
                    ssh_iter,
                    dce_rpc_iter,
                    ftp_iter,
                    mqtt_iter,
                    ldap_iter,
                    tls_iter,
                    size,
                    is_forward,
                )
            },
        )
        .await
    }

    async fn search_conn_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.conn_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Conn>(&exist_data, &filter))
    }

    async fn search_dns_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.dns_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Dns>(&exist_data, &filter))
    }

    async fn search_http_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.http_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Http>(&exist_data, &filter))
    }

    async fn search_rdp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.rdp_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Rdp>(&exist_data, &filter))
    }

    async fn search_smtp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.smtp_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Smtp>(&exist_data, &filter))
    }

    async fn search_ntlm_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.ntlm_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Ntlm>(&exist_data, &filter))
    }

    async fn search_kerberos_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.kerberos_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Kerberos>(&exist_data, &filter))
    }

    async fn search_ssh_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.ssh_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Ssh>(&exist_data, &filter))
    }

    async fn search_dce_rpc_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.dce_rpc_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<DceRpc>(&exist_data, &filter))
    }

    async fn search_ftp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.ftp_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Ftp>(&exist_data, &filter))
    }

    async fn search_mqtt_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.mqtt_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Mqtt>(&exist_data, &filter))
    }

    async fn search_ldap_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.ldap_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Ldap>(&exist_data, &filter))
    }

    async fn search_tls_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.tls_store()?;
        let exist_data = store
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<Tls>(&exist_data, &filter))
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn network_connection(
    mut conn_iter: Peekable<FilteredIter<Conn>>,
    mut dns_iter: Peekable<FilteredIter<Dns>>,
    mut http_iter: Peekable<FilteredIter<Http>>,
    mut rdp_iter: Peekable<FilteredIter<Rdp>>,
    mut ntlm_iter: Peekable<FilteredIter<Ntlm>>,
    mut kerberos_iter: Peekable<FilteredIter<Kerberos>>,
    mut ssh_iter: Peekable<FilteredIter<Ssh>>,
    mut dce_rpc_iter: Peekable<FilteredIter<DceRpc>>,
    mut ftp_iter: Peekable<FilteredIter<Ftp>>,
    mut mqtt_iter: Peekable<FilteredIter<Mqtt>>,
    mut ldap_iter: Peekable<FilteredIter<Ldap>>,
    mut tls_iter: Peekable<FilteredIter<Tls>>,
    size: usize,
    is_forward: bool,
) -> Result<Connection<String, NetworkRawEvents>> {
    let timestamp = min_max_time(is_forward);
    let mut result_vec: Vec<Edge<String, NetworkRawEvents, _>> = Vec::new();
    let mut has_previous_page: bool = false;
    let mut has_next_page: bool = false;
    let mut has_next_value: bool = false;

    let mut conn_data = conn_iter.next();
    let mut dns_data = dns_iter.next();
    let mut http_data = http_iter.next();
    let mut rdp_data = rdp_iter.next();
    let mut ntlm_data = ntlm_iter.next();
    let mut kerberos_data = kerberos_iter.next();
    let mut ssh_data = ssh_iter.next();
    let mut dce_rpc_data = dce_rpc_iter.next();
    let mut ftp_data = ftp_iter.next();
    let mut mqtt_data = mqtt_iter.next();
    let mut ldap_data = ldap_iter.next();
    let mut tls_data = tls_iter.next();

    loop {
        let conn_ts = if let Some((ref key, _)) = conn_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let dns_ts = if let Some((ref key, _)) = dns_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let http_ts = if let Some((ref key, _)) = http_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let rdp_ts = if let Some((ref key, _)) = rdp_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let ntlm_ts = if let Some((ref key, _)) = ntlm_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let kerberos_ts = if let Some((ref key, _)) = kerberos_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let ssh_ts = if let Some((ref key, _)) = ssh_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let dce_rpc_ts = if let Some((ref key, _)) = dce_rpc_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let ftp_ts = if let Some((ref key, _)) = ftp_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let mqtt_ts = if let Some((ref key, _)) = mqtt_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let ldap_ts = if let Some((ref key, _)) = ldap_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let tls_ts = if let Some((ref key, _)) = tls_data {
            get_timestamp(key)?
        } else {
            min_max_time(is_forward)
        };

        let selected =
            if is_forward {
                timestamp.min(dns_ts.min(conn_ts.min(http_ts.min(rdp_ts.min(ntlm_ts.min(
                    kerberos_ts.min(
                        ssh_ts.min(dce_rpc_ts.min(ftp_ts.min(mqtt_ts.min(ldap_ts.min(tls_ts))))),
                    ),
                ))))))
            } else {
                timestamp.max(dns_ts.max(conn_ts.max(http_ts.max(rdp_ts.max(ntlm_ts.max(
                    kerberos_ts.max(
                        ssh_ts.max(dce_rpc_ts.max(ftp_ts.max(mqtt_ts.max(ldap_ts.max(tls_ts))))),
                    ),
                ))))))
            };

        match selected {
            _ if selected == conn_ts => {
                if let Some((key, value)) = conn_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::ConnRawEvent(ConnRawEvent::from_key_value(&key, value)?),
                    ));
                    conn_data = conn_iter.next();
                } else {
                };
            }
            _ if selected == dns_ts => {
                if let Some((key, value)) = dns_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::DnsRawEvent(DnsRawEvent::from_key_value(&key, value)?),
                    ));
                    dns_data = dns_iter.next();
                } else {
                };
            }
            _ if selected == http_ts => {
                if let Some((key, value)) = http_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::HttpRawEvent(HttpRawEvent::from_key_value(&key, value)?),
                    ));
                    http_data = http_iter.next();
                } else {
                };
            }
            _ if selected == rdp_ts => {
                if let Some((key, value)) = rdp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::RdpRawEvent(RdpRawEvent::from_key_value(&key, value)?),
                    ));
                    rdp_data = rdp_iter.next();
                } else {
                };
            }
            _ if selected == ntlm_ts => {
                if let Some((key, value)) = ntlm_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::NtlmRawEvent(NtlmRawEvent::from_key_value(&key, value)?),
                    ));
                    ntlm_data = ntlm_iter.next();
                } else {
                };
            }
            _ if selected == kerberos_ts => {
                if let Some((key, value)) = kerberos_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::KerberosRawEvent(KerberosRawEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    kerberos_data = kerberos_iter.next();
                } else {
                };
            }
            _ if selected == ssh_ts => {
                if let Some((key, value)) = ssh_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::SshRawEvent(SshRawEvent::from_key_value(&key, value)?),
                    ));
                    ssh_data = ssh_iter.next();
                } else {
                };
            }
            _ if selected == dce_rpc_ts => {
                if let Some((key, value)) = dce_rpc_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::DceRpcRawEvent(DceRpcRawEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    dce_rpc_data = dce_rpc_iter.next();
                } else {
                };
            }
            _ if selected == ftp_ts => {
                if let Some((key, value)) = ftp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::FtpRawEvent(FtpRawEvent::from_key_value(&key, value)?),
                    ));
                    ftp_data = ftp_iter.next();
                } else {
                };
            }
            _ if selected == mqtt_ts => {
                if let Some((key, value)) = mqtt_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::MqttRawEvent(MqttRawEvent::from_key_value(&key, value)?),
                    ));
                    mqtt_data = mqtt_iter.next();
                } else {
                };
            }
            _ if selected == ldap_ts => {
                if let Some((key, value)) = ldap_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::LdapRawEvent(LdapRawEvent::from_key_value(&key, value)?),
                    ));
                    ldap_data = ldap_iter.next();
                } else {
                };
            }
            _ if selected == tls_ts => {
                if let Some((key, value)) = tls_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::TlsRawEvent(TlsRawEvent::from_key_value(&key, value)?),
                    ));
                    tls_data = tls_iter.next();
                } else {
                };
            }
            _ => {}
        }
        if (result_vec.len() >= size)
            || (conn_data.is_none()
                && dns_data.is_none()
                && http_data.is_none()
                && rdp_data.is_none()
                && ntlm_data.is_none()
                && kerberos_data.is_none()
                && ssh_data.is_none()
                && dce_rpc_data.is_none()
                && ftp_data.is_none()
                && mqtt_data.is_none()
                && ldap_data.is_none()
                && tls_data.is_none())
        {
            if conn_data.is_some()
                || dns_data.is_some()
                || http_data.is_some()
                || rdp_data.is_some()
                || ntlm_data.is_some()
                || kerberos_data.is_some()
                || ssh_data.is_some()
                || dce_rpc_data.is_some()
                || ftp_data.is_some()
                || mqtt_data.is_some()
                || ldap_data.is_some()
                || tls_data.is_some()
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

fn min_max_time(is_forward: bool) -> DateTime<Utc> {
    if is_forward {
        DateTime::<Utc>::MAX_UTC
    } else {
        DateTime::<Utc>::MIN_UTC
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    use crate::storage::RawEventStore;
    use chrono::{Duration, TimeZone, Utc};
    use giganto_client::ingest::network::{
        Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Ntlm, Rdp, Smtp, Ssh, Tls,
    };
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
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            duration: tmp_dur.num_nanoseconds().unwrap(),
            service: "-".to_string(),
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
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
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
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            method: "POST".to_string(),
            host: "einsis".to_string(),
            uri: "/einsis.gif".to_string(),
            referrer: "einsis.com".to_string(),
            version: String::new(),
            user_agent: "giganto".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: String::new(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: String::new(),
            cache_control: String::new(),
            orig_filenames: Vec::new(),
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: Vec::new(),
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
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
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
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
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
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
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
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
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
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
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
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            rtt: 3,
            named_pipe: "named_pipe".to_string(),
            endpoint: "endpoint".to_string(),
            operation: "operation".to_string(),
        };
        let ser_dce_rpc_body = bincode::serialize(&dce_rpc_body).unwrap();

        store.append(&key, &ser_dce_rpc_body).unwrap();
    }

    #[tokio::test]
    async fn ftp_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.ftp_store().unwrap();

        insert_ftp_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_ftp_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            ftpRawEvents(
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
            "{ftpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
        );
    }

    fn insert_ftp_raw_event(store: &RawEventStore<Ftp>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let ftp_body = Ftp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            user: "einsis".to_string(),
            password: "aice".to_string(),
            command: "command".to_string(),
            reply_code: "500".to_string(),
            reply_msg: "reply_message".to_string(),
            data_passive: false,
            data_orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            data_resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            data_resp_port: 80,
            file: "fpt_file".to_string(),
            file_size: 100,
            file_id: "1".to_string(),
        };
        let ser_ftp_body = bincode::serialize(&ftp_body).unwrap();

        store.append(&key, &ser_ftp_body).unwrap();
    }

    #[tokio::test]
    async fn mqtt_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.mqtt_store().unwrap();

        insert_mqtt_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_mqtt_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            mqttRawEvents(
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
            "{mqttRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
        );
    }

    fn insert_mqtt_raw_event(store: &RawEventStore<Mqtt>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let mqtt_body = Mqtt {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            protocol: "protocol".to_string(),
            version: 1,
            client_id: "1".to_string(),
            connack_reason: 1,
            subscribe: vec!["subscribe".to_string()],
            suback_reason: vec![1],
        };
        let ser_mqtt_body = bincode::serialize(&mqtt_body).unwrap();

        store.append(&key, &ser_mqtt_body).unwrap();
    }

    #[tokio::test]
    async fn ldap_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.ldap_store().unwrap();

        insert_ldap_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_ldap_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            ldapRawEvents(
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
            "{ldapRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
        );
    }

    fn insert_ldap_raw_event(store: &RawEventStore<Ldap>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let ldap_body = Ldap {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            message_id: 1,
            version: 1,
            opcode: vec!["opcode".to_string()],
            result: vec!["result".to_string()],
            diagnostic_message: Vec::new(),
            object: Vec::new(),
            argument: Vec::new(),
        };
        let ser_ldap_body = bincode::serialize(&ldap_body).unwrap();

        store.append(&key, &ser_ldap_body).unwrap();
    }

    #[tokio::test]
    async fn tls_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.tls_store().unwrap();

        insert_tls_raw_event(&store, "src 1", Utc::now().timestamp_nanos());
        insert_tls_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            tlsRawEvents(
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
            "{tlsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
        );
    }

    fn insert_tls_raw_event(store: &RawEventStore<Tls>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let tls_body = Tls {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            server_name: "server_name".to_string(),
            alpn_protocol: "alpn_protocol".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            cipher: 10,
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "sub_contry".to_string(),
            subject_org_name: "sub_org".to_string(),
            subject_common_name: "sub_comm".to_string(),
            validity_not_before: 11,
            validity_not_after: 12,
            subject_alt_name: "sub_alt".to_string(),
            issuer_country: "issuer_contry".to_string(),
            issuer_org_name: "issuer_org".to_string(),
            issuer_org_unit_name: "issuer_org_unit".to_string(),
            issuer_common_name: "issuer_comm".to_string(),
            last_alert: 13,
        };
        let ser_tls_body = bincode::serialize(&tls_body).unwrap();

        store.append(&key, &ser_tls_body).unwrap();
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
        let ntlm_store = schema.db.ntlm_store().unwrap();
        let kerberos_store = schema.db.kerberos_store().unwrap();
        let ssh_store = schema.db.ssh_store().unwrap();
        let dce_rpc_store = schema.db.dce_rpc_store().unwrap();
        let ftp_store = schema.db.ftp_store().unwrap();
        let mqtt_store = schema.db.mqtt_store().unwrap();
        let ldap_store = schema.db.ldap_store().unwrap();
        let tls_store = schema.db.tls_store().unwrap();

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
        insert_ntlm_raw_event(
            &ntlm_store,
            "src 1",
            Utc.with_ymd_and_hms(2022, 1, 5, 0, 1, 1)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_kerberos_raw_event(
            &kerberos_store,
            "src 1",
            Utc.with_ymd_and_hms(2023, 1, 5, 0, 1, 1)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_ssh_raw_event(
            &ssh_store,
            "src 1",
            Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_dce_rpc_raw_event(
            &dce_rpc_store,
            "src 1",
            Utc.with_ymd_and_hms(2020, 1, 5, 6, 5, 0)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_ftp_raw_event(
            &ftp_store,
            "src 1",
            Utc.with_ymd_and_hms(2023, 1, 5, 12, 12, 0)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_mqtt_raw_event(
            &mqtt_store,
            "src 1",
            Utc.with_ymd_and_hms(2023, 1, 5, 12, 12, 0)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_ldap_raw_event(
            &ldap_store,
            "src 1",
            Utc.with_ymd_and_hms(2023, 1, 6, 12, 12, 0)
                .unwrap()
                .timestamp_nanos(),
        );
        insert_tls_raw_event(
            &tls_store,
            "src 1",
            Utc.with_ymd_and_hms(2023, 1, 6, 11, 11, 0)
                .unwrap()
                .timestamp_nanos(),
        );

        // order: ssh, conn, rdp, dce_rpc, http, dns, ntlm, kerberos, ftp, mqtt,tls, ldap
        let query = r#"
        {
            networkRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                    source: "src 1"
                }
                first: 20
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
                        ... on NtlmRawEvent {
                            timestamp
                        }
                        ... on KerberosRawEvent {
                            timestamp
                        }
                        ... on SshRawEvent {
                            timestamp
                        }
                        ... on DceRpcRawEvent {
                            timestamp
                        }
                        ... on FtpRawEvent {
                            timestamp
                        }
                        ... on MqttRawEvent {
                            timestamp
                        }
                        ... on LdapRawEvent {
                            timestamp
                        }
                        ... on TlsRawEvent {
                            timestamp
                        }
                        __typename
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{networkRawEvents: {edges: [{node: {timestamp: \"2020-01-01T00:00:01+00:00\",__typename: \"SshRawEvent\"}},{node: {timestamp: \"2020-01-01T00:01:01+00:00\",__typename: \"ConnRawEvent\"}},{node: {timestamp: \"2020-01-05T00:01:01+00:00\",__typename: \"RdpRawEvent\"}},{node: {timestamp: \"2020-01-05T06:05:00+00:00\",__typename: \"DceRpcRawEvent\"}},{node: {timestamp: \"2020-06-01T00:01:01+00:00\",__typename: \"HttpRawEvent\"}},{node: {timestamp: \"2021-01-01T00:01:01+00:00\",__typename: \"DnsRawEvent\"}},{node: {timestamp: \"2022-01-05T00:01:01+00:00\",__typename: \"NtlmRawEvent\"}},{node: {timestamp: \"2023-01-05T00:01:01+00:00\",__typename: \"KerberosRawEvent\"}},{node: {timestamp: \"2023-01-05T12:12:00+00:00\",__typename: \"FtpRawEvent\"}},{node: {timestamp: \"2023-01-05T12:12:00+00:00\",__typename: \"MqttRawEvent\"}},{node: {timestamp: \"2023-01-06T11:11:00+00:00\",__typename: \"TlsRawEvent\"}},{node: {timestamp: \"2023-01-06T12:12:00+00:00\",__typename: \"LdapRawEvent\"}}]}}");
    }

    #[tokio::test]
    async fn search_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            searchHttpRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 46377, end: 46380 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{searchHttpRawEvents: []}");
    }

    #[tokio::test]
    async fn search_http_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.http_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_http_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_http_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_http_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_http_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchHttpRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchHttpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_conn_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.conn_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_conn_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_conn_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_conn_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_conn_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchConnRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchConnRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_dns_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.dns_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_dns_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_dns_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_dns_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_dns_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchDnsRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                    origPort: { start: 70, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchDnsRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_rdp_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.rdp_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_rdp_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_rdp_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_rdp_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_rdp_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchRdpRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchRdpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_smtp_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.smtp_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_smtp_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_smtp_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_smtp_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_smtp_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchSmtpRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchSmtpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_ntlm_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.ntlm_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_ntlm_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_ntlm_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_ntlm_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_ntlm_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchNtlmRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchNtlmRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_kerberos_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.kerberos_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_kerberos_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_kerberos_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_kerberos_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_kerberos_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchKerberosRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchKerberosRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_ssh_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.ssh_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_ssh_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_ssh_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_ssh_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_ssh_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchSshRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchSshRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_dce_rpc_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.dce_rpc_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_dce_rpc_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_dce_rpc_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_dce_rpc_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_dce_rpc_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchDceRpcRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchDceRpcRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_ftp_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.ftp_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_ftp_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_ftp_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_ftp_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_ftp_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchFtpRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchFtpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_mqtt_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.mqtt_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_mqtt_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_mqtt_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_mqtt_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_mqtt_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchMqttRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchMqttRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_ldap_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.ldap_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_ldap_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_ldap_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_ldap_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_ldap_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchLdapRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchLdapRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }

    #[tokio::test]
    async fn search_tls_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.tls_store().unwrap();

        let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
        let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
        let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
        let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

        insert_tls_raw_event(&store, "src 1", timestamp1.timestamp_nanos());
        insert_tls_raw_event(&store, "src 1", timestamp2.timestamp_nanos());
        insert_tls_raw_event(&store, "src 1", timestamp3.timestamp_nanos());
        insert_tls_raw_event(&store, "src 1", timestamp4.timestamp_nanos());

        let query = r#"
        {
            searchTlsRawEvents(
                filter: {
                    time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                    source: "src 1"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 75, end: 85 }
                    timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
                }
            )
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{searchTlsRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
        );
    }
}
