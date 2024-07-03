#![allow(clippy::too_many_arguments)]
#[cfg(test)]
mod tests;

use std::{collections::BTreeSet, fmt::Debug, iter::Peekable, net::IpAddr};

use async_graphql::{
    connection::{query, Connection, Edge},
    Context, Object, Result, SimpleObject, Union,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::network::{
    Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
};
use giganto_proc_macro::ConvertGraphQLEdgesNode;
use graphql_client::GraphQLQuery;

use super::{
    base64_engine, check_address, check_agent_id, check_port, collect_exist_timestamp,
    events_vec_in_cluster, get_peekable_iter, get_source_from_key, get_timestamp_from_key,
    handle_paged_events, handle_paged_events_for_all_source,
    impl_from_giganto_network_filter_for_graphql_client,
    impl_from_giganto_network_option_filter_for_graphql_client,
    impl_from_giganto_range_structs_for_graphql_client,
    impl_from_giganto_search_filter_for_graphql_client, min_max_time, paged_events_in_cluster,
    Engine, FromKeyValue, NetworkFilter, NetworkOptFilter, NodeCompare, RawEventFilter,
    SearchFilter,
};
use crate::storage::{Database, FilteredIter, KeyExtractor};
use crate::{
    graphql::client::derives::{
        conn_raw_events, dce_rpc_raw_events, dns_raw_events, ftp_raw_events, http_raw_events,
        kerberos_raw_events, ldap_raw_events, mqtt_raw_events, network_raw_events, nfs_raw_events,
        ntlm_raw_events, rdp_raw_events, search_conn_raw_events, search_dce_rpc_raw_events,
        search_dns_raw_events, search_ftp_raw_events, search_http_raw_events,
        search_kerberos_raw_events, search_ldap_raw_events, search_mqtt_raw_events,
        search_nfs_raw_events, search_ntlm_raw_events, search_rdp_raw_events,
        search_smb_raw_events, search_smtp_raw_events, search_ssh_raw_events,
        search_tls_raw_events, smb_raw_events, smtp_raw_events, ssh_raw_events, tls_raw_events,
        ConnRawEvents, DceRpcRawEvents, DnsRawEvents, FtpRawEvents, HttpRawEvents,
        KerberosRawEvents, LdapRawEvents, MqttRawEvents,
        NetworkRawEvents as GraphQlNetworkRawEvents, NfsRawEvents, NtlmRawEvents, RdpRawEvents,
        SearchConnRawEvents, SearchDceRpcRawEvents, SearchDnsRawEvents, SearchFtpRawEvents,
        SearchHttpRawEvents, SearchKerberosRawEvents, SearchLdapRawEvents, SearchMqttRawEvents,
        SearchNfsRawEvents, SearchNtlmRawEvents, SearchRdpRawEvents, SearchSmbRawEvents,
        SearchSmtpRawEvents, SearchSshRawEvents, SearchTlsRawEvents, SmbRawEvents, SmtpRawEvents,
        SshRawEvents, TlsRawEvents,
    },
    IngestSources,
};

#[derive(Default)]
pub(super) struct NetworkQuery;

impl KeyExtractor for NetworkOptFilter {
    // source always exists in the condition that calls `get_start_key`.
    fn get_start_key(&self) -> &str {
        self.source.as_ref().unwrap()
    }

    // network event don't use mid key
    fn get_mid_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_range_end_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }
}

impl RawEventFilter for NetworkOptFilter {
    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
        _log_level: Option<String>,
        _log_contents: Option<String>,
        _text: Option<String>,
        _source: Option<String>,
        _agent_id: Option<String>,
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

impl KeyExtractor for NetworkFilter {
    fn get_start_key(&self) -> &str {
        &self.source
    }

    // network event don't use mid key
    fn get_mid_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_range_end_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }
}

impl RawEventFilter for NetworkFilter {
    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
        _log_level: Option<String>,
        _log_contents: Option<String>,
        _text: Option<String>,
        _source: Option<String>,
        agent_id: Option<String>,
    ) -> Result<bool> {
        if check_address(&self.orig_addr, orig_addr)?
            && check_address(&self.resp_addr, resp_addr)?
            && check_port(&self.orig_port, orig_port)
            && check_port(&self.resp_port, resp_port)
            && check_agent_id(&self.agent_id, &agent_id)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

impl RawEventFilter for SearchFilter {
    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
        _log_level: Option<String>,
        _log_contents: Option<String>,
        text: Option<String>,
        _source: Option<String>,
        agent_id: Option<String>,
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
            && check_agent_id(&self.agent_id, &agent_id)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [conn_raw_events::ConnRawEventsConnRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnConnRawEvent])]
struct ConnRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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
#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [dns_raw_events::DnsRawEventsDnsRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnDnsRawEvent])]
struct DnsRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [http_raw_events::HttpRawEventsHttpRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnHttpRawEvent])]
struct HttpRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [rdp_raw_events::RdpRawEventsRdpRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnRdpRawEvent])]
struct RdpRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    cookie: String,
}

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [smtp_raw_events::SmtpRawEventsSmtpRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnSmtpRawEvent])]
struct SmtpRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [ntlm_raw_events::NtlmRawEventsNtlmRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnNtlmRawEvent])]
struct NtlmRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [kerberos_raw_events::KerberosRawEventsKerberosRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnKerberosRawEvent])]
struct KerberosRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    client_time: i64,
    server_time: i64,
    error_code: u32,
    client_realm: String,
    cname_type: u8,
    client_name: Vec<String>,
    realm: String,
    sname_type: u8,
    service_name: Vec<String>,
}

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [ssh_raw_events::SshRawEventsSshRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnSshRawEvent])]
struct SshRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [dce_rpc_raw_events::DceRpcRawEventsDceRpcRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnDceRpcRawEvent])]
struct DceRpcRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [ftp_raw_events::FtpRawEventsFtpRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnFtpRawEvent])]
struct FtpRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    user: String,
    password: String,
    command: String,
    reply_code: String,
    reply_msg: String,
    data_passive: bool,
    data_orig_addr: String,
    data_resp_addr: String,
    data_resp_port: u16,
    file: String,
    file_size: u64,
    file_id: String,
}

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [mqtt_raw_events::MqttRawEventsMqttRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnMqttRawEvent])]
struct MqttRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [ldap_raw_events::LdapRawEventsLdapRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnLdapRawEvent])]
struct LdapRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [tls_raw_events::TlsRawEventsTlsRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnTlsRawEvent])]
struct TlsRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
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
    #[graphql_client_type(from_name = "ja3_s")]
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

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [smb_raw_events::SmbRawEventsSmbRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnSmbRawEvent])]
struct SmbRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    command: u8,
    path: String,
    service: String,
    file_name: String,
    file_size: u64,
    resource_type: u16,
    fid: u16,
    create_time: i64,
    access_time: i64,
    write_time: i64,
    change_time: i64,
}

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [nfs_raw_events::NfsRawEventsNfsRawEventsEdgesNode, network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnNfsRawEvent])]
struct NfsRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    read_files: Vec<String>,
    write_files: Vec<String>,
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
    SmbRawEvent(SmbRawEvent),
    NfsRawEvent(NfsRawEvent),
    SmtpRawEvent(SmtpRawEvent),
}

impl From<network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode> for NetworkRawEvents {
    fn from(node: network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode) -> Self {
        match node {
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::ConnRawEvent(event) => {
                NetworkRawEvents::ConnRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::DnsRawEvent(event) => {
                NetworkRawEvents::DnsRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::HttpRawEvent(event) => {
                NetworkRawEvents::HttpRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::RdpRawEvent(event) => {
                NetworkRawEvents::RdpRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::NtlmRawEvent(event) => {
                NetworkRawEvents::NtlmRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::KerberosRawEvent(
                event,
            ) => NetworkRawEvents::KerberosRawEvent(event.into()),
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::SshRawEvent(event) => {
                NetworkRawEvents::SshRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::DceRpcRawEvent(
                event,
            ) => NetworkRawEvents::DceRpcRawEvent(event.into()),
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::FtpRawEvent(event) => {
                NetworkRawEvents::FtpRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::MqttRawEvent(event) => {
                NetworkRawEvents::MqttRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::LdapRawEvent(event) => {
                NetworkRawEvents::LdapRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::TlsRawEvent(event) => {
                NetworkRawEvents::TlsRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::SmbRawEvent(event) => {
                NetworkRawEvents::SmbRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::NfsRawEvent(event) => {
                NetworkRawEvents::NfsRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::SmtpRawEvent(event) => {
                NetworkRawEvents::SmtpRawEvent(event.into())
            }
        }
    }
}

macro_rules! from_key_value {
    ($to:ty, $from:ty, $($fields:ident),*) => {
        impl FromKeyValue<$from> for $to {
            fn from_key_value(key: &[u8], val: $from) -> Result<Self> {
                let timestamp = get_timestamp_from_key(key)?;
                let source = get_source_from_key(key)?;
                Ok(Self {
                    timestamp,
                    source,
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
            timestamp: get_timestamp_from_key(key)?,
            source: get_source_from_key(key)?,
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
            timestamp: get_timestamp_from_key(key)?,
            source: get_source_from_key(key)?,
            orig_addr: val.orig_addr.to_string(),
            resp_addr: val.resp_addr.to_string(),
            orig_port: val.orig_port,
            resp_port: val.resp_port,
            proto: val.proto,
            last_time: val.last_time,
            user: val.user,
            password: val.password,
            command: val.command,
            reply_code: val.reply_code,
            reply_msg: val.reply_msg,
            data_passive: val.data_passive,
            data_orig_addr: val.data_orig_addr.to_string(),
            data_resp_addr: val.data_resp_addr.to_string(),
            data_resp_port: val.data_resp_port,
            file: val.file,
            file_size: val.file_size,
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
    client_time,
    server_time,
    error_code,
    client_realm,
    cname_type,
    client_name,
    realm,
    sname_type,
    service_name
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

from_key_value!(
    SmbRawEvent,
    Smb,
    command,
    path,
    service,
    file_name,
    file_size,
    resource_type,
    fid,
    create_time,
    access_time,
    write_time,
    change_time
);

from_key_value!(NfsRawEvent, Nfs, read_files, write_files);

macro_rules! impl_node_compare_trait {
    ($($node_type:ty),*) => {
        $(
            impl NodeCompare for $node_type {
                fn source(&self) -> &str{
                    &self.source
                }
                fn time(&self) -> DateTime<Utc>{
                    self.timestamp
                }
            }
        )*
    };
}

impl_node_compare_trait!(
    ConnRawEvent,
    DnsRawEvent,
    HttpRawEvent,
    RdpRawEvent,
    SmtpRawEvent,
    NtlmRawEvent,
    KerberosRawEvent,
    SshRawEvent,
    DceRpcRawEvent,
    FtpRawEvent,
    MqttRawEvent,
    LdapRawEvent,
    TlsRawEvent,
    NfsRawEvent,
    SmbRawEvent
);

async fn handle_paged_conn_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, ConnRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.conn_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_dns_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, DnsRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.dns_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_http_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, HttpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.http_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_rdp_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, RdpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.rdp_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_smtp_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, SmtpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.smtp_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_ntlm_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, NtlmRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.ntlm_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_kerberos_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, KerberosRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.kerberos_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_ssh_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, SshRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.ssh_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_dce_rpc_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, DceRpcRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.dce_rpc_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}
async fn handle_paged_ftp_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, FtpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.ftp_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_mqtt_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>, // TODO: fix this
    last: Option<i32>,
) -> Result<Connection<String, MqttRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.mqtt_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_ldap_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>, // TODO: fix this
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, LdapRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.ldap_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_tls_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, TlsRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.tls_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_smb_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, SmbRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.smb_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_paged_nfs_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: Option<NetworkOptFilter>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, NfsRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.nfs_store()?;
    let sources = ctx.data::<IngestSources>()?;
    let filter = filter.unwrap_or_default();

    if filter.source.is_some() {
        handle_paged_events(store, filter, after, before, first, last).await
    } else {
        handle_paged_events_for_all_source(store, sources, filter, after, before, first, last).await
    }
}

async fn handle_network_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, NetworkRawEvents>> {
    let db = ctx.data::<Database>()?;
    query(
        after,
        before,
        first,
        last,
        |after, before, first, last| async move {
            let (conn_iter, size) =
                get_peekable_iter(&db.conn_store()?, &filter, &after, &before, first, last)?;

            let (dns_iter, _) =
                get_peekable_iter(&db.dns_store()?, &filter, &after, &before, first, last)?;

            let (http_iter, _) =
                get_peekable_iter(&db.http_store()?, &filter, &after, &before, first, last)?;

            let (rdp_iter, _) =
                get_peekable_iter(&db.rdp_store()?, &filter, &after, &before, first, last)?;

            let (ntlm_iter, _) =
                get_peekable_iter(&db.ntlm_store()?, &filter, &after, &before, first, last)?;

            let (kerberos_iter, _) =
                get_peekable_iter(&db.kerberos_store()?, &filter, &after, &before, first, last)?;

            let (ssh_iter, _) =
                get_peekable_iter(&db.ssh_store()?, &filter, &after, &before, first, last)?;

            let (dce_rpc_iter, _) =
                get_peekable_iter(&db.dce_rpc_store()?, &filter, &after, &before, first, last)?;

            let (ftp_iter, _) =
                get_peekable_iter(&db.ftp_store()?, &filter, &after, &before, first, last)?;

            let (mqtt_iter, _) =
                get_peekable_iter(&db.mqtt_store()?, &filter, &after, &before, first, last)?;

            let (ldap_iter, _) =
                get_peekable_iter(&db.ldap_store()?, &filter, &after, &before, first, last)?;

            let (tls_iter, _) =
                get_peekable_iter(&db.tls_store()?, &filter, &after, &before, first, last)?;

            let (smb_iter, _) =
                get_peekable_iter(&db.smb_store()?, &filter, &after, &before, first, last)?;

            let (nfs_iter, _) =
                get_peekable_iter(&db.nfs_store()?, &filter, &after, &before, first, last)?;

            let (smtp_iter, _) =
                get_peekable_iter(&db.smtp_store()?, &filter, &after, &before, first, last)?;

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
                smb_iter,
                nfs_iter,
                smtp_iter,
                size,
                is_forward,
            )
        },
    )
    .await
}

#[Object]
impl NetworkQuery {
    async fn conn_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, ConnRawEvent>> {
        let handler = handle_paged_conn_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            ConnRawEvents,
            conn_raw_events::Variables,
            conn_raw_events::ResponseData,
            conn_raw_events
        )
    }

    async fn dns_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, DnsRawEvent>> {
        let handler = handle_paged_dns_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            DnsRawEvents,
            dns_raw_events::Variables,
            dns_raw_events::ResponseData,
            dns_raw_events
        )
    }

    async fn http_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, HttpRawEvent>> {
        let handler = handle_paged_http_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            HttpRawEvents,
            http_raw_events::Variables,
            http_raw_events::ResponseData,
            http_raw_events
        )
    }

    async fn rdp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, RdpRawEvent>> {
        let handler = handle_paged_rdp_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            RdpRawEvents,
            rdp_raw_events::Variables,
            rdp_raw_events::ResponseData,
            rdp_raw_events
        )
    }

    async fn smtp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, SmtpRawEvent>> {
        let handler = handle_paged_smtp_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            SmtpRawEvents,
            smtp_raw_events::Variables,
            smtp_raw_events::ResponseData,
            smtp_raw_events
        )
    }

    async fn ntlm_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, NtlmRawEvent>> {
        let handler = handle_paged_ntlm_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            NtlmRawEvents,
            ntlm_raw_events::Variables,
            ntlm_raw_events::ResponseData,
            ntlm_raw_events
        )
    }

    async fn kerberos_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, KerberosRawEvent>> {
        let handler = handle_paged_kerberos_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            KerberosRawEvents,
            kerberos_raw_events::Variables,
            kerberos_raw_events::ResponseData,
            kerberos_raw_events
        )
    }

    async fn ssh_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, SshRawEvent>> {
        let handler = handle_paged_ssh_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            SshRawEvents,
            ssh_raw_events::Variables,
            ssh_raw_events::ResponseData,
            ssh_raw_events
        )
    }

    async fn dce_rpc_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, DceRpcRawEvent>> {
        let handler = handle_paged_dce_rpc_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            DceRpcRawEvents,
            dce_rpc_raw_events::Variables,
            dce_rpc_raw_events::ResponseData,
            dce_rpc_raw_events
        )
    }

    async fn ftp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, FtpRawEvent>> {
        let handler = handle_paged_ftp_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            FtpRawEvents,
            ftp_raw_events::Variables,
            ftp_raw_events::ResponseData,
            ftp_raw_events
        )
    }

    async fn mqtt_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, MqttRawEvent>> {
        let handler = handle_paged_mqtt_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            MqttRawEvents,
            mqtt_raw_events::Variables,
            mqtt_raw_events::ResponseData,
            mqtt_raw_events
        )
    }

    async fn ldap_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, LdapRawEvent>> {
        let handler = handle_paged_ldap_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            LdapRawEvents,
            ldap_raw_events::Variables,
            ldap_raw_events::ResponseData,
            ldap_raw_events
        )
    }

    async fn tls_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, TlsRawEvent>> {
        let handler = handle_paged_tls_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            TlsRawEvents,
            tls_raw_events::Variables,
            tls_raw_events::ResponseData,
            tls_raw_events
        )
    }

    async fn smb_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, SmbRawEvent>> {
        let handler = handle_paged_smb_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            SmbRawEvents,
            smb_raw_events::Variables,
            smb_raw_events::ResponseData,
            smb_raw_events
        )
    }

    async fn nfs_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: Option<NetworkOptFilter>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, NfsRawEvent>> {
        let handler = handle_paged_nfs_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            filter.map(std::convert::Into::into),
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            NfsRawEvents,
            nfs_raw_events::Variables,
            nfs_raw_events::ResponseData,
            nfs_raw_events
        )
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
        let handler = handle_network_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.into(),
            filter.source,
            after,
            before,
            first,
            last,
            handler,
            GraphQlNetworkRawEvents,
            network_raw_events::Variables,
            network_raw_events::ResponseData,
            network_raw_events
        )
    }

    async fn search_conn_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.conn_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
            Ok(collect_exist_timestamp::<Conn>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchConnRawEvents,
            search_conn_raw_events::Variables,
            search_conn_raw_events::ResponseData,
            search_conn_raw_events
        )
    }
    async fn search_dns_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.dns_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
            Ok(collect_exist_timestamp::<Dns>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchDnsRawEvents,
            search_dns_raw_events::Variables,
            search_dns_raw_events::ResponseData,
            search_dns_raw_events
        )
    }

    async fn search_http_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.http_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
            Ok(collect_exist_timestamp::<Http>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchHttpRawEvents,
            search_http_raw_events::Variables,
            search_http_raw_events::ResponseData,
            search_http_raw_events
        )
    }

    async fn search_rdp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.rdp_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
            Ok(collect_exist_timestamp::<Rdp>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchRdpRawEvents,
            search_rdp_raw_events::Variables,
            search_rdp_raw_events::ResponseData,
            search_rdp_raw_events
        )
    }

    async fn search_smtp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.smtp_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
            Ok(collect_exist_timestamp::<Smtp>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchSmtpRawEvents,
            search_smtp_raw_events::Variables,
            search_smtp_raw_events::ResponseData,
            search_smtp_raw_events
        )
    }

    async fn search_ntlm_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.ntlm_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
            Ok(collect_exist_timestamp::<Ntlm>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchNtlmRawEvents,
            search_ntlm_raw_events::Variables,
            search_ntlm_raw_events::ResponseData,
            search_ntlm_raw_events
        )
    }

    async fn search_kerberos_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.kerberos_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();

            Ok(collect_exist_timestamp::<Kerberos>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchKerberosRawEvents,
            search_kerberos_raw_events::Variables,
            search_kerberos_raw_events::ResponseData,
            search_kerberos_raw_events
        )
    }

    async fn search_ssh_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.ssh_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();

            Ok(collect_exist_timestamp::<Ssh>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchSshRawEvents,
            search_ssh_raw_events::Variables,
            search_ssh_raw_events::ResponseData,
            search_ssh_raw_events
        )
    }

    async fn search_dce_rpc_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.dce_rpc_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();

            Ok(collect_exist_timestamp::<DceRpc>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchDceRpcRawEvents,
            search_dce_rpc_raw_events::Variables,
            search_dce_rpc_raw_events::ResponseData,
            search_dce_rpc_raw_events
        )
    }

    async fn search_ftp_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.ftp_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();

            Ok(collect_exist_timestamp::<Ftp>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchFtpRawEvents,
            search_ftp_raw_events::Variables,
            search_ftp_raw_events::ResponseData,
            search_ftp_raw_events
        )
    }

    async fn search_mqtt_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.mqtt_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();

            Ok(collect_exist_timestamp::<Mqtt>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchMqttRawEvents,
            search_mqtt_raw_events::Variables,
            search_mqtt_raw_events::ResponseData,
            search_mqtt_raw_events
        )
    }

    async fn search_ldap_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.ldap_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();

            Ok(collect_exist_timestamp::<Ldap>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchLdapRawEvents,
            search_ldap_raw_events::Variables,
            search_ldap_raw_events::ResponseData,
            search_ldap_raw_events
        )
    }

    async fn search_tls_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.tls_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();

            Ok(collect_exist_timestamp::<Tls>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchTlsRawEvents,
            search_tls_raw_events::Variables,
            search_tls_raw_events::ResponseData,
            search_tls_raw_events
        )
    }

    async fn search_smb_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;

            let store = db.smb_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();

            Ok(collect_exist_timestamp::<Smb>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchSmbRawEvents,
            search_smb_raw_events::Variables,
            search_smb_raw_events::ResponseData,
            search_smb_raw_events
        )
    }

    async fn search_nfs_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'ctx>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.nfs_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();

            Ok(collect_exist_timestamp::<Nfs>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            SearchNfsRawEvents,
            search_nfs_raw_events::Variables,
            search_nfs_raw_events::ResponseData,
            search_nfs_raw_events
        )
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn network_connection(
    mut conn_iter: Peekable<FilteredIter<Conn, NetworkFilter>>,
    mut dns_iter: Peekable<FilteredIter<Dns, NetworkFilter>>,
    mut http_iter: Peekable<FilteredIter<Http, NetworkFilter>>,
    mut rdp_iter: Peekable<FilteredIter<Rdp, NetworkFilter>>,
    mut ntlm_iter: Peekable<FilteredIter<Ntlm, NetworkFilter>>,
    mut kerberos_iter: Peekable<FilteredIter<Kerberos, NetworkFilter>>,
    mut ssh_iter: Peekable<FilteredIter<Ssh, NetworkFilter>>,
    mut dce_rpc_iter: Peekable<FilteredIter<DceRpc, NetworkFilter>>,
    mut ftp_iter: Peekable<FilteredIter<Ftp, NetworkFilter>>,
    mut mqtt_iter: Peekable<FilteredIter<Mqtt, NetworkFilter>>,
    mut ldap_iter: Peekable<FilteredIter<Ldap, NetworkFilter>>,
    mut tls_iter: Peekable<FilteredIter<Tls, NetworkFilter>>,
    mut smb_iter: Peekable<FilteredIter<Smb, NetworkFilter>>,
    mut nfs_iter: Peekable<FilteredIter<Nfs, NetworkFilter>>,
    mut smtp_iter: Peekable<FilteredIter<Smtp, NetworkFilter>>,
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
    let mut smb_data = smb_iter.next();
    let mut nfs_data = nfs_iter.next();
    let mut smtp_data = smtp_iter.next();

    loop {
        let conn_ts = if let Some((ref key, _)) = conn_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let dns_ts = if let Some((ref key, _)) = dns_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let http_ts = if let Some((ref key, _)) = http_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let rdp_ts = if let Some((ref key, _)) = rdp_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let ntlm_ts = if let Some((ref key, _)) = ntlm_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let kerberos_ts = if let Some((ref key, _)) = kerberos_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let ssh_ts = if let Some((ref key, _)) = ssh_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let dce_rpc_ts = if let Some((ref key, _)) = dce_rpc_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let ftp_ts = if let Some((ref key, _)) = ftp_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let mqtt_ts = if let Some((ref key, _)) = mqtt_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let ldap_ts = if let Some((ref key, _)) = ldap_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let tls_ts = if let Some((ref key, _)) = tls_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let smb_ts = if let Some((ref key, _)) = smb_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let nfs_ts = if let Some((ref key, _)) = nfs_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let smtp_ts = if let Some((ref key, _)) = smtp_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let selected =
            if is_forward {
                timestamp.min(dns_ts.min(conn_ts.min(http_ts.min(rdp_ts.min(ntlm_ts.min(
                    kerberos_ts.min(ssh_ts.min(dce_rpc_ts.min(ftp_ts.min(
                        mqtt_ts.min(ldap_ts.min(tls_ts.min(smb_ts.min(nfs_ts.min(smtp_ts))))),
                    )))),
                ))))))
            } else {
                timestamp.max(dns_ts.max(conn_ts.max(http_ts.max(rdp_ts.max(ntlm_ts.max(
                    kerberos_ts.max(ssh_ts.max(dce_rpc_ts.max(ftp_ts.max(
                        mqtt_ts.max(ldap_ts.max(tls_ts.max(smb_ts.max(nfs_ts.max(smtp_ts))))),
                    )))),
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
                };
            }
            _ if selected == dns_ts => {
                if let Some((key, value)) = dns_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::DnsRawEvent(DnsRawEvent::from_key_value(&key, value)?),
                    ));
                    dns_data = dns_iter.next();
                };
            }
            _ if selected == http_ts => {
                if let Some((key, value)) = http_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::HttpRawEvent(HttpRawEvent::from_key_value(&key, value)?),
                    ));
                    http_data = http_iter.next();
                };
            }
            _ if selected == rdp_ts => {
                if let Some((key, value)) = rdp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::RdpRawEvent(RdpRawEvent::from_key_value(&key, value)?),
                    ));
                    rdp_data = rdp_iter.next();
                };
            }
            _ if selected == ntlm_ts => {
                if let Some((key, value)) = ntlm_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::NtlmRawEvent(NtlmRawEvent::from_key_value(&key, value)?),
                    ));
                    ntlm_data = ntlm_iter.next();
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
                };
            }
            _ if selected == ssh_ts => {
                if let Some((key, value)) = ssh_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::SshRawEvent(SshRawEvent::from_key_value(&key, value)?),
                    ));
                    ssh_data = ssh_iter.next();
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
                };
            }
            _ if selected == ftp_ts => {
                if let Some((key, value)) = ftp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::FtpRawEvent(FtpRawEvent::from_key_value(&key, value)?),
                    ));
                    ftp_data = ftp_iter.next();
                };
            }
            _ if selected == mqtt_ts => {
                if let Some((key, value)) = mqtt_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::MqttRawEvent(MqttRawEvent::from_key_value(&key, value)?),
                    ));
                    mqtt_data = mqtt_iter.next();
                };
            }
            _ if selected == ldap_ts => {
                if let Some((key, value)) = ldap_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::LdapRawEvent(LdapRawEvent::from_key_value(&key, value)?),
                    ));
                    ldap_data = ldap_iter.next();
                };
            }
            _ if selected == tls_ts => {
                if let Some((key, value)) = tls_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::TlsRawEvent(TlsRawEvent::from_key_value(&key, value)?),
                    ));
                    tls_data = tls_iter.next();
                };
            }
            _ if selected == smb_ts => {
                if let Some((key, value)) = smb_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::SmbRawEvent(SmbRawEvent::from_key_value(&key, value)?),
                    ));
                    smb_data = smb_iter.next();
                };
            }
            _ if selected == nfs_ts => {
                if let Some((key, value)) = nfs_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::NfsRawEvent(NfsRawEvent::from_key_value(&key, value)?),
                    ));
                    nfs_data = nfs_iter.next();
                };
            }
            _ if selected == smtp_ts => {
                if let Some((key, value)) = smtp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::SmtpRawEvent(SmtpRawEvent::from_key_value(&key, value)?),
                    ));
                    smtp_data = smtp_iter.next();
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
                && tls_data.is_none()
                && smb_data.is_none()
                && nfs_data.is_none()
                && smtp_data.is_none())
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
                || smb_data.is_some()
                || nfs_data.is_some()
                || smtp_data.is_some()
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
    connection.edges.extend(result_vec);

    Ok(connection)
}

impl_from_giganto_range_structs_for_graphql_client!(
    network_raw_events,
    conn_raw_events,
    dns_raw_events,
    http_raw_events,
    rdp_raw_events,
    smtp_raw_events,
    ntlm_raw_events,
    kerberos_raw_events,
    ssh_raw_events,
    dce_rpc_raw_events,
    ftp_raw_events,
    mqtt_raw_events,
    ldap_raw_events,
    tls_raw_events,
    nfs_raw_events,
    smb_raw_events,
    search_conn_raw_events,
    search_dce_rpc_raw_events,
    search_dns_raw_events,
    search_ftp_raw_events,
    search_http_raw_events,
    search_kerberos_raw_events,
    search_ldap_raw_events,
    search_mqtt_raw_events,
    search_nfs_raw_events,
    search_ntlm_raw_events,
    search_rdp_raw_events,
    search_smb_raw_events,
    search_smtp_raw_events,
    search_ssh_raw_events,
    search_tls_raw_events
);

impl_from_giganto_network_option_filter_for_graphql_client!(
    conn_raw_events,
    dns_raw_events,
    http_raw_events,
    rdp_raw_events,
    smtp_raw_events,
    ntlm_raw_events,
    kerberos_raw_events,
    ssh_raw_events,
    dce_rpc_raw_events,
    ftp_raw_events,
    mqtt_raw_events,
    ldap_raw_events,
    tls_raw_events,
    nfs_raw_events,
    smb_raw_events
);

impl_from_giganto_network_filter_for_graphql_client!(network_raw_events);

impl_from_giganto_search_filter_for_graphql_client!(
    search_conn_raw_events,
    search_dce_rpc_raw_events,
    search_dns_raw_events,
    search_ftp_raw_events,
    search_http_raw_events,
    search_kerberos_raw_events,
    search_ldap_raw_events,
    search_mqtt_raw_events,
    search_nfs_raw_events,
    search_ntlm_raw_events,
    search_rdp_raw_events,
    search_smb_raw_events,
    search_smtp_raw_events,
    search_ssh_raw_events,
    search_tls_raw_events
);
