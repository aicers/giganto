#[cfg(test)]
pub(crate) mod tests;

use std::{collections::BTreeSet, fmt::Debug, iter::Peekable, net::IpAddr};

use async_graphql::{
    Context, Object, Result, SimpleObject, Union,
    connection::{Connection, Edge, query},
};
use base64::Engine;
use chrono::{DateTime, Utc};
use giganto_client::ingest::network::{
    Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Kerberos, Ldap, MalformedDns, Mqtt, Nfs, Ntlm,
    Radius, Rdp, Smb, Smtp, Ssh, Tls,
};
#[cfg(feature = "cluster")]
use giganto_proc_macro::ConvertGraphQLEdgesNode;
#[cfg(feature = "cluster")]
use graphql_client::GraphQLQuery;
use jiff::Timestamp;

use super::{
    Engine, FromKeyValue, GigantoTimestamp, NetworkFilter, RawEventFilter, SearchFilter,
    StringNumberI64,
    StringNumberU32,
    StringNumberU64, StringNumberUsize, base64_engine, check_address, check_agent_id, check_port,
    collect_exist_times, events_vec_in_cluster, get_peekable_iter, get_time_from_key,
    handle_paged_events, min_max_time, paged_events_in_cluster,
};
#[cfg(feature = "cluster")]
use crate::graphql::client::{
    cluster::{
        impl_from_giganto_network_filter_for_graphql_client,
        impl_from_giganto_range_structs_for_graphql_client,
        impl_from_giganto_search_filter_for_graphql_client,
    },
    derives::{
        BootpRawEvents, ConnRawEvents, DceRpcRawEvents, DhcpRawEvents, DnsRawEvents, FtpRawEvents,
        HttpRawEvents, KerberosRawEvents, LdapRawEvents, MalformedDnsRawEvents, MqttRawEvents,
        NetworkRawEvents as GraphQlNetworkRawEvents, NfsRawEvents, NtlmRawEvents, RadiusRawEvents,
        RdpRawEvents, SearchBootpRawEvents, SearchConnRawEvents, SearchDceRpcRawEvents,
        SearchDhcpRawEvents, SearchDnsRawEvents, SearchFtpRawEvents, SearchHttpRawEvents,
        SearchKerberosRawEvents, SearchLdapRawEvents, SearchMalformedDnsRawEvents,
        SearchMqttRawEvents, SearchNfsRawEvents, SearchNtlmRawEvents, SearchRadiusRawEvents,
        SearchRdpRawEvents, SearchSmbRawEvents, SearchSmtpRawEvents, SearchSshRawEvents,
        SearchTlsRawEvents, SmbRawEvents, SmtpRawEvents, SshRawEvents, TlsRawEvents,
        bootp_raw_events, conn_raw_events, dce_rpc_raw_events, dhcp_raw_events, dns_raw_events,
        ftp_raw_events, http_raw_events, kerberos_raw_events, ldap_raw_events,
        malformed_dns_raw_events, mqtt_raw_events, network_raw_events, nfs_raw_events,
        ntlm_raw_events, radius_raw_events, rdp_raw_events, search_bootp_raw_events,
        search_conn_raw_events, search_dce_rpc_raw_events, search_dhcp_raw_events,
        search_dns_raw_events, search_ftp_raw_events, search_http_raw_events,
        search_kerberos_raw_events, search_ldap_raw_events, search_malformed_dns_raw_events,
        search_mqtt_raw_events, search_nfs_raw_events, search_ntlm_raw_events,
        search_radius_raw_events, search_rdp_raw_events, search_smb_raw_events,
        search_smtp_raw_events, search_ssh_raw_events, search_tls_raw_events, smb_raw_events,
        smtp_raw_events, ssh_raw_events, tls_raw_events,
    },
};
use crate::storage::{Database, FilteredIter, KeyExtractor};

#[derive(Default)]
pub(super) struct NetworkQuery;

impl KeyExtractor for NetworkFilter {
    fn get_start_key(&self) -> &str {
        &self.sensor
    }

    // network event don't use mid key
    fn get_mid_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_range_end_key(&self) -> (Option<Timestamp>, Option<Timestamp>) {
        if let Some(time) = &self.time {
            (time.start.map(|t| t.0), time.end.map(|t| t.0))
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
        _sensor: Option<String>,
        agent_id: Option<String>,
    ) -> Result<bool> {
        if check_address(self.orig_addr.as_ref(), orig_addr)?
            && check_address(self.resp_addr.as_ref(), resp_addr)?
            && check_port(self.orig_port.as_ref(), orig_port)
            && check_port(self.resp_port.as_ref(), resp_port)
            && check_agent_id(self.agent_id.as_deref(), agent_id.as_deref())
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
        _sensor: Option<String>,
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
        if check_address(self.orig_addr.as_ref(), orig_addr)?
            && check_address(self.resp_addr.as_ref(), resp_addr)?
            && check_port(self.orig_port.as_ref(), orig_port)
            && check_port(self.resp_port.as_ref(), resp_port)
            && check_agent_id(self.agent_id.as_deref(), agent_id.as_deref())
        {
            return Ok(true);
        }
        Ok(false)
    }
}

/// Represents an event extracted from a session.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    conn_raw_events::ConnRawEventsConnRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnConnRawEvent
]))]
struct ConnRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Connection State
    ///
    /// This is only used in TCP connections.
    ///
    /// The connection state is a string of letters that represent the state of the connection. The
    /// letters are as follows:
    ///
    /// - S: The originator sent a SYN segment.
    /// - h: The responder sent a SYN ACK segment.
    /// - A: The originator sent an ACK segment.
    /// - D: The originator sent at least one segment with payload data. In this case, that was HTTP
    ///   over TCP.
    /// - a: The responder replied with an ACK segment.
    /// - d: The responder replied with at least one segment with payload data.
    /// - F: The originator sent a FIN ACK segment.
    /// - f: The responder replied with a FIN ACK segment.
    /// - R: The originator sent a RST segment.
    /// - r: The responder sent a RST segment.
    /// - T: Timeout
    ///
    /// For example, `ShDdAaFf` indicates a session without packet loss.
    conn_state: String,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Service Name
    service: String,
    /// Bytes Sent by Source
    orig_bytes: StringNumberU64,
    /// Bytes Received by Destination
    resp_bytes: StringNumberU64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
}

/// Represents an event extracted from the DNS protocol.
#[allow(clippy::struct_excessive_bools)]
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    dns_raw_events::DnsRawEventsDnsRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnDnsRawEvent
]))]
struct DnsRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Query
    query: String,
    /// Answer
    answer: Vec<String>,
    /// Transaction ID
    trans_id: u16,
    /// Round-Trip Time
    rtt: StringNumberI64,
    /// Query Class
    qclass: u16,
    /// Query Type
    qtype: u16,
    /// Response Code
    rcode: u16,
    /// Authoritative Answer Flag
    aa_flag: bool,
    /// Truncated Flag
    tc_flag: bool,
    /// Recursion Desired Flag
    rd_flag: bool,
    /// Recursion Available Flag
    ra_flag: bool,
    /// Time to Live
    ttl: Vec<i32>,
}

/// Represents an event for malformed DNS traffic.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    malformed_dns_raw_events::MalformedDnsRawEventsMalformedDnsRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnMalformedDnsRawEvent
]))]
struct MalformedDnsRawEvent {
    /// Time the event started transmitting from a sensor
    time: DateTime<Utc>,
    /// Source IP address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: DateTime<Utc>,
    /// End Time
    end_time: DateTime<Utc>,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Transaction ID
    trans_id: u16,
    /// DNS Flags bitfield
    flags: u16,
    /// Question Record count
    question_count: u16,
    /// Answer Record count
    answer_count: u16,
    /// Authority Record count
    authority_count: u16,
    /// Additional Record count
    additional_count: u16,
    /// Captured malformed query count
    query_count: StringNumberU32,
    /// Captured malformed response count
    resp_count: StringNumberU32,
    /// Total malformed query bytes
    query_bytes: StringNumberU64,
    /// Total malformed response bytes
    resp_bytes: StringNumberU64,
    /// Raw malformed query payloads
    query_body: Vec<Vec<u8>>,
    /// Raw malformed response payloads
    resp_body: Vec<Vec<u8>>,
}

/// Represents an event extracted from the HTTP protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    http_raw_events::HttpRawEventsHttpRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnHttpRawEvent
]))]
struct HttpRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// HTTP Method
    method: String,
    /// Host
    host: String,
    /// URI
    uri: String,
    /// Referer
    referer: String,
    /// HTTP Version
    version: String,
    /// User Agent
    user_agent: String,
    /// Request Length
    request_len: StringNumberUsize,
    /// Response Length
    response_len: StringNumberUsize,
    /// Status Code
    status_code: u16,
    /// Status Message
    status_msg: String,
    /// Username
    username: String,
    /// Password
    password: String,
    /// Cookie
    cookie: String,
    /// Content Encoding
    content_encoding: String,
    /// Content Type
    content_type: String,
    /// Cache Control
    cache_control: String,
    /// Filenames
    filenames: Vec<String>,
    /// MIME Types
    mime_types: Vec<String>,
    /// Body
    body: Vec<u8>,
    /// Last State
    state: String,
}

/// Represents an event extracted from the RDP protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    rdp_raw_events::RdpRawEventsRdpRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnRdpRawEvent
]))]
struct RdpRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Cookie
    cookie: String,
}

/// Represents an event extracted from the SMTP protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    smtp_raw_events::SmtpRawEventsSmtpRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnSmtpRawEvent
]))]
struct SmtpRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Mail From
    mailfrom: String,
    /// Date
    date: String,
    /// From
    from: String,
    /// To
    to: String,
    /// Subject
    subject: String,
    /// Agent
    agent: String,
    /// State
    state: String,
}

/// Represents an event extracted from the NTLM protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    ntlm_raw_events::NtlmRawEventsNtlmRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnNtlmRawEvent
]))]
struct NtlmRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Username
    username: String,
    /// Hostname
    hostname: String,
    /// Domain Name
    domainname: String,
    /// Authentication Success
    success: String,
    /// Transport Protocol
    protocol: String,
}

/// Represents an event extracted from the Kerberos protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    kerberos_raw_events::KerberosRawEventsKerberosRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnKerberosRawEvent
]))]
struct KerberosRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Client Time
    client_time: StringNumberI64,
    /// Server Time
    server_time: StringNumberI64,
    /// Error Code
    error_code: StringNumberU32,
    /// Client Realm
    client_realm: String,
    /// Client Name Type
    cname_type: u8,
    /// Client Name
    client_name: Vec<String>,
    /// Realm
    realm: String,
    /// Service Name Type
    sname_type: u8,
    /// Service Name
    service_name: Vec<String>,
}

/// Represents an event extracted from the SSH protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    ssh_raw_events::SshRawEventsSshRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnSshRawEvent
]))]
struct SshRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Client
    client: String,
    /// Server
    server: String,
    /// Cipher Algorithm
    cipher_alg: String,
    /// MAC Algorithms
    mac_alg: String,
    /// Compression Algorithm
    compression_alg: String,
    /// Key Exchange Algorithm
    kex_alg: String,
    /// Host Key Algorithm
    host_key_alg: String,
    /// HASSH Algorithms
    hassh_algorithms: String,
    /// HASSH
    hassh: String,
    /// HASSH Server Algorithm
    hassh_server_algorithms: String,
    /// HASSH Server
    hassh_server: String,
    /// Client Signed Host Key Algorithm
    client_shka: String,
    /// Server Signed Host Key Algorithm
    server_shka: String,
}

/// Represents an event extracted from the DCE-RPC protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    dce_rpc_raw_events::DceRpcRawEventsDceRpcRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnDceRpcRawEvent
]))]
struct DceRpcRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Round-Trip Time
    rtt: StringNumberI64,
    /// Named Pipe
    named_pipe: String,
    /// Endpoint
    endpoint: String,
    /// Operation
    operation: String,
}

/// Represents an individual FTP command with its response and associated data.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    ftp_raw_events::FtpRawEventsFtpRawEventsEdgesNodeCommands,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnFtpRawEventCommands
]))]
struct FtpCommandRawEvent {
    /// Command
    command: String,
    /// Reply Code
    reply_code: String,
    /// Reply Message
    reply_msg: String,
    /// Passive Mode Flag
    data_passive: bool,
    /// Data Channel Source IP Address
    data_orig_addr: String,
    /// Data Channel Destination IP Address
    data_resp_addr: String,
    /// Data Channel Destination Port Number
    data_resp_port: u16,
    /// Filename
    file: String,
    /// File Size
    file_size: StringNumberU64,
    /// File ID
    file_id: String,
}

/// Represents an event extracted from the FTP protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    ftp_raw_events::FtpRawEventsFtpRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnFtpRawEvent
]))]
struct FtpRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Username
    user: String,
    /// Password
    password: String,
    /// Commands and their responses
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    commands: Vec<FtpCommandRawEvent>,
}

/// Represents an event extracted from the MQTT protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    mqtt_raw_events::MqttRawEventsMqttRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnMqttRawEvent
]))]
struct MqttRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// MQTT Protocol
    protocol: String,
    /// Version
    version: u8,
    /// Client ID
    client_id: String,
    /// Connection Acknowledgement Response
    connack_reason: u8,
    /// Subscription Request
    subscribe: Vec<String>,
    /// Subscription Acknowledgement Response
    suback_reason: Vec<u8>,
}

/// Represents an event extracted from the LDAP protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    ldap_raw_events::LdapRawEventsLdapRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnLdapRawEvent
]))]
struct LdapRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Message ID
    message_id: StringNumberU32,
    /// Version
    version: u8,
    /// Operation Code
    opcode: Vec<String>,
    /// Result Code
    result: Vec<String>,
    /// Diagnostic Message
    diagnostic_message: Vec<String>,
    /// Object
    object: Vec<String>,
    /// Argument
    argument: Vec<String>,
}

/// Represents an event extracted from the TLS protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    tls_raw_events::TlsRawEventsTlsRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnTlsRawEvent
]))]
struct TlsRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Server Name
    server_name: String,
    /// ALPN Protocol
    alpn_protocol: String,
    /// JA3 Fingerprint
    ja3: String,
    /// TLS Version
    version: String,
    /// Client Cipher Suites
    client_cipher_suites: Vec<u16>,
    /// Client Extensions
    client_extensions: Vec<u16>,
    /// Cipher
    cipher: u16,
    /// Extensions
    extensions: Vec<u16>,
    /// JA3S Fingerprint
    #[cfg_attr(feature = "cluster", graphql_client_type(from_name = "ja3_s"))]
    ja3s: String,
    /// Certificate Serial Number
    serial: String,
    /// Certificate Subject Country Name
    subject_country: String,
    /// Certificate Subject Organization Name
    subject_org_name: String,
    /// Certificate Common Name
    subject_common_name: String,
    /// Certificate Validity Start
    validity_not_before: StringNumberI64,
    /// Certificate Validity End
    validity_not_after: StringNumberI64,
    /// Certificate Subject Alternative Name
    subject_alt_name: String,
    /// Certificate Issuer Country
    issuer_country: String,
    /// Certificate Issuer Organization Name
    issuer_org_name: String,
    /// Certificate Issuer Organization Unit Name
    issuer_org_unit_name: String,
    /// Certificate Issuer Common Name
    issuer_common_name: String,
    /// Last Alert Message
    last_alert: u8,
}

/// Represents an event extracted from the SMB protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    smb_raw_events::SmbRawEventsSmbRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnSmbRawEvent
]))]
struct SmbRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Command
    command: u8,
    /// Path
    path: String,
    /// Service
    service: String,
    /// Filename
    file_name: String,
    /// File Size
    file_size: StringNumberU64,
    /// Resource Type
    resource_type: u16,
    /// File ID
    fid: u16,
    /// Create Time
    create_time: StringNumberI64,
    /// Access Time
    access_time: StringNumberI64,
    /// Write Time
    write_time: StringNumberI64,
    /// Change Time
    change_time: StringNumberI64,
}

/// Represents an event extracted from the NFS protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    nfs_raw_events::NfsRawEventsNfsRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnNfsRawEvent
]))]
struct NfsRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Read Files
    read_files: Vec<String>,
    /// Write Files
    write_files: Vec<String>,
}

/// Represents an event extracted from the BOOTP protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    bootp_raw_events::BootpRawEventsBootpRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnBootpRawEvent
]))]
struct BootpRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Operation Code
    op: u8,
    /// Hardware Type
    htype: u8,
    /// Hop Count
    hops: u8,
    /// Transaction ID
    xid: StringNumberU32,
    /// Client IP Address
    ciaddr: String,
    /// Your IP Address
    yiaddr: String,
    /// Server IP Address
    siaddr: String,
    /// Gateway IP Address
    giaddr: String,
    /// Client Hardware IP Address
    chaddr: Vec<u8>,
    /// Server Hostname
    sname: String,
    /// Boot Filename
    file: String,
}

impl From<i64> for StringNumberI64 {
    fn from(val: i64) -> Self {
        Self(val)
    }
}

impl From<u64> for StringNumberU64 {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<u32> for StringNumberU32 {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<usize> for StringNumberUsize {
    fn from(val: usize) -> Self {
        Self(val)
    }
}

/// Represents an event extracted from the DHCP protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    dhcp_raw_events::DhcpRawEventsDhcpRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnDhcpRawEvent
]))]
struct DhcpRawEvent {
    /// Start Time
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Message Type
    msg_type: u8,
    /// Client IP Address
    ciaddr: String,
    /// Your IP Address
    yiaddr: String,
    /// Server IP Address
    siaddr: String,
    /// Gateway IP Address
    giaddr: String,
    /// Subnet Mask
    subnet_mask: String,
    /// Routers
    router: Vec<String>,
    /// Domain Name Servers
    domain_name_server: Vec<String>,
    /// Request IP Address
    req_ip_addr: String,
    /// Lease Time
    lease_time: StringNumberU32,
    /// Server ID
    server_id: String,
    /// Parameter Request List
    param_req_list: Vec<u8>,
    /// Message
    message: String,
    /// Renewal Time
    renewal_time: StringNumberU32,
    /// Rebinding Time
    rebinding_time: StringNumberU32,
    /// Class ID List
    class_id: Vec<u8>,
    /// Client ID Type
    client_id_type: u8,
    /// Client ID List
    client_id: Vec<u8>,
}

/// Represents an event extracted from the RADIUS protocol.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    radius_raw_events::RadiusRawEventsRadiusRawEventsEdgesNode,
    network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNodeOnRadiusRawEvent
]))]
struct RadiusRawEvent {
    /// Time the event started transmitting from a sensor
    time: GigantoTimestamp,
    /// Source IP Address
    orig_addr: String,
    /// Source Port Number
    orig_port: u16,
    /// Destination IP Address
    resp_addr: String,
    /// Destination Port Number
    resp_port: u16,
    /// Protocol Number
    ///
    /// TCP is 6, and UDP is 17.
    proto: u8,
    /// Start Time
    start_time: GigantoTimestamp,
    /// End Time
    end_time: GigantoTimestamp,
    /// Duration
    ///
    /// It is measured in nanoseconds.
    duration: StringNumberI64,
    /// Packets Sent by Source
    orig_pkts: StringNumberU64,
    /// Packets Received by Destination
    resp_pkts: StringNumberU64,
    /// Layer 2 Bytes Sent by Source
    orig_l2_bytes: StringNumberU64,
    /// Layer 2 Bytes Received by Destination
    resp_l2_bytes: StringNumberU64,
    /// Identifier
    id: u8,
    /// Code
    code: u8,
    /// Response Code
    resp_code: u8,
    /// Authenticator
    auth: String,
    /// Response Authenticator
    resp_auth: String,
    /// User Name
    user_name: Vec<u8>,
    /// User Password
    user_passwd: Vec<u8>,
    /// CHAP Password
    chap_passwd: Vec<u8>,
    /// NAS IP Address
    nas_ip: String,
    /// NAS Port
    nas_port: StringNumberU32,
    /// State
    state: Vec<u8>,
    /// NAS Identifier
    nas_id: Vec<u8>,
    /// NAS Port Type
    nas_port_type: StringNumberU32,
    /// Message
    message: String,
}

#[allow(clippy::enum_variant_names)]
#[derive(Union)]
enum NetworkRawEvents {
    ConnRawEvent(ConnRawEvent),
    DnsRawEvent(DnsRawEvent),
    MalformedDnsRawEvent(MalformedDnsRawEvent),
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
    BootpRawEvent(BootpRawEvent),
    DhcpRawEvent(DhcpRawEvent),
    RadiusRawEvent(RadiusRawEvent),
}

#[cfg(feature = "cluster")]
impl From<network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode> for NetworkRawEvents {
    fn from(node: network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode) -> Self {
        match node {
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::ConnRawEvent(event) => {
                NetworkRawEvents::ConnRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::DnsRawEvent(event) => {
                NetworkRawEvents::DnsRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::MalformedDnsRawEvent(
                event,
            ) => NetworkRawEvents::MalformedDnsRawEvent(event.into()),
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
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::BootpRawEvent(event) => {
                NetworkRawEvents::BootpRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::DhcpRawEvent(event) => {
                NetworkRawEvents::DhcpRawEvent(event.into())
            }
            network_raw_events::NetworkRawEventsNetworkRawEventsEdgesNode::RadiusRawEvent(
                event,
            ) => NetworkRawEvents::RadiusRawEvent(event.into()),
        }
    }
}

macro_rules! from_key_value {
    ($to:ty, $from:ty,$( $plain_field:ident ),* ; $( $str_num_field:ident ),* ) => {
        impl FromKeyValue<$from> for $to {
            fn from_key_value(key: &[u8], val: $from) -> Result<Self> {
                let time = get_time_from_key(key)?.into();
                Ok(Self {
                    time,
                    orig_addr: val.orig_addr.to_string(),
                    resp_addr: val.resp_addr.to_string(),
                    orig_port: val.orig_port,
                    resp_port: val.resp_port,
                    proto: val.proto,
                    start_time: Timestamp::from_nanosecond(val.start_time.timestamp_nanos_opt().unwrap_or(0).into()).ok().map(Into::into).unwrap_or_else(|| Timestamp::MIN.into()),
                    end_time: Timestamp::from_nanosecond(val.end_time.timestamp_nanos_opt().unwrap_or(0).into()).ok().map(Into::into).unwrap_or_else(|| Timestamp::MIN.into()),
                    duration: val.duration.into(),
                    orig_pkts: val.orig_pkts.into(),
                    resp_pkts: val.resp_pkts.into(),
                    orig_l2_bytes: val.orig_l2_bytes.into(),
                    resp_l2_bytes: val.resp_l2_bytes.into(),
                    $(
                        $plain_field: val.$plain_field,
                    )*
                    $(
                        $str_num_field: {
                            val.$str_num_field.into()
                        },
                    )*
                })
            }
        }
    };
}

impl FromKeyValue<Http> for HttpRawEvent {
    fn from_key_value(key: &[u8], val: Http) -> Result<Self> {
        Ok(HttpRawEvent {
            time: get_time_from_key(key)?.into(),
            orig_addr: val.orig_addr.to_string(),
            resp_addr: val.resp_addr.to_string(),
            orig_port: val.orig_port,
            resp_port: val.resp_port,
            proto: val.proto,
            start_time: Timestamp::from_nanosecond(
                val.start_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            end_time: Timestamp::from_nanosecond(
                val.end_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            duration: val.duration.into(),
            orig_pkts: val.orig_pkts.into(),
            resp_pkts: val.resp_pkts.into(),
            orig_l2_bytes: val.orig_l2_bytes.into(),
            resp_l2_bytes: val.resp_l2_bytes.into(),
            method: val.method,
            host: val.host,
            uri: val.uri,
            referer: val.referer,
            version: val.version,
            user_agent: val.user_agent,
            status_code: val.status_code,
            status_msg: val.status_msg,
            username: val.username,
            password: val.password,
            cookie: val.cookie,
            content_encoding: val.content_encoding,
            content_type: val.content_type,
            cache_control: val.cache_control,
            filenames: val.filenames.clone(),
            mime_types: val.mime_types.clone(),
            body: val.body.clone(),
            state: val.state,
            request_len: StringNumberUsize(val.request_len),
            response_len: StringNumberUsize(val.response_len),
        })
    }
}

impl FromKeyValue<MalformedDns> for MalformedDnsRawEvent {
    fn from_key_value(key: &[u8], val: MalformedDns) -> Result<Self> {
        Ok(MalformedDnsRawEvent {
            time: get_time_from_key(key)?,
            orig_addr: val.orig_addr.to_string(),
            resp_addr: val.resp_addr.to_string(),
            orig_port: val.orig_port,
            resp_port: val.resp_port,
            proto: val.proto,
            start_time: val.start_time,
            end_time: val.end_time,
            duration: val.duration.into(),
            orig_pkts: val.orig_pkts.into(),
            resp_pkts: val.resp_pkts.into(),
            orig_l2_bytes: val.orig_l2_bytes.into(),
            resp_l2_bytes: val.resp_l2_bytes.into(),
            trans_id: val.trans_id,
            flags: val.flags,
            question_count: val.question_count,
            answer_count: val.answer_count,
            authority_count: val.authority_count,
            additional_count: val.additional_count,
            query_count: val.query_count.into(),
            resp_count: val.resp_count.into(),
            query_bytes: val.query_bytes.into(),
            resp_bytes: val.resp_bytes.into(),
            query_body: val.query_body,
            resp_body: val.resp_body,
        })
    }
}

impl FromKeyValue<Conn> for ConnRawEvent {
    fn from_key_value(key: &[u8], val: Conn) -> Result<Self> {
        Ok(ConnRawEvent {
            time: get_time_from_key(key)?.into(),
            orig_addr: val.orig_addr.to_string(),
            resp_addr: val.resp_addr.to_string(),
            orig_port: val.orig_port,
            resp_port: val.resp_port,
            proto: val.proto,
            conn_state: val.conn_state,
            start_time: Timestamp::from_nanosecond(
                val.start_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            end_time: Timestamp::from_nanosecond(
                val.end_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            duration: val.duration.into(),
            service: val.service,
            orig_bytes: val.orig_bytes.into(),
            resp_bytes: val.resp_bytes.into(),
            orig_pkts: val.orig_pkts.into(),
            resp_pkts: val.resp_pkts.into(),
            orig_l2_bytes: val.orig_l2_bytes.into(),
            resp_l2_bytes: val.resp_l2_bytes.into(),
        })
    }
}

impl FromKeyValue<Ftp> for FtpRawEvent {
    fn from_key_value(key: &[u8], val: Ftp) -> Result<Self> {
        Ok(FtpRawEvent {
            time: get_time_from_key(key)?.into(),
            orig_addr: val.orig_addr.to_string(),
            resp_addr: val.resp_addr.to_string(),
            orig_port: val.orig_port,
            resp_port: val.resp_port,
            proto: val.proto,
            start_time: Timestamp::from_nanosecond(
                val.start_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            end_time: Timestamp::from_nanosecond(
                val.end_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            duration: val.duration.into(),
            orig_pkts: val.orig_pkts.into(),
            resp_pkts: val.resp_pkts.into(),
            orig_l2_bytes: val.orig_l2_bytes.into(),
            resp_l2_bytes: val.resp_l2_bytes.into(),
            user: val.user,
            password: val.password,
            commands: val
                .commands
                .into_iter()
                .map(|cmd| FtpCommandRawEvent {
                    command: cmd.command,
                    reply_code: cmd.reply_code,
                    reply_msg: cmd.reply_msg,
                    data_passive: cmd.data_passive,
                    data_orig_addr: cmd.data_orig_addr.to_string(),
                    data_resp_addr: cmd.data_resp_addr.to_string(),
                    data_resp_port: cmd.data_resp_port,
                    file: cmd.file,
                    file_size: cmd.file_size.into(),
                    file_id: cmd.file_id,
                })
                .collect(),
        })
    }
}

impl FromKeyValue<Bootp> for BootpRawEvent {
    fn from_key_value(key: &[u8], val: Bootp) -> Result<Self> {
        Ok(BootpRawEvent {
            time: get_time_from_key(key)?.into(),
            orig_addr: val.orig_addr.to_string(),
            orig_port: val.orig_port,
            resp_addr: val.resp_addr.to_string(),
            resp_port: val.resp_port,
            proto: val.proto,
            start_time: Timestamp::from_nanosecond(
                val.start_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            end_time: Timestamp::from_nanosecond(
                val.end_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            duration: val.duration.into(),
            orig_pkts: val.orig_pkts.into(),
            resp_pkts: val.resp_pkts.into(),
            orig_l2_bytes: val.orig_l2_bytes.into(),
            resp_l2_bytes: val.resp_l2_bytes.into(),
            op: val.op,
            htype: val.htype,
            hops: val.hops,
            xid: val.xid.into(),
            ciaddr: val.ciaddr.to_string(),
            yiaddr: val.yiaddr.to_string(),
            siaddr: val.siaddr.to_string(),
            giaddr: val.giaddr.to_string(),
            chaddr: val.chaddr.clone(),
            sname: val.sname.clone(),
            file: val.file.clone(),
        })
    }
}

impl FromKeyValue<Dhcp> for DhcpRawEvent {
    fn from_key_value(key: &[u8], val: Dhcp) -> Result<Self> {
        Ok(DhcpRawEvent {
            time: get_time_from_key(key)?.into(),
            orig_addr: val.orig_addr.to_string(),
            orig_port: val.orig_port,
            resp_addr: val.resp_addr.to_string(),
            resp_port: val.resp_port,
            proto: val.proto,
            start_time: Timestamp::from_nanosecond(
                val.start_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            end_time: Timestamp::from_nanosecond(
                val.end_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            duration: val.duration.into(),
            orig_pkts: val.orig_pkts.into(),
            resp_pkts: val.resp_pkts.into(),
            orig_l2_bytes: val.orig_l2_bytes.into(),
            resp_l2_bytes: val.resp_l2_bytes.into(),
            msg_type: val.msg_type,
            ciaddr: val.ciaddr.to_string(),
            yiaddr: val.yiaddr.to_string(),
            siaddr: val.siaddr.to_string(),
            giaddr: val.giaddr.to_string(),
            subnet_mask: val.subnet_mask.to_string(),
            router: val.router.iter().map(ToString::to_string).collect(),
            domain_name_server: val
                .domain_name_server
                .iter()
                .map(ToString::to_string)
                .collect(),
            req_ip_addr: val.req_ip_addr.to_string(),
            lease_time: StringNumberU32(val.lease_time),
            server_id: val.server_id.to_string(),
            param_req_list: val.param_req_list.clone(),
            message: val.message.clone(),
            renewal_time: StringNumberU32(val.renewal_time),
            rebinding_time: StringNumberU32(val.rebinding_time),
            class_id: val.class_id.clone(),
            client_id_type: val.client_id_type,
            client_id: val.client_id.clone(),
        })
    }
}

impl FromKeyValue<Radius> for RadiusRawEvent {
    fn from_key_value(key: &[u8], val: Radius) -> Result<Self> {
        Ok(RadiusRawEvent {
            time: get_time_from_key(key)?.into(),
            orig_addr: val.orig_addr.to_string(),
            orig_port: val.orig_port,
            resp_addr: val.resp_addr.to_string(),
            resp_port: val.resp_port,
            proto: val.proto,
            start_time: Timestamp::from_nanosecond(
                val.start_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            end_time: Timestamp::from_nanosecond(
                val.end_time.timestamp_nanos_opt().unwrap_or(0).into(),
            )
            .ok()
            .map_or_else(|| Timestamp::MIN.into(), Into::into),
            duration: val.duration.into(),
            orig_pkts: val.orig_pkts.into(),
            resp_pkts: val.resp_pkts.into(),
            orig_l2_bytes: val.orig_l2_bytes.into(),
            resp_l2_bytes: val.resp_l2_bytes.into(),
            id: val.id,
            code: val.code,
            resp_code: val.resp_code,
            auth: val.auth.clone(),
            resp_auth: val.resp_auth.clone(),
            user_name: val.user_name.clone(),
            user_passwd: val.user_passwd.clone(),
            chap_passwd: val.chap_passwd.clone(),
            nas_ip: val.nas_ip.to_string(),
            nas_port: StringNumberU32(val.nas_port),
            state: val.state.clone(),
            nas_id: val.nas_id.clone(),
            nas_port_type: StringNumberU32(val.nas_port_type),
            message: val.message.clone(),
        })
    }
}

from_key_value!(RdpRawEvent, Rdp, cookie;);

from_key_value!(
    DnsRawEvent,
    Dns,
    query,
    answer,
    trans_id,
    qclass,
    qtype,
    rcode,
    aa_flag,
    tc_flag,
    rd_flag,
    ra_flag,
    ttl;
    rtt
);

from_key_value!(
    SmtpRawEvent,
    Smtp,
    mailfrom,
    date,
    from,
    to,
    subject,
    agent,
    state;
);

from_key_value!(
    NtlmRawEvent,
    Ntlm,
    username,
    hostname,
    domainname,
    success,
    protocol;
);

from_key_value!(
    KerberosRawEvent,
    Kerberos,
    client_realm,
    cname_type,
    client_name,
    realm,
    sname_type,
    service_name;
    client_time,
    server_time,
    error_code
);

from_key_value!(
    SshRawEvent,
    Ssh,
    client,
    server,
    cipher_alg,
    mac_alg,
    compression_alg,
    kex_alg,
    host_key_alg,
    hassh_algorithms,
    hassh,
    hassh_server_algorithms,
    hassh_server,
    client_shka,
    server_shka;
);

from_key_value!(
    DceRpcRawEvent,
    DceRpc,
    named_pipe,
    endpoint,
    operation;
    rtt
);

from_key_value!(
    MqttRawEvent,
    Mqtt,
    protocol,
    version,
    client_id,
    connack_reason,
    subscribe,
    suback_reason;
);

from_key_value!(
    LdapRawEvent,
    Ldap,
    version,
    opcode,
    result,
    diagnostic_message,
    object,
    argument;
    message_id
);

from_key_value!(
    TlsRawEvent,
    Tls,
    server_name,
    alpn_protocol,
    ja3,
    version,
    client_cipher_suites,
    client_extensions,
    cipher,
    extensions,
    ja3s,
    serial,
    subject_country,
    subject_org_name,
    subject_common_name,
    subject_alt_name,
    issuer_country,
    issuer_org_name,
    issuer_org_unit_name,
    issuer_common_name,
    last_alert;
    validity_not_before,
    validity_not_after
);

from_key_value!(
    SmbRawEvent,
    Smb,
    command,
    path,
    service,
    file_name,
    resource_type,
    fid;
    file_size,
    create_time,
    access_time,
    write_time,
    change_time
);

from_key_value!(NfsRawEvent, Nfs, read_files, write_files;);

async fn handle_paged_conn_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, ConnRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.conn_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_dns_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, DnsRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.dns_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_malformed_dns_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, MalformedDnsRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.malformed_dns_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_http_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, HttpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.http_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_rdp_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, RdpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.rdp_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_smtp_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, SmtpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.smtp_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_ntlm_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, NtlmRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.ntlm_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_kerberos_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, KerberosRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.kerberos_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_ssh_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, SshRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.ssh_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_dce_rpc_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, DceRpcRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.dce_rpc_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}
async fn handle_paged_ftp_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, FtpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.ftp_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_mqtt_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>, // TODO: fix this
    last: Option<i32>,
) -> Result<Connection<String, MqttRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.mqtt_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_ldap_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>, // TODO: fix this
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, LdapRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.ldap_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_tls_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, TlsRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.tls_store()?;
    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_smb_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, SmbRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.smb_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_nfs_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, NfsRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.nfs_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_bootp_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, BootpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.bootp_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_dhcp_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, DhcpRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.dhcp_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_paged_radius_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, RadiusRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.radius_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

#[allow(clippy::too_many_lines)]
async fn handle_network_raw_events(
    ctx: &Context<'_>,
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
            let (conn_iter, size) = get_peekable_iter(
                &db.conn_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (dns_iter, _) = get_peekable_iter(
                &db.dns_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (malformed_dns_iter, _) = get_peekable_iter(
                &db.malformed_dns_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (http_iter, _) = get_peekable_iter(
                &db.http_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (rdp_iter, _) = get_peekable_iter(
                &db.rdp_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (ntlm_iter, _) = get_peekable_iter(
                &db.ntlm_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (kerberos_iter, _) = get_peekable_iter(
                &db.kerberos_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (ssh_iter, _) = get_peekable_iter(
                &db.ssh_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (dce_rpc_iter, _) = get_peekable_iter(
                &db.dce_rpc_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (ftp_iter, _) = get_peekable_iter(
                &db.ftp_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (mqtt_iter, _) = get_peekable_iter(
                &db.mqtt_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (ldap_iter, _) = get_peekable_iter(
                &db.ldap_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (tls_iter, _) = get_peekable_iter(
                &db.tls_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (smb_iter, _) = get_peekable_iter(
                &db.smb_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (nfs_iter, _) = get_peekable_iter(
                &db.nfs_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (smtp_iter, _) = get_peekable_iter(
                &db.smtp_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (bootp_iter, _) = get_peekable_iter(
                &db.bootp_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (dhcp_iter, _) = get_peekable_iter(
                &db.dhcp_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (radius_iter, _) = get_peekable_iter(
                &db.radius_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let mut is_forward: bool = true;
            if before.is_some() || last.is_some() {
                is_forward = false;
            }

            network_connection(
                conn_iter,
                dns_iter,
                malformed_dns_iter,
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
                bootp_iter,
                dhcp_iter,
                radius_iter,
                size,
                is_forward,
            )
        },
    )
    .await
}

#[Object]
#[allow(clippy::unused_async)]
impl NetworkQuery {
    async fn conn_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ConnRawEvent>> {
        let handler = handle_paged_conn_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            ConnRawEvents,
            conn_raw_events::Variables,
            conn_raw_events::ResponseData,
            conn_raw_events
        )
    }

    async fn dns_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DnsRawEvent>> {
        let handler = handle_paged_dns_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            DnsRawEvents,
            dns_raw_events::Variables,
            dns_raw_events::ResponseData,
            dns_raw_events
        )
    }

    async fn malformed_dns_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, MalformedDnsRawEvent>> {
        let handler = handle_paged_malformed_dns_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            MalformedDnsRawEvents,
            malformed_dns_raw_events::Variables,
            malformed_dns_raw_events::ResponseData,
            malformed_dns_raw_events
        )
    }

    async fn http_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, HttpRawEvent>> {
        let handler = handle_paged_http_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            HttpRawEvents,
            http_raw_events::Variables,
            http_raw_events::ResponseData,
            http_raw_events
        )
    }

    async fn rdp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RdpRawEvent>> {
        let handler = handle_paged_rdp_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            RdpRawEvents,
            rdp_raw_events::Variables,
            rdp_raw_events::ResponseData,
            rdp_raw_events
        )
    }

    async fn smtp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, SmtpRawEvent>> {
        let handler = handle_paged_smtp_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            SmtpRawEvents,
            smtp_raw_events::Variables,
            smtp_raw_events::ResponseData,
            smtp_raw_events
        )
    }

    async fn ntlm_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, NtlmRawEvent>> {
        let handler = handle_paged_ntlm_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            NtlmRawEvents,
            ntlm_raw_events::Variables,
            ntlm_raw_events::ResponseData,
            ntlm_raw_events
        )
    }

    async fn kerberos_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, KerberosRawEvent>> {
        let handler = handle_paged_kerberos_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            KerberosRawEvents,
            kerberos_raw_events::Variables,
            kerberos_raw_events::ResponseData,
            kerberos_raw_events
        )
    }

    async fn ssh_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, SshRawEvent>> {
        let handler = handle_paged_ssh_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            SshRawEvents,
            ssh_raw_events::Variables,
            ssh_raw_events::ResponseData,
            ssh_raw_events
        )
    }

    async fn dce_rpc_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DceRpcRawEvent>> {
        let handler = handle_paged_dce_rpc_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            DceRpcRawEvents,
            dce_rpc_raw_events::Variables,
            dce_rpc_raw_events::ResponseData,
            dce_rpc_raw_events
        )
    }

    async fn ftp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FtpRawEvent>> {
        let handler = handle_paged_ftp_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            FtpRawEvents,
            ftp_raw_events::Variables,
            ftp_raw_events::ResponseData,
            ftp_raw_events
        )
    }

    async fn mqtt_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, MqttRawEvent>> {
        let handler = handle_paged_mqtt_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            MqttRawEvents,
            mqtt_raw_events::Variables,
            mqtt_raw_events::ResponseData,
            mqtt_raw_events
        )
    }

    async fn ldap_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, LdapRawEvent>> {
        let handler = handle_paged_ldap_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            LdapRawEvents,
            ldap_raw_events::Variables,
            ldap_raw_events::ResponseData,
            ldap_raw_events
        )
    }

    async fn tls_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, TlsRawEvent>> {
        let handler = handle_paged_tls_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            TlsRawEvents,
            tls_raw_events::Variables,
            tls_raw_events::ResponseData,
            tls_raw_events
        )
    }

    async fn smb_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, SmbRawEvent>> {
        let handler = handle_paged_smb_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            SmbRawEvents,
            smb_raw_events::Variables,
            smb_raw_events::ResponseData,
            smb_raw_events
        )
    }

    async fn nfs_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, NfsRawEvent>> {
        let handler = handle_paged_nfs_raw_events;
        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            NfsRawEvents,
            nfs_raw_events::Variables,
            nfs_raw_events::ResponseData,
            nfs_raw_events
        )
    }

    async fn bootp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, BootpRawEvent>> {
        let handler = handle_paged_bootp_raw_events;
        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            BootpRawEvents,
            bootp_raw_events::Variables,
            bootp_raw_events::ResponseData,
            bootp_raw_events
        )
    }

    async fn dhcp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DhcpRawEvent>> {
        let handler = handle_paged_dhcp_raw_events;
        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            DhcpRawEvents,
            dhcp_raw_events::Variables,
            dhcp_raw_events::ResponseData,
            dhcp_raw_events
        )
    }

    async fn radius_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RadiusRawEvent>> {
        let handler = handle_paged_radius_raw_events;
        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            RadiusRawEvents,
            radius_raw_events::Variables,
            radius_raw_events::ResponseData,
            radius_raw_events
        )
    }

    async fn network_raw_events(
        &self,
        ctx: &Context<'_>,
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
            filter.sensor,
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

    async fn search_conn_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.conn_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();
            Ok(collect_exist_times::<Conn>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchConnRawEvents,
            search_conn_raw_events::Variables,
            search_conn_raw_events::ResponseData,
            search_conn_raw_events
        )
    }

    async fn search_dns_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.dns_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();
            Ok(collect_exist_times::<Dns>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchDnsRawEvents,
            search_dns_raw_events::Variables,
            search_dns_raw_events::ResponseData,
            search_dns_raw_events
        )
    }

    async fn search_malformed_dns_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.malformed_dns_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
            Ok(collect_exist_times::<MalformedDns>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchMalformedDnsRawEvents,
            search_malformed_dns_raw_events::Variables,
            search_malformed_dns_raw_events::ResponseData,
            search_malformed_dns_raw_events
        )
    }

    async fn search_http_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.http_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();
            Ok(collect_exist_times::<Http>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchHttpRawEvents,
            search_http_raw_events::Variables,
            search_http_raw_events::ResponseData,
            search_http_raw_events
        )
    }

    async fn search_rdp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.rdp_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();
            Ok(collect_exist_times::<Rdp>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchRdpRawEvents,
            search_rdp_raw_events::Variables,
            search_rdp_raw_events::ResponseData,
            search_rdp_raw_events
        )
    }

    async fn search_smtp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.smtp_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();
            Ok(collect_exist_times::<Smtp>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchSmtpRawEvents,
            search_smtp_raw_events::Variables,
            search_smtp_raw_events::ResponseData,
            search_smtp_raw_events
        )
    }

    async fn search_ntlm_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.ntlm_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();
            Ok(collect_exist_times::<Ntlm>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchNtlmRawEvents,
            search_ntlm_raw_events::Variables,
            search_ntlm_raw_events::ResponseData,
            search_ntlm_raw_events
        )
    }

    async fn search_kerberos_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.kerberos_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Kerberos>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchKerberosRawEvents,
            search_kerberos_raw_events::Variables,
            search_kerberos_raw_events::ResponseData,
            search_kerberos_raw_events
        )
    }

    async fn search_ssh_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.ssh_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Ssh>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchSshRawEvents,
            search_ssh_raw_events::Variables,
            search_ssh_raw_events::ResponseData,
            search_ssh_raw_events
        )
    }

    async fn search_dce_rpc_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.dce_rpc_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<DceRpc>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchDceRpcRawEvents,
            search_dce_rpc_raw_events::Variables,
            search_dce_rpc_raw_events::ResponseData,
            search_dce_rpc_raw_events
        )
    }

    async fn search_ftp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.ftp_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Ftp>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchFtpRawEvents,
            search_ftp_raw_events::Variables,
            search_ftp_raw_events::ResponseData,
            search_ftp_raw_events
        )
    }

    async fn search_mqtt_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.mqtt_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Mqtt>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchMqttRawEvents,
            search_mqtt_raw_events::Variables,
            search_mqtt_raw_events::ResponseData,
            search_mqtt_raw_events
        )
    }

    async fn search_ldap_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.ldap_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Ldap>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchLdapRawEvents,
            search_ldap_raw_events::Variables,
            search_ldap_raw_events::ResponseData,
            search_ldap_raw_events
        )
    }

    async fn search_tls_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.tls_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Tls>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchTlsRawEvents,
            search_tls_raw_events::Variables,
            search_tls_raw_events::ResponseData,
            search_tls_raw_events
        )
    }

    async fn search_smb_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;

            let store = db.smb_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Smb>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchSmbRawEvents,
            search_smb_raw_events::Variables,
            search_smb_raw_events::ResponseData,
            search_smb_raw_events
        )
    }

    async fn search_nfs_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.nfs_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Nfs>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchNfsRawEvents,
            search_nfs_raw_events::Variables,
            search_nfs_raw_events::ResponseData,
            search_nfs_raw_events
        )
    }

    async fn search_bootp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.bootp_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Bootp>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchBootpRawEvents,
            search_bootp_raw_events::Variables,
            search_bootp_raw_events::ResponseData,
            search_bootp_raw_events
        )
    }

    async fn search_dhcp_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.dhcp_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Dhcp>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchDhcpRawEvents,
            search_dhcp_raw_events::Variables,
            search_dhcp_raw_events::ResponseData,
            search_dhcp_raw_events
        )
    }

    async fn search_radius_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<GigantoTimestamp>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.radius_store()?;
            let times: Vec<Timestamp> = filter.times.iter().map(|t| t.0).collect();
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &times)
                .into_iter()
                .collect::<BTreeSet<(Timestamp, Vec<u8>)>>();

            Ok(collect_exist_times::<Radius>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchRadiusRawEvents,
            search_radius_raw_events::Variables,
            search_radius_raw_events::ResponseData,
            search_radius_raw_events
        )
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn network_connection(
    mut conn_iter: Peekable<FilteredIter<Conn>>,
    mut dns_iter: Peekable<FilteredIter<Dns>>,
    mut malformed_dns_iter: Peekable<FilteredIter<MalformedDns>>,
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
    mut smb_iter: Peekable<FilteredIter<Smb>>,
    mut nfs_iter: Peekable<FilteredIter<Nfs>>,
    mut smtp_iter: Peekable<FilteredIter<Smtp>>,
    mut bootp_iter: Peekable<FilteredIter<Bootp>>,
    mut dhcp_iter: Peekable<FilteredIter<Dhcp>>,
    mut radius_iter: Peekable<FilteredIter<Radius>>,
    size: usize,
    is_forward: bool,
) -> Result<Connection<String, NetworkRawEvents>> {
    let time = min_max_time(is_forward);
    let mut result_vec: Vec<Edge<String, NetworkRawEvents, _>> = Vec::new();
    let mut has_previous_page: bool = false;
    let mut has_next_page: bool = false;
    let mut has_next_value: bool = false;

    let mut conn_data = conn_iter.next();
    let mut dns_data = dns_iter.next();
    let mut malformed_dns_data = malformed_dns_iter.next();
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
    let mut bootp_data = bootp_iter.next();
    let mut dhcp_data = dhcp_iter.next();
    let mut radius_data = radius_iter.next();

    loop {
        let conn_ts = if let Some((ref key, _)) = conn_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let dns_ts = if let Some((ref key, _)) = dns_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let malformed_dns_ts = if let Some((ref key, _)) = malformed_dns_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let http_ts = if let Some((ref key, _)) = http_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let rdp_ts = if let Some((ref key, _)) = rdp_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let ntlm_ts = if let Some((ref key, _)) = ntlm_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let kerberos_ts = if let Some((ref key, _)) = kerberos_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let ssh_ts = if let Some((ref key, _)) = ssh_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let dce_rpc_ts = if let Some((ref key, _)) = dce_rpc_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let ftp_ts = if let Some((ref key, _)) = ftp_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let mqtt_ts = if let Some((ref key, _)) = mqtt_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let ldap_ts = if let Some((ref key, _)) = ldap_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let tls_ts = if let Some((ref key, _)) = tls_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let smb_ts = if let Some((ref key, _)) = smb_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let nfs_ts = if let Some((ref key, _)) = nfs_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let smtp_ts = if let Some((ref key, _)) = smtp_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let bootp_ts = if let Some((ref key, _)) = bootp_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let dhcp_ts = if let Some((ref key, _)) = dhcp_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let radius_ts = if let Some((ref key, _)) = radius_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let selected = if is_forward {
            time.min(dns_ts)
                .min(malformed_dns_ts)
                .min(conn_ts)
                .min(http_ts)
                .min(rdp_ts)
                .min(ntlm_ts)
                .min(kerberos_ts)
                .min(ssh_ts)
                .min(dce_rpc_ts)
                .min(ftp_ts)
                .min(mqtt_ts)
                .min(ldap_ts)
                .min(tls_ts)
                .min(smb_ts)
                .min(nfs_ts)
                .min(smtp_ts)
                .min(bootp_ts)
                .min(dhcp_ts)
                .min(radius_ts)
        } else {
            time.max(dns_ts)
                .max(malformed_dns_ts)
                .max(conn_ts)
                .max(http_ts)
                .max(rdp_ts)
                .max(ntlm_ts)
                .max(kerberos_ts)
                .max(ssh_ts)
                .max(dce_rpc_ts)
                .max(ftp_ts)
                .max(mqtt_ts)
                .max(ldap_ts)
                .max(tls_ts)
                .max(smb_ts)
                .max(nfs_ts)
                .max(smtp_ts)
                .max(bootp_ts)
                .max(dhcp_ts)
                .max(radius_ts)
        };

        match selected {
            _ if selected == conn_ts => {
                if let Some((key, value)) = conn_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::ConnRawEvent(ConnRawEvent::from_key_value(&key, value)?),
                    ));
                    conn_data = conn_iter.next();
                }
            }
            _ if selected == dns_ts => {
                if let Some((key, value)) = dns_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::DnsRawEvent(DnsRawEvent::from_key_value(&key, value)?),
                    ));
                    dns_data = dns_iter.next();
                }
            }
            _ if selected == malformed_dns_ts => {
                if let Some((key, value)) = malformed_dns_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::MalformedDnsRawEvent(
                            MalformedDnsRawEvent::from_key_value(&key, value)?,
                        ),
                    ));
                    malformed_dns_data = malformed_dns_iter.next();
                }
            }
            _ if selected == http_ts => {
                if let Some((key, value)) = http_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::HttpRawEvent(HttpRawEvent::from_key_value(&key, value)?),
                    ));
                    http_data = http_iter.next();
                }
            }
            _ if selected == rdp_ts => {
                if let Some((key, value)) = rdp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::RdpRawEvent(RdpRawEvent::from_key_value(&key, value)?),
                    ));
                    rdp_data = rdp_iter.next();
                }
            }
            _ if selected == ntlm_ts => {
                if let Some((key, value)) = ntlm_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::NtlmRawEvent(NtlmRawEvent::from_key_value(&key, value)?),
                    ));
                    ntlm_data = ntlm_iter.next();
                }
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
                }
            }
            _ if selected == ssh_ts => {
                if let Some((key, value)) = ssh_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::SshRawEvent(SshRawEvent::from_key_value(&key, value)?),
                    ));
                    ssh_data = ssh_iter.next();
                }
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
                }
            }
            _ if selected == ftp_ts => {
                if let Some((key, value)) = ftp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::FtpRawEvent(FtpRawEvent::from_key_value(&key, value)?),
                    ));
                    ftp_data = ftp_iter.next();
                }
            }
            _ if selected == mqtt_ts => {
                if let Some((key, value)) = mqtt_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::MqttRawEvent(MqttRawEvent::from_key_value(&key, value)?),
                    ));
                    mqtt_data = mqtt_iter.next();
                }
            }
            _ if selected == ldap_ts => {
                if let Some((key, value)) = ldap_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::LdapRawEvent(LdapRawEvent::from_key_value(&key, value)?),
                    ));
                    ldap_data = ldap_iter.next();
                }
            }
            _ if selected == tls_ts => {
                if let Some((key, value)) = tls_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::TlsRawEvent(TlsRawEvent::from_key_value(&key, value)?),
                    ));
                    tls_data = tls_iter.next();
                }
            }
            _ if selected == smb_ts => {
                if let Some((key, value)) = smb_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::SmbRawEvent(SmbRawEvent::from_key_value(&key, value)?),
                    ));
                    smb_data = smb_iter.next();
                }
            }
            _ if selected == nfs_ts => {
                if let Some((key, value)) = nfs_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::NfsRawEvent(NfsRawEvent::from_key_value(&key, value)?),
                    ));
                    nfs_data = nfs_iter.next();
                }
            }
            _ if selected == smtp_ts => {
                if let Some((key, value)) = smtp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::SmtpRawEvent(SmtpRawEvent::from_key_value(&key, value)?),
                    ));
                    smtp_data = smtp_iter.next();
                }
            }
            _ if selected == bootp_ts => {
                if let Some((key, value)) = bootp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::BootpRawEvent(BootpRawEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    bootp_data = bootp_iter.next();
                }
            }
            _ if selected == dhcp_ts => {
                if let Some((key, value)) = dhcp_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::DhcpRawEvent(DhcpRawEvent::from_key_value(&key, value)?),
                    ));
                    dhcp_data = dhcp_iter.next();
                }
            }
            _ if selected == radius_ts => {
                if let Some((key, value)) = radius_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        NetworkRawEvents::RadiusRawEvent(RadiusRawEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    radius_data = radius_iter.next();
                }
            }
            _ => {}
        }
        if (result_vec.len() >= size)
            || (conn_data.is_none()
                && dns_data.is_none()
                && malformed_dns_data.is_none()
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
                && smtp_data.is_none()
                && bootp_data.is_none()
                && dhcp_data.is_none()
                && radius_data.is_none())
        {
            if conn_data.is_some()
                || dns_data.is_some()
                || malformed_dns_data.is_some()
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
                || bootp_data.is_some()
                || dhcp_data.is_some()
                || radius_data.is_some()
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

#[cfg(feature = "cluster")]
impl_from_giganto_range_structs_for_graphql_client!(
    network_raw_events,
    conn_raw_events,
    dns_raw_events,
    malformed_dns_raw_events,
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
    bootp_raw_events,
    dhcp_raw_events,
    radius_raw_events,
    search_conn_raw_events,
    search_dce_rpc_raw_events,
    search_dns_raw_events,
    search_malformed_dns_raw_events,
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
    search_tls_raw_events,
    search_bootp_raw_events,
    search_dhcp_raw_events,
    search_radius_raw_events
);

#[cfg(feature = "cluster")]
impl_from_giganto_network_filter_for_graphql_client!(
    network_raw_events,
    conn_raw_events,
    dns_raw_events,
    malformed_dns_raw_events,
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
    bootp_raw_events,
    dhcp_raw_events,
    radius_raw_events
);

#[cfg(feature = "cluster")]
impl_from_giganto_search_filter_for_graphql_client!(
    search_conn_raw_events,
    search_dce_rpc_raw_events,
    search_dns_raw_events,
    search_malformed_dns_raw_events,
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
    search_tls_raw_events,
    search_bootp_raw_events,
    search_dhcp_raw_events,
    search_radius_raw_events
);
