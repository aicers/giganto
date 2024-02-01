#[cfg(test)]
mod tests;

use super::{
    check_address, check_agent_id, check_port,
    netflow::{millis_to_secs, tcp_flags},
    statistics::MAX_CORE_SIZE,
    IpRange, NodeName, PortRange, RawEventFilter, TimeRange, TIMESTAMP_SIZE,
};
use crate::{
    graphql::{
        client::derives::{export as exports, Export as Exports},
        events_in_cluster, impl_from_giganto_range_structs_for_graphql_client,
    },
    ingest::implement::EventFilter,
    storage::{BoundaryIter, Database, Direction, KeyExtractor, RawEventStore, StorageKey},
};
use anyhow::anyhow;
use async_graphql::{Context, InputObject, Object, Result};
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use giganto_client::{
    ingest::{
        log::{Log, OpLog, SecuLog},
        netflow::{Netflow5, Netflow9},
        network::{
            Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Qclass, Qtype, Rdp, Smb,
            Smtp, Ssh, Tls,
        },
        statistics::Statistics,
        sysmon::{
            DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
            FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
            ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
        },
        timeseries::PeriodicTimeSeries,
    },
    RawEventKind,
};
use graphql_client::GraphQLQuery;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    borrow::Cow,
    fmt::Display,
    fs::{self, File},
    io::Write,
    iter::Peekable,
    net::IpAddr,
    path::{Path, PathBuf},
};
use tracing::{error, info};

const ADDRESS_PROTOCOL: [&str; 16] = [
    "conn",
    "dns",
    "http",
    "rdp",
    "smtp",
    "ntlm",
    "kerberos",
    "ssh",
    "dce rpc",
    "ftp",
    "mqtt",
    "ldap",
    "tls",
    "smb",
    "nfs",
    "network connect",
];
const AGENT_PROTOCOL: [&str; 14] = [
    "process create",
    "file create time",
    "process terminate",
    "image load",
    "file create",
    "network connect",
    "registry value set",
    "registry key rename",
    "file create stream hash",
    "pipe event",
    "dns query",
    "file delete",
    "process tamper",
    "file delete detected",
];
const KIND_PROTOCOL: [&str; 2] = ["log", "secu log"];

#[derive(Default)]
pub(super) struct ExportQuery;

#[derive(Serialize, Debug)]
struct ConnJsonOutput {
    timestamp: String,
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
#[derive(Serialize, Debug)]
struct DnsJsonOutput {
    timestamp: String,
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
    qclass: String,
    qtype: String,
    rcode: u16,
    aa_flag: bool,
    tc_flag: bool,
    rd_flag: bool,
    ra_flag: bool,
    ttl: Vec<String>,
}

#[derive(Serialize, Debug)]
struct HttpJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct RdpJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    cookie: String,
}

#[derive(Serialize, Debug)]
struct SmtpJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct NtlmJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct KerberosJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct SshJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct DceRpcJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct FtpJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct MqttJsonOutput {
    timestamp: String,
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
    suback_reason: Vec<String>,
}

#[derive(Serialize, Debug)]
struct LdapJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct TlsJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct SmbJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct NfsJsonOutput {
    timestamp: String,
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

#[derive(Serialize, Debug)]
struct LogJsonOutput {
    timestamp: String,
    source: String,
    kind: String,
    log: String,
}

#[derive(Serialize, Debug)]
struct TimeSeriesJsonOutput {
    start: String,
    id: String,
    data: Vec<f64>,
}

#[derive(Serialize, Debug)]
struct OpLogJsonOutput {
    timestamp: String,
    agent_id: String,
    level: String,
    contents: String,
}

#[derive(Serialize, Debug)]
struct SecuLogJsonOutput {
    timestamp: String,
    source: String,
    kind: String,
    orig_addr: String,
    orig_port: String,
    resp_addr: String,
    resp_port: String,
    proto: String,
    contents: String,
}

#[derive(Serialize, Debug)]
struct StatisticsJsonOutput {
    timestamp: String,
    source: String,
    core: u32,
    period: u16,
    stats: Vec<(RawEventKind, u64, u64)>,
}

#[derive(Serialize, Debug)]
struct ProcessCreateJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    file_version: String,
    description: String,
    product: String,
    company: String,
    original_file_name: String,
    command_line: String,
    current_directory: String,
    user: String,
    logon_guid: String,
    logon_id: u32,
    terminal_session_id: u32,
    integrity_level: String,
    hashes: Vec<String>,
    parent_process_guid: String,
    parent_process_id: u32,
    parent_image: String,
    parent_command_line: String,
    parent_user: String,
}

#[derive(Serialize, Debug)]
struct FileCreateTimeJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_filename: String,
    creation_utc_time: i64,
    previous_creation_utc_time: i64,
    user: String,
}

#[derive(Serialize, Debug)]
struct NetworkConnectJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    user: String,
    protocol: String,
    initiated: bool,
    source_is_ipv6: bool,
    source_ip: String,
    source_hostname: String,
    source_port: u16,
    source_port_name: String,
    destination_is_ipv6: bool,
    destination_ip: String,
    destination_hostname: String,
    destination_port: u16,
    destination_port_name: String,
}

#[derive(Serialize, Debug)]
struct ProcessTerminateJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    user: String,
}

#[derive(Serialize, Debug)]
struct ImageLoadJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    image_loaded: String,
    file_version: String,
    description: String,
    product: String,
    company: String,
    original_file_name: String,
    hashes: Vec<String>,
    signed: bool,
    signature: String,
    signature_status: String,
    user: String,
}

#[derive(Serialize, Debug)]
struct FileCreateJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_filename: String,
    creation_utc_time: i64,
    user: String,
}

#[derive(Serialize, Debug)]
struct RegistryValueSetJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_object: String,
    details: String,
    user: String,
}

#[derive(Serialize, Debug)]
struct RegistryKeyRenameJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_object: String,
    new_name: String,
    user: String,
}

#[derive(Serialize, Debug)]
struct FileCreateStreamHashJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_filename: String,
    creation_utc_time: i64,
    hash: Vec<String>,
    contents: String,
    user: String,
}

#[derive(Serialize, Debug)]
struct PipeEventJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: u32,
    pipe_name: String,
    image: String,
    user: String,
}

#[derive(Serialize, Debug)]
struct DnsQueryJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    query_name: String,
    query_status: u32,
    query_results: Vec<String>, // divided by ';'
    image: String,
    user: String,
}

#[derive(Serialize, Debug)]
struct FileDeleteJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    user: String,
    image: String,
    target_filename: String,
    hashes: Vec<String>,
    is_executable: bool,
    archived: bool,
}

#[derive(Serialize, Debug)]
struct ProcessTamperJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    tamper_type: String,
    user: String,
}

#[derive(Serialize, Debug)]
struct FileDeleteDetectedJsonOutput {
    timestamp: String,
    source: String,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    user: String,
    image: String,
    target_filename: String,
    hashes: Vec<String>,
    is_executable: bool,
}

#[derive(Serialize, Debug)]
pub struct Netflow5JsonOutput {
    timestamp: String,
    source: String,
    src_addr: String,
    dst_addr: String,
    next_hop: String,
    input: u16,
    output: u16,
    d_pkts: u32,
    d_octets: u32,
    first: String, // milliseconds
    last: String,  // milliseconds
    src_port: u16,
    dst_port: u16,
    tcp_flags: String,
    prot: u8,
    tos: String, // Hex
    src_as: u16,
    dst_as: u16,
    src_mask: u8,
    dst_mask: u8,
    sequence: u32,
    engine_type: u8,
    engine_id: u8,
    sampling_mode: String,
    sampling_rate: u16,
}

#[derive(Serialize, Debug)]
pub struct Netflow9JsonOutput {
    timestamp: String,
    source: String,
    sequence: u32,
    source_id: u32,
    template_id: u16,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    contents: String,
}

pub trait JsonOutput<T>: Sized {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<T>;
}

macro_rules! convert_json_output {
    ($to:ident, $from:ty, $($fields:ident),*) => {
        impl JsonOutput<$to> for $from {
            fn convert_json_output(&self, timestamp:String, source:String) -> Result<$to> {
                Ok($to {
                    timestamp,
                    source,
                    orig_addr: self.orig_addr.to_string(),
                    orig_port: self.orig_port,
                    resp_addr: self.resp_addr.to_string(),
                    resp_port: self.resp_port,
                    proto: self.proto,
                    last_time: self.last_time,
                    $(
                        $fields: self.$fields.clone(),
                    )*
                })
            }
        }
    };
}

convert_json_output!(
    HttpJsonOutput,
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

convert_json_output!(RdpJsonOutput, Rdp, cookie);

convert_json_output!(
    SmtpJsonOutput,
    Smtp,
    mailfrom,
    date,
    from,
    to,
    subject,
    agent
);

convert_json_output!(
    NtlmJsonOutput,
    Ntlm,
    username,
    hostname,
    domainname,
    server_nb_computer_name,
    server_dns_computer_name,
    server_tree_name,
    success
);

convert_json_output!(
    KerberosJsonOutput,
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

convert_json_output!(
    SshJsonOutput,
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

convert_json_output!(
    DceRpcJsonOutput,
    DceRpc,
    rtt,
    named_pipe,
    endpoint,
    operation
);

convert_json_output!(
    LdapJsonOutput,
    Ldap,
    message_id,
    version,
    opcode,
    result,
    diagnostic_message,
    object,
    argument
);

convert_json_output!(
    TlsJsonOutput,
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

convert_json_output!(
    SmbJsonOutput,
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

convert_json_output!(NfsJsonOutput, Nfs, read_files, write_files);

impl JsonOutput<ConnJsonOutput> for Conn {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<ConnJsonOutput> {
        Ok(ConnJsonOutput {
            timestamp,
            source,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            duration: self.duration,
            service: self.service.clone(),
            orig_bytes: self.orig_bytes,
            resp_bytes: self.resp_bytes,
            orig_pkts: self.orig_pkts,
            resp_pkts: self.resp_pkts,
        })
    }
}

impl JsonOutput<DnsJsonOutput> for Dns {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<DnsJsonOutput> {
        Ok(DnsJsonOutput {
            timestamp,
            source,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            last_time: self.last_time,
            query: self.query.clone(),
            answer: self.answer.clone(),
            trans_id: self.trans_id,
            rtt: self.rtt,
            qclass: Qclass::from(self.qclass).to_string(),
            qtype: Qtype::from(self.qtype).to_string(),
            rcode: self.rcode,
            aa_flag: self.aa_flag,
            tc_flag: self.tc_flag,
            rd_flag: self.rd_flag,
            ra_flag: self.ra_flag,
            ttl: to_vec_string(&self.ttl),
        })
    }
}

impl JsonOutput<LogJsonOutput> for Log {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<LogJsonOutput> {
        Ok(LogJsonOutput {
            timestamp,
            source,
            kind: self.kind.clone(),
            log: String::from_utf8_lossy(&self.log).to_string(),
        })
    }
}

impl JsonOutput<TimeSeriesJsonOutput> for PeriodicTimeSeries {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<TimeSeriesJsonOutput> {
        Ok(TimeSeriesJsonOutput {
            start: timestamp,
            id: source,
            data: self.data.clone(),
        })
    }
}

impl JsonOutput<OpLogJsonOutput> for OpLog {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<OpLogJsonOutput> {
        Ok(OpLogJsonOutput {
            timestamp,
            agent_id: source,
            level: self.log_level().unwrap_or_else(|| "-".to_string()),
            contents: self.contents.clone(),
        })
    }
}

impl JsonOutput<SecuLogJsonOutput> for SecuLog {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<SecuLogJsonOutput> {
        Ok(SecuLogJsonOutput {
            timestamp,
            source,
            kind: self.kind.clone(),
            orig_addr: to_string_or_empty(self.orig_addr),
            orig_port: to_string_or_empty(self.orig_port),
            resp_addr: to_string_or_empty(self.resp_addr),
            resp_port: to_string_or_empty(self.resp_port),
            proto: to_string_or_empty(self.proto),
            contents: self.contents.clone(),
        })
    }
}

impl JsonOutput<FtpJsonOutput> for Ftp {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<FtpJsonOutput> {
        Ok(FtpJsonOutput {
            timestamp,
            source,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            last_time: self.last_time,
            user: self.user.clone(),
            password: self.password.clone(),
            command: self.command.clone(),
            reply_code: self.reply_code.clone(),
            reply_msg: self.reply_msg.clone(),
            data_passive: self.data_passive,
            data_orig_addr: self.data_orig_addr.to_string(),
            data_resp_addr: self.data_resp_addr.to_string(),
            data_resp_port: self.data_resp_port,
            file: self.file.clone(),
            file_size: self.file_size,
            file_id: self.file_id.clone(),
        })
    }
}

impl JsonOutput<MqttJsonOutput> for Mqtt {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<MqttJsonOutput> {
        Ok(MqttJsonOutput {
            timestamp,
            source,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            last_time: self.last_time,
            protocol: self.protocol.clone(),
            version: self.version,
            client_id: self.client_id.clone(),
            connack_reason: self.connack_reason,
            subscribe: self.subscribe.clone(),
            suback_reason: to_vec_string(&self.suback_reason),
        })
    }
}

impl JsonOutput<StatisticsJsonOutput> for Statistics {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<StatisticsJsonOutput> {
        Ok(StatisticsJsonOutput {
            timestamp,
            source,
            core: self.core,
            period: self.period,
            stats: self.stats.clone(),
        })
    }
}

impl JsonOutput<ProcessCreateJsonOutput> for ProcessCreate {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<ProcessCreateJsonOutput> {
        Ok(ProcessCreateJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            file_version: self.file_version.clone(),
            description: self.description.clone(),
            product: self.product.clone(),
            company: self.company.clone(),
            original_file_name: self.original_file_name.clone(),
            command_line: self.command_line.clone(),
            current_directory: self.current_directory.clone(),
            user: self.user.clone(),
            logon_guid: self.logon_guid.clone(),
            logon_id: self.logon_id,
            terminal_session_id: self.terminal_session_id,
            integrity_level: self.integrity_level.clone(),
            hashes: self.hashes.clone(),
            parent_process_guid: self.parent_process_guid.clone(),
            parent_process_id: self.parent_process_id,
            parent_image: self.parent_image.clone(),
            parent_command_line: self.parent_command_line.clone(),
            parent_user: self.user.clone(),
        })
    }
}

impl JsonOutput<FileCreateTimeJsonOutput> for FileCreationTimeChanged {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<FileCreateTimeJsonOutput> {
        Ok(FileCreateTimeJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            target_filename: self.target_filename.clone(),
            creation_utc_time: self.creation_utc_time,
            previous_creation_utc_time: self.previous_creation_utc_time,
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<NetworkConnectJsonOutput> for NetworkConnection {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<NetworkConnectJsonOutput> {
        Ok(NetworkConnectJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            user: self.user.clone(),
            protocol: self.protocol.clone(),
            initiated: self.initiated,
            source_is_ipv6: self.source_is_ipv6,
            source_ip: self.source_ip.to_string(),
            source_hostname: self.source_hostname.clone(),
            source_port: self.source_port,
            source_port_name: self.source_port_name.clone(),
            destination_is_ipv6: self.destination_is_ipv6,
            destination_ip: self.destination_ip.to_string(),
            destination_hostname: self.destination_hostname.clone(),
            destination_port: self.destination_port,
            destination_port_name: self.destination_port_name.clone(),
        })
    }
}

impl JsonOutput<ProcessTerminateJsonOutput> for ProcessTerminated {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<ProcessTerminateJsonOutput> {
        Ok(ProcessTerminateJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<ImageLoadJsonOutput> for ImageLoaded {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<ImageLoadJsonOutput> {
        Ok(ImageLoadJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            image_loaded: self.image_loaded.clone(),
            file_version: self.file_version.clone(),
            description: self.description.clone(),
            product: self.product.clone(),
            company: self.company.clone(),
            original_file_name: self.original_file_name.clone(),
            hashes: self.hashes.clone(),
            signed: self.signed,
            signature: self.signature.clone(),
            signature_status: self.signature_status.clone(),
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<FileCreateJsonOutput> for FileCreate {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<FileCreateJsonOutput> {
        Ok(FileCreateJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            target_filename: self.target_filename.clone(),
            creation_utc_time: self.creation_utc_time,
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<RegistryValueSetJsonOutput> for RegistryValueSet {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<RegistryValueSetJsonOutput> {
        Ok(RegistryValueSetJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            event_type: self.event_type.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            target_object: self.target_object.clone(),
            details: self.details.clone(),
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<RegistryKeyRenameJsonOutput> for RegistryKeyValueRename {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<RegistryKeyRenameJsonOutput> {
        Ok(RegistryKeyRenameJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            event_type: self.event_type.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            target_object: self.target_object.clone(),
            new_name: self.new_name.clone(),
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<FileCreateStreamHashJsonOutput> for FileCreateStreamHash {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<FileCreateStreamHashJsonOutput> {
        Ok(FileCreateStreamHashJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            target_filename: self.target_filename.clone(),
            creation_utc_time: self.creation_utc_time,
            hash: self.hash.clone(),
            contents: self.contents.clone(),
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<PipeEventJsonOutput> for PipeEvent {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<PipeEventJsonOutput> {
        Ok(PipeEventJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            event_type: self.event_type.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            pipe_name: self.pipe_name.clone(),
            image: self.image.clone(),
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<DnsQueryJsonOutput> for DnsEvent {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<DnsQueryJsonOutput> {
        Ok(DnsQueryJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            query_name: self.query_name.clone(),
            query_status: self.query_status,
            query_results: self.query_results.clone(),
            image: self.image.clone(),
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<FileDeleteJsonOutput> for FileDelete {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<FileDeleteJsonOutput> {
        Ok(FileDeleteJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            user: self.user.clone(),
            image: self.image.clone(),
            target_filename: self.target_filename.clone(),
            hashes: self.hashes.clone(),
            is_executable: self.is_executable,
            archived: self.archived,
        })
    }
}

impl JsonOutput<ProcessTamperJsonOutput> for ProcessTampering {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<ProcessTamperJsonOutput> {
        Ok(ProcessTamperJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            image: self.image.clone(),
            tamper_type: self.tamper_type.clone(),
            user: self.user.clone(),
        })
    }
}

impl JsonOutput<FileDeleteDetectedJsonOutput> for FileDeleteDetected {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<FileDeleteDetectedJsonOutput> {
        Ok(FileDeleteDetectedJsonOutput {
            timestamp,
            source,
            agent_name: self.agent_name.clone(),
            agent_id: self.agent_id.clone(),
            process_guid: self.process_guid.clone(),
            process_id: self.process_id,
            user: self.user.clone(),
            image: self.image.clone(),
            target_filename: self.target_filename.clone(),
            hashes: self.hashes.clone(),
            is_executable: self.is_executable,
        })
    }
}

impl JsonOutput<Netflow5JsonOutput> for Netflow5 {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<Netflow5JsonOutput> {
        Ok(Netflow5JsonOutput {
            timestamp,
            source,
            src_addr: self.src_addr.to_string(),
            dst_addr: self.dst_addr.to_string(),
            next_hop: self.next_hop.to_string(),
            input: self.input,
            output: self.output,
            d_pkts: self.d_pkts,
            d_octets: self.d_octets,
            first: millis_to_secs(self.first),
            last: millis_to_secs(self.last), // milliseconds
            src_port: self.src_port,
            dst_port: self.dst_port,
            tcp_flags: tcp_flags(self.tcp_flags),
            prot: self.prot,
            tos: format!("{:x}", self.tos),
            src_as: self.src_as,
            dst_as: self.dst_as,
            src_mask: self.src_mask,
            dst_mask: self.dst_mask,
            sequence: self.sequence,
            engine_type: self.engine_type,
            engine_id: self.engine_id,
            sampling_mode: format!("{:x}", self.sampling_mode),
            sampling_rate: self.sampling_rate,
        })
    }
}

impl JsonOutput<Netflow9JsonOutput> for Netflow9 {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<Netflow9JsonOutput> {
        Ok(Netflow9JsonOutput {
            timestamp,
            source,
            sequence: self.sequence,
            source_id: self.source_id,
            template_id: self.template_id,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            contents: self.contents.clone(),
        })
    }
}

fn to_string_or_empty<T: Display>(option: Option<T>) -> String {
    match option {
        Some(val) => val.to_string(),
        None => "-".to_string(),
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize, Clone)]
pub struct ExportFilter {
    protocol: String,
    source_id: String,
    agent_name: Option<String>,
    agent_id: Option<String>,
    kind: Option<String>,
    time: Option<TimeRange>,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
}

impl KeyExtractor for ExportFilter {
    fn get_start_key(&self) -> &str {
        &self.source_id
    }

    fn get_mid_key(&self) -> Option<Vec<u8>> {
        let mut mid_key = Vec::new();
        if let Some(kind) = &self.kind {
            mid_key.extend_from_slice(kind.as_bytes());
            return Some(mid_key);
        };
        if let Some(agent_name) = &self.agent_name {
            mid_key.extend_from_slice(agent_name.as_bytes());
            if let Some(agent_id) = &self.agent_id {
                mid_key.push(0);
                mid_key.extend_from_slice(agent_id.as_bytes());
            }
            return Some(mid_key);
        };
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

impl RawEventFilter for ExportFilter {
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

fn handle_export(ctx: &Context<'_>, filter: &ExportFilter, export_type: String) -> Result<String> {
    let db = ctx.data::<Database>()?;
    let path = ctx.data::<PathBuf>()?;
    let node_name = ctx.data::<NodeName>()?;

    // set export file path
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    let filename = format!(
        "{}_{}.{export_type}",
        filter.protocol,
        Local::now().format("%Y%m%d_%H%M%S"),
    );
    let export_path = path.join(filename.replace(' ', ""));
    let download_path = format!("{}@{}", export_path.display(), node_name.0);

    export_by_protocol(db.clone(), filter, export_type, export_path)?;

    Ok(download_path)
}

#[Object]
impl ExportQuery {
    async fn export(
        &self,
        ctx: &Context<'_>,
        export_type: String,
        filter: ExportFilter,
    ) -> Result<String> {
        if !ADDRESS_PROTOCOL.contains(&filter.protocol.as_str()) {
            // check sysmon type/log type/time_series/statistics filter format
            if filter.orig_addr.is_some()
                || filter.resp_addr.is_some()
                || filter.orig_port.is_some()
                || filter.resp_port.is_some()
            {
                return Err(anyhow!("Invalid ip/port input").into());
            }
        }
        if !AGENT_PROTOCOL.contains(&filter.protocol.as_str()) {
            // check network/log type/time_series/netflow/statistics filter format
            if filter.agent_name.is_some() || filter.agent_id.is_some() {
                return Err(anyhow!("Invalid kind/agent_name/agent_id input").into());
            }
        }
        if !KIND_PROTOCOL.contains(&filter.protocol.as_str()) {
            // check sysomon/network/time_series/netflow/statistics filter format
            if filter.kind.is_some() {
                return Err(anyhow!("Invalid kind/agent_name/agent_id input").into());
            }
        }

        // check export file type
        if !(export_type.eq("csv") || export_type.eq("json")) {
            return Err(anyhow!("Invalid export file format").into());
        }

        let handler = handle_export;

        events_in_cluster!(
            ctx,
            filter,
            filter.source_id,
            handler,
            Exports,
            exports::Variables,
            exports::ResponseData,
            export,
            String,
            with_extra_handler_args (export_type),
            with_extra_query_args (export_type := export_type)
        )
    }
}

#[allow(clippy::too_many_lines)]
fn export_by_protocol(
    db: Database,
    filter: &ExportFilter,
    export_type: String,
    export_path: PathBuf,
) -> Result<()> {
    let filter = filter.clone();
    match filter.protocol.as_str() {
        "conn" => tokio::spawn(async move {
            if let Ok(store) = db.conn_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "dns" => tokio::spawn(async move {
            if let Ok(store) = db.dns_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "http" => tokio::spawn(async move {
            if let Ok(store) = db.http_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "log" => tokio::spawn(async move {
            if let Ok(store) = db.log_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "rdp" => tokio::spawn(async move {
            if let Ok(store) = db.rdp_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "smtp" => tokio::spawn(async move {
            if let Ok(store) = db.smtp_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "periodic time series" => tokio::spawn(async move {
            if let Ok(store) = db.periodic_time_series_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "ntlm" => tokio::spawn(async move {
            if let Ok(store) = db.ntlm_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "kerberos" => tokio::spawn(async move {
            if let Ok(store) = db.kerberos_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "ssh" => tokio::spawn(async move {
            if let Ok(store) = db.ssh_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "dce rpc" => tokio::spawn(async move {
            if let Ok(store) = db.dce_rpc_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "op_log" => tokio::spawn(async move {
            if let Ok(store) = db.op_log_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "ftp" => tokio::spawn(async move {
            if let Ok(store) = db.ftp_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "mqtt" => tokio::spawn(async move {
            if let Ok(store) = db.mqtt_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "ldap" => tokio::spawn(async move {
            if let Ok(store) = db.ldap_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "tls" => tokio::spawn(async move {
            if let Ok(store) = db.tls_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "smb" => tokio::spawn(async move {
            if let Ok(store) = db.smb_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "nfs" => tokio::spawn(async move {
            if let Ok(store) = db.nfs_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "statistics" => tokio::spawn(async move {
            if let Ok(store) = db.statistics_store() {
                match process_statistics_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "process create" => tokio::spawn(async move {
            if let Ok(store) = db.process_create_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "file create time" => tokio::spawn(async move {
            if let Ok(store) = db.file_create_time_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "network_connect" => tokio::spawn(async move {
            if let Ok(store) = db.network_connect_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "process terminate" => tokio::spawn(async move {
            if let Ok(store) = db.process_terminate_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "image load" => tokio::spawn(async move {
            if let Ok(store) = db.image_load_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "file create" => tokio::spawn(async move {
            if let Ok(store) = db.file_create_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "registry value set" => tokio::spawn(async move {
            if let Ok(store) = db.registry_value_set_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "registry key rename" => tokio::spawn(async move {
            if let Ok(store) = db.registry_key_rename_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "file create stream hash" => tokio::spawn(async move {
            if let Ok(store) = db.file_create_stream_hash_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "pipe event" => tokio::spawn(async move {
            if let Ok(store) = db.pipe_event_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "dns query" => tokio::spawn(async move {
            if let Ok(store) = db.dns_query_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "file delete" => tokio::spawn(async move {
            if let Ok(store) = db.file_delete_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "process tamper" => tokio::spawn(async move {
            if let Ok(store) = db.process_tamper_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "file delete detected" => tokio::spawn(async move {
            if let Ok(store) = db.file_delete_detected_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "netflow5" => tokio::spawn(async move {
            if let Ok(store) = db.netflow5_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "netflow9" => tokio::spawn(async move {
            if let Ok(store) = db.netflow9_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "secu log" => tokio::spawn(async move {
            if let Ok(store) = db.secu_log_store() {
                match process_export(&store, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        none => {
            return Err(anyhow!("{}: Unknown protocol", none).into());
        }
    };
    Ok(())
}

fn process_export<T, N>(
    store: &RawEventStore<'_, T>,
    filter: &(impl RawEventFilter + KeyExtractor),
    export_type: &str,
    export_path: &Path,
) -> Result<String>
where
    T: DeserializeOwned + Display + EventFilter + JsonOutput<N> + Send + Serialize,
    N: Serialize,
{
    // generate storage search key
    let key_builder = StorageKey::builder()
        .start_key(filter.get_start_key())
        .mid_key(filter.get_mid_key());
    let from_key = key_builder
        .clone()
        .lower_closed_bound_end_key(filter.get_range_end_key().0)
        .build();
    let to_key = key_builder
        .upper_open_bound_end_key(filter.get_range_end_key().1)
        .build();

    let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);
    export_file(iter, filter, export_type, export_path)
}

fn process_statistics_export(
    store: &RawEventStore<Statistics>,
    filter: &(impl RawEventFilter + KeyExtractor),
    export_type: &str,
    export_path: &Path,
) -> Result<String> {
    let mut iter_vec = Vec::new();
    for core in 0..MAX_CORE_SIZE {
        let key_builder = StorageKey::builder()
            .start_key(filter.get_start_key())
            .mid_key(Some(core.to_be_bytes().to_vec()));
        let from_key = key_builder
            .clone()
            .lower_closed_bound_end_key(filter.get_range_end_key().0)
            .build();
        let to_key = key_builder
            .upper_open_bound_end_key(filter.get_range_end_key().1)
            .build();
        let mut iter = store
            .boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward)
            .peekable();
        if iter.peek().is_some() {
            iter_vec.push(iter);
        }
    }
    export_statistic_file(iter_vec, filter, export_type, export_path)
}

fn export_file<I, T, N>(
    iter: I,
    filter: &(impl RawEventFilter + KeyExtractor),
    export_type: &str,
    path: &Path,
) -> Result<String>
where
    I: Iterator<Item = anyhow::Result<(Box<[u8]>, T)>> + Send,
    T: Display + EventFilter + JsonOutput<N> + Serialize,
    N: Serialize,
{
    // export file open
    let mut writer = File::create(path)?;
    let mut invalid_data_cnt: u32 = 0;

    // check filter condition & write file
    for item in iter {
        if item.is_err() {
            invalid_data_cnt += 1;
            continue;
        }
        let (key, value) = item.expect("not error value");
        write_filtered_data_to_file(filter, export_type, &key, &value, &mut writer)?;
    }
    if invalid_data_cnt > 1 {
        error!("failed to read database or invalid data #{invalid_data_cnt}");
    }
    Ok(format!("export file success: {path:?}"))
}

fn export_statistic_file(
    mut statistics_vec: Vec<Peekable<BoundaryIter<'_, Statistics>>>,
    filter: &(impl RawEventFilter + KeyExtractor),
    export_type: &str,
    path: &Path,
) -> Result<String> {
    let mut writer = File::create(path)?;

    // store the first value of all iters in a comparison vector.
    let mut iter_next_values = Vec::with_capacity(statistics_vec.len());
    let mut invalid_data_cnt: u32 = 0;
    for iter in &mut statistics_vec {
        loop {
            match iter.next() {
                Some(Ok(item)) => {
                    iter_next_values.push(item);
                    break;
                }
                Some(Err(_)) => {
                    // deserialize fail
                    invalid_data_cnt += 1;
                }
                None => {
                    // No value to call with the iterator.
                    break;
                }
            }
        }
    }

    loop {
        // select the value and index with the smallest timestamp.
        let (min_index, (key, value)) = iter_next_values.iter().enumerate().fold(
            (0, (&iter_next_values[0].0, &iter_next_values[0].1)),
            |(min_index, (min_key, min_value)), (index, (key, value))| {
                if key[(key.len() - TIMESTAMP_SIZE)..] < min_key[(min_key.len() - TIMESTAMP_SIZE)..]
                {
                    (index, (key, value))
                } else {
                    (min_index, (min_key, min_value))
                }
            },
        );

        write_filtered_data_to_file(filter, export_type, key, value, &mut writer)?;

        // change the value of the selected iter to the following value.
        if let Some(iter) = statistics_vec.get_mut(min_index) {
            loop {
                match iter.next() {
                    Some(Ok(item)) => {
                        // replace new value (min_index's vector value is always exist)
                        *iter_next_values.get_mut(min_index).unwrap() = item;
                        break;
                    }
                    Some(Err(_)) => {
                        // deserialize fail
                        invalid_data_cnt += 1;
                    }
                    None => {
                        // No value to call with the iterator.
                        let _ = statistics_vec.remove(min_index);
                        let _ = iter_next_values.remove(min_index);
                        break;
                    }
                }
            }
        }

        // if all iters have no value, end file writing.
        if iter_next_values.is_empty() {
            break;
        }
    }

    if invalid_data_cnt > 1 {
        error!("failed to read database or invalid data #{invalid_data_cnt}");
    }
    Ok(format!("export file success: {path:?}"))
}

fn write_filtered_data_to_file<T, N>(
    filter: &(impl RawEventFilter + KeyExtractor),
    export_type: &str,
    key: &[u8],
    value: &T,
    writer: &mut File,
) -> Result<()>
where
    T: Display + EventFilter + JsonOutput<N> + Serialize,
    N: Serialize,
{
    match filter.check(
        value.orig_addr(),
        value.resp_addr(),
        value.orig_port(),
        value.resp_port(),
        value.log_level(),
        value.log_contents(),
        value.text(),
        value.source(),
        value.agent_id(),
    ) {
        Ok(true) => {
            let (source, timestamp) = parse_key(key)?;
            let timestamp = {
                let secs = timestamp / 1_000_000_000;
                let nanosecs = u32::try_from(timestamp % 1_000_000_000).expect("< 1_000_000_000");
                NaiveDateTime::from_timestamp_opt(secs, nanosecs)
                    .map_or("-".to_string(), |s| s.format("%s%.9f").to_string())
            };
            match export_type {
                "csv" => {
                    writeln!(writer, "{timestamp}\t{source}\t{value}")?;
                }
                "json" => {
                    let json_data = value.convert_json_output(timestamp, source.to_string())?;
                    let json_data = serde_json::to_string(&json_data)?;
                    writeln!(writer, "{json_data}")?;
                }
                _ => {}
            }
        }
        Ok(false) | Err(_) => {}
    }
    Ok(())
}

fn parse_key(key: &[u8]) -> anyhow::Result<(Cow<str>, i64)> {
    if let Some(pos) = key.iter().position(|x| *x == 0) {
        if let Some(s) = key.get(..pos) {
            let source = String::from_utf8_lossy(s);
            if let Some(t) = key.get(key.len() - 8..) {
                let timestamp = i64::from_be_bytes(t.try_into()?);
                return Ok((source, timestamp));
            };
        }
    }
    Err(anyhow!("Invalid key"))
}

fn to_vec_string<T>(vec: &[T]) -> Vec<String>
where
    T: Display,
{
    if vec.is_empty() {
        vec!["-".to_string()]
    } else {
        vec.iter().map(ToString::to_string).collect::<Vec<_>>()
    }
}

macro_rules! impl_from_giganto_export_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<ExportFilter> for $autogen_mod::ExportFilter {
                fn from(filter: ExportFilter) -> Self {
                    Self {
                        protocol: filter.protocol,
                        source_id: filter.source_id,
                        agent_name: filter.agent_name,
                        agent_id: filter.agent_id,
                        kind: filter.kind,
                        time: filter.time.map(Into::into),
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                    }
                }
            }
        )*
    };
}

impl_from_giganto_range_structs_for_graphql_client!(exports);
impl_from_giganto_export_filter_for_graphql_client!(exports);
