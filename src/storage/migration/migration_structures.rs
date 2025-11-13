use std::net::IpAddr;

use giganto_client::ingest::{log::OpLogLevel, network::FtpCommand};
use serde::{Deserialize, Serialize};

use crate::{
    comm::ingest::implement::EventFilter,
    storage::{
        Bootp as BootpFromV26, DceRpc as DceRpcFromV26, Dhcp as DhcpFromV26, Dns as DnsFromV26,
        Ftp as FtpFromV26, Kerberos as KerberosFromV26, Ldap as LdapFromV26, Mqtt as MqttFromV26,
        Netflow5 as Netflow5FromV23, Netflow9 as Netflow9FromV23, Nfs as NfsFromV26,
        Ntlm as NtlmFromV26, OpLog as OpLogFromV24, Rdp as RdpFromV26, SecuLog as SecuLogFromV23,
        Smb as SmbFromV26, Smtp as SmtpFromV26, Ssh as SshFromV26, Tls as TlsFromV26,
    },
};
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct HttpFromV21BeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub struct ConnFromV21BeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
}

#[derive(Deserialize, Serialize)]
pub struct Netflow5BeforeV23 {
    pub source: String,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub next_hop: IpAddr,
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub first: u32, // milliseconds
    pub last: u32,  // milliseconds
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8, // Hex
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_mode: u8,
    pub sampling_rate: u16,
}

impl EventFilter for Netflow5BeforeV23 {
    fn data_type(&self) -> String {
        "netflow v5".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        Some(self.src_addr)
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        Some(self.dst_addr)
    }
    fn orig_port(&self) -> Option<u16> {
        Some(self.src_port)
    }
    fn resp_port(&self) -> Option<u16> {
        Some(self.dst_port)
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn sensor(&self) -> Option<String> {
        Some(self.source.clone())
    }
}

impl From<Netflow5BeforeV23> for Netflow5FromV23 {
    fn from(input: Netflow5BeforeV23) -> Self {
        Self {
            src_addr: input.src_addr,
            dst_addr: input.dst_addr,
            next_hop: input.next_hop,
            input: input.input,
            output: input.output,
            d_pkts: input.d_pkts,
            d_octets: input.d_octets,
            first: input.first,
            last: input.last,
            src_port: input.src_port,
            dst_port: input.dst_port,
            tcp_flags: input.tcp_flags,
            prot: input.prot,
            tos: input.tos,
            src_as: input.src_as,
            dst_as: input.dst_as,
            src_mask: input.src_mask,
            dst_mask: input.dst_mask,
            sequence: input.sequence,
            engine_type: input.engine_type,
            engine_id: input.engine_id,
            sampling_mode: input.sampling_mode,
            sampling_rate: input.sampling_rate,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Netflow9BeforeV23 {
    pub source: String,
    pub sequence: u32,
    pub source_id: u32,
    pub template_id: u16,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub contents: String,
}

impl EventFilter for Netflow9BeforeV23 {
    fn data_type(&self) -> String {
        "netflow v9".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        Some(self.orig_addr)
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        Some(self.resp_addr)
    }
    fn orig_port(&self) -> Option<u16> {
        Some(self.orig_port)
    }
    fn resp_port(&self) -> Option<u16> {
        Some(self.resp_port)
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        Some(self.contents.clone())
    }
    fn sensor(&self) -> Option<String> {
        Some(self.source.clone())
    }
}

impl From<Netflow9BeforeV23> for Netflow9FromV23 {
    fn from(input: Netflow9BeforeV23) -> Self {
        Self {
            sequence: input.sequence,
            source_id: input.source_id,
            template_id: input.template_id,
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            contents: input.contents,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct SecuLogBeforeV23 {
    pub source: String,
    pub kind: String,
    pub log_type: String,
    pub version: String,
    pub orig_addr: Option<IpAddr>,
    pub orig_port: Option<u16>,
    pub resp_addr: Option<IpAddr>,
    pub resp_port: Option<u16>,
    pub proto: Option<u8>,
    pub contents: String,
}

impl EventFilter for SecuLogBeforeV23 {
    fn data_type(&self) -> String {
        "security log".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        self.orig_addr
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        self.resp_addr
    }
    fn orig_port(&self) -> Option<u16> {
        self.orig_port
    }
    fn resp_port(&self) -> Option<u16> {
        self.resp_port
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        Some(self.contents.clone())
    }
    fn sensor(&self) -> Option<String> {
        Some(self.source.clone())
    }
}

impl From<SecuLogBeforeV23> for SecuLogFromV23 {
    fn from(input: SecuLogBeforeV23) -> Self {
        Self {
            kind: input.kind,
            log_type: input.log_type,
            version: input.version,
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            contents: input.contents,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct OpLogBeforeV24 {
    pub agent_name: String,
    pub log_level: OpLogLevel,
    pub contents: String,
}

impl From<OpLogBeforeV24> for OpLogFromV24 {
    fn from(input: OpLogBeforeV24) -> Self {
        Self {
            sensor: String::new(),
            agent_name: input.agent_name,
            log_level: input.log_level,
            contents: input.contents,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RdpBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub cookie: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SmtpBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NtlmBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KerberosBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SshBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DceRpcBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FtpBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub user: String,
    pub password: String,
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MqttBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LdapBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlsBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SmbBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub command: u8,
    pub path: String,
    pub service: String,
    pub file_name: String,
    pub file_size: u64,
    pub resource_type: u16,
    pub fid: u16,
    pub create_time: i64,
    pub access_time: i64,
    pub write_time: i64,
    pub change_time: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NfsBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BootpBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub op: u8,
    pub htype: u8,
    pub hops: u8,
    pub xid: u32,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub chaddr: Vec<u8>,
    pub sname: String,
    pub file: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DhcpBeforeV26 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub msg_type: u8,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub subnet_mask: IpAddr,
    pub router: Vec<IpAddr>,
    pub domain_name_server: Vec<IpAddr>,
    pub req_ip_addr: IpAddr,
    pub lease_time: u32,
    pub server_id: IpAddr,
    pub param_req_list: Vec<u8>,
    pub message: String,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub class_id: Vec<u8>,
    pub client_id_type: u8,
    pub client_id: Vec<u8>,
}

pub trait MigrationNew<OldT> {
    fn new(old_data: OldT, start_time: i64) -> Self;
}

impl MigrationNew<DnsBeforeV26> for DnsFromV26 {
    fn new(old_data: DnsBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: old_data.query,
            answer: old_data.answer,
            trans_id: old_data.trans_id,
            rtt: old_data.rtt,
            qclass: old_data.qclass,
            qtype: old_data.qtype,
            rcode: old_data.rcode,
            aa_flag: old_data.aa_flag,
            tc_flag: old_data.tc_flag,
            rd_flag: old_data.rd_flag,
            ra_flag: old_data.ra_flag,
            ttl: old_data.ttl,
        }
    }
}

impl MigrationNew<RdpBeforeV26> for RdpFromV26 {
    fn new(old_data: RdpBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            cookie: old_data.cookie,
        }
    }
}

impl MigrationNew<SmtpBeforeV26> for SmtpFromV26 {
    fn new(old_data: SmtpBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            mailfrom: old_data.mailfrom,
            date: old_data.date,
            from: old_data.from,
            to: old_data.to,
            subject: old_data.subject,
            agent: old_data.agent,
            state: old_data.state,
        }
    }
}

impl MigrationNew<NtlmBeforeV26> for NtlmFromV26 {
    fn new(old_data: NtlmBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            protocol: old_data.protocol,
            username: old_data.username,
            hostname: old_data.hostname,
            domainname: old_data.domainname,
            success: old_data.success,
        }
    }
}

impl MigrationNew<KerberosBeforeV26> for KerberosFromV26 {
    fn new(old_data: KerberosBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            client_time: old_data.client_time,
            server_time: old_data.server_time,
            error_code: old_data.error_code,
            client_realm: old_data.client_realm,
            cname_type: old_data.cname_type,
            client_name: old_data.client_name,
            realm: old_data.realm,
            sname_type: old_data.sname_type,
            service_name: old_data.service_name,
        }
    }
}

impl MigrationNew<SshBeforeV26> for SshFromV26 {
    fn new(old_data: SshBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            client: old_data.client,
            server: old_data.server,
            cipher_alg: old_data.cipher_alg,
            mac_alg: old_data.mac_alg,
            compression_alg: old_data.compression_alg,
            kex_alg: old_data.kex_alg,
            host_key_alg: old_data.host_key_alg,
            hassh_algorithms: old_data.hassh_algorithms,
            hassh: old_data.hassh,
            hassh_server_algorithms: old_data.hassh_server_algorithms,
            hassh_server: old_data.hassh_server,
            client_shka: old_data.client_shka,
            server_shka: old_data.server_shka,
        }
    }
}

impl MigrationNew<DceRpcBeforeV26> for DceRpcFromV26 {
    fn new(old_data: DceRpcBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            rtt: old_data.rtt,
            named_pipe: old_data.named_pipe,
            endpoint: old_data.endpoint,
            operation: old_data.operation,
        }
    }
}

impl MigrationNew<FtpBeforeV26> for FtpFromV26 {
    fn new(old_data: FtpBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            user: old_data.user,
            password: old_data.password,
            commands: vec![FtpCommand {
                command: old_data.command,
                reply_code: old_data.reply_code,
                reply_msg: old_data.reply_msg,
                data_passive: old_data.data_passive,
                data_orig_addr: old_data.data_orig_addr,
                data_resp_addr: old_data.data_resp_addr,
                data_resp_port: old_data.data_resp_port,
                file: old_data.file,
                file_size: old_data.file_size,
                file_id: old_data.file_id,
            }],
        }
    }
}

impl MigrationNew<MqttBeforeV26> for MqttFromV26 {
    fn new(old_data: MqttBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            protocol: old_data.protocol,
            version: old_data.version,
            client_id: old_data.client_id,
            connack_reason: old_data.connack_reason,
            subscribe: old_data.subscribe,
            suback_reason: old_data.suback_reason,
        }
    }
}

impl MigrationNew<LdapBeforeV26> for LdapFromV26 {
    fn new(old_data: LdapBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            message_id: old_data.message_id,
            version: old_data.version,
            opcode: old_data.opcode,
            result: old_data.result,
            diagnostic_message: old_data.diagnostic_message,
            object: old_data.object,
            argument: old_data.argument,
        }
    }
}

impl MigrationNew<TlsBeforeV26> for TlsFromV26 {
    fn new(old_data: TlsBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            server_name: old_data.server_name,
            alpn_protocol: old_data.alpn_protocol,
            ja3: old_data.ja3,
            version: old_data.version,
            client_cipher_suites: old_data.client_cipher_suites,
            client_extensions: old_data.client_extensions,
            cipher: old_data.cipher,
            extensions: old_data.extensions,
            ja3s: old_data.ja3s,
            serial: old_data.serial,
            subject_country: old_data.subject_country,
            subject_org_name: old_data.subject_org_name,
            subject_common_name: old_data.subject_common_name,
            validity_not_before: old_data.validity_not_before,
            validity_not_after: old_data.validity_not_after,
            subject_alt_name: old_data.subject_alt_name,
            issuer_country: old_data.issuer_country,
            issuer_org_name: old_data.issuer_org_name,
            issuer_org_unit_name: old_data.issuer_org_unit_name,
            issuer_common_name: old_data.issuer_common_name,
            last_alert: old_data.last_alert,
        }
    }
}

impl MigrationNew<SmbBeforeV26> for SmbFromV26 {
    fn new(old_data: SmbBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            command: old_data.command,
            path: old_data.path,
            service: old_data.service,
            file_name: old_data.file_name,
            file_size: old_data.file_size,
            resource_type: old_data.resource_type,
            fid: old_data.fid,
            create_time: old_data.create_time,
            access_time: old_data.access_time,
            write_time: old_data.write_time,
            change_time: old_data.change_time,
        }
    }
}

impl MigrationNew<NfsBeforeV26> for NfsFromV26 {
    fn new(old_data: NfsBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            read_files: old_data.read_files,
            write_files: old_data.write_files,
        }
    }
}

impl MigrationNew<BootpBeforeV26> for BootpFromV26 {
    fn new(old_data: BootpBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            op: old_data.op,
            htype: old_data.htype,
            hops: old_data.hops,
            xid: old_data.xid,
            ciaddr: old_data.ciaddr,
            yiaddr: old_data.yiaddr,
            siaddr: old_data.siaddr,
            giaddr: old_data.giaddr,
            chaddr: old_data.chaddr,
            sname: old_data.sname,
            file: old_data.file,
        }
    }
}

impl MigrationNew<DhcpBeforeV26> for DhcpFromV26 {
    fn new(old_data: DhcpBeforeV26, start_time: i64) -> Self {
        Self {
            orig_addr: old_data.orig_addr,
            orig_port: old_data.orig_port,
            resp_addr: old_data.resp_addr,
            resp_port: old_data.resp_port,
            proto: old_data.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old_data.end_time),
            duration: old_data.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            msg_type: old_data.msg_type,
            ciaddr: old_data.ciaddr,
            yiaddr: old_data.yiaddr,
            siaddr: old_data.siaddr,
            giaddr: old_data.giaddr,
            subnet_mask: old_data.subnet_mask,
            router: old_data.router,
            domain_name_server: old_data.domain_name_server,
            req_ip_addr: old_data.req_ip_addr,
            lease_time: old_data.lease_time,
            server_id: old_data.server_id,
            param_req_list: old_data.param_req_list,
            message: old_data.message,
            renewal_time: old_data.renewal_time,
            rebinding_time: old_data.rebinding_time,
            class_id: old_data.class_id,
            client_id_type: old_data.client_id_type,
            client_id: old_data.client_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{TimeZone, Utc};

    use super::*;

    #[test]
    fn rdp_migration_sets_chrono_fields() {
        let start_time = 1_700_000_000_000_000_000_i64;
        let end_time = start_time + 2_000;

        let old = RdpBeforeV26 {
            orig_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1)),
            orig_port: 3389,
            resp_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            resp_port: 3389,
            proto: 6,
            end_time,
            cookie: "session-cookie".to_string(),
        };

        let migrated = RdpFromV26::new(old, start_time);

        assert_eq!(
            migrated.start_time.timestamp_nanos_opt().unwrap(),
            start_time
        );
        assert_eq!(migrated.end_time.timestamp_nanos_opt().unwrap(), end_time);
        assert_eq!(migrated.duration, end_time - start_time);
        assert_eq!(
            migrated.start_time,
            Utc.timestamp_nanos(start_time),
            "start_time should use chrono conversion"
        );
        assert_eq!(migrated.cookie, "session-cookie");
    }
}
