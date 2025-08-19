use std::net::IpAddr;

use giganto_client::ingest::log::OpLogLevel;
use serde::{Deserialize, Serialize};

use crate::{
    comm::ingest::implement::EventFilter,
    storage::{
        Http as HttpFromV21, Netflow5 as Netflow5FromV23, Netflow9 as Netflow9FromV23,
        Ntlm as NtlmFromV21, OpLog as OpLogFromV24, SecuLog as SecuLogFromV23, Smtp as SmtpFromV21,
        Ssh as SshFromV21, Tls as TlsFromV21,
    },
};
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct HttpFromV21BeforeV27 {
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

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct HttpFromV12BeforeV21 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
}

#[derive(Deserialize, Serialize)]
pub struct ConnBeforeV21 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
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
pub struct SmtpBeforeV21 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
}

#[derive(Deserialize, Serialize)]
pub struct NtlmBeforeV21 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub server_nb_computer_name: String,
    pub server_dns_computer_name: String,
    pub server_tree_name: String,
    pub success: String,
}

#[derive(Deserialize, Serialize)]
pub struct SshBeforeV21 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub version: i64,
    pub auth_success: String,
    pub auth_attempts: i64,
    pub direction: String,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub host_key: String,
}

#[derive(Deserialize, Serialize)]
pub struct TlsBeforeV21 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub cipher: u16,
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

impl From<ConnBeforeV21> for ConnFromV21BeforeV26 {
    fn from(input: ConnBeforeV21) -> Self {
        Self {
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            conn_state: String::new(),
            duration: input.duration,
            service: input.service,
            orig_bytes: input.orig_bytes,
            resp_bytes: input.resp_bytes,
            orig_pkts: input.orig_pkts,
            resp_pkts: input.resp_pkts,
            resp_l2_bytes: 0,
            orig_l2_bytes: 0,
        }
    }
}

impl From<HttpFromV21BeforeV27> for HttpFromV21 {
    fn from(input: HttpFromV21BeforeV27) -> Self {
        let mut filenames = input.orig_filenames;
        filenames.extend(input.resp_filenames);

        let mut mime_types = input.orig_mime_types;
        mime_types.extend(input.resp_mime_types);

        Self {
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            end_time: input.end_time,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referer: input.referer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            filenames,
            mime_types,
            body: input.post_body,
            state: input.state,
        }
    }
}

impl From<HttpFromV12BeforeV21> for HttpFromV21BeforeV27 {
    fn from(input: HttpFromV12BeforeV21) -> Self {
        Self {
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            end_time: input.last_time,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referer: input.referer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: input.orig_filenames,
            orig_mime_types: input.orig_mime_types,
            resp_filenames: input.resp_filenames,
            resp_mime_types: input.resp_mime_types,
            post_body: Vec::new(),
            state: String::new(),
        }
    }
}
impl From<SmtpBeforeV21> for SmtpFromV21 {
    fn from(input: SmtpBeforeV21) -> Self {
        Self {
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            end_time: input.last_time,
            mailfrom: input.mailfrom,
            date: input.date,
            from: input.from,
            to: input.to,
            subject: input.subject,
            agent: input.agent,
            state: String::new(),
        }
    }
}
impl From<NtlmBeforeV21> for NtlmFromV21 {
    fn from(input: NtlmBeforeV21) -> Self {
        Self {
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            end_time: input.last_time,
            protocol: String::new(),
            username: input.username,
            hostname: input.hostname,
            domainname: input.domainname,
            success: input.success,
        }
    }
}
impl From<SshBeforeV21> for SshFromV21 {
    fn from(input: SshBeforeV21) -> Self {
        Self {
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            end_time: input.last_time,
            client: input.client,
            server: input.server,
            cipher_alg: input.cipher_alg,
            mac_alg: input.mac_alg,
            compression_alg: input.compression_alg,
            kex_alg: input.kex_alg,
            host_key_alg: input.host_key_alg,
            hassh_algorithms: String::new(),
            hassh: String::new(),
            hassh_server_algorithms: String::new(),
            hassh_server: String::new(),
            client_shka: String::new(),
            server_shka: String::new(),
        }
    }
}

impl From<TlsBeforeV21> for TlsFromV21 {
    fn from(input: TlsBeforeV21) -> Self {
        Self {
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            end_time: input.last_time,
            server_name: input.server_name,
            alpn_protocol: input.alpn_protocol,
            ja3: input.ja3,
            version: input.version,
            client_cipher_suites: Vec::new(),
            client_extensions: Vec::new(),
            cipher: input.cipher,
            extensions: Vec::new(),
            ja3s: input.ja3s,
            serial: input.serial,
            subject_country: input.subject_country,
            subject_org_name: input.subject_org_name,
            subject_common_name: input.subject_common_name,
            validity_not_before: input.validity_not_before,
            validity_not_after: input.validity_not_after,
            subject_alt_name: input.subject_alt_name,
            issuer_country: input.issuer_country,
            issuer_org_name: input.issuer_org_name,
            issuer_org_unit_name: input.issuer_org_unit_name,
            issuer_common_name: input.issuer_common_name,
            last_alert: input.last_alert,
        }
    }
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
