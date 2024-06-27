use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::storage::{
    Conn as ConnFromV21, Http as HttpFromV21, Ntlm as NtlmFromV21, Smtp as SmtpFromV21,
    Ssh as SshFromV21, Tls as TlsFromV21,
};

#[derive(Deserialize, Serialize)]
pub struct HttpBeforeV12 {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
    pub referrer: String,
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
pub struct ConnBeforeV21A1 {
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

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct ConnFromV21A1BeforeV21A2 {
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

impl From<HttpBeforeV12> for HttpFromV12BeforeV21 {
    fn from(input: HttpBeforeV12) -> Self {
        Self {
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            last_time: input.last_time,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referrer: input.referrer,
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
            orig_filenames: vec!["-".to_string()],
            orig_mime_types: vec!["-".to_string()],
            resp_filenames: vec!["-".to_string()],
            resp_mime_types: vec!["-".to_string()],
        }
    }
}

impl From<ConnBeforeV21A1> for ConnFromV21A1BeforeV21A2 {
    fn from(input: ConnBeforeV21A1) -> Self {
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
        }
    }
}

impl From<ConnFromV21A1BeforeV21A2> for ConnFromV21 {
    fn from(input: ConnFromV21A1BeforeV21A2) -> Self {
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

impl From<HttpFromV12BeforeV21> for HttpFromV21 {
    fn from(input: HttpFromV12BeforeV21) -> Self {
        Self {
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            last_time: input.last_time,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referrer: input.referrer,
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
            last_time: input.last_time,
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
            last_time: input.last_time,
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
            last_time: input.last_time,
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
            last_time: input.last_time,
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
