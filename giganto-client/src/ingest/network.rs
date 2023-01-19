use crate::{convert_time_format, publish::range::ResponseRangeData};
use anyhow::Result;
use num_enum::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Conn {
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

impl Display for Conn {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.duration),
            self.service,
            self.orig_bytes,
            self.resp_bytes,
            self.orig_pkts,
            self.resp_pkts
        )
    }
}

impl ResponseRangeData for Conn {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let conn_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, &conn_csv.as_bytes())))
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Dns {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
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

#[derive(Debug, FromPrimitive)]
#[repr(u16)]
pub enum Qclass {
    CInternet = 1,
    #[num_enum(default)]
    Unknown,
}

impl Display for Qclass {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CInternet => write!(f, "C_INTERNET"),
            Self::Unknown => write!(f, "{self:?}"),
        }
    }
}

#[derive(Debug, FromPrimitive)]
#[repr(u16)]
pub enum Qtype {
    A = 1,
    Ns,
    Md,
    Mf,
    Cname,
    Soa,
    Mb,
    Mg,
    Mr,
    Null,
    Wks,
    Ptr,
    Hinfo,
    Minfo,
    Mx,
    Txt,
    Rp,
    Afsdb,
    X25,
    Isdn,
    Rt,
    Nsap,
    NsapPtr,
    Sig,
    Key,
    Px,
    Gpos,
    Aaaa,
    Loc,
    Nxt,
    Eid,
    Nimloc,
    Srv,
    Atma,
    Naptr,
    Kx,
    Cert,
    A6,
    Dname,
    Sink,
    Opt,
    Apl,
    Ds,
    Sshfp,
    Ipseckey,
    Rrsig,
    Nsec,
    Dnskey,
    Dhcid,
    Nsec3,
    Nsec3param,
    Tlsa,
    Smimea,
    Hip = 55,
    Ninfo,
    Rkey,
    Talink,
    Cds,
    Cdnskey,
    Openpgpkey,
    Csync,
    Zonemd,
    Svcb,
    Https,
    Spf = 99,
    #[num_enum(default)]
    Unknown,
}

impl Display for Qtype {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let upper = match self {
            Self::NsapPtr => "NSAP-PTR".to_string(),
            _ => format!("{self:?}").to_uppercase(),
        };
        write!(f, "{upper}")
    }
}

impl Display for Dns {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let answer = if self.answer.is_empty() {
            "-".to_string()
        } else {
            self.answer
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        let ttl = if self.ttl.is_empty() {
            "-".to_string()
        } else {
            self.ttl
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };

        let qclass = Qclass::from(self.qclass).to_string();
        let qtype = Qtype::from(self.qtype).to_string();

        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.duration),
            self.query,
            answer,
            self.trans_id,
            self.rtt,
            qclass,
            qtype,
            self.rcode,
            self.aa_flag,
            self.tc_flag,
            self.rd_flag,
            self.ra_flag,
            ttl,
        )
    }
}

impl ResponseRangeData for Dns {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let dns_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, &dns_csv.as_bytes())))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Http {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
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

impl Display for Http {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.duration),
            if self.method.is_empty() {
                "-"
            } else {
                &self.method
            },
            if self.host.is_empty() {
                "-"
            } else {
                &self.host
            },
            if self.uri.is_empty() { "-" } else { &self.uri },
            if self.referrer.is_empty() {
                "-"
            } else {
                &self.referrer
            },
            if self.version.is_empty() {
                "-"
            } else {
                &self.version
            },
            if self.user_agent.is_empty() {
                "-"
            } else {
                &self.user_agent
            },
            self.request_len,
            self.response_len,
            self.status_code,
            if self.status_msg.is_empty() {
                "-"
            } else {
                &self.status_msg
            },
            if self.username.is_empty() {
                "-"
            } else {
                &self.username
            },
            if self.password.is_empty() {
                "-"
            } else {
                &self.password
            },
            if self.cookie.is_empty() {
                "-"
            } else {
                &self.cookie
            },
            if self.content_encoding.is_empty() {
                "-"
            } else {
                &self.content_encoding
            },
            if self.content_type.is_empty() {
                "-"
            } else {
                &self.content_type
            },
            if self.cache_control.is_empty() {
                "-"
            } else {
                &self.cache_control
            },
        )
    }
}

impl ResponseRangeData for Http {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let http_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, &http_csv.as_bytes())))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rdp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub cookie: String,
}

impl Display for Rdp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.duration),
            self.cookie
        )
    }
}

impl ResponseRangeData for Rdp {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let rdp_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, &rdp_csv.as_bytes())))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Smtp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
}

impl Display for Smtp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.duration),
            if self.mailfrom.is_empty() {
                "-"
            } else {
                &self.mailfrom
            },
            if self.date.is_empty() {
                "-"
            } else {
                &self.date
            },
            if self.from.is_empty() {
                "-"
            } else {
                &self.from
            },
            if self.to.is_empty() { "-" } else { &self.to },
            if self.subject.is_empty() {
                "-"
            } else {
                &self.subject
            },
            if self.agent.is_empty() {
                "-"
            } else {
                &self.agent
            },
        )
    }
}

impl ResponseRangeData for Smtp {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let smtp_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, &smtp_csv.as_bytes())))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ntlm {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub server_nb_computer_name: String,
    pub server_dns_computer_name: String,
    pub server_tree_name: String,
    pub success: String,
}

impl Display for Ntlm {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.duration),
            if self.username.is_empty() {
                "-"
            } else {
                &self.username
            },
            if self.hostname.is_empty() {
                "-"
            } else {
                &self.hostname
            },
            if self.domainname.is_empty() {
                "-"
            } else {
                &self.domainname
            },
            if self.server_nb_computer_name.is_empty() {
                "-"
            } else {
                &self.server_nb_computer_name
            },
            if self.server_dns_computer_name.is_empty() {
                "-"
            } else {
                &self.server_dns_computer_name
            },
            if self.server_tree_name.is_empty() {
                "-"
            } else {
                &self.server_tree_name
            },
            if self.success.is_empty() {
                "-"
            } else {
                &self.success
            },
        )
    }
}

impl ResponseRangeData for Ntlm {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let ntlm_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, &ntlm_csv.as_bytes())))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Kerberos {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub request_type: String,
    pub client: String,
    pub service: String,
    pub success: String,
    pub error_msg: String,
    pub from: i64,
    pub till: i64,
    pub cipher: String,
    pub forwardable: String,
    pub renewable: String,
    pub client_cert_subject: String,
    pub server_cert_subject: String,
}

impl Display for Kerberos {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.duration),
            if self.request_type.is_empty() {
                "-"
            } else {
                &self.request_type
            },
            if self.client.is_empty() {
                "-"
            } else {
                &self.client
            },
            if self.service.is_empty() {
                "-"
            } else {
                &self.service
            },
            if self.success.is_empty() {
                "-"
            } else {
                &self.success
            },
            if self.error_msg.is_empty() {
                "-"
            } else {
                &self.error_msg
            },
            self.from,
            self.till,
            if self.cipher.is_empty() {
                "-"
            } else {
                &self.cipher
            },
            if self.forwardable.is_empty() {
                "-"
            } else {
                &self.forwardable
            },
            if self.renewable.is_empty() {
                "-"
            } else {
                &self.renewable
            },
            if self.client_cert_subject.is_empty() {
                "-"
            } else {
                &self.client_cert_subject
            },
            if self.server_cert_subject.is_empty() {
                "-"
            } else {
                &self.server_cert_subject
            },
        )
    }
}

impl ResponseRangeData for Kerberos {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let kerberos_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, &kerberos_csv.as_bytes())))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ssh {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
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

impl Display for Ssh {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.duration),
            self.version,
            if self.auth_success.is_empty() {
                "-"
            } else {
                &self.auth_success
            },
            self.auth_attempts,
            if self.direction.is_empty() {
                "-"
            } else {
                &self.direction
            },
            if self.client.is_empty() {
                "-"
            } else {
                &self.client
            },
            if self.server.is_empty() {
                "-"
            } else {
                &self.server
            },
            if self.cipher_alg.is_empty() {
                "-"
            } else {
                &self.cipher_alg
            },
            if self.mac_alg.is_empty() {
                "-"
            } else {
                &self.mac_alg
            },
            if self.compression_alg.is_empty() {
                "-"
            } else {
                &self.compression_alg
            },
            if self.kex_alg.is_empty() {
                "-"
            } else {
                &self.kex_alg
            },
            if self.host_key_alg.is_empty() {
                "-"
            } else {
                &self.host_key_alg
            },
            if self.host_key.is_empty() {
                "-"
            } else {
                &self.host_key
            },
        )
    }
}

impl ResponseRangeData for Ssh {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let ssh_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, &ssh_csv.as_bytes())))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DceRpc {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
}

impl Display for DceRpc {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.duration),
            self.rtt,
            if self.named_pipe.is_empty() {
                "-"
            } else {
                &self.named_pipe
            },
            if self.endpoint.is_empty() {
                "-"
            } else {
                &self.endpoint
            },
            if self.operation.is_empty() {
                "-"
            } else {
                &self.operation
            },
        )
    }
}

impl ResponseRangeData for DceRpc {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let dce_rpc_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, &dce_rpc_csv.as_bytes())))
    }
}
