use crate::ingestion::EventFilter;
use crate::publish::PubMessage;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Conn {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
}

impl EventFilter for Conn {
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
}

impl PubMessage for Conn {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>> {
        let conn_csv = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            Conn::convert_time_format(timestamp),
            source,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            Conn::convert_time_format(self.duration),
            self.orig_bytes,
            self.resp_bytes,
            self.orig_pkts,
            self.resp_pkts
        );

        Ok(bincode::serialize(&Some((
            timestamp,
            &conn_csv.as_bytes(),
        )))?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Dns {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub proto: u8,
    pub query: String,
    pub answer: Vec<String>,
}

impl EventFilter for Dns {
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
}

impl PubMessage for Dns {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>> {
        let answer = if self.answer.is_empty() {
            "-".to_string()
        } else {
            self.answer
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };

        let dns_csv = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            Dns::convert_time_format(timestamp),
            source,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            self.query,
            answer,
        );

        Ok(bincode::serialize(&Some((timestamp, &dns_csv.as_bytes())))?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Http {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
    pub user_agent: String,
    pub status_code: u16,
}

impl EventFilter for Http {
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
}

impl PubMessage for Http {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>> {
        let http_csv = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            Http::convert_time_format(timestamp),
            source,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
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
            if self.user_agent.is_empty() {
                "-"
            } else {
                &self.user_agent
            },
            self.status_code
        );

        Ok(bincode::serialize(&Some((
            timestamp,
            &http_csv.as_bytes(),
        )))?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rdp {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub cookie: String,
}

impl EventFilter for Rdp {
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
}

impl PubMessage for Rdp {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>> {
        let rdp_csv = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            Rdp::convert_time_format(timestamp),
            source,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.cookie
        );

        Ok(bincode::serialize(&Some((timestamp, &rdp_csv.as_bytes())))?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Smtp {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
}

impl EventFilter for Smtp {
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
}

impl PubMessage for Smtp {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>> {
        let smtp_csv = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            Smtp::convert_time_format(timestamp),
            source,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
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
        );

        Ok(bincode::serialize(&Some((
            timestamp,
            &smtp_csv.as_bytes(),
        )))?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ntlm {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub server_nb_computer_name: String,
    pub server_dns_computer_name: String,
    pub server_tree_name: String,
    pub success: String,
}

impl EventFilter for Ntlm {
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
}

impl PubMessage for Ntlm {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>> {
        let ntlm_csv = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            Ntlm::convert_time_format(timestamp),
            source,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
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
        );

        Ok(bincode::serialize(&Some((
            timestamp,
            &ntlm_csv.as_bytes(),
        )))?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Kerberos {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
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

impl EventFilter for Kerberos {
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
}

impl PubMessage for Kerberos {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>> {
        let kerberos_csv = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            Kerberos::convert_time_format(timestamp),
            source,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
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
        );

        Ok(bincode::serialize(&Some((
            timestamp,
            &kerberos_csv.as_bytes(),
        )))?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ssh {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
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

impl EventFilter for Ssh {
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
}

impl PubMessage for Ssh {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>> {
        let ssh_csv = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            Ssh::convert_time_format(timestamp),
            source,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
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
        );

        Ok(bincode::serialize(&Some((timestamp, &ssh_csv.as_bytes())))?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DceRpc {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
}

impl EventFilter for DceRpc {
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
}

impl PubMessage for DceRpc {
    fn message(&self, timestamp: i64, source: &str) -> Result<Vec<u8>> {
        let dce_rpc_csv = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            DceRpc::convert_time_format(timestamp),
            source,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
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
        );

        Ok(bincode::serialize(&Some((
            timestamp,
            &dce_rpc_csv.as_bytes(),
        )))?)
    }
}
