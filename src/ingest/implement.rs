use std::net::IpAddr;

use giganto_client::ingest::{
    log::{Log, OpLog, OpLogLevel, SecuLog},
    netflow::{Netflow5, Netflow9},
    network::{
        Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp,
        Ssh, Tls,
    },
    statistics::Statistics,
    sysmon::{
        DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
        FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
        ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
    },
    timeseries::PeriodicTimeSeries,
    Packet,
};

pub trait EventFilter {
    fn data_type(&self) -> String;
    fn orig_addr(&self) -> Option<IpAddr>;
    fn resp_addr(&self) -> Option<IpAddr>;
    fn orig_port(&self) -> Option<u16>;
    fn resp_port(&self) -> Option<u16>;
    fn log_level(&self) -> Option<String>;
    fn log_contents(&self) -> Option<String>;
    fn text(&self) -> Option<String> {
        None
    }
    fn sensor(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        None
    }
}

impl EventFilter for Conn {
    fn data_type(&self) -> String {
        "conn".to_string()
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
        None
    }
}

impl EventFilter for Dns {
    fn data_type(&self) -> String {
        "dns".to_string()
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
        None
    }
}

impl EventFilter for Http {
    fn data_type(&self) -> String {
        "http".to_string()
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
        None
    }
    fn text(&self) -> Option<String> {
        Some(self.to_string())
    }
}

impl EventFilter for Rdp {
    fn data_type(&self) -> String {
        "rdp".to_string()
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
        None
    }
}

impl EventFilter for Smtp {
    fn data_type(&self) -> String {
        "smtp".to_string()
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
        None
    }
}

impl EventFilter for Ntlm {
    fn data_type(&self) -> String {
        "ntlm".to_string()
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
        None
    }
}

impl EventFilter for Kerberos {
    fn data_type(&self) -> String {
        "kerberos".to_string()
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
        None
    }
}

impl EventFilter for Ssh {
    fn data_type(&self) -> String {
        "ssh".to_string()
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
        None
    }
}

impl EventFilter for DceRpc {
    fn data_type(&self) -> String {
        "dce rpc".to_string()
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
        None
    }
}

impl EventFilter for Log {
    fn data_type(&self) -> String {
        "log".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
}

impl EventFilter for OpLog {
    fn data_type(&self) -> String {
        "oplog".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        match self.log_level {
            OpLogLevel::Info => Some("Info".to_string()),
            OpLogLevel::Warn => Some("Warn".to_string()),
            OpLogLevel::Error => Some("Error".to_string()),
        }
    }
    fn log_contents(&self) -> Option<String> {
        Some(self.contents.clone())
    }
}

impl EventFilter for PeriodicTimeSeries {
    fn data_type(&self) -> String {
        "periodic time series".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
}

impl EventFilter for Packet {
    fn data_type(&self) -> String {
        "packet".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
}

impl EventFilter for Ftp {
    fn data_type(&self) -> String {
        "ftp".to_string()
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
        None
    }
}

impl EventFilter for Mqtt {
    fn data_type(&self) -> String {
        "mqtt".to_string()
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
        None
    }
}

impl EventFilter for Ldap {
    fn data_type(&self) -> String {
        "ldap".to_string()
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
        None
    }
}

impl EventFilter for Tls {
    fn data_type(&self) -> String {
        "tls".to_string()
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
        None
    }
}

impl EventFilter for Smb {
    fn data_type(&self) -> String {
        "smb".to_string()
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
        None
    }
}

impl EventFilter for Nfs {
    fn data_type(&self) -> String {
        "nfs".to_string()
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
        None
    }
}

impl EventFilter for Bootp {
    fn data_type(&self) -> String {
        "bootp".to_string()
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
        None
    }
}

impl EventFilter for Dhcp {
    fn data_type(&self) -> String {
        "dhcp".to_string()
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
        None
    }
}

impl EventFilter for Statistics {
    fn data_type(&self) -> String {
        "statistics".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
}

impl EventFilter for ProcessCreate {
    fn data_type(&self) -> String {
        "process create".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for FileCreationTimeChanged {
    fn data_type(&self) -> String {
        "file creation time changed".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for NetworkConnection {
    fn data_type(&self) -> String {
        "network connection".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        Some(self.source_ip)
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        Some(self.destination_ip)
    }
    fn orig_port(&self) -> Option<u16> {
        Some(self.source_port)
    }
    fn resp_port(&self) -> Option<u16> {
        Some(self.destination_port)
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for ProcessTerminated {
    fn data_type(&self) -> String {
        "process terminated".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for ImageLoaded {
    fn data_type(&self) -> String {
        "image loaded".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for FileCreate {
    fn data_type(&self) -> String {
        "file create".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for RegistryValueSet {
    fn data_type(&self) -> String {
        "registry value set".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for RegistryKeyValueRename {
    fn data_type(&self) -> String {
        "registry key value rename".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for FileCreateStreamHash {
    fn data_type(&self) -> String {
        "file create stream hash".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for PipeEvent {
    fn data_type(&self) -> String {
        "pipe event".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for DnsEvent {
    fn data_type(&self) -> String {
        "dns event".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for FileDelete {
    fn data_type(&self) -> String {
        "file delete".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for ProcessTampering {
    fn data_type(&self) -> String {
        "process tampering".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for FileDeleteDetected {
    fn data_type(&self) -> String {
        "file delete detected".to_string()
    }
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
    fn agent_id(&self) -> Option<String> {
        Some(self.agent_id.clone())
    }
}

impl EventFilter for Netflow5 {
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
}

impl EventFilter for Netflow9 {
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
}

impl EventFilter for SecuLog {
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
}
