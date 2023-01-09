use crate::ingest::EventFilter;
use crate::publish::PubMessage;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub kind: String,
    pub log: Vec<u8>,
}

impl EventFilter for Log {
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

impl Display for Log {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}\t{}", self.kind, String::from_utf8_lossy(&self.log))
    }
}

impl PubMessage for Log {
    fn message(&self, timestamp: i64, _source: &str) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&Some((timestamp, &self.log)))?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Oplog {
    pub agent_name: String,
    pub log_level: OpLogLevel,
    pub contents: String,
    // Category, id
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OpLogLevel {
    Info,
    Warn,
    Error,
}

impl EventFilter for Oplog {
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

impl Display for Oplog {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{:?}\t{}",
            self.agent_name, self.log_level, self.contents
        )
    }
}
