use crate::publish::range::ResponseRangeData;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub kind: String,
    pub log: Vec<u8>,
}

impl Display for Log {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}\t{}", self.kind, String::from_utf8_lossy(&self.log))
    }
}

impl ResponseRangeData for Log {
    fn response_data(&self, timestamp: i64, _source: &str) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(&Some((timestamp, &self.log)))
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

impl Display for Oplog {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{:?}\t{}",
            self.agent_name, self.log_level, self.contents
        )
    }
}
