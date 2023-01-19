use anyhow::Result;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

pub trait ResponseRangeData {
    /// # Errors
    ///
    /// Will return `Err` if response data's serialize faild.
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error>;

    /// # Errors
    ///
    /// Will return `Err` if serialize faild.
    fn response_done() -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize::<Option<(i64, Vec<u8>)>>(&None)
    }
}

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u32)]
pub enum MessageCode {
    Log = 0,
    PeriodicTimeSeries = 1,
    Pcap = 2,
}

pub enum REconvergeKindType {
    Conn,
    Dns,
    Rdp,
    Http,
    Log,
    Smtp,
    Ntlm,
    Kerberos,
    Ssh,
    DceRpc,
}

impl REconvergeKindType {
    #[must_use]
    pub fn convert_type(input: &str) -> REconvergeKindType {
        match input {
            "conn" => REconvergeKindType::Conn,
            "dns" => REconvergeKindType::Dns,
            "rdp" => REconvergeKindType::Rdp,
            "http" => REconvergeKindType::Http,
            "smtp" => REconvergeKindType::Smtp,
            "ntlm" => REconvergeKindType::Ntlm,
            "kerberos" => REconvergeKindType::Kerberos,
            "ssh" => REconvergeKindType::Ssh,
            "dce rpc" => REconvergeKindType::DceRpc,
            _ => REconvergeKindType::Log,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestRange {
    pub source: String, //certification name
    pub kind: String,
    pub start: i64,
    pub end: i64,
    pub count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestTimeSeriesRange {
    pub source: String, //sampling policy id
    pub start: i64,
    pub end: i64,
    pub count: usize,
}
