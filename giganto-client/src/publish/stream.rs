use anyhow::{anyhow, Result};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const STREAM_REQUEST_ALL_SOURCE: &str = "all";

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u8)]
pub enum NodeType {
    Hog = 0,
    Crusher = 1,
}

#[derive(Clone, Copy, Deserialize, Debug, Eq, TryFromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u32)]
pub enum RequestStreamRecord {
    Conn = 0,
    Dns = 1,
    Rdp = 2,
    Http = 3,
    Log = 4,
    Smtp = 5,
    Ntlm = 6,
    Kerberos = 7,
    Ssh = 8,
    DceRpc = 9,
}

impl RequestStreamRecord {
    #[must_use]
    pub fn convert_to_str(&self) -> &str {
        match self {
            RequestStreamRecord::Conn => "conn",
            RequestStreamRecord::Dns => "dns",
            RequestStreamRecord::Rdp => "rdp",
            RequestStreamRecord::Http => "http",
            RequestStreamRecord::Log => "log",
            RequestStreamRecord::Smtp => "smtp",
            RequestStreamRecord::Ntlm => "ntlm",
            RequestStreamRecord::Kerberos => "kerberos",
            RequestStreamRecord::Ssh => "ssh",
            RequestStreamRecord::DceRpc => "dce rpc",
        }
    }

    /// # Errors
    ///
    /// Will return `Err` if `input` does not match protocol string
    pub fn convert_type(input: &str) -> Result<RequestStreamRecord> {
        match input {
            "conn" => Ok(RequestStreamRecord::Conn),
            "dns" => Ok(RequestStreamRecord::Dns),
            "rdp" => Ok(RequestStreamRecord::Rdp),
            "http" => Ok(RequestStreamRecord::Http),
            "log" => Ok(RequestStreamRecord::Log),
            "smtp" => Ok(RequestStreamRecord::Smtp),
            "ntlm" => Ok(RequestStreamRecord::Ntlm),
            "kerberos" => Ok(RequestStreamRecord::Kerberos),
            "ssh" => Ok(RequestStreamRecord::Ssh),
            "dce rpc" => Ok(RequestStreamRecord::DceRpc),
            _ => Err(anyhow!("invalid protocol type")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestHogStream {
    pub start: i64,
    pub source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestCrusherStream {
    pub start: i64,
    pub id: String,
    pub src_ip: Option<IpAddr>,
    pub des_ip: Option<IpAddr>,
    pub source: Option<String>,
}
