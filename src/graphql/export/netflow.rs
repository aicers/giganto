use super::JsonOutput;
use crate::graphql::{get_timestamp_from_key, FromKeyValue};
use async_graphql::{Result, SimpleObject};
use chrono::{DateTime, Utc};
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use serde::Serialize;

#[derive(Serialize, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow5JsonOutput {
    timestamp: String,
    source: String,
    srcaddr: String,
    dstaddr: String,
    nexthop: String,
    input: u16,
    output: u16,
    dpkts: u32,
    doctets: u32,
    first: String, // milliseconds
    last: String,  // milliseconds
    srcport: u16,
    dstport: u16,
    tcp_flags: String,
    prot: u8,
    tos: String, // Hex
    src_as: u16,
    dst_as: u16,
    src_mask: u8,
    dst_mask: u8,
    sequence: u32,
    engine_type: u8,
    engine_id: u8,
    sampling_mode: String,
    sampling_rate: u16,
}

impl JsonOutput<Netflow5JsonOutput> for Netflow5 {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<Netflow5JsonOutput> {
        Ok(Netflow5JsonOutput {
            timestamp,
            source,
            srcaddr: self.srcaddr.to_string(),
            dstaddr: self.dstaddr.to_string(),
            nexthop: self.nexthop.to_string(),
            input: self.input,
            output: self.output,
            dpkts: self.dpkts,
            doctets: self.doctets,
            first: milli_to_secs(self.first),
            last: milli_to_secs(self.last), // milliseconds
            srcport: self.srcport,
            dstport: self.dstport,
            tcp_flags: tcp_flags(self.tcp_flags),
            prot: self.prot,
            tos: format!("{:x}", self.tos),
            src_as: self.src_as,
            dst_as: self.dst_as,
            src_mask: self.src_mask,
            dst_mask: self.dst_mask,
            sequence: self.sequence,
            engine_type: self.engine_type,
            engine_id: self.engine_id,
            sampling_mode: format!("{:x}", self.sampling_mode),
            sampling_rate: self.sampling_rate,
        })
    }
}

#[derive(SimpleObject, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow5RawEvent {
    timestamp: DateTime<Utc>,
    srcaddr: String,
    dstaddr: String,
    nexthop: String,
    input: u16,
    output: u16,
    dpkts: u32,
    doctets: u32,
    first: String, // milliseconds
    last: String,  // milliseconds
    srcport: u16,
    dstport: u16,
    tcp_flags: String,
    prot: u8,
    tos: String, // Hex
    src_as: u16,
    dst_as: u16,
    src_mask: u8,
    dst_mask: u8,
    sequence: u32,
    engine_type: u8,
    engine_id: u8,
    sampling_mode: String,
    sampling_rate: u16,
}

impl FromKeyValue<Netflow5> for Netflow5RawEvent {
    fn from_key_value(key: &[u8], val: Netflow5) -> Result<Self> {
        Ok(Netflow5RawEvent {
            timestamp: get_timestamp_from_key(key)?,
            srcaddr: val.srcaddr.to_string(),
            dstaddr: val.dstaddr.to_string(),
            nexthop: val.nexthop.to_string(),
            input: val.input,
            output: val.output,
            dpkts: val.dpkts,
            doctets: val.doctets,
            first: milli_to_secs(val.first),
            last: milli_to_secs(val.last),
            srcport: val.srcport,
            dstport: val.dstport,
            tcp_flags: tcp_flags(val.tcp_flags),
            prot: val.prot,
            tos: format!("{:x}", val.tos),
            src_as: val.src_as,
            dst_as: val.dst_as,
            src_mask: val.src_mask,
            dst_mask: val.dst_mask,
            sequence: val.sequence,
            engine_type: val.engine_type,
            engine_id: val.engine_id,
            sampling_mode: format!("{:x}", val.sampling_mode),
            sampling_rate: val.sampling_rate,
        })
    }
}

#[derive(Serialize, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow9JsonOutput {
    timestamp: String,
    source: String,
    sequence: u32,
    source_id: u32,
    template_id: u16,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    contents: String,
}

impl JsonOutput<Netflow9JsonOutput> for Netflow9 {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<Netflow9JsonOutput> {
        Ok(Netflow9JsonOutput {
            timestamp,
            source,
            sequence: self.sequence,
            source_id: self.source_id,
            template_id: self.template_id,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            contents: self.contents.clone(),
        })
    }
}

#[derive(SimpleObject, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct NetflowV9RawEvent {
    timestamp: DateTime<Utc>,
    sequence: u32,
    source_id: u32,
    template_id: u16,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    contents: String,
}

impl FromKeyValue<Netflow9> for NetflowV9RawEvent {
    fn from_key_value(key: &[u8], val: Netflow9) -> Result<Self> {
        Ok(NetflowV9RawEvent {
            timestamp: get_timestamp_from_key(key)?,
            sequence: val.sequence,
            source_id: val.source_id,
            template_id: val.template_id,
            orig_addr: val.orig_addr.to_string(),
            orig_port: val.orig_port,
            resp_addr: val.resp_addr.to_string(),
            resp_port: val.resp_port,
            proto: val.proto,
            contents: val.contents,
        })
    }
}

fn milli_to_secs(millis: u32) -> String {
    format!("{}.{}", millis / 1000, millis - (millis / 1000) * 1000)
}

static TCP_FLAGS: [(u8, &str); 8] = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x08, "CWR"),
];

fn tcp_flags(b: u8) -> String {
    let mut res = String::new();
    for e in &TCP_FLAGS {
        if b & e.0 == e.0 {
            res.push_str(e.1);
            res.push('-');
        }
    }
    if res.is_empty() {
        res.push_str("None");
    }

    if res.ends_with('-') {
        res.pop();
    }
    res
}
