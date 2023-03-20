use anyhow::{bail, Result};
use giganto_client::publish::{
    range::{RequestRange, RequestTimeSeriesRange},
    stream::{NodeType, RequestCrusherStream, RequestHogStream},
};
use std::net::IpAddr;

pub trait RequestStreamMessage {
    fn database_key(&self) -> Result<Vec<u8>>;
    fn channel_key(&self, source: Option<String>, record_type: &str) -> Result<String>;
    fn start_time(&self) -> i64;
    fn filter_ip(&self, orig_addr: IpAddr, resp_addr: IpAddr) -> bool;
    fn source_id(&self) -> Option<String>;
}

impl RequestStreamMessage for RequestHogStream {
    fn database_key(&self) -> Result<Vec<u8>> {
        if let Some(ref target_source) = self.source {
            let mut key_prefix: Vec<u8> = Vec::new();
            key_prefix.extend_from_slice(target_source.as_bytes());
            key_prefix.push(0);
            return Ok(key_prefix);
        }
        bail!("Failed to generate hog key, source is required.");
    }

    fn channel_key(&self, source: Option<String>, record_type: &str) -> Result<String> {
        if let Some(ref target_source) = self.source {
            let mut hog_key = String::new();
            hog_key.push_str(NodeType::Hog.convert_to_str());
            hog_key.push('\0');
            hog_key.push_str(&source.unwrap());
            hog_key.push('\0');
            hog_key.push_str(target_source);
            hog_key.push('\0');
            hog_key.push_str(record_type);
            return Ok(hog_key);
        }
        bail!("Failed to generate hog channel key, source is required.");
    }

    fn start_time(&self) -> i64 {
        self.start
    }

    fn filter_ip(&self, _orig_addr: IpAddr, _resp_addr: IpAddr) -> bool {
        true
    }

    fn source_id(&self) -> Option<String> {
        self.source.clone()
    }
}

impl RequestStreamMessage for RequestCrusherStream {
    fn database_key(&self) -> Result<Vec<u8>> {
        if let Some(ref target_source) = self.source {
            let mut key_prefix: Vec<u8> = Vec::new();
            key_prefix.extend_from_slice(target_source.as_bytes());
            key_prefix.push(0);
            return Ok(key_prefix);
        }
        bail!("Failed to generate crusher key, source is required.");
    }

    fn channel_key(&self, _source: Option<String>, record_type: &str) -> Result<String> {
        if let Some(ref target_source) = self.source {
            let mut crusher_key = String::new();
            crusher_key.push_str(NodeType::Crusher.convert_to_str());
            crusher_key.push('\0');
            crusher_key.push_str(&self.id);
            crusher_key.push('\0');
            crusher_key.push_str(target_source);
            crusher_key.push('\0');
            crusher_key.push_str(record_type);
            return Ok(crusher_key);
        }
        bail!("Failed to generate crusher channel key, source is required.");
    }

    fn start_time(&self) -> i64 {
        self.start
    }

    fn filter_ip(&self, orig_addr: IpAddr, resp_addr: IpAddr) -> bool {
        match (self.src_ip, self.dst_ip) {
            (Some(c_orig_addr), Some(c_resp_addr)) => {
                if c_orig_addr == orig_addr && c_resp_addr == resp_addr {
                    return true;
                }
            }
            (None, Some(c_resp_addr)) => {
                if c_resp_addr == resp_addr {
                    return true;
                }
            }
            (Some(c_orig_addr), None) => {
                if c_orig_addr == orig_addr {
                    return true;
                }
            }
            (None, None) => {
                return true;
            }
        }
        false
    }

    fn source_id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}

pub trait RequestRangeMessage {
    fn source(&self) -> &str;
    fn kind(&self) -> &str;
    fn start(&self) -> i64;
    fn end(&self) -> i64;
    fn count(&self) -> usize;
}

impl RequestRangeMessage for RequestRange {
    fn source(&self) -> &str {
        &self.source
    }
    fn kind(&self) -> &str {
        &self.kind
    }
    fn start(&self) -> i64 {
        self.start
    }
    fn end(&self) -> i64 {
        self.end
    }
    fn count(&self) -> usize {
        self.count
    }
}

impl RequestRangeMessage for RequestTimeSeriesRange {
    fn source(&self) -> &str {
        &self.source
    }
    fn kind(&self) -> &str {
        ""
    }
    fn start(&self) -> i64 {
        self.start
    }
    fn end(&self) -> i64 {
        self.end
    }
    fn count(&self) -> usize {
        self.count
    }
}
