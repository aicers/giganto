use anyhow::{bail, Result};
use giganto_client::publish::stream::{NodeType, RequestCrusherStream, RequestHogStream};
use std::{net::IpAddr, vec};

pub trait RequestStreamMessage {
    fn database_key(&self) -> Result<Vec<u8>>;
    fn channel_key(&self, source: Option<String>, record_type: &str) -> Result<Vec<String>>;
    fn start_time(&self) -> i64;
    fn filter_ip(&self, orig_addr: IpAddr, resp_addr: IpAddr) -> bool;
    fn source_id(&self) -> Option<String>;
}

impl RequestStreamMessage for RequestHogStream {
    // Hog don't use DB key
    fn database_key(&self) -> Result<Vec<u8>> {
        unreachable!()
    }

    fn channel_key(&self, source: Option<String>, record_type: &str) -> Result<Vec<String>> {
        if let Some(ref source_list) = self.source {
            let hog_keys = source_list
                .iter()
                .map(|target_source| {
                    let mut key = String::new();
                    key.push_str(NodeType::Hog.convert_to_str());
                    key.push('\0');
                    key.push_str(source.as_ref().unwrap());
                    key.push('\0');
                    key.push_str(target_source);
                    key.push('\0');
                    key.push_str(record_type);
                    key
                })
                .collect::<Vec<String>>();
            return Ok(hog_keys);
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
        None
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

    fn channel_key(&self, _source: Option<String>, record_type: &str) -> Result<Vec<String>> {
        if let Some(ref target_source) = self.source {
            let mut crusher_key = String::new();
            crusher_key.push_str(NodeType::Crusher.convert_to_str());
            crusher_key.push('\0');
            crusher_key.push_str(&self.id);
            crusher_key.push('\0');
            crusher_key.push_str(target_source);
            crusher_key.push('\0');
            crusher_key.push_str(record_type);
            return Ok(vec![crusher_key]);
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
