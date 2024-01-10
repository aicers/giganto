use anyhow::{bail, Result};
use giganto_client::publish::stream::{
    NodeType, RequestCrusherStream, RequestHogStream, RequestUrlCollectorStream,
};
use std::{net::IpAddr, vec};

pub trait RequestStreamMessage {
    fn channel_key(&self, source: Option<String>, record_type: &str) -> Result<Vec<String>>;
    fn start_time(&self) -> i64;
    fn filter_ip(&self, orig_addr: IpAddr, resp_addr: IpAddr) -> bool;
    fn source(&self) -> Result<String>;
    fn id(&self) -> Option<String>;
}

impl RequestStreamMessage for RequestHogStream {
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

    // Hog don't use source function
    fn source(&self) -> Result<String> {
        unreachable!()
    }

    // Hog don't use id function
    fn id(&self) -> Option<String> {
        unreachable!()
    }
}

impl RequestStreamMessage for RequestCrusherStream {
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

    fn source(&self) -> Result<String> {
        if let Some(ref source) = self.source {
            return Ok(source.clone());
        }
        bail!("Failed to generate crusher key, source is required.");
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}

impl RequestStreamMessage for RequestUrlCollectorStream {
    fn channel_key(&self, source: Option<String>, record_type: &str) -> Result<Vec<String>> {
        if let Some(ref target_source) = self.source {
            let mut url_collector_key = String::new();
            url_collector_key.push_str(NodeType::UrlCollector.convert_to_str());
            url_collector_key.push('\0');
            url_collector_key.push_str(source.as_ref().unwrap());
            url_collector_key.push('\0');
            url_collector_key.push_str(target_source);
            url_collector_key.push('\0');
            url_collector_key.push_str(record_type);
            return Ok(vec![url_collector_key]);
        }
        bail!("Failed to generate url collector channel key, source is required.");
    }
    fn start_time(&self) -> i64 {
        self.start
    }

    fn filter_ip(&self, _orig_addr: IpAddr, _resp_addr: IpAddr) -> bool {
        true
    }

    fn source(&self) -> Result<String> {
        if let Some(ref source) = self.source {
            return Ok(source.clone());
        }
        bail!("Failed to generate url collector key, source is required.");
    }

    // url collector don't use id function
    fn id(&self) -> Option<String> {
        unreachable!()
    }
}
