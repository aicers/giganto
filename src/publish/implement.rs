use std::{net::IpAddr, vec};

use anyhow::{anyhow, bail, Result};
use giganto_client::publish::stream::{NodeType, RequestCrusherStream, RequestHogStream};

pub trait RequestStreamMessage {
    fn channel_key(&self, sensor: Option<String>, record_type: &str) -> Result<Vec<String>>;
    fn start_time(&self) -> i64;
    fn filter_ip(&self, orig_addr: IpAddr, resp_addr: IpAddr) -> bool;
    fn sensor(&self) -> Result<String>;
    fn id(&self) -> Option<String>;
}

impl RequestStreamMessage for RequestHogStream {
    fn channel_key(&self, sensor: Option<String>, record_type: &str) -> Result<Vec<String>> {
        let sensor = sensor.ok_or_else(|| {
            anyhow!("Failed to generate semi-supervised channel key, sensor is required.")
        })?;
        if let Some(ref sensor_list) = self.sensor {
            let hog_keys = sensor_list
                .iter()
                .map(|target_sensor| {
                    let mut key = String::new();
                    key.push_str(&NodeType::Hog.to_string());
                    key.push('\0');
                    key.push_str(&sensor);
                    key.push('\0');
                    key.push_str(target_sensor);
                    key.push('\0');
                    key.push_str(record_type);
                    key
                })
                .collect::<Vec<String>>();
            return Ok(hog_keys);
        }
        bail!("Failed to generate hog channel key, sensor is required.");
    }

    fn start_time(&self) -> i64 {
        self.start
    }

    fn filter_ip(&self, _orig_addr: IpAddr, _resp_addr: IpAddr) -> bool {
        true
    }

    // Hog don't use sensor function
    fn sensor(&self) -> Result<String> {
        unreachable!()
    }

    // Hog don't use id function
    fn id(&self) -> Option<String> {
        unreachable!()
    }
}

impl RequestStreamMessage for RequestCrusherStream {
    fn channel_key(&self, _sensor: Option<String>, record_type: &str) -> Result<Vec<String>> {
        if let Some(ref target_sensor) = self.sensor {
            let mut crusher_key = String::new();
            crusher_key.push_str(&NodeType::Crusher.to_string());
            crusher_key.push('\0');
            crusher_key.push_str(&self.id);
            crusher_key.push('\0');
            crusher_key.push_str(target_sensor);
            crusher_key.push('\0');
            crusher_key.push_str(record_type);
            return Ok(vec![crusher_key]);
        }
        bail!("Failed to generate crusher channel key, sensor is required.");
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

    fn sensor(&self) -> Result<String> {
        if let Some(ref sensor) = self.sensor {
            return Ok(sensor.clone());
        }
        bail!("Failed to generate crusher key, sensor is required.");
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}
