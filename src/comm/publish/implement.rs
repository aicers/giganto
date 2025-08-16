use std::{net::IpAddr, vec};

use anyhow::{Result, anyhow, bail};
use giganto_client::publish::stream::{
    RequestSemiSupervisedStream, RequestTimeSeriesGeneratorStream,
};

pub trait RequestStreamMessage {
    fn channel_key(&self, sensor: Option<String>, record_type: &str) -> Result<Vec<String>>;
    fn start_time(&self) -> i64;
    fn filter_ip(&self, orig_addr: IpAddr, resp_addr: IpAddr) -> bool;
    fn sensor(&self) -> Result<String>;
    fn id(&self) -> Option<String>;
    fn is_semi_supervised(&self) -> bool;
    fn is_time_series_generator(&self) -> bool;
}

impl RequestStreamMessage for RequestSemiSupervisedStream {
    fn channel_key(&self, sensor: Option<String>, record_type: &str) -> Result<Vec<String>> {
        let sensor = sensor.ok_or_else(|| {
            anyhow!("Failed to generate the Semi-supervised channel key, sensor is required.")
        })?;
        if let Some(ref sensor_list) = self.sensor {
            let semi_supervised_keys = sensor_list
                .iter()
                .map(|target_sensor| {
                    let mut key = String::new();
                    key.push_str("SemiSupervised");
                    key.push('\0');
                    key.push_str(&sensor);
                    key.push('\0');
                    key.push_str(target_sensor);
                    key.push('\0');
                    key.push_str(record_type);
                    key
                })
                .collect::<Vec<String>>();
            return Ok(semi_supervised_keys);
        }
        bail!("Failed to generate the Semi-supervised Engine channel key, sensor is required.");
    }

    fn start_time(&self) -> i64 {
        self.start
    }

    fn filter_ip(&self, _orig_addr: IpAddr, _resp_addr: IpAddr) -> bool {
        true
    }

    // The Semi-supervised Engine does't use sensor function
    fn sensor(&self) -> Result<String> {
        unreachable!()
    }

    // The Semi-supervised Engine does't use id function
    fn id(&self) -> Option<String> {
        unreachable!()
    }

    fn is_semi_supervised(&self) -> bool {
        true
    }

    fn is_time_series_generator(&self) -> bool {
        false
    }
}

impl RequestStreamMessage for RequestTimeSeriesGeneratorStream {
    fn channel_key(&self, _sensor: Option<String>, record_type: &str) -> Result<Vec<String>> {
        if let Some(ref target_sensor) = self.sensor {
            let mut time_series_generator_key = String::new();
            time_series_generator_key.push_str("TimeSeriesGenerator");
            time_series_generator_key.push('\0');
            time_series_generator_key.push_str(&self.id);
            time_series_generator_key.push('\0');
            time_series_generator_key.push_str(target_sensor);
            time_series_generator_key.push('\0');
            time_series_generator_key.push_str(record_type);
            return Ok(vec![time_series_generator_key]);
        }
        bail!("Failed to generate the Time Series Generator channel key, sensor is required.");
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
        bail!("Failed to generate the Time Series Generator key, sensor is required.");
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }

    fn is_semi_supervised(&self) -> bool {
        false
    }

    fn is_time_series_generator(&self) -> bool {
        true
    }
}
