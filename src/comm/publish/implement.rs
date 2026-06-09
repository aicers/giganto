use std::net::IpAddr;

use anyhow::{Result, anyhow, bail};
use giganto_client::publish::stream::{
    RequestSemiSupervisedStream, RequestStreamRecord, RequestTimeSeriesGeneratorStream,
};

use crate::comm::stream_channel_key::StreamChannelKey;

pub trait RequestStreamMessage {
    fn channel_keys(
        &self,
        publisher_sensor: Option<&str>,
        record_type: RequestStreamRecord,
    ) -> Result<Vec<StreamChannelKey>>;
    fn start_time(&self) -> i64;
    fn filter_ip(&self, orig_addr: IpAddr, resp_addr: IpAddr) -> bool;
    fn sensor(&self) -> Result<String>;
    fn id(&self) -> Option<String>;
    fn is_semi_supervised(&self) -> bool;
    fn is_time_series_generator(&self) -> bool;
}

impl RequestStreamMessage for RequestSemiSupervisedStream {
    fn channel_keys(
        &self,
        publisher_sensor: Option<&str>,
        record_type: RequestStreamRecord,
    ) -> Result<Vec<StreamChannelKey>> {
        let publisher_sensor = publisher_sensor.ok_or_else(|| {
            anyhow!("Failed to generate the Semi-supervised channel key, sensor is required.")
        })?;
        if let Some(ref sensor_list) = self.sensor {
            let semi_supervised_keys = sensor_list
                .iter()
                .map(|target_sensor| StreamChannelKey::SemiSupervised {
                    publisher_sensor: publisher_sensor.to_string(),
                    target_sensor: target_sensor.clone(),
                    record_type,
                })
                .collect::<Vec<StreamChannelKey>>();
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
    fn channel_keys(
        &self,
        _publisher_sensor: Option<&str>,
        record_type: RequestStreamRecord,
    ) -> Result<Vec<StreamChannelKey>> {
        if let Some(ref target_sensor) = self.sensor {
            return Ok(vec![StreamChannelKey::TimeSeriesGenerator {
                id: self.id.clone(),
                target_sensor: target_sensor.clone(),
                record_type,
            }]);
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
