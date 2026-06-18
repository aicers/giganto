use std::hash::{Hash, Hasher};

use giganto_client::publish::stream::RequestStreamRecord;

use crate::comm::ingest::NetworkKey;

/// Typed internal routing key for publish stream direct channels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StreamChannelKey {
    SemiSupervised {
        publisher_sensor: String,
        target_sensor: String,
        record_type: RequestStreamRecord,
    },
    TimeSeriesGenerator {
        id: String,
        target_sensor: String,
        record_type: RequestStreamRecord,
    },
}

impl Hash for StreamChannelKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::SemiSupervised {
                publisher_sensor,
                target_sensor,
                record_type,
            } => {
                0u8.hash(state);
                publisher_sensor.hash(state);
                target_sensor.hash(state);
                u32::from(*record_type).hash(state);
            }
            Self::TimeSeriesGenerator {
                id,
                target_sensor,
                record_type,
            } => {
                1u8.hash(state);
                id.hash(state);
                target_sensor.hash(state);
                u32::from(*record_type).hash(state);
            }
        }
    }
}

impl StreamChannelKey {
    /// Returns whether this channel key matches the given network event key.
    pub(crate) fn matches_network_key(&self, network_key: &NetworkKey) -> bool {
        let (target_sensor, record_type) = match self {
            Self::SemiSupervised {
                target_sensor,
                record_type,
                ..
            }
            | Self::TimeSeriesGenerator {
                target_sensor,
                record_type,
                ..
            } => (target_sensor, record_type),
        };

        let sensor_match =
            target_sensor == network_key.sensor.as_str() || target_sensor.as_str() == "all";

        sensor_match && *record_type == network_key.record_type
    }

    /// Returns whether the direct-stream payload embeds the publisher sensor.
    pub(crate) fn embeds_publisher_sensor_in_payload(&self) -> bool {
        matches!(self, Self::SemiSupervised { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semi_supervised_matches_sensor_and_protocol() {
        let key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "pub".to_string(),
            target_sensor: "src1".to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        let network_key = NetworkKey::new("src1", RequestStreamRecord::Conn);
        assert!(key.matches_network_key(&network_key));
    }

    #[test]
    fn semi_supervised_matches_all_sensor() {
        let key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "pub".to_string(),
            target_sensor: "all".to_string(),
            record_type: RequestStreamRecord::Dns,
        };
        let network_key = NetworkKey::new("any-sensor", RequestStreamRecord::Dns);
        assert!(key.matches_network_key(&network_key));
    }

    #[test]
    fn semi_supervised_rejects_sensor_mismatch() {
        let key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "pub".to_string(),
            target_sensor: "src1".to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        let network_key = NetworkKey::new("src2", RequestStreamRecord::Conn);
        assert!(!key.matches_network_key(&network_key));
    }

    #[test]
    fn semi_supervised_rejects_record_type_mismatch() {
        let key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "pub".to_string(),
            target_sensor: "src1".to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        let network_key = NetworkKey::new("src1", RequestStreamRecord::Dns);
        assert!(!key.matches_network_key(&network_key));
    }

    #[test]
    fn time_series_generator_rejects_sensor_mismatch() {
        let key = StreamChannelKey::TimeSeriesGenerator {
            id: "tsg-1".to_string(),
            target_sensor: "src1".to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        let network_key = NetworkKey::new("src2", RequestStreamRecord::Conn);
        assert!(!key.matches_network_key(&network_key));
    }

    #[test]
    fn time_series_generator_rejects_record_type_mismatch() {
        let key = StreamChannelKey::TimeSeriesGenerator {
            id: "tsg-1".to_string(),
            target_sensor: "src1".to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        let network_key = NetworkKey::new("src1", RequestStreamRecord::Dns);
        assert!(!key.matches_network_key(&network_key));
    }

    #[test]
    fn time_series_generator_does_not_embed_publisher_sensor() {
        let key = StreamChannelKey::TimeSeriesGenerator {
            id: "SemiSupervised-policy".to_string(),
            target_sensor: "src1".to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        assert!(!key.embeds_publisher_sensor_in_payload());
    }

    #[test]
    fn semi_supervised_embeds_publisher_sensor() {
        let key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "pub".to_string(),
            target_sensor: "src1".to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        assert!(key.embeds_publisher_sensor_in_payload());
    }
}
