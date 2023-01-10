use crate::storage::RawEventStore;

use super::{EventFilter, RecordType, STATISTICS_VALIAD_RECORD_COUNT};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
    net::IpAddr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Serialize, Deserialize)]
pub struct CollectorStatistics {
    pub period: u16,
    pub stats: Vec<(RecordType, u64, u64)>, // protocol, packet count, packet size
}

impl EventFilter for CollectorStatistics {
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
}

impl Display for CollectorStatistics {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        for stat in &self.stats {
            writeln!(f, "{:?}\t{}\t{}\t{}", stat.0, stat.1, stat.2, self.period)?;
        }
        Ok(())
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalyzerStatistics {
    pub period: u16,
    pub stats: BTreeMap<String, BTreeMap<String, (u64, u64)>>, // source, protocol\0kind, raw data count, raw data size
}

impl EventFilter for AnalyzerStatistics {
    fn orig_addr(&self) -> Option<IpAddr> {
        None
    }
    fn resp_addr(&self) -> Option<IpAddr> {
        None
    }
    fn orig_port(&self) -> Option<u16> {
        None
    }
    fn resp_port(&self) -> Option<u16> {
        None
    }
    fn log_level(&self) -> Option<String> {
        None
    }
    fn log_contents(&self) -> Option<String> {
        None
    }
}

impl Display for AnalyzerStatistics {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        for (source, stats) in &self.stats {
            for (key, val) in stats {
                let mut proto_kind = key.split('\0');
                let proto = proto_kind.next().ok_or(std::fmt::Error)?;
                if let Some(kind) = proto_kind.next() {
                    writeln!(
                        f,
                        "{source}\t{proto}\t{kind}\t{}\t{}\t{}",
                        val.0, val.1, self.period
                    )?;
                } else {
                    writeln!(
                        f,
                        "{source}\t{proto}\t{}\t{}\t{}",
                        val.0, val.1, self.period
                    )?;
                }
            }
        }
        Ok(())
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct RealTimeStatistics {
    period: u16,
    stats: BTreeMap<String, BTreeMap<String, (AtomicU64, AtomicUsize)>>, // source, protocol\0kind, raw data count, raw data size
}

impl RealTimeStatistics {
    pub fn new(store: &RawEventStore<AnalyzerStatistics>, period: u16) -> Result<Self> {
        let mut stats = BTreeMap::new();
        if let Some(value) = store.last_item_value()? {
            let init_data = bincode::deserialize::<AnalyzerStatistics>(&value)?;
            for (source, records) in init_data.stats {
                let mut records_map = BTreeMap::new();
                for proto in records.keys() {
                    records_map.insert(proto.clone(), (AtomicU64::new(0), AtomicUsize::new(0)));
                }
                stats.insert(source, records_map);
            }
        }
        Ok(Self { period, stats })
    }

    pub fn init_source(&mut self, source: String) -> Result<()> {
        if self.stats.get(&source).is_none() {
            self.stats.insert(source, Self::gen_record_statistics()?);
        }
        Ok(())
    }

    pub fn append(
        &mut self,
        source: String,
        kind: Option<String>,
        record_type: RecordType,
        len: usize,
    ) {
        let record_str = record_type.convert_to_str().to_string();
        let record_key = match kind {
            Some(k_val) => format!("{record_str}\0{k_val}"),
            None => record_str,
        };

        self.stats.entry(source).and_modify(|stats_hash| {
            if let Some((cnt, size)) = stats_hash.get_mut(&record_key) {
                cnt.fetch_add(1, Ordering::SeqCst);
                size.fetch_add(len, Ordering::SeqCst);
            } else {
                // only log's data will input
                stats_hash.insert(record_key, (AtomicU64::new(1), AtomicUsize::new(len)));
            }
        });
    }

    pub fn clear(&mut self) -> Result<AnalyzerStatistics> {
        let mut result_stats = AnalyzerStatistics {
            period: self.period,
            stats: BTreeMap::new(),
        };

        for (source, stats_hash) in &mut self.stats {
            let mut append_stats_hash = BTreeMap::new();
            for (key, (cnt, size)) in stats_hash {
                let count = *cnt.get_mut();
                *cnt.get_mut() = 0;
                let len = *size.get_mut();
                *size.get_mut() = 0;
                append_stats_hash.insert(key.to_string(), (count, u64::try_from(len)?));
            }
            result_stats.stats.insert(source.clone(), append_stats_hash);
        }
        Ok(result_stats)
    }

    fn gen_record_statistics() -> Result<BTreeMap<String, (AtomicU64, AtomicUsize)>> {
        let mut stats_hash: BTreeMap<String, (AtomicU64, AtomicUsize)> = BTreeMap::new();
        for record in 0..STATISTICS_VALIAD_RECORD_COUNT {
            let record_type = RecordType::try_from(record)?;
            match record_type {
                RecordType::PeriodicTimeSeries
                | RecordType::CollectStatistics
                | RecordType::Oplog
                | RecordType::Log => {
                    continue;
                }
                _ => {
                    stats_hash.insert(
                        record_type.convert_to_str().to_string(),
                        (AtomicU64::new(0), AtomicUsize::new(0)),
                    );
                }
            }
        }
        Ok(stats_hash)
    }
}
