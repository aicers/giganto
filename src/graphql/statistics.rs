#![allow(clippy::module_name_repetitions)]

use super::TIMESTAMP_SIZE;
use crate::{
    graphql::TimeRange,
    storage::{Database, RawEventStore, StatisticsIter, StorageKey},
};
use anyhow::anyhow;
use async_graphql::{Context, Object, Result, SimpleObject};
use giganto_client::{ingest::statistics::Statistics, RawEventKind};
use num_traits::NumCast;
use rocksdb::Direction;
use serde::de::DeserializeOwned;
use std::{
    collections::{HashMap, HashSet},
    iter::Peekable,
    str::FromStr,
};
use tracing::error;

pub const MAX_CORE_SIZE: u32 = 16; // Number of queues on the collect device's NIC
const BYTE_TO_BIT: u64 = 8;
const STATS_ALLOWED_KINDS: [RawEventKind; 16] = [
    RawEventKind::Conn,
    RawEventKind::Dns,
    RawEventKind::Rdp,
    RawEventKind::Http,
    RawEventKind::Smtp,
    RawEventKind::Ntlm,
    RawEventKind::Kerberos,
    RawEventKind::Ssh,
    RawEventKind::DceRpc,
    RawEventKind::Ftp,
    RawEventKind::Mqtt,
    RawEventKind::Ldap,
    RawEventKind::Tls,
    RawEventKind::Smb,
    RawEventKind::Nfs,
    RawEventKind::Statistics,
];

#[derive(SimpleObject, Debug)]
pub struct StatisticsRawEvent {
    pub source: String,
    pub stats: Vec<StatisticsInfo>,
}

#[derive(SimpleObject, Debug, Clone)]
pub struct StatisticsInfo {
    pub timestamp: i64,
    pub detail: Vec<StatisticsDetail>,
}

#[derive(SimpleObject, Debug, Default, Clone)]
pub struct StatisticsDetail {
    pub protocol: String,
    pub bps: Option<f64>,
    pub pps: Option<f64>,
    pub eps: Option<f64>,
}

#[derive(Default)]
pub(super) struct StatisticsQuery;

#[Object]
impl StatisticsQuery {
    #[allow(clippy::unused_async)]
    async fn statistics<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        time: Option<TimeRange>,
        sources: Vec<String>,
        protocols: Option<Vec<String>>,
    ) -> Result<Vec<StatisticsRawEvent>> {
        let db = ctx.data::<Database>()?;
        let mut total_stats: Vec<StatisticsRawEvent> = Vec::new();
        let mut stats_iters: Vec<Peekable<StatisticsIter<'_, Statistics>>> = Vec::new();

        // Configure the protocol HashSet for which statistics output is allowed.
        let raw_event_kinds = if let Some(protocols) = &protocols {
            let mut records = HashSet::new();
            for proto in protocols {
                records.insert(convert_to_stats_allowed_type(proto)?);
            }
            records
        } else {
            STATS_ALLOWED_KINDS.into_iter().collect()
        };

        // Configure statistics results by source.
        for source in sources {
            for core in 0..MAX_CORE_SIZE {
                let stats_iter = get_statistics_iter(&db.statistics_store()?, core, &source, &time);
                let mut peek_stats_iter = stats_iter.peekable();
                if peek_stats_iter.peek().is_some() {
                    stats_iters.push(peek_stats_iter);
                }
            }
            let stats =
                gen_statistics(&mut stats_iters, &source, time.is_none(), &raw_event_kinds)?;
            total_stats.push(stats);
        }
        Ok(total_stats)
    }
}

fn get_statistics_iter<'c, T>(
    store: &RawEventStore<'c, T>,
    core_id: u32,
    source: &str,
    time: &Option<TimeRange>,
) -> StatisticsIter<'c, T>
where
    T: DeserializeOwned,
{
    let (start, end) = if let Some(time) = &time {
        (time.start, time.end)
    } else {
        (None, None)
    };

    let key_builder = StorageKey::builder()
        .start_key(source)
        .mid_key(Some(core_id.to_be_bytes().to_vec()));
    let from_key = key_builder.clone().upper_closed_bound_end_key(end).build();
    let to_key = key_builder.lower_closed_bound_end_key(start).build();
    let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Reverse);
    StatisticsIter::new(iter)
}

fn gen_statistics(
    stats_iters: &mut Vec<Peekable<StatisticsIter<'_, Statistics>>>,
    source: &str,
    latest_flag: bool,
    allowed_raw_event_kinds: &HashSet<RawEventKind>,
) -> Result<StatisticsRawEvent> {
    let mut stats_info_vec: Vec<StatisticsInfo> = Vec::new();
    let mut stats_detail_vec: Vec<StatisticsDetail> = Vec::new();
    let mut iter_next_values: Vec<(Box<[u8]>, Statistics)> = Vec::with_capacity(stats_iters.len());

    for iter in &mut *stats_iters {
        if let Some(item) = iter.next() {
            iter_next_values.push(item);
        }
    }

    loop {
        let mut next_candidate = Vec::new();

        // Find the most recent statistics in iter by core.
        let check_latest_values = iter_next_values.clone();
        let Some((latest_key, latest_stats)) = check_latest_values
            .iter()
            .max_by_key(|(key, _)| &key[(key.len() - TIMESTAMP_SIZE)..])
        else {
            break;
        };

        let latest_key_timestamp =
            i64::from_be_bytes(latest_key[(latest_key.len() - TIMESTAMP_SIZE)..].try_into()?);
        let mut total_stats: HashMap<RawEventKind, (u64, u64)> = HashMap::new();

        // Collect statistics formed at the same timestamp as the most recent statistics into a HashMap.
        for (idx, (key, value)) in iter_next_values.clone().iter().enumerate() {
            let compare_key_timestamp =
                i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
            if latest_key_timestamp == compare_key_timestamp {
                for (record, count, size) in &value.stats {
                    if allowed_raw_event_kinds.contains(record) {
                        total_stats
                            .entry(*record)
                            .and_modify(|(stats_count, stats_size)| {
                                *stats_count += count;
                                *stats_size += size;
                            })
                            .or_insert((*count, *size));
                    }
                }
                next_candidate.push(idx);
            }
        }
        next_candidate.reverse();

        // Change the value of the selected iter to the following value.
        for idx in next_candidate {
            if let Some(iter) = stats_iters.get_mut(idx) {
                if let Some(item) = iter.next() {
                    // replace new value (value is always exist)
                    *iter_next_values.get_mut(idx).unwrap() = item;
                } else {
                    // No value to call with the iterator.
                    let _ = stats_iters.remove(idx);
                    let _ = iter_next_values.remove(idx);
                }
            }
        }

        // Generates StatisticsDetail by calculating the bps/pps/eps.
        for (r_type, (count, size)) in total_stats {
            let mut stats_detail = StatisticsDetail {
                protocol: format!("{r_type:?}"),
                ..Default::default()
            };
            if r_type == RawEventKind::Statistics {
                stats_detail.bps = Some(calculate_ps(latest_stats.period, size * BYTE_TO_BIT)); // convert to bit size
                stats_detail.pps = Some(calculate_ps(latest_stats.period, count));
            } else {
                stats_detail.eps = Some(calculate_ps(latest_stats.period, count));
            }
            stats_detail_vec.push(stats_detail);
        }

        stats_info_vec.push(StatisticsInfo {
            timestamp: latest_key_timestamp,
            detail: stats_detail_vec.clone(),
        });
        stats_detail_vec.clear();

        // If there is no time condition, only the most recent statistics are passed.
        if latest_flag {
            break;
        }
    }

    Ok(StatisticsRawEvent {
        source: source.to_string(),
        stats: stats_info_vec,
    })
}

fn convert_to_stats_allowed_type(input: &str) -> Result<RawEventKind> {
    let raw_event_kind = RawEventKind::from_str(input).unwrap_or_default();
    if STATS_ALLOWED_KINDS.contains(&raw_event_kind) {
        Ok(raw_event_kind)
    } else {
        Err(anyhow!("not allowed RawEventKind string: {}", input).into())
    }
}

fn calculate_ps(period: u16, len: u64) -> f64 {
    if let (Some(len), Some(period)) = (NumCast::from(len), NumCast::from(period)) {
        let cal_len: f64 = len;
        let cal_period: f64 = period;
        let cal_result = format!("{:.2}", cal_len / cal_period);
        if let Ok(result) = cal_result.parse::<f64>() {
            return result;
        }
    }
    error!("Failed to convert period/len to f64");
    0.0
}

#[cfg(test)]
mod tests {
    use crate::{graphql::TestSchema, storage::RawEventStore};
    use chrono::Utc;
    use giganto_client::{ingest::statistics::Statistics, RawEventKind};

    #[tokio::test]
    async fn test_statistics() {
        let schema = TestSchema::new();
        let store = schema.db.statistics_store().unwrap();
        let now = Utc::now().timestamp_nanos_opt().unwrap();
        insert_statistics_raw_event(&store, now, "src 1", 0, 600, 1000000, 300000000);
        insert_statistics_raw_event(&store, now, "src 1", 1, 600, 2000000, 600000000);
        insert_statistics_raw_event(&store, now, "src 1", 2, 600, 3000000, 900000000);

        let query = r#"
    {
        statistics(
            sources: ["src 1"]
        ) {
            source,
            stats {
                detail {
                    protocol,
                    bps,
                    pps,
                }
            }
        }
    }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{statistics: [{source: \"src 1\",stats: [{detail: [{protocol: \"Statistics\",bps: 24000000.0,pps: 10000.0}]}]}]}"
        );
    }

    fn insert_statistics_raw_event(
        store: &RawEventStore<Statistics>,
        timestamp: i64,
        source: &str,
        core: u32,
        period: u16,
        count: u64,
        size: u64,
    ) {
        let mut key = Vec::with_capacity(source.len() + 1 + std::mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend_from_slice(&core.to_be_bytes());
        key.push(0);
        key.extend_from_slice(&timestamp.to_be_bytes());

        let msg = Statistics {
            core,
            period,
            stats: vec![(RawEventKind::Statistics, count, size)],
        };
        let msg = bincode::serialize(&msg).unwrap();
        store.append(&key, &msg).unwrap();
    }
}
