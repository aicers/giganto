#[cfg(feature = "cluster")]
mod client;
mod export;
mod log;
mod netflow;
pub mod network;
mod packet;
mod security;
mod sensor;
#[cfg(not(feature = "cluster"))]
mod standalone;
pub mod statistics;
pub mod status;
mod sysmon;
mod timeseries;

use std::{collections::BTreeSet, net::IpAddr, path::PathBuf, process::Command, sync::Arc};

use anyhow::anyhow;
use async_graphql::{
    EmptySubscription, InputObject, InputValueError, InputValueResult, MergedObject, OutputType,
    Result, Scalar, ScalarType, Value,
    connection::{Connection, Edge, query},
};
use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use chrono::{DateTime, TimeZone, Utc};
use giganto_client::ingest::Packet as pk;
use libc::timeval;
use pcap::{Capture, Linktype, Packet, PacketHeader};
use serde::{Serialize, de::DeserializeOwned};
use tempfile::NamedTempFile;
use tokio::sync::{Notify, mpsc::Sender};
use tracing::error;

#[cfg(feature = "cluster")]
pub(crate) use crate::graphql::client::cluster::{
    events_in_cluster, events_vec_in_cluster, paged_events_in_cluster,
};
#[cfg(not(feature = "cluster"))]
pub(crate) use crate::graphql::standalone::{
    events_in_cluster, events_vec_in_cluster, paged_events_in_cluster,
};
use crate::{
    comm::{IngestSensors, PcapSensors, ingest::implement::EventFilter, peer::Peers},
    settings::{ConfigVisible, Settings},
    storage::{
        Database, Direction, FilteredIter, KeyExtractor, KeyValue, RawEventStore, StorageKey,
        TimestampKeyExtractor,
    },
};

pub const TIMESTAMP_SIZE: usize = 8;
/// Note: The `unused` warning appears because this constant is only used in
/// `schema_should_be_up_to_date` (test code) and `gen_schema.rs` (an auxiliary binary), which are
/// not detected by the compiler as part of the main binary.
#[allow(unused)]
pub(crate) const SCHEMA_PATH: &str = "src/graphql/client/schema/schema.graphql";

#[derive(Default, MergedObject)]
pub struct Query(
    log::LogQuery,
    network::NetworkQuery,
    export::ExportQuery,
    packet::PacketQuery,
    timeseries::TimeSeriesQuery,
    status::StatusQuery,
    sensor::SensorQuery,
    statistics::StatisticsQuery,
    sysmon::SysmonQuery,
    security::SecurityLogQuery,
    netflow::NetflowQuery,
);

#[derive(Default, MergedObject)]
pub struct Mutation(status::ConfigMutation);

#[derive(InputObject, Serialize, Clone, Debug)]
pub struct TimeRange {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}
#[derive(InputObject, Serialize, Clone)]
pub struct IpRange {
    pub start: Option<String>,
    pub end: Option<String>,
}

#[derive(InputObject, Serialize, Clone)]
pub struct PortRange {
    pub start: Option<u16>,
    pub end: Option<u16>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct NetworkFilter {
    pub time: Option<TimeRange>,
    #[serde(skip)]
    pub sensor: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    log_level: Option<String>,
    log_contents: Option<String>,
    agent_id: Option<String>,
}

#[derive(InputObject, Serialize)]
pub struct SearchFilter {
    pub time: Option<TimeRange>,
    #[serde(skip)]
    pub sensor: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    log_level: Option<String>,
    log_contents: Option<String>,
    pub times: Vec<DateTime<Utc>>,
    keyword: Option<String>,
    agent_id: Option<String>,
}

pub trait RawEventFilter {
    #[allow(clippy::too_many_arguments)]
    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
        log_level: Option<String>,
        log_contents: Option<String>,
        text: Option<String>,
        sensor: Option<String>,
        agent_name: Option<String>,
    ) -> Result<bool>;
}

pub trait FromKeyValue<T>: Sized {
    fn from_key_value(key: &[u8], value: T) -> Result<Self>;
}

type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;
type ConnArgs<T> = (Vec<(Box<[u8]>, T)>, bool, bool);

pub struct NodeName(pub String);
pub struct RebootNotify(Arc<Notify>); // reboot
pub struct PowerOffNotify(Arc<Notify>); // shutdown
pub struct TerminateNotify(Arc<Notify>); // stop

#[allow(clippy::too_many_arguments)]
pub fn schema(
    node_name: NodeName,
    database: Database,
    pcap_sensors: PcapSensors,
    ingest_sensors: IngestSensors,
    peers: Peers,
    request_client_pool: reqwest::Client,
    export_path: PathBuf,
    reload_tx: Sender<ConfigVisible>,
    notify_reboot: Arc<Notify>,
    notify_power_off: Arc<Notify>,
    notify_terminate: Arc<Notify>,
    settings: Settings,
) -> Schema {
    Schema::build(Query::default(), Mutation::default(), EmptySubscription)
        .data(node_name)
        .data(database)
        .data(pcap_sensors)
        .data(ingest_sensors)
        .data(peers)
        .data(request_client_pool)
        .data(export_path)
        .data(reload_tx)
        .data(TerminateNotify(notify_terminate))
        .data(RebootNotify(notify_reboot))
        .data(PowerOffNotify(notify_power_off))
        .data(settings)
        .finish()
}

/// The default page size for connections when neither `first` nor `last` is
/// provided. Maximum size: 100.
const MAXIMUM_PAGE_SIZE: usize = 100;
const A_BILLION: i64 = 1_000_000_000;

fn collect_exist_times<T>(
    target_data: &BTreeSet<(DateTime<Utc>, Vec<u8>)>,
    filter: &SearchFilter,
) -> Vec<DateTime<Utc>>
where
    T: EventFilter + DeserializeOwned,
{
    let (start, end) = time_range(filter.time.as_ref());
    target_data
        .iter()
        .filter_map(|(time, value)| {
            bincode::deserialize::<T>(value).ok().and_then(|raw_event| {
                if *time >= start && *time < end {
                    filter
                        .check(
                            raw_event.orig_addr(),
                            raw_event.resp_addr(),
                            raw_event.orig_port(),
                            raw_event.resp_port(),
                            raw_event.log_level(),
                            raw_event.log_contents(),
                            raw_event.text(),
                            raw_event.sensor(),
                            raw_event.agent_name(),
                        )
                        .map_or(None, |c| c.then_some(*time))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<_>>()
}

fn time_range(time_range: Option<&TimeRange>) -> (DateTime<Utc>, DateTime<Utc>) {
    let (start, end) = if let Some(time) = time_range {
        (time.start, time.end)
    } else {
        (None, None)
    };
    let start = start.unwrap_or(Utc.timestamp_nanos(i64::MIN));
    let end = end.unwrap_or(Utc.timestamp_nanos(i64::MAX));
    (start, end)
}

#[allow(clippy::too_many_lines)]
fn get_connection<T>(
    store: &RawEventStore<'_, T>,
    filter: &(impl RawEventFilter + KeyExtractor),
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<ConnArgs<T>>
where
    T: DeserializeOwned + EventFilter,
{
    let (records, has_previous, has_next) = if let Some(before) = before {
        if after.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if first.is_some() {
            return Err("'before' and 'first' cannot be specified simultaneously".into());
        }

        let last = last.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64_engine.decode(before)?;

        // generate storage search key
        let key_builder = StorageKey::builder()
            .start_key(filter.get_start_key())
            .mid_key(filter.get_mid_key());
        let from_key = key_builder
            .clone()
            .upper_open_bound_end_key(filter.get_range_end_key().1)
            .build();
        let to_key = key_builder
            .lower_closed_bound_end_key(filter.get_range_end_key().0)
            .build();

        if cursor.cmp(&from_key.key()) == std::cmp::Ordering::Greater {
            return Err("invalid cursor".into());
        }
        let mut iter = store
            .boundary_iter(&cursor, &to_key.key(), Direction::Reverse)
            .peekable();
        if let Some(Ok((key, _))) = iter.peek()
            && key.as_ref() == cursor
        {
            iter.next();
        }
        let (mut records, has_previous) = collect_records(iter, last, filter);
        records.reverse();
        (records, has_previous, false)
    } else if let Some(after) = after {
        if before.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if last.is_some() {
            return Err("'after' and 'last' cannot be specified simultaneously".into());
        }
        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64_engine.decode(after)?;

        // generate storage search key
        let key_builder = StorageKey::builder()
            .start_key(filter.get_start_key())
            .mid_key(filter.get_mid_key());
        let from_key = key_builder
            .clone()
            .lower_closed_bound_end_key(filter.get_range_end_key().0)
            .build();
        let to_key = key_builder
            .upper_open_bound_end_key(filter.get_range_end_key().1)
            .build();

        if cursor.cmp(&from_key.key()) == std::cmp::Ordering::Less {
            return Err("invalid cursor".into());
        }
        let mut iter = store
            .boundary_iter(&cursor, &to_key.key(), Direction::Forward)
            .peekable();
        if let Some(Ok((key, _))) = iter.peek()
            && key.as_ref() == cursor
        {
            iter.next();
        }
        let (records, has_next) = collect_records(iter, first, filter);
        (records, false, has_next)
    } else if let Some(last) = last {
        if first.is_some() {
            return Err("first and last cannot be used together".into());
        }
        let last = last.min(MAXIMUM_PAGE_SIZE);

        // generate storage search key
        let key_builder = StorageKey::builder()
            .start_key(filter.get_start_key())
            .mid_key(filter.get_mid_key());
        let from_key = key_builder
            .clone()
            .upper_closed_bound_end_key(filter.get_range_end_key().1)
            .build();
        let to_key = key_builder
            .lower_closed_bound_end_key(filter.get_range_end_key().0)
            .build();

        let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Reverse);
        let (mut records, has_previous) = collect_records(iter, last, filter);
        records.reverse();
        (records, has_previous, false)
    } else {
        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        // generate storage search key
        let key_builder = StorageKey::builder()
            .start_key(filter.get_start_key())
            .mid_key(filter.get_mid_key());
        let from_key = key_builder
            .clone()
            .lower_closed_bound_end_key(filter.get_range_end_key().0)
            .build();
        let to_key = key_builder
            .upper_open_bound_end_key(filter.get_range_end_key().1)
            .build();

        let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);
        let (records, has_next) = collect_records(iter, first, filter);
        (records, false, has_next)
    };
    Ok((records, has_previous, has_next))
}

#[allow(clippy::too_many_lines)]
fn get_connection_by_prefix_timestamp_key<T>(
    store: &RawEventStore<'_, T>,
    filter: &(impl RawEventFilter + TimestampKeyExtractor),
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<ConnArgs<T>>
where
    T: DeserializeOwned + EventFilter,
{
    let (records, has_previous, has_next) = if let Some(before) = before {
        if after.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if first.is_some() {
            return Err("'before' and 'first' cannot be specified simultaneously".into());
        }

        let last = last.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64_engine.decode(before)?;

        // generate storage search key
        let key_builder = StorageKey::timestamp_builder();
        let from_key = key_builder
            .clone()
            .upper_open_bound_start_key(filter.get_range_start_key().1)
            .build();
        let to_key = key_builder
            .lower_closed_bound_start_key(filter.get_range_start_key().0)
            .build();

        if cursor.cmp(&from_key.key()) == std::cmp::Ordering::Greater {
            return Err("invalid cursor".into());
        }
        let mut iter = store
            .boundary_iter(&cursor, &to_key.key(), Direction::Reverse)
            .peekable();
        if let Some(Ok((key, _))) = iter.peek()
            && key.as_ref() == cursor
        {
            iter.next();
        }
        let (mut records, has_previous) = collect_records(iter, last, filter);
        records.reverse();
        (records, has_previous, false)
    } else if let Some(after) = after {
        if before.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if last.is_some() {
            return Err("'after' and 'last' cannot be specified simultaneously".into());
        }
        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64_engine.decode(after)?;

        // generate storage search key
        let key_builder = StorageKey::timestamp_builder();
        let from_key = key_builder
            .clone()
            .lower_closed_bound_start_key(filter.get_range_start_key().0)
            .build();
        let to_key = key_builder
            .upper_open_bound_start_key(filter.get_range_start_key().1)
            .build();

        if cursor.cmp(&from_key.key()) == std::cmp::Ordering::Less {
            return Err("invalid cursor".into());
        }
        let mut iter = store
            .boundary_iter(&cursor, &to_key.key(), Direction::Forward)
            .peekable();
        if let Some(Ok((key, _))) = iter.peek()
            && key.as_ref() == cursor
        {
            iter.next();
        }
        let (records, has_next) = collect_records(iter, first, filter);
        (records, false, has_next)
    } else if let Some(last) = last {
        if first.is_some() {
            return Err("first and last cannot be used together".into());
        }
        let last = last.min(MAXIMUM_PAGE_SIZE);

        // generate storage search key
        let key_builder = StorageKey::timestamp_builder();
        let from_key = key_builder
            .clone()
            .upper_closed_bound_start_key(filter.get_range_start_key().1)
            .build();
        let to_key = key_builder
            .lower_closed_bound_start_key(filter.get_range_start_key().0)
            .build();

        let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Reverse);
        let (mut records, has_previous) = collect_records(iter, last, filter);
        records.reverse();
        (records, has_previous, false)
    } else {
        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        // generate storage search key
        let key_builder = StorageKey::timestamp_builder();
        let from_key = key_builder
            .clone()
            .lower_closed_bound_start_key(filter.get_range_start_key().0)
            .build();
        let to_key = key_builder
            .upper_open_bound_start_key(filter.get_range_start_key().1)
            .build();

        let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);
        let (records, has_next) = collect_records(iter, first, filter);
        (records, false, has_next)
    };
    Ok((records, has_previous, has_next))
}

fn load_connection<N, T>(
    store: &RawEventStore<'_, T>,
    filter: &(impl RawEventFilter + KeyExtractor),
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, N>>
where
    N: FromKeyValue<T> + OutputType,
    T: DeserializeOwned + EventFilter,
{
    let (records, has_previous, has_next) =
        get_connection(store, filter, after, before, first, last)?;

    create_connection(records, has_previous, has_next)
}

fn load_connection_by_prefix_timestamp_key<N, T>(
    store: &RawEventStore<'_, T>,
    filter: &(impl RawEventFilter + TimestampKeyExtractor),
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, N>>
where
    N: FromKeyValue<T> + OutputType,
    T: DeserializeOwned + EventFilter,
{
    let (records, has_previous, has_next) =
        get_connection_by_prefix_timestamp_key(store, filter, after, before, first, last)?;

    create_connection(records, has_previous, has_next)
}

#[allow(clippy::unnecessary_wraps)]
fn create_connection<N, T>(
    records: Vec<(Box<[u8]>, T)>,
    has_previous: bool,
    has_next: bool,
) -> Result<Connection<String, N>>
where
    N: FromKeyValue<T> + OutputType,
    T: DeserializeOwned,
{
    let mut connection: Connection<String, N> = Connection::new(has_previous, has_next);
    connection.edges = records
        .into_iter()
        .map(|(key, node)| {
            Edge::new(
                base64_engine.encode(&key),
                N::from_key_value(&key, node).expect("failed to convert value"),
            )
        })
        .collect();
    Ok(connection)
}

fn collect_records<I, T>(
    mut iter: I,
    size: usize,
    filter: &impl RawEventFilter,
) -> (Vec<KeyValue<T>>, bool)
where
    I: Iterator<Item = anyhow::Result<(Box<[u8]>, T)>>,
    T: EventFilter,
{
    let mut records = Vec::with_capacity(size);
    let mut has_more = false;
    let mut invalid_data_cnt: u32 = 0;
    while let Some(item) = iter.next() {
        if item.is_err() {
            invalid_data_cnt += 1;
            continue;
        }
        let item = item.expect("not error value");
        let data_type = item.1.data_type();

        if let Ok(true) = filter.check(
            item.1.orig_addr(),
            item.1.resp_addr(),
            item.1.orig_port(),
            item.1.resp_port(),
            item.1.log_level(),
            item.1.log_contents(),
            item.1.text(),
            item.1.sensor(),
            item.1.agent_name(),
        ) {
            records.push(item);
        }

        if records.len() == size {
            if invalid_data_cnt > 1 {
                error!(
                    "Failed to read database or invalid data of {data_type} #{invalid_data_cnt}"
                );
            }
            has_more = iter.next().is_some();
            break;
        }
    }
    (records, has_more)
}

pub fn get_time_from_key_prefix(key: &[u8]) -> Result<DateTime<Utc>, anyhow::Error> {
    if key.len() > TIMESTAMP_SIZE {
        let timestamp = i64::from_be_bytes(key[0..TIMESTAMP_SIZE].try_into()?);
        return Ok(Utc.timestamp_nanos(timestamp));
    }
    Err(anyhow!("invalid database key length"))
}

pub fn get_time_from_key(key: &[u8]) -> Result<DateTime<Utc>, anyhow::Error> {
    if key.len() > TIMESTAMP_SIZE {
        let nanos = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        return Ok(Utc.timestamp_nanos(nanos));
    }
    Err(anyhow!("invalid database key length"))
}

fn get_peekable_iter<'c, T>(
    store: &RawEventStore<'c, T>,
    filter: &'c NetworkFilter,
    after: Option<&str>,
    before: Option<&str>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(std::iter::Peekable<FilteredIter<'c, T>>, usize)>
where
    T: DeserializeOwned + EventFilter,
{
    let (filtered_iter, cursor, size) =
        get_filtered_iter(store, filter, after, before, first, last)?;
    let mut filtered_iter = filtered_iter.peekable();
    if let Some(cursor) = cursor
        && let Some((key, _)) = filtered_iter.peek()
        && key.as_ref() == cursor
    {
        filtered_iter.next();
    }
    Ok((filtered_iter, size))
}

fn get_filtered_iter<'c, T>(
    store: &RawEventStore<'c, T>,
    filter: &'c NetworkFilter,
    after: Option<&str>,
    before: Option<&str>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(FilteredIter<'c, T>, Option<Vec<u8>>, usize)>
where
    T: DeserializeOwned + EventFilter,
{
    let (iter, cursor, size) = if let Some(before) = before {
        if after.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if first.is_some() {
            return Err("'before' and 'first' cannot be specified simultaneously".into());
        }

        let last = last.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64_engine.decode(before)?;

        // generate storage search key
        let key_builder = StorageKey::builder().start_key(filter.get_start_key());
        let from_key = key_builder
            .clone()
            .upper_open_bound_end_key(filter.get_range_end_key().1)
            .build();
        let to_key = key_builder
            .lower_closed_bound_end_key(filter.get_range_end_key().0)
            .build();

        if cursor.cmp(&from_key.key()) == std::cmp::Ordering::Greater {
            return Err("invalid cursor".into());
        }
        let iter = store.boundary_iter(&cursor, &to_key.key(), Direction::Reverse);

        (FilteredIter::new(iter, filter), Some(cursor), last)
    } else if let Some(after) = after {
        if before.is_some() {
            return Err("cannot use both `after` and `before`".into());
        }
        if last.is_some() {
            return Err("'after' and 'last' cannot be specified simultaneously".into());
        }

        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let cursor = base64_engine.decode(after)?;

        // generate storage search key
        let key_builder = StorageKey::builder().start_key(filter.get_start_key());
        let from_key = key_builder
            .clone()
            .lower_closed_bound_end_key(filter.get_range_end_key().0)
            .build();
        let to_key = key_builder
            .upper_open_bound_end_key(filter.get_range_end_key().1)
            .build();

        if cursor.cmp(&from_key.key()) == std::cmp::Ordering::Less {
            return Err("invalid cursor".into());
        }

        let iter = store.boundary_iter(&cursor, &to_key.key(), Direction::Forward);
        (FilteredIter::new(iter, filter), Some(cursor), first)
    } else if let Some(last) = last {
        if first.is_some() {
            return Err("first and last cannot be used together".into());
        }
        let last = last.min(MAXIMUM_PAGE_SIZE);

        // generate storage search key
        let key_builder = StorageKey::builder().start_key(filter.get_start_key());
        let from_key = key_builder
            .clone()
            .upper_closed_bound_end_key(filter.get_range_end_key().1)
            .build();
        let to_key = key_builder
            .lower_closed_bound_end_key(filter.get_range_end_key().0)
            .build();
        let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Reverse);
        (FilteredIter::new(iter, filter), None, last)
    } else {
        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);

        // generate storage search key
        let key_builder = StorageKey::builder().start_key(filter.get_start_key());
        let from_key = key_builder
            .clone()
            .lower_closed_bound_end_key(filter.get_range_end_key().0)
            .build();
        let to_key = key_builder
            .upper_open_bound_end_key(filter.get_range_end_key().1)
            .build();
        let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);
        (FilteredIter::new(iter, filter), None, first)
    };

    Ok((iter, cursor, size))
}

fn write_run_tcpdump(packets: &Vec<pk>) -> Result<String, anyhow::Error> {
    let temp_file = NamedTempFile::new()?;
    let file_path = temp_file.path();
    let new_pcap = Capture::dead_with_precision(Linktype::ETHERNET, pcap::Precision::Nano)?;
    let mut file = new_pcap.savefile(file_path)?;
    let file_path_str = file_path.to_str().ok_or_else(|| {
        anyhow!(
            "failed to convert file path to string: {}",
            file_path.display()
        )
    })?;

    for packet in packets {
        let len = u32::try_from(packet.packet.len()).unwrap_or_default();
        let header = PacketHeader {
            ts: timeval {
                tv_sec: packet.packet_timestamp / A_BILLION,
                #[cfg(target_os = "macos")]
                tv_usec: i32::try_from(packet.packet_timestamp & A_BILLION).unwrap_or_default(),
                #[cfg(target_os = "linux")]
                tv_usec: packet.packet_timestamp & A_BILLION,
            },
            caplen: len,
            len,
        };
        let p = Packet {
            header: &header,
            data: &packet.packet,
        };
        file.write(&p);
    }
    file.flush()?;

    let cmd = "tcpdump";
    let args = ["-n", "-X", "-tttt", "-v", "-r", file_path_str];

    let output = Command::new(cmd)
        .env("PATH", "/usr/sbin:/usr/bin")
        .args(args)
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("failed to run tcpdump"));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn check_address(filter_addr: Option<&IpRange>, target_addr: Option<IpAddr>) -> Result<bool> {
    match (filter_addr, target_addr) {
        (Some(ip_range), Some(addr)) => {
            let starts_after_or_at = if let Some(start) = ip_range.start.as_deref() {
                addr >= start.parse::<IpAddr>()?
            } else {
                true
            };

            let ends_before = if let Some(end) = ip_range.end.as_deref() {
                addr < end.parse::<IpAddr>()?
            } else {
                true
            };

            Ok(starts_after_or_at && ends_before)
        }
        _ => Ok(true),
    }
}

fn check_port(filter_port: Option<&PortRange>, target_port: Option<u16>) -> bool {
    match (filter_port, target_port) {
        (Some(port_range), Some(port)) => {
            let starts_after_or_at = port_range.start.is_none_or(|start| port >= start);
            let ends_before = port_range.end.is_none_or(|end| port < end);
            starts_after_or_at && ends_before
        }
        _ => true,
    }
}

fn check_contents(filter_str: Option<&str>, target_str: Option<String>) -> bool {
    filter_str
        .as_ref()
        .is_none_or(|filter_str| target_str.is_some_and(|contents| contents.contains(*filter_str)))
}

fn check_agent_id(filter_agent_id: Option<&str>, target_agent_id: Option<&str>) -> bool {
    filter_by_str(filter_agent_id, target_agent_id)
}

fn filter_by_str(filter_str: Option<&str>, target_str: Option<&str>) -> bool {
    filter_str.as_ref().is_none_or(|filter_id| {
        target_str
            .as_ref()
            .is_some_and(|agent_id| agent_id == filter_id)
    })
}

fn min_max_time(is_forward: bool) -> DateTime<Utc> {
    if is_forward {
        DateTime::<Utc>::MAX_UTC
    } else {
        DateTime::<Utc>::MIN_UTC
    }
}

async fn handle_paged_events<N, T>(
    store: RawEventStore<'_, T>,
    filter: impl RawEventFilter + KeyExtractor,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, N>>
where
    N: FromKeyValue<T> + OutputType,
    T: DeserializeOwned + EventFilter,
{
    query(
        after,
        before,
        first,
        last,
        |after, before, first, last| async move {
            load_connection::<N, T>(&store, &filter, after, before, first, last)
        },
    )
    .await
}

/// Generates the GraphQL schema.
///
/// Note: The `unused` warning appears because this function is only used in
/// `schema_should_be_up_to_date` (test code) and `gen_schema.rs` (an auxiliary binary), which are
/// not detected by the compiler as part of the main binary.
#[allow(unused)]
pub(crate) fn generate_schema() -> String {
    Schema::build(Query::default(), Mutation::default(), EmptySubscription)
        .finish()
        .sdl()
}

macro_rules! impl_string_number {
    ($struct_name:ident, $type:ty) => {
        #[derive(Debug, PartialEq, Default, Clone, serde::Serialize)]
        pub struct $struct_name(pub $type);

        impl<'de> serde::Deserialize<'de> for $struct_name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                s.parse::<$type>()
                    .map($struct_name)
                    .map_err(serde::de::Error::custom)
            }
        }

        #[Scalar]
        impl ScalarType for $struct_name {
            fn parse(value: Value) -> InputValueResult<Self> {
                if let Value::String(value) = &value {
                    Ok(value.parse().map($struct_name)?)
                } else {
                    Err(InputValueError::expected_type(value))
                }
            }

            fn to_value(&self) -> Value {
                Value::String(self.0.to_string())
            }
        }
    };
}

impl_string_number!(StringNumberUsize, usize);
impl_string_number!(StringNumberU64, u64);
impl_string_number!(StringNumberU32, u32);
impl_string_number!(StringNumberI64, i64);

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use async_graphql::EmptySubscription;
    use tokio::sync::Notify;

    use super::{
        NodeName, StringNumberI64, StringNumberU32, StringNumberU64, StringNumberUsize, schema,
    };
    use crate::comm::{
        IngestSensors, new_pcap_sensors,
        peer::{PeerInfo, Peers},
    };
    use crate::graphql::{Mutation, Query};
    use crate::settings::{ConfigVisible, Settings};
    use crate::storage::{Database, DbOptions};

    type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;

    const CURRENT_GIGANTO_INGEST_SENSORS: [&str; 3] = ["src1", "src 1", "ingest src 1"];
    const PEER_GIGANTO_2_INGEST_SENSORS: [&str; 3] = ["src2", "src 2", "ingest src 2"];

    pub struct TestSchema {
        pub _dir: tempfile::TempDir, // to prevent the data directory from being deleted while the test is running
        pub db: Database,
        pub schema: Schema,
    }

    impl TestSchema {
        fn setup(ingest_sensors: IngestSensors, peers: Peers) -> Self {
            let db_dir = tempfile::tempdir().unwrap();
            let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
            let pcap_sensors = new_pcap_sensors();
            let request_client_pool = reqwest::Client::new();
            let export_dir = tempfile::tempdir().unwrap();
            let (reload_tx, _) = tokio::sync::mpsc::channel::<ConfigVisible>(1);
            let notify_reboot = Arc::new(Notify::new());
            let notify_power_off = Arc::new(Notify::new());
            let notify_terminate = Arc::new(Notify::new());
            let settings = Settings::from_file("tests/config.toml").unwrap();
            let schema = schema(
                NodeName("giganto1".to_string()),
                db.clone(),
                pcap_sensors,
                ingest_sensors,
                peers,
                request_client_pool,
                export_dir.path().to_path_buf(),
                reload_tx,
                notify_reboot,
                notify_power_off,
                notify_terminate,
                settings,
            );

            Self {
                _dir: db_dir,
                db,
                schema,
            }
        }

        pub fn new() -> Self {
            let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
                CURRENT_GIGANTO_INGEST_SENSORS
                    .into_iter()
                    .map(str::to_string)
                    .collect::<HashSet<String>>(),
            ));

            let peers = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
            Self::setup(ingest_sensors, peers)
        }

        pub fn new_with_graphql_peer(port: u16) -> Self {
            let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
                CURRENT_GIGANTO_INGEST_SENSORS
                    .into_iter()
                    .map(str::to_string)
                    .collect::<HashSet<String>>(),
            ));

            let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
                "127.0.0.1".to_string(),
                PeerInfo {
                    ingest_sensors: PEER_GIGANTO_2_INGEST_SENSORS
                        .into_iter()
                        .map(str::to_string)
                        .collect::<HashSet<String>>(),
                    graphql_port: Some(port),
                    publish_port: None,
                },
            )])));

            Self::setup(ingest_sensors, peers)
        }

        pub async fn execute(&self, query: &str) -> async_graphql::Response {
            let request: async_graphql::Request = query.into();
            self.schema.execute(request).await
        }
    }

    #[test]
    fn schema_should_be_up_to_date() {
        let expect = super::generate_schema();
        let actual = std::fs::read_to_string(super::SCHEMA_PATH).unwrap();
        assert!(
            expect == actual,
            "The GraphQL schema is not up to date. Please run the following command to update it.\n\
            `cargo run --bin gen_schema --no-default-features --target-dir target/gen_schema`"
        );
    }

    #[test]
    fn string_number_deserialization_from_string() {
        // Test StringNumberU64
        let json_str = r#""12345678901234""#;
        let result: StringNumberU64 = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.0, 12_345_678_901_234_u64);

        // Test StringNumberU32
        let json_str = r#""12345""#;
        let result: StringNumberU32 = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.0, 12345_u32);

        // Test StringNumberI64
        let json_str = r#""-9876543210""#;
        let result: StringNumberI64 = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.0, -9_876_543_210_i64);

        // Test StringNumberUsize
        let json_str = r#""98765""#;
        let result: StringNumberUsize = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.0, 98765_usize);
    }

    #[test]
    fn string_number_deserialization_handles_invalid_input() {
        // Test invalid string for StringNumberU64
        let json_str = r#""not_a_number""#;
        let result: Result<StringNumberU64, _> = serde_json::from_str(json_str);
        assert!(result.is_err());

        // Test empty string
        let json_str = r#""""#;
        let result: Result<StringNumberU64, _> = serde_json::from_str(json_str);
        assert!(result.is_err());

        // Test overflow for u32
        let json_str = r#""99999999999999999999""#;
        let result: Result<StringNumberU32, _> = serde_json::from_str(json_str);
        assert!(result.is_err());
    }
}
