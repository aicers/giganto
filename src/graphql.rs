mod export;
mod log;
pub mod network;
mod packet;
mod source;
pub mod statistics;
pub mod status;
mod sysmon;
mod timeseries;

use self::network::{IpRange, NetworkFilter, PortRange, SearchFilter};
use crate::{
    ingest::{implement::EventFilter, PacketSources},
    storage::{
        addr_to_index_key, mid_idx_key, start_idx_key, truncate_datetime, Database, Direction,
        FilteredIter, KeyExtractor, KeyValue, RawEventStore, StorageKey,
    },
};
use anyhow::anyhow;
use async_graphql::{
    connection::{Connection, Edge},
    EmptySubscription, InputObject, MergedObject, OutputType, Result,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use chrono::{DateTime, TimeZone, Utc};
use giganto_client::ingest::{Packet as pk, RecordType};
use libc::timeval;
use pcap::{Capture, Linktype, Packet, PacketHeader};
use serde::{de::DeserializeOwned, Serialize};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::{
    collections::{BTreeSet, HashSet},
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tempfile::tempfile;
use tokio::sync::Notify;
use tracing::error;

pub const TIMESTAMP_SIZE: usize = 8;
const TIME_RANGE_MULTI_UNIT: i32 = 60;

#[derive(Default, MergedObject)]
pub struct Query(
    log::LogQuery,
    network::NetworkQuery,
    export::ExportQuery,
    packet::PacketQuery,
    timeseries::TimeSeriesQuery,
    status::GigantoStatusQuery,
    source::SourceQuery,
    statistics::StatisticsQuery,
    sysmon::SysmonQuery,
);

#[derive(Default, MergedObject)]
pub struct Mutation(status::GigantoConfigMutation);

#[derive(InputObject, Serialize)]
pub struct TimeRange {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
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
    ) -> Result<bool>;
}

pub trait FromKeyValue<T>: Sized {
    fn from_key_value(key: &[u8], value: T) -> Result<Self>;
}

pub type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;
type ConnArgs<T> = (Vec<(Box<[u8]>, T)>, bool, bool);
type IndexKeyValue<T> = (Vec<u8>, T);
type IndexArgs<T> = (Vec<IndexKeyValue<T>>, bool, bool);

pub fn schema(
    database: Database,
    packet_sources: PacketSources,
    export_path: PathBuf,
    config_reload: Arc<Notify>,
    config_file_path: String,
    index_period: Option<Duration>,
) -> Schema {
    Schema::build(Query::default(), Mutation::default(), EmptySubscription)
        .data(database)
        .data(packet_sources)
        .data(export_path)
        .data(config_reload)
        .data(config_file_path)
        .data(index_period)
        .finish()
}

/// The default page size for connections when neither `first` nor `last` is
/// provided.
/// Maximum size: 100.
const MAXIMUM_PAGE_SIZE: usize = 100;
const A_BILLION: i64 = 1_000_000_000;

fn collect_exist_timestamp<T>(
    target_data: &BTreeSet<(DateTime<Utc>, Vec<u8>)>,
    filter: &SearchFilter,
) -> Vec<DateTime<Utc>>
where
    T: EventFilter + DeserializeOwned,
{
    let (start, end) = time_range(&filter.time);
    let search_time = target_data
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
                        )
                        .map_or(None, |c| c.then_some(*time))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<_>>();
    search_time
}

fn time_range(time_range: &Option<TimeRange>) -> (DateTime<Utc>, DateTime<Utc>) {
    let (start, end) = if let Some(time) = time_range {
        (time.start, time.end)
    } else {
        (None, None)
    };
    let start = start.unwrap_or(Utc.timestamp_nanos(0));
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
            .upper_closed_bound_end_key(filter.get_range_end_key().1)
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
        if let Some(Ok((key, _))) = iter.peek() {
            if key.as_ref() == cursor {
                iter.next();
            }
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
        if let Some(Ok((key, _))) = iter.peek() {
            if key.as_ref() == cursor {
                iter.next();
            }
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
            .upper_open_bound_end_key(filter.get_range_end_key().1)
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

        match filter.check(
            item.1.orig_addr(),
            item.1.resp_addr(),
            item.1.orig_port(),
            item.1.resp_port(),
            item.1.log_level(),
            item.1.log_contents(),
            item.1.text(),
        ) {
            Ok(true) => records.push(item),
            Ok(false) | Err(_) => {}
        }
        if records.len() == size {
            if invalid_data_cnt > 1 {
                error!(
                    "failed to read database or invalid data of {data_type} #{invalid_data_cnt}"
                );
            }
            has_more = iter.next().is_some();
            break;
        }
    }
    (records, has_more)
}

pub fn get_timestamp_from_key(key: &[u8]) -> Result<DateTime<Utc>, anyhow::Error> {
    if key.len() > TIMESTAMP_SIZE {
        let nanos = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        return Ok(Utc.timestamp_nanos(nanos));
    }
    Err(anyhow!("invalid database key length"))
}

fn get_filtered_iter<'c, T>(
    store: &RawEventStore<'c, T>,
    filter: &'c NetworkFilter,
    after: &Option<String>,
    before: &Option<String>,
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
            .upper_closed_bound_end_key(filter.get_range_end_key().1)
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
            .upper_open_bound_end_key(filter.get_range_end_key().1)
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
    let mut temp_file = tempfile()?;
    let fd = temp_file.as_raw_fd();
    let new_pcap = Capture::dead_with_precision(Linktype::ETHERNET, pcap::Precision::Nano)?;
    let mut file = unsafe { new_pcap.savefile_raw_fd(fd)? };

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
    let mut buf = Vec::new();
    file.flush()?;
    temp_file.seek(SeekFrom::Start(0))?;
    temp_file.read_to_end(&mut buf)?;

    let cmd = "tcpdump";
    let args = ["-n", "-X", "-tttt", "-v", "-r", "-"];

    let mut child = Command::new(cmd)
        .env("PATH", "/usr/sbin:/usr/bin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    if let Some(mut child_stdin) = child.stdin.take() {
        #[cfg(target_os = "macos")]
        child_stdin.write_all(&[0, 0, 0, 0])?;
        child_stdin.write_all(&buf)?;
    } else {
        return Err(anyhow!("failed to execute tcpdump"));
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!("failed to run tcpdump"));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn check_address(filter_addr: &Option<IpRange>, target_addr: Option<IpAddr>) -> Result<bool> {
    if let Some(ip_range) = filter_addr {
        if let Some(addr) = target_addr {
            let end = if let Some(end) = &ip_range.end {
                addr >= end.parse::<IpAddr>()?
            } else {
                false
            };

            let start = if let Some(start) = &ip_range.start {
                addr < start.parse::<IpAddr>()?
            } else {
                false
            };
            if end || start {
                return Ok(false);
            };
        }
    }
    Ok(true)
}

fn check_port(filter_port: &Option<PortRange>, target_port: Option<u16>) -> bool {
    if let Some(port_range) = filter_port {
        if let Some(port) = target_port {
            let end = if let Some(end) = port_range.end {
                port >= end
            } else {
                false
            };
            let start = if let Some(start) = port_range.start {
                port < start
            } else {
                false
            };
            if end || start {
                return false;
            };
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn load_index_connection<N, T>(
    db: &Database,
    store: &RawEventStore<'_, T>,
    filter: &NetworkFilter,
    idx_duration: Duration,
    protocol: RecordType,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, N>>
where
    T: DeserializeOwned + EventFilter,
    N: FromKeyValue<T> + OutputType,
{
    let (records, has_previous, has_next) = get_index_connection(
        db,
        store,
        filter,
        idx_duration,
        protocol,
        after,
        before,
        first,
        last,
    )?;

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

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn get_index_connection<T>(
    db: &Database,
    store: &RawEventStore<'_, T>,
    filter: &NetworkFilter,
    idx_duration: Duration,
    protocol: RecordType,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<IndexArgs<T>>
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
        let cursor_datetime = get_timestamp_from_key(&cursor)?;
        let (from, mut to) = parse_datetimes_for_index(&filter.time, idx_duration)?;

        if cursor_datetime.cmp(&to) == std::cmp::Ordering::Greater {
            return Err("invalid cursor".into());
        }
        to = cursor_datetime - chrono::Duration::nanoseconds(1);

        let (records, has_previous) = collect_index_records(
            db,
            store,
            filter,
            idx_duration,
            protocol,
            (from, to),
            last,
            true,
        )?;
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
        let cursor_datetime = get_timestamp_from_key(&cursor)?;
        let (mut from, to) = parse_datetimes_for_index(&filter.time, idx_duration)?;

        if cursor_datetime.cmp(&from) == std::cmp::Ordering::Less {
            return Err("invalid cursor".into());
        }
        from = cursor_datetime + chrono::Duration::nanoseconds(1);

        let (records, has_next) = collect_index_records(
            db,
            store,
            filter,
            idx_duration,
            protocol,
            (from, to),
            first,
            false,
        )?;
        (records, false, has_next)
    } else if let Some(last) = last {
        if first.is_some() {
            return Err("first and last cannot be used together".into());
        }
        let last = last.min(MAXIMUM_PAGE_SIZE);

        let (from, to) = parse_datetimes_for_index(&filter.time, idx_duration)?;

        let (records, has_previous) = collect_index_records(
            db,
            store,
            filter,
            idx_duration,
            protocol,
            (from, to),
            last,
            true,
        )?;
        (records, has_previous, false)
    } else {
        let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
        let (from, to) = parse_datetimes_for_index(&filter.time, idx_duration)?;
        let (records, has_next) = collect_index_records(
            db,
            store,
            filter,
            idx_duration,
            protocol,
            (from, to),
            first,
            false,
        )?;
        (records, false, has_next)
    };
    Ok((records, has_previous, has_next))
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn collect_index_records<T>(
    db: &Database,
    store: &RawEventStore<'_, T>,
    filter: &NetworkFilter,
    idx_duration: Duration,
    protocol: RecordType,
    search_time_range: (DateTime<Utc>, DateTime<Utc>),
    size: usize,
    is_reverse: bool,
) -> Result<(Vec<IndexKeyValue<T>>, bool)>
where
    T: DeserializeOwned + EventFilter,
{
    let mut idx_common_key: Vec<u8> = Vec::new();
    let mut idx_from_to_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut store_vec: Vec<RawEventStore<'_, Vec<i64>>> = Vec::new();

    start_idx_key(&mut idx_common_key, &filter.source, protocol);
    let replace_start_loc = idx_common_key.len();

    mid_idx_key(&mut idx_common_key, &Utc::now());
    let replace_end_loc = idx_common_key.len() - 1;

    if let Some(ref ip_range) = filter.orig_addr {
        let src_addr_idx_store = db.src_addr_index()?;
        store_vec.push(src_addr_idx_store);

        let (start, end) = end_addr_idx_key(ip_range)?;
        let mut start_key = idx_common_key.clone();
        start_key.extend_from_slice(&start);
        let mut end_key = idx_common_key.clone();
        end_key.extend_from_slice(&end);
        idx_from_to_keys.push((start_key, end_key));
    }

    if let Some(ref ip_range) = filter.resp_addr {
        let dst_addr_idx_store = db.dst_addr_index()?;
        store_vec.push(dst_addr_idx_store);

        let (start, end) = end_addr_idx_key(ip_range)?;
        let mut start_key = idx_common_key.clone();
        start_key.extend_from_slice(&start);
        let mut end_key = idx_common_key.clone();
        end_key.extend_from_slice(&end);
        idx_from_to_keys.push((start_key, end_key));
    }

    if let Some(ref port_range) = filter.orig_port {
        let src_port_idx_store = db.src_port_index()?;
        store_vec.push(src_port_idx_store);

        let (start, end) = end_port_idx_key(port_range);
        let mut start_key = idx_common_key.clone();
        start_key.extend_from_slice(&start);
        let mut end_key = idx_common_key.clone();
        end_key.extend_from_slice(&end);
        idx_from_to_keys.push((start_key, end_key));
    }

    if let Some(ref port_range) = filter.resp_port {
        let dst_port_idx_store = db.dst_port_index()?;
        store_vec.push(dst_port_idx_store);

        let (start, end) = end_port_idx_key(port_range);

        let mut start_key = idx_common_key.clone();
        start_key.extend_from_slice(&start);
        let mut end_key = idx_common_key.clone();
        end_key.extend_from_slice(&end);
        idx_from_to_keys.push((start_key, end_key));
    }

    // The start/end values of the time for the index cf lookup.
    let from_time_key = truncate_datetime(search_time_range.0, idx_duration)?;
    let to_time_key = truncate_datetime(search_time_range.1, idx_duration)?
        + chrono::Duration::from_std(idx_duration)?;

    // Value for detailed time comparison in lookup results. (from_real_time,to_real_time is always exist)
    let compare_from_time = search_time_range.0.timestamp_nanos_opt().unwrap();
    let compare_to_time = search_time_range.1.timestamp_nanos_opt().unwrap();

    let (mut current_lookup_time, target_lookup_time, sum_duration) = if is_reverse {
        (
            to_time_key,
            from_time_key,
            -chrono::Duration::from_std(idx_duration)?,
        )
    } else {
        (
            from_time_key,
            to_time_key,
            chrono::Duration::from_std(idx_duration)?,
        )
    };

    let mut records = Vec::with_capacity(size);
    let mut has_more = false;
    let mut invalid_data_cnt: u32 = 0;

    'search_loop: loop {
        let mut time_vec = Vec::new();
        let mut iter_vec = Vec::new();
        if current_lookup_time == target_lookup_time {
            break;
        }
        for (idx, store) in store_vec.iter().enumerate() {
            let (idx_start_key, idx_end_key) = idx_from_to_keys.get_mut(idx).unwrap(); //현재 store_vec와 페어인 idx는 항상 존재합니다.
            idx_start_key[replace_start_loc..replace_end_loc].copy_from_slice(
                current_lookup_time
                    .format("%Y%m%d%H%M")
                    .to_string()
                    .as_bytes(),
            );
            idx_end_key[replace_start_loc..replace_end_loc].copy_from_slice(
                current_lookup_time
                    .format("%Y%m%d%H%M")
                    .to_string()
                    .as_bytes(),
            );

            let mut iter = if is_reverse {
                store
                    .boundary_iter(idx_end_key, idx_start_key, rocksdb::Direction::Reverse)
                    .peekable()
            } else {
                store
                    .boundary_iter(idx_start_key, idx_end_key, rocksdb::Direction::Forward)
                    .peekable()
            };

            if iter.peek().is_none() {
                current_lookup_time += sum_duration;
                continue 'search_loop;
            }
            iter_vec.push(iter);
        }

        for iter in iter_vec {
            let data: HashSet<i64> = iter
                .filter_map(std::result::Result::ok)
                .flat_map(|(_, timestamp_keys)| timestamp_keys.into_iter())
                .filter(|&x| x >= compare_from_time && x < compare_to_time)
                .collect();
            time_vec.push(data);
        }

        // Time_vec always has at least one value.
        let mut search_list: Vec<_> = time_vec
            .pop()
            .unwrap()
            .into_iter()
            .filter(|x| time_vec.iter().all(|s| s.contains(x)))
            .collect();
        search_list.sort_unstable();

        while !search_list.is_empty() {
            let candidate_timestamp = if is_reverse {
                search_list.pop().unwrap() //last value is always exist.
            } else {
                search_list.remove(0)
            };

            let data_type = if let Ok((key, value)) =
                store.get_key_value(&filter.source, candidate_timestamp)
            {
                if let Ok(de_value) = bincode::deserialize::<T>(&value) {
                    let data_type = de_value.data_type();
                    if is_reverse {
                        records.insert(0, (key, de_value));
                    } else {
                        records.push((key, de_value));
                    }
                    data_type
                } else {
                    invalid_data_cnt += 1;
                    continue;
                }
            } else {
                invalid_data_cnt += 1;
                continue;
            };

            if records.len() == size + 1 {
                if invalid_data_cnt > 1 {
                    error!(
                        "failed to read database or invalid data of {data_type} #{invalid_data_cnt}"
                    );
                }
                has_more = true;

                if is_reverse {
                    records.remove(0);
                } else {
                    records.pop();
                }
                break 'search_loop;
            }
        }

        current_lookup_time += sum_duration;
    }

    Ok((records, has_more))
}

fn end_addr_idx_key(target_addr: &IpRange) -> Result<(Vec<u8>, Vec<u8>)> {
    // addr is always exist
    let ((Some(ip_addr), _) | (_, Some(ip_addr))) = (&target_addr.start, &target_addr.end) else {
        unreachable!()
    };
    let is_v4 = ip_addr.parse::<IpAddr>()?.is_ipv4();

    let start_addr_key = if let Some(ref start) = target_addr.start {
        addr_to_index_key(start.parse::<IpAddr>()?, false)
    } else if is_v4 {
        addr_to_index_key(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), false)
    } else {
        addr_to_index_key(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), false)
    };

    let end_addr_key = if let Some(ref end) = target_addr.end {
        addr_to_index_key(end.parse::<IpAddr>()?, true)
    } else if is_v4 {
        addr_to_index_key(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), true)
    } else {
        addr_to_index_key(
            IpAddr::V6(Ipv6Addr::new(
                65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            )),
            true,
        )
    };
    Ok((start_addr_key, end_addr_key))
}

fn end_port_idx_key(target_port: &PortRange) -> (Vec<u8>, Vec<u8>) {
    let start_port = target_port.start.unwrap_or(0);
    let end_port = if let Some(end_port) = target_port.end {
        end_port - 1
    } else {
        u16::MAX
    };
    (
        start_port.to_be_bytes().to_vec(),
        end_port.to_be_bytes().to_vec(),
    )
}

fn parse_datetimes_for_index(
    times: &Option<TimeRange>,
    idx_duration: Duration,
) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    let (start, end) = if let Some(time) = times {
        (time.start, time.end)
    } else {
        (None, None)
    };
    let max_range_time = chrono::Duration::from_std(idx_duration)? * TIME_RANGE_MULTI_UNIT;

    let (from_real_time, to_real_time) = match (start, end) {
        (Some(s), Some(e)) => {
            if e.signed_duration_since(s) > max_range_time {
                (s, s + max_range_time)
            } else {
                (s, e)
            }
        }
        (None, Some(e)) => (e - max_range_time, e),
        (Some(s), None) => (s, s + max_range_time),
        (None, None) => {
            let current_utc = Utc::now();
            (current_utc - max_range_time, current_utc)
        }
    };
    Ok((from_real_time, to_real_time))
}

#[cfg(test)]
struct TestSchema {
    _dir: tempfile::TempDir, // to prevent the data directory from being deleted while the test is running
    db: Database,
    schema: Schema,
}

#[cfg(test)]
impl TestSchema {
    fn new() -> Self {
        use crate::storage::DbOptions;
        use std::collections::HashMap;
        use tokio::sync::RwLock;

        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let packet_sources = Arc::new(RwLock::new(HashMap::new()));
        let export_dir = tempfile::tempdir().unwrap();
        let config_reload = Arc::new(Notify::new());
        let schema = schema(
            db.clone(),
            packet_sources,
            export_dir.path().to_path_buf(),
            config_reload,
            "file_path".to_string(),
            None,
        );
        Self {
            _dir: db_dir,
            db,
            schema,
        }
    }
    async fn execute(&self, query: &str) -> async_graphql::Response {
        let request: async_graphql::Request = query.into();
        self.schema.execute(request).await
    }
}
