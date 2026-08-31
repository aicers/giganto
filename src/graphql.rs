#[cfg(feature = "cluster")]
mod client;
#[cfg(feature = "bootroot")]
pub(crate) mod customer_deletion;
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

use std::{collections::BTreeSet, net::IpAddr, path::PathBuf, process::Stdio, sync::Arc};

use anyhow::anyhow;
use async_graphql::{
    EmptySubscription, InputObject, InputValueError, InputValueResult, MergedObject, OutputType,
    Result, Scalar, ScalarType, Value,
    connection::{Connection, Edge, query},
};
use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use giganto_client::ingest::Packet as pk;
use libc::timeval;
use pcap::{Capture, Linktype, Packet, PacketHeader};
use serde::{Serialize, de::DeserializeOwned};
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::sync::{Notify, mpsc::Sender};
use tracing::error;

#[cfg(feature = "bootroot")]
use crate::comm::{RunTimeIngestSensors, StreamDirectChannels};
use crate::datetime::DateTime;
#[cfg(feature = "cluster")]
pub(crate) use crate::graphql::client::cluster::{
    events_in_cluster, events_vec_in_cluster, paged_events_in_cluster,
};
#[cfg(not(feature = "cluster"))]
pub(crate) use crate::graphql::standalone::{
    events_in_cluster, events_vec_in_cluster, paged_events_in_cluster,
};
use crate::{
    cancellation::TaskTracker,
    comm::{IngestSensors, PcapSensors, ingest::implement::EventFilter, peer::Peers},
    settings::{ConfigVisible, Settings},
    storage::{
        Database, Direction, FilteredIter, KeyExtractor, KeyValue, RawEventStore, StorageKey,
        TimestampKeyExtractor, deletion_coordination::CustomerDeletionCoordinator,
    },
};

pub const TIMESTAMP_SIZE: usize = 8;
/// Note: The `unused` warning appears because this constant is only used in
/// `schema_should_be_up_to_date` (test code) and `gen_schema.rs` (an auxiliary binary), which are
/// not detected by the compiler as part of the main binary.
#[allow(unused)]
pub(crate) const SCHEMA_PATH: &str = "src/graphql/client/schema/schema.graphql";

/// Returns an immediately ready future for synchronous resolver paths.
pub(crate) fn ready<T>(value: T) -> std::future::Ready<T> {
    std::future::ready(value)
}

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
pub struct Mutation(
    status::ConfigMutation,
    #[cfg(feature = "bootroot")] customer_deletion::CustomerDeletionMutation,
);

/// Time range filter.
///
/// Range semantics:
/// - `start` is inclusive.
/// - `end` is exclusive.
/// - Omitting `start` means the range is unbounded below.
/// - Omitting `end` means the range is unbounded above.
#[derive(InputObject, Serialize, Clone, Debug)]
pub struct TimeRange {
    start: Option<DateTime>,
    end: Option<DateTime>,
}
/// IP address range filter.
///
/// Range semantics:
/// - `start` is inclusive.
/// - `end` is exclusive.
/// - Omitting `start` means the range is unbounded below.
/// - Omitting `end` means the range is unbounded above.
#[derive(InputObject, Serialize, Clone)]
pub struct IpRange {
    pub start: Option<String>,
    pub end: Option<String>,
}

/// Port range filter.
///
/// Range semantics:
/// - `start` is inclusive.
/// - `end` is exclusive.
/// - Omitting `start` means the range is unbounded below.
/// - Omitting `end` means the range is unbounded above.
#[derive(InputObject, Serialize, Clone)]
pub struct PortRange {
    pub start: Option<u16>,
    pub end: Option<u16>,
}

/// Filter options for network queries.
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
}

/// Filter options for Sysmon event queries.
#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct SysmonEventFilter {
    pub time: Option<TimeRange>,
    #[serde(skip)]
    pub sensor: String,
    agent_id: Option<String>,
}

/// Filter options for text search.
#[derive(InputObject, Serialize)]
pub struct SearchFilter {
    pub time: Option<TimeRange>,
    #[serde(skip)]
    pub sensor: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    pub times: Vec<DateTime>,
    /// Matches values that contain this keyword, case-insensitively.
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
        agent_id: Option<String>,
        service_name: Option<String>,
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

/// A web-owned [`TaskTracker`] the PCAP resolver registers `tcpdump`-reaping
/// tasks on when a request future is dropped (e.g. by the web graceful-shutdown
/// timeout).
///
/// It is a distinct newtype rather than the plain [`TaskTracker`] already in the
/// context so `ctx.data::<TaskTracker>()` keeps returning the top-level tracker
/// export registers on: async-graphql keys context data by type, so two bare
/// `TaskTracker` values would collide. Unlike that top-level tracker — cancelled
/// and drained *after* web shutdown — this one is drained by the generation as
/// part of web shutdown, before subsystem cancellation begins, so a timed-out
/// PCAP child is killed and reaped before the drain rather than as detached
/// best-effort work that can outlive web shutdown.
pub struct PcapReaperTracker(pub TaskTracker);

#[allow(clippy::too_many_arguments)]
pub fn schema(
    node_name: NodeName,
    database: Database,
    pcap_sensors: PcapSensors,
    ingest_sensors: IngestSensors,
    #[cfg(feature = "bootroot")] runtime_ingest_sensors: RunTimeIngestSensors,
    #[cfg(feature = "bootroot")] stream_direct_channels: StreamDirectChannels,
    #[cfg(feature = "bootroot")] peer_notify: Option<Arc<Notify>>,
    peers: Peers,
    request_client_pool: reqwest::Client,
    export_path: PathBuf,
    reload_tx: Sender<ConfigVisible>,
    notify_reboot: Arc<Notify>,
    notify_power_off: Arc<Notify>,
    notify_terminate: Arc<Notify>,
    settings: Settings,
    // The generation's top-level tracker, plumbed into the GraphQL context so a
    // detached export task can register itself in the same registry the
    // shutdown drain waits on. Registering it there is what makes an accepted
    // export finish before `database.shutdown()`; web-first shutdown is what
    // stops new export requests from arriving, so no separate refusal path is
    // added here.
    top_level_tracker: TaskTracker,
    // A separate web-owned tracker the PCAP resolver registers `tcpdump`-reaping
    // tasks on. The generation drains it as part of web shutdown, before it
    // cancels and drains the top-level tracker, so a request cut off by the web
    // graceful-shutdown timeout has its `tcpdump` child killed and reaped before
    // subsystem cancellation begins rather than left as detached work.
    pcap_reaper_tracker: TaskTracker,
    // The state customer deletion and retention agree on, shared with the
    // generation's retention entry task. It is in the context so the
    // `deleteCustomerData` resolver can claim the store before it persists a
    // job and hold the claim until the deletion is over.
    deletion_coordination: Arc<CustomerDeletionCoordinator>,
) -> Schema {
    let schema = Schema::build(Query::default(), Mutation::default(), EmptySubscription)
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
        .data(top_level_tracker)
        .data(PcapReaperTracker(pcap_reaper_tracker))
        .data(deletion_coordination);
    #[cfg(feature = "bootroot")]
    let schema = schema
        .data(runtime_ingest_sensors)
        .data(stream_direct_channels);
    #[cfg(feature = "bootroot")]
    let schema = if let Some(peer_notify) = peer_notify {
        schema.data(peer_notify)
    } else {
        schema
    };
    schema.finish()
}

/// The default page size for connections when neither `first` nor `last` is
/// provided. Maximum size: 100.
const MAXIMUM_PAGE_SIZE: usize = 100;
const A_BILLION: i64 = 1_000_000_000;

/// Converts a nanosecond timestamp to seconds and sub-second nanoseconds.
///
/// Returns a tuple of `(seconds, subsec_nanos)` where:
/// - `seconds` is the whole seconds portion
/// - `subsec_nanos` is the remaining nanoseconds (0 to 999,999,999)
#[inline]
fn timestamp_to_sec_nsec(timestamp_ns: i64) -> (i64, i64) {
    (timestamp_ns / A_BILLION, timestamp_ns % A_BILLION)
}

#[cfg(test)]
thread_local! {
    static SEARCH_CANDIDATE_DESERIALIZE_COUNT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_search_candidate_deserialize_count() {
    SEARCH_CANDIDATE_DESERIALIZE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn search_candidate_deserialize_count() -> usize {
    SEARCH_CANDIDATE_DESERIALIZE_COUNT.with(std::cell::Cell::get)
}

fn deserialize_search_candidate<T: DeserializeOwned>(value: &[u8]) -> Option<T> {
    #[cfg(test)]
    SEARCH_CANDIDATE_DESERIALIZE_COUNT.with(|count| count.set(count.get() + 1));
    bincode::deserialize(value).ok()
}

fn collect_exist_times<T>(
    target_data: &BTreeSet<(DateTime, Vec<u8>)>,
    filter: &SearchFilter,
) -> Vec<DateTime>
where
    T: EventFilter + DeserializeOwned,
{
    let (start, end) = time_range(filter.time.as_ref());
    target_data
        .iter()
        .filter_map(|(time, value)| {
            if *time < start || *time >= end {
                return None;
            }
            deserialize_search_candidate::<T>(value).and_then(|raw_event| {
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
                        raw_event.agent_id(),
                        raw_event.service_name(),
                    )
                    .map_or(None, |c| c.then_some(*time))
            })
        })
        .collect::<Vec<_>>()
}

fn time_range(time_range: Option<&TimeRange>) -> (DateTime, DateTime) {
    let (start, end) = if let Some(time) = time_range {
        (time.start, time.end)
    } else {
        (None, None)
    };
    let start = start.unwrap_or(DateTime::from_timestamp_nanos(i64::MIN));
    let end = end.unwrap_or(DateTime::from_timestamp_nanos(i64::MAX));
    (start, end)
}

/// Validates pagination argument combinations.
///
/// Pagination rules:
/// - `after` and `before` cannot be used together.
/// - `first` and `last` cannot be used together.
/// - `before` cannot be used with `first`.
/// - `after` cannot be used with `last`.
///
/// # Errors
///
/// Returns an error if the pagination arguments contain an unsupported
/// combination.
pub(crate) fn validate_pagination_args<A: ?Sized, B: ?Sized, F, L>(
    after: Option<&A>,
    before: Option<&B>,
    first: Option<&F>,
    last: Option<&L>,
) -> Result<()> {
    if before.is_some() && after.is_some() {
        return Err("cannot use both `after` and `before`".into());
    }
    if before.is_some() && first.is_some() {
        return Err("'before' and 'first' cannot be specified simultaneously".into());
    }
    if after.is_some() && last.is_some() {
        return Err("'after' and 'last' cannot be specified simultaneously".into());
    }
    if first.is_some() && last.is_some() {
        return Err("first and last cannot be used together".into());
    }
    Ok(())
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
    validate_pagination_args(
        after.as_ref(),
        before.as_ref(),
        first.as_ref(),
        last.as_ref(),
    )?;

    let (records, has_previous, has_next) = if let Some(before) = before {
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
    validate_pagination_args(
        after.as_ref(),
        before.as_ref(),
        first.as_ref(),
        last.as_ref(),
    )?;

    let (records, has_previous, has_next) = if let Some(before) = before {
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
            item.1.agent_id(),
            item.1.service_name(),
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

pub fn get_time_from_key_prefix(key: &[u8]) -> Result<DateTime, anyhow::Error> {
    if key.len() > TIMESTAMP_SIZE {
        let timestamp = i64::from_be_bytes(key[0..TIMESTAMP_SIZE].try_into()?);
        return Ok(DateTime::from_timestamp_nanos(timestamp));
    }
    Err(anyhow!("invalid database key length"))
}

pub fn get_time_from_key(key: &[u8]) -> Result<DateTime, anyhow::Error> {
    if key.len() > TIMESTAMP_SIZE {
        let nanos = i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
        return Ok(DateTime::from_timestamp_nanos(nanos));
    }
    Err(anyhow!("invalid database key length"))
}

fn get_peekable_iter<'c, T, F>(
    store: &RawEventStore<'c, T>,
    filter: &'c F,
    after: Option<&str>,
    before: Option<&str>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(std::iter::Peekable<FilteredIter<'c, T, F>>, usize)>
where
    T: DeserializeOwned + EventFilter,
    F: RawEventFilter + KeyExtractor,
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

#[allow(clippy::type_complexity)]
fn get_filtered_iter<'c, T, F>(
    store: &RawEventStore<'c, T>,
    filter: &'c F,
    after: Option<&str>,
    before: Option<&str>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(FilteredIter<'c, T, F>, Option<Vec<u8>>, usize)>
where
    T: DeserializeOwned + EventFilter,
    F: RawEventFilter + KeyExtractor,
{
    validate_pagination_args(
        after.as_ref(),
        before.as_ref(),
        first.as_ref(),
        last.as_ref(),
    )?;

    let (iter, cursor, size) = if let Some(before) = before {
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

/// Owns a running `tcpdump` child so a dropped request future both kills and
/// reaps it, with the reaping observable to web shutdown.
///
/// `kill_on_drop(true)` only *signals* the child when the handle drops; Tokio
/// documents that the follow-up reaping is best-effort, so a bare drop can leave
/// a zombie. This issue requires that a timed-out PCAP request kill *and* await
/// `tcpdump`, and that web shutdown be complete before subsystem cancellation
/// and drain. So this guard's `Drop` registers the `kill().await` on a
/// web-owned [`TaskTracker`] rather than a bare `tokio::spawn`: the generation
/// drains that tracker as part of web shutdown, before it cancels the tracked
/// subsystems, so the child is killed and reaped before the drain instead of by
/// detached work that could outlive `WebController::shutdown`. The normal path
/// disarms the guard (`child` set to `None`) after awaiting the child itself, so
/// `Drop` only reaps on cancellation.
///
/// `kill_on_drop(true)` is kept on the child as a last-resort backstop: if the
/// tracker is already closed (which web-first shutdown makes unreachable while a
/// PCAP request is in flight), registration fails, the reaping future is dropped
/// unpolled, and the signal-only drop is all that remains — no worse than the
/// pre-existing behavior.
struct ChildReaper {
    child: Option<tokio::process::Child>,
    tracker: TaskTracker,
}

impl Drop for ChildReaper {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let spawned = self
                .tracker
                .spawn("pcap-tcpdump-reaper", |_token| async move {
                    // `kill()` sends `SIGKILL` and then `wait()`s, reaping the child
                    // rather than merely signalling it. The token is ignored on
                    // purpose: cancellation must not abandon the child mid-reap.
                    if let Err(e) = child.kill().await {
                        tracing::warn!(
                            "failed to reap tcpdump child after a PCAP request was cancelled: {e}"
                        );
                    }
                });
            if let Err(e) = spawned {
                tracing::warn!(
                    "could not register tcpdump reaper on the web tracker ({e}); \
                     the child is left to `kill_on_drop`'s best-effort signalling"
                );
            }
        }
    }
}

/// Writes `packets` to a temporary pcap file and returns `tcpdump`'s parsed
/// output for it.
///
/// Cancellation and cleanup contract: the `NamedTempFile` is owned by this
/// future for its whole life, so it is removed on normal completion, on error,
/// and on cancellation — including when the web graceful-shutdown timeout drops
/// the in-flight PCAP request future at one of the `.await`s below. The
/// `tcpdump` child is held by a [`ChildReaper`] guard until it exits, so a
/// dropped future kills and *awaits* the child (reaping it, not merely
/// signalling it) rather than leaking a process. The reaping is registered on
/// `reaper_tracker`, a web-owned tracker the generation drains as part of web
/// shutdown, so the child is reaped before subsystem cancellation and drain.
/// Permitted loss: a cancelled PCAP request yields no pcap output, and nothing
/// durable is owed for it.
async fn write_run_tcpdump(
    packets: &Vec<pk>,
    reaper_tracker: TaskTracker,
) -> Result<String, anyhow::Error> {
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
        let (seconds, subsec_nanos) = timestamp_to_sec_nsec(packet.packet_timestamp);
        let header = PacketHeader {
            ts: timeval {
                tv_sec: seconds,
                #[cfg(target_os = "macos")]
                tv_usec: i32::try_from(subsec_nanos).unwrap_or_default(),
                #[cfg(target_os = "linux")]
                tv_usec: subsec_nanos,
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

    // `tokio::process::Command` keeps the parse off the runtime worker thread.
    // The child is spawned with its stdout piped so it can be read here, and is
    // moved into a `ChildReaper` guard so that if this future is dropped (e.g.
    // the web graceful-shutdown timeout cuts off the request), the child is
    // killed *and* awaited rather than surviving as an orphan or zombie.
    let mut child = tokio::process::Command::new(cmd)
        .env("PATH", "/usr/sbin:/usr/bin")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;

    // Take the stdout pipe before the child moves into the reaper.
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture tcpdump stdout"))?;
    let mut reaper = ChildReaper {
        child: Some(child),
        tracker: reaper_tracker,
    };

    // Read tcpdump's output to EOF, then wait for it to exit. Both awaits are
    // cancellation points; until they return the reaper owns the child, so a
    // dropped future kills and reaps it. (stderr is discarded via `Stdio::null`,
    // so it cannot fill a pipe and stall the read.)
    let mut stdout_buf = Vec::new();
    stdout.read_to_end(&mut stdout_buf).await?;
    let status = reaper
        .child
        .as_mut()
        .expect("set at construction and cleared only after this wait returns")
        .wait()
        .await?;

    // `tcpdump` has exited and been reaped on the normal path; disarm the reaper
    // so its `Drop` does not try to kill an already-finished child.
    reaper.child = None;

    // Keep the temporary input file alive until after `tcpdump` has finished
    // reading it; dropping it here (rather than relying on end-of-scope) makes
    // the ownership across the awaits explicit.
    drop(temp_file);

    if !status.success() {
        return Err(anyhow!("failed to run tcpdump"));
    }

    Ok(String::from_utf8_lossy(&stdout_buf).into_owned())
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
        (Some(_), None) => Ok(false),
        (None, _) => Ok(true),
    }
}

fn check_port(filter_port: Option<&PortRange>, target_port: Option<u16>) -> bool {
    match (filter_port, target_port) {
        (Some(port_range), Some(port)) => {
            let starts_after_or_at = port_range.start.is_none_or(|start| port >= start);
            let ends_before = port_range.end.is_none_or(|end| port < end);
            starts_after_or_at && ends_before
        }
        (Some(_), None) => false,
        (None, _) => true,
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

fn min_max_time(is_forward: bool) -> DateTime {
    if is_forward {
        DateTime::max_utc()
    } else {
        DateTime::min_utc()
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

// `pub(crate)` so the lifecycle tests in `main.rs` can build a schema: the
// customer-deletion shutdown property is about a generation's teardown, so it
// is proved where the teardown lives, against the real resolver.
#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::net::IpAddr;
    use std::sync::Arc;

    use async_graphql::EmptySubscription;
    use serde::{Deserialize, Serialize};
    use tokio::sync::Notify;

    use super::{
        ChildReaper, NodeName, Result, SearchFilter, StringNumberI64, StringNumberU32,
        StringNumberU64, StringNumberUsize, TIMESTAMP_SIZE, TimeRange, check_address,
        check_agent_id, check_contents, check_port, collect_exist_times, get_time_from_key,
        get_time_from_key_prefix, min_max_time, pk, reset_search_candidate_deserialize_count,
        schema, search_candidate_deserialize_count, time_range, write_run_tcpdump,
    };
    use crate::comm::{
        IngestSensors,
        ingest::implement::EventFilter,
        new_pcap_sensors,
        peer::{PeerInfo, Peers},
    };
    #[cfg(feature = "bootroot")]
    use crate::comm::{
        PcapSensors, RunTimeIngestSensors, StreamDirectChannels, new_runtime_ingest_sensors,
        new_stream_direct_channels,
    };
    use crate::datetime::DateTime;
    use crate::graphql::{IpRange, Mutation, PortRange, Query};
    use crate::settings::{ConfigVisible, Settings};
    use crate::storage::{Database, DbOptions, deletion_coordination::CustomerDeletionCoordinator};

    type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;

    const CURRENT_GIGANTO_INGEST_SENSORS: [&str; 3] = ["src1", "src 1", "ingest src 1"];
    const PEER_GIGANTO_2_INGEST_SENSORS: [&str; 3] = ["src2", "src 2", "ingest src 2"];

    pub struct TestSchema {
        pub _dir: tempfile::TempDir, // to prevent the data directory from being deleted while the test is running
        pub export_dir: tempfile::TempDir, // keep export directory alive for tests
        pub db: Database,
        pub schema: Schema,
        /// The generation tracker the schema was built with, so a test can
        /// close it the way shutdown does and drain it the way a generation
        /// teardown does.
        #[cfg(feature = "bootroot")]
        pub(crate) top_level_tracker: crate::cancellation::TaskTracker,
        /// The store claim the schema was built with, so a test can hold it
        /// the way a retention cycle or another customer's deletion does.
        #[cfg(feature = "bootroot")]
        pub(crate) deletion_coordination: Arc<CustomerDeletionCoordinator>,
        #[cfg(feature = "bootroot")]
        pub(crate) ingest_sensors: IngestSensors,
        #[cfg(feature = "bootroot")]
        pub(super) runtime_ingest_sensors: RunTimeIngestSensors,
        #[cfg(feature = "bootroot")]
        pub(super) pcap_sensors: PcapSensors,
        #[cfg(feature = "bootroot")]
        pub(super) stream_direct_channels: StreamDirectChannels,
    }

    impl TestSchema {
        fn setup(ingest_sensors: IngestSensors, peers: Peers) -> Self {
            Self::setup_with_node_name(
                ingest_sensors,
                peers,
                "giganto1",
                #[cfg(feature = "bootroot")]
                None,
            )
        }

        fn setup_with_node_name(
            ingest_sensors: IngestSensors,
            peers: Peers,
            node_name: &str,
            #[cfg(feature = "bootroot")] peer_notify: Option<Arc<Notify>>,
        ) -> Self {
            let db_dir = tempfile::tempdir().unwrap();
            let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
            let pcap_sensors = new_pcap_sensors();
            #[cfg(feature = "bootroot")]
            let runtime_ingest_sensors = new_runtime_ingest_sensors();
            #[cfg(feature = "bootroot")]
            let stream_direct_channels = new_stream_direct_channels();
            let request_client_pool = reqwest::Client::new();
            let export_dir = tempfile::tempdir().unwrap();
            let (reload_tx, _) = tokio::sync::mpsc::channel::<ConfigVisible>(1);
            let notify_reboot = Arc::new(Notify::new());
            let notify_power_off = Arc::new(Notify::new());
            let notify_terminate = Arc::new(Notify::new());
            let settings = Settings::load("tests/config.toml").unwrap();
            // Kept on the fixture, not built inline: the customer-deletion
            // tests drive the generation's shutdown boundary and the store
            // claim through these two, and both have to be the very ones the
            // schema resolves out of its context.
            let top_level_tracker = crate::cancellation::TaskTracker::new();
            let deletion_coordination = Arc::new(CustomerDeletionCoordinator::new());
            let schema = schema(
                NodeName(node_name.to_string()),
                db.clone(),
                #[cfg(feature = "bootroot")]
                pcap_sensors.clone(),
                #[cfg(not(feature = "bootroot"))]
                pcap_sensors,
                #[cfg(feature = "bootroot")]
                ingest_sensors.clone(),
                #[cfg(not(feature = "bootroot"))]
                ingest_sensors,
                #[cfg(feature = "bootroot")]
                runtime_ingest_sensors.clone(),
                #[cfg(feature = "bootroot")]
                stream_direct_channels.clone(),
                #[cfg(feature = "bootroot")]
                peer_notify,
                peers,
                request_client_pool,
                export_dir.path().to_path_buf(),
                reload_tx,
                notify_reboot,
                notify_power_off,
                notify_terminate,
                settings,
                top_level_tracker.clone(),
                crate::cancellation::TaskTracker::new(),
                Arc::clone(&deletion_coordination),
            );

            Self {
                _dir: db_dir,
                export_dir,
                db,
                schema,
                #[cfg(feature = "bootroot")]
                top_level_tracker,
                #[cfg(feature = "bootroot")]
                deletion_coordination,
                #[cfg(feature = "bootroot")]
                ingest_sensors,
                #[cfg(feature = "bootroot")]
                runtime_ingest_sensors,
                #[cfg(feature = "bootroot")]
                pcap_sensors,
                #[cfg(feature = "bootroot")]
                stream_direct_channels,
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

        #[cfg(feature = "bootroot")]
        pub fn new_with_node_name(node_name: &str) -> Self {
            let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
                CURRENT_GIGANTO_INGEST_SENSORS
                    .into_iter()
                    .map(str::to_string)
                    .collect::<HashSet<String>>(),
            ));

            let peers = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
            Self::setup_with_node_name(ingest_sensors, peers, node_name, None)
        }

        #[cfg(feature = "bootroot")]
        pub(crate) fn new_with_ingest_sensors(sensors: &[&str]) -> Self {
            Self::new_with_ingest_sensors_and_peer_notify(sensors, None)
        }

        #[cfg(feature = "bootroot")]
        pub(super) fn new_with_ingest_sensors_and_peer_notify(
            sensors: &[&str],
            peer_notify: Option<Arc<Notify>>,
        ) -> Self {
            let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
                sensors
                    .iter()
                    .map(|sensor| (*sensor).to_string())
                    .collect::<HashSet<String>>(),
            ));
            Self::new_with_shared_ingest_sensors_and_peer_notify(ingest_sensors, peer_notify)
        }

        #[cfg(feature = "bootroot")]
        pub(super) fn new_with_shared_ingest_sensors_and_peer_notify(
            ingest_sensors: IngestSensors,
            peer_notify: Option<Arc<Notify>>,
        ) -> Self {
            let peers = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
            Self::setup_with_node_name(ingest_sensors, peers, "giganto1", peer_notify)
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
    #[ignore = "Run only in the schema check step"]
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
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid digit found in string"));

        // Test empty string
        let json_str = r#""""#;
        let result: Result<StringNumberU64, _> = serde_json::from_str(json_str);
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot parse integer from empty string"));

        // Test overflow for u32
        let json_str = r#""99999999999999999999""#;
        let result: Result<StringNumberU32, _> = serde_json::from_str(json_str);
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("number too large to fit in target type"));
    }

    #[test]
    fn test_check_address_with_bounded_range() {
        let filter = IpRange {
            start: Some("192.168.0.1".to_string()),
            end: Some("192.168.0.3".to_string()),
        };

        assert!(check_address(Some(&filter), Some("192.168.0.1".parse().unwrap())).unwrap());
        assert!(!check_address(Some(&filter), Some("192.168.0.3".parse().unwrap())).unwrap());
    }

    #[test]
    fn test_check_address_with_open_ended_range() {
        let start_only_filter = IpRange {
            start: Some("192.168.0.1".to_string()),
            end: None,
        };
        let end_only_filter = IpRange {
            start: None,
            end: Some("192.168.0.3".to_string()),
        };

        assert!(
            check_address(
                Some(&start_only_filter),
                Some("192.168.0.1".parse().unwrap())
            )
            .unwrap()
        );
        assert!(
            !check_address(
                Some(&start_only_filter),
                Some("192.168.0.0".parse().unwrap())
            )
            .unwrap()
        );
        assert!(
            check_address(Some(&end_only_filter), Some("192.168.0.2".parse().unwrap())).unwrap()
        );
        assert!(
            !check_address(Some(&end_only_filter), Some("192.168.0.3".parse().unwrap())).unwrap()
        );
    }

    #[test]
    fn test_check_address_with_missing_target_or_filter() {
        let filter = IpRange {
            start: Some("192.168.0.1".to_string()),
            end: Some("192.168.0.3".to_string()),
        };

        assert!(!check_address(Some(&filter), None).unwrap());
        assert!(check_address(None, Some("192.168.0.1".parse().unwrap())).unwrap());
        assert!(check_address(None, None).unwrap());
    }

    #[test]
    fn test_check_port_with_bounded_range() {
        let filter = PortRange {
            start: Some(1000),
            end: Some(1002),
        };

        assert!(check_port(Some(&filter), Some(1000)));
        assert!(!check_port(Some(&filter), Some(1002)));
    }

    #[test]
    fn test_check_port_with_open_ended_range() {
        let start_only_filter = PortRange {
            start: Some(1000),
            end: None,
        };
        let end_only_filter = PortRange {
            start: None,
            end: Some(1002),
        };

        assert!(check_port(Some(&start_only_filter), Some(1000)));
        assert!(!check_port(Some(&start_only_filter), Some(999)));
        assert!(check_port(Some(&end_only_filter), Some(1001)));
        assert!(!check_port(Some(&end_only_filter), Some(1002)));
    }

    #[test]
    fn test_check_port_with_missing_target_or_filter() {
        let filter = PortRange {
            start: Some(1000),
            end: Some(1002),
        };

        assert!(!check_port(Some(&filter), None));
        assert!(check_port(None, Some(1000)));
        assert!(check_port(None, None));
    }

    #[test]
    fn timestamp_to_sec_nsec_converts_correctly() {
        use super::timestamp_to_sec_nsec;

        // Test with a timestamp that has both seconds and nanoseconds
        // 1_234_567_890_123_456_789 ns = 1_234_567_890 seconds + 123_456_789 nanoseconds
        let timestamp = 1_234_567_890_123_456_789_i64;
        let (seconds, subsec_nanos) = timestamp_to_sec_nsec(timestamp);
        assert_eq!(seconds, 1_234_567_890);
        assert_eq!(subsec_nanos, 123_456_789);

        // Verify roundtrip: seconds * 1_000_000_000 + subsec_nanos == original timestamp
        assert_eq!(seconds * 1_000_000_000 + subsec_nanos, timestamp);
    }

    #[test]
    fn timestamp_to_sec_nsec_handles_edge_cases() {
        use super::timestamp_to_sec_nsec;

        // Test with exactly one second (no sub-second portion)
        let timestamp = 1_000_000_000_i64;
        let (seconds, subsec_nanos) = timestamp_to_sec_nsec(timestamp);
        assert_eq!(seconds, 1);
        assert_eq!(subsec_nanos, 0);

        // Test with only nanoseconds (less than one second)
        let timestamp = 500_000_000_i64; // 0.5 seconds
        let (seconds, subsec_nanos) = timestamp_to_sec_nsec(timestamp);
        assert_eq!(seconds, 0);
        assert_eq!(subsec_nanos, 500_000_000);

        // Test with zero
        let timestamp = 0_i64;
        let (seconds, subsec_nanos) = timestamp_to_sec_nsec(timestamp);
        assert_eq!(seconds, 0);
        assert_eq!(subsec_nanos, 0);

        // Test with max nanoseconds before rolling over to next second
        let timestamp = 999_999_999_i64;
        let (seconds, subsec_nanos) = timestamp_to_sec_nsec(timestamp);
        assert_eq!(seconds, 0);
        assert_eq!(subsec_nanos, 999_999_999);

        // Test that subsec_nanos is always less than 1 billion
        let timestamp = 5_999_999_999_i64; // 5.999999999 seconds
        let (seconds, subsec_nanos) = timestamp_to_sec_nsec(timestamp);
        assert_eq!(seconds, 5);
        assert_eq!(subsec_nanos, 999_999_999);
        assert!(subsec_nanos < 1_000_000_000);
    }

    #[test]
    fn time_range_defaults_and_missing_bounds() {
        let (start, end) = time_range(None);
        assert_eq!(start, DateTime::from_timestamp_nanos(i64::MIN));
        assert_eq!(end, DateTime::from_timestamp_nanos(i64::MAX));

        let start = DateTime::from("2024-01-01T00:00:00Z".parse::<jiff::Timestamp>().unwrap());
        let time = TimeRange {
            start: Some(start),
            end: None,
        };
        let (range_start, range_end) = time_range(Some(&time));
        assert_eq!(range_start, start);
        assert_eq!(range_end, DateTime::from_timestamp_nanos(i64::MAX));

        let end = DateTime::from("2024-01-02T00:00:00Z".parse::<jiff::Timestamp>().unwrap());
        let time = TimeRange {
            start: None,
            end: Some(end),
        };
        let (range_start, range_end) = time_range(Some(&time));
        assert_eq!(range_start, DateTime::from_timestamp_nanos(i64::MIN));
        assert_eq!(range_end, end);

        let start = DateTime::from("2024-01-01T00:00:00Z".parse::<jiff::Timestamp>().unwrap());
        let end = DateTime::from("2024-01-02T00:00:00Z".parse::<jiff::Timestamp>().unwrap());
        let time = TimeRange {
            start: Some(start),
            end: Some(end),
        };
        let (range_start, range_end) = time_range(Some(&time));
        assert_eq!(range_start, start);
        assert_eq!(range_end, end);
    }

    #[test]
    fn timestamp_to_sec_nsec_modulo_vs_bitwise_and() {
        use super::timestamp_to_sec_nsec;

        // This test demonstrates why modulo (%) is correct and bitwise AND (&) is wrong
        // for extracting the sub-second nanosecond portion from a timestamp.
        //
        // Using 1_000_000_000 as both a divisor and a mask:
        // - Modulo (%) gives the remainder: correct for extracting sub-second part
        // - Bitwise AND (&) gives bits that match: INCORRECT for decimal values
        //
        // Example: 1_234_567_890_123_456_789 ns
        // Correct (modulo): 123_456_789 ns
        // Wrong (bitwise AND): would give a corrupted value

        let timestamp = 1_234_567_890_123_456_789_i64;
        let a_billion: i64 = 1_000_000_000;

        // Correct calculation using modulo
        let correct_nsec = timestamp % a_billion;
        assert_eq!(correct_nsec, 123_456_789);

        // Incorrect calculation using bitwise AND (the bug we fixed)
        let wrong_nsec = timestamp & a_billion;
        // This produces a different value because 1_000_000_000 in binary is
        // 0b00111011_10011010_11001010_00000000, and bitwise AND with this
        // does not correctly extract the decimal remainder.
        assert_ne!(wrong_nsec, 123_456_789);
        assert_ne!(correct_nsec, wrong_nsec);

        // Verify our helper function uses the correct calculation
        let (_, subsec_nanos) = timestamp_to_sec_nsec(timestamp);
        assert_eq!(subsec_nanos, correct_nsec);
    }

    #[test]
    fn test_get_time_from_key_prefix() {
        let timestamp = 1_700_000_000_123_456_789_i64;
        let mut key = Vec::new();
        key.extend_from_slice(&timestamp.to_be_bytes());
        key.extend_from_slice(&[1, 2, 3, 4]);

        let time = get_time_from_key_prefix(&key).unwrap();
        assert_eq!(time, DateTime::from_timestamp_nanos(timestamp));

        let too_short = vec![0u8; TIMESTAMP_SIZE];
        let err = get_time_from_key_prefix(&too_short).unwrap_err();
        assert_eq!(err.to_string(), "invalid database key length");
    }

    #[test]
    fn test_get_time_from_key() {
        let timestamp = 1_700_000_001_987_654_321_i64;
        let mut key = vec![0xAB, 0xCD, 0xEF];
        key.extend_from_slice(&timestamp.to_be_bytes());

        let time = get_time_from_key(&key).unwrap();
        assert_eq!(time, DateTime::from_timestamp_nanos(timestamp));

        let too_short = vec![0u8; TIMESTAMP_SIZE];
        let err = get_time_from_key(&too_short).unwrap_err();
        assert_eq!(err.to_string(), "invalid database key length");
    }

    #[tokio::test]
    async fn test_write_run_tcpdump() {
        let packet = |timestamp, len| pk {
            packet_timestamp: timestamp,
            packet: vec![0u8; len],
        };
        let packets = vec![
            packet(1_700_049_600_123_456_789_i64, 60),
            packet(1_700_049_601_987_654_321_i64, 64),
        ];
        let tracker = crate::cancellation::TaskTracker::new();
        let output = write_run_tcpdump(&packets, tracker.clone()).await.unwrap();
        assert!(!output.is_empty());
        assert!(output.contains("2023-11-15"));
        assert!(output.contains("123456"));
        assert!(output.contains("987654"));
        assert!(output.contains("0x0000"));

        let out_empty = write_run_tcpdump(&vec![], tracker).await.unwrap();
        assert!(out_empty.is_empty());
    }

    /// A dropped `ChildReaper` must register its child's kill-and-reap on the
    /// web tracker, and *draining that tracker must await the reaping* — the
    /// exact lifecycle a timed-out PCAP request drives: the web graceful-shutdown
    /// timeout drops the request future, and the generation then drains this
    /// web-owned tracker as part of web shutdown before it cancels and drains the
    /// tracked subsystems. A long-lived `sleep` stands in for a `tcpdump` that
    /// has not finished, so the reaping is observed deterministically instead of
    /// racing the millisecond-scale `tcpdump` runs the happy-path test uses.
    ///
    /// The assertion after the drain uses no polling: because `drain` awaits the
    /// reaper task, which `wait()`s on the child, the pid must already be gone
    /// once `drain` returns. A child that was only signalled (not awaited) would
    /// linger as a zombie, for which `kill(pid, 0)` still returns `0`.
    #[tokio::test]
    async fn child_reaper_reaping_is_awaited_by_tracker_drain() {
        use std::time::Duration;

        use crate::cancellation::TaskTracker;

        let tracker = TaskTracker::new();

        let child = tokio::process::Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sleep");
        let pid = i32::try_from(child.id().expect("child pid")).expect("pid fits in pid_t");

        // The child is running: `kill(pid, 0)` probes for its existence.
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            0,
            "the child should be running before the reaper drops"
        );

        // Dropping the reaper registers the kill-and-reap on the tracker, exactly
        // as the dropped PCAP request future does at the graceful-shutdown
        // timeout.
        drop(ChildReaper {
            child: Some(child),
            tracker: tracker.clone(),
        });

        // Drain the tracker the way the generation drains the web reaper tracker
        // during web shutdown. Draining awaits the reaper, so once it returns the
        // child has been killed and reaped.
        tracker.close().expect("close the reaper tracker");
        let outcome = tracker
            .drain(Duration::from_secs(10))
            .await
            .expect("drain the reaper tracker");
        assert!(
            matches!(outcome, crate::cancellation::DrainOutcome::Drained),
            "the reaper must finish within the drain, got {outcome:?}"
        );

        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "after the tracker drain the child must be killed and reaped, leaving no zombie"
        );
    }

    #[test]
    fn test_check_address() {
        let filter = IpRange {
            start: Some("192.168.0.1".to_string()),
            end: Some("192.168.0.3".to_string()),
        };

        let in_range = check_address(Some(&filter), Some("192.168.0.1".parse().unwrap())).unwrap();
        assert!(in_range);

        let end_exclusive =
            check_address(Some(&filter), Some("192.168.0.3".parse().unwrap())).unwrap();
        assert!(!end_exclusive);

        let no_filter = check_address(None, None).unwrap();
        assert!(no_filter);
    }

    #[test]
    fn test_check_address_invalid_ip_string() {
        let filter = IpRange {
            start: Some("invalid-ip".to_string()),
            end: Some("192.168.0.3".to_string()),
        };

        let err = check_address(Some(&filter), Some("192.168.0.1".parse().unwrap())).unwrap_err();
        let msg = err.message;
        assert!(msg.contains("invalid IP address syntax"));
    }

    #[test]
    fn test_check_address_invalid_ip_string_end() {
        let filter = IpRange {
            start: Some("192.168.0.1".to_string()),
            end: Some("invalid-ip".to_string()),
        };

        let err = check_address(Some(&filter), Some("192.168.0.1".parse().unwrap())).unwrap_err();
        let msg = err.message;
        assert!(msg.contains("invalid IP address syntax"));
    }

    #[test]
    fn test_check_port() {
        let filter = PortRange {
            start: Some(1000),
            end: Some(1002),
        };

        assert!(check_port(Some(&filter), Some(1000)));
        assert!(!check_port(Some(&filter), Some(1002)));
        assert!(check_port(None, Some(1000)));
        assert!(check_port(None, None));
    }

    #[test]
    fn test_check_contents() {
        assert!(check_contents(None, None));
        assert!(check_contents(
            Some("needle"),
            Some("haystack needle".to_string())
        ));
        assert!(!check_contents(
            Some("needle"),
            Some("haystack".to_string())
        ));
        assert!(!check_contents(Some("needle"), None));
        assert!(check_contents(None, Some("haystack".to_string())));
    }

    #[test]
    fn test_check_agent_id() {
        assert!(check_agent_id(Some("agent-1"), Some("agent-1")));
        assert!(!check_agent_id(Some("agent-1"), Some("agent-2")));
        assert!(!check_agent_id(Some("agent-1"), None));
        assert!(check_agent_id(None, Some("agent-1")));
        assert!(check_agent_id(None, None));
    }

    #[test]
    fn test_min_max_time() {
        assert_eq!(min_max_time(true), DateTime::max_utc());
        assert_eq!(min_max_time(false), DateTime::min_utc());
    }

    #[derive(Serialize, Deserialize)]
    struct DummyEvent {
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
        text: Option<String>,
        agent_id: Option<String>,
    }

    impl EventFilter for DummyEvent {
        fn data_type(&self) -> String {
            "dummy".to_string()
        }
        fn orig_addr(&self) -> Option<IpAddr> {
            self.orig_addr
        }
        fn resp_addr(&self) -> Option<IpAddr> {
            self.resp_addr
        }
        fn orig_port(&self) -> Option<u16> {
            self.orig_port
        }
        fn resp_port(&self) -> Option<u16> {
            self.resp_port
        }
        fn log_level(&self) -> Option<String> {
            None
        }
        fn log_contents(&self) -> Option<String> {
            None
        }
        fn text(&self) -> Option<String> {
            self.text.clone()
        }
        fn agent_id(&self) -> Option<String> {
            self.agent_id.clone()
        }
    }

    #[test]
    fn collect_exist_times_filters_by_time_and_search_filter() {
        let t1 = DateTime::from("2023-01-01T00:00:00Z".parse::<jiff::Timestamp>().unwrap());
        let t2 = DateTime::from("2023-01-01T00:01:00Z".parse::<jiff::Timestamp>().unwrap());
        let t3 = DateTime::from("2023-01-01T00:02:00Z".parse::<jiff::Timestamp>().unwrap());
        let t4 = DateTime::from("2023-01-01T00:03:00Z".parse::<jiff::Timestamp>().unwrap());

        let mut target_data = BTreeSet::new();
        let ok_event = DummyEvent {
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            text: Some("haystack needle".to_string()),
            agent_id: Some("agent-1".to_string()),
        };
        target_data.insert((t1, bincode::serialize(&ok_event).unwrap()));

        let no_keyword_match = DummyEvent {
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            text: Some("no match".to_string()),
            agent_id: Some("agent-1".to_string()),
        };
        target_data.insert((t2, bincode::serialize(&no_keyword_match).unwrap()));

        let wrong_agent = DummyEvent {
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            text: Some("needle".to_string()),
            agent_id: Some("agent-2".to_string()),
        };
        target_data.insert((t2, bincode::serialize(&wrong_agent).unwrap()));

        let end_boundary = DummyEvent {
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            text: Some("needle".to_string()),
            agent_id: Some("agent-1".to_string()),
        };
        target_data.insert((t3, bincode::serialize(&end_boundary).unwrap()));

        let out_of_range = DummyEvent {
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            text: Some("needle".to_string()),
            agent_id: Some("agent-1".to_string()),
        };
        target_data.insert((t4, bincode::serialize(&out_of_range).unwrap()));

        target_data.insert((t2, vec![0, 1, 2, 3]));

        let filter = SearchFilter {
            time: Some(TimeRange {
                start: Some(t1),
                end: Some(t3),
            }),
            sensor: "src 1".to_string(),
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            times: Vec::new(),
            keyword: Some("needle".to_string()),
            agent_id: Some("agent-1".to_string()),
        };

        let result = collect_exist_times::<DummyEvent>(&target_data, &filter);
        assert_eq!(result, vec![t1]);
    }

    #[test]
    fn collect_exist_times_skips_deserialization_for_out_of_range_candidates() {
        let in_range = DateTime::from("2023-01-01T00:01:00Z".parse::<jiff::Timestamp>().unwrap());
        let out_of_range =
            DateTime::from("2023-01-01T00:05:00Z".parse::<jiff::Timestamp>().unwrap());

        let matching_event = DummyEvent {
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            text: Some("needle".to_string()),
            agent_id: Some("agent-1".to_string()),
        };
        let serialized = bincode::serialize(&matching_event).unwrap();

        let out_of_range_base = out_of_range.timestamp_nanos_opt().unwrap();
        let mut target_data = BTreeSet::new();
        target_data.insert((in_range, serialized.clone()));
        for offset in 0..100 {
            let time = DateTime::from_timestamp_nanos(out_of_range_base + offset);
            target_data.insert((time, serialized.clone()));
        }

        let filter = SearchFilter {
            time: Some(TimeRange {
                start: Some(in_range),
                end: Some(DateTime::from(
                    "2023-01-01T00:02:00Z".parse::<jiff::Timestamp>().unwrap(),
                )),
            }),
            sensor: "src 1".to_string(),
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            times: Vec::new(),
            keyword: Some("needle".to_string()),
            agent_id: Some("agent-1".to_string()),
        };

        reset_search_candidate_deserialize_count();
        let result = collect_exist_times::<DummyEvent>(&target_data, &filter);

        assert_eq!(result, vec![in_range]);
        assert_eq!(search_candidate_deserialize_count(), 1);
    }

    #[test]
    fn collect_exist_times_deserializes_all_candidates_when_time_filter_is_none() {
        let t1 = DateTime::from("2023-01-01T00:01:00Z".parse::<jiff::Timestamp>().unwrap());
        let t2 = DateTime::from("2023-01-01T00:05:00Z".parse::<jiff::Timestamp>().unwrap());

        let event = DummyEvent {
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            text: Some("needle".to_string()),
            agent_id: None,
        };
        let serialized = bincode::serialize(&event).unwrap();

        let mut target_data = BTreeSet::new();
        target_data.insert((t1, serialized.clone()));
        target_data.insert((t2, serialized));

        let filter = SearchFilter {
            time: None,
            sensor: "src 1".to_string(),
            orig_addr: None,
            resp_addr: None,
            orig_port: None,
            resp_port: None,
            times: Vec::new(),
            keyword: Some("needle".to_string()),
            agent_id: None,
        };

        reset_search_candidate_deserialize_count();
        let result = collect_exist_times::<DummyEvent>(&target_data, &filter);

        assert_eq!(result, vec![t1, t2]);
        assert_eq!(search_candidate_deserialize_count(), 2);
    }

    #[test]
    fn validate_pagination_args_rejects_before_and_first() {
        let result =
            super::validate_pagination_args(None::<&str>, Some(&"cursor"), Some(&10), None::<&i32>);
        let err = result.unwrap_err();
        assert_eq!(
            err.message,
            "'before' and 'first' cannot be specified simultaneously"
        );
    }

    #[test]
    fn validate_pagination_args_rejects_after_and_last() {
        let result =
            super::validate_pagination_args(Some(&"cursor"), None::<&str>, None::<&i32>, Some(&10));
        let err = result.unwrap_err();
        assert_eq!(
            err.message,
            "'after' and 'last' cannot be specified simultaneously"
        );
    }

    #[test]
    fn validate_pagination_args_rejects_after_and_before() {
        let result = super::validate_pagination_args(
            Some(&"cursor_a"),
            Some(&"cursor_b"),
            None::<&i32>,
            None::<&i32>,
        );
        let err = result.unwrap_err();
        assert_eq!(err.message, "cannot use both `after` and `before`");
    }

    #[test]
    fn validate_pagination_args_rejects_first_and_last() {
        let result =
            super::validate_pagination_args(None::<&str>, None::<&str>, Some(&10), Some(&5));
        let err = result.unwrap_err();
        assert_eq!(err.message, "first and last cannot be used together");
    }

    #[test]
    fn validate_pagination_args_accepts_valid_combinations() {
        // first only
        assert!(
            super::validate_pagination_args(None::<&str>, None::<&str>, Some(&10), None::<&i32>,)
                .is_ok()
        );

        // last only
        assert!(
            super::validate_pagination_args(None::<&str>, None::<&str>, None::<&i32>, Some(&10),)
                .is_ok()
        );

        // after + first
        assert!(super::validate_pagination_args(
            Some(&"cursor"),
            None::<&str>,
            Some(&10),
            None::<&i32>,
        )
        .is_ok());

        // before + last
        assert!(super::validate_pagination_args(
            None::<&str>,
            Some(&"cursor"),
            None::<&i32>,
            Some(&10),
        )
        .is_ok());

        // no args
        assert!(super::validate_pagination_args(
            None::<&str>,
            None::<&str>,
            None::<&i32>,
            None::<&i32>,
        )
        .is_ok());
    }
}
