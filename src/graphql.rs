mod client;
mod export;
mod log;
mod netflow;
pub mod network;
mod packet;
mod security;
mod sensor;
pub mod statistics;
pub mod status;
mod sysmon;
mod timeseries;

use std::{
    collections::{BTreeSet, HashSet},
    io::{Read, Seek, SeekFrom, Write},
    net::IpAddr,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};

use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    Context, EmptySubscription, Error, InputObject, MergedObject, OutputType, Result,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use chrono::{DateTime, TimeZone, Utc};
use giganto_client::ingest::Packet as pk;
use graphql_client::Response as GraphQlResponse;
use libc::timeval;
use num_traits::AsPrimitive;
use pcap::{Capture, Linktype, Packet, PacketHeader};
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use tempfile::NamedTempFile;
use tokio::sync::{mpsc::Sender, Notify};
use tracing::error;

use crate::{
    ingest::implement::EventFilter,
    peer::Peers,
    settings::Settings,
    storage::{
        Database, Direction, FilteredIter, KeyExtractor, KeyValue, RawEventStore, StorageKey,
    },
    AckTransmissionCount, IngestSensors, PcapSensors,
};

pub const TIMESTAMP_SIZE: usize = 8;

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

#[derive(InputObject, Serialize, Clone)]
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
    pub timestamps: Vec<DateTime<Utc>>,
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
    ) -> Result<bool>;
}

pub trait FromKeyValue<T>: Sized {
    fn from_key_value(key: &[u8], value: T) -> Result<Self>;
}

pub trait ClusterSortKey {
    fn secondary(&self) -> Option<&str>;
}

pub type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;
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
    reload_tx: Sender<String>,
    notify_reboot: Arc<Notify>,
    notify_power_off: Arc<Notify>,
    notify_terminate: Arc<Notify>,
    ack_transmission_cnt: AckTransmissionCount,
    is_local_config: bool,
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
        .data(ack_transmission_cnt)
        .data(TerminateNotify(notify_terminate))
        .data(RebootNotify(notify_reboot))
        .data(PowerOffNotify(notify_power_off))
        .data(is_local_config)
        .data(settings)
        .finish()
}

/// The default page size for connections when neither `first` nor `last` is
/// provided. Maximum size: 100.
const MAXIMUM_PAGE_SIZE: usize = 100;
const A_BILLION: i64 = 1_000_000_000;

fn collect_exist_timestamp<T>(
    target_data: &BTreeSet<(DateTime<Utc>, Vec<u8>)>,
    filter: &SearchFilter,
) -> Vec<DateTime<Utc>>
where
    T: EventFilter + DeserializeOwned,
{
    let (start, end) = time_range(filter.time.as_ref());
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
                            raw_event.sensor(),
                            raw_event.agent_id(),
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
        ) {
            records.push(item);
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

fn get_peekable_iter<'c, T>(
    store: &RawEventStore<'c, T>,
    filter: &'c NetworkFilter,
    after: Option<&String>,
    before: Option<&String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(std::iter::Peekable<FilteredIter<'c, T>>, usize)>
where
    T: DeserializeOwned + EventFilter,
{
    let (filtered_iter, cursor, size) =
        get_filtered_iter(store, filter, after, before, first, last)?;
    let mut filtered_iter = filtered_iter.peekable();
    if let Some(cursor) = cursor {
        if let Some((key, _)) = filtered_iter.peek() {
            if key.as_ref() == cursor {
                filtered_iter.next();
            }
        }
    }
    Ok((filtered_iter, size))
}

fn get_filtered_iter<'c, T>(
    store: &RawEventStore<'c, T>,
    filter: &'c NetworkFilter,
    after: Option<&String>,
    before: Option<&String>,
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
    let mut temp_file = NamedTempFile::new()?;
    let file_path = temp_file.path();
    let new_pcap = Capture::dead_with_precision(Linktype::ETHERNET, pcap::Precision::Nano)?;
    let mut file = new_pcap.savefile(file_path)?;

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

fn check_address(filter_addr: Option<&IpRange>, target_addr: Option<IpAddr>) -> Result<bool> {
    if let Some(ip_range) = filter_addr {
        if let Some(addr) = target_addr {
            if let Some(start) = ip_range.start.as_deref() {
                if let Some(end) = ip_range.end.as_deref() {
                    if addr >= start.parse::<IpAddr>()? && addr < end.parse::<IpAddr>()? {
                        return Ok(true);
                    }
                    return Ok(false);
                }
                if addr == start.parse::<IpAddr>()? {
                    return Ok(true);
                }
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn check_port(filter_port: Option<&PortRange>, target_port: Option<u16>) -> bool {
    if let Some(port_range) = filter_port {
        if let Some(port) = target_port {
            if let Some(start) = port_range.start {
                if let Some(end) = port_range.end {
                    return port >= start && port < end;
                }
                return port == start;
            }
        }
    }
    true
}

fn check_contents(filter_str: Option<&String>, target_str: Option<String>) -> bool {
    filter_str.as_ref().map_or(true, |filter_str| {
        target_str.map_or(false, |contents| contents.contains(*filter_str))
    })
}

fn check_agent_id(filter_agent_id: Option<&String>, target_agent_id: Option<&String>) -> bool {
    filter_by_str(filter_agent_id, target_agent_id)
}

fn filter_by_str(filter_str: Option<&String>, target_str: Option<&String>) -> bool {
    filter_str.as_ref().map_or(true, |filter_id| {
        target_str
            .as_ref()
            .map_or(false, |agent_id| agent_id == filter_id)
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

// This macro helps to reduce boilerplate for handling
// `search_[something]_events` APIs in giganto cluster. If the current giganto
// is in charge of the given `filter.sensor`, it will execute the handler
// locally. Otherwise, it will forward the request to a peer giganto in charge
// of the given `filter.sensor`. Peer giganto's response will be converted to
// the return type of the current giganto.
//
// Below is detailed explanation of arguments:
// * `$ctx` - The context of the GraphQL query.
// * `$filter` - The filter of the query.
// * `$sensor` - The sensor of the query.
// * `$handler` - The handler to be carried out by the current giganto if it is
//   in charge.
// * `$graphql_query_type` - Name of the struct that derives `GraphQLQuery`.
// * `$variables_type` - Query variable type generated by `graphql_client`. For
//   example, `search_conn_raw_events::Variables`.
// * `$response_data_type` - Response data type generated by `graphql_client`.
//   For example, `search_conn_raw_events::ResponseData`.
// * `$field_name` - Name of the field in the response data that contains the
//   result. For example, `search_conn_raw_events`.
// * `$result_type` - The type to which the response data will be converted.
// * `with_extra_handler_args ($($handler_arg:expr ),* )` - Extra arguments to
//  be passed to the handler. For example, `with_extra_handler_args (after,
//  before, first, last)`.
// * `with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* )` -
//  Extra arguments to be passed to the GraphQL query variables. For example,
//  `with_extra_query_args (after := after, before := before, first := first,
//  last := last)`.
//
// For your information, `$variables_type`, `$response_data_type`, `$field_name`
// are generated by `graphql_client` macro. You can `cargo expand` to see the
// generated code.
macro_rules! events_in_cluster {
    ($ctx:expr,
     $filter:expr,
     $sensor:expr,
     $handler:ident,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident,
     $result_type:tt
     $(, with_extra_handler_args ($($handler_arg:expr ),* ))?
     $(, with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* ))? ) => {{
        type QueryVariables = $variables_type;
        if crate::graphql::is_current_giganto_in_charge($ctx, &$sensor).await {
            $handler($ctx, &$filter, $($($handler_arg)*)*)
        } else {
            let peer_addr = crate::graphql::peer_in_charge_graphql_addr($ctx, &$sensor).await;

            match peer_addr {
                Some(peer_addr) => {
                    #[allow(clippy::redundant_field_names)]
                    let request_body = $graphql_query_type::build_query(QueryVariables {
                        filter: $filter.into(),
                        $($($query_arg: $query_arg_from),*)*
                    });
                    let response_to_result_converter = |resp_data: Option<$response_data_type>| {
                        resp_data.map_or_else($result_type::new, |resp_data| {
                            resp_data.$field_name.into()
                        })
                    };
                    crate::graphql::request_peer(
                        $ctx,
                        peer_addr,
                        request_body,
                        response_to_result_converter,
                    )
                    .await
                }
                None => Ok($result_type::new()),
            }
        }
    }};

    // This variant of the macro is for the case where API request comes with
    // multiple sensors. In this case, current giganto will figure out which
    // gigantos are in charge of requested `sensors`, including itself. If
    // current giganto is in charge of any of the requested `sensors`, it will
    // handle the request locally, and if peer gigantos are in charge of any of
    // the requested `sensors`, it will forward the request to them.
    //
    // This macro has the same arguments as the primary macro variant, except
    // these arguments:
    // * `$sensors` - The sensors of the query. It should be iterable.
    // * `$request_from_peer` - Whether the request comes from a peer giganto.
    (multiple_sensors
     $ctx:expr,
     $sensors:expr,
     $request_from_peer:expr,
     $handler:ident,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident,
     $result_type:path
     $(, with_extra_handler_args ($($handler_arg:expr ),* ))?
     $(, with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* ))? ) => {{
        if $request_from_peer.unwrap_or_default() {
            return $handler($ctx, $sensors.as_ref(), $($($handler_arg,)*)*).await;
        }

        let sensors_set: HashSet<_> = $sensors.iter().map(|s| s.as_str()).collect();
        let (sensors_to_handle_by_current_giganto, peers_in_charge_graphql_addrs)
            = crate::graphql::find_who_are_in_charge(&$ctx, &sensors_set).await;

        match (
            !sensors_to_handle_by_current_giganto.is_empty(),
            !peers_in_charge_graphql_addrs.is_empty(),
        ) {
            (true, true) => {
                let current_giganto_result_fut = $handler($ctx, sensors_to_handle_by_current_giganto.as_ref(), $($($handler_arg,)*)*);

                let peer_results_fut = crate::graphql::request_selected_peers_for_events_fut!(
                    $ctx,
                    $sensors,
                    peers_in_charge_graphql_addrs,
                    $response_data_type,
                    $field_name,
                    $variables_type,
                    $graphql_query_type,
                    $($($query_arg := $query_arg_from),*)*
                );

                let (current_giganto_result, peer_results) = tokio::join!(current_giganto_result_fut, peer_results_fut);

                let current_giganto_result = current_giganto_result
                    .map_err(|_| Error::new("Current giganto failed to get result"))?;

                let peer_results = peer_results
                    .into_iter()
                    .map(|peer_result| match peer_result {
                        Ok(result) => Ok(result),
                        Err(e) => Err(Error::new(format!("Peer giganto failed to respond {e:?}"))),
                    })
                    .collect::<Result<Vec<$result_type>>>()?;

                let combined = peer_results
                    .into_iter()
                    .flatten()
                    .chain(current_giganto_result)
                    .collect();

                Ok(combined)
            }
            (false, true) => {
                let peer_results = crate::graphql::request_selected_peers_for_events_fut!(
                    $ctx,
                    $sensors,
                    peers_in_charge_graphql_addrs,
                    $response_data_type,
                    $field_name,
                    $variables_type,
                    $graphql_query_type,
                    $($($query_arg := $query_arg_from),*)*
                ).await;

                let peer_results = peer_results
                    .into_iter()
                    .map(|result| result.map_err(|e| Error::new(format!("Peer giganto failed to respond {e:?}"))))
                    .collect::<Result<Vec<$result_type>, _>>()?;

                Ok(peer_results.into_iter().flatten().collect())
            }
            (true, false) => {
                $handler($ctx, sensors_to_handle_by_current_giganto.as_ref(), $($($handler_arg,)*)*).await
            }
            (false, false) => Ok(Vec::new()),
        }
    }};
}
pub(crate) use events_in_cluster;

// This macro is a specialized macro. It calls `events_in_cluster` macro with
// `Vec` as the `$result_type` type, without extra args. It is one of the most
// common cases, so this macro is provided for convenience.
macro_rules! events_vec_in_cluster {
    ($ctx:expr,
     $filter:expr,
     $sensor:expr,
     $handler:ident,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident) => {{
        crate::graphql::events_in_cluster!(
            $ctx,
            $filter,
            $sensor,
            $handler,
            $graphql_query_type,
            $variables_type,
            $response_data_type,
            $field_name,
            Vec
        )
    }};
}
pub(crate) use events_vec_in_cluster;

// This macro helps to reduce boilerplate for handling
// `[something]_events_connection` APIs in giganto cluster. If the current
// giganto is in charge of the given `filter.sensor`, it will execute the
// handler locally. Otherwise, it will forward the request to a peer giganto in
// charge of the given `filter.sensor`. Peer giganto's response will be
// converted to the return type of the current giganto.
//
// Below is detailed explanation of arguments:
// * `$ctx` - The context of the GraphQL query.
// * `$filter` - The filter of the query.
// * `$sensor` - The sensor of the query.
// * `$after` - The cursor of the last edge of the previous page.
// * `$before` - The cursor of the first edge of the next page.
// * `$first` - The number of edges to be returned from the first edge of the
//   next page.
// * `$last` - The number of edges to be returned from the last edge of the
//   previous page.
// * `$handler` - The handler to be carried out by the current giganto if it is
//   in charge.
// * `$graphql_query_type` - Name of the struct that derives `GraphQLQuery`.
// * `$variables_type` - Query variable type generated by `graphql_client`. For
//   example, `conn_raw_events::Variables`.
// * `$response_data_type` - Response data type generated by `graphql_client`.
//   For example, `conn_raw_events::ResponseData`.
// * `$field_name` - Name of the field in the response data that contains the
//   result. For example, `conn_raw_events`.
// * `with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* )` -
//  Extra arguments to be passed to the GraphQL query variables.
//
// For your information, `$variables_type`, `$response_data_type`, `$field_name`
// are generated by `graphql_client` macro. You can `cargo expand` to see the
// generated code.
macro_rules! paged_events_in_cluster {
    ($ctx:expr,
     $filter:expr,
     $sensor:expr,
     $after:expr,
     $before:expr,
     $first:expr,
     $last:expr,
     $handler:expr,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident
     $(, with_extra_query_args ($($query_arg:tt := $query_arg_from:expr),* ))? ) => {{
        if crate::graphql::is_current_giganto_in_charge($ctx, &$sensor).await {
            $handler($ctx, $filter, $after, $before, $first, $last).await
        } else {
            let peer_addr = crate::graphql::peer_in_charge_graphql_addr($ctx, &$sensor).await;

            match peer_addr {
                Some(peer_addr) => {
                    type QueryVariables = $variables_type;
                    let request_body = $graphql_query_type::build_query(QueryVariables {
                        filter: $filter.into(),
                        after: $after,
                        before: $before,
                        first: $first.map(std::convert::Into::into),
                        last: $last.map(std::convert::Into::into),
                        $($($query_arg: $query_arg_from),*)*
                    });

                    let response_to_result_converter = |resp_data: Option<$response_data_type>| {
                        if let Some(data) = resp_data {
                            let page_info = data.$field_name.page_info;

                            let mut connection = async_graphql::connection::Connection::new(
                                page_info.has_previous_page,
                                page_info.has_next_page,
                            );

                            connection.edges = data
                                .$field_name
                                .edges
                                .into_iter()
                                .map(|e| {
                                    async_graphql::connection::Edge::new(e.cursor, e.node.into())
                                })
                                .collect();

                            connection
                        } else {
                            async_graphql::connection::Connection::new(false, false)
                        }
                    };

                    crate::graphql::request_peer(
                        $ctx,
                        peer_addr,
                        request_body,
                        response_to_result_converter,
                    )
                    .await
                }
                None => Ok(Connection::new(false, false)),
            }
        }
    }};

    // This macro variant is for the case where user does not specify `sensor`
    // in the filter. In this case, the current giganto will request all peers
    // for the result and combine them.
    //
    // This macro has the same arguments as the primary macro variant, except
    // these arguments:
    // * `$request_from_peer` - Whether the request comes from a peer giganto.
    (request_all_peers_if_sensor_is_none
     $ctx:expr,
     $filter:expr,
     $after:expr,
     $before:expr,
     $first:expr,
     $last:expr,
     $request_from_peer:expr,
     $handler:expr,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident) => {{
        if $request_from_peer.unwrap_or_default() {
            return $handler($ctx, $filter, $after, $before, $first, $last).await;
        }

        match &$filter.sensor {
            Some(sensor) => {
                paged_events_in_cluster!(
                    $ctx,
                    $filter,
                    sensor,
                    $after,
                    $before,
                    $first,
                    $last,
                    $handler,
                    $graphql_query_type,
                    $variables_type,
                    $response_data_type,
                    $field_name,
                    with_extra_query_args (request_from_peer := Some(true))

                )
            }
            None => {
                let current_giganto_result_fut = $handler(
                    $ctx,
                    $filter.clone(),
                    $after.clone(),
                    $before.clone(),
                    $first,
                    $last,
                );

                let peer_results_fut = crate::graphql::request_all_peers_for_paged_events_fut!(
                    $ctx,
                    $filter,
                    $after,
                    $before,
                    $first,
                    $last,
                    $request_from_peer,
                    $graphql_query_type,
                    $variables_type,
                    $response_data_type,
                    $field_name
                );

                let (current_giganto_result, peer_results) =
                    tokio::join!(current_giganto_result_fut, peer_results_fut);

                let current_giganto_result = current_giganto_result
                    .map_err(|_| Error::new("Current giganto failed to get result"))?;

                let peer_results: Vec<_> = peer_results
                    .into_iter()
                    .map(|result| result.map_err(|e| Error::new(format!("Peer giganto failed to respond {e:?}"))))
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(crate::graphql::combine_results(
                    current_giganto_result,
                    peer_results,
                    &$before,
                    $first,
                    $last,
                ))
            }
        }
    }};

    (request_all_peers
        $ctx:expr,
        $filter:expr,
        $after:expr,
        $before:expr,
        $first:expr,
        $last:expr,
        $request_from_peer:expr,
        $handler:expr,
        $graphql_query_type:ident,
        $variables_type:ty,
        $response_data_type:path,
        $field_name:ident) => {{
            if $request_from_peer.unwrap_or_default() {
               return $handler($ctx, $filter, $after, $before, $first, $last).await;
            }

            let current_giganto_result_fut = $handler(
                $ctx,
                $filter.clone(),
                $after.clone(),
                $before.clone(),
                $first,
                $last,
            );

            let peer_results_fut = crate::graphql::request_all_peers_for_paged_events_fut!(
                $ctx,
                $filter,
                $after,
                $before,
                $first,
                $last,
                $request_from_peer,
                $graphql_query_type,
                $variables_type,
                $response_data_type,
                $field_name
            );

            let (current_giganto_result, peer_results) =
                tokio::join!(current_giganto_result_fut, peer_results_fut);

            let current_giganto_result = current_giganto_result
                .map_err(|_| async_graphql::Error::new("Current giganto failed to get result"))?;

            let peer_results: Vec<_> = peer_results
                .into_iter()
                .map(|result| result.map_err(|e| async_graphql::Error::new(format!("Peer giganto failed to respond {e:?}"))))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(crate::graphql::combine_results(
                current_giganto_result,
                peer_results,
                &$before,
                $first,
                $last,
            ))
       }};
}
pub(crate) use paged_events_in_cluster;

#[allow(unused)]
fn combine_results<N>(
    current_giganto_result: Connection<String, N>,
    peer_results: Vec<Connection<String, N>>,
    before: Option<&String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Connection<String, N>
where
    N: OutputType + ClusterSortKey,
{
    let (has_next_page_combined, has_prev_page_combined) = peer_results.iter().fold(
        (
            current_giganto_result.has_previous_page,
            current_giganto_result.has_next_page,
        ),
        |(has_prev_page, has_next_page), result| {
            (
                has_prev_page || result.has_previous_page,
                has_next_page || result.has_next_page,
            )
        },
    );

    let edges_combined = peer_results
        .into_iter()
        .flat_map(|fpr| fpr.edges)
        .chain(current_giganto_result.edges)
        .collect();
    let edges_combined = sort_and_trunk_edges(edges_combined, before, first, last);

    let mut connection_to_return = Connection::new(has_prev_page_combined, has_next_page_combined);
    connection_to_return.edges = edges_combined;

    connection_to_return
}

#[allow(unused)]
#[derive(PartialEq)]
enum TakeDirection {
    First,
    Last,
}

#[allow(unused)]
fn sort_and_trunk_edges<N>(
    mut edges: Vec<Edge<String, N, EmptyFields>>,
    before: Option<&String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Vec<Edge<String, N, EmptyFields>>
where
    N: OutputType + ClusterSortKey,
{
    let (take_direction, get_len) = if before.is_some() || last.is_some() {
        (
            TakeDirection::Last,
            last.map_or(MAXIMUM_PAGE_SIZE, |l| MAXIMUM_PAGE_SIZE.min(l.as_())),
        )
    } else {
        (
            TakeDirection::First,
            first.map_or(MAXIMUM_PAGE_SIZE, |f| MAXIMUM_PAGE_SIZE.min(f.as_())),
        )
    };

    // Sort by `cursor`, and then `sensor`. Since each node in giganto may have
    // conflicting `cursor` values, we need a secondary sort key.
    edges.sort_unstable_by(|a, b| {
        a.cursor.cmp(&b.cursor).then_with(|| {
            a.node
                .secondary()
                .unwrap_or_default()
                .cmp(b.node.secondary().unwrap_or_default())
        })
    });

    if take_direction == TakeDirection::First {
        edges.truncate(get_len);
    } else {
        let drain_start = edges.len().saturating_sub(get_len);
        edges = edges.drain(drain_start..).collect();
    }

    edges
}

async fn is_current_giganto_in_charge<'ctx>(ctx: &Context<'ctx>, sensor_filter: &str) -> bool {
    let ingest_sensors = ctx.data_opt::<IngestSensors>();
    match ingest_sensors {
        Some(ingest_sensors) => ingest_sensors.read().await.contains(sensor_filter),
        None => false,
    }
}

async fn peer_in_charge_graphql_addr<'ctx>(
    ctx: &Context<'ctx>,
    sensor_filter: &str,
) -> Option<SocketAddr> {
    let peers = ctx.data_opt::<Peers>();
    match peers {
        Some(peers) => {
            peers
                .read()
                .await
                .iter()
                .find_map(|(addr_to_peers, peer_info)| {
                    peer_info
                        .ingest_sensors
                        .contains(sensor_filter)
                        .then(|| {
                            SocketAddr::new(
                                addr_to_peers.parse::<IpAddr>().expect("Peer's IP address must be valid, because it is validated when peer giganto started."),
                                peer_info.graphql_port.expect("Peer's graphql port must be valid, because it is validated when peer giganto started."),
                            )
                        })
                })
        }
        None => None,
    }
}

async fn find_who_are_in_charge(
    ctx: &Context<'_>,
    sensors: &HashSet<&str>,
) -> (Vec<String>, Vec<SocketAddr>) {
    let ingest_sensors = ctx.data_opt::<IngestSensors>();

    let sensors_to_handle_by_current_giganto: Vec<String> = match ingest_sensors {
        Some(ingest_sensors) => {
            let ingest_sensors = ingest_sensors.read().await;
            let ingest_sensors_set = ingest_sensors
                .iter()
                .map(std::string::String::as_str)
                .collect::<HashSet<_>>();

            sensors
                .intersection(&ingest_sensors_set)
                .map(ToString::to_string)
                .collect()
        }
        None => Vec::new(),
    };

    let peers = ctx.data_opt::<Peers>();
    let peers_in_charge_graphql_addrs: Vec<SocketAddr> = match peers {
        Some(peers) => peers
            .read()
            .await
            .iter()
            .filter(|&(_addr_to_peers, peer_info)| {
                peer_info
                    .ingest_sensors
                    .iter()
                    .any(|ingest_sensor| sensors.contains(&ingest_sensor.as_str()))
            })
            .map(|(addr_to_peers, peer_info)| {
                SocketAddr::new(
                    addr_to_peers
                        .parse::<IpAddr>()
                        .expect("Peer's IP address must be valid, because it is validated when peer giganto started."),
                    peer_info
                        .graphql_port
                        .expect("Peer's graphql port must be valid, because it is validated when peer giganto started."),
                )
            })
            .collect(),
        None => Vec::new(),
    };

    (
        sensors_to_handle_by_current_giganto,
        peers_in_charge_graphql_addrs,
    )
}

pub async fn request_peer<'ctx, QueryBodyType, ResponseDataType, ResultDataType, F>(
    ctx: &Context<'ctx>,
    peer_graphql_addr: SocketAddr,
    req_body: graphql_client::QueryBody<QueryBodyType>,
    response_to_result_converter: F,
) -> Result<ResultDataType>
where
    QueryBodyType: Serialize,
    ResponseDataType: for<'a> Deserialize<'a>,
    F: 'static + FnOnce(Option<ResponseDataType>) -> ResultDataType,
{
    let client = ctx.data::<reqwest::Client>()?;
    let req = client
        .post(format!(
            "{}://{}/graphql",
            if cfg!(test) { "http" } else { "https" },
            peer_graphql_addr
        ))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&req_body);

    let resp = req
        .send()
        .await
        .map_err(|e| Error::new(format!("Peer giganto did not respond {e}")))?;

    resp.error_for_status()
        .map_err(|e| {
            Error::new(format!(
                "Peer giganto's response status is not success. {e}"
            ))
        })?
        .json::<GraphQlResponse<ResponseDataType>>()
        .await
        .map_err(|_| Error::new("Peer giganto's response failed to deserialize."))
        .map(|graphql_res| response_to_result_converter(graphql_res.data))
}

#[allow(unused_macros)]
macro_rules! request_all_peers_for_paged_events_fut {
    ($ctx:expr,
     $filter:expr,
     $after:expr,
     $before:expr,
     $first:expr,
     $last:expr,
     $request_from_peer:expr,
     $graphql_query_type:ident,
     $variables_type:ty,
     $response_data_type:path,
     $field_name:ident) => {{
        let peer_graphql_endpoints = match $ctx.data_opt::<crate::peer::Peers>() {
            Some(peers) => {
                peers
                    .read()
                    .await
                    .iter()
                    .map(|(addr_to_peers, peer_info)| {
                        std::net::SocketAddr::new(
                            addr_to_peers.parse::<IpAddr>().expect("Peer's IP address must be valid, because it is validated when peer giganto started."),
                            peer_info.graphql_port.expect("Peer's graphql port must be valid, because it is validated when peer giganto started."),
                        )
                    }).collect()
            }
            None => Vec::new(),
        };

        let response_to_result_converter = |resp_data: Option<$response_data_type>| {
            if let Some(data) = resp_data {
                let page_info = data.$field_name.page_info;

                let mut connection = async_graphql::connection::Connection::new(
                    page_info.has_previous_page,
                    page_info.has_next_page,
                );

                connection.edges = data
                    .$field_name
                    .edges
                    .into_iter()
                    .map(|e| async_graphql::connection::Edge::new(e.cursor, e.node.into()))
                    .collect();

                connection
            } else {
                Connection::new(false, false)
            }
        };

        let peer_requests = peer_graphql_endpoints
        .into_iter()
        .map(|peer_endpoint| {
                type QueryVariables = $variables_type;
                let request_body = $graphql_query_type::build_query(QueryVariables {
                    filter: $filter.clone().into(),
                    after: $after.clone(),
                    before: $before.clone(),
                    first: $first.map(std::convert::Into::into),
                    last: $last.map(std::convert::Into::into),
                    request_from_peer: $request_from_peer.into(),
                });
                crate::graphql::request_peer(
                    $ctx,
                    peer_endpoint,
                    request_body,
                    response_to_result_converter,
                )
            });

        futures_util::future::join_all(peer_requests)
    }};
}
#[allow(unused_imports)]
pub(crate) use request_all_peers_for_paged_events_fut;

macro_rules! request_selected_peers_for_events_fut {
    ($ctx:expr,
     $sensors:expr,
     $peers_in_charge_graphql_addrs:expr,
     $response_data_type:path,
     $field_name:ident,
     $variables_type:ty,
     $graphql_query_type:ident,
     $($query_arg:tt := $query_arg_from:expr),*) => {{
        let response_to_result_converter = |resp_data: Option<$response_data_type>| {
            resp_data.map_or_else(Vec::new, |resp_data| {
                resp_data.$field_name.into_iter().map(Into::into).collect()
            })
        };

        let peer_requests = $peers_in_charge_graphql_addrs
            .into_iter()
            .map(|peer_endpoint| {
                type QueryVariables = $variables_type;
                let request_body = $graphql_query_type::build_query(QueryVariables {
                    sensors: $sensors.clone(),
                    request_from_peer: Some(true),
                    $($query_arg: $query_arg_from),*
                });
                crate::graphql::request_peer(
                    $ctx,
                    peer_endpoint,
                    request_body,
                    response_to_result_converter,
                )
            });
        futures_util::future::join_all(peer_requests)
    }};
}
pub(crate) use request_selected_peers_for_events_fut;

macro_rules! impl_from_giganto_time_range_struct_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<crate::graphql::TimeRange> for $autogen_mod::TimeRange {
                fn from(range: crate::graphql::TimeRange) -> Self {
                    Self {
                        start: range.start,
                        end: range.end,
                    }
                }
            }
        )*
    };
}
pub(crate) use impl_from_giganto_time_range_struct_for_graphql_client;

macro_rules! impl_from_giganto_range_structs_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            crate::graphql::impl_from_giganto_time_range_struct_for_graphql_client!($autogen_mod);

            impl From<crate::graphql::IpRange> for $autogen_mod::IpRange {
                fn from(range: crate::graphql::IpRange) -> Self {
                    Self {
                        start: range.start,
                        end: range.end,
                    }
                }
            }
            impl From<crate::graphql::PortRange> for $autogen_mod::PortRange {
                fn from(range: crate::graphql::PortRange) -> Self {
                    Self {
                        start: range.start.map(Into::into),
                        end: range.end.map(Into::into),
                    }
                }
            }
        )*
    };
}
pub(crate) use impl_from_giganto_range_structs_for_graphql_client;

macro_rules! impl_from_giganto_network_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<NetworkFilter> for $autogen_mod::NetworkFilter {
                fn from(filter: NetworkFilter) -> Self {
                    Self {
                        time: filter.time.map(Into::into),
                        sensor: filter.sensor,
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                        log_level: filter.log_level,
                        log_contents: filter.log_contents,
                        agent_id: filter.agent_id,
                    }
                }
            }
        )*
    };
}
pub(crate) use impl_from_giganto_network_filter_for_graphql_client;

macro_rules! impl_from_giganto_search_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<SearchFilter> for $autogen_mod::SearchFilter {
                fn from(filter: SearchFilter) -> Self {
                    Self {
                        time: filter.time.map(Into::into),
                        sensor: filter.sensor,
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                        log_level: filter.log_level,
                        log_contents: filter.log_contents,
                        timestamps: filter.timestamps,
                        keyword: filter.keyword,
                        agent_id: filter.agent_id,
                    }
                }
            }
        )*
    };
}
pub(crate) use impl_from_giganto_search_filter_for_graphql_client;

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use async_graphql::{
        connection::{Edge, EmptyFields},
        EmptySubscription, SimpleObject,
    };
    use chrono::{DateTime, Utc};
    use tokio::sync::{Notify, RwLock};

    use super::{schema, sort_and_trunk_edges, NodeName};
    use crate::graphql::{ClusterSortKey, Mutation, Query};
    use crate::peer::{PeerInfo, Peers};
    use crate::settings::Settings;
    use crate::storage::{Database, DbOptions};
    use crate::{new_pcap_sensors, IngestSensors};

    type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;

    const CURRENT_GIGANTO_INGEST_SENSORS: [&str; 3] = ["src1", "src 1", "ingest src 1"];
    const PEER_GIGANTO_2_INGEST_SENSORS: [&str; 3] = ["src2", "src 2", "ingest src 2"];

    pub struct TestSchema {
        pub _dir: tempfile::TempDir, // to prevent the data directory from being deleted while the test is running
        pub db: Database,
        pub schema: Schema,
    }

    impl TestSchema {
        fn setup(ingest_sensors: IngestSensors, peers: Peers, is_local_config: bool) -> Self {
            let db_dir = tempfile::tempdir().unwrap();
            let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
            let pcap_sensors = new_pcap_sensors();
            let request_client_pool = reqwest::Client::new();
            let export_dir = tempfile::tempdir().unwrap();
            let (reload_tx, _) = tokio::sync::mpsc::channel::<String>(1);
            let notify_reboot = Arc::new(Notify::new());
            let notify_power_off = Arc::new(Notify::new());
            let notify_terminate = Arc::new(Notify::new());
            let settings = Settings::new().unwrap();
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
                Arc::new(RwLock::new(1024)),
                is_local_config,
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
                    .map(|sensor| sensor.to_string())
                    .collect::<HashSet<String>>(),
            ));

            let peers = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
            Self::setup(ingest_sensors, peers, true)
        }

        pub fn new_with_graphql_peer(port: u16) -> Self {
            let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
                CURRENT_GIGANTO_INGEST_SENSORS
                    .into_iter()
                    .map(|sensor| sensor.to_string())
                    .collect::<HashSet<String>>(),
            ));

            let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
                "127.0.0.1".to_string(),
                PeerInfo {
                    ingest_sensors: PEER_GIGANTO_2_INGEST_SENSORS
                        .into_iter()
                        .map(|sensor| (sensor.to_string()))
                        .collect::<HashSet<String>>(),
                    graphql_port: Some(port),
                    publish_port: None,
                },
            )])));

            Self::setup(ingest_sensors, peers, true)
        }

        pub fn new_with_remote_config() -> Self {
            let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
                CURRENT_GIGANTO_INGEST_SENSORS
                    .into_iter()
                    .map(|sensor| sensor.to_string())
                    .collect::<HashSet<String>>(),
            ));

            let peers = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
            Self::setup(ingest_sensors, peers, false)
        }

        pub async fn execute(&self, query: &str) -> async_graphql::Response {
            let request: async_graphql::Request = query.into();
            self.schema.execute(request).await
        }
    }

    #[derive(SimpleObject, Debug)]
    struct TestNode {
        timestamp: DateTime<Utc>,
    }

    impl ClusterSortKey for TestNode {
        fn secondary(&self) -> Option<&str> {
            None
        }
    }

    fn edges_fixture() -> Vec<Edge<String, TestNode, EmptyFields>> {
        vec![
            Edge::new(
                "warn_001".to_string(),
                TestNode {
                    timestamp: Utc::now(),
                },
            ),
            Edge::new(
                "danger_001".to_string(),
                TestNode {
                    timestamp: Utc::now(),
                },
            ),
            Edge::new(
                "danger_002".to_string(),
                TestNode {
                    timestamp: Utc::now(),
                },
            ),
            Edge::new(
                "info_001".to_string(),
                TestNode {
                    timestamp: Utc::now(),
                },
            ),
            Edge::new(
                "info_002".to_string(),
                TestNode {
                    timestamp: Utc::now(),
                },
            ),
            Edge::new(
                "info_003".to_string(),
                TestNode {
                    timestamp: Utc::now(),
                },
            ),
        ]
    }

    #[test]
    fn test_sort_and_trunk_edges() {
        let empty_vec = Vec::<Edge<String, TestNode, EmptyFields>>::new();
        let result = sort_and_trunk_edges(empty_vec, None, None, None);
        assert!(result.is_empty());

        let result = sort_and_trunk_edges(edges_fixture(), None, None, None);
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), None, Some(5), None);
        assert_eq!(result.len(), 5);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "info_003".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), None, Some(10), None);
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), None, None, Some(5));
        assert_eq!(result.len(), 5);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_002".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(edges_fixture(), None, None, Some(10));
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result =
            sort_and_trunk_edges(edges_fixture(), Some("zebra_001"), None, None);
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(
            edges_fixture(),
            Some("zebra_001".to_string()),
            None,
            Some(5),
        );
        assert_eq!(result.len(), 5);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_002".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());

        let result = sort_and_trunk_edges(
            edges_fixture(),
            Some("zebra_001".to_string()),
            None,
            Some(10),
        );
        assert_eq!(result.len(), 6);
        assert!(result.windows(2).all(|w| w[0].cursor < w[1].cursor));
        assert_eq!(result[0].cursor, "danger_001".to_string());
        assert_eq!(result[result.len() - 1].cursor, "warn_001".to_string());
    }
}
