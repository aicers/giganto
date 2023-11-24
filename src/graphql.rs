mod client;
mod export;
mod log;
mod netflow;
pub mod network;
mod packet;
mod security;
mod source;
pub mod statistics;
pub mod status;
mod sysmon;
mod timeseries;

use crate::{
    ingest::implement::EventFilter,
    peer::Peers,
    storage::{
        Database, Direction, FilteredIter, KeyExtractor, KeyValue, RawEventStore, StorageKey,
    },
    AckTransmissionCount, IngestSources, PcapSources,
};
use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection, Edge},
    Context, EmptySubscription, Error, InputObject, MergedObject, OutputType, Result,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use chrono::{DateTime, TimeZone, Utc};
use giganto_client::ingest::Packet as pk;
use graphql_client::Response as GraphQlResponse;
use libc::timeval;
use pcap::{Capture, Linktype, Packet, PacketHeader};
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom, Write},
    net::IpAddr,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};
use tempfile::tempfile;
use tokio::sync::Notify;
use tracing::error;

pub const TIMESTAMP_SIZE: usize = 8;

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
    security::SecurityLogQuery,
    netflow::NetflowQuery,
);

#[derive(Default, MergedObject)]
pub struct Mutation(status::GigantoConfigMutation);

#[derive(InputObject, Serialize)]
pub struct TimeRange {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}
#[derive(InputObject, Serialize)]
pub struct IpRange {
    pub start: Option<String>,
    pub end: Option<String>,
}

#[derive(InputObject, Serialize)]
pub struct PortRange {
    pub start: Option<u16>,
    pub end: Option<u16>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct NetworkFilter {
    pub time: Option<TimeRange>,
    #[serde(skip)]
    pub source: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    log_level: Option<String>,
    log_contents: Option<String>,
}

#[derive(InputObject, Serialize)]
pub struct SearchFilter {
    pub time: Option<TimeRange>,
    #[serde(skip)]
    pub source: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    log_level: Option<String>,
    log_contents: Option<String>,
    pub timestamps: Vec<DateTime<Utc>>,
    keyword: Option<String>,
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
        source: Option<String>,
    ) -> Result<bool>;
}

pub trait FromKeyValue<T>: Sized {
    fn from_key_value(key: &[u8], value: T) -> Result<Self>;
}

pub type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;
type ConnArgs<T> = (Vec<(Box<[u8]>, T)>, bool, bool);

#[allow(clippy::too_many_arguments)]
pub fn schema(
    database: Database,
    pcap_sources: PcapSources,
    ingest_sources: IngestSources,
    peers: Peers,
    request_client_pool: reqwest::Client,
    export_path: PathBuf,
    config_reload: Arc<Notify>,
    config_file_path: String,
    ack_transmission_cnt: AckTransmissionCount,
) -> Schema {
    Schema::build(Query::default(), Mutation::default(), EmptySubscription)
        .data(database)
        .data(pcap_sources)
        .data(ingest_sources)
        .data(peers)
        .data(request_client_pool)
        .data(export_path)
        .data(config_reload)
        .data(config_file_path)
        .data(ack_transmission_cnt)
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
                            raw_event.source(),
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

        match filter.check(
            item.1.orig_addr(),
            item.1.resp_addr(),
            item.1.orig_port(),
            item.1.resp_port(),
            item.1.log_level(),
            item.1.log_contents(),
            item.1.text(),
            item.1.source(),
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

fn get_peekable_iter<'c, T>(
    store: &RawEventStore<'c, T>,
    filter: &'c NetworkFilter,
    after: &Option<String>,
    before: &Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(std::iter::Peekable<FilteredIter<'c, T>>, usize)>
where
    T: DeserializeOwned + EventFilter,
{
    let (filterd_iter, cursor, size) =
        get_filtered_iter(store, filter, after, before, first, last)?;
    let mut filterd_iter = filterd_iter.peekable();
    if let Some(cursor) = cursor {
        if let Some((key, _)) = filterd_iter.peek() {
            if key.as_ref() == cursor {
                filterd_iter.next();
            }
        }
    }
    Ok((filterd_iter, size))
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
            if let Some(start) = ip_range.start.clone() {
                if let Some(end) = ip_range.end.clone() {
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

fn check_port(filter_port: &Option<PortRange>, target_port: Option<u16>) -> bool {
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

fn check_contents(filter_str: &Option<String>, target_str: Option<String>) -> bool {
    filter_str.as_ref().map_or(true, |filter_str| {
        target_str.map_or(false, |contents| contents.contains(filter_str))
    })
}

fn check_source(filter_src: &Option<String>, target_src: &Option<String>) -> bool {
    filter_src.as_ref().map_or(true, |filter_src| {
        target_src
            .as_ref()
            .map_or(false, |source| source == filter_src)
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
    filter: NetworkFilter,
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
// is in charge of the given `filter.source`, it will execute the handler
// locally. Otherwise, it will forward the request to a peer giganto in charge
// of the given `filter.source`. Peer giganto's response will be converted to
// the return type of the current giganto.
//
// Below is detailed explanation of arguments:
// * `$ctx` - The context of the GraphQL query.
// * `$filter` - The filter of the query.
// * `$handler` - The handler to be carried out by the current giganto if it
//   is in charge.
// * `$graphql_query_type` - Name of the struct that derives `GraphQLQuery`.
// * `$variables_type` - Query variable type generated by `graphql_client`. For
//   example, `search_conn_raw_events::Variables`.
// * `$response_data_type` - Response data type generated by `graphql_client`.
//   For example, `search_conn_raw_events::ResponseData`.
// * `$field_name` - Name of the field in the response data that contains the
//   result. For example, `search_conn_raw_events`.
//
// For your information, `$variables_type`, `$response_data_type`, `$field_name`
// are generated by `graphql_client` macro. You can `cargo expand` to see the
// generated code.
macro_rules! events_in_cluster {
    ($ctx:expr, $filter:expr, $handler:ident, $graphql_query_type:ident, $variables_type:ty, $response_data_type:path, $field_name:ident) => {{
        type QueryVariables = $variables_type;
        if is_current_giganto_in_charge($ctx, &$filter.source).await {
            $handler($ctx, &$filter)
        } else {
            let peer_addr = peer_in_charge_graphql_addr($ctx, &$filter.source).await;

            match peer_addr {
                Some(peer_addr) => {
                    let request_body = $graphql_query_type::build_query(QueryVariables {
                        filter: $filter.into(),
                    });
                    let response_to_result_converter = |resp_data: Option<$response_data_type>| {
                        resp_data.map_or_else(Vec::new, |data| data.$field_name)
                    };

                    request_peer($ctx, &peer_addr, request_body, response_to_result_converter).await
                }
                None => Ok(Vec::new()),
            }
        }
    }};
}
pub(crate) use events_in_cluster;

// This macro helps to reduce boilerplate for handling
// `[something]_events_connection` APIs in giganto cluster. If the current
// giganto is in charge of the given `filter.source`, it will execute the
// handler locally. Otherwise, it will forward the request to a peer giganto
// in charge of the given `filter.source`. Peer giganto's response will be
// converted to the return type of the current giganto.
//
// Below is detailed explanation of arguments:
// * `$ctx` - The context of the GraphQL query.
// * `$filter` - The filter of the query.
// * `$after` - The cursor of the last edge of the previous page.
// * `$before` - The cursor of the first edge of the next page.
// * `$first` - The number of edges to be returned from the first edge of the
//   next page.
// * `$last` - The number of edges to be returned from the last edge of the
//   previous page.
// * `$handler` - The handler to be carried out by the current giganto if it
//   is in charge.
// * `$graphql_query_type` - Name of the struct that derives `GraphQLQuery`.
// * `$variables_type` - Query variable type generated by `graphql_client`. For
//   example, `conn_raw_events::Variables`.
// * `$response_data_type` - Response data type generated by `graphql_client`.
//   For example, `conn_raw_events::ResponseData`.
// * `$field_name` - Name of the field in the response data that contains the
//   result. For example, `conn_raw_events`.
//
// For your information, `$variables_type`, `$response_data_type`, `$field_name`
// are generated by `graphql_client` macro. You can `cargo expand` to see the
// generated code.
macro_rules! paged_events_in_cluster {
    ($ctx:expr, $filter:expr, $after:expr, $before:expr, $first:expr, $last:expr, $handler:expr, $graphql_query_type:ident, $variables_type:ty, $response_data_type:path, $field_name:ident) => {{
        if is_current_giganto_in_charge($ctx, &$filter.source).await {
            $handler($ctx, $filter, $after, $before, $first, $last).await
        } else {
            let peer_addr = peer_in_charge_graphql_addr($ctx, &$filter.source).await;

            match peer_addr {
                Some(peer_addr) => {
                    type QueryVariables = $variables_type;
                    let request_body = $graphql_query_type::build_query(QueryVariables {
                        filter: $filter.into(),
                        after: $after,
                        before: $before,
                        first: $first.map(std::convert::Into::into),
                        last: $last.map(std::convert::Into::into),
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
                                .map(|e| Edge::new(e.cursor, e.node.into()))
                                .collect();

                            connection
                        } else {
                            async_graphql::connection::Connection::new(false, false)
                        }
                    };

                    request_peer($ctx, &peer_addr, request_body, response_to_result_converter).await
                }
                None => Ok(Connection::new(false, false)),
            }
        }
    }};
}
pub(crate) use paged_events_in_cluster;

async fn is_current_giganto_in_charge<'ctx>(ctx: &Context<'ctx>, source_filter: &str) -> bool {
    let ingest_sources = ctx.data_opt::<IngestSources>();
    match ingest_sources {
        Some(ingest_sources) => ingest_sources
            .read()
            .await
            .iter()
            .any(|(ingest_source_name, _last_conn_time)| ingest_source_name == source_filter),
        None => false,
    }
}

async fn peer_in_charge_graphql_addr<'ctx>(
    ctx: &Context<'ctx>,
    source_filter: &str,
) -> Option<SocketAddr> {
    let peers = ctx.data_opt::<Peers>();
    match peers {
        Some(peers) => {
            peers
                .read()
                .await
                .iter()
                .find_map(|(peer_address, peer_info)| {
                    peer_info
                        .ingest_sources
                        .contains(source_filter)
                        .then(|| {
                            SocketAddr::new(
                                peer_address.parse::<IpAddr>().expect("Peer's IP address must be valid, because it is validated when peer giganto started."),
                                peer_info.graphql_port.expect("Peer's graphql port must be valid, because it is validated when peer giganto started."),
                            )
                        })
                })
        }
        None => None,
    }
}

async fn request_peer<'ctx, QueryBodyType, ResponseDataType, ResultDataType, F>(
    ctx: &Context<'ctx>,
    peer_graphql_addr: &SocketAddr,
    req_body: graphql_client::QueryBody<QueryBodyType>,
    response_to_result_converter: F,
) -> Result<ResultDataType>
where
    QueryBodyType: Serialize,
    ResponseDataType: for<'a> Deserialize<'a>,
    F: 'static + FnOnce(Option<ResponseDataType>) -> ResultDataType,
{
    let client: &reqwest::Client = ctx.data::<reqwest::Client>()?;
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

    match resp.error_for_status() {
        Ok(resp_ok) => {
            if let Ok(graphql_resp) = resp_ok.json::<GraphQlResponse<ResponseDataType>>().await {
                Ok(response_to_result_converter(graphql_resp.data))
            } else {
                Err(Error::new("Peer giganto's response failed to deserialize."))
            }
        }
        Err(e) => Err(Error::new(format!(
            "Peer giganto's response status is not success. {e}"
        ))),
    }
}

macro_rules! impl_from_giganto_range_structs_for_graphql_client {
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

macro_rules! impl_from_giganto_network_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<NetworkFilter> for $autogen_mod::NetworkFilter {
                fn from(filter: NetworkFilter) -> Self {
                    Self {
                        time: filter.time.map(Into::into),
                        source: filter.source,
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                        log_level: filter.log_level,
                        log_contents: filter.log_contents,
                    }
                }
            }
        )*
    };
}

macro_rules! impl_from_giganto_search_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<SearchFilter> for $autogen_mod::SearchFilter {
                fn from(filter: SearchFilter) -> Self {
                    Self {
                        time: filter.time.map(Into::into),
                        source: filter.source,
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                        log_level: filter.log_level,
                        log_contents: filter.log_contents,
                        timestamps: filter.timestamps,
                        keyword: filter.keyword,
                    }
                }
            }
        )*
    };
}

pub(crate) use impl_from_giganto_network_filter_for_graphql_client;
pub(crate) use impl_from_giganto_range_structs_for_graphql_client;
pub(crate) use impl_from_giganto_search_filter_for_graphql_client;

#[cfg(test)]
mod tests {
    use super::schema;
    use crate::graphql::{Mutation, Query};
    use crate::peer::{PeerInfo, Peers};
    use crate::storage::{Database, DbOptions};
    use crate::{new_pcap_sources, IngestSources};
    use async_graphql::EmptySubscription;
    use chrono::{DateTime, Utc};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tokio::sync::{Notify, RwLock};

    type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;

    const CURRENT_GIGANTO_INGEST_SOURCES: [&str; 2] = ["src 1", "ingest src 1"];
    const PEER_GIGANTO_INGEST_SOURCES: [&str; 2] = ["src 2", "ingest src 2"];

    pub struct TestSchema {
        pub _dir: tempfile::TempDir, // to prevent the data directory from being deleted while the test is running
        pub db: Database,
        pub schema: Schema,
    }

    impl TestSchema {
        fn setup(ingest_sources: IngestSources, peers: Peers) -> Self {
            let db_dir = tempfile::tempdir().unwrap();
            let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
            let pcap_sources = new_pcap_sources();
            let request_client_pool = reqwest::Client::new();
            let export_dir = tempfile::tempdir().unwrap();
            let config_reload = Arc::new(Notify::new());
            let schema = schema(
                db.clone(),
                pcap_sources,
                ingest_sources,
                peers,
                request_client_pool,
                export_dir.path().to_path_buf(),
                config_reload,
                "file_path".to_string(),
                Arc::new(RwLock::new(1024)),
            );

            Self {
                _dir: db_dir,
                db,
                schema,
            }
        }

        pub fn new() -> Self {
            let ingest_sources = Arc::new(tokio::sync::RwLock::new(
                CURRENT_GIGANTO_INGEST_SOURCES
                    .into_iter()
                    .map(|source| (source.to_string(), Utc::now()))
                    .collect::<HashMap<String, DateTime<Utc>>>(),
            ));

            let peers = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
            Self::setup(ingest_sources, peers)
        }

        pub fn new_with_graphql_peer(port: u16) -> Self {
            let ingest_sources = Arc::new(tokio::sync::RwLock::new(
                CURRENT_GIGANTO_INGEST_SOURCES
                    .into_iter()
                    .map(|source| (source.to_string(), Utc::now()))
                    .collect::<HashMap<String, DateTime<Utc>>>(),
            ));

            let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
                "127.0.0.1".to_string(),
                PeerInfo {
                    ingest_sources: PEER_GIGANTO_INGEST_SOURCES
                        .into_iter()
                        .map(|source| (source.to_string()))
                        .collect::<HashSet<String>>(),
                    graphql_port: Some(port),
                    publish_port: None,
                },
            )])));

            Self::setup(ingest_sources, peers)
        }

        pub async fn execute(&self, query: &str) -> async_graphql::Response {
            let request: async_graphql::Request = query.into();
            self.schema.execute(request).await
        }
    }

    #[test]
    fn test_check_source() {
        use super::check_source;
        assert!(check_source(
            &Some("test".to_string()),
            &Some("test".to_string())
        ));
        assert!(!check_source(
            &Some("test".to_string()),
            &Some("test1".to_string())
        ));
        assert!(!check_source(&Some("test".to_string()), &None));
        assert!(check_source(&None, &Some("test".to_string()),));
        assert!(check_source(&None, &None));
    }
}
