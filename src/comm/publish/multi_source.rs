//! Multi-source range reads and re-reads with per-source status.
//!
//! Both requests answer with event frames, the `None` terminator, and one
//! `RangeStatus` frame that says, per requested source, whether it was served.
//! A source a peer is in charge of is forwarded to that peer as the same
//! request, and every wait on the peer is bounded, so a peer that stops
//! answering fails its own sources and nothing else.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    time::Duration,
};

use anyhow::Result;
use futures_util::{Stream, StreamExt, future::join_all, stream};
use giganto_client::{
    RawEventKind,
    frame::{self, send_raw},
    ingest::{
        log::Log,
        netflow::{Netflow5, Netflow9},
        network::{
            Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Icmp, Kerberos, Ldap, MalformedDns, Mqtt,
            Nfs, Ntlm, Radius, Rdp, Smb, Smtp, Ssh, Tls,
        },
        sysmon::{
            DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
            FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
            ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
        },
        timeseries::PeriodicTimeSeries,
    },
    publish::{
        range::{
            MessageCode, RangeStatus, RequestMultiSourceRange, RequestRawData, ResponseRangeData,
            SourceStatus,
        },
        receive_range_status, send_range_data_request, send_range_status,
    },
};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use serde::{Serialize, de::DeserializeOwned};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::{
    close_peer_connection, connect, is_current_giganto_in_charge, peer_in_charge_publish_addr,
    peer_name,
};
use crate::comm::{
    IngestSensors,
    peer::{PeerIdents, Peers},
};
use crate::datetime::DateTime;
use crate::graphql::TIMESTAMP_SIZE;
use crate::storage::{Database, Direction, RawEventStore, StorageKey};
use crate::tls_reload::TlsWatch;

/// How long a multi-source read or a re-read with status waits on a peer at
/// each step: connecting and the handshake together, opening the stream and
/// writing the request together, and each frame read.
pub(super) const PEER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// What a multi-source read or a re-read with status needs to route its
/// sources and to wait on peers.
pub(super) struct Routing<'a> {
    pub(super) ingest_sensors: &'a IngestSensors,
    pub(super) peers: &'a Peers,
    pub(super) peer_idents: &'a PeerIdents,
    pub(super) tls_watch: &'a TlsWatch,
    pub(super) token: &'a CancellationToken,
    pub(super) peer_timeout: Duration,
}

/// How the events of one kind are keyed, and where they are served from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KindLayout {
    /// Keyed by sensor and timestamp; served by the node in charge.
    Event,
    /// Keyed by sensor, the requested kind string, and timestamp; served by
    /// the node in charge.
    Log,
    /// Keyed by sampling-policy ID and timestamp; served from the local store
    /// only, with `f64` payloads.
    TimeSeries,
}

/// One event read from a store, as `(timestamp, frame)`, or why it could not
/// be read.
type FrameResult = Result<(i64, Vec<u8>), String>;

/// One kind's store, with the type its values decode to erased, producing the
/// frames a client receives.
trait EventStore<'db>: Send {
    /// Returns the events of `source` from `start` (inclusive) to `end`
    /// (exclusive), in time order, as `(timestamp, frame)` pairs.
    fn range_frames(
        &self,
        source: &str,
        mid_key: Option<&[u8]>,
        start: i64,
        end: i64,
    ) -> Box<dyn Iterator<Item = FrameResult> + Send + 'db>;

    /// Looks up the events of `source` at `timestamps`, returning a frame for
    /// each stored event and an error for each one that could not be read or
    /// decoded. A timestamp with no stored event yields nothing.
    fn lookup_frames(
        &self,
        source: &str,
        mid_key: Option<&[u8]>,
        timestamps: &[i64],
    ) -> Vec<FrameResult>;
}

impl<'db, T> EventStore<'db> for RawEventStore<'db, T>
where
    T: DeserializeOwned + ResponseRangeData + Send + 'db,
{
    fn range_frames(
        &self,
        source: &str,
        mid_key: Option<&[u8]>,
        start: i64,
        end: i64,
    ) -> Box<dyn Iterator<Item = FrameResult> + Send + 'db> {
        let key_builder = StorageKey::builder()
            .start_key(source)
            .mid_key(mid_key.map(<[u8]>::to_vec));
        let from_key = key_builder
            .clone()
            .lower_closed_bound_end_key(Some(DateTime::from_timestamp_nanos(start)))
            .build();
        let to_key = key_builder
            .upper_open_bound_end_key(Some(DateTime::from_timestamp_nanos(end)))
            .build();
        let source = source.to_owned();
        let iter = self.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);
        Box::new(iter.map(move |item| {
            let (key, value) = item.map_err(|e| format!("reading the store failed: {e:#}"))?;
            let timestamp = key_timestamp(&key)
                .ok_or_else(|| "the store holds a key without a timestamp".to_string())?;
            let frame = value
                .response_data(timestamp, &source)
                .map_err(|e| format!("encoding the event at {timestamp} failed: {e}"))?;
            Ok((timestamp, frame))
        }))
    }

    fn lookup_frames(
        &self,
        source: &str,
        mid_key: Option<&[u8]>,
        timestamps: &[i64],
    ) -> Vec<FrameResult> {
        self.checked_multi_get(source, mid_key, timestamps)
            .into_iter()
            .filter_map(|(timestamp, value)| match value {
                Ok(None) => None,
                Ok(Some(value)) => Some(
                    bincode::deserialize::<T>(&value)
                        .map_err(|e| format!("decoding the event at {timestamp} failed: {e}"))
                        .and_then(|value| {
                            value.response_data(timestamp, source).map_err(|e| {
                                format!("encoding the event at {timestamp} failed: {e}")
                            })
                        })
                        .map(|frame| (timestamp, frame)),
                ),
                Err(e) => Some(Err(format!(
                    "looking up the event at {timestamp} failed: {e}"
                ))),
            })
            .collect()
    }
}

/// Reads the big-endian timestamp that ends a store key.
fn key_timestamp(key: &[u8]) -> Option<i64> {
    let at = key.len().checked_sub(TIMESTAMP_SIZE)?;
    let bytes = <[u8; TIMESTAMP_SIZE]>::try_from(key.get(at..)?).ok()?;
    Some(i64::from_be_bytes(bytes))
}

/// The store a request's kind is read from, and how that kind is keyed.
struct KindStore<'db> {
    store: Box<dyn EventStore<'db> + 'db>,
    layout: KindLayout,
}

/// Opens the store the requested `kind` is read from.
///
/// The kind is parsed as `ReqRange` and `RawData` parse it, so an unknown
/// string is a log kind. The kinds those requests do not serve are refused
/// here too.
///
/// # Errors
///
/// Returns the reason the request cannot be served if the kind is not served
/// or its store cannot be opened.
fn open_kind_store<'db>(db: &'db Database, kind: &str) -> Result<KindStore<'db>, String> {
    fn open<'db, T>(
        store: Result<RawEventStore<'db, T>>,
        name: &str,
        layout: KindLayout,
    ) -> Result<KindStore<'db>, String>
    where
        T: DeserializeOwned + ResponseRangeData + Send + 'db,
    {
        store
            .map(|store| KindStore {
                store: Box::new(store),
                layout,
            })
            .map_err(|e| format!("failed to open the {name} store: {e:#}"))
    }

    use KindLayout::Event;
    match RawEventKind::from_str(kind).unwrap_or_default() {
        RawEventKind::Conn => open::<Conn>(db.conn_store(), "conn", Event),
        RawEventKind::Dns => open::<Dns>(db.dns_store(), "dns", Event),
        RawEventKind::MalformedDns => {
            open::<MalformedDns>(db.malformed_dns_store(), "malformed_dns", Event)
        }
        RawEventKind::Rdp => open::<Rdp>(db.rdp_store(), "rdp", Event),
        RawEventKind::Http => open::<Http>(db.http_store(), "http", Event),
        RawEventKind::Smtp => open::<Smtp>(db.smtp_store(), "smtp", Event),
        RawEventKind::Log => open::<Log>(db.log_store(), "log", KindLayout::Log),
        RawEventKind::Ntlm => open::<Ntlm>(db.ntlm_store(), "ntlm", Event),
        RawEventKind::Kerberos => open::<Kerberos>(db.kerberos_store(), "kerberos", Event),
        RawEventKind::Ssh => open::<Ssh>(db.ssh_store(), "ssh", Event),
        RawEventKind::DceRpc => open::<DceRpc>(db.dce_rpc_store(), "dce rpc", Event),
        RawEventKind::Ftp => open::<Ftp>(db.ftp_store(), "ftp", Event),
        RawEventKind::Mqtt => open::<Mqtt>(db.mqtt_store(), "mqtt", Event),
        RawEventKind::PeriodicTimeSeries => open::<PeriodicTimeSeries>(
            db.periodic_time_series_store(),
            "periodic time series",
            KindLayout::TimeSeries,
        ),
        RawEventKind::Ldap => open::<Ldap>(db.ldap_store(), "ldap", Event),
        RawEventKind::Tls => open::<Tls>(db.tls_store(), "tls", Event),
        RawEventKind::Smb => open::<Smb>(db.smb_store(), "smb", Event),
        RawEventKind::Nfs => open::<Nfs>(db.nfs_store(), "nfs", Event),
        RawEventKind::Bootp => open::<Bootp>(db.bootp_store(), "bootp", Event),
        RawEventKind::Dhcp => open::<Dhcp>(db.dhcp_store(), "dhcp", Event),
        RawEventKind::Radius => open::<Radius>(db.radius_store(), "radius", Event),
        RawEventKind::Icmp => open::<Icmp>(db.icmp_store(), "icmp", Event),
        RawEventKind::ProcessCreate => {
            open::<ProcessCreate>(db.process_create_store(), "process_create", Event)
        }
        RawEventKind::FileCreateTime => {
            open::<FileCreationTimeChanged>(db.file_create_time_store(), "file_create_time", Event)
        }
        RawEventKind::NetworkConnect => {
            open::<NetworkConnection>(db.network_connect_store(), "network_connect", Event)
        }
        RawEventKind::ProcessTerminate => {
            open::<ProcessTerminated>(db.process_terminate_store(), "process_terminate", Event)
        }
        RawEventKind::ImageLoad => open::<ImageLoaded>(db.image_load_store(), "image_load", Event),
        RawEventKind::FileCreate => {
            open::<FileCreate>(db.file_create_store(), "file_create", Event)
        }
        RawEventKind::RegistryValueSet => {
            open::<RegistryValueSet>(db.registry_value_set_store(), "registry_value_set", Event)
        }
        RawEventKind::RegistryKeyRename => open::<RegistryKeyValueRename>(
            db.registry_key_rename_store(),
            "registry_key_rename",
            Event,
        ),
        RawEventKind::FileCreateStreamHash => open::<FileCreateStreamHash>(
            db.file_create_stream_hash_store(),
            "file_create_stream_hash",
            Event,
        ),
        RawEventKind::PipeEvent => open::<PipeEvent>(db.pipe_event_store(), "pipe_event", Event),
        RawEventKind::DnsQuery => open::<DnsEvent>(db.dns_query_store(), "dns_query", Event),
        RawEventKind::FileDelete => {
            open::<FileDelete>(db.file_delete_store(), "file_delete", Event)
        }
        RawEventKind::ProcessTamper => {
            open::<ProcessTampering>(db.process_tamper_store(), "process_tamper", Event)
        }
        RawEventKind::FileDeleteDetected => open::<FileDeleteDetected>(
            db.file_delete_detected_store(),
            "file_delete_detected",
            Event,
        ),
        RawEventKind::Netflow5 => open::<Netflow5>(db.netflow5_store(), "netflow5", Event),
        RawEventKind::Netflow9 => open::<Netflow9>(db.netflow9_store(), "netflow9", Event),
        // `statistics`, `op_log`, `packet` and `secu_log`, which `ReqRange` and
        // `RawData` do not serve either, and any kind added after them.
        _ => Err(format!("kind {kind} is not served by range reads")),
    }
}

/// One event of a multi-source read, encoded as the frame the client
/// receives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SourceEvent {
    pub(super) timestamp: i64,
    /// The source's position in the request's `sources`.
    pub(super) source: usize,
    pub(super) frame: Vec<u8>,
}

/// One input of the merge: a stream of events sorted by timestamp and then by
/// source position, which ends with `Err(reason)` if it breaks off.
pub(super) type MergeInput<'a> =
    Pin<Box<dyn Stream<Item = Result<SourceEvent, String>> + Send + 'a>>;

/// Where the merged events of a multi-source read go.
pub(super) trait EventSink {
    /// Writes one event.
    fn emit(&mut self, event: SourceEvent) -> impl Future<Output = Result<()>> + Send;
}

impl EventSink for SendStream {
    async fn emit(&mut self, event: SourceEvent) -> Result<()> {
        send_raw(self, &event.frame).await?;
        Ok(())
    }
}

/// Merges `inputs` into one stream in time order and writes it to `sink`,
/// stopping after `count` events and the boundary rule.
///
/// Events with equal timestamps are ordered by source position, and events of
/// one input keep the input's order. Once `count` events have been written,
/// writing continues only while the next event has the source and the
/// timestamp of the event just written, so each source's next read can start
/// at its last timestamp plus one without losing an event.
///
/// An input that yields `Err(reason)` leaves the merge with the events it
/// has already contributed, and the others go on. Returns, per input, the
/// reason it broke off, if it did.
///
/// # Errors
///
/// Returns an error if writing to `sink` fails.
pub(super) async fn merge_source_events<S, K>(
    inputs: &mut [S],
    count: usize,
    sink: &mut K,
) -> Result<Vec<Option<String>>>
where
    S: Stream<Item = Result<SourceEvent, String>> + Unpin,
    K: EventSink,
{
    let mut failures: Vec<Option<String>> = vec![None; inputs.len()];
    let mut heads = Vec::with_capacity(inputs.len());
    for (input, failure) in inputs.iter_mut().zip(failures.iter_mut()) {
        heads.push(next_head(input, failure).await);
    }

    let mut sent = 0;
    let mut last = None;
    while let Some((position, order)) = heads
        .iter()
        .enumerate()
        .filter_map(|(position, head)| {
            head.as_ref()
                .map(|event| (position, (event.timestamp, event.source)))
        })
        .min_by_key(|(_, order)| *order)
    {
        if sent >= count && last != Some(order) {
            break;
        }
        let (Some(head), Some(input), Some(failure)) = (
            heads.get_mut(position),
            inputs.get_mut(position),
            failures.get_mut(position),
        ) else {
            break;
        };
        let Some(event) = head.take() else {
            break;
        };
        sink.emit(event).await?;
        sent += 1;
        last = Some(order);
        *head = next_head(input, failure).await;
    }
    Ok(failures)
}

async fn next_head<S>(input: &mut S, failure: &mut Option<String>) -> Option<SourceEvent>
where
    S: Stream<Item = Result<SourceEvent, String>> + Unpin,
{
    match input.next().await {
        Some(Ok(event)) => Some(event),
        Some(Err(reason)) => {
            *failure = Some(reason);
            None
        }
        None => None,
    }
}

/// Serves a multi-source range read (`MessageCode::MultiSourceRange`) whose
/// body is `body`.
///
/// # Errors
///
/// Returns an error if writing the response to `send` fails. A request that
/// cannot be served is answered with a failure status, not an error.
pub(super) async fn process_multi_source_range(
    send: &mut SendStream,
    db: &Database,
    body: &[u8],
    routing: &Routing<'_>,
) -> Result<()> {
    let status = serve_multi_source_range(send, db, body, routing).await?;
    if let Err(reason) = &status {
        warn!("Refused a multi-source range request: {reason}");
    }
    finish_status_response(send, &status, routing.token).await
}

/// Serves a re-read with status (`MessageCode::RawDataWithStatus`) whose body
/// is `body`.
///
/// # Errors
///
/// Returns an error if writing the response to `send` fails. A request that
/// cannot be served is answered with a failure status, not an error.
pub(super) async fn process_raw_data_with_status(
    send: &mut SendStream,
    db: &Database,
    body: &[u8],
    routing: &Routing<'_>,
) -> Result<()> {
    let status = serve_raw_data_with_status(send, db, body, routing).await?;
    if let Err(reason) = &status {
        warn!("Refused a raw-data request with status: {reason}");
    }
    finish_status_response(send, &status, routing.token).await
}

async fn serve_multi_source_range(
    send: &mut SendStream,
    db: &Database,
    body: &[u8],
    routing: &Routing<'_>,
) -> Result<RangeStatus> {
    let request = match bincode::deserialize::<RequestMultiSourceRange>(body) {
        Ok(request) => request,
        Err(e) => return Ok(Err(format!("failed to deserialize the request: {e}"))),
    };
    if let Err(reason) = check_sources(&request.sources) {
        return Ok(Err(reason));
    }
    let kind_store = match open_kind_store(db, &request.kind) {
        Ok(kind_store) => kind_store,
        Err(reason) => return Ok(Err(reason)),
    };
    let layout = kind_store.layout;
    let mid_key = (layout == KindLayout::Log).then_some(request.kind.as_bytes());

    let mut statuses: Vec<Option<SourceStatus>> = vec![None; request.sources.len()];
    let mut local = Vec::new();
    let mut peer_reads: Vec<PeerRead> = Vec::new();
    for (position, (source, _)) in request.sources.iter().enumerate() {
        match route_source(source, layout, routing).await {
            Route::Local => local.push(position),
            Route::Peer(addr) => add_to_peer(&mut peer_reads, addr, source, position),
            Route::NoNode => set_status(&mut statuses, position, SourceStatus::NoNode),
        }
    }

    join_all(peer_reads.iter_mut().map(|peer| {
        let peer_request = RequestMultiSourceRange {
            kind: request.kind.clone(),
            sources: peer
                .sources
                .iter()
                .filter_map(|(_, position)| request.sources.get(*position).cloned())
                .collect(),
            end: request.end,
            count: request.count,
        };
        peer.open(routing, MessageCode::MultiSourceRange, peer_request)
    }))
    .await;

    let mut inputs: Vec<MergeInput<'_>> = Vec::with_capacity(local.len() + peer_reads.len());
    let mut local_owners = Vec::with_capacity(local.len());
    for position in local {
        let Some((source, start)) = request.sources.get(position) else {
            continue;
        };
        let events = kind_store
            .store
            .range_frames(source, mid_key, *start, request.end)
            .map(move |event| {
                event.map(|(timestamp, frame)| SourceEvent {
                    timestamp,
                    source: position,
                    frame,
                })
            });
        inputs.push(Box::pin(stream::iter(events)));
        local_owners.push(position);
    }
    for peer in &mut peer_reads {
        inputs.push(peer.events(layout, routing.token, routing.peer_timeout));
    }

    let merged = merge_source_events(&mut inputs, request.count, send).await;
    drop(inputs);
    let failures = match merged {
        Ok(failures) => failures,
        Err(e) => {
            join_all(peer_reads.iter_mut().map(PeerRead::close)).await;
            return Err(e);
        }
    };
    for (position, failure) in local_owners.into_iter().zip(failures) {
        let status = failure.map_or(SourceStatus::Served, SourceStatus::Failed);
        set_status(&mut statuses, position, status);
    }

    // Each peer is read through to its status frame, discarding events past
    // the stop point, so its sources' statuses are known.
    join_all(
        peer_reads
            .iter_mut()
            .map(|peer| peer.finish(layout, routing.token, routing.peer_timeout)),
    )
    .await;
    for peer in &peer_reads {
        peer.apply_statuses(&mut statuses);
    }

    Ok(Ok(collect_statuses(
        request.sources.into_iter().map(|(source, _)| source),
        statuses,
    )))
}

async fn serve_raw_data_with_status(
    send: &mut SendStream,
    db: &Database,
    body: &[u8],
    routing: &Routing<'_>,
) -> Result<RangeStatus> {
    let request = match bincode::deserialize::<RequestRawData>(body) {
        Ok(request) => request,
        Err(e) => return Ok(Err(format!("failed to deserialize the request: {e}"))),
    };
    let kind_store = match open_kind_store(db, &request.kind) {
        Ok(kind_store) => kind_store,
        Err(reason) => return Ok(Err(reason)),
    };
    let layout = kind_store.layout;
    let mid_key = (layout == KindLayout::Log).then_some(request.kind.as_bytes());

    // One entry per distinct source, in order of first appearance.
    let mut inputs: Vec<(String, Vec<i64>)> = Vec::new();
    let mut positions: HashMap<String, usize> = HashMap::new();
    for (source, timestamps) in request.input {
        if let Some(entry) = positions
            .get(&source)
            .and_then(|position| inputs.get_mut(*position))
        {
            entry.1.extend(timestamps);
        } else {
            positions.insert(source.clone(), inputs.len());
            inputs.push((source, timestamps));
        }
    }

    let mut statuses: Vec<Option<SourceStatus>> = vec![None; inputs.len()];
    let mut peer_reads: Vec<PeerRead> = Vec::new();
    for (position, (source, timestamps)) in inputs.iter().enumerate() {
        match route_source(source, layout, routing).await {
            Route::Local => {
                let mut failure = None;
                for event in kind_store.store.lookup_frames(source, mid_key, timestamps) {
                    match event {
                        Ok((_, frame)) => send_raw(send, &frame).await?,
                        Err(reason) => {
                            failure.get_or_insert(reason);
                        }
                    }
                }
                let status = failure.map_or(SourceStatus::Served, SourceStatus::Failed);
                set_status(&mut statuses, position, status);
            }
            Route::Peer(addr) => add_to_peer(&mut peer_reads, addr, source, position),
            Route::NoNode => set_status(&mut statuses, position, SourceStatus::NoNode),
        }
    }

    for peer in &mut peer_reads {
        if routing.token.is_cancelled() {
            break;
        }
        let peer_request = RequestRawData {
            kind: request.kind.clone(),
            input: peer
                .sources
                .iter()
                .filter_map(|(_, position)| inputs.get(*position).cloned())
                .collect(),
        };
        peer.open(routing, MessageCode::RawDataWithStatus, peer_request)
            .await;
        while let Some(event) = peer
            .next_event(layout, routing.token, routing.peer_timeout)
            .await
        {
            // A broken-off peer has already recorded why; its events so far
            // stay delivered.
            if let Ok(event) = event
                && let Err(e) = send_raw(send, &event.frame).await
            {
                peer.close().await;
                return Err(e.into());
            }
        }
        peer.finish(layout, routing.token, routing.peer_timeout)
            .await;
        peer.apply_statuses(&mut statuses);
    }

    Ok(Ok(collect_statuses(
        inputs.into_iter().map(|(source, _)| source),
        statuses,
    )))
}

/// Refuses a multi-source request whose source list is empty or names a
/// source twice.
fn check_sources(sources: &[(String, i64)]) -> Result<(), String> {
    if sources.is_empty() {
        return Err("the request names no source".to_string());
    }
    let mut seen = HashSet::with_capacity(sources.len());
    for (source, _) in sources {
        if !seen.insert(source.as_str()) {
            return Err(format!("source {source} appears more than once"));
        }
    }
    Ok(())
}

/// Who serves one source.
enum Route {
    Local,
    Peer(SocketAddr),
    NoNode,
}

async fn route_source(source: &str, layout: KindLayout, routing: &Routing<'_>) -> Route {
    // Time series are stored under sampling-policy IDs, which no sensor set
    // carries, and are never routed to a peer.
    if layout == KindLayout::TimeSeries
        || is_current_giganto_in_charge(routing.ingest_sensors.clone(), source).await
    {
        Route::Local
    } else if let Some(addr) = peer_in_charge_publish_addr(routing.peers.clone(), source).await {
        Route::Peer(addr)
    } else {
        Route::NoNode
    }
}

fn add_to_peer(peer_reads: &mut Vec<PeerRead>, addr: SocketAddr, source: &str, position: usize) {
    if let Some(peer) = peer_reads.iter_mut().find(|peer| peer.addr == addr) {
        peer.sources.push((source.to_string(), position));
    } else {
        peer_reads.push(PeerRead::new(addr, source.to_string(), position));
    }
}

fn set_status(statuses: &mut [Option<SourceStatus>], position: usize, status: SourceStatus) {
    if let Some(slot) = statuses.get_mut(position) {
        *slot = Some(status);
    }
}

fn collect_statuses(
    sources: impl Iterator<Item = String>,
    statuses: Vec<Option<SourceStatus>>,
) -> Vec<(String, SourceStatus)> {
    sources
        .zip(statuses)
        .map(|(source, status)| {
            let status = status.unwrap_or_else(|| {
                SourceStatus::Failed("no status was recorded for the source".to_string())
            });
            (source, status)
        })
        .collect()
}

/// Writes the terminator and the status frame of a multi-source read or a
/// re-read with status, and finishes the stream, unless `token` has fired.
///
/// This is the sibling of `finish_range_response` for the two requests whose
/// response ends with a status frame, and it keeps the same cancellation
/// rule: a cancelled request leaves its stream unterminated and sends no
/// status, so the client sees an incomplete response and retries.
async fn finish_status_response(
    send: &mut SendStream,
    status: &RangeStatus,
    token: &CancellationToken,
) -> Result<()> {
    if token.is_cancelled() {
        return Ok(());
    }
    // The terminator is `None`, which encodes the same for every payload type.
    let terminator = bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&None)?;
    send_raw(send, &terminator).await?;
    send_range_status(send, status).await?;
    send.finish()?;
    Ok(())
}

/// The connection and stream of a request forwarded to a peer.
struct PeerLink {
    endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl PeerLink {
    async fn close(self) {
        let PeerLink {
            endpoint,
            connection,
            mut send,
            recv,
        } = self;
        send.finish().ok();
        drop(recv);
        close_peer_connection(&endpoint, &connection).await;
    }
}

/// The result of one bounded wait on a peer.
enum PeerWait<T> {
    Done(T),
    Failed(String),
    Cancelled,
}

/// Dials the peer and writes one request to it, bounding each step by
/// `timeout`.
///
/// This is the timed counterpart of `request_range_data_to_peer`, which
/// `ReqRange` keeps using: `connect` runs under one timeout, and opening the
/// stream and writing the request under another. A timed-out dial or
/// handshake is dropped with `connect`; a connection `connect` has returned is
/// closed. Cancellation is reported as such rather than as a failure.
async fn request_to_peer_timed<T>(
    peer_addr: SocketAddr,
    peer_name: &str,
    tls_watch: &TlsWatch,
    message_code: MessageCode,
    request: T,
    token: &CancellationToken,
    timeout: Duration,
) -> PeerWait<PeerLink>
where
    T: Serialize,
{
    let (endpoint, connection) = match tokio::time::timeout(
        timeout,
        connect(peer_addr, peer_name, tls_watch, token),
    )
    .await
    {
        Err(_) => {
            return PeerWait::Failed(format!(
                "connecting and the handshake timed out after {timeout:?}"
            ));
        }
        Ok(Err(e)) => return PeerWait::Failed(format!("connecting failed: {e:#}")),
        Ok(Ok(None)) => return PeerWait::Cancelled,
        Ok(Ok(Some(connected))) => connected,
    };

    let requested = tokio::time::timeout(
        timeout,
        token.run_until_cancelled(async {
            let (mut send, recv) = connection
                .open_bi()
                .await
                .map_err(|e| format!("opening a stream failed: {e}"))?;
            send_range_data_request(&mut send, message_code, request)
                .await
                .map_err(|e| format!("sending the request failed: {e}"))?;
            Ok::<_, String>((send, recv))
        }),
    )
    .await;
    match requested {
        Ok(Some(Ok((send, recv)))) => PeerWait::Done(PeerLink {
            endpoint,
            connection,
            send,
            recv,
        }),
        Ok(Some(Err(reason))) => {
            close_peer_connection(&endpoint, &connection).await;
            PeerWait::Failed(reason)
        }
        Ok(None) => {
            close_peer_connection(&endpoint, &connection).await;
            PeerWait::Cancelled
        }
        Err(_) => {
            close_peer_connection(&endpoint, &connection).await;
            PeerWait::Failed(format!(
                "opening a stream and sending the request timed out after {timeout:?}"
            ))
        }
    }
}

/// Where a peer's part of a request stands.
enum PeerState {
    /// Event frames are still arriving.
    Reading,
    /// The terminator has arrived; the status frame is next.
    Terminated,
    /// The peer's status frame has arrived.
    Reported(RangeStatus),
    /// The peer cannot serve its sources; the reason names the peer.
    Failed(String),
    /// The request was cancelled during shutdown.
    Cancelled,
}

/// One peer's part of a multi-source read or a re-read with status: the
/// sources forwarded to it and the state of its response.
struct PeerRead {
    addr: SocketAddr,
    /// Names the peer in failure reasons.
    label: String,
    /// The sources forwarded to the peer, with their positions in the
    /// response's statuses.
    sources: Vec<(String, usize)>,
    link: Option<PeerLink>,
    state: PeerState,
    buf: Vec<u8>,
}

impl PeerRead {
    fn new(addr: SocketAddr, source: String, position: usize) -> Self {
        Self {
            addr,
            label: format!("peer at {addr}"),
            sources: vec![(source, position)],
            link: None,
            state: PeerState::Reading,
            buf: Vec::new(),
        }
    }

    /// Resolves the peer's server name, dials it, and sends it `request`.
    async fn open<T>(&mut self, routing: &Routing<'_>, message_code: MessageCode, request: T)
    where
        T: Serialize,
    {
        let name = match peer_name(routing.peer_idents.clone(), &self.addr).await {
            Ok(name) => name,
            Err(e) => {
                self.fail(format!("its server name could not be resolved: {e}"))
                    .await;
                return;
            }
        };
        self.label = format!("peer {name} at {}", self.addr);
        match request_to_peer_timed(
            self.addr,
            &name,
            routing.tls_watch,
            message_code,
            request,
            routing.token,
            routing.peer_timeout,
        )
        .await
        {
            PeerWait::Done(link) => self.link = Some(link),
            PeerWait::Failed(reason) => {
                self.fail(reason).await;
            }
            PeerWait::Cancelled => self.state = PeerState::Cancelled,
        }
    }

    /// Returns the peer's events as a merge input.
    fn events<'a>(
        &'a mut self,
        layout: KindLayout,
        token: &'a CancellationToken,
        timeout: Duration,
    ) -> MergeInput<'a> {
        Box::pin(stream::unfold(self, move |peer| async move {
            let event = peer.next_event(layout, token, timeout).await?;
            Some((event, peer))
        }))
    }

    /// Reads the peer's next event, or `None` once its terminator has
    /// arrived or it can send no more.
    async fn next_event(
        &mut self,
        layout: KindLayout,
        token: &CancellationToken,
        timeout: Duration,
    ) -> Option<Result<SourceEvent, String>> {
        if !matches!(self.state, PeerState::Reading) {
            return None;
        }
        let link = self.link.as_mut()?;
        let outcome = match tokio::time::timeout(
            timeout,
            token.run_until_cancelled(frame::recv_raw(&mut link.recv, &mut self.buf)),
        )
        .await
        {
            Err(_) => Err(format!(
                "waiting for its response timed out after {timeout:?}"
            )),
            Ok(None) => {
                self.cancel().await;
                return None;
            }
            Ok(Some(Err(e))) => Err(format!("its response broke off: {e}")),
            Ok(Some(Ok(()))) => decode_event_header(&self.buf, layout)
                .map_err(|e| format!("it sent an event that could not be decoded: {e}")),
        };
        let header = match outcome {
            Ok(header) => header,
            Err(reason) => return Some(Err(self.fail(reason).await)),
        };
        let Some((timestamp, source)) = header else {
            self.state = PeerState::Terminated;
            return None;
        };
        let Some(position) = self
            .sources
            .iter()
            .find_map(|(name, position)| (*name == source).then_some(*position))
        else {
            let reason = format!("it sent an event of source {source}, which it was not asked for");
            return Some(Err(self.fail(reason).await));
        };
        Some(Ok(SourceEvent {
            timestamp,
            source: position,
            frame: std::mem::take(&mut self.buf),
        }))
    }

    /// Reads the rest of the peer's response through to its status frame,
    /// discarding any events, and closes the connection.
    async fn finish(&mut self, layout: KindLayout, token: &CancellationToken, timeout: Duration) {
        while self.next_event(layout, token, timeout).await.is_some() {}
        if matches!(self.state, PeerState::Terminated)
            && let Some(link) = self.link.as_mut()
        {
            match tokio::time::timeout(
                timeout,
                token.run_until_cancelled(receive_range_status(&mut link.recv)),
            )
            .await
            {
                Err(_) => {
                    self.fail(format!(
                        "waiting for its status timed out after {timeout:?}"
                    ))
                    .await;
                }
                Ok(None) => self.cancel().await,
                Ok(Some(Err(e))) => {
                    self.fail(format!("its response ended without a status: {e}"))
                        .await;
                }
                Ok(Some(Ok(status))) => self.state = PeerState::Reported(status),
            }
        }
        self.close().await;
    }

    /// Records each of the peer's sources' status in `statuses`.
    fn apply_statuses(&self, statuses: &mut [Option<SourceStatus>]) {
        for (source, position) in &self.sources {
            let status = match &self.state {
                PeerState::Reported(Ok(reported)) => reported
                    .iter()
                    .find_map(|(name, status)| (name == source).then(|| status.clone()))
                    .unwrap_or_else(|| {
                        SourceStatus::Failed(format!(
                            "{}: its status did not list the source",
                            self.label
                        ))
                    }),
                PeerState::Reported(Err(reason)) => SourceStatus::Failed(format!(
                    "{}: it failed the whole request: {reason}",
                    self.label
                )),
                PeerState::Failed(reason) => SourceStatus::Failed(reason.clone()),
                PeerState::Reading | PeerState::Terminated | PeerState::Cancelled => {
                    SourceStatus::Failed(format!("{}: its response is incomplete", self.label))
                }
            };
            set_status(statuses, *position, status);
        }
    }

    /// Records why the peer cannot serve its sources, closes its connection,
    /// and returns the recorded reason.
    async fn fail(&mut self, reason: String) -> String {
        let reason = format!("{}: {reason}", self.label);
        self.state = PeerState::Failed(reason.clone());
        self.close().await;
        reason
    }

    async fn cancel(&mut self) {
        self.state = PeerState::Cancelled;
        self.close().await;
    }

    async fn close(&mut self) {
        if let Some(link) = self.link.take() {
            link.close().await;
        }
    }
}

/// Decodes the timestamp and the source of an event frame, or `None` for the
/// terminator, using the kind's payload type.
fn decode_event_header(
    frame: &[u8],
    layout: KindLayout,
) -> Result<Option<(i64, String)>, bincode::Error> {
    Ok(match layout {
        KindLayout::TimeSeries => bincode::deserialize::<Option<(i64, String, Vec<f64>)>>(frame)?
            .map(|(timestamp, source, _)| (timestamp, source)),
        KindLayout::Event | KindLayout::Log => {
            bincode::deserialize::<Option<(i64, String, Vec<u8>)>>(frame)?
                .map(|(timestamp, source, _)| (timestamp, source))
        }
    })
}
