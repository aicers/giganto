//! The conversion of a senta telemetry record into the giganto-client struct
//! it is stored as, and the record kinds the endpoint entry accepts.
//!
//! A record of a Sysmon kind becomes the struct of the matching Sysmon event
//! kind, with the record's header in its `endpoint`; a record of a log kind
//! becomes one of the endpoint log structs. [`ACCEPTED_KINDS`] lists exactly
//! the senta kinds [`convert`] converts, and the entry announces them in its
//! `hello_ack`.

use std::{
    fmt::{Debug, Write},
    net::{IpAddr, Ipv4Addr},
};

use giganto_client::{
    RawEventKind,
    ingest::{
        endpoint::{ClockOffset, CollectionMode, EndpointHeader, NetStateSource, OsFamily},
        log::{AuditRecord, Auditd, EventData, Journald, LogField, LogValue, WindowsEventLog},
        sysmon::{
            CreateRemoteThread, DnsEvent, DriverLoad, FileCreate, FileCreateStreamHash,
            FileCreationTimeChanged, FileDelete, FileDeleteDetected, ImageLoaded,
            NetworkConnection, PipeEvent, ProcessAccess, ProcessCreate, ProcessTampering,
            ProcessTerminated, RawAccessRead, RegistryKeyValueRename, RegistryObjectAddDel,
            RegistryValueSet,
        },
    },
};
use jiff::Timestamp;
use senta_protocol::{
    connection::{AcceptedKind, ClockOffset as SentaClockOffset, cbor},
    host::{CollectionMode as SentaCollectionMode, OsFamily as SentaOsFamily},
    telemetry::{
        NetStateSource as SentaNetStateSource, Record, RecordHeader, kind, logs,
        sysmon::{self, HashEntry},
    },
};
use serde::Serialize;
use uuid::Uuid;

/// The senta record kinds the endpoint entry accepts, in ascending order:
/// every kind [`convert`] converts, and no other.
pub(super) const ACCEPTED_KINDS: [u16; 22] = [
    kind::SYSMON_PROCESS_CREATE,
    kind::SYSMON_FILE_CREATE_TIME,
    kind::SYSMON_NETWORK_CONNECT,
    kind::SYSMON_PROCESS_TERMINATE,
    kind::SYSMON_DRIVER_LOAD,
    kind::SYSMON_IMAGE_LOAD,
    kind::SYSMON_CREATE_REMOTE_THREAD,
    kind::SYSMON_RAW_ACCESS_READ,
    kind::SYSMON_PROCESS_ACCESS,
    kind::SYSMON_FILE_CREATE,
    kind::SYSMON_REGISTRY_ADD_DELETE,
    kind::SYSMON_REGISTRY_VALUE_SET,
    kind::SYSMON_REGISTRY_RENAME,
    kind::SYSMON_FILE_CREATE_STREAM_HASH,
    kind::SYSMON_PIPE_CREATED,
    kind::SYSMON_DNS_QUERY,
    kind::SYSMON_FILE_DELETE,
    kind::SYSMON_PROCESS_TAMPERING,
    kind::SYSMON_FILE_DELETE_DETECTED,
    kind::WINDOWS_EVENT_LOG,
    kind::JOURNALD,
    kind::AUDITD,
];

/// The raw-data column families the records of [`ACCEPTED_KINDS`] are stored
/// in, one per kind: the 14 Sysmon kinds module ingest also stores, and the
/// eight added for endpoints. Customer data deletion deletes an endpoint's
/// records from these.
pub(crate) const RECORD_COLUMN_FAMILIES: [&str; 22] = [
    "process create",
    "file create time",
    "network connect",
    "process terminate",
    "driver load",
    "image load",
    "create remote thread",
    "raw access read",
    "process access",
    "file create",
    "registry object add del",
    "registry value set",
    "registry key rename",
    "file create stream hash",
    "pipe event",
    "dns query",
    "file delete",
    "process tamper",
    "file delete detected",
    "endpoint windows event log",
    "endpoint journald",
    "endpoint auditd",
];

/// The one schema version of each accepted kind the entry reads.
const ACCEPTED_SCHEMA: u16 = 1;

/// The separator of the results in a Sysmon `DnsQuery`'s `QueryResults`.
const DNS_QUERY_RESULTS_SEPARATOR: char = ';';

/// Returns the accepted kinds the entry announces in its `hello_ack`: each of
/// [`ACCEPTED_KINDS`] at schema version 1 only.
pub(super) fn accepted_kinds() -> Vec<AcceptedKind> {
    ACCEPTED_KINDS
        .iter()
        .map(|&kind| AcceptedKind {
            kind,
            schema_min: ACCEPTED_SCHEMA,
            schema_max: ACCEPTED_SCHEMA,
        })
        .collect()
}

/// A senta record converted into the giganto-client struct it is stored as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConvertedRecord {
    /// The storage sensor: the header's `endpoint_id`, lowercase hyphenated.
    pub(crate) sensor: String,
    /// The storage time: the header's `event_time` in nanoseconds since the
    /// Unix epoch.
    pub(crate) timestamp: i64,
    /// The giganto-client struct.
    pub(crate) event: EndpointEvent,
}

impl ConvertedRecord {
    /// Returns the Giganto event kind the record is stored as.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn kind(&self) -> RawEventKind {
        self.event.kind()
    }
}

/// The giganto-client struct of a converted endpoint record.
///
/// The structs are boxed: they differ in size by several hundred bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EndpointEvent {
    ProcessCreate(Box<ProcessCreate>),
    FileCreateTime(Box<FileCreationTimeChanged>),
    NetworkConnect(Box<NetworkConnection>),
    ProcessTerminate(Box<ProcessTerminated>),
    DriverLoad(Box<DriverLoad>),
    ImageLoad(Box<ImageLoaded>),
    CreateRemoteThread(Box<CreateRemoteThread>),
    RawAccessRead(Box<RawAccessRead>),
    ProcessAccess(Box<ProcessAccess>),
    FileCreate(Box<FileCreate>),
    RegistryObjectAddDel(Box<RegistryObjectAddDel>),
    RegistryValueSet(Box<RegistryValueSet>),
    RegistryKeyRename(Box<RegistryKeyValueRename>),
    FileCreateStreamHash(Box<FileCreateStreamHash>),
    PipeEvent(Box<PipeEvent>),
    DnsQuery(Box<DnsEvent>),
    FileDelete(Box<FileDelete>),
    ProcessTamper(Box<ProcessTampering>),
    FileDeleteDetected(Box<FileDeleteDetected>),
    WindowsEventLog(Box<WindowsEventLog>),
    Journald(Box<Journald>),
    Auditd(Box<Auditd>),
}

impl EndpointEvent {
    /// Returns the Giganto event kind of the struct.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn kind(&self) -> RawEventKind {
        match self {
            Self::ProcessCreate(_) => RawEventKind::ProcessCreate,
            Self::FileCreateTime(_) => RawEventKind::FileCreateTime,
            Self::NetworkConnect(_) => RawEventKind::NetworkConnect,
            Self::ProcessTerminate(_) => RawEventKind::ProcessTerminate,
            Self::DriverLoad(_) => RawEventKind::DriverLoad,
            Self::ImageLoad(_) => RawEventKind::ImageLoad,
            Self::CreateRemoteThread(_) => RawEventKind::CreateRemoteThread,
            Self::RawAccessRead(_) => RawEventKind::RawAccessRead,
            Self::ProcessAccess(_) => RawEventKind::ProcessAccess,
            Self::FileCreate(_) => RawEventKind::FileCreate,
            Self::RegistryObjectAddDel(_) => RawEventKind::RegistryObjectAddDel,
            Self::RegistryValueSet(_) => RawEventKind::RegistryValueSet,
            Self::RegistryKeyRename(_) => RawEventKind::RegistryKeyRename,
            Self::FileCreateStreamHash(_) => RawEventKind::FileCreateStreamHash,
            Self::PipeEvent(_) => RawEventKind::PipeEvent,
            Self::DnsQuery(_) => RawEventKind::DnsQuery,
            Self::FileDelete(_) => RawEventKind::FileDelete,
            Self::ProcessTamper(_) => RawEventKind::ProcessTamper,
            Self::FileDeleteDetected(_) => RawEventKind::FileDeleteDetected,
            Self::WindowsEventLog(_) => RawEventKind::WindowsEventLog,
            Self::Journald(_) => RawEventKind::Journald,
            Self::Auditd(_) => RawEventKind::Auditd,
        }
    }

    /// Returns the raw-data column family the struct is stored in: the one
    /// module ingest stores its kind in, and the GraphQL, export and publish
    /// paths read.
    pub(crate) fn column_family(&self) -> &'static str {
        match self {
            Self::ProcessCreate(_) => "process create",
            Self::FileCreateTime(_) => "file create time",
            Self::NetworkConnect(_) => "network connect",
            Self::ProcessTerminate(_) => "process terminate",
            Self::DriverLoad(_) => "driver load",
            Self::ImageLoad(_) => "image load",
            Self::CreateRemoteThread(_) => "create remote thread",
            Self::RawAccessRead(_) => "raw access read",
            Self::ProcessAccess(_) => "process access",
            Self::FileCreate(_) => "file create",
            Self::RegistryObjectAddDel(_) => "registry object add del",
            Self::RegistryValueSet(_) => "registry value set",
            Self::RegistryKeyRename(_) => "registry key rename",
            Self::FileCreateStreamHash(_) => "file create stream hash",
            Self::PipeEvent(_) => "pipe event",
            Self::DnsQuery(_) => "dns query",
            Self::FileDelete(_) => "file delete",
            Self::ProcessTamper(_) => "process tamper",
            Self::FileDeleteDetected(_) => "file delete detected",
            Self::WindowsEventLog(_) => "endpoint windows event log",
            Self::Journald(_) => "endpoint journald",
            Self::Auditd(_) => "endpoint auditd",
        }
    }

    /// Returns the struct's bincode 1 serialization, the value module ingest
    /// stores for its kind.
    ///
    /// # Errors
    ///
    /// Returns an error if the struct cannot be serialized.
    pub(crate) fn to_bincode(&self) -> bincode::Result<Vec<u8>> {
        match self {
            Self::ProcessCreate(event) => bincode::serialize(event),
            Self::FileCreateTime(event) => bincode::serialize(event),
            Self::NetworkConnect(event) => bincode::serialize(event),
            Self::ProcessTerminate(event) => bincode::serialize(event),
            Self::DriverLoad(event) => bincode::serialize(event),
            Self::ImageLoad(event) => bincode::serialize(event),
            Self::CreateRemoteThread(event) => bincode::serialize(event),
            Self::RawAccessRead(event) => bincode::serialize(event),
            Self::ProcessAccess(event) => bincode::serialize(event),
            Self::FileCreate(event) => bincode::serialize(event),
            Self::RegistryObjectAddDel(event) => bincode::serialize(event),
            Self::RegistryValueSet(event) => bincode::serialize(event),
            Self::RegistryKeyRename(event) => bincode::serialize(event),
            Self::FileCreateStreamHash(event) => bincode::serialize(event),
            Self::PipeEvent(event) => bincode::serialize(event),
            Self::DnsQuery(event) => bincode::serialize(event),
            Self::FileDelete(event) => bincode::serialize(event),
            Self::ProcessTamper(event) => bincode::serialize(event),
            Self::FileDeleteDetected(event) => bincode::serialize(event),
            Self::WindowsEventLog(event) => bincode::serialize(event),
            Self::Journald(event) => bincode::serialize(event),
            Self::Auditd(event) => bincode::serialize(event),
        }
    }
}

/// Why a record could not be converted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ConvertError {
    /// The record's kind is not one of [`ACCEPTED_KINDS`].
    #[error("record kind {0} is not converted by the endpoint entry")]
    UnsupportedKind(u16),
    /// The body does not decode for the record's kind.
    #[error("the body of record kind {kind} does not decode: {reason}")]
    Body { kind: u16, reason: String },
    /// A time lies outside the range of an `i64` count of nanoseconds.
    #[error("{field} {time} is outside the range of i64 nanoseconds since the Unix epoch")]
    TimeOutOfRange {
        field: &'static str,
        time: Timestamp,
    },
}

/// Converts a senta record into the giganto-client struct it is stored as.
///
/// The record is trusted as the entry's receiver hands it over: its endpoint
/// id and kind have been checked against the connection and the accepted
/// kinds already. Its `schema` is copied into the header and not used to pick
/// a decoder.
///
/// # Errors
///
/// Returns [`ConvertError::UnsupportedKind`] when the kind is not one of
/// [`ACCEPTED_KINDS`], [`ConvertError::Body`] when the body does not decode
/// for the kind, and [`ConvertError::TimeOutOfRange`] when a header or body
/// time does not fit an `i64` count of nanoseconds.
pub(crate) fn convert(record: Record) -> Result<ConvertedRecord, ConvertError> {
    let Record {
        header,
        kind,
        schema,
        body,
    } = record;
    if !ACCEPTED_KINDS.contains(&kind) {
        return Err(ConvertError::UnsupportedKind(kind));
    }
    let endpoint = endpoint_header(header, schema)?;
    let sensor = endpoint.endpoint_id.to_string();
    let timestamp = endpoint.event_time;
    let agent = Agent {
        name: endpoint.hostname.clone(),
        id: sensor.clone(),
    };
    let event = if logs::KINDS.contains(&kind) {
        let body = logs::LogBody::decode(kind, &body).map_err(|e| ConvertError::Body {
            kind,
            reason: e.to_string(),
        })?;
        log_event(body, endpoint)?
    } else {
        let body = sysmon::Body::from_record_body(kind, &body).map_err(|e| match e {
            sysmon::BodyError::UnsupportedKind(kind) => ConvertError::UnsupportedKind(kind),
            e => ConvertError::Body {
                kind,
                reason: e.to_string(),
            },
        })?;
        sysmon_event(body, agent, endpoint)?
    };
    Ok(ConvertedRecord {
        sensor,
        timestamp,
        event,
    })
}

/// The `agent_name` and `agent_id` of a Sysmon struct.
struct Agent {
    name: String,
    id: String,
}

/// Builds the stored header from a record's header and schema version.
fn endpoint_header(header: RecordHeader, schema: u16) -> Result<EndpointHeader, ConvertError> {
    let RecordHeader {
        endpoint_id,
        stream,
        seq,
        event_time,
        collected_at,
        clock_offset,
        hostname,
        ips,
        default_route_ip,
        net_state_source,
        os,
        collection_mode,
        process_key,
    } = header;
    Ok(EndpointHeader {
        endpoint_id,
        stream,
        seq,
        event_time: nanos("event_time", event_time)?,
        collected_at: nanos("collected_at", collected_at)?,
        clock_offset: clock_offset.map(convert_clock_offset).transpose()?,
        hostname,
        ips,
        default_route_ip,
        net_state_source: convert_net_state_source(net_state_source),
        os_family: convert_os_family(os.family),
        os_version: os.version,
        collection_mode: convert_collection_mode(collection_mode),
        process_key: process_key.map(|key| key.value),
        schema,
    })
}

fn convert_clock_offset(offset: SentaClockOffset) -> Result<ClockOffset, ConvertError> {
    Ok(ClockOffset {
        offset_ms: offset.offset_ms,
        uncertainty_ms: offset.uncertainty_ms,
        measured_at: nanos("clock_offset.measured_at", offset.measured_at)?,
    })
}

fn convert_net_state_source(source: SentaNetStateSource) -> NetStateSource {
    match source {
        SentaNetStateSource::Observed => NetStateSource::Observed,
        SentaNetStateSource::Inferred => NetStateSource::Inferred,
        SentaNetStateSource::Unknown => NetStateSource::Unknown,
        SentaNetStateSource::Other(tag) => NetStateSource::Other(tag),
        other => NetStateSource::Other(wire_tag(&other)),
    }
}

fn convert_os_family(family: SentaOsFamily) -> OsFamily {
    match family {
        SentaOsFamily::Windows => OsFamily::Windows,
        SentaOsFamily::Linux => OsFamily::Linux,
        SentaOsFamily::Macos => OsFamily::Macos,
        SentaOsFamily::Other(tag) => OsFamily::Other(tag),
        other => OsFamily::Other(wire_tag(&other)),
    }
}

fn convert_collection_mode(mode: SentaCollectionMode) -> CollectionMode {
    match mode {
        SentaCollectionMode::Extended => CollectionMode::Extended,
        SentaCollectionMode::Essential => CollectionMode::Essential,
        SentaCollectionMode::Other(tag) => CollectionMode::Other(tag),
        other => CollectionMode::Other(wire_tag(&other)),
    }
}

/// Returns the text tag senta writes an enum's value as.
///
/// senta-protocol has no public accessor for the tag, so it is read back from
/// the value's CBOR. Should that fail, the value's `Debug` form stands in, so
/// that an unknown value never fails a conversion.
pub(super) fn wire_tag<T: Serialize + Debug>(value: &T) -> String {
    cbor::to_vec(value)
        .ok()
        .and_then(|bytes| cbor::from_slice::<String>(&bytes).ok())
        .unwrap_or_else(|| format!("{value:?}"))
}

/// Returns `time` as nanoseconds since the Unix epoch.
fn nanos(field: &'static str, time: Timestamp) -> Result<i64, ConvertError> {
    i64::try_from(time.as_nanosecond()).map_err(|_| ConvertError::TimeOutOfRange { field, time })
}

/// Returns a body time as nanoseconds since the Unix epoch, `0` when absent.
fn body_nanos(field: &'static str, time: Option<Timestamp>) -> Result<i64, ConvertError> {
    time.map_or(Ok(0), |time| nanos(field, time))
}

/// Returns a GUID in Sysmon's notation, braced uppercase hexadecimal, or an
/// empty string when absent.
fn guid(guid: Option<Uuid>) -> String {
    guid.map_or_default(|guid| format!("{:X}", guid.braced()))
}

/// Returns each hash as `ALGO=HEX`, the hexadecimal in uppercase.
fn hashes(hashes: Option<Vec<HashEntry>>) -> Vec<String> {
    hashes
        .unwrap_or_default()
        .into_iter()
        .map(|HashEntry { algo, value }| {
            let mut out = String::with_capacity(algo.len() + 1 + 2 * value.len());
            out.push_str(&algo);
            out.push('=');
            for byte in value {
                write!(out, "{byte:02X}").expect("writing to a String cannot fail");
            }
            out
        })
        .collect()
}

/// Returns whether a Sysmon flag written as text is `true`, in any case.
fn text_flag(flag: Option<&str>) -> bool {
    flag.is_some_and(|flag| flag.eq_ignore_ascii_case("true"))
}

/// Returns an IP address and whether it is `IPv6`: `0.0.0.0` and `false` when
/// the address is absent, else the address and the body's flag.
fn ip_with_flag(ip: Option<IpAddr>, is_ipv6: Option<bool>) -> (IpAddr, bool) {
    match ip {
        Some(ip) => (ip, is_ipv6.unwrap_or_default()),
        None => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), false),
    }
}

/// Returns `ProcessCreate`'s `logon_id` and `logon_id_full`.
fn logon_ids(logon_id: Option<u64>) -> (u32, Option<u64>) {
    match logon_id {
        Some(full) => (u32::try_from(full).unwrap_or(u32::MAX), Some(full)),
        None => (0, None),
    }
}

/// Returns a `DnsQuery`'s `QueryStatus` as a number, `0` when it is absent or
/// not a decimal `u32`.
fn query_status(status: Option<&str>) -> u32 {
    status
        .filter(|status| !status.is_empty() && status.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|status| status.parse().ok())
        .unwrap_or_default()
}

/// Returns a `DnsQuery`'s `QueryResults` split on `;`, every element kept; an
/// empty list when absent.
fn query_results(results: Option<String>) -> Vec<String> {
    results.map_or_default(|results| {
        results
            .split(DNS_QUERY_RESULTS_SEPARATOR)
            .map(str::to_owned)
            .collect()
    })
}

/// Returns `FileCreateStreamHash`'s `Hash` as a one-element list, or an empty
/// list when absent or empty.
fn stream_hash(hash: Option<String>) -> Vec<String> {
    hash.filter(|hash| !hash.is_empty()).into_iter().collect()
}

#[allow(clippy::too_many_lines)] // One arm per Sysmon kind, each a field list.
fn sysmon_event(
    body: sysmon::Body,
    agent: Agent,
    endpoint: EndpointHeader,
) -> Result<EndpointEvent, ConvertError> {
    let Agent {
        name: agent_name,
        id: agent_id,
    } = agent;
    let endpoint = Some(endpoint);
    let event = match body {
        sysmon::Body::ProcessCreate(b) => {
            let (logon_id, logon_id_full) = logon_ids(b.logon_id);
            EndpointEvent::ProcessCreate(Box::new(ProcessCreate {
                agent_name,
                agent_id,
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                file_version: b.file_version.unwrap_or_default(),
                description: b.description.unwrap_or_default(),
                product: b.product.unwrap_or_default(),
                company: b.company.unwrap_or_default(),
                original_file_name: b.original_file_name.unwrap_or_default(),
                command_line: b.command_line.unwrap_or_default(),
                current_directory: b.current_directory.unwrap_or_default(),
                user: b.user.unwrap_or_default(),
                logon_guid: guid(b.logon_guid),
                logon_id,
                terminal_session_id: b.terminal_session_id.unwrap_or_default(),
                integrity_level: b.integrity_level.unwrap_or_default(),
                hashes: hashes(b.hashes),
                parent_process_guid: guid(b.parent_process_guid),
                parent_process_id: b.parent_process_id.unwrap_or_default(),
                parent_image: b.parent_image.unwrap_or_default(),
                parent_command_line: b.parent_command_line.unwrap_or_default(),
                parent_user: b.parent_user.unwrap_or_default(),
                endpoint,
                logon_id_full,
            }))
        }
        sysmon::Body::FileCreateTime(b) => {
            EndpointEvent::FileCreateTime(Box::new(FileCreationTimeChanged {
                agent_name,
                agent_id,
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                target_filename: b.target_filename.unwrap_or_default(),
                creation_utc_time: body_nanos("creation_utc_time", b.creation_utc_time)?,
                previous_creation_utc_time: body_nanos(
                    "previous_creation_utc_time",
                    b.previous_creation_utc_time,
                )?,
                user: b.user.unwrap_or_default(),
                endpoint,
            }))
        }
        sysmon::Body::NetworkConnect(b) => {
            let (source_ip, source_is_ipv6) = ip_with_flag(b.source_ip, b.source_is_ipv6);
            let (destination_ip, destination_is_ipv6) =
                ip_with_flag(b.destination_ip, b.destination_is_ipv6);
            EndpointEvent::NetworkConnect(Box::new(NetworkConnection {
                agent_name,
                agent_id,
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                user: b.user.unwrap_or_default(),
                protocol: b.protocol.unwrap_or_default(),
                initiated: b.initiated.unwrap_or_default(),
                source_is_ipv6,
                source_ip,
                source_hostname: b.source_hostname.unwrap_or_default(),
                source_port: b.source_port.unwrap_or_default(),
                source_port_name: b.source_port_name.unwrap_or_default(),
                destination_is_ipv6,
                destination_ip,
                destination_hostname: b.destination_hostname.unwrap_or_default(),
                destination_port: b.destination_port.unwrap_or_default(),
                destination_port_name: b.destination_port_name.unwrap_or_default(),
                endpoint,
            }))
        }
        sysmon::Body::ProcessTerminate(b) => {
            EndpointEvent::ProcessTerminate(Box::new(ProcessTerminated {
                agent_name,
                agent_id,
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                user: b.user.unwrap_or_default(),
                endpoint,
            }))
        }
        sysmon::Body::DriverLoad(b) => EndpointEvent::DriverLoad(Box::new(DriverLoad {
            agent_name,
            agent_id,
            image_loaded: b.image_loaded.unwrap_or_default(),
            hashes: hashes(b.hashes),
            signed: text_flag(b.signed.as_deref()),
            signature: b.signature.unwrap_or_default(),
            signature_status: b.signature_status.unwrap_or_default(),
            endpoint,
        })),
        sysmon::Body::ImageLoad(b) => EndpointEvent::ImageLoad(Box::new(ImageLoaded {
            agent_name,
            agent_id,
            process_guid: guid(b.process_guid),
            process_id: b.process_id.unwrap_or_default(),
            image: b.image.unwrap_or_default(),
            image_loaded: b.image_loaded.unwrap_or_default(),
            file_version: b.file_version.unwrap_or_default(),
            description: b.description.unwrap_or_default(),
            product: b.product.unwrap_or_default(),
            company: b.company.unwrap_or_default(),
            original_file_name: b.original_file_name.unwrap_or_default(),
            hashes: hashes(b.hashes),
            signed: text_flag(b.signed.as_deref()),
            signature: b.signature.unwrap_or_default(),
            signature_status: b.signature_status.unwrap_or_default(),
            user: b.user.unwrap_or_default(),
            endpoint,
        })),
        sysmon::Body::CreateRemoteThread(b) => {
            EndpointEvent::CreateRemoteThread(Box::new(CreateRemoteThread {
                agent_name,
                agent_id,
                source_process_guid: guid(b.source_process_guid),
                source_process_id: b.source_process_id.unwrap_or_default(),
                source_image: b.source_image.unwrap_or_default(),
                target_process_guid: guid(b.target_process_guid),
                target_process_id: b.target_process_id.unwrap_or_default(),
                target_image: b.target_image.unwrap_or_default(),
                new_thread_id: b.new_thread_id.unwrap_or_default(),
                start_address: b.start_address.unwrap_or_default(),
                start_module: b.start_module.unwrap_or_default(),
                start_function: b.start_function.unwrap_or_default(),
                source_user: b.source_user.unwrap_or_default(),
                target_user: b.target_user.unwrap_or_default(),
                endpoint,
            }))
        }
        sysmon::Body::RawAccessRead(b) => EndpointEvent::RawAccessRead(Box::new(RawAccessRead {
            agent_name,
            agent_id,
            process_guid: guid(b.process_guid),
            process_id: b.process_id.unwrap_or_default(),
            image: b.image.unwrap_or_default(),
            device: b.device.unwrap_or_default(),
            user: b.user.unwrap_or_default(),
            endpoint,
        })),
        sysmon::Body::ProcessAccess(b) => EndpointEvent::ProcessAccess(Box::new(ProcessAccess {
            agent_name,
            agent_id,
            source_process_guid: guid(b.source_process_guid),
            source_process_id: b.source_process_id.unwrap_or_default(),
            source_thread_id: b.source_thread_id.unwrap_or_default(),
            source_image: b.source_image.unwrap_or_default(),
            target_process_guid: guid(b.target_process_guid),
            target_process_id: b.target_process_id.unwrap_or_default(),
            target_image: b.target_image.unwrap_or_default(),
            granted_access: b.granted_access.unwrap_or_default(),
            call_trace: b.call_trace.unwrap_or_default(),
            source_user: b.source_user.unwrap_or_default(),
            target_user: b.target_user.unwrap_or_default(),
            endpoint,
        })),
        sysmon::Body::FileCreate(b) => EndpointEvent::FileCreate(Box::new(FileCreate {
            agent_name,
            agent_id,
            process_guid: guid(b.process_guid),
            process_id: b.process_id.unwrap_or_default(),
            image: b.image.unwrap_or_default(),
            target_filename: b.target_filename.unwrap_or_default(),
            creation_utc_time: body_nanos("creation_utc_time", b.creation_utc_time)?,
            user: b.user.unwrap_or_default(),
            endpoint,
        })),
        sysmon::Body::RegistryAddDelete(b) => {
            EndpointEvent::RegistryObjectAddDel(Box::new(RegistryObjectAddDel {
                agent_name,
                agent_id,
                event_type: b.event_type.unwrap_or_default(),
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                target_object: b.target_object.unwrap_or_default(),
                user: b.user.unwrap_or_default(),
                endpoint,
            }))
        }
        sysmon::Body::RegistryValueSet(b) => {
            EndpointEvent::RegistryValueSet(Box::new(RegistryValueSet {
                agent_name,
                agent_id,
                event_type: b.event_type.unwrap_or_default(),
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                target_object: b.target_object.unwrap_or_default(),
                details: b.details.unwrap_or_default(),
                user: b.user.unwrap_or_default(),
                endpoint,
            }))
        }
        sysmon::Body::RegistryRename(b) => {
            EndpointEvent::RegistryKeyRename(Box::new(RegistryKeyValueRename {
                agent_name,
                agent_id,
                event_type: b.event_type.unwrap_or_default(),
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                target_object: b.target_object.unwrap_or_default(),
                new_name: b.new_name.unwrap_or_default(),
                user: b.user.unwrap_or_default(),
                endpoint,
            }))
        }
        sysmon::Body::FileCreateStreamHash(b) => {
            EndpointEvent::FileCreateStreamHash(Box::new(FileCreateStreamHash {
                agent_name,
                agent_id,
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                target_filename: b.target_filename.unwrap_or_default(),
                creation_utc_time: body_nanos("creation_utc_time", b.creation_utc_time)?,
                hash: stream_hash(b.hash),
                contents: b.contents.unwrap_or_default(),
                user: b.user.unwrap_or_default(),
                endpoint,
            }))
        }
        sysmon::Body::PipeCreated(b) => EndpointEvent::PipeEvent(Box::new(PipeEvent {
            agent_name,
            agent_id,
            event_type: b.event_type.unwrap_or_default(),
            process_guid: guid(b.process_guid),
            process_id: b.process_id.unwrap_or_default(),
            pipe_name: b.pipe_name.unwrap_or_default(),
            image: b.image.unwrap_or_default(),
            user: b.user.unwrap_or_default(),
            endpoint,
        })),
        sysmon::Body::DnsQuery(b) => EndpointEvent::DnsQuery(Box::new(DnsEvent {
            agent_name,
            agent_id,
            process_guid: guid(b.process_guid),
            process_id: b.process_id.unwrap_or_default(),
            query_name: b.query_name.unwrap_or_default(),
            query_status: query_status(b.query_status.as_deref()),
            query_results: query_results(b.query_results),
            image: b.image.unwrap_or_default(),
            user: b.user.unwrap_or_default(),
            endpoint,
        })),
        sysmon::Body::FileDelete(b) => EndpointEvent::FileDelete(Box::new(FileDelete {
            agent_name,
            agent_id,
            process_guid: guid(b.process_guid),
            process_id: b.process_id.unwrap_or_default(),
            user: b.user.unwrap_or_default(),
            image: b.image.unwrap_or_default(),
            target_filename: b.target_filename.unwrap_or_default(),
            hashes: hashes(b.hashes),
            is_executable: b.is_executable.unwrap_or_default(),
            archived: text_flag(b.archived.as_deref()),
            endpoint,
        })),
        sysmon::Body::ProcessTampering(b) => {
            EndpointEvent::ProcessTamper(Box::new(ProcessTampering {
                agent_name,
                agent_id,
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                tamper_type: b.r#type.unwrap_or_default(),
                user: b.user.unwrap_or_default(),
                endpoint,
            }))
        }
        sysmon::Body::FileDeleteDetected(b) => {
            EndpointEvent::FileDeleteDetected(Box::new(FileDeleteDetected {
                agent_name,
                agent_id,
                process_guid: guid(b.process_guid),
                process_id: b.process_id.unwrap_or_default(),
                user: b.user.unwrap_or_default(),
                image: b.image.unwrap_or_default(),
                target_filename: b.target_filename.unwrap_or_default(),
                hashes: hashes(b.hashes),
                is_executable: b.is_executable.unwrap_or_default(),
                endpoint,
            }))
        }
        // `sysmon::Body` is non-exhaustive. A body this version has no arm for
        // has a kind outside `ACCEPTED_KINDS`, which `convert` refused already.
        other => return Err(ConvertError::UnsupportedKind(other.kind())),
    };
    Ok(event)
}

fn log_event(body: logs::LogBody, endpoint: EndpointHeader) -> Result<EndpointEvent, ConvertError> {
    let event = match body {
        logs::LogBody::WindowsEventLog(b) => {
            EndpointEvent::WindowsEventLog(Box::new(WindowsEventLog {
                channel: b.channel,
                provider: b.provider,
                event_id: b.event_id,
                version: b.version,
                level: b.level,
                task: b.task,
                opcode: b.opcode,
                keywords: b.keywords,
                record_id: b.record_id,
                computer: b.computer,
                user_sid: b.user_sid,
                event_data: b.event_data.map(|data| {
                    data.into_iter()
                        .map(|logs::EventData { name, value }| EventData { name, value })
                        .collect()
                }),
                user_data_xml: b.user_data_xml,
                endpoint,
            }))
        }
        logs::LogBody::Journald(b) => EndpointEvent::Journald(Box::new(Journald {
            fields: b.fields.map(log_fields),
            endpoint,
        })),
        logs::LogBody::Auditd(b) => EndpointEvent::Auditd(Box::new(Auditd {
            serial: b.serial,
            records: b.records.map(|records| {
                records
                    .into_iter()
                    .map(
                        |logs::AuditRecord {
                             record_type,
                             fields,
                         }| AuditRecord {
                            record_type,
                            fields: log_fields(fields),
                        },
                    )
                    .collect()
            }),
            endpoint,
        })),
        // `logs::LogBody` is non-exhaustive. A body this version has no arm
        // for has a kind outside `ACCEPTED_KINDS`, which `convert` refused
        // already.
        other => return Err(ConvertError::UnsupportedKind(other.kind())),
    };
    Ok(event)
}

fn log_fields(fields: Vec<logs::LogField>) -> Vec<LogField> {
    fields
        .into_iter()
        .map(|logs::LogField { name, value }| LogField {
            name,
            value: match value {
                logs::LogValue::Text(text) => LogValue::Text(text),
                logs::LogValue::Bytes(bytes) => LogValue::Bytes(bytes),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests;
