//! Records carrying endpoint headers, for tests.
//!
//! Each Sysmon record's string fields hold the field's own name, its `u32`
//! fields `7`, its `u16` fields `443`, its `bool` fields `true` and its
//! addresses `192.0.2.1`, so a test can tell what each field returns.

use giganto_client::ingest::{
    endpoint::{ClockOffset, CollectionMode, EndpointHeader, NetStateSource, OsFamily},
    log::{AuditRecord, Auditd, EventData, Journald, LogField, LogValue, WindowsEventLog},
    sysmon::{
        CreateRemoteThread, DnsEvent, DriverLoad, FileCreate, FileCreateStreamHash,
        FileCreationTimeChanged, FileDelete, FileDeleteDetected, ImageLoaded, NetworkConnection,
        PipeEvent, ProcessAccess, ProcessCreate, ProcessTampering, ProcessTerminated,
        RawAccessRead, RegistryKeyValueRename, RegistryObjectAddDel, RegistryValueSet,
    },
};

/// The value of every Sysmon `i64` time field: 2020-09-13T12:26:40Z.
pub(crate) const CREATION_TIME: i64 = 1_600_000_000_000_000_000;
/// The value of `ProcessAccess::granted_access`, above `u32::MAX`.
pub(crate) const GRANTED_ACCESS: u64 = 0x1_0000_0001;
/// A logon ID above `u32::MAX`.
pub(crate) const LOGON_ID_FULL: u64 = 0x1_2345_6789;

/// Returns a header with every field filled and `Other` enum values.
///
/// Its event time is 2023-11-14T22:13:20.000000001Z, its collection time
/// 2023-11-14T22:13:21Z and its clock offset's measurement time
/// 2023-11-14T22:13:20.5Z.
pub(crate) fn full_header() -> EndpointHeader {
    EndpointHeader {
        endpoint_id: "0B1C2D3E-4F50-6172-8394-A5B6C7D8E9F0"
            .parse()
            .expect("valid UUID"),
        stream: "F0E9D8C7-B6A5-4493-8271-605F4E3D2C1B"
            .parse()
            .expect("valid UUID"),
        seq: u64::MAX,
        event_time: 1_700_000_000_000_000_001,
        collected_at: 1_700_000_001_000_000_000,
        clock_offset: Some(ClockOffset {
            offset_ms: -15,
            uncertainty_ms: 3,
            measured_at: 1_700_000_000_500_000_000,
        }),
        hostname: "host-01".to_string(),
        ips: vec![
            "192.0.2.10".parse().expect("valid IP"),
            "2001:db8::1".parse().expect("valid IP"),
        ],
        default_route_ip: Some("192.0.2.10".parse().expect("valid IP")),
        net_state_source: NetStateSource::Other("probed".to_string()),
        os_family: OsFamily::Other("freebsd".to_string()),
        os_version: "14.1".to_string(),
        collection_mode: CollectionMode::Other("minimal".to_string()),
        process_key: Some(vec![0x00, 0xab, 0x0f, 0xff]),
        schema: 3,
    }
}

/// Returns a header with known enum values and every optional field absent.
///
/// Its event time is 2023-11-14T22:13:20Z and its collection time
/// 2023-11-14T22:13:20.25Z.
pub(crate) fn sparse_header() -> EndpointHeader {
    EndpointHeader {
        endpoint_id: "11111111-2222-3333-4444-555555555555"
            .parse()
            .expect("valid UUID"),
        stream: "66666666-7777-8888-9999-aaaaaaaaaaaa"
            .parse()
            .expect("valid UUID"),
        seq: 1,
        event_time: 1_700_000_000_000_000_000,
        collected_at: 1_700_000_000_250_000_000,
        clock_offset: None,
        hostname: "host-02".to_string(),
        ips: Vec::new(),
        default_route_ip: None,
        net_state_source: NetStateSource::Observed,
        os_family: OsFamily::Windows,
        os_version: "10.0.19045".to_string(),
        collection_mode: CollectionMode::Extended,
        process_key: None,
        schema: 1,
    }
}

/// Returns a Windows event log record with every field filled, including an
/// unnamed `EventData` element.
pub(crate) fn windows_event_log() -> WindowsEventLog {
    WindowsEventLog {
        channel: Some("Security".to_string()),
        provider: Some("Microsoft-Windows-Security-Auditing".to_string()),
        event_id: Some(4624),
        version: Some(2),
        level: Some(4),
        task: Some(12544),
        opcode: Some(1),
        keywords: Some(0x8020_0000_0000_0000),
        record_id: Some(123_456),
        computer: Some("host-01".to_string()),
        user_sid: Some("S-1-5-18".to_string()),
        event_data: Some(vec![
            EventData {
                name: Some("SubjectUserName".to_string()),
                value: "SYSTEM".to_string(),
            },
            EventData {
                name: None,
                value: "unnamed".to_string(),
            },
        ]),
        user_data_xml: Some("<UserData/>".to_string()),
        endpoint: full_header(),
    }
}

/// Returns a Windows event log record with every optional field absent.
pub(crate) fn empty_windows_event_log() -> WindowsEventLog {
    WindowsEventLog {
        channel: None,
        provider: None,
        event_id: None,
        version: None,
        level: None,
        task: None,
        opcode: None,
        keywords: None,
        record_id: None,
        computer: None,
        user_sid: None,
        event_data: None,
        user_data_xml: None,
        endpoint: sparse_header(),
    }
}

/// Returns a journald record with a text and a bytes field.
pub(crate) fn journald() -> Journald {
    Journald {
        fields: Some(vec![
            LogField {
                name: "MESSAGE".to_string(),
                value: LogValue::Text("Started session".to_string()),
            },
            LogField {
                name: "BINARY".to_string(),
                value: LogValue::Bytes(vec![0x00, 0x1f, 0xa0, 0xff]),
            },
        ]),
        endpoint: full_header(),
    }
}

/// Returns a journald record without fields.
pub(crate) fn empty_journald() -> Journald {
    Journald {
        fields: None,
        endpoint: sparse_header(),
    }
}

/// Returns an auditd record of three audit records, one of them without
/// fields, with text and bytes values.
pub(crate) fn auditd() -> Auditd {
    Auditd {
        serial: Some(8_731),
        records: Some(vec![
            AuditRecord {
                record_type: "SYSCALL".to_string(),
                fields: vec![LogField {
                    name: "syscall".to_string(),
                    value: LogValue::Text("59".to_string()),
                }],
            },
            AuditRecord {
                record_type: "EXECVE".to_string(),
                fields: vec![
                    LogField {
                        name: "argc".to_string(),
                        value: LogValue::Text("1".to_string()),
                    },
                    LogField {
                        name: "a0".to_string(),
                        value: LogValue::Bytes(b"ls".to_vec()),
                    },
                ],
            },
            AuditRecord {
                record_type: "EOE".to_string(),
                fields: Vec::new(),
            },
        ]),
        endpoint: full_header(),
    }
}

/// Returns an auditd record without a serial number or records.
pub(crate) fn empty_auditd() -> Auditd {
    Auditd {
        serial: None,
        records: None,
        endpoint: sparse_header(),
    }
}

/// Returns a `ProcessCreate` record whose string fields hold their own names.
pub(crate) fn process_create(
    endpoint: Option<EndpointHeader>,
    logon_id_full: Option<u64>,
) -> ProcessCreate {
    ProcessCreate {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        file_version: "file_version".to_string(),
        description: "description".to_string(),
        product: "product".to_string(),
        company: "company".to_string(),
        original_file_name: "original_file_name".to_string(),
        command_line: "command_line".to_string(),
        current_directory: "current_directory".to_string(),
        user: "user".to_string(),
        logon_guid: "logon_guid".to_string(),
        logon_id: 7,
        terminal_session_id: 7,
        integrity_level: "integrity_level".to_string(),
        hashes: vec!["hashes".to_string()],
        parent_process_guid: "parent_process_guid".to_string(),
        parent_process_id: 7,
        parent_image: "parent_image".to_string(),
        parent_command_line: "parent_command_line".to_string(),
        parent_user: "parent_user".to_string(),
        endpoint,
        logon_id_full,
    }
}

/// Returns a `FileCreationTimeChanged` record whose string fields hold their own names.
pub(crate) fn file_creation_time_changed(
    endpoint: Option<EndpointHeader>,
) -> FileCreationTimeChanged {
    FileCreationTimeChanged {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        target_filename: "target_filename".to_string(),
        creation_utc_time: CREATION_TIME,
        previous_creation_utc_time: CREATION_TIME,
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `NetworkConnection` record whose string fields hold their own names.
pub(crate) fn network_connection(endpoint: Option<EndpointHeader>) -> NetworkConnection {
    NetworkConnection {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        user: "user".to_string(),
        protocol: "protocol".to_string(),
        initiated: true,
        source_is_ipv6: true,
        source_ip: "192.0.2.1".parse().expect("valid IP"),
        source_hostname: "source_hostname".to_string(),
        source_port: 443,
        source_port_name: "source_port_name".to_string(),
        destination_is_ipv6: true,
        destination_ip: "192.0.2.1".parse().expect("valid IP"),
        destination_hostname: "destination_hostname".to_string(),
        destination_port: 443,
        destination_port_name: "destination_port_name".to_string(),
        endpoint,
    }
}

/// Returns a `ProcessTerminated` record whose string fields hold their own names.
pub(crate) fn process_terminated(endpoint: Option<EndpointHeader>) -> ProcessTerminated {
    ProcessTerminated {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `ImageLoaded` record whose string fields hold their own names.
pub(crate) fn image_loaded(endpoint: Option<EndpointHeader>) -> ImageLoaded {
    ImageLoaded {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        image_loaded: "image_loaded".to_string(),
        file_version: "file_version".to_string(),
        description: "description".to_string(),
        product: "product".to_string(),
        company: "company".to_string(),
        original_file_name: "original_file_name".to_string(),
        hashes: vec!["hashes".to_string()],
        signed: true,
        signature: "signature".to_string(),
        signature_status: "signature_status".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `FileCreate` record whose string fields hold their own names.
pub(crate) fn file_create(endpoint: Option<EndpointHeader>) -> FileCreate {
    FileCreate {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        target_filename: "target_filename".to_string(),
        creation_utc_time: CREATION_TIME,
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `RegistryValueSet` record whose string fields hold their own names.
pub(crate) fn registry_value_set(endpoint: Option<EndpointHeader>) -> RegistryValueSet {
    RegistryValueSet {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        event_type: "event_type".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        target_object: "target_object".to_string(),
        details: "details".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `RegistryKeyValueRename` record whose string fields hold their own names.
pub(crate) fn registry_key_value_rename(
    endpoint: Option<EndpointHeader>,
) -> RegistryKeyValueRename {
    RegistryKeyValueRename {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        event_type: "event_type".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        target_object: "target_object".to_string(),
        new_name: "new_name".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `FileCreateStreamHash` record whose string fields hold their own names.
pub(crate) fn file_create_stream_hash(endpoint: Option<EndpointHeader>) -> FileCreateStreamHash {
    FileCreateStreamHash {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        target_filename: "target_filename".to_string(),
        creation_utc_time: CREATION_TIME,
        hash: vec!["hash".to_string()],
        contents: "contents".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `PipeEvent` record whose string fields hold their own names.
pub(crate) fn pipe_event(endpoint: Option<EndpointHeader>) -> PipeEvent {
    PipeEvent {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        event_type: "event_type".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        pipe_name: "pipe_name".to_string(),
        image: "image".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `DnsEvent` record whose string fields hold their own names.
pub(crate) fn dns_event(endpoint: Option<EndpointHeader>) -> DnsEvent {
    DnsEvent {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        query_name: "query_name".to_string(),
        query_status: 7,
        query_results: vec!["query_results".to_string()],
        image: "image".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `FileDelete` record whose string fields hold their own names.
pub(crate) fn file_delete(endpoint: Option<EndpointHeader>) -> FileDelete {
    FileDelete {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        user: "user".to_string(),
        image: "image".to_string(),
        target_filename: "target_filename".to_string(),
        hashes: vec!["hashes".to_string()],
        is_executable: true,
        archived: true,
        endpoint,
    }
}

/// Returns a `ProcessTampering` record whose string fields hold their own names.
pub(crate) fn process_tampering(endpoint: Option<EndpointHeader>) -> ProcessTampering {
    ProcessTampering {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        tamper_type: "tamper_type".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `FileDeleteDetected` record whose string fields hold their own names.
pub(crate) fn file_delete_detected(endpoint: Option<EndpointHeader>) -> FileDeleteDetected {
    FileDeleteDetected {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        user: "user".to_string(),
        image: "image".to_string(),
        target_filename: "target_filename".to_string(),
        hashes: vec!["hashes".to_string()],
        is_executable: true,
        endpoint,
    }
}

/// Returns a `DriverLoad` record whose string fields hold their own names.
pub(crate) fn driver_load(endpoint: Option<EndpointHeader>) -> DriverLoad {
    DriverLoad {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        image_loaded: "image_loaded".to_string(),
        hashes: vec!["hashes".to_string()],
        signed: true,
        signature: "signature".to_string(),
        signature_status: "signature_status".to_string(),
        endpoint,
    }
}

/// Returns a `CreateRemoteThread` record whose string fields hold their own names.
pub(crate) fn create_remote_thread(endpoint: Option<EndpointHeader>) -> CreateRemoteThread {
    CreateRemoteThread {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        source_process_guid: "source_process_guid".to_string(),
        source_process_id: 7,
        source_image: "source_image".to_string(),
        target_process_guid: "target_process_guid".to_string(),
        target_process_id: 7,
        target_image: "target_image".to_string(),
        new_thread_id: 7,
        start_address: "start_address".to_string(),
        start_module: "start_module".to_string(),
        start_function: "start_function".to_string(),
        source_user: "source_user".to_string(),
        target_user: "target_user".to_string(),
        endpoint,
    }
}

/// Returns a `RawAccessRead` record whose string fields hold their own names.
pub(crate) fn raw_access_read(endpoint: Option<EndpointHeader>) -> RawAccessRead {
    RawAccessRead {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        device: "device".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// Returns a `ProcessAccess` record whose string fields hold their own names.
pub(crate) fn process_access(endpoint: Option<EndpointHeader>) -> ProcessAccess {
    ProcessAccess {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        source_process_guid: "source_process_guid".to_string(),
        source_process_id: 7,
        source_thread_id: 7,
        source_image: "source_image".to_string(),
        target_process_guid: "target_process_guid".to_string(),
        target_process_id: 7,
        target_image: "target_image".to_string(),
        granted_access: GRANTED_ACCESS,
        call_trace: "call_trace".to_string(),
        source_user: "source_user".to_string(),
        target_user: "target_user".to_string(),
        endpoint,
    }
}

/// Returns a `RegistryObjectAddDel` record whose string fields hold their own names.
pub(crate) fn registry_object_add_del(endpoint: Option<EndpointHeader>) -> RegistryObjectAddDel {
    RegistryObjectAddDel {
        agent_name: "agent_name".to_string(),
        agent_id: "agent_id".to_string(),
        event_type: "event_type".to_string(),
        process_guid: "process_guid".to_string(),
        process_id: 7,
        image: "image".to_string(),
        target_object: "target_object".to_string(),
        user: "user".to_string(),
        endpoint,
    }
}

/// The GraphQL selection of every `EndpointHeader` field, under `endpoint`.
pub(crate) const HEADER_SELECTION: &str = "endpoint { endpointId stream seq eventTime \
    collectedAt clockOffset { offsetMs uncertaintyMs measuredAt } hostname ips \
    defaultRouteIp netStateSource osFamily osVersion collectionMode processKey schema }";

/// Returns what GraphQL returns for `full_header()`.
pub(crate) fn full_header_graphql() -> serde_json::Value {
    serde_json::json!({
        "endpointId": "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0",
        "stream": "f0e9d8c7-b6a5-4493-8271-605f4e3d2c1b",
        "seq": "18446744073709551615",
        "eventTime": "2023-11-14T22:13:20.000000001Z",
        "collectedAt": "2023-11-14T22:13:21Z",
        "clockOffset": {
            "offsetMs": "-15",
            "uncertaintyMs": "3",
            "measuredAt": "2023-11-14T22:13:20.5Z",
        },
        "hostname": "host-01",
        "ips": ["192.0.2.10", "2001:db8::1"],
        "defaultRouteIp": "192.0.2.10",
        "netStateSource": "probed",
        "osFamily": "freebsd",
        "osVersion": "14.1",
        "collectionMode": "minimal",
        "processKey": "00ab0fff",
        "schema": 3,
    })
}

/// Returns what GraphQL returns for `sparse_header()`.
pub(crate) fn sparse_header_graphql() -> serde_json::Value {
    serde_json::json!({
        "endpointId": "11111111-2222-3333-4444-555555555555",
        "stream": "66666666-7777-8888-9999-aaaaaaaaaaaa",
        "seq": "1",
        "eventTime": "2023-11-14T22:13:20Z",
        "collectedAt": "2023-11-14T22:13:20.25Z",
        "clockOffset": null,
        "hostname": "host-02",
        "ips": [],
        "defaultRouteIp": null,
        "netStateSource": "observed",
        "osFamily": "windows",
        "osVersion": "10.0.19045",
        "collectionMode": "extended",
        "processKey": null,
        "schema": 1,
    })
}
