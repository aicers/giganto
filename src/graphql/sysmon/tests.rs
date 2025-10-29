use std::{
    mem,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};
use jiff::{Timestamp, civil, tz::TimeZone};
use serde::Serialize;

use crate::{bincode_utils::encode_legacy, graphql::tests::TestSchema, storage::RawEventStore};

const SENSOR: &str = "src 1";
const SEARCH_TIME_REQUEST: &str = "2023-01-20T00:00:00Z";
const SEARCH_TIME_OTHER: &str = "2023-01-21T00:00:00Z";
const SEARCH_TIME_RESPONSE: &str = "2023-01-20T00:00:00+00:00";

fn append_event<T: Serialize>(
    store: &RawEventStore<'_, T>,
    sensor: &str,
    timestamp: i64,
    event: &T,
) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let serialized = encode_legacy(event).unwrap();
    store.append(&key, &serialized).unwrap();
    store.flush().unwrap();
}

fn sample_timestamp() -> Timestamp {
    civil::datetime(2023, 1, 20, 0, 0, 0, 0)
        .to_zoned(TimeZone::UTC)
        .unwrap()
        .timestamp()
}

fn timestamp_at(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Timestamp {
    civil::datetime(
        year.try_into().unwrap(),
        month.try_into().unwrap(),
        day.try_into().unwrap(),
        hour.try_into().unwrap(),
        minute.try_into().unwrap(),
        second.try_into().unwrap(),
        0,
    )
    .to_zoned(TimeZone::UTC)
    .unwrap()
    .timestamp()
}

fn timestamp_ns(timestamp: Timestamp) -> i64 {
    timestamp.as_nanosecond().try_into().unwrap()
}

fn build_search_query(query_name: &str) -> String {
    format!(
        r#"
        {{
            {query_name}(
                filter: {{
                    time: {{ start: "2023-01-19T00:00:00Z", end: "2023-01-21T00:00:00Z" }}
                    sensor: "{SENSOR}"
                    times:["{SEARCH_TIME_REQUEST}","{SEARCH_TIME_OTHER}"]
                }}
            )
        }}"#
    )
}

fn expected_search_output(query_name: &str) -> String {
    format!("{{{query_name}: [\"{SEARCH_TIME_RESPONSE}\"]}}")
}

fn sample_process_create() -> ProcessCreate {
    ProcessCreate {
        agent_name: "agent-one".to_string(),
        agent_id: "agent-1".to_string(),
        process_guid: "process-guid-1".to_string(),
        process_id: 4_242,
        image: "/opt/bin/process.exe".to_string(),
        file_version: "1.2.3".to_string(),
        description: "Example Process".to_string(),
        product: "ProcessProduct".to_string(),
        company: "ProcessCompany".to_string(),
        original_file_name: "process.exe".to_string(),
        command_line: "/opt/bin/process.exe --flag example".to_string(),
        current_directory: "/opt/bin".to_string(),
        user: "user-one".to_string(),
        logon_guid: "logon-guid-1".to_string(),
        logon_id: 1_001,
        terminal_session_id: 7,
        integrity_level: "High".to_string(),
        hashes: vec!["SHA1=abc123".to_string()],
        parent_process_guid: "parent-guid-1".to_string(),
        parent_process_id: 3_000,
        parent_image: "/opt/bin/parent.exe".to_string(),
        parent_command_line: "/opt/bin/parent.exe --child".to_string(),
        parent_user: "parent-user".to_string(),
    }
}

fn sample_file_creation_time_changed() -> FileCreationTimeChanged {
    FileCreationTimeChanged {
        agent_name: "agent-file-time".to_string(),
        agent_id: "agent-file-time-1".to_string(),
        process_guid: "file-time-guid".to_string(),
        process_id: 44,
        image: "/usr/bin/time-change".to_string(),
        target_filename: "/tmp/old.txt".to_string(),
        creation_utc_time: timestamp_at(2023, 1, 19, 23, 59, 59),
        previous_creation_utc_time: timestamp_at(2023, 1, 10, 0, 0, 0),
        user: "user-file-time".to_string(),
    }
}

fn sample_network_connection() -> NetworkConnection {
    NetworkConnection {
        agent_name: "agent-network".to_string(),
        agent_id: "agent-network-1".to_string(),
        process_guid: "network-guid".to_string(),
        process_id: 9_001,
        image: "/usr/bin/net".to_string(),
        user: "user-network".to_string(),
        protocol: "tcp".to_string(),
        initiated: true,
        source_is_ipv6: false,
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        source_hostname: "source-host".to_string(),
        source_port: 1234,
        source_port_name: "client".to_string(),
        destination_is_ipv6: false,
        destination_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        destination_hostname: "dest-host".to_string(),
        destination_port: 443,
        destination_port_name: "https".to_string(),
    }
}

fn sample_process_terminated() -> ProcessTerminated {
    ProcessTerminated {
        agent_name: "agent-terminate".to_string(),
        agent_id: "agent-terminate-1".to_string(),
        process_guid: "terminate-guid".to_string(),
        process_id: 55,
        image: "/usr/bin/terminate".to_string(),
        user: "user-terminate".to_string(),
    }
}

fn sample_image_loaded() -> ImageLoaded {
    ImageLoaded {
        agent_name: "agent-image".to_string(),
        agent_id: "agent-image-1".to_string(),
        process_guid: "image-guid".to_string(),
        process_id: 77,
        image: "/usr/bin/loaded".to_string(),
        image_loaded: "/usr/lib/libexample.so".to_string(),
        file_version: "4.5.6".to_string(),
        description: "Example library".to_string(),
        product: "ImageProduct".to_string(),
        company: "ImageCompany".to_string(),
        original_file_name: "libexample.so".to_string(),
        hashes: vec!["SHA1=imagehash".to_string()],
        signed: true,
        signature: "Example CA".to_string(),
        signature_status: "Valid".to_string(),
        user: "user-image".to_string(),
    }
}

fn sample_file_create() -> FileCreate {
    FileCreate {
        agent_name: "agent-file".to_string(),
        agent_id: "agent-file-1".to_string(),
        process_guid: "file-guid".to_string(),
        process_id: 88,
        image: "/usr/bin/filecreate".to_string(),
        target_filename: "/tmp/new.txt".to_string(),
        creation_utc_time: timestamp_at(2023, 1, 19, 23, 58, 0),
        user: "user-file".to_string(),
    }
}

fn sample_registry_value_set() -> RegistryValueSet {
    RegistryValueSet {
        agent_name: "agent-reg-value".to_string(),
        agent_id: "agent-reg-value-1".to_string(),
        event_type: "SetValue".to_string(),
        process_guid: "reg-value-guid".to_string(),
        process_id: 99,
        image: "/usr/bin/reg".to_string(),
        target_object: "HKCU/Software/Example".to_string(),
        details: "Updated value".to_string(),
        user: "user-reg-value".to_string(),
    }
}

fn sample_registry_key_value_rename() -> RegistryKeyValueRename {
    RegistryKeyValueRename {
        agent_name: "agent-reg-rename".to_string(),
        agent_id: "agent-reg-rename-1".to_string(),
        event_type: "Rename".to_string(),
        process_guid: "reg-rename-guid".to_string(),
        process_id: 101,
        image: "/usr/bin/reg-rename".to_string(),
        target_object: "HKCU/Software/Example".to_string(),
        new_name: "ExampleRenamed".to_string(),
        user: "user-reg-rename".to_string(),
    }
}

fn sample_file_create_stream_hash() -> FileCreateStreamHash {
    FileCreateStreamHash {
        agent_name: "agent-stream".to_string(),
        agent_id: "agent-stream-1".to_string(),
        process_guid: "stream-guid".to_string(),
        process_id: 202,
        image: "/usr/bin/stream".to_string(),
        target_filename: "/tmp/stream.bin".to_string(),
        creation_utc_time: timestamp_at(2023, 1, 19, 23, 57, 0),
        hash: vec!["MD5=1234".to_string(), "SHA1=5678".to_string()],
        contents: "binary".to_string(),
        user: "user-stream".to_string(),
    }
}

fn sample_pipe_event() -> PipeEvent {
    PipeEvent {
        agent_name: "agent-pipe".to_string(),
        agent_id: "agent-pipe-1".to_string(),
        event_type: "PipeCreated".to_string(),
        process_guid: "pipe-guid".to_string(),
        process_id: 303,
        pipe_name: "/pipe/example".to_string(),
        image: "/usr/bin/pipe".to_string(),
        user: "user-pipe".to_string(),
    }
}

fn sample_dns_event() -> DnsEvent {
    DnsEvent {
        agent_name: "agent-dns".to_string(),
        agent_id: "agent-dns-1".to_string(),
        process_guid: "dns-guid".to_string(),
        process_id: 404,
        query_name: "example.com".to_string(),
        query_status: 0,
        query_results: vec!["93.184.216.34".to_string()],
        image: "/usr/bin/dns".to_string(),
        user: "user-dns".to_string(),
    }
}

fn sample_file_delete() -> FileDelete {
    FileDelete {
        agent_name: "agent-file-delete".to_string(),
        agent_id: "agent-file-delete-1".to_string(),
        process_guid: "file-delete-guid".to_string(),
        process_id: 505,
        user: "user-file-delete".to_string(),
        image: "/usr/bin/delete".to_string(),
        target_filename: "/tmp/delete.txt".to_string(),
        hashes: vec!["SHA256=delete".to_string()],
        is_executable: true,
        archived: false,
    }
}

fn sample_process_tampering() -> ProcessTampering {
    ProcessTampering {
        agent_name: "agent-tamper".to_string(),
        agent_id: "agent-tamper-1".to_string(),
        process_guid: "tamper-guid".to_string(),
        process_id: 606,
        image: "/usr/bin/tamper".to_string(),
        tamper_type: "ThreadHijack".to_string(),
        user: "user-tamper".to_string(),
    }
}

fn sample_file_delete_detected() -> FileDeleteDetected {
    FileDeleteDetected {
        agent_name: "agent-file-delete-detected".to_string(),
        agent_id: "agent-file-delete-detected-1".to_string(),
        process_guid: "file-delete-detected-guid".to_string(),
        process_id: 707,
        user: "user-file-delete-detected".to_string(),
        image: "/usr/bin/delete-detected".to_string(),
        target_filename: "/tmp/delete-detected.txt".to_string(),
        hashes: vec!["SHA1=detected".to_string()],
        is_executable: true,
    }
}

fn insert_process_create_event(
    store: &RawEventStore<'_, ProcessCreate>,
    sensor: &str,
    timestamp: i64,
) {
    append_event(store, sensor, timestamp, &sample_process_create());
}

fn insert_file_create_time_event(
    store: &RawEventStore<'_, FileCreationTimeChanged>,
    sensor: &str,
    timestamp: i64,
) {
    append_event(
        store,
        sensor,
        timestamp,
        &sample_file_creation_time_changed(),
    );
}

fn insert_network_connect_event(
    store: &RawEventStore<'_, NetworkConnection>,
    sensor: &str,
    timestamp: i64,
) {
    append_event(store, sensor, timestamp, &sample_network_connection());
}

fn insert_process_terminate_event(
    store: &RawEventStore<'_, ProcessTerminated>,
    sensor: &str,
    timestamp: i64,
) {
    append_event(store, sensor, timestamp, &sample_process_terminated());
}

fn insert_image_load_event(store: &RawEventStore<'_, ImageLoaded>, sensor: &str, timestamp: i64) {
    append_event(store, sensor, timestamp, &sample_image_loaded());
}

fn insert_file_create_event(store: &RawEventStore<'_, FileCreate>, sensor: &str, timestamp: i64) {
    append_event(store, sensor, timestamp, &sample_file_create());
}

fn insert_registry_value_set_event(
    store: &RawEventStore<'_, RegistryValueSet>,
    sensor: &str,
    timestamp: i64,
) {
    append_event(store, sensor, timestamp, &sample_registry_value_set());
}

fn insert_registry_key_rename_event(
    store: &RawEventStore<'_, RegistryKeyValueRename>,
    sensor: &str,
    timestamp: i64,
) {
    append_event(
        store,
        sensor,
        timestamp,
        &sample_registry_key_value_rename(),
    );
}

fn insert_file_create_stream_hash_event(
    store: &RawEventStore<'_, FileCreateStreamHash>,
    sensor: &str,
    timestamp: i64,
) {
    append_event(store, sensor, timestamp, &sample_file_create_stream_hash());
}

fn insert_pipe_event(store: &RawEventStore<'_, PipeEvent>, sensor: &str, timestamp: i64) {
    append_event(store, sensor, timestamp, &sample_pipe_event());
}

fn insert_dns_event(store: &RawEventStore<'_, DnsEvent>, sensor: &str, timestamp: i64) {
    append_event(store, sensor, timestamp, &sample_dns_event());
}

fn insert_file_delete_event(store: &RawEventStore<'_, FileDelete>, sensor: &str, timestamp: i64) {
    append_event(store, sensor, timestamp, &sample_file_delete());
}

fn insert_process_tamper_event(
    store: &RawEventStore<'_, ProcessTampering>,
    sensor: &str,
    timestamp: i64,
) {
    append_event(store, sensor, timestamp, &sample_process_tampering());
}

fn insert_file_delete_detected_event(
    store: &RawEventStore<'_, FileDeleteDetected>,
    sensor: &str,
    timestamp: i64,
) {
    append_event(store, sensor, timestamp, &sample_file_delete_detected());
}

#[tokio::test]
async fn process_create_empty() {
    let schema = TestSchema::new();
    let query = r#"
    {
        processCreateEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentName
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{processCreateEvents: {edges: []}}");
}

#[tokio::test]
async fn process_create_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.process_create_store().unwrap();

    insert_process_create_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        processCreateEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentName,
                    processGuid,
                    processId,
                    integrityLevel,
                    hashes,
                    parentProcessId,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{processCreateEvents: {edges: [{node: {agentName: \"agent-one\", processGuid: \"process-guid-1\", processId: \"4242\", integrityLevel: \"High\", hashes: [\"SHA1=abc123\"], parentProcessId: \"3000\"}}]}}"
    );
}

#[tokio::test]
async fn process_create_with_data_giganto_cluster() {
    let query = r#"
    {
        processCreateEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "ingest src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentName,
                    processGuid,
                    processId,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "processCreateEvents": {
                "pageInfo": {
                    "hasPreviousPage": false,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "Y3Vyc29y",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "cluster-agent",
                            "agentId": "cluster-agent-1",
                            "processGuid": "cluster-guid",
                            "processId": "1010",
                            "image": "/opt/bin/process",
                            "fileVersion": "2.0.0",
                            "description": "Cluster process",
                            "product": "ClusterProduct",
                            "company": "ClusterCompany",
                            "originalFileName": "cluster.exe",
                            "commandLine": "/opt/bin/process --arg",
                            "currentDirectory": "/opt/bin",
                            "user": "cluster-user",
                            "logonGuid": "cluster-logon-guid",
                            "logonId": "100",
                            "terminalSessionId": "2",
                            "integrityLevel": "Medium",
                            "hashes": [
                                "SHA1=deadbeef"
                            ],
                            "parentProcessGuid": "cluster-parent-guid",
                            "parentProcessId": "999",
                            "parentImage": "/opt/bin/parent",
                            "parentCommandLine": "/opt/bin/parent --child",
                            "parentUser": "cluster-parent"
                        }
                    }
                ]
            }
        }
    }
    "#;
    let mock = peer_server
        .mock("POST", "/graphql")
        .with_status(200)
        .with_body(peer_response_mock_data)
        .create();

    let peer_port = peer_server
        .host_with_port()
        .parse::<SocketAddr>()
        .expect("Port must exist")
        .port();
    let schema = TestSchema::new_with_graphql_peer(peer_port);

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{processCreateEvents: {edges: [{node: {agentName: \"cluster-agent\", processGuid: \"cluster-guid\", processId: \"1010\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn sysmon_events_returns_process_create_node() {
    let schema = TestSchema::new();
    let store = schema.db.process_create_store().unwrap();

    insert_process_create_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        sysmonEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    __typename,
                    ... on ProcessCreateEvent {
                        processGuid,
                        processId,
                    }
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{sysmonEvents: {edges: [{node: {__typename: \"ProcessCreateEvent\", processGuid: \"process-guid-1\", processId: \"4242\"}}]}}"
    );
}

#[tokio::test]
async fn file_create_time_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.file_create_time_store().unwrap();

    insert_file_create_time_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        fileCreateTimeEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentName,
                    targetFilename,
                    creationUtcTime,
                    previousCreationUtcTime
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{fileCreateTimeEvents: {edges: [{node: {agentName: \"agent-file-time\", targetFilename: \"/tmp/old.txt\", creationUtcTime: \"2023-01-19T23:59:59+00:00\", previousCreationUtcTime: \"2023-01-10T00:00:00+00:00\"}}]}}"
    );
}

#[tokio::test]
async fn network_connect_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.network_connect_store().unwrap();

    insert_network_connect_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        networkConnectEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    protocol,
                    initiated,
                    sourceIp,
                    destinationPort,
                    destinationPortName
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{networkConnectEvents: {edges: [{node: {protocol: \"tcp\", initiated: true, sourceIp: \"192.168.1.10\", destinationPort: 443, destinationPortName: \"https\"}}]}}"
    );
}

#[tokio::test]
async fn process_terminate_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.process_terminate_store().unwrap();

    insert_process_terminate_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        processTerminateEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    image,
                    user
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{processTerminateEvents: {edges: [{node: {image: \"/usr/bin/terminate\", user: \"user-terminate\"}}]}}"
    );
}

#[tokio::test]
async fn image_load_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.image_load_store().unwrap();

    insert_image_load_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        imageLoadEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    imageLoaded,
                    hashes,
                    signed,
                    signatureStatus
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{imageLoadEvents: {edges: [{node: {imageLoaded: \"/usr/lib/libexample.so\", hashes: [\"SHA1=imagehash\"], signed: true, signatureStatus: \"Valid\"}}]}}"
    );
}

#[tokio::test]
async fn file_create_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.file_create_store().unwrap();

    insert_file_create_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        fileCreateEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    targetFilename,
                    creationUtcTime,
                    user
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{fileCreateEvents: {edges: [{node: {targetFilename: \"/tmp/new.txt\", creationUtcTime: \"2023-01-19T23:58:00+00:00\", user: \"user-file\"}}]}}"
    );
}

#[tokio::test]
async fn registry_value_set_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.registry_value_set_store().unwrap();

    insert_registry_value_set_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        registryValueSetEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    eventType,
                    details,
                    user
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{registryValueSetEvents: {edges: [{node: {eventType: \"SetValue\", details: \"Updated value\", user: \"user-reg-value\"}}]}}"
    );
}

#[tokio::test]
async fn registry_key_rename_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.registry_key_rename_store().unwrap();

    insert_registry_key_rename_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        registryKeyRenameEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    targetObject,
                    newName,
                    user
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{registryKeyRenameEvents: {edges: [{node: {targetObject: \"HKCU/Software/Example\", newName: \"ExampleRenamed\", user: \"user-reg-rename\"}}]}}"
    );
}

#[tokio::test]
async fn file_create_stream_hash_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.file_create_stream_hash_store().unwrap();

    insert_file_create_stream_hash_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        fileCreateStreamHashEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    targetFilename,
                    hash,
                    contents
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{fileCreateStreamHashEvents: {edges: [{node: {targetFilename: \"/tmp/stream.bin\", hash: [\"MD5=1234\", \"SHA1=5678\"], contents: \"binary\"}}]}}"
    );
}

#[tokio::test]
async fn pipe_event_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.pipe_event_store().unwrap();

    insert_pipe_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        pipeEventEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    eventType,
                    pipeName,
                    user
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{pipeEventEvents: {edges: [{node: {eventType: \"PipeCreated\", pipeName: \"/pipe/example\", user: \"user-pipe\"}}]}}"
    );
}

#[tokio::test]
async fn dns_query_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.dns_query_store().unwrap();

    insert_dns_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        dnsQueryEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    queryName,
                    queryStatus,
                    queryResults
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{dnsQueryEvents: {edges: [{node: {queryName: \"example.com\", queryStatus: \"0\", queryResults: [\"93.184.216.34\"]}}]}}"
    );
}

#[tokio::test]
async fn file_delete_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.file_delete_store().unwrap();

    insert_file_delete_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        fileDeleteEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    targetFilename,
                    hashes,
                    isExecutable,
                    archived
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{fileDeleteEvents: {edges: [{node: {targetFilename: \"/tmp/delete.txt\", hashes: [\"SHA256=delete\"], isExecutable: true, archived: false}}]}}"
    );
}

#[tokio::test]
async fn process_tamper_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.process_tamper_store().unwrap();

    insert_process_tamper_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        processTamperEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    tamperType,
                    user
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{processTamperEvents: {edges: [{node: {tamperType: \"ThreadHijack\", user: \"user-tamper\"}}]}}"
    );
}

#[tokio::test]
async fn file_delete_detected_events_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.file_delete_detected_store().unwrap();

    insert_file_delete_detected_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = r#"
    {
        fileDeleteDetectedEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    targetFilename,
                    hashes,
                    isExecutable
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{fileDeleteDetectedEvents: {edges: [{node: {targetFilename: \"/tmp/delete-detected.txt\", hashes: [\"SHA1=detected\"], isExecutable: true}}]}}"
    );
}

#[tokio::test]
async fn search_process_create_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.process_create_store().unwrap();

    insert_process_create_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchProcessCreateEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchProcessCreateEvents")
    );
}

#[tokio::test]
async fn search_file_create_time_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.file_create_time_store().unwrap();

    insert_file_create_time_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchFileCreateTimeEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchFileCreateTimeEvents")
    );
}

#[tokio::test]
async fn search_network_connect_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.network_connect_store().unwrap();

    insert_network_connect_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchNetworkConnectEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchNetworkConnectEvents")
    );
}

#[tokio::test]
async fn search_process_terminate_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.process_terminate_store().unwrap();

    insert_process_terminate_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchProcessTerminateEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchProcessTerminateEvents")
    );
}

#[tokio::test]
async fn search_image_load_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.image_load_store().unwrap();

    insert_image_load_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchImageLoadEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchImageLoadEvents")
    );
}

#[tokio::test]
async fn search_file_create_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.file_create_store().unwrap();

    insert_file_create_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchFileCreateEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchFileCreateEvents")
    );
}

#[tokio::test]
async fn search_registry_value_set_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.registry_value_set_store().unwrap();

    insert_registry_value_set_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchRegistryValueSetEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchRegistryValueSetEvents")
    );
}

#[tokio::test]
async fn search_registry_key_rename_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.registry_key_rename_store().unwrap();

    insert_registry_key_rename_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchRegistryKeyRenameEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchRegistryKeyRenameEvents")
    );
}

#[tokio::test]
async fn search_file_create_stream_hash_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.file_create_stream_hash_store().unwrap();

    insert_file_create_stream_hash_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchFileCreateStreamHashEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchFileCreateStreamHashEvents")
    );
}

#[tokio::test]
async fn search_pipe_event_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.pipe_event_store().unwrap();

    insert_pipe_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchPipeEventEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchPipeEventEvents")
    );
}

#[tokio::test]
async fn search_dns_query_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.dns_query_store().unwrap();

    insert_dns_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchDnsQueryEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchDnsQueryEvents")
    );
}

#[tokio::test]
async fn search_file_delete_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.file_delete_store().unwrap();

    insert_file_delete_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchFileDeleteEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchFileDeleteEvents")
    );
}

#[tokio::test]
async fn search_process_tamper_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.process_tamper_store().unwrap();

    insert_process_tamper_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchProcessTamperEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchProcessTamperEvents")
    );
}

#[tokio::test]
async fn search_file_delete_detected_events_returns_matching_times() {
    let schema = TestSchema::new();
    let store = schema.db.file_delete_detected_store().unwrap();

    insert_file_delete_detected_event(&store, SENSOR, timestamp_ns(sample_timestamp()));

    let query = build_search_query("searchFileDeleteDetectedEvents");
    let res = schema.execute(&query).await;
    assert_eq!(
        res.data.to_string(),
        expected_search_output("searchFileDeleteDetectedEvents")
    );
}
