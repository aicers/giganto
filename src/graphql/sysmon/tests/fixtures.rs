use std::{
    mem,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use chrono::{TimeZone, Utc};
use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};

use crate::{graphql::tests::TestSchema, storage::RawEventStore};

pub(super) async fn run_local_event_query<F>(setup: F, query: &str, expected: &str)
where
    F: FnOnce(&TestSchema),
{
    let schema = TestSchema::new();
    setup(&schema);
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), expected);
}

pub(super) async fn run_cluster_event_query(query: &str, expected: &str, peer_response: &str) {
    let mut peer_server = mockito::Server::new_async().await;
    let mock = peer_server
        .mock("POST", "/graphql")
        .with_status(200)
        .with_body(peer_response)
        .create();

    let peer_port = peer_server
        .host_with_port()
        .parse::<SocketAddr>()
        .expect("Port must exist")
        .port();
    let schema = TestSchema::new_with_graphql_peer(peer_port);

    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), expected);

    mock.assert_async().await;
}

pub(super) async fn run_local_error_query(query: &str, expected_error: &str) {
    let schema = TestSchema::new();
    let res = schema.execute(query).await;
    assert!(!res.errors.is_empty(), "Expected GraphQL errors, got none");
    assert!(
        res.errors
            .iter()
            .any(|error| error.message.contains(expected_error)),
        "Expected error containing '{expected_error}', got {:?}",
        res.errors
    );
}

pub(super) fn normalize_error_query(query: &str) -> String {
    query.replace("sensor: \"src 2\"", "sensor: \"src 1\"")
}

pub(super) fn replace_first_pagination(query: &str, replacement: &str) -> String {
    let updated = normalize_error_query(query);
    if updated.contains("first: 1") {
        return updated.replace("first: 1", replacement);
    }
    panic!("query must include first: 1 for pagination validation test");
}

pub(super) fn make_same_cursor_query(query: &str) -> String {
    let cursor = "Y3Vyc29y";
    replace_first_pagination(
        query,
        &format!("first: 1, after: \"{cursor}\", before: \"{cursor}\""),
    )
}

pub(super) fn make_after_last_query(query: &str) -> String {
    replace_first_pagination(query, "after: \"Y3Vyc29y\", last: 1")
}

pub(super) fn make_before_first_query(query: &str) -> String {
    replace_first_pagination(query, "before: \"Y3Vyc29y\", first: 1")
}

pub(super) fn make_out_of_range_after_query(query: &str) -> String {
    replace_first_pagination(query, "after: \"AA==\", first: 1")
}

pub(super) fn make_out_of_range_before_query(query: &str) -> String {
    replace_first_pagination(query, "before: \"/w==\", last: 1")
}

pub(super) fn sample_time_timestamps() -> [i64; 4] {
    [
        Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
        Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
        Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
        Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    ]
}

pub(super) fn sensor_timestamp_key(sensor: &str, timestamp: i64) -> Vec<u8> {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend_from_slice(&timestamp.to_be_bytes());
    key
}

pub(super) fn setup_process_create(schema: &TestSchema) {
    let store = schema.db.process_create_store().unwrap();
    insert_process_create_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_file_create_time(schema: &TestSchema) {
    let store = schema.db.file_create_time_store().unwrap();
    let ts = sample_time_timestamps()[0];
    insert_file_create_time_event(&store, "src 1", ts, ts, ts);
}

pub(super) fn setup_network_connect(schema: &TestSchema) {
    let store = schema.db.network_connect_store().unwrap();
    insert_network_connect_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_process_terminate(schema: &TestSchema) {
    let store = schema.db.process_terminate_store().unwrap();
    insert_process_terminated_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_image_load(schema: &TestSchema) {
    let store = schema.db.image_load_store().unwrap();
    insert_image_loaded_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_file_create(schema: &TestSchema) {
    let store = schema.db.file_create_store().unwrap();
    let ts = sample_time_timestamps()[0];
    insert_file_create_event(&store, "src 1", ts, ts);
}

pub(super) fn setup_registry_value_set(schema: &TestSchema) {
    let store = schema.db.registry_value_set_store().unwrap();
    insert_registry_value_set_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_registry_key_rename(schema: &TestSchema) {
    let store = schema.db.registry_key_rename_store().unwrap();
    insert_registry_key_rename_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_file_create_stream_hash(schema: &TestSchema) {
    let store = schema.db.file_create_stream_hash_store().unwrap();
    insert_file_create_stream_hash_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_pipe_event(schema: &TestSchema) {
    let store = schema.db.pipe_event_store().unwrap();
    insert_pipe_event_raw_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_dns_query(schema: &TestSchema) {
    let store = schema.db.dns_query_store().unwrap();
    insert_dns_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_file_delete(schema: &TestSchema) {
    let store = schema.db.file_delete_store().unwrap();
    insert_file_delete_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_process_tamper(schema: &TestSchema) {
    let store = schema.db.process_tamper_store().unwrap();
    insert_process_tampering_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_file_delete_detected(schema: &TestSchema) {
    let store = schema.db.file_delete_detected_store().unwrap();
    insert_file_delete_detected_event(&store, "src 1", sample_time_timestamps()[0]);
}

pub(super) fn setup_search_process_create(schema: &TestSchema) {
    let store = schema.db.process_create_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_process_create_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_file_create_time(schema: &TestSchema) {
    let store = schema.db.file_create_time_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_file_create_time_event(&store, "src 1", ts, ts, ts);
    }
}

pub(super) fn setup_search_network_connect(schema: &TestSchema) {
    let store = schema.db.network_connect_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_network_connect_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_process_terminate(schema: &TestSchema) {
    let store = schema.db.process_terminate_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_process_terminated_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_image_load(schema: &TestSchema) {
    let store = schema.db.image_load_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_image_loaded_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_file_create(schema: &TestSchema) {
    let store = schema.db.file_create_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_file_create_event(&store, "src 1", ts, ts);
    }
}

pub(super) fn setup_search_registry_value_set(schema: &TestSchema) {
    let store = schema.db.registry_value_set_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_registry_value_set_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_registry_key_rename(schema: &TestSchema) {
    let store = schema.db.registry_key_rename_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_registry_key_rename_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_file_create_stream_hash(schema: &TestSchema) {
    let store = schema.db.file_create_stream_hash_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_file_create_stream_hash_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_pipe_event(schema: &TestSchema) {
    let store = schema.db.pipe_event_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_pipe_event_raw_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_dns_query(schema: &TestSchema) {
    let store = schema.db.dns_query_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_dns_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_file_delete(schema: &TestSchema) {
    let store = schema.db.file_delete_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_file_delete_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_process_tamper(schema: &TestSchema) {
    let store = schema.db.process_tamper_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_process_tampering_event(&store, "src 1", ts);
    }
}

pub(super) fn setup_search_file_delete_detected(schema: &TestSchema) {
    let store = schema.db.file_delete_detected_store().unwrap();
    for &ts in &sample_time_timestamps() {
        insert_file_delete_detected_event(&store, "src 1", ts);
    }
}

pub(super) fn insert_process_create_event(
    store: &RawEventStore<ProcessCreate>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = ProcessCreate {
        agent_name: "pc-agent".to_string(),
        agent_id: "pc-agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 1234,
        image: "proc.exe".to_string(),
        file_version: "1.0".to_string(),
        description: "desc".to_string(),
        product: "product".to_string(),
        company: "company".to_string(),
        original_file_name: "proc.exe".to_string(),
        command_line: "proc.exe /S".to_string(),
        current_directory: "C:\\".to_string(),
        user: "user".to_string(),
        logon_guid: "logon_guid".to_string(),
        logon_id: 99,
        terminal_session_id: 1,
        integrity_level: "high".to_string(),
        hashes: vec!["SHA256=abc".to_string()],
        parent_process_guid: "parent_guid".to_string(),
        parent_process_id: 4321,
        parent_image: "parent.exe".to_string(),
        parent_command_line: "parent.exe".to_string(),
        parent_user: "parent_user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_file_create_time_event(
    store: &RawEventStore<FileCreationTimeChanged>,
    sensor: &str,
    timestamp: i64,
    creation_ts: i64,
    prev_ts: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = FileCreationTimeChanged {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "proc.exe".to_string(),
        target_filename: "time.log".to_string(),
        creation_utc_time: creation_ts,
        previous_creation_utc_time: prev_ts,
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_network_connect_event(
    store: &RawEventStore<NetworkConnection>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = NetworkConnection {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 1,
        image: "proc.exe".to_string(),
        user: "user".to_string(),
        protocol: "TCP".to_string(),
        initiated: true,
        source_is_ipv6: false,
        source_ip: IpAddr::from_str("192.0.2.1").unwrap(),
        source_hostname: "src-host".to_string(),
        source_port: 1234,
        source_port_name: "src".to_string(),
        destination_is_ipv6: false,
        destination_ip: IpAddr::from_str("192.0.2.2").unwrap(),
        destination_hostname: "dst-host".to_string(),
        destination_port: 4321,
        destination_port_name: "dst".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_process_terminated_event(
    store: &RawEventStore<ProcessTerminated>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = ProcessTerminated {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 77,
        image: "terminated.exe".to_string(),
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_image_loaded_event(
    store: &RawEventStore<ImageLoaded>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = ImageLoaded {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 99,
        image: "proc.exe".to_string(),
        image_loaded: "loaded.dll".to_string(),
        file_version: "1.0.0".to_string(),
        description: "desc".to_string(),
        product: "product".to_string(),
        company: "company".to_string(),
        original_file_name: "loaded.dll".to_string(),
        hashes: vec!["SHA256=123".to_string()],
        signed: true,
        signature: "signature".to_string(),
        signature_status: "Valid".to_string(),
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_file_create_event(
    store: &RawEventStore<FileCreate>,
    sensor: &str,
    timestamp: i64,
    creation_ts: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = FileCreate {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 42,
        image: "proc.exe".to_string(),
        target_filename: "created.txt".to_string(),
        creation_utc_time: creation_ts,
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_registry_value_set_event(
    store: &RawEventStore<RegistryValueSet>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = RegistryValueSet {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        event_type: "SetValue".to_string(),
        process_guid: "guid".to_string(),
        process_id: 8,
        image: "reg.exe".to_string(),
        target_object: "\\Registry\\Machine\\Key".to_string(),
        details: "REG_SZ".to_string(),
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_registry_key_rename_event(
    store: &RawEventStore<RegistryKeyValueRename>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = RegistryKeyValueRename {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        event_type: "RenameValue".to_string(),
        process_guid: "guid".to_string(),
        process_id: 8,
        image: "reg.exe".to_string(),
        target_object: "\\Registry\\Machine\\Key\\Old".to_string(),
        new_name: "NewName".to_string(),
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_file_create_stream_hash_event(
    store: &RawEventStore<FileCreateStreamHash>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = FileCreateStreamHash {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 9,
        image: "proc.exe".to_string(),
        target_filename: "stream.log".to_string(),
        creation_utc_time: timestamp,
        hash: vec!["SHA256=stream".to_string()],
        contents: "stream-bytes".to_string(),
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_pipe_event_raw_event(
    store: &RawEventStore<PipeEvent>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = PipeEvent {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        event_type: "PipeEvent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 11,
        pipe_name: "\\\\.\\pipe\\example".to_string(),
        image: "proc.exe".to_string(),
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_dns_event(store: &RawEventStore<DnsEvent>, sensor: &str, timestamp: i64) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = DnsEvent {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 12,
        query_name: "example.com".to_string(),
        query_status: 0,
        query_results: vec!["93.184.216.34".to_string()],
        image: "proc.exe".to_string(),
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_file_delete_event(
    store: &RawEventStore<FileDelete>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = FileDelete {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 13,
        user: "user".to_string(),
        image: "proc.exe".to_string(),
        target_filename: "old.log".to_string(),
        hashes: vec!["SHA256=old".to_string()],
        is_executable: false,
        archived: false,
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_process_tampering_event(
    store: &RawEventStore<ProcessTampering>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = ProcessTampering {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 14,
        image: "proc.exe".to_string(),
        tamper_type: "ThreadSuspend".to_string(),
        user: "user".to_string(),
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}

pub(super) fn insert_file_delete_detected_event(
    store: &RawEventStore<FileDeleteDetected>,
    sensor: &str,
    timestamp: i64,
) {
    let key = sensor_timestamp_key(sensor, timestamp);
    let event = FileDeleteDetected {
        agent_name: "agent".to_string(),
        agent_id: "agent_id".to_string(),
        process_guid: "guid".to_string(),
        process_id: 15,
        user: "user".to_string(),
        image: "proc.exe".to_string(),
        target_filename: "suspect.log".to_string(),
        hashes: vec!["SHA256=suspect".to_string()],
        is_executable: true,
    };
    let value = bincode::serialize(&event).unwrap();
    store.append(&key, &value).unwrap();
}
