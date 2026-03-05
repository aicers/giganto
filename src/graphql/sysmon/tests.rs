use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use chrono::{TimeZone, Utc};

use crate::graphql::tests::TestSchema;

mod fixtures;
use fixtures::{
    insert_dns_event, insert_file_create_event, insert_file_create_stream_hash_event,
    insert_file_create_time_event, insert_file_delete_detected_event, insert_file_delete_event,
    insert_image_loaded_event, insert_network_connect_event, insert_pipe_event_raw_event,
    insert_process_create_event, insert_process_tampering_event, insert_process_terminated_event,
    insert_registry_key_rename_event, insert_registry_value_set_event, make_after_last_query,
    make_before_first_query, make_out_of_range_after_query, make_out_of_range_before_query,
    make_same_cursor_query, run_cluster_event_query, run_local_error_query, run_local_event_query,
    setup_dns_query, setup_file_create, setup_file_create_stream_hash, setup_file_create_time,
    setup_file_delete, setup_file_delete_detected, setup_image_load, setup_network_connect,
    setup_pipe_event, setup_process_create, setup_process_tamper, setup_process_terminate,
    setup_registry_key_rename, setup_registry_value_set, setup_search_dns_query,
    setup_search_file_create, setup_search_file_create_stream_hash, setup_search_file_create_time,
    setup_search_file_delete, setup_search_file_delete_detected, setup_search_image_load,
    setup_search_network_connect, setup_search_pipe_event, setup_search_process_create,
    setup_search_process_tamper, setup_search_process_terminate, setup_search_registry_key_rename,
    setup_search_registry_value_set,
};

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn sysmon_events_timestamp_format_stability() {
    let schema = TestSchema::new();
    let sensor = "src1";
    let base_ts = Utc
        .with_ymd_and_hms(2024, 3, 4, 5, 6, 7)
        .unwrap()
        .timestamp_nanos_opt()
        .unwrap();
    let step = 1_000_000;

    let process_create_store = schema.db.process_create_store().unwrap();
    let file_create_time_store = schema.db.file_create_time_store().unwrap();
    let network_connect_store = schema.db.network_connect_store().unwrap();
    let process_terminate_store = schema.db.process_terminate_store().unwrap();
    let image_load_store = schema.db.image_load_store().unwrap();
    let file_create_store = schema.db.file_create_store().unwrap();
    let registry_value_set_store = schema.db.registry_value_set_store().unwrap();
    let registry_key_rename_store = schema.db.registry_key_rename_store().unwrap();
    let file_create_stream_hash_store = schema.db.file_create_stream_hash_store().unwrap();
    let pipe_event_store = schema.db.pipe_event_store().unwrap();
    let dns_query_store = schema.db.dns_query_store().unwrap();
    let file_delete_store = schema.db.file_delete_store().unwrap();
    let process_tamper_store = schema.db.process_tamper_store().unwrap();
    let file_delete_detected_store = schema.db.file_delete_detected_store().unwrap();

    insert_process_create_event(&process_create_store, sensor, base_ts);
    let file_create_time_creation = base_ts + step + 10;
    let file_create_time_previous = base_ts + step - 10;
    insert_file_create_time_event(
        &file_create_time_store,
        sensor,
        base_ts + step,
        file_create_time_creation,
        file_create_time_previous,
    );
    insert_network_connect_event(&network_connect_store, sensor, base_ts + step * 2);
    insert_process_terminated_event(&process_terminate_store, sensor, base_ts + step * 3);
    insert_image_loaded_event(&image_load_store, sensor, base_ts + step * 4);
    let file_create_creation = base_ts + step * 5 + 20;
    insert_file_create_event(
        &file_create_store,
        sensor,
        base_ts + step * 5,
        file_create_creation,
    );
    insert_registry_value_set_event(&registry_value_set_store, sensor, base_ts + step * 6);
    insert_registry_key_rename_event(&registry_key_rename_store, sensor, base_ts + step * 7);
    insert_file_create_stream_hash_event(
        &file_create_stream_hash_store,
        sensor,
        base_ts + step * 8,
    );
    insert_pipe_event_raw_event(&pipe_event_store, sensor, base_ts + step * 9);
    insert_dns_event(&dns_query_store, sensor, base_ts + step * 10);
    insert_file_delete_event(&file_delete_store, sensor, base_ts + step * 11);
    insert_process_tampering_event(&process_tamper_store, sensor, base_ts + step * 12);
    insert_file_delete_detected_event(&file_delete_detected_store, sensor, base_ts + step * 13);

    let query = r#"
    {
        sysmonEvents(
            filter: {
                sensor: "src1",
                time: { start: "2024-03-04T05:06:06Z", end: "2024-03-04T05:06:25Z" }
            },
            first: 20
        ) {
            edges {
                node {
                    __typename
                    ... on ProcessCreateEvent { time }
                    ... on FileCreationTimeChangedEvent { time creationUtcTime previousCreationUtcTime }
                    ... on NetworkConnectionEvent { time }
                    ... on ProcessTerminatedEvent { time }
                    ... on ImageLoadedEvent { time }
                    ... on FileCreateEvent { time creationUtcTime }
                    ... on RegistryValueSetEvent { time }
                    ... on RegistryKeyValueRenameEvent { time }
                    ... on FileCreateStreamHashEvent { time creationUtcTime }
                    ... on PipeEventEvent { time }
                    ... on DnsEventEvent { time }
                    ... on FileDeleteEvent { time }
                    ... on ProcessTamperingEvent { time }
                    ... on FileDeleteDetectedEvent { time }
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
    let data = res.data.into_json().unwrap();
    let edges = data["sysmonEvents"]["edges"].as_array().unwrap();

    let expected_types = [
        "ProcessCreateEvent",
        "FileCreationTimeChangedEvent",
        "NetworkConnectionEvent",
        "ProcessTerminatedEvent",
        "ImageLoadedEvent",
        "FileCreateEvent",
        "RegistryValueSetEvent",
        "RegistryKeyValueRenameEvent",
        "FileCreateStreamHashEvent",
        "PipeEventEvent",
        "DnsEventEvent",
        "FileDeleteEvent",
        "ProcessTamperingEvent",
        "FileDeleteDetectedEvent",
    ];
    let mut seen = HashSet::new();
    let mut expected_times: HashMap<&str, String> = HashMap::new();
    expected_times.insert(
        "ProcessCreateEvent",
        Utc.timestamp_nanos(base_ts).to_rfc3339(),
    );
    expected_times.insert(
        "FileCreationTimeChangedEvent",
        Utc.timestamp_nanos(base_ts + step).to_rfc3339(),
    );
    expected_times.insert(
        "NetworkConnectionEvent",
        Utc.timestamp_nanos(base_ts + step * 2).to_rfc3339(),
    );
    expected_times.insert(
        "ProcessTerminatedEvent",
        Utc.timestamp_nanos(base_ts + step * 3).to_rfc3339(),
    );
    expected_times.insert(
        "ImageLoadedEvent",
        Utc.timestamp_nanos(base_ts + step * 4).to_rfc3339(),
    );
    expected_times.insert(
        "FileCreateEvent",
        Utc.timestamp_nanos(base_ts + step * 5).to_rfc3339(),
    );
    expected_times.insert(
        "RegistryValueSetEvent",
        Utc.timestamp_nanos(base_ts + step * 6).to_rfc3339(),
    );
    expected_times.insert(
        "RegistryKeyValueRenameEvent",
        Utc.timestamp_nanos(base_ts + step * 7).to_rfc3339(),
    );
    expected_times.insert(
        "FileCreateStreamHashEvent",
        Utc.timestamp_nanos(base_ts + step * 8).to_rfc3339(),
    );
    expected_times.insert(
        "PipeEventEvent",
        Utc.timestamp_nanos(base_ts + step * 9).to_rfc3339(),
    );
    expected_times.insert(
        "DnsEventEvent",
        Utc.timestamp_nanos(base_ts + step * 10).to_rfc3339(),
    );
    expected_times.insert(
        "FileDeleteEvent",
        Utc.timestamp_nanos(base_ts + step * 11).to_rfc3339(),
    );
    expected_times.insert(
        "ProcessTamperingEvent",
        Utc.timestamp_nanos(base_ts + step * 12).to_rfc3339(),
    );
    expected_times.insert(
        "FileDeleteDetectedEvent",
        Utc.timestamp_nanos(base_ts + step * 13).to_rfc3339(),
    );

    for edge in edges {
        let node = edge["node"].as_object().unwrap();
        let typename = node["__typename"].as_str().unwrap();
        seen.insert(typename.to_string());
        let expected_time = expected_times.get(typename).unwrap();
        assert_eq!(node["time"].as_str().unwrap(), expected_time);
        match typename {
            "FileCreationTimeChangedEvent" => {
                assert_eq!(
                    node["creationUtcTime"].as_str().unwrap(),
                    Utc.timestamp_nanos(file_create_time_creation).to_rfc3339()
                );
                assert_eq!(
                    node["previousCreationUtcTime"].as_str().unwrap(),
                    Utc.timestamp_nanos(file_create_time_previous).to_rfc3339()
                );
            }
            "FileCreateEvent" => {
                assert_eq!(
                    node["creationUtcTime"].as_str().unwrap(),
                    Utc.timestamp_nanos(file_create_creation).to_rfc3339()
                );
            }
            "FileCreateStreamHashEvent" => {
                assert_eq!(
                    node["creationUtcTime"].as_str().unwrap(),
                    Utc.timestamp_nanos(base_ts + step * 8).to_rfc3339()
                );
            }
            _ => {}
        }
    }
    assert_eq!(seen.len(), expected_types.len());
    for expected in expected_types {
        assert!(
            seen.contains(expected),
            "Missing sysmon event type {expected}"
        );
    }
}

#[tokio::test]
async fn sysmon_events_last_selects_latest() {
    let schema = TestSchema::new();
    let process_create_store = schema.db.process_create_store().unwrap();
    let file_delete_detected_store = schema.db.file_delete_detected_store().unwrap();

    let time1 = Utc
        .with_ymd_and_hms(2024, 3, 4, 5, 6, 7)
        .unwrap()
        .timestamp_nanos_opt()
        .unwrap();
    let time2 = Utc
        .with_ymd_and_hms(2024, 3, 4, 5, 6, 8)
        .unwrap()
        .timestamp_nanos_opt()
        .unwrap();

    insert_process_create_event(&process_create_store, "src1", time1);
    insert_file_delete_detected_event(&file_delete_detected_store, "src1", time2);

    let query = r#"
    {
        sysmonEvents(
            filter: {
                sensor: "src1",
                time: { start: "2024-03-04T05:06:06Z", end: "2024-03-04T05:06:09Z" }
            },
            last: 1
        ) {
            edges {
                node {
                    __typename
                    ... on ProcessCreateEvent { time }
                    ... on FileDeleteDetectedEvent { time }
                }
            }
        }
    }"#;

    let res = schema.execute(query).await;
    assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
    let data = res.data.into_json().unwrap();
    let node = &data["sysmonEvents"]["edges"][0]["node"];
    assert_eq!(
        node["__typename"].as_str().unwrap(),
        "FileDeleteDetectedEvent"
    );
    assert_eq!(node["time"].as_str().unwrap(), "2024-03-04T05:06:08+00:00");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sysmon_events_with_data_giganto_cluster() {
    let query = r#"
    {
        sysmonEvents(
            filter: { sensor: "src 2" }
            first: 20
        ) {
            edges {
                node {
                    __typename
                    ... on ProcessCreateEvent { time agentName agentId processGuid image commandLine parentProcessGuid }
                    ... on FileCreationTimeChangedEvent { time agentName agentId processGuid targetFilename creationUtcTime }
                    ... on NetworkConnectionEvent { time agentName agentId processGuid protocol sourceIp destinationIp }
                    ... on ProcessTerminatedEvent { time agentName agentId processGuid image }
                    ... on ImageLoadedEvent { time agentName agentId processGuid imageLoaded signed }
                    ... on FileCreateEvent { time agentName agentId processGuid targetFilename }
                    ... on RegistryValueSetEvent { time agentName agentId processGuid eventType targetObject }
                    ... on RegistryKeyValueRenameEvent { time agentName agentId processGuid eventType newName }
                    ... on FileCreateStreamHashEvent { time agentName agentId processGuid targetFilename contents }
                    ... on PipeEventEvent { time agentName agentId processGuid eventType pipeName }
                    ... on DnsEventEvent { time agentName agentId processGuid queryName queryStatus }
                    ... on FileDeleteEvent { time agentName agentId processGuid targetFilename archived }
                    ... on ProcessTamperingEvent { time agentName agentId processGuid tamperType image }
                    ... on FileDeleteDetectedEvent { time agentName agentId processGuid targetFilename isExecutable }
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "sysmonEvents": {
                "pageInfo": {
                    "hasPreviousPage": false,
                    "hasNextPage": false,
                    "startCursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                    "endCursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM="
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "ProcessCreateEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "pc-agent",
                            "agentId": "pc-agent_id",
                            "processGuid": "guid",
                            "processId": "1234",
                            "image": "proc.exe",
                            "fileVersion": "1.0",
                            "description": "desc",
                            "product": "product",
                            "company": "company",
                            "originalFileName": "proc.exe",
                            "commandLine": "proc.exe /S",
                            "currentDirectory": "C:\\",
                            "user": "user",
                            "logonGuid": "logon_guid",
                            "logonId": "99",
                            "terminalSessionId": "1",
                            "integrityLevel": "high",
                            "hashes": ["SHA256=abc"],
                            "parentProcessGuid": "parent_guid",
                            "parentProcessId": "4321",
                            "parentImage": "parent.exe",
                            "parentCommandLine": "parent.exe",
                            "parentUser": "parent_user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "FileCreationTimeChangedEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "123",
                            "image": "proc.exe",
                            "targetFilename": "time.log",
                            "creationUtcTime": "2023-11-16T15:03:45.291779203+00:00",
                            "previousCreationUtcTime": "2023-11-16T15:03:35.291779203+00:00",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "NetworkConnectionEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "1",
                            "image": "proc.exe",
                            "user": "user",
                            "protocol": "TCP",
                            "initiated": true,
                            "sourceIsIpv6": false,
                            "sourceIp": "192.0.2.1",
                            "sourceHostname": "src-host",
                            "sourcePort": 1234,
                            "sourcePortName": "src",
                            "destinationIsIpv6": false,
                            "destinationIp": "192.0.2.2",
                            "destinationHostname": "dst-host",
                            "destinationPort": 4321,
                            "destinationPortName": "dst"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "ProcessTerminatedEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "77",
                            "image": "terminated.exe",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "ImageLoadedEvent",
                            "time": "2020-06-01T00:01:01+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "99",
                            "image": "proc.exe",
                            "imageLoaded": "loaded.dll",
                            "fileVersion": "1.0.0",
                            "description": "desc",
                            "product": "product",
                            "company": "company",
                            "originalFileName": "loaded.dll",
                            "hashes": ["SHA256=123"],
                            "signed": true,
                            "signature": "signature",
                            "signatureStatus": "Valid",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "FileCreateEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "42",
                            "image": "proc.exe",
                            "targetFilename": "created.txt",
                            "creationUtcTime": "2023-11-16T15:03:45.291779203+00:00",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "RegistryValueSetEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "eventType": "set",
                            "processGuid": "guid",
                            "processId": "44",
                            "image": "proc.exe",
                            "targetObject": "HKLM\\Software\\Key",
                            "details": "value=1",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "RegistryKeyValueRenameEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "eventType": "rename",
                            "processGuid": "guid",
                            "processId": "45",
                            "image": "proc.exe",
                            "targetObject": "HKLM\\Software\\Old",
                            "newName": "HKLM\\Software\\New",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "FileCreateStreamHashEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "9",
                            "image": "proc.exe",
                            "targetFilename": "stream.log",
                            "creationUtcTime": "2023-11-16T15:03:45.291779203+00:00",
                            "hash": ["SHA256=stream"],
                            "contents": "stream-bytes",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "PipeEventEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "eventType": "create",
                            "processGuid": "guid",
                            "processId": "47",
                            "pipeName": "\\\\pipe\\\\pipe",
                            "image": "proc.exe",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "DnsEventEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "12",
                            "queryName": "example.com",
                            "queryStatus": "0",
                            "queryResults": ["93.184.216.34"],
                            "image": "proc.exe",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "FileDeleteEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "49",
                            "user": "user",
                            "image": "proc.exe",
                            "targetFilename": "deleted.txt",
                            "hashes": ["SHA256=deadbeef"],
                            "isExecutable": false,
                            "archived": true
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "ProcessTamperingEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "50",
                            "image": "proc.exe",
                            "tamperType": "suspend",
                            "user": "user"
                        }
                    },
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "__typename": "FileDeleteDetectedEvent",
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "51",
                            "user": "user",
                            "image": "proc.exe",
                            "targetFilename": "deleted.txt",
                            "hashes": ["SHA256=deadbeef"],
                            "isExecutable": true
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

    assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
    let data = res.data.into_json().unwrap();
    let edges = data["sysmonEvents"]["edges"].as_array().unwrap();
    let expected_types = [
        "ProcessCreateEvent",
        "FileCreationTimeChangedEvent",
        "NetworkConnectionEvent",
        "ProcessTerminatedEvent",
        "ImageLoadedEvent",
        "FileCreateEvent",
        "RegistryValueSetEvent",
        "RegistryKeyValueRenameEvent",
        "FileCreateStreamHashEvent",
        "PipeEventEvent",
        "DnsEventEvent",
        "FileDeleteEvent",
        "ProcessTamperingEvent",
        "FileDeleteDetectedEvent",
    ];
    let mut seen = HashSet::new();
    for edge in edges {
        let node = edge["node"].as_object().unwrap();
        let typename = node["__typename"].as_str().unwrap();
        seen.insert(typename.to_string());
        match typename {
            "ProcessCreateEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "pc-agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "pc-agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["image"].as_str().unwrap(), "proc.exe");
                assert_eq!(node["commandLine"].as_str().unwrap(), "proc.exe /S");
                assert_eq!(node["parentProcessGuid"].as_str().unwrap(), "parent_guid");
            }
            "FileCreationTimeChangedEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["targetFilename"].as_str().unwrap(), "time.log");
                assert_eq!(
                    node["creationUtcTime"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
            }
            "NetworkConnectionEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["protocol"].as_str().unwrap(), "TCP");
                assert_eq!(node["sourceIp"].as_str().unwrap(), "192.0.2.1");
                assert_eq!(node["destinationIp"].as_str().unwrap(), "192.0.2.2");
            }
            "ProcessTerminatedEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["image"].as_str().unwrap(), "terminated.exe");
            }
            "ImageLoadedEvent" => {
                assert_eq!(node["time"].as_str().unwrap(), "2020-06-01T00:01:01+00:00");
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["imageLoaded"].as_str().unwrap(), "loaded.dll");
                assert!(node["signed"].as_bool().unwrap());
            }
            "FileCreateEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["targetFilename"].as_str().unwrap(), "created.txt");
            }
            "RegistryValueSetEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["eventType"].as_str().unwrap(), "set");
                assert_eq!(
                    node["targetObject"].as_str().unwrap(),
                    "HKLM\\Software\\Key"
                );
            }
            "RegistryKeyValueRenameEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["eventType"].as_str().unwrap(), "rename");
                assert_eq!(node["newName"].as_str().unwrap(), "HKLM\\Software\\New");
            }
            "FileCreateStreamHashEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["targetFilename"].as_str().unwrap(), "stream.log");
                assert_eq!(node["contents"].as_str().unwrap(), "stream-bytes");
            }
            "PipeEventEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["eventType"].as_str().unwrap(), "create");
                assert_eq!(node["pipeName"].as_str().unwrap(), "\\\\pipe\\\\pipe");
            }
            "DnsEventEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["queryName"].as_str().unwrap(), "example.com");
                assert_eq!(node["queryStatus"].as_str().unwrap(), "0");
            }
            "FileDeleteEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["targetFilename"].as_str().unwrap(), "deleted.txt");
                assert!(node["archived"].as_bool().unwrap());
            }
            "ProcessTamperingEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["tamperType"].as_str().unwrap(), "suspend");
                assert_eq!(node["image"].as_str().unwrap(), "proc.exe");
            }
            "FileDeleteDetectedEvent" => {
                assert_eq!(
                    node["time"].as_str().unwrap(),
                    "2023-11-16T15:03:45.291779203+00:00"
                );
                assert_eq!(node["agentName"].as_str().unwrap(), "agent");
                assert_eq!(node["agentId"].as_str().unwrap(), "agent_id");
                assert_eq!(node["processGuid"].as_str().unwrap(), "guid");
                assert_eq!(node["targetFilename"].as_str().unwrap(), "deleted.txt");
                assert!(node["isExecutable"].as_bool().unwrap());
            }
            _ => {}
        }
    }
    assert_eq!(seen.len(), expected_types.len());
    for expected in expected_types {
        assert!(
            seen.contains(expected),
            "Missing sysmon event type {expected}"
        );
    }
    mock.assert_async().await;
}

#[tokio::test]
async fn sysmon_events_local_cases() {
    for case in EVENT_CASES {
        run_local_event_query(case.setup, case.query, case.expected).await;
        let same_cursor_query = make_same_cursor_query(case.query);
        run_local_error_query(&same_cursor_query, "cannot use both `after` and `before`").await;
        let after_last_query = make_after_last_query(case.query);
        run_local_error_query(
            &after_last_query,
            "'after' and 'last' cannot be specified simultaneously",
        )
        .await;
        let before_first_query = make_before_first_query(case.query);
        run_local_error_query(
            &before_first_query,
            "'before' and 'first' cannot be specified simultaneously",
        )
        .await;
        let out_of_range_after_query = make_out_of_range_after_query(case.query);
        run_local_error_query(&out_of_range_after_query, "invalid cursor").await;
        let out_of_range_before_query = make_out_of_range_before_query(case.query);
        run_local_error_query(&out_of_range_before_query, "invalid cursor").await;
    }
}

#[tokio::test]
async fn sysmon_events_cluster_cases() {
    for case in CLUSTER_EVENT_CASES {
        run_cluster_event_query(case.query, case.expected, case.peer_response).await;
        let same_cursor_query = make_same_cursor_query(case.query);
        run_local_error_query(&same_cursor_query, "cannot use both `after` and `before`").await;
        let after_last_query = make_after_last_query(case.query);
        run_local_error_query(
            &after_last_query,
            "'after' and 'last' cannot be specified simultaneously",
        )
        .await;
        let before_first_query = make_before_first_query(case.query);
        run_local_error_query(
            &before_first_query,
            "'before' and 'first' cannot be specified simultaneously",
        )
        .await;
        let out_of_range_after_query = make_out_of_range_after_query(case.query);
        run_local_error_query(&out_of_range_after_query, "invalid cursor").await;
        let out_of_range_before_query = make_out_of_range_before_query(case.query);
        run_local_error_query(&out_of_range_before_query, "invalid cursor").await;
    }
}

#[tokio::test]
async fn sysmon_search_local_cases() {
    for case in SEARCH_CASES {
        run_local_event_query(case.setup, case.query, case.expected).await;
    }
}

#[tokio::test]
async fn sysmon_search_local_empty_cases() {
    for case in SEARCH_EMPTY_CASES {
        run_local_event_query(case.setup, case.query, case.expected).await;
    }
}

#[tokio::test]
async fn sysmon_search_cluster_cases() {
    for case in SEARCH_CLUSTER_CASES {
        run_cluster_event_query(case.query, case.expected, case.peer_response).await;
    }
}

struct EventCase {
    query: &'static str,
    expected: &'static str,
    setup: fn(&TestSchema),
}

struct ClusterEventCase {
    query: &'static str,
    expected: &'static str,
    peer_response: &'static str,
}

struct SearchCase {
    query: &'static str,
    expected: &'static str,
    setup: fn(&TestSchema),
}

struct SearchClusterCase {
    query: &'static str,
    expected: &'static str,
    peer_response: &'static str,
}

const EVENT_CASES: &[EventCase] = &[
    EventCase {
        query: r#"
    {
        processCreateEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{processCreateEvents: {edges: [{node: {agentId: \"pc-agent_id\", agentName: \"pc-agent\", processGuid: \"guid\", processId: \"1234\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_process_create,
    },
    EventCase {
        query: r#"
    {
        fileCreateTimeEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileCreateTimeEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"123\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_file_create_time,
    },
    EventCase {
        query: r#"
    {
        networkConnectEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{networkConnectEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"1\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_network_connect,
    },
    EventCase {
        query: r#"
    {
        processTerminateEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{processTerminateEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"77\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_process_terminate,
    },
    EventCase {
        query: r#"
    {
        imageLoadEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{imageLoadEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"99\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_image_load,
    },
    EventCase {
        query: r#"
    {
        fileCreateEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileCreateEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"42\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_file_create,
    },
    EventCase {
        query: r#"
    {
        registryValueSetEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{registryValueSetEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"8\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_registry_value_set,
    },
    EventCase {
        query: r#"
    {
        registryKeyRenameEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{registryKeyRenameEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"8\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_registry_key_rename,
    },
    EventCase {
        query: r#"
    {
        fileCreateStreamHashEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileCreateStreamHashEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"9\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_file_create_stream_hash,
    },
    EventCase {
        query: r#"
    {
        pipeEventEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{pipeEventEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"11\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_pipe_event,
    },
    EventCase {
        query: r#"
    {
        dnsQueryEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{dnsQueryEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"12\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_dns_query,
    },
    EventCase {
        query: r#"
    {
        fileDeleteEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileDeleteEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"13\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_file_delete,
    },
    EventCase {
        query: r#"
    {
        processTamperEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{processTamperEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"14\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_process_tamper,
    },
    EventCase {
        query: r#"
    {
        fileDeleteDetectedEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileDeleteDetectedEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"15\", time: \"2020-01-01T00:00:01+00:00\"}}]}}",
        setup: setup_file_delete_detected,
    },
];

const CLUSTER_EVENT_CASES: &[ClusterEventCase] = &[
    ClusterEventCase {
        query: r#"
    {
        processCreateEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{processCreateEvents: {edges: [{node: {agentId: \"pc-agent_id\", agentName: \"pc-agent\", processGuid: \"guid\", processId: \"1234\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "processCreateEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "pc-agent",
                            "agentId": "pc-agent_id",
                            "processGuid": "guid",
                            "processId": "1234",
                            "image": "proc.exe",
                            "fileVersion": "1.0",
                            "description": "desc",
                            "product": "product",
                            "company": "company",
                            "originalFileName": "proc.exe",
                            "commandLine": "proc.exe /S",
                            "currentDirectory": "C:\\",
                            "user": "user",
                            "logonGuid": "logon_guid",
                            "logonId": "99",
                            "terminalSessionId": "1",
                            "integrityLevel": "high",
                            "hashes": ["SHA256=abc"],
                            "parentProcessGuid": "parent_guid",
                            "parentProcessId": "4321",
                            "parentImage": "parent.exe",
                            "parentCommandLine": "parent.exe",
                            "parentUser": "parent_user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        fileCreateTimeEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileCreateTimeEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"123\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "fileCreateTimeEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "123",
                            "image": "proc.exe",
                            "targetFilename": "time.log",
                            "creationUtcTime": "2023-11-16T15:03:45.291779203+00:00",
                            "previousCreationUtcTime": "2023-11-16T15:03:35.291779203+00:00",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        networkConnectEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{networkConnectEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"1\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "networkConnectEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "1",
                            "image": "proc.exe",
                            "user": "user",
                            "protocol": "TCP",
                            "initiated": true,
                            "sourceIsIpv6": false,
                            "sourceIp": "192.0.2.1",
                            "sourceHostname": "src-host",
                            "sourcePort": 1234,
                            "sourcePortName": "src",
                            "destinationIsIpv6": false,
                            "destinationIp": "192.0.2.2",
                            "destinationHostname": "dst-host",
                            "destinationPort": 4321,
                            "destinationPortName": "dst"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        processTerminateEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{processTerminateEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"77\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "processTerminateEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "77",
                            "image": "terminated.exe",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        imageLoadEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{imageLoadEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"99\", time: \"2020-06-01T00:01:01+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "imageLoadEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2020-06-01T00:01:01+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "99",
                            "image": "proc.exe",
                            "imageLoaded": "loaded.dll",
                            "fileVersion": "1.0.0",
                            "description": "desc",
                            "product": "product",
                            "company": "company",
                            "originalFileName": "loaded.dll",
                            "hashes": ["SHA256=123"],
                            "signed": true,
                            "signature": "signature",
                            "signatureStatus": "Valid",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        fileCreateEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileCreateEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"42\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "fileCreateEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "42",
                            "image": "proc.exe",
                            "targetFilename": "created.txt",
                            "creationUtcTime": "2023-11-16T15:03:45.291779203+00:00",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        registryValueSetEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{registryValueSetEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"44\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "registryValueSetEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "eventType": "set",
                            "processGuid": "guid",
                            "processId": "44",
                            "image": "proc.exe",
                            "targetObject": "HKLM\\Software\\Key",
                            "details": "value=1",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        registryKeyRenameEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{registryKeyRenameEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"45\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "registryKeyRenameEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "eventType": "rename",
                            "processGuid": "guid",
                            "processId": "45",
                            "image": "proc.exe",
                            "targetObject": "HKLM\\Software\\Old",
                            "newName": "HKLM\\Software\\New",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        fileCreateStreamHashEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileCreateStreamHashEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"9\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "fileCreateStreamHashEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "9",
                            "image": "proc.exe",
                            "targetFilename": "stream.log",
                            "creationUtcTime": "2023-11-16T15:03:45.291779203+00:00",
                            "hash": ["SHA256=stream"],
                            "contents": "stream-bytes",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        pipeEventEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{pipeEventEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"47\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "pipeEventEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "eventType": "create",
                            "processGuid": "guid",
                            "processId": "47",
                            "pipeName": "\\\\pipe\\\\pipe",
                            "image": "proc.exe",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        dnsQueryEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{dnsQueryEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"12\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "dnsQueryEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "12",
                            "queryName": "example.com",
                            "queryStatus": "0",
                            "queryResults": ["93.184.216.34"],
                            "image": "proc.exe",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        fileDeleteEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileDeleteEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"49\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "fileDeleteEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "49",
                            "user": "user",
                            "image": "proc.exe",
                            "targetFilename": "deleted.txt",
                            "hashes": ["SHA256=deadbeef"],
                            "isExecutable": false,
                            "archived": true
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        processTamperEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{processTamperEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"50\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "processTamperEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "50",
                            "image": "proc.exe",
                            "tamperType": "suspend",
                            "user": "user"
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
    ClusterEventCase {
        query: r#"
    {
        fileDeleteDetectedEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    agentId
                    agentName
                    processGuid
                    processId
                    time
                }
            }
        }
    }"#,
        expected: "{fileDeleteDetectedEvents: {edges: [{node: {agentId: \"agent_id\", agentName: \"agent\", processGuid: \"guid\", processId: \"51\", time: \"2023-11-16T15:03:45.291779203+00:00\"}}]}}",
        peer_response: r#"
    {
        "data": {
            "fileDeleteDetectedEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "agentName": "agent",
                            "agentId": "agent_id",
                            "processGuid": "guid",
                            "processId": "51",
                            "user": "user",
                            "image": "proc.exe",
                            "targetFilename": "deleted.txt",
                            "hashes": ["SHA256=deadbeef"],
                            "isExecutable": true
                        }
                    }
                ]
            }
        }
    }
    "#,
    },
];

const SEARCH_CASES: &[SearchCase] = &[
    SearchCase {
        query: r#"
    {
        searchProcessCreateEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchProcessCreateEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_process_create,
    },
    SearchCase {
        query: r#"
    {
        searchFileCreateTimeEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileCreateTimeEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_file_create_time,
    },
    SearchCase {
        query: r#"
    {
        searchNetworkConnectEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchNetworkConnectEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_network_connect,
    },
    SearchCase {
        query: r#"
    {
        searchProcessTerminateEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchProcessTerminateEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_process_terminate,
    },
    SearchCase {
        query: r#"
    {
        searchImageLoadEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchImageLoadEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_image_load,
    },
    SearchCase {
        query: r#"
    {
        searchFileCreateEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileCreateEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_file_create,
    },
    SearchCase {
        query: r#"
    {
        searchRegistryValueSetEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchRegistryValueSetEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_registry_value_set,
    },
    SearchCase {
        query: r#"
    {
        searchRegistryKeyRenameEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchRegistryKeyRenameEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_registry_key_rename,
    },
    SearchCase {
        query: r#"
    {
        searchFileCreateStreamHashEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileCreateStreamHashEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_file_create_stream_hash,
    },
    SearchCase {
        query: r#"
    {
        searchPipeEventEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchPipeEventEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_pipe_event,
    },
    SearchCase {
        query: r#"
    {
        searchDnsQueryEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchDnsQueryEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_dns_query,
    },
    SearchCase {
        query: r#"
    {
        searchFileDeleteEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileDeleteEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_file_delete,
    },
    SearchCase {
        query: r#"
    {
        searchProcessTamperEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchProcessTamperEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_process_tamper,
    },
    SearchCase {
        query: r#"
    {
        searchFileDeleteDetectedEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileDeleteDetectedEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        setup: setup_search_file_delete_detected,
    },
];

const SEARCH_EMPTY_CASES: &[SearchCase] = &[
    SearchCase {
        query: r#"
    {
        searchProcessCreateEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchProcessCreateEvents: []}",
        setup: setup_search_process_create,
    },
    SearchCase {
        query: r#"
    {
        searchFileCreateTimeEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileCreateTimeEvents: []}",
        setup: setup_search_file_create_time,
    },
    SearchCase {
        query: r#"
    {
        searchNetworkConnectEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchNetworkConnectEvents: []}",
        setup: setup_search_network_connect,
    },
    SearchCase {
        query: r#"
    {
        searchProcessTerminateEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchProcessTerminateEvents: []}",
        setup: setup_search_process_terminate,
    },
    SearchCase {
        query: r#"
    {
        searchImageLoadEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchImageLoadEvents: []}",
        setup: setup_search_image_load,
    },
    SearchCase {
        query: r#"
    {
        searchFileCreateEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileCreateEvents: []}",
        setup: setup_search_file_create,
    },
    SearchCase {
        query: r#"
    {
        searchRegistryValueSetEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchRegistryValueSetEvents: []}",
        setup: setup_search_registry_value_set,
    },
    SearchCase {
        query: r#"
    {
        searchRegistryKeyRenameEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchRegistryKeyRenameEvents: []}",
        setup: setup_search_registry_key_rename,
    },
    SearchCase {
        query: r#"
    {
        searchFileCreateStreamHashEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileCreateStreamHashEvents: []}",
        setup: setup_search_file_create_stream_hash,
    },
    SearchCase {
        query: r#"
    {
        searchPipeEventEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchPipeEventEvents: []}",
        setup: setup_search_pipe_event,
    },
    SearchCase {
        query: r#"
    {
        searchDnsQueryEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchDnsQueryEvents: []}",
        setup: setup_search_dns_query,
    },
    SearchCase {
        query: r#"
    {
        searchFileDeleteEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileDeleteEvents: []}",
        setup: setup_search_file_delete,
    },
    SearchCase {
        query: r#"
    {
        searchProcessTamperEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchProcessTamperEvents: []}",
        setup: setup_search_process_tamper,
    },
    SearchCase {
        query: r#"
    {
        searchFileDeleteDetectedEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "no-match"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileDeleteDetectedEvents: []}",
        setup: setup_search_file_delete_detected,
    },
];

const SEARCH_CLUSTER_CASES: &[SearchClusterCase] = &[
    SearchClusterCase {
        query: r#"
    {
        searchProcessCreateEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchProcessCreateEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchProcessCreateEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchFileCreateTimeEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileCreateTimeEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchFileCreateTimeEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchNetworkConnectEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchNetworkConnectEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchNetworkConnectEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchProcessTerminateEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchProcessTerminateEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchProcessTerminateEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchImageLoadEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchImageLoadEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchImageLoadEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchFileCreateEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileCreateEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchFileCreateEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchRegistryValueSetEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchRegistryValueSetEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchRegistryValueSetEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchRegistryKeyRenameEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchRegistryKeyRenameEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchRegistryKeyRenameEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchFileCreateStreamHashEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileCreateStreamHashEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchFileCreateStreamHashEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchPipeEventEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchPipeEventEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchPipeEventEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchDnsQueryEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchDnsQueryEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchDnsQueryEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchFileDeleteEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileDeleteEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchFileDeleteEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchProcessTamperEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchProcessTamperEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchProcessTamperEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
    SearchClusterCase {
        query: r#"
    {
        searchFileDeleteDetectedEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#,
        expected: "{searchFileDeleteDetectedEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}",
        peer_response: r#"
    {
        "data": {
            "searchFileDeleteDetectedEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
        }
    }
    "#,
    },
];
