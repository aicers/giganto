//! Export of the endpoint header on Sysmon records and of the endpoint record
//! kinds.

use std::fmt::Display;

use giganto_client::ingest::endpoint::EndpointHeader;
use serde::Serialize;
use serde_json::{Value, json};

use super::{assert_keys_in_order, export_identification_lines, fixture::assert_export_error};
use crate::{
    graphql::{
        endpoint_header::fixtures::{
            LOGON_ID_FULL, auditd, create_remote_thread, dns_event, driver_load, empty_auditd,
            empty_journald, empty_windows_event_log, file_create, file_create_stream_hash,
            file_creation_time_changed, file_delete, file_delete_detected, full_header,
            image_loaded, journald, network_connection, pipe_event, process_access, process_create,
            process_tampering, process_terminated, raw_access_read, registry_key_value_rename,
            registry_object_add_del, registry_value_set, sparse_header, windows_event_log,
        },
        tests::TestSchema,
    },
    storage::RawEventStore,
};

const SENSOR: &str = "src1";
/// 2026-01-01T00:00:00Z, inside the range `export_identification_lines`
/// exports.
const TIMESTAMP: i64 = 1_767_225_600_000_000_000;
const TIME: &str = "1767225600.000000000";
const NEXT_TIME: &str = "1767225600.000000001";

fn put<T: Serialize>(store: &RawEventStore<'_, T>, timestamp: i64, record: &T) {
    let mut key = SENSOR.as_bytes().to_vec();
    key.push(0);
    key.extend_from_slice(&timestamp.to_be_bytes());
    store
        .append(&key, &bincode::serialize(record).unwrap())
        .unwrap();
}

/// Returns the JSON export of `full_header()`.
fn full_header_json() -> Value {
    json!({
        "endpoint_id": "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0",
        "stream": "f0e9d8c7-b6a5-4493-8271-605f4e3d2c1b",
        "seq": u64::MAX,
        "event_time": "1700000000.000000001",
        "collected_at": "1700000001.000000000",
        "clock_offset": {
            "offset_ms": -15,
            "uncertainty_ms": 3,
            "measured_at": "1700000000.500000000",
        },
        "hostname": "host-01",
        "ips": ["192.0.2.10", "2001:db8::1"],
        "default_route_ip": "192.0.2.10",
        "net_state_source": "probed",
        "os_family": "freebsd",
        "os_version": "14.1",
        "collection_mode": "minimal",
        "process_key": "00ab0fff",
        "schema": 3,
    })
}

/// Returns the JSON export of `sparse_header()`.
fn sparse_header_json() -> Value {
    json!({
        "endpoint_id": "11111111-2222-3333-4444-555555555555",
        "stream": "66666666-7777-8888-9999-aaaaaaaaaaaa",
        "seq": 1,
        "event_time": "1700000000.000000000",
        "collected_at": "1700000000.250000000",
        "clock_offset": null,
        "hostname": "host-02",
        "ips": [],
        "default_route_ip": null,
        "net_state_source": "observed",
        "os_family": "windows",
        "os_version": "10.0.19045",
        "collection_mode": "extended",
        "process_key": null,
        "schema": 1,
    })
}

/// Asserts that the JSON object `line` starts with `time` and `sensor` and
/// ends with `endpoint`.
fn assert_starts_with_time_and_ends_with_endpoint(line: &str) {
    assert!(line.starts_with("{\"time\":"), "{line}");
    let sensor = line.find(",\"sensor\":").expect("sensor key");
    assert!(
        !line[..sensor].contains(",\""),
        "sensor is not second in {line}"
    );
    let endpoint = line.rfind("\"endpoint\":").expect("endpoint key");
    let value = &line[endpoint + "\"endpoint\":".len()..line.len() - 1];
    assert!(
        serde_json::from_str::<Value>(value).is_ok(),
        "endpoint is not the last key in {line}"
    );
}

const NO_HEADER_CSV: &str = "-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-";

/// Exports `protocol` as CSV and JSON, and returns the lines of each.
async fn export(schema: &TestSchema, protocol: &str) -> (Vec<String>, Vec<Value>) {
    let csv = export_identification_lines(schema, protocol, "csv").await;
    let json = export_identification_lines(schema, protocol, "json").await;
    let json = json
        .iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (csv, json)
}

fn json_lines(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// Exports an existing Sysmon kind holding a record with a full header, then
/// one with a sparse header, then one without, and checks the header columns
/// and keys of each.
async fn assert_existing_kind<T, F>(protocol: &str, store: F, make: fn(Option<EndpointHeader>) -> T)
where
    T: Serialize + Display,
    F: Fn(&TestSchema) -> RawEventStore<'_, T>,
{
    let schema = TestSchema::new();
    let records = [
        make(Some(full_header())),
        make(Some(sparse_header())),
        make(None),
    ];
    {
        let store = store(&schema);
        for (offset, record) in (0..).zip(&records) {
            put(&store, TIMESTAMP + offset, record);
        }
    }

    let csv = export_identification_lines(&schema, protocol, "csv").await;
    assert_eq!(csv.len(), 3, "{protocol}");
    for (line, record) in csv.iter().zip(&records) {
        assert!(line.ends_with(&format!("\t{record}")), "{protocol}: {line}");
    }
    assert!(
        csv[0].ends_with(&format!("\t{}", full_header())),
        "{protocol}"
    );
    assert!(
        csv[1].ends_with(&format!("\t{}", sparse_header())),
        "{protocol}"
    );
    assert!(
        csv[2].ends_with(&format!("\t{NO_HEADER_CSV}")),
        "{protocol}"
    );

    let lines = export_identification_lines(&schema, protocol, "json").await;
    for line in &lines {
        assert_starts_with_time_and_ends_with_endpoint(line);
    }
    let json = json_lines(&lines);
    assert_eq!(json[0]["endpoint"], full_header_json(), "{protocol}");
    assert_eq!(json[1]["endpoint"], sparse_header_json(), "{protocol}");
    assert_eq!(json[2]["endpoint"], Value::Null, "{protocol}");
}

#[tokio::test]
async fn export_existing_sysmon_kinds_end_with_the_endpoint_header() {
    assert_existing_kind(
        "file create time",
        |s| s.db.file_create_time_store().unwrap(),
        file_creation_time_changed,
    )
    .await;
    // `export_by_protocol` names this kind `network_connect`.
    assert_existing_kind(
        "network_connect",
        |s| s.db.network_connect_store().unwrap(),
        network_connection,
    )
    .await;
    assert_existing_kind(
        "process terminate",
        |s| s.db.process_terminate_store().unwrap(),
        process_terminated,
    )
    .await;
    assert_existing_kind(
        "image load",
        |s| s.db.image_load_store().unwrap(),
        image_loaded,
    )
    .await;
    assert_existing_kind(
        "file create",
        |s| s.db.file_create_store().unwrap(),
        file_create,
    )
    .await;
    assert_existing_kind(
        "registry value set",
        |s| s.db.registry_value_set_store().unwrap(),
        registry_value_set,
    )
    .await;
    assert_existing_kind(
        "registry key rename",
        |s| s.db.registry_key_rename_store().unwrap(),
        registry_key_value_rename,
    )
    .await;
    assert_existing_kind(
        "file create stream hash",
        |s| s.db.file_create_stream_hash_store().unwrap(),
        file_create_stream_hash,
    )
    .await;
    assert_existing_kind(
        "pipe event",
        |s| s.db.pipe_event_store().unwrap(),
        pipe_event,
    )
    .await;
    assert_existing_kind("dns query", |s| s.db.dns_query_store().unwrap(), dns_event).await;
    assert_existing_kind(
        "file delete",
        |s| s.db.file_delete_store().unwrap(),
        file_delete,
    )
    .await;
    assert_existing_kind(
        "process tamper",
        |s| s.db.process_tamper_store().unwrap(),
        process_tampering,
    )
    .await;
    assert_existing_kind(
        "file delete detected",
        |s| s.db.file_delete_detected_store().unwrap(),
        file_delete_detected,
    )
    .await;
}

#[tokio::test]
async fn export_process_create_ends_with_the_header_and_logon_id_full() {
    let schema = TestSchema::new();
    let with_header = process_create(Some(full_header()), Some(LOGON_ID_FULL));
    let without_header = process_create(None, None);
    let store = schema.db.process_create_store().unwrap();
    put(&store, TIMESTAMP, &with_header);
    put(&store, TIMESTAMP + 1, &without_header);

    let (csv, json) = export(&schema, "process create").await;
    assert_eq!(
        csv,
        vec![
            format!("{TIME}\t{SENSOR}\t{with_header}"),
            format!("{NEXT_TIME}\t{SENSOR}\t{without_header}"),
        ]
    );
    assert!(csv[0].ends_with(&format!("\t{}\t{LOGON_ID_FULL}", full_header())));
    assert!(csv[1].ends_with(&format!("\t{NO_HEADER_CSV}\t-")));

    let lines = export_identification_lines(&schema, "process create", "json").await;
    assert_keys_in_order(&lines[0], &["parent_user", "endpoint", "logon_id_full"]);
    assert_eq!(json[0]["endpoint"], full_header_json());
    assert_eq!(json[0]["logon_id_full"], json!(LOGON_ID_FULL));
    assert_eq!(json[1]["endpoint"], Value::Null);
    assert_eq!(json[1]["logon_id_full"], Value::Null);
}

/// Exports `protocol`, holding `record` and then `second`, and checks the
/// CSV lines are the records' `Display` and the JSON lines `expected`.
async fn assert_new_kind<T: Serialize + Display>(
    schema: &TestSchema,
    protocol: &str,
    store: &RawEventStore<'_, T>,
    records: [T; 2],
    expected: [Value; 2],
) {
    put(store, TIMESTAMP, &records[0]);
    put(store, TIMESTAMP + 1, &records[1]);

    let (csv, json) = export(schema, protocol).await;
    assert_eq!(
        csv,
        vec![
            format!("{TIME}\t{SENSOR}\t{}", records[0]),
            format!("{NEXT_TIME}\t{SENSOR}\t{}", records[1]),
        ],
        "{protocol}"
    );
    assert_eq!(json, expected.to_vec(), "{protocol}");

    let lines = export_identification_lines(schema, protocol, "json").await;
    for line in &lines {
        assert_starts_with_time_and_ends_with_endpoint(line);
    }
}

// One case per kind, listed in full so each expectation reads on its own.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn export_new_sysmon_kinds() {
    let schema = TestSchema::new();
    assert_new_kind(
        &schema,
        "driver load",
        &schema.db.driver_load_store().unwrap(),
        [driver_load(Some(full_header())), driver_load(None)],
        [true, false].map(|with_header| {
            json!({
                "time": if with_header { TIME } else { NEXT_TIME },
                "sensor": SENSOR,
                "agent_name": "agent_name",
                "agent_id": "agent_id",
                "image_loaded": "image_loaded",
                "hashes": ["hashes"],
                "signed": true,
                "signature": "signature",
                "signature_status": "signature_status",
                "endpoint": if with_header { full_header_json() } else { Value::Null },
            })
        }),
    )
    .await;
    assert_new_kind(
        &schema,
        "create remote thread",
        &schema.db.create_remote_thread_store().unwrap(),
        [
            create_remote_thread(Some(full_header())),
            create_remote_thread(None),
        ],
        [true, false].map(|with_header| {
            json!({
                "time": if with_header { TIME } else { NEXT_TIME },
                "sensor": SENSOR,
                "agent_name": "agent_name",
                "agent_id": "agent_id",
                "source_process_guid": "source_process_guid",
                "source_process_id": 7,
                "source_image": "source_image",
                "target_process_guid": "target_process_guid",
                "target_process_id": 7,
                "target_image": "target_image",
                "new_thread_id": 7,
                "start_address": "start_address",
                "start_module": "start_module",
                "start_function": "start_function",
                "source_user": "source_user",
                "target_user": "target_user",
                "endpoint": if with_header { full_header_json() } else { Value::Null },
            })
        }),
    )
    .await;
    assert_new_kind(
        &schema,
        "raw access read",
        &schema.db.raw_access_read_store().unwrap(),
        [raw_access_read(Some(full_header())), raw_access_read(None)],
        [true, false].map(|with_header| {
            json!({
                "time": if with_header { TIME } else { NEXT_TIME },
                "sensor": SENSOR,
                "agent_name": "agent_name",
                "agent_id": "agent_id",
                "process_guid": "process_guid",
                "process_id": 7,
                "image": "image",
                "device": "device",
                "user": "user",
                "endpoint": if with_header { full_header_json() } else { Value::Null },
            })
        }),
    )
    .await;
    assert_new_kind(
        &schema,
        "process access",
        &schema.db.process_access_store().unwrap(),
        [process_access(Some(full_header())), process_access(None)],
        [true, false].map(|with_header| {
            json!({
                "time": if with_header { TIME } else { NEXT_TIME },
                "sensor": SENSOR,
                "agent_name": "agent_name",
                "agent_id": "agent_id",
                "source_process_guid": "source_process_guid",
                "source_process_id": 7,
                "source_thread_id": 7,
                "source_image": "source_image",
                "target_process_guid": "target_process_guid",
                "target_process_id": 7,
                "target_image": "target_image",
                "granted_access": 0x1_0000_0001_u64,
                "call_trace": "call_trace",
                "source_user": "source_user",
                "target_user": "target_user",
                "endpoint": if with_header { full_header_json() } else { Value::Null },
            })
        }),
    )
    .await;
    assert_new_kind(
        &schema,
        "registry object add del",
        &schema.db.registry_object_add_del_store().unwrap(),
        [
            registry_object_add_del(Some(full_header())),
            registry_object_add_del(None),
        ],
        [true, false].map(|with_header| {
            json!({
                "time": if with_header { TIME } else { NEXT_TIME },
                "sensor": SENSOR,
                "agent_name": "agent_name",
                "agent_id": "agent_id",
                "event_type": "event_type",
                "process_guid": "process_guid",
                "process_id": 7,
                "image": "image",
                "target_object": "target_object",
                "user": "user",
                "endpoint": if with_header { full_header_json() } else { Value::Null },
            })
        }),
    )
    .await;
}

// One case per kind, listed in full so each expectation reads on its own.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn export_endpoint_log_kinds() {
    let schema = TestSchema::new();
    assert_new_kind(
        &schema,
        "endpoint windows event log",
        &schema.db.endpoint_windows_event_log_store().unwrap(),
        [windows_event_log(), empty_windows_event_log()],
        [
            json!({
                "time": TIME,
                "sensor": SENSOR,
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": 4624,
                "version": 2,
                "level": 4,
                "task": 12544,
                "opcode": 1,
                "keywords": 0x8020_0000_0000_0000_u64,
                "record_id": 123_456,
                "computer": "host-01",
                "user_sid": "S-1-5-18",
                "event_data": [
                    {"name": "SubjectUserName", "value": "SYSTEM"},
                    {"name": null, "value": "unnamed"},
                ],
                "user_data_xml": "<UserData/>",
                "endpoint": full_header_json(),
            }),
            json!({
                "time": NEXT_TIME,
                "sensor": SENSOR,
                "channel": null,
                "provider": null,
                "event_id": null,
                "version": null,
                "level": null,
                "task": null,
                "opcode": null,
                "keywords": null,
                "record_id": null,
                "computer": null,
                "user_sid": null,
                "event_data": null,
                "user_data_xml": null,
                "endpoint": sparse_header_json(),
            }),
        ],
    )
    .await;
    assert_new_kind(
        &schema,
        "endpoint journald",
        &schema.db.endpoint_journald_store().unwrap(),
        [journald(), empty_journald()],
        [
            json!({
                "time": TIME,
                "sensor": SENSOR,
                "fields": [
                    {"name": "MESSAGE", "text": "Started session", "bytes": null},
                    {"name": "BINARY", "text": null, "bytes": "001fa0ff"},
                ],
                "endpoint": full_header_json(),
            }),
            json!({
                "time": NEXT_TIME,
                "sensor": SENSOR,
                "fields": null,
                "endpoint": sparse_header_json(),
            }),
        ],
    )
    .await;
    assert_new_kind(
        &schema,
        "endpoint auditd",
        &schema.db.endpoint_auditd_store().unwrap(),
        [auditd(), empty_auditd()],
        [
            json!({
                "time": TIME,
                "sensor": SENSOR,
                "serial": 8731,
                "records": [
                    {
                        "record_type": "SYSCALL",
                        "fields": [{"name": "syscall", "text": "59", "bytes": null}],
                    },
                    {
                        "record_type": "EXECVE",
                        "fields": [
                            {"name": "argc", "text": "1", "bytes": null},
                            {"name": "a0", "text": null, "bytes": "6c73"},
                        ],
                    },
                    {"record_type": "EOE", "fields": []},
                ],
                "endpoint": full_header_json(),
            }),
            json!({
                "time": NEXT_TIME,
                "sensor": SENSOR,
                "serial": null,
                "records": null,
                "endpoint": sparse_header_json(),
            }),
        ],
    )
    .await;
}

fn export_query(protocol: &str, extra_filter: &str) -> String {
    format!(
        r#"{{ export(filter: {{ protocol: "{protocol}", sensorId: "{SENSOR}", {extra_filter} }},
            exportType: "json") }}"#
    )
}

const NEW_SYSMON_PROTOCOLS: [&str; 5] = [
    "driver load",
    "create remote thread",
    "raw access read",
    "process access",
    "registry object add del",
];
const ENDPOINT_LOG_PROTOCOLS: [&str; 3] = [
    "endpoint windows event log",
    "endpoint journald",
    "endpoint auditd",
];
const ADDRESS_FILTER: &str = r#"origAddr: { start: "192.0.2.1", end: "192.0.2.9" }"#;
const PORT_FILTER: &str = "respPort: { start: 1, end: 2 }";
const AGENT_FILTER: &str = r#"agentName: "agent_name", agentId: "agent_id""#;
const KIND_FILTER: &str = r#"kind: "kind""#;

#[tokio::test]
async fn new_sysmon_protocols_accept_agent_filters_only() {
    for protocol in NEW_SYSMON_PROTOCOLS {
        let schema = TestSchema::new();
        let res = schema.execute(&export_query(protocol, AGENT_FILTER)).await;
        assert!(res.errors.is_empty(), "{protocol}: {:?}", res.errors);

        for filter in [ADDRESS_FILTER, PORT_FILTER] {
            assert_export_error(&export_query(protocol, filter), "Invalid ip/port input").await;
        }
        assert_export_error(
            &export_query(protocol, KIND_FILTER),
            "Invalid kind/agent_name/agent_id input",
        )
        .await;
    }
}

#[tokio::test]
async fn endpoint_log_protocols_accept_no_address_agent_or_kind_filter() {
    for protocol in ENDPOINT_LOG_PROTOCOLS {
        let schema = TestSchema::new();
        let res = schema.execute(&export_query(protocol, "")).await;
        assert!(res.errors.is_empty(), "{protocol}: {:?}", res.errors);

        for filter in [ADDRESS_FILTER, PORT_FILTER] {
            assert_export_error(&export_query(protocol, filter), "Invalid ip/port input").await;
        }
        for filter in [AGENT_FILTER, KIND_FILTER] {
            assert_export_error(
                &export_query(protocol, filter),
                "Invalid kind/agent_name/agent_id input",
            )
            .await;
        }
    }
}

/// The agent filter applies to the new Sysmon kinds' exports.
#[tokio::test]
async fn new_sysmon_exports_apply_the_agent_filter() {
    let schema = TestSchema::new();
    put(
        &schema.db.driver_load_store().unwrap(),
        TIMESTAMP,
        &driver_load(None),
    );
    let token_of = |res: async_graphql::Response| {
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        res.data.into_json().unwrap()["export"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let matching = token_of(
        schema
            .execute(&export_query(
                "driver load",
                r#"agentId: "agent_id", time: { start: "2026-01-01T00:00:00Z" }"#,
            ))
            .await,
    );
    let other = token_of(
        schema
            .execute(&export_query(
                "driver load",
                r#"agentId: "other", time: { start: "2026-01-01T00:00:00Z" }"#,
            ))
            .await,
    );
    let matching = super::read_export_file_with_retry(&matching).await;
    let other = super::read_export_file_with_retry(&other).await;
    assert_eq!(matching.lines().count(), 1);
    assert_eq!(other.lines().count(), 0);
}
