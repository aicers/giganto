use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    datetime::DateTime,
    graphql::{
        endpoint_header::fixtures::{
            HEADER_SELECTION, auditd, empty_auditd, empty_journald, empty_windows_event_log,
            full_header_graphql, journald, sparse_header_graphql, windows_event_log,
        },
        sysmon::tests::endpoint::assert_relayed_from_peer,
        tests::TestSchema,
    },
    storage::RawEventStore,
};

/// A sensor this node ingests, which the queries read locally.
const SENSOR: &str = "src 1";
/// 2023-11-14T22:15:00Z.
const BASE: i64 = 1_700_000_100_000_000_000;

fn put<T: Serialize>(store: &RawEventStore<'_, T>, timestamp: i64, record: &T) {
    let mut key = SENSOR.as_bytes().to_vec();
    key.push(0);
    key.extend_from_slice(&timestamp.to_be_bytes());
    store
        .append(&key, &bincode::serialize(record).unwrap())
        .unwrap();
}

fn time(timestamp: i64) -> String {
    DateTime::from_timestamp_nanos(timestamp).to_rfc3339()
}

async fn nodes(schema: &TestSchema, query: &str, filter: &str, selection: &str) -> Vec<Value> {
    let request = format!(
        "{{ {query}(filter: {{ {filter} }}, first: 10) \
         {{ edges {{ node {{ {selection} {HEADER_SELECTION} }} }} }} }}"
    );
    let res = schema.execute(&request).await;
    assert!(res.errors.is_empty(), "{request}: {:?}", res.errors);
    let data = res.data.into_json().unwrap();
    data[query]["edges"]
        .as_array()
        .expect("edges is a list")
        .iter()
        .map(|edge| edge["node"].clone())
        .collect()
}

fn sensor_filter() -> String {
    format!("sensor: \"{SENSOR}\"")
}

#[tokio::test]
async fn windows_event_log_events_return_every_field() {
    let schema = TestSchema::new();
    let store = schema.db.endpoint_windows_event_log_store().unwrap();
    put(&store, BASE, &windows_event_log());
    put(&store, BASE + 1, &empty_windows_event_log());

    let selection = "time channel provider eventId version level task opcode keywords \
        recordId computer userSid eventData { name value } userDataXml";
    assert_eq!(
        nodes(
            &schema,
            "endpointWindowsEventLogEvents",
            &sensor_filter(),
            selection
        )
        .await,
        vec![
            json!({
                "time": time(BASE),
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "eventId": 4624,
                "version": 2,
                "level": 4,
                "task": 12544,
                "opcode": 1,
                "keywords": "9232379236109516800",
                "recordId": "123456",
                "computer": "host-01",
                "userSid": "S-1-5-18",
                "eventData": [
                    {"name": "SubjectUserName", "value": "SYSTEM"},
                    {"name": null, "value": "unnamed"},
                ],
                "userDataXml": "<UserData/>",
                "endpoint": full_header_graphql(),
            }),
            json!({
                "time": time(BASE + 1),
                "channel": null,
                "provider": null,
                "eventId": null,
                "version": null,
                "level": null,
                "task": null,
                "opcode": null,
                "keywords": null,
                "recordId": null,
                "computer": null,
                "userSid": null,
                "eventData": null,
                "userDataXml": null,
                "endpoint": sparse_header_graphql(),
            }),
        ]
    );
}

#[tokio::test]
async fn journald_events_return_every_field() {
    let schema = TestSchema::new();
    let store = schema.db.endpoint_journald_store().unwrap();
    put(&store, BASE, &journald());
    put(&store, BASE + 1, &empty_journald());

    assert_eq!(
        nodes(
            &schema,
            "endpointJournaldEvents",
            &sensor_filter(),
            "time fields { name text bytes }"
        )
        .await,
        vec![
            json!({
                "time": time(BASE),
                "fields": [
                    {"name": "MESSAGE", "text": "Started session", "bytes": null},
                    {"name": "BINARY", "text": null, "bytes": "001fa0ff"},
                ],
                "endpoint": full_header_graphql(),
            }),
            json!({
                "time": time(BASE + 1),
                "fields": null,
                "endpoint": sparse_header_graphql(),
            }),
        ]
    );
}

#[tokio::test]
async fn auditd_events_return_every_field() {
    let schema = TestSchema::new();
    let store = schema.db.endpoint_auditd_store().unwrap();
    put(&store, BASE, &auditd());
    put(&store, BASE + 1, &empty_auditd());

    assert_eq!(
        nodes(
            &schema,
            "endpointAuditdEvents",
            &sensor_filter(),
            "time serial records { recordType fields { name text bytes } }"
        )
        .await,
        vec![
            json!({
                "time": time(BASE),
                "serial": "8731",
                "records": [
                    {
                        "recordType": "SYSCALL",
                        "fields": [{"name": "syscall", "text": "59", "bytes": null}],
                    },
                    {
                        "recordType": "EXECVE",
                        "fields": [
                            {"name": "argc", "text": "1", "bytes": null},
                            {"name": "a0", "text": null, "bytes": "6c73"},
                        ],
                    },
                    {"recordType": "EOE", "fields": []},
                ],
                "endpoint": full_header_graphql(),
            }),
            json!({
                "time": time(BASE + 1),
                "serial": null,
                "records": null,
                "endpoint": sparse_header_graphql(),
            }),
        ]
    );
}

#[tokio::test]
async fn endpoint_log_filter_selects_sensor_and_time() {
    let schema = TestSchema::new();
    let store = schema.db.endpoint_journald_store().unwrap();
    put(&store, BASE, &journald());
    put(&store, BASE + 1_000_000_000, &journald());

    let filter = format!(
        "sensor: \"{SENSOR}\", time: {{ start: \"{}\" }}",
        time(BASE + 1_000_000_000)
    );
    let selected = nodes(&schema, "endpointJournaldEvents", &filter, "time").await;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0]["time"], json!(time(BASE + 1_000_000_000)));

    let other_sensor = nodes(
        &schema,
        "endpointJournaldEvents",
        "sensor: \"other\"",
        "time",
    )
    .await;
    assert_eq!(other_sensor, Vec::<Value>::new());
}

#[tokio::test]
async fn endpoint_log_results_relayed_from_a_peer_carry_every_field() {
    let peer = TestSchema::new();
    let windows = peer.db.endpoint_windows_event_log_store().unwrap();
    put(&windows, BASE, &windows_event_log());
    put(&windows, BASE + 1, &empty_windows_event_log());
    let journald_store = peer.db.endpoint_journald_store().unwrap();
    put(&journald_store, BASE, &journald());
    put(&journald_store, BASE + 1, &empty_journald());
    let auditd_store = peer.db.endpoint_auditd_store().unwrap();
    put(&auditd_store, BASE, &auditd());
    put(&auditd_store, BASE + 1, &empty_auditd());

    for file in [
        "endpoint_windows_event_log_events",
        "endpoint_journald_events",
        "endpoint_auditd_events",
    ] {
        assert_relayed_from_peer(&peer, file).await;
    }
}
