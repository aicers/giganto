//! Tests of the endpoint header on Sysmon records and of the Sysmon kinds
//! endpoints added.

use std::net::SocketAddr;

use async_graphql::{Request, Variables};
use giganto_client::ingest::endpoint::EndpointHeader;
use serde::Serialize;
use serde_json::{Value, json};

use super::fixtures::sensor_timestamp_key;
use crate::{
    datetime::DateTime,
    graphql::{
        endpoint_header::fixtures::{
            HEADER_SELECTION, LOGON_ID_FULL, create_remote_thread, dns_event, driver_load,
            file_create, file_create_stream_hash, file_creation_time_changed, file_delete,
            file_delete_detected, full_header, full_header_graphql, image_loaded,
            network_connection, pipe_event, process_access, process_create, process_tampering,
            process_terminated, raw_access_read, registry_key_value_rename,
            registry_object_add_del, registry_value_set, sparse_header, sparse_header_graphql,
        },
        tests::TestSchema,
    },
    storage::{Database, RawEventStore},
};

const SENSOR: &str = "src 1";
const PEER_SENSOR: &str = "src 2";
/// 2023-11-14T22:15:00Z.
const BASE: i64 = 1_700_000_100_000_000_000;

/// A Sysmon kind: its connection query, the type it returns, and how to store
/// a record of it.
struct Kind {
    query: &'static str,
    type_name: &'static str,
    /// The file under `src/graphql/client/schema/` holding the query a node
    /// sends a peer.
    cluster_query: &'static str,
    store: fn(&Database, i64, Option<EndpointHeader>),
    /// Stores a record in the shape it had before the header was added.
    store_old: fn(&Database, i64),
}

impl Kind {
    fn search_query(&self) -> String {
        let mut chars = self.query.chars();
        let first = chars.next().expect("query names are not empty");
        format!("search{}{}", first.to_ascii_uppercase(), chars.as_str())
    }

    fn is_new(&self) -> bool {
        NEW_TYPES.contains(&self.type_name)
    }
}

const NEW_TYPES: [&str; 5] = [
    "DriverLoadEvent",
    "CreateRemoteThreadEvent",
    "RawAccessReadEvent",
    "ProcessAccessEvent",
    "RegistryObjectAddDelEvent",
];

fn put<T: Serialize>(store: &RawEventStore<'_, T>, timestamp: i64, record: &T) {
    put_bytes(store, timestamp, &bincode::serialize(record).unwrap());
}

fn put_bytes<T>(store: &RawEventStore<'_, T>, timestamp: i64, bytes: &[u8]) {
    store
        .append(&sensor_timestamp_key(SENSOR, timestamp), bytes)
        .unwrap();
}

/// Serializes `record`, whose trailing optional fields are `None`, without
/// those fields, as records stored before they were added are.
fn old_bytes<T: Serialize>(record: &T, trailing_fields: usize) -> Vec<u8> {
    let mut bytes = bincode::serialize(record).unwrap();
    bytes.truncate(bytes.len() - trailing_fields);
    bytes
}

macro_rules! kind {
    ($query:literal, $type_name:literal, $cluster:literal, $store:ident, $make:expr, $trailing:literal) => {
        Kind {
            query: $query,
            type_name: $type_name,
            cluster_query: $cluster,
            store: |db, timestamp, endpoint| {
                put(&db.$store().unwrap(), timestamp, &($make)(endpoint));
            },
            store_old: |db, timestamp| {
                put_bytes(
                    &db.$store().unwrap(),
                    timestamp,
                    &old_bytes(&($make)(None), $trailing),
                );
            },
        }
    };
}

/// Returns every Sysmon kind, new ones interleaved with existing ones.
// One case per kind, listed in full so each expectation reads on its own.
#[allow(clippy::too_many_lines)]
fn kinds() -> Vec<Kind> {
    vec![
        kind!(
            "processCreateEvents",
            "ProcessCreateEvent",
            "process_create_events",
            process_create_store,
            |endpoint| process_create(endpoint, None),
            2
        ),
        kind!(
            "driverLoadEvents",
            "DriverLoadEvent",
            "driver_load_events",
            driver_load_store,
            driver_load,
            1
        ),
        kind!(
            "fileCreateTimeEvents",
            "FileCreationTimeChangedEvent",
            "file_create_time_events",
            file_create_time_store,
            file_creation_time_changed,
            1
        ),
        kind!(
            "createRemoteThreadEvents",
            "CreateRemoteThreadEvent",
            "create_remote_thread_events",
            create_remote_thread_store,
            create_remote_thread,
            1
        ),
        kind!(
            "networkConnectEvents",
            "NetworkConnectionEvent",
            "network_connect_events",
            network_connect_store,
            network_connection,
            1
        ),
        kind!(
            "rawAccessReadEvents",
            "RawAccessReadEvent",
            "raw_access_read_events",
            raw_access_read_store,
            raw_access_read,
            1
        ),
        kind!(
            "processTerminateEvents",
            "ProcessTerminatedEvent",
            "process_terminate_events",
            process_terminate_store,
            process_terminated,
            1
        ),
        kind!(
            "processAccessEvents",
            "ProcessAccessEvent",
            "process_access_events",
            process_access_store,
            process_access,
            1
        ),
        kind!(
            "imageLoadEvents",
            "ImageLoadedEvent",
            "image_load_events",
            image_load_store,
            image_loaded,
            1
        ),
        kind!(
            "registryObjectAddDelEvents",
            "RegistryObjectAddDelEvent",
            "registry_object_add_del_events",
            registry_object_add_del_store,
            registry_object_add_del,
            1
        ),
        kind!(
            "fileCreateEvents",
            "FileCreateEvent",
            "file_create_events",
            file_create_store,
            file_create,
            1
        ),
        kind!(
            "registryValueSetEvents",
            "RegistryValueSetEvent",
            "registry_value_set_events",
            registry_value_set_store,
            registry_value_set,
            1
        ),
        kind!(
            "registryKeyRenameEvents",
            "RegistryKeyValueRenameEvent",
            "registry_key_rename_events",
            registry_key_rename_store,
            registry_key_value_rename,
            1
        ),
        kind!(
            "fileCreateStreamHashEvents",
            "FileCreateStreamHashEvent",
            "file_create_stream_hash_events",
            file_create_stream_hash_store,
            file_create_stream_hash,
            1
        ),
        kind!(
            "pipeEventEvents",
            "PipeEventEvent",
            "pipe_event_events",
            pipe_event_store,
            pipe_event,
            1
        ),
        kind!(
            "dnsQueryEvents",
            "DnsEventEvent",
            "dns_query_events",
            dns_query_store,
            dns_event,
            1
        ),
        kind!(
            "fileDeleteEvents",
            "FileDeleteEvent",
            "file_delete_events",
            file_delete_store,
            file_delete,
            1
        ),
        kind!(
            "processTamperEvents",
            "ProcessTamperingEvent",
            "process_tamper_events",
            process_tamper_store,
            process_tampering,
            1
        ),
        kind!(
            "fileDeleteDetectedEvents",
            "FileDeleteDetectedEvent",
            "file_delete_detected_events",
            file_delete_detected_store,
            file_delete_detected,
            1
        ),
    ]
}

fn time(timestamp: i64) -> String {
    DateTime::from_timestamp_nanos(timestamp).to_rfc3339()
}

async fn execute(schema: &TestSchema, query: &str) -> Value {
    let res = schema.execute(query).await;
    assert!(res.errors.is_empty(), "{query}: {:?}", res.errors);
    res.data.into_json().unwrap()
}

fn connection_query(query: &str, selection: &str) -> String {
    format!(
        "{{ {query}(filter: {{ sensor: \"{SENSOR}\" }}, first: 50) \
         {{ edges {{ node {{ {selection} }} }} }} }}"
    )
}

fn nodes(data: &Value, query: &str) -> Vec<Value> {
    data[query]["edges"]
        .as_array()
        .expect("edges is a list")
        .iter()
        .map(|edge| edge["node"].clone())
        .collect()
}

#[tokio::test]
async fn every_sysmon_kind_returns_its_endpoint_header() {
    for kind in kinds() {
        let schema = TestSchema::new();
        (kind.store)(&schema.db, BASE, Some(full_header()));
        (kind.store)(&schema.db, BASE + 1, Some(sparse_header()));
        (kind.store)(&schema.db, BASE + 2, None);

        let query = connection_query(kind.query, &format!("time {HEADER_SELECTION}"));
        let data = execute(&schema, &query).await;
        assert_eq!(
            nodes(&data, kind.query),
            vec![
                json!({"time": time(BASE), "endpoint": full_header_graphql()}),
                json!({"time": time(BASE + 1), "endpoint": sparse_header_graphql()}),
                json!({"time": time(BASE + 2), "endpoint": null}),
            ],
            "{}",
            kind.query
        );
    }
}

#[tokio::test]
async fn process_create_returns_logon_id_full() {
    let schema = TestSchema::new();
    let store = schema.db.process_create_store().unwrap();
    put(
        &store,
        BASE,
        &process_create(Some(full_header()), Some(LOGON_ID_FULL)),
    );
    put(&store, BASE + 1, &process_create(None, None));

    let query = connection_query("processCreateEvents", "logonId logonIdFull");
    let data = execute(&schema, &query).await;
    assert_eq!(
        nodes(&data, "processCreateEvents"),
        vec![
            json!({"logonId": "7", "logonIdFull": LOGON_ID_FULL.to_string()}),
            json!({"logonId": "7", "logonIdFull": null}),
        ]
    );
}

fn sysmon_events_query(arguments: &str) -> String {
    let fragments = kinds()
        .iter()
        .map(|kind| format!("... on {} {{ time {HEADER_SELECTION} }}", kind.type_name))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{{ sysmonEvents(filter: {{ sensor: \"{SENSOR}\" }}, {arguments}) \
         {{ edges {{ node {{ __typename {fragments} }} }} }} }}"
    )
}

#[tokio::test]
async fn sysmon_events_returns_every_kind_in_time_order_with_headers() {
    let schema = TestSchema::new();
    let mut expected = Vec::new();
    for (index, kind) in (0_i64..).zip(kinds()) {
        let with_header = BASE + index * 2_000;
        let without_header = with_header + 1_000;
        (kind.store)(&schema.db, with_header, Some(full_header()));
        (kind.store)(&schema.db, without_header, None);
        expected.push(json!({
            "__typename": kind.type_name,
            "time": time(with_header),
            "endpoint": full_header_graphql(),
        }));
        expected.push(json!({
            "__typename": kind.type_name,
            "time": time(without_header),
            "endpoint": null,
        }));
    }

    let data = execute(&schema, &sysmon_events_query("first: 50")).await;
    assert_eq!(nodes(&data, "sysmonEvents"), expected);

    let data = execute(&schema, &sysmon_events_query("last: 3")).await;
    assert_eq!(
        nodes(&data, "sysmonEvents"),
        expected[expected.len() - 3..].to_vec()
    );
}

// One case per kind, listed in full so each expectation reads on its own.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn new_sysmon_kinds_return_every_field() {
    let schema = TestSchema::new();
    put(
        &schema.db.driver_load_store().unwrap(),
        BASE,
        &driver_load(Some(full_header())),
    );
    put(
        &schema.db.create_remote_thread_store().unwrap(),
        BASE,
        &create_remote_thread(Some(full_header())),
    );
    put(
        &schema.db.raw_access_read_store().unwrap(),
        BASE,
        &raw_access_read(Some(full_header())),
    );
    put(
        &schema.db.process_access_store().unwrap(),
        BASE,
        &process_access(Some(full_header())),
    );
    put(
        &schema.db.registry_object_add_del_store().unwrap(),
        BASE,
        &registry_object_add_del(Some(full_header())),
    );

    let cases = [
        (
            "driverLoadEvents",
            "time agentName agentId imageLoaded hashes signed signature signatureStatus",
            json!({
                "time": time(BASE),
                "agentName": "agent_name",
                "agentId": "agent_id",
                "imageLoaded": "image_loaded",
                "hashes": ["hashes"],
                "signed": true,
                "signature": "signature",
                "signatureStatus": "signature_status",
                "endpoint": full_header_graphql(),
            }),
        ),
        (
            "createRemoteThreadEvents",
            "time agentName agentId sourceProcessGuid sourceProcessId sourceImage \
             targetProcessGuid targetProcessId targetImage newThreadId startAddress \
             startModule startFunction sourceUser targetUser",
            json!({
                "time": time(BASE),
                "agentName": "agent_name",
                "agentId": "agent_id",
                "sourceProcessGuid": "source_process_guid",
                "sourceProcessId": "7",
                "sourceImage": "source_image",
                "targetProcessGuid": "target_process_guid",
                "targetProcessId": "7",
                "targetImage": "target_image",
                "newThreadId": "7",
                "startAddress": "start_address",
                "startModule": "start_module",
                "startFunction": "start_function",
                "sourceUser": "source_user",
                "targetUser": "target_user",
                "endpoint": full_header_graphql(),
            }),
        ),
        (
            "rawAccessReadEvents",
            "time agentName agentId processGuid processId image device user",
            json!({
                "time": time(BASE),
                "agentName": "agent_name",
                "agentId": "agent_id",
                "processGuid": "process_guid",
                "processId": "7",
                "image": "image",
                "device": "device",
                "user": "user",
                "endpoint": full_header_graphql(),
            }),
        ),
        (
            "processAccessEvents",
            "time agentName agentId sourceProcessGuid sourceProcessId sourceThreadId \
             sourceImage targetProcessGuid targetProcessId targetImage grantedAccess \
             callTrace sourceUser targetUser",
            json!({
                "time": time(BASE),
                "agentName": "agent_name",
                "agentId": "agent_id",
                "sourceProcessGuid": "source_process_guid",
                "sourceProcessId": "7",
                "sourceThreadId": "7",
                "sourceImage": "source_image",
                "targetProcessGuid": "target_process_guid",
                "targetProcessId": "7",
                "targetImage": "target_image",
                "grantedAccess": "4294967297",
                "callTrace": "call_trace",
                "sourceUser": "source_user",
                "targetUser": "target_user",
                "endpoint": full_header_graphql(),
            }),
        ),
        (
            "registryObjectAddDelEvents",
            "time agentName agentId eventType processGuid processId image targetObject user",
            json!({
                "time": time(BASE),
                "agentName": "agent_name",
                "agentId": "agent_id",
                "eventType": "event_type",
                "processGuid": "process_guid",
                "processId": "7",
                "image": "image",
                "targetObject": "target_object",
                "user": "user",
                "endpoint": full_header_graphql(),
            }),
        ),
    ];
    for (query, selection, expected) in cases {
        let data = execute(
            &schema,
            &connection_query(query, &format!("{selection} {HEADER_SELECTION}")),
        )
        .await;
        assert_eq!(nodes(&data, query), vec![expected], "{query}");

        // The agent ID filter applies to the new kinds as to the others.
        let filtered = format!(
            "{{ {query}(filter: {{ sensor: \"{SENSOR}\", agentId: \"other\" }}, first: 10) \
             {{ edges {{ node {{ time }} }} }} }}"
        );
        let data = execute(&schema, &filtered).await;
        assert_eq!(nodes(&data, query), Vec::<Value>::new(), "{query}");
    }
}

fn search_query(kind: &Kind, timestamps: &[i64]) -> String {
    let times = timestamps
        .iter()
        .map(|timestamp| format!("\"{}\"", time(*timestamp)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{ {}(filter: {{ sensor: \"{SENSOR}\", times: [{times}] }}) }}",
        kind.search_query()
    )
}

#[tokio::test]
async fn new_sysmon_search_queries_find_stored_times() {
    for kind in kinds().into_iter().filter(Kind::is_new) {
        let schema = TestSchema::new();
        (kind.store)(&schema.db, BASE, Some(full_header()));
        (kind.store)(&schema.db, BASE + 2_000, None);

        let data = execute(
            &schema,
            &search_query(&kind, &[BASE, BASE + 1_000, BASE + 2_000]),
        )
        .await;
        assert_eq!(
            data[kind.search_query()],
            json!([time(BASE), time(BASE + 2_000)]),
            "{}",
            kind.search_query()
        );
    }
}

/// A record stored in the shape a Sysmon kind had before the header was added
/// fails to deserialize, and each query handles it as it handled such a record
/// before: no made-up values and no error.
#[tokio::test]
async fn old_shape_sysmon_records_are_never_presented() {
    let driver_load_time = BASE + 3_000;
    for kind in kinds().into_iter().filter(|kind| !kind.is_new()) {
        let schema = TestSchema::new();
        (kind.store)(&schema.db, BASE, Some(full_header()));
        (kind.store_old)(&schema.db, BASE + 1_000);
        (kind.store)(&schema.db, BASE + 2_000, None);
        put(
            &schema.db.driver_load_store().unwrap(),
            driver_load_time,
            &driver_load(None),
        );

        // The connection query skips it and returns the records around it.
        let data = execute(&schema, &connection_query(kind.query, "time")).await;
        assert_eq!(
            nodes(&data, kind.query),
            vec![
                json!({"time": time(BASE)}),
                json!({"time": time(BASE + 2_000)}),
            ],
            "{}",
            kind.query
        );

        // Search does not return its time.
        let data = execute(
            &schema,
            &search_query(&kind, &[BASE, BASE + 1_000, BASE + 2_000]),
        )
        .await;
        assert_eq!(
            data[kind.search_query()],
            json!([time(BASE), time(BASE + 2_000)]),
            "{}",
            kind.search_query()
        );

        // `sysmonEvents` ends that kind's records at it, as before, and
        // continues with the other kinds.
        let query = format!(
            "{{ sysmonEvents(filter: {{ sensor: \"{SENSOR}\" }}, first: 10) \
             {{ edges {{ node {{ __typename ... on {} {{ time }} \
             ... on DriverLoadEvent {{ time }} }} }} }} }}",
            kind.type_name
        );
        let data = execute(&schema, &query).await;
        assert_eq!(
            nodes(&data, "sysmonEvents"),
            vec![
                json!({"__typename": kind.type_name, "time": time(BASE)}),
                json!({"__typename": "DriverLoadEvent", "time": time(driver_load_time)}),
            ],
            "{}",
            kind.type_name
        );
    }
}

/// Executes the query a node sends a peer, from its file under
/// `src/graphql/client/schema/`, against `schema` for `sensor`.
async fn execute_cluster_query(schema: &TestSchema, file: &str, sensor: &str) -> Value {
    let path = format!("src/graphql/client/schema/{file}.graphql");
    let query = std::fs::read_to_string(&path).unwrap();
    let request = Request::new(query).variables(Variables::from_json(json!({
        "filter": { "sensor": sensor },
        "first": 50,
    })));
    let res = schema.schema.execute(request).await;
    assert!(res.errors.is_empty(), "{file}: {:?}", res.errors);
    res.data.into_json().unwrap()
}

/// Asserts that a node relaying `file`'s query to a peer returns what the
/// peer returned for its locally stored records.
pub(crate) async fn assert_relayed_from_peer(local: &TestSchema, file: &str) {
    let peer_data = execute_cluster_query(local, file, SENSOR).await;
    let query_name = peer_data
        .as_object()
        .and_then(|data| data.keys().next())
        .expect("one query")
        .clone();
    assert!(
        !nodes(&peer_data, &query_name).is_empty(),
        "{file} returns stored records"
    );

    let mut peer_server = mockito::Server::new_async().await;
    let mock = peer_server
        .mock("POST", "/graphql")
        .with_status(200)
        .with_body(json!({ "data": peer_data }).to_string())
        .create();
    let peer_port = peer_server
        .host_with_port()
        .parse::<SocketAddr>()
        .expect("Port must exist")
        .port();
    let cluster = TestSchema::new_with_graphql_peer(peer_port);

    let relayed = execute_cluster_query(&cluster, file, PEER_SENSOR).await;
    assert_eq!(
        nodes(&relayed, &query_name),
        nodes(&peer_data, &query_name),
        "{file}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn results_relayed_from_a_peer_carry_headers_and_new_fields() {
    for kind in kinds() {
        let peer = TestSchema::new();
        (kind.store)(&peer.db, BASE, Some(full_header()));
        (kind.store)(&peer.db, BASE + 1, Some(sparse_header()));
        (kind.store)(&peer.db, BASE + 2, None);
        if kind.type_name == "ProcessCreateEvent" {
            put(
                &peer.db.process_create_store().unwrap(),
                BASE + 3,
                &process_create(Some(full_header()), Some(LOGON_ID_FULL)),
            );
        }
        assert_relayed_from_peer(&peer, kind.cluster_query).await;
    }

    let peer = TestSchema::new();
    for (index, kind) in (0_i64..).zip(kinds()) {
        (kind.store)(&peer.db, BASE + index * 2, Some(full_header()));
        (kind.store)(&peer.db, BASE + index * 2 + 1, None);
    }
    assert_relayed_from_peer(&peer, "sysmon_events").await;
}
