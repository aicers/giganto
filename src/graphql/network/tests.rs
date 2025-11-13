use std::{
    collections::HashMap,
    mem,
    net::{IpAddr, SocketAddr},
};

use async_graphql::{Request, Variables};
use chrono::{DateTime, TimeZone, Utc};
use giganto_client::ingest::network::{
    Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, FtpCommand, Http, Kerberos, Ldap, MalformedDns, Mqtt, Nfs,
    Ntlm, Radius, Rdp, Smb, Smtp, Ssh, Tls,
};
use mockito;
use serde::Serialize;
use serde_json::{Value, json};

use crate::bincode_utils::encode_legacy;
use crate::graphql::tests::TestSchema;
use crate::storage::RawEventStore;

const SENSOR: &str = "src 1";

fn timestamp_ns(timestamp: DateTime<Utc>) -> i64 {
    timestamp.timestamp_nanos_opt().unwrap()
}

fn build_key(sensor: &str, timestamp: i64) -> Vec<u8> {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());
    key
}

fn append_event<T: Serialize>(
    store: &RawEventStore<'_, T>,
    sensor: &str,
    timestamp: i64,
    event: &T,
) -> Vec<u8> {
    let key = build_key(sensor, timestamp);
    let serialized = encode_legacy(event).unwrap();
    store.append(&key, &serialized).unwrap();
    key
}

#[tokio::test]
async fn conn_empty() {
    let schema = TestSchema::new();
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                sensor: "ingest_sensor_1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 50, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{connRawEvents: {edges: []}}");
}

#[tokio::test]
async fn conn_empty_giganto_cluster() {
    // given
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                sensor: "ingest src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 50, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "connRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": false,
                    "hasNextPage": false
                },
                "edges": [
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(res.data.to_string(), "{connRawEvents: {edges: []}}");

    mock.assert_async().await;
}

#[tokio::test]
async fn conn_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.conn_store().unwrap();

    insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                    startTime,
                    endTime,
                    origBytes,
                    respBytes,
                    origPkts,
                    respPkts,
                    origL2Bytes,
                    respL2Bytes,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"192.168.4.76\", \
         origPort: 46378, startTime: \"2023-01-20T00:00:00+00:00\", \
         endTime: \"2023-01-20T00:00:00+00:00\", origBytes: \"77\", respBytes: \"295\", origPkts: \
         \"397\", respPkts: \"511\", origL2Bytes: \"21515\", respL2Bytes: \"27889\"}}]}}"
    );
}

pub(crate) fn insert_conn_raw_event(store: &RawEventStore<Conn>, sensor: &str, timestamp: i64) {
    let conn_body = sample_conn_event();
    let _ = append_event(store, sensor, timestamp, &conn_body);
}

fn create_conn_body(
    orig_addr: Option<IpAddr>,
    orig_port: Option<u16>,
    resp_addr: Option<IpAddr>,
    resp_port: Option<u16>,
) -> Conn {
    let time = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 0).unwrap();
    Conn {
        orig_addr: orig_addr.unwrap_or("192.168.4.76".parse::<IpAddr>().unwrap()),
        orig_port: orig_port.unwrap_or(46378),
        resp_addr: resp_addr.unwrap_or("192.168.4.76".parse::<IpAddr>().unwrap()),
        resp_port: resp_port.unwrap_or(80),
        proto: 6,
        conn_state: "sf".to_string(),
        start_time: time,
        end_time: time,
        duration: 1_000_000_000,
        service: "-".to_string(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
        orig_l2_bytes: 21515,
        resp_l2_bytes: 27889,
    }
}

fn sample_conn_event() -> Conn {
    create_conn_body(None, None, None, None)
}

#[tokio::test]
async fn conn_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "ingest src 2"
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                    startTime,
                    endTime,
                    origBytes,
                    respBytes,
                    origPkts,
                    respPkts,
                    origL2Bytes,
                    respL2Bytes,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "connRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 46378,
                            "respPort": 443,
                            "proto": 6,
                            "connState": "-",
                            "service": "-",
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origBytes": "0",
                            "respBytes": "0",
                            "origPkts": "6",
                            "respPkts": "0",
                            "origL2Bytes": "0",
                            "respL2Bytes": "0"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"192.168.4.76\", \
         origPort: 46378, startTime: \"2023-11-16T15:03:45.291779203+00:00\", \
         endTime: \"2023-11-16T15:03:45.291779203+00:00\", origBytes: \"0\", respBytes: \"0\", \
         origPkts: \"6\", respPkts: \"0\", origL2Bytes: \"0\", respL2Bytes: \"0\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn dns_empty() {
    let schema = TestSchema::new();
    let query = r#"
    {
        dnsRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                sensor: "cluml"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.123", end: "31.3.245.143" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 100, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
            pageInfo {
                hasPreviousPage
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{dnsRawEvents: {edges: [], pageInfo: {hasPreviousPage: false}}}"
    );
}

#[tokio::test]
async fn dns_empty_giganto_cluster() {
    // given
    let query = r#"
    {
        dnsRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.123", end: "31.3.245.143" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 100, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
            pageInfo {
                hasPreviousPage
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "dnsRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": false,
                    "hasNextPage": false
                },
                "edges": [
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{dnsRawEvents: {edges: [], pageInfo: {hasPreviousPage: false}}}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn dns_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.dns_store().unwrap();

    insert_dns_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        dnsRawEvents(
            filter: {
                sensor: "src 1"
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            last: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                    rtt,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{dnsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"31.3.245.133\", \
        origPort: 46378, rtt: \"1\"}}]}}"
    );
}

fn sample_dns_event() -> Dns {
    let start_time = Utc.with_ymd_and_hms(2021, 1, 1, 0, 0, 0).unwrap();
    let end_time = start_time + chrono::Duration::seconds(1);
    Dns {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time,
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        query: "Hello Server Hello Server Hello Server".to_string(),
        answer: vec!["1.1.1.1".to_string()],
        trans_id: 1,
        rtt: 1,
        qclass: 0,
        qtype: 0,
        rcode: 0,
        aa_flag: false,
        tc_flag: false,
        rd_flag: false,
        ra_flag: false,
        ttl: vec![1; 5],
    }
}

pub(crate) fn insert_dns_raw_event(store: &RawEventStore<Dns>, sensor: &str, timestamp: i64) {
    let dns_body = sample_dns_event();
    let _ = append_event(store, sensor, timestamp, &dns_body);
}

fn sample_malformed_dns_event() -> MalformedDns {
    let start_time = Utc.with_ymd_and_hms(2021, 1, 1, 0, 0, 0).unwrap();
    let end_time = start_time + chrono::Duration::seconds(1);
    MalformedDns {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time,
        duration: 1,
        orig_pkts: 1,
        resp_pkts: 2,
        orig_l2_bytes: 32,
        resp_l2_bytes: 64,
        trans_id: 1,
        flags: 42,
        question_count: 1,
        answer_count: 2,
        authority_count: 3,
        additional_count: 4,
        query_count: 5,
        resp_count: 6,
        query_bytes: 32,
        resp_bytes: 64,
        query_body: vec![vec![113]],
        resp_body: vec![vec![114]],
    }
}

fn insert_malformed_dns_raw_event(
    store: &RawEventStore<MalformedDns>,
    sensor: &str,
    timestamp: i64,
) {
    let malformed_dns_body = sample_malformed_dns_event();
    let _ = append_event(store, sensor, timestamp, &malformed_dns_body);
}

#[tokio::test]
async fn dns_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        dnsRawEvents(
            filter: {
                sensor: "src 2"
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            last: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                    rtt,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "dnsRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "31.3.245.133",
                            "origPort": 46378,
                            "respPort": 443,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "proto": 6,
                            "query": "example.com",
                            "answer": [
                                "192.168.1.1"
                            ],
                            "transId": 12345,
                            "rtt": "567",
                            "qclass": 1,
                            "qtype": 1,
                            "rcode": 0,
                            "aaFlag": true,
                            "tcFlag": false,
                            "rdFlag": true,
                            "raFlag": false,
                            "ttl": [
                                3600,
                                1800,
                                900
                            ]
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{dnsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"31.3.245.133\", \
        origPort: 46378, rtt: \"567\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn malformed_dns_empty() {
    let schema = TestSchema::new();
    let query = r#"
    {
        malformedDnsRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                sensor: "ingest_sensor_1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.123", end: "31.3.245.143" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 100, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{malformedDnsRawEvents: {edges: []}}");
}

#[tokio::test]
async fn malformed_dns_empty_giganto_cluster() {
    // given
    let query = r#"
    {
        malformedDnsRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.123", end: "31.3.245.143" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 100, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "malformedDnsRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": false,
                    "hasNextPage": false
                },
                "edges": [
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(res.data.to_string(), "{malformedDnsRawEvents: {edges: []}}");

    mock.assert_async().await;
}

#[tokio::test]
async fn malformed_dns_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.malformed_dns_store().unwrap();

    insert_malformed_dns_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_malformed_dns_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        malformedDnsRawEvents(
            filter: {
                sensor: "src 1"
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            last: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    questionCount,
                    queryCount,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{malformedDnsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"31.3.245.133\", questionCount: 1, queryCount: \"5\"}}]}}"
    );
}

#[tokio::test]
async fn malformed_dns_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        malformedDnsRawEvents(
            filter: {
                sensor: "src 2"
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            last: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    questionCount,
                    queryCount,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "malformedDnsRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "bWFsZm9ybWVkRG5zQ3Vyc29y",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "31.3.245.133",
                            "origPort": 46378,
                            "respPort": 80,
                            "proto": 17,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:46.291779203+00:00",
                            "duration": "1",
                            "origPkts": "1",
                            "respPkts": "2",
                            "origL2Bytes": "32",
                            "respL2Bytes": "64",
                            "transId": 1,
                            "flags": 42,
                            "questionCount": 1,
                            "answerCount": 2,
                            "authorityCount": 3,
                            "additionalCount": 4,
                            "queryCount": "5",
                            "respCount": "6",
                            "queryBytes": "32",
                            "respBytes": "64",
                            "queryBody": [[113]],
                            "respBody": [[114]]
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{malformedDnsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"31.3.245.133\", questionCount: 1, queryCount: \"5\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn http_empty() {
    let schema = TestSchema::new();
    let query = r#"
    {
        httpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2024-09-22T00:00:00Z" }
                sensor: "cluml"
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{httpRawEvents: {edges: []}}");
}

#[tokio::test]
async fn http_empty_giganto_cluster() {
    // given
    let query = r#"
{
    httpRawEvents(
        filter: {
            time: { start: "1992-06-05T00:00:00Z", end: "2024-09-22T00:00:00Z" }
            sensor: "src 2"
            respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
            origPort: { start: 46377, end: 46380 }
            respPort: { start: 0, end: 200 }
        }
        first: 1
    ) {
        edges {
            node {
                origAddr,
                respAddr,
                origPort,
            }
        }
    }
}"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
{
    "data": {
        "httpRawEvents": {
            "pageInfo": {
                "hasPreviousPage": false,
                "hasNextPage": false
            },
            "edges": [
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(res.data.to_string(), "{httpRawEvents: {edges: []}}");

    mock.assert_async().await;
}

#[tokio::test]
async fn http_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.http_store().unwrap();

    insert_http_raw_event(
        &store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 6, 1, 0, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_http_raw_event(
        &store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 6, 1, 0, 1, 2)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );

    let query = r#"
    {
        httpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2030-09-22T00:00:00Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                    requestLen,
                    responseLen,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{httpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"192.168.4.76\", \
         origPort: 46378, requestLen: \"0\", responseLen: \"0\"}}]}}"
    );
}

fn sample_http_event() -> Http {
    let time = Utc.with_ymd_and_hms(1992, 6, 5, 12, 0, 0).unwrap();
    Http {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        method: "POST".to_string(),
        host: "cluml".to_string(),
        uri: "/cluml.gif".to_string(),
        referer: "cluml.com".to_string(),
        version: String::new(),
        user_agent: "giganto".to_string(),
        request_len: 0,
        response_len: 0,
        status_code: 200,
        status_msg: String::new(),
        username: String::new(),
        password: String::new(),
        cookie: String::new(),
        content_encoding: String::new(),
        content_type: String::new(),
        cache_control: String::new(),
        filenames: Vec::new(),
        mime_types: Vec::new(),
        body: Vec::new(),
        state: String::new(),
    }
}

pub(crate) fn insert_http_raw_event(store: &RawEventStore<Http>, sensor: &str, timestamp: i64) {
    let http_body = sample_http_event();
    let _ = append_event(store, sensor, timestamp, &http_body);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn http_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        httpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                    requestLen,
                    responseLen,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "httpRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {

                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 46378,
                            "respPort": 443,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "method": "GET",
                            "host": "example.com",
                            "uri": "/path/to/resource",
                            "referer": "http://referrer.com",
                            "version": "HTTP/1.1",
                            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                            "requestLen": "1024",
                            "responseLen": "2048",
                            "statusCode": 200,
                            "statusMsg": "OK",
                            "username": "user123",
                            "password": "pass456",
                            "cookie": "session=abc123",
                            "contentEncoding": "gzip",
                            "contentType": "text/html",
                            "cacheControl": "no-cache",
                            "filenames": [
                                "file1.txt",
                                "file2.txt",
                                "response1.txt",
                                "response2.txt"
                            ],
                            "mimeTypes": [
                                "text/plain",
                                "text/plain"
                            ],
                            "body": [
                                200,
                                300
                            ],
                            "state": "OK"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{httpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"192.168.4.76\", \
         origPort: 46378, requestLen: \"1024\", responseLen: \"2048\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn rdp_empty() {
    let schema = TestSchema::new();
    let query = r#"
    {
        rdpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                sensor: "cluml"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respPort: { start: 0, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{rdpRawEvents: {edges: []}}");
}

#[tokio::test]
async fn rdp_empty_giganto_cluster() {
    // given
    let query = r#"
    {
        rdpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                sensor: "ingest src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respPort: { start: 0, end: 200 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "rdpRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": false,
                    "hasNextPage": false
                },
                "edges": [
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(res.data.to_string(), "{rdpRawEvents: {edges: []}}");

    mock.assert_async().await;
}

#[tokio::test]
async fn rdp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.rdp_store().unwrap();

    insert_rdp_raw_event(
        &store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 6, 1, 0, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_rdp_raw_event(
        &store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 6, 1, 0, 1, 2)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );

    let query = r#"
    {
        rdpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2030-09-22T00:00:00Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
        first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{rdpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"192.168.4.76\", origPort: 46378}}]}}"
    );
}

fn sample_rdp_event() -> Rdp {
    let time = Utc.with_ymd_and_hms(1992, 6, 5, 12, 0, 0).unwrap();
    Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        cookie: "rdp_test".to_string(),
    }
}

fn insert_rdp_raw_event(store: &RawEventStore<Rdp>, sensor: &str, timestamp: i64) {
    let rdp_body = sample_rdp_event();
    let _ = append_event(store, sensor, timestamp, &rdp_body);
}

#[tokio::test]
async fn rdp_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        rdpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
        first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "rdpRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 46378,
                            "respPort": 54321,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "cookie": "session=xyz789"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{rdpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", respAddr: \"192.168.4.76\", origPort: 46378}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn smtp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.smtp_store().unwrap();

    insert_smtp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        smtpRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{smtpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn sample_smtp_event() -> Smtp {
    let start_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    Smtp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        mailfrom: "mailfrom".to_string(),
        date: "date".to_string(),
        from: "from".to_string(),
        to: "to".to_string(),
        subject: "subject".to_string(),
        agent: "agent".to_string(),
        state: String::new(),
    }
}

fn insert_smtp_raw_event(store: &RawEventStore<Smtp>, sensor: &str, timestamp: i64) {
    let smtp_body = sample_smtp_event();
    let _ = append_event(store, sensor, timestamp, &smtp_body);
}

#[tokio::test]
async fn smtp_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        smtpRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "smtpRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 25,
                            "respPort": 587,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "mailfrom": "sender@example.com",
                            "date": "2023-11-16T15:03:45+00:00",
                            "from": "sender@example.com",
                            "to": "recipient@example.com",
                            "subject": "Test Email",
                            "agent": "SMTP Client 1.0",
                            "state": "OK"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{smtpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn ntlm_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ntlm_store().unwrap();

    insert_ntlm_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        ntlmRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{ntlmRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn sample_ntlm_event() -> Ntlm {
    let start_time = Utc.with_ymd_and_hms(2022, 1, 5, 0, 1, 1).unwrap();
    Ntlm {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        username: "bly".to_string(),
        hostname: "host".to_string(),
        domainname: "domain".to_string(),
        success: "tf".to_string(),
        protocol: "protocol".to_string(),
    }
}

fn insert_ntlm_raw_event(store: &RawEventStore<Ntlm>, sensor: &str, timestamp: i64) {
    let ntlm_body = sample_ntlm_event();
    let _ = append_event(store, sensor, timestamp, &ntlm_body);
}

#[tokio::test]
async fn ntlm_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        ntlmRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "ntlmRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.1.200",
                            "origPort": 12345,
                            "respPort": 6789,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "username": "john_doe",
                            "hostname": "client_machine",
                            "domainname": "example.com",
                            "success": "true",
                            "protocol": "6"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{ntlmRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn kerberos_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.kerberos_store().unwrap();

    insert_kerberos_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        kerberosRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{kerberosRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn sample_kerberos_event() -> Kerberos {
    let start_time = Utc.with_ymd_and_hms(2023, 1, 5, 0, 1, 1).unwrap();
    Kerberos {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        client_time: 1,
        server_time: 1,
        error_code: 1,
        client_realm: "client_realm".to_string(),
        cname_type: 1,
        client_name: vec!["client_name".to_string()],
        realm: "realm".to_string(),
        sname_type: 1,
        service_name: vec!["service_name".to_string()],
    }
}

fn insert_kerberos_raw_event(store: &RawEventStore<Kerberos>, sensor: &str, timestamp: i64) {
    let kerberos_body = sample_kerberos_event();
    let _ = append_event(store, sensor, timestamp, &kerberos_body);
}

#[tokio::test]
async fn kerberos_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        kerberosRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    clientTime,
                    serverTime,
                    errorCode,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "kerberosRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.1.200",
                            "origPort": 12345,
                            "respPort": 6789,
                            "proto": 17,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "clientTime": "123456789",
                            "serverTime": "987654321",
                            "errorCode": "0",
                            "clientRealm": "client_realm",
                            "cnameType": 1,
                            "clientName": [
                                "john_doe"
                            ],
                            "realm": "example.com",
                            "snameType": 2,
                            "serviceName": [
                                "service_name_1",
                                "service_name_2"
                            ]
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{kerberosRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", clientTime: \
        \"123456789\", serverTime: \"987654321\", errorCode: \"0\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn ssh_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ssh_store().unwrap();

    insert_ssh_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        sshRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{sshRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn sample_ssh_event() -> Ssh {
    let start_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap();
    Ssh {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        client: "client".to_string(),
        server: "server".to_string(),
        cipher_alg: "cipher_alg".to_string(),
        mac_alg: "mac_alg".to_string(),
        compression_alg: "compression_alg".to_string(),
        kex_alg: "kex_alg".to_string(),
        host_key_alg: "host_key_alg".to_string(),
        hassh_algorithms: "hassh_algorithms".to_string(),
        hassh: "hassh".to_string(),
        hassh_server_algorithms: "hassh_server_algorithms".to_string(),
        hassh_server: "hassh_server".to_string(),
        client_shka: "client_shka".to_string(),
        server_shka: "server_shka".to_string(),
    }
}

fn insert_ssh_raw_event(store: &RawEventStore<Ssh>, sensor: &str, timestamp: i64) {
    let ssh_body = sample_ssh_event();
    let _ = append_event(store, sensor, timestamp, &ssh_body);
}

#[tokio::test]
async fn ssh_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        sshRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "sshRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 22,
                            "respPort": 54321,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "client": "ssh_client",
                            "server": "ssh_server",
                            "cipherAlg": "aes256-ctr",
                            "macAlg": "hmac-sha2-256",
                            "compressionAlg": "none",
                            "kexAlg": "diffie-hellman-group14-sha1",
                            "hostKeyAlg": "ssh-rsa",
                            "hasshAlgorithms": "hassh_algorithms",
                            "hassh": "hassh",
                            "hasshServerAlgorithms": "hassh_server_algorithms",
                            "hasshServer": "hassh_server",
                            "clientShka": "client_shka",
                            "serverShka": "server_shka"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{sshRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn dce_rpc_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.dce_rpc_store().unwrap();

    insert_dce_rpc_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        dceRpcRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{dceRpcRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn insert_dce_rpc_raw_event(store: &RawEventStore<DceRpc>, sensor: &str, timestamp: i64) {
    let dce_rpc_body = sample_dce_rpc_event();
    let _ = append_event(store, sensor, timestamp, &dce_rpc_body);
}

fn sample_dce_rpc_event() -> DceRpc {
    let start_time = Utc.with_ymd_and_hms(2020, 1, 5, 6, 5, 0).unwrap();
    DceRpc {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        rtt: 3,
        named_pipe: "named_pipe".to_string(),
        endpoint: "endpoint".to_string(),
        operation: "operation".to_string(),
    }
}

#[tokio::test]
async fn dce_rpc_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        dceRpcRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    rtt,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "dceRpcRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 135,
                            "respPort": 54321,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "rtt": "123456",
                            "namedPipe": "example_pipe",
                            "endpoint": "rpc_endpoint",
                            "operation": "rpc_operation"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{dceRpcRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", rtt: \"123456\"}}]}}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn ftp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ftp_store().unwrap();

    insert_ftp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        ftpRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{ftpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn sample_ftp_event() -> Ftp {
    let start_time = Utc.with_ymd_and_hms(2023, 1, 5, 12, 12, 0).unwrap();
    Ftp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        user: "cluml".to_string(),
        password: "aice".to_string(),
        commands: vec![FtpCommand {
            command: "command".to_string(),
            reply_code: "500".to_string(),
            reply_msg: "reply_message".to_string(),
            data_passive: false,
            data_orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            data_resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            data_resp_port: 80,
            file: "ftp_file".to_string(),
            file_size: 100,
            file_id: "1".to_string(),
        }],
    }
}

fn insert_ftp_raw_event(store: &RawEventStore<Ftp>, sensor: &str, timestamp: i64) {
    let ftp_body = sample_ftp_event();
    let _ = append_event(store, sensor, timestamp, &ftp_body);
}

#[tokio::test]
async fn ftp_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        ftpRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    commands {
                        fileSize,
                    }
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "ftpRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 21,
                            "respPort": 12345,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "user": "example_user",
                            "password": "example_password",
                            "commands": [
                                {
                                    "command": "example_command",
                                    "replyCode": "200",
                                    "replyMsg": "Command OK",
                                    "dataPassive": true,
                                    "dataOrigAddr": "192.168.4.76",
                                    "dataRespAddr": "192.168.4.76",
                                    "dataRespPort": 54321,
                                    "file": "example_file.txt",
                                    "fileSize": "1024",
                                    "fileId": "123456789"
                                }
                            ]
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{ftpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", commands: [{fileSize: \"1024\"}]}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn mqtt_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.mqtt_store().unwrap();

    insert_mqtt_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        mqttRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{mqttRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn sample_mqtt_event() -> Mqtt {
    let start_time = Utc.with_ymd_and_hms(2023, 1, 5, 12, 12, 0).unwrap();
    Mqtt {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        protocol: "protocol".to_string(),
        version: 1,
        client_id: "1".to_string(),
        connack_reason: 1,
        subscribe: vec!["subscribe".to_string()],
        suback_reason: vec![1],
    }
}

fn insert_mqtt_raw_event(store: &RawEventStore<Mqtt>, sensor: &str, timestamp: i64) {
    let mqtt_body = sample_mqtt_event();
    let _ = append_event(store, sensor, timestamp, &mqtt_body);
}

#[tokio::test]
async fn mqtt_with_data_giganto_cluster() {
    // given

    let query = r#"
    {
        mqttRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "mqttRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 1883,
                            "respPort": 5678,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "protocol": "MQTT",
                            "version": 4,
                            "clientId": "example_client_id",
                            "connackReason": 0,
                            "subscribe": [
                                "topic/example"
                            ],
                            "subackReason": [
                                0
                            ]
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{mqttRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn ldap_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ldap_store().unwrap();

    insert_ldap_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        ldapRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{ldapRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn sample_ldap_event() -> Ldap {
    let start_time = Utc.with_ymd_and_hms(2023, 1, 6, 12, 12, 0).unwrap();
    Ldap {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        message_id: 1,
        version: 1,
        opcode: vec!["opcode".to_string()],
        result: vec!["result".to_string()],
        diagnostic_message: Vec::new(),
        object: Vec::new(),
        argument: Vec::new(),
    }
}

fn insert_ldap_raw_event(store: &RawEventStore<Ldap>, sensor: &str, timestamp: i64) {
    let ldap_body = sample_ldap_event();
    let _ = append_event(store, sensor, timestamp, &ldap_body);
}

#[tokio::test]
async fn ldap_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        ldapRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    messageId,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "ldapRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 389,
                            "respPort": 636,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "messageId": "123",
                            "version": 3,
                            "opcode": [
                                "bind",
                                "search"
                            ],
                            "result": [
                                "success",
                                "noSuchObject"
                            ],
                            "diagnosticMessage": [
                                "",
                                "Object not found"
                            ],
                            "object": [
                                "CN=John Doe",
                                "OU=Users"
                            ],
                            "argument": [
                                "username",
                                "(&(objectClass=user)(sAMAccountName=jdoe))"
                            ]
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{ldapRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", messageId: \"123\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn tls_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.tls_store().unwrap();

    insert_tls_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        tlsRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{tlsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn sample_tls_event() -> Tls {
    let start_time = Utc.with_ymd_and_hms(2023, 1, 6, 11, 11, 0).unwrap();
    Tls {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        server_name: "server_name".to_string(),
        alpn_protocol: "alpn_protocol".to_string(),
        ja3: "ja3".to_string(),
        version: "version".to_string(),
        client_cipher_suites: vec![771, 769, 770],
        client_extensions: vec![0, 1, 2],
        cipher: 10,
        extensions: vec![0, 1],
        ja3s: "ja3s".to_string(),
        serial: "serial".to_string(),
        subject_country: "sub_country".to_string(),
        subject_org_name: "sub_org".to_string(),
        subject_common_name: "sub_comm".to_string(),
        validity_not_before: 11,
        validity_not_after: 12,
        subject_alt_name: "sub_alt".to_string(),
        issuer_country: "issuer_country".to_string(),
        issuer_org_name: "issuer_org".to_string(),
        issuer_org_unit_name: "issuer_org_unit".to_string(),
        issuer_common_name: "issuer_comm".to_string(),
        last_alert: 13,
    }
}

fn insert_tls_raw_event(store: &RawEventStore<Tls>, sensor: &str, timestamp: i64) {
    let tls_body = sample_tls_event();
    let _ = append_event(store, sensor, timestamp, &tls_body);
}

#[tokio::test]
async fn tls_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        tlsRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    validityNotBefore,
                    validityNotAfter,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "tlsRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 443,
                            "respPort": 54321,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "serverName": "example.com",
                            "alpnProtocol": "h2",
                            "ja3": "aabbccddeeff",
                            "version": "TLSv1.2",
                            "clientCipherSuites": [
                                771,
                                769,
                                770
                            ],
                            "clientExtensions": [
                                0,
                                1,
                                2
                            ],
                            "cipher": 256,
                            "extensions": [
                                0,
                                1
                            ],
                            "ja3S": "1122334455",
                            "serial": "1234567890",
                            "subjectCountry": "US",
                            "subjectOrgName": "Organization",
                            "subjectCommonName": "CommonName",
                            "validityNotBefore": "1637076000",
                            "validityNotAfter": "1668612000",
                            "subjectAltName": "www.example.com",
                            "issuerCountry": "CA",
                            "issuerOrgName": "IssuerOrg",
                            "issuerOrgUnitName": "IssuerUnit",
                            "issuerCommonName": "IssuerCommon",
                            "lastAlert": 789012345
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{tlsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", validityNotBefore: \
        \"1637076000\", validityNotAfter: \"1668612000\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn smb_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.smb_store().unwrap();

    insert_smb_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        smbRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    fileSize,
                    createTime,
                    accessTime,
                    writeTime,
                    changeTime,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{smbRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", fileSize: \"10\", \
        createTime: \"10000000\", accessTime: \"20000000\", writeTime: \"10000000\", \
        changeTime: \"20000000\"}}]}}"
    );
}

fn sample_smb_event() -> Smb {
    let start_time = Utc.with_ymd_and_hms(2023, 1, 6, 12, 12, 10).unwrap();
    Smb {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        command: 0,
        path: "something/path".to_string(),
        service: "service".to_string(),
        file_name: "fine_name".to_string(),
        file_size: 10,
        resource_type: 20,
        fid: 30,
        create_time: 10_000_000,
        access_time: 20_000_000,
        write_time: 10_000_000,
        change_time: 20_000_000,
    }
}

fn insert_smb_raw_event(store: &RawEventStore<Smb>, sensor: &str, timestamp: i64) {
    let smb_body = sample_smb_event();
    let _ = append_event(store, sensor, timestamp, &smb_body);
}

#[tokio::test]
async fn smb_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        smbRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    fileSize,
                    createTime,
                    accessTime,
                    writeTime,
                    changeTime,
                }
            }
        }
    }"#;
    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "smbRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.77",
                            "origPort": 445,
                            "respPort": 12345,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "command": 1,
                            "path": "\\share\\folder\\file.txt",
                            "service": "IPC",
                            "fileName": "file.txt",
                            "fileSize": "1024",
                            "resourceType": 1,
                            "fid": 123,
                            "createTime": "1609459200",
                            "accessTime": "1637076000",
                            "writeTime": "1668612000",
                            "changeTime": "1700148000"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{smbRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", fileSize: \"1024\", \
        createTime: \"1609459200\", accessTime: \"1637076000\", writeTime: \"1668612000\", \
        changeTime: \"1700148000\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn nfs_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.nfs_store().unwrap();

    insert_nfs_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        nfsRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{nfsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn sample_nfs_event() -> Nfs {
    let start_time = Utc.with_ymd_and_hms(2023, 1, 6, 12, 13, 0).unwrap();
    Nfs {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        read_files: vec![],
        write_files: vec![],
    }
}

fn insert_nfs_raw_event(store: &RawEventStore<Nfs>, sensor: &str, timestamp: i64) {
    let nfs_body = sample_nfs_event();
    let _ = append_event(store, sensor, timestamp, &nfs_body);
}

#[tokio::test]
async fn nfs_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        nfsRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "nfsRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 2049,
                            "respPort": 54321,
                            "proto": 6,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "readFiles": [
                                "file1.txt",
                                "file2.txt"
                            ],
                            "writeFiles": [
                                "file3.txt",
                                "file4.txt"
                            ]
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{nfsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn bootp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.bootp_store().unwrap();

    insert_bootp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_bootp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        bootpRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    xid,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{bootpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", xid: \"0\"}}]}}"
    );
}

fn insert_bootp_raw_event(store: &RawEventStore<Bootp>, sensor: &str, timestamp: i64) {
    let bootp_body = sample_bootp_event();
    let _ = append_event(store, sensor, timestamp, &bootp_body);
}

fn sample_bootp_event() -> Bootp {
    let start_time = Utc.with_ymd_and_hms(2019, 12, 31, 23, 59, 59).unwrap();
    Bootp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        op: 0,
        htype: 0,
        hops: 0,
        xid: 0,
        ciaddr: "192.168.4.1".parse::<IpAddr>().unwrap(),
        yiaddr: "192.168.4.2".parse::<IpAddr>().unwrap(),
        siaddr: "192.168.4.3".parse::<IpAddr>().unwrap(),
        giaddr: "192.168.4.4".parse::<IpAddr>().unwrap(),
        chaddr: vec![0, 1, 2],
        sname: "sname".to_string(),
        file: "file".to_string(),
    }
}

#[tokio::test]
async fn bootp_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        bootpRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    xid,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "bootpRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "31.3.245.133",
                            "origPort": 46378,
                            "respPort": 80,
                            "proto": 17,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "op": 0,
                            "htype": 0,
                            "hops": 0,
                            "xid": "0",
                            "ciaddr": "192.168.4.1",
                            "yiaddr": "192.168.4.2",
                            "siaddr": "192.168.4.3",
                            "giaddr": "192.168.4.4",
                            "chaddr": [0, 1, 2],
                            "sname": "sname",
                            "file": "file"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{bootpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", xid: \"0\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn dhcp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.dhcp_store().unwrap();

    insert_dhcp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_dhcp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        dhcpRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    leaseTime,
                    renewalTime,
                    rebindingTime,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{dhcpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", leaseTime: \"1\", \
        renewalTime: \"1\", rebindingTime: \"1\"}}]}}"
    );
}

fn insert_dhcp_raw_event(store: &RawEventStore<Dhcp>, sensor: &str, timestamp: i64) {
    let dhcp_body = sample_dhcp_event();
    let _ = append_event(store, sensor, timestamp, &dhcp_body);
}

fn sample_dhcp_event() -> Dhcp {
    let start_time = Utc.with_ymd_and_hms(2023, 1, 6, 12, 13, 10).unwrap();
    Dhcp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        msg_type: 0,
        ciaddr: "192.168.4.1".parse::<IpAddr>().unwrap(),
        yiaddr: "192.168.4.2".parse::<IpAddr>().unwrap(),
        siaddr: "192.168.4.3".parse::<IpAddr>().unwrap(),
        giaddr: "192.168.4.4".parse::<IpAddr>().unwrap(),
        subnet_mask: "192.168.4.5".parse::<IpAddr>().unwrap(),
        router: vec![
            "192.168.1.11".parse::<IpAddr>().unwrap(),
            "192.168.1.22".parse::<IpAddr>().unwrap(),
        ],
        domain_name_server: vec![
            "192.168.1.33".parse::<IpAddr>().unwrap(),
            "192.168.1.44".parse::<IpAddr>().unwrap(),
        ],
        req_ip_addr: "192.168.4.6".parse::<IpAddr>().unwrap(),
        lease_time: 1,
        server_id: "192.168.4.7".parse::<IpAddr>().unwrap(),
        param_req_list: vec![0, 1, 2],
        message: "message".to_string(),
        renewal_time: 1,
        rebinding_time: 1,
        class_id: vec![0, 1, 2],
        client_id_type: 1,
        client_id: vec![0, 1, 2],
    }
}

#[tokio::test]
async fn dhcp_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        dhcpRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    leaseTime,
                    renewalTime,
                    rebindingTime,
                }
            }
        }
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "dhcpRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "31.3.245.133",
                            "origPort": 46378,
                            "respPort": 80,
                            "proto": 17,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "msgType": 0,
                            "ciaddr": "192.168.4.1",
                            "yiaddr": "192.168.4.2",
                            "siaddr": "192.168.4.3",
                            "giaddr": "192.168.4.4",
                            "subnetMask": "192.168.4.5",
                            "router": ["192.168.1.11", "192.168.1.22"],
                            "domainNameServer": ["192.168.1.33", "192.168.1.44"],
                            "reqIpAddr": "192.168.4.6",
                            "leaseTime": "1",
                            "serverId": "192.168.4.7",
                            "paramReqList": [0, 1, 2],
                            "message": "message",
                            "renewalTime": "1",
                            "rebindingTime": "1",
                            "classId": [0, 1, 2],
                            "clientIdType": 1,
                            "clientId": [0, 1, 2]
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{dhcpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", leaseTime: \"1\", renewalTime: \"1\", rebindingTime: \"1\"}}]}}"
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn radius_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.radius_store().unwrap();

    insert_radius_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_radius_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        radiusRawEvents(
            filter: {
                sensor: "src 1"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    nasPort,
                    code,
                    respCode,
                    message,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{radiusRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", nasPort: \"12345\", \
        code: 1, respCode: 2, message: \"test_message\"}}]}}"
    );
}

fn insert_radius_raw_event(store: &RawEventStore<Radius>, sensor: &str, timestamp: i64) {
    let radius_body = sample_radius_event();
    let _ = append_event(store, sensor, timestamp, &radius_body);
}

fn sample_radius_event() -> Radius {
    let start_time = Utc.with_ymd_and_hms(2023, 1, 6, 12, 14, 0).unwrap();
    Radius {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 1812,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 1813,
        proto: 17,
        start_time,
        end_time: start_time + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        id: 123,
        code: 1,
        resp_code: 2,
        auth: "00112233445566778899aabbccddeeff".to_string(),
        resp_auth: "ffeeddccbbaa99887766554433221100".to_string(),
        user_name: "test_user".to_string().into_bytes(),
        user_passwd: "test_password".to_string().into_bytes(),
        chap_passwd: vec![2u8; 16],
        nas_ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
        nas_port: 12345,
        state: vec![3u8; 8],
        nas_id: "test_nas".to_string().into_bytes(),
        nas_port_type: 15,
        message: "test_message".to_string(),
    }
}

fn expected_conn_node(time: DateTime<Utc>) -> Value {
    let Conn {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        conn_state,
        service,
        start_time,
        end_time,
        duration,
        orig_bytes,
        resp_bytes,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        ..
    } = sample_conn_event();
    json!({
        "__typename": "ConnRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "connState": conn_state,
        "service": service,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origBytes": orig_bytes.to_string(),
        "respBytes": resp_bytes.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string()
    })
}

fn expected_dns_node(time: DateTime<Utc>) -> Value {
    let Dns {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        query,
        answer,
        trans_id,
        rtt,
        qclass,
        qtype,
        rcode,
        aa_flag,
        tc_flag,
        rd_flag,
        ra_flag,
        ttl,
        ..
    } = sample_dns_event();
    json!({
        "__typename": "DnsRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "query": query,
        "answer": answer,
        "transId": trans_id,
        "rtt": rtt.to_string(),
        "qclass": qclass,
        "qtype": qtype,
        "rcode": rcode,
        "aaFlag": aa_flag,
        "tcFlag": tc_flag,
        "rdFlag": rd_flag,
        "raFlag": ra_flag,
        "ttl": ttl
    })
}

fn expected_http_node(time: DateTime<Utc>) -> Value {
    let Http {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        method,
        host,
        uri,
        referer,
        version,
        user_agent,
        request_len,
        response_len,
        status_code,
        status_msg,
        username,
        password,
        cookie,
        content_encoding,
        content_type,
        cache_control,
        filenames,
        mime_types,
        body,
        state,
        ..
    } = sample_http_event();
    json!({
        "__typename": "HttpRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "method": method,
        "host": host,
        "uri": uri,
        "referer": referer,
        "version": version,
        "userAgent": user_agent,
        "requestLen": request_len.to_string(),
        "responseLen": response_len.to_string(),
        "statusCode": status_code,
        "statusMsg": status_msg,
        "username": username,
        "password": password,
        "cookie": cookie,
        "contentEncoding": content_encoding,
        "contentType": content_type,
        "cacheControl": cache_control,
        "filenames": filenames,
        "mimeTypes": mime_types,
        "body": body,
        "state": state
    })
}

fn expected_rdp_node(time: DateTime<Utc>) -> Value {
    let Rdp {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        cookie,
        ..
    } = sample_rdp_event();
    json!({
        "__typename": "RdpRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "cookie": cookie
    })
}

fn expected_ntlm_node(time: DateTime<Utc>) -> Value {
    let Ntlm {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        username,
        hostname,
        domainname,
        success,
        protocol,
        ..
    } = sample_ntlm_event();
    json!({
        "__typename": "NtlmRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "username": username,
        "hostname": hostname,
        "domainname": domainname,
        "success": success,
        "protocol": protocol
    })
}

fn expected_kerberos_node(time: DateTime<Utc>) -> Value {
    let Kerberos {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        client_time,
        server_time,
        error_code,
        client_realm,
        cname_type,
        client_name,
        realm,
        sname_type,
        service_name,
        ..
    } = sample_kerberos_event();
    json!({
        "__typename": "KerberosRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "clientTime": client_time.to_string(),
        "serverTime": server_time.to_string(),
        "errorCode": error_code.to_string(),
        "clientRealm": client_realm,
        "cnameType": cname_type,
        "clientName": client_name,
        "realm": realm,
        "snameType": sname_type,
        "serviceName": service_name
    })
}

fn expected_ssh_node(time: DateTime<Utc>) -> Value {
    let Ssh {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        client,
        server,
        cipher_alg,
        mac_alg,
        compression_alg,
        kex_alg,
        host_key_alg,
        hassh_algorithms,
        hassh,
        hassh_server_algorithms,
        hassh_server,
        client_shka,
        server_shka,
        ..
    } = sample_ssh_event();
    json!({
        "__typename": "SshRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "client": client,
        "server": server,
        "cipherAlg": cipher_alg,
        "macAlg": mac_alg,
        "compressionAlg": compression_alg,
        "kexAlg": kex_alg,
        "hostKeyAlg": host_key_alg,
        "hasshAlgorithms": hassh_algorithms,
        "hassh": hassh,
        "hasshServerAlgorithms": hassh_server_algorithms,
        "hasshServer": hassh_server,
        "clientShka": client_shka,
        "serverShka": server_shka
    })
}

fn expected_dce_rpc_node(time: DateTime<Utc>) -> Value {
    let DceRpc {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        rtt,
        named_pipe,
        endpoint,
        operation,
        ..
    } = sample_dce_rpc_event();
    json!({
        "__typename": "DceRpcRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "rtt": rtt.to_string(),
        "namedPipe": named_pipe,
        "endpoint": endpoint,
        "operation": operation
    })
}

fn expected_ftp_node(time: DateTime<Utc>) -> Value {
    let Ftp {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        user,
        password,
        commands,
        ..
    } = sample_ftp_event();
    json!({
        "__typename": "FtpRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "user": user,
        "password": password,
        "commands": commands.iter().map(|command| {
            json!({
                "command": command.command,
                "replyCode": command.reply_code,
                "replyMsg": command.reply_msg,
                "dataPassive": command.data_passive,
                "dataOrigAddr": command.data_orig_addr.to_string(),
                "dataRespAddr": command.data_resp_addr.to_string(),
                "dataRespPort": command.data_resp_port,
                "file": command.file,
                "fileSize": command.file_size.to_string(),
                "fileId": command.file_id
            })
        }).collect::<Vec<_>>()
    })
}

fn expected_mqtt_node(time: DateTime<Utc>) -> Value {
    let Mqtt {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        protocol,
        version,
        client_id,
        connack_reason,
        subscribe,
        suback_reason,
        ..
    } = sample_mqtt_event();
    json!({
        "__typename": "MqttRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "protocol": protocol,
        "version": version,
        "clientId": client_id,
        "connackReason": connack_reason,
        "subscribe": subscribe,
        "subackReason": suback_reason
    })
}

fn expected_ldap_node(time: DateTime<Utc>) -> Value {
    let Ldap {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        message_id,
        version,
        opcode,
        result,
        diagnostic_message,
        object,
        argument,
        ..
    } = sample_ldap_event();
    json!({
        "__typename": "LdapRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "messageId": message_id.to_string(),
        "version": version,
        "opcode": opcode,
        "result": result,
        "diagnosticMessage": diagnostic_message,
        "object": object,
        "argument": argument
    })
}

fn expected_tls_node(time: DateTime<Utc>) -> Value {
    let Tls {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        server_name,
        alpn_protocol,
        ja3,
        version,
        client_cipher_suites,
        client_extensions,
        cipher,
        extensions,
        ja3s,
        serial,
        subject_country,
        subject_org_name,
        subject_common_name,
        validity_not_before,
        validity_not_after,
        subject_alt_name,
        issuer_country,
        issuer_org_name,
        issuer_org_unit_name,
        issuer_common_name,
        last_alert,
        ..
    } = sample_tls_event();
    json!({
        "__typename": "TlsRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "serverName": server_name,
        "alpnProtocol": alpn_protocol,
        "ja3": ja3,
        "version": version,
        "clientCipherSuites": client_cipher_suites,
        "clientExtensions": client_extensions,
        "cipher": cipher,
        "extensions": extensions,
        "ja3S": ja3s,
        "serial": serial,
        "subjectCountry": subject_country,
        "subjectOrgName": subject_org_name,
        "subjectCommonName": subject_common_name,
        "validityNotBefore": validity_not_before.to_string(),
        "validityNotAfter": validity_not_after.to_string(),
        "subjectAltName": subject_alt_name,
        "issuerCountry": issuer_country,
        "issuerOrgName": issuer_org_name,
        "issuerOrgUnitName": issuer_org_unit_name,
        "issuerCommonName": issuer_common_name,
        "lastAlert": last_alert
    })
}

fn expected_smb_node(time: DateTime<Utc>) -> Value {
    let Smb {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        command,
        path,
        service,
        file_name,
        file_size,
        resource_type,
        fid,
        create_time,
        access_time,
        write_time,
        change_time,
        ..
    } = sample_smb_event();
    json!({
        "__typename": "SmbRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "command": command,
        "path": path,
        "service": service,
        "fileName": file_name,
        "fileSize": file_size.to_string(),
        "resourceType": resource_type,
        "fid": fid,
        "createTime": create_time.to_string(),
        "accessTime": access_time.to_string(),
        "writeTime": write_time.to_string(),
        "changeTime": change_time.to_string()
    })
}

fn expected_nfs_node(time: DateTime<Utc>) -> Value {
    let Nfs {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        read_files,
        write_files,
        ..
    } = sample_nfs_event();
    json!({
        "__typename": "NfsRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "readFiles": read_files,
        "writeFiles": write_files
    })
}

fn expected_smtp_node(time: DateTime<Utc>) -> Value {
    let Smtp {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        mailfrom,
        date,
        from,
        to,
        subject,
        agent,
        state,
        ..
    } = sample_smtp_event();
    json!({
        "__typename": "SmtpRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "mailfrom": mailfrom,
        "date": date,
        "from": from,
        "to": to,
        "subject": subject,
        "agent": agent,
        "state": state
    })
}

fn expected_bootp_node(time: DateTime<Utc>) -> Value {
    let Bootp {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        op,
        htype,
        hops,
        xid,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr,
        sname,
        file,
        ..
    } = sample_bootp_event();
    json!({
        "__typename": "BootpRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "op": op,
        "htype": htype,
        "hops": hops,
        "xid": xid.to_string(),
        "ciaddr": ciaddr.to_string(),
        "yiaddr": yiaddr.to_string(),
        "siaddr": siaddr.to_string(),
        "giaddr": giaddr.to_string(),
        "chaddr": chaddr,
        "sname": sname,
        "file": file
    })
}

fn expected_dhcp_node(time: DateTime<Utc>) -> Value {
    let Dhcp {
        orig_addr,
        resp_addr,
        orig_port,
        resp_port,
        proto,
        start_time,
        end_time,
        duration,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes,
        resp_l2_bytes,
        msg_type,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        subnet_mask,
        router,
        domain_name_server,
        req_ip_addr,
        lease_time,
        server_id,
        param_req_list,
        message,
        renewal_time,
        rebinding_time,
        class_id,
        client_id_type,
        client_id,
        ..
    } = sample_dhcp_event();
    json!({
        "__typename": "DhcpRawEvent",
        "time": time.to_rfc3339(),
        "origAddr": orig_addr.to_string(),
        "respAddr": resp_addr.to_string(),
        "origPort": orig_port,
        "respPort": resp_port,
        "proto": proto,
        "startTime": start_time.to_rfc3339(),
        "endTime": end_time.to_rfc3339(),
        "duration": duration.to_string(),
        "origPkts": orig_pkts.to_string(),
        "respPkts": resp_pkts.to_string(),
        "origL2Bytes": orig_l2_bytes.to_string(),
        "respL2Bytes": resp_l2_bytes.to_string(),
        "msgType": msg_type,
        "ciaddr": ciaddr.to_string(),
        "yiaddr": yiaddr.to_string(),
        "siaddr": siaddr.to_string(),
        "giaddr": giaddr.to_string(),
        "subnetMask": subnet_mask.to_string(),
        "router": router.into_iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        "domainNameServer": domain_name_server.into_iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        "reqIpAddr": req_ip_addr.to_string(),
        "leaseTime": lease_time.to_string(),
        "serverId": server_id.to_string(),
        "paramReqList": param_req_list,
        "message": message,
        "renewalTime": renewal_time.to_string(),
        "rebindingTime": rebinding_time.to_string(),
        "classId": class_id,
        "clientIdType": client_id_type,
        "clientId": client_id
    })
}

#[tokio::test]
async fn radius_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        radiusRawEvents(
            filter: {
                sensor: "src 2"
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    nasPort,
                    code,
                    respCode,
                    message,
                }
            }
        }
    }"#;
    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "radiusRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "time": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "31.3.245.133",
                            "origPort": 1812,
                            "respPort": 1813,
                            "proto": 17,
                            "startTime": "2023-11-16T15:03:45.291779203+00:00",
                            "endTime": "2023-11-16T15:03:45.291779203+00:00",
                            "duration": "1000000000",
                            "origPkts": "1",
                            "respPkts": "1",
                            "origL2Bytes": "100",
                            "respL2Bytes": "200",
                            "id": 123,
                            "code": 1,
                            "respCode": 2,
                            "auth": "00112233445566778899aabbccddeeff",
                            "respAuth": "ffeeddccbbaa99887766554433221100",
                            "userName": [116, 101, 115, 116, 95, 117, 115, 101, 114],
                            "userPasswd": [116, 101, 115, 116, 95, 112, 97, 115, 115, 119, 111, 114, 100],
                            "chapPasswd": [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
                            "nasIp": "192.168.1.1",
                            "nasPort": "12345",
                            "state": [3, 3, 3, 3, 3, 3, 3, 3],
                            "nasId": [116, 101, 115, 116, 95, 110, 97, 115],
                            "nasPortType": "15",
                            "message": "test_message"
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

    // when
    let res = schema.execute(query).await;

    // then
    assert_eq!(
        res.data.to_string(),
        "{radiusRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\", nasPort: \"12345\", \
        code: 1, respCode: 2, message: \"test_message\"}}]}}"
    );
    mock.assert_async().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_search_boundary_for_addr_port() {
    let schema = TestSchema::new();
    let store = schema.db.conn_store().unwrap();

    insert_conn_raw_event_with_addr_port(
        &store,
        "src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
        "192.168.4.70".parse::<IpAddr>().ok(),
        Some(100),
        "192.168.4.80".parse::<IpAddr>().ok(),
        Some(200),
    );
    insert_conn_raw_event_with_addr_port(
        &store,
        "src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
        "192.168.4.71".parse::<IpAddr>().ok(),
        Some(101),
        "192.168.4.81".parse::<IpAddr>().ok(),
        Some(201),
    );
    insert_conn_raw_event_with_addr_port(
        &store,
        "src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
        "192.168.4.72".parse::<IpAddr>().ok(),
        Some(102),
        "192.168.4.82".parse::<IpAddr>().ok(),
        Some(202),
    );

    // Only the start value of origAddr is provided (Retrieves all events where origAddr is greater
    // than or equal to the given start value)
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.70" }
            }
        ) {
            edges {
                node {
                    origAddr
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.70\"}}, {node: {origAddr: \"192.168.4.71\"}}, {node: {origAddr: \"192.168.4.72\"}}]}}"
    );

    // Only the end value of origAddr is provided (Retrieves all events where origAddr is less
    // than the given end value)
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                origAddr: { end: "192.168.4.72" }
            }
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.70\"}}, {node: {origAddr: \"192.168.4.71\"}}]}}"
    );

    // Both start and end origAddr are provided (Retrieves all events where origAddr is within the
    // range from the given start origAddr (inclusive) to end origAddr (exclusive)).
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.70", end: "192.168.4.72"}
            }
        ) {
            edges {
                node {
                    origAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.70\"}}, {node: {origAddr: \"192.168.4.71\"}}]}}"
    );

    // Only the start value of respAddr is provided (Retrieves all events where respAddr is greater
    // than or equal to the given start value)
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                respAddr: { start: "192.168.4.80" }
            }
        ) {
            edges {
                node {
                    respAddr
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {respAddr: \"192.168.4.80\"}}, {node: {respAddr: \"192.168.4.81\"}}, {node: {respAddr: \"192.168.4.82\"}}]}}"
    );

    // Only the end value of respAddr is provided (Retrieves all events where respAddr is less
    // than the given end value)
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                respAddr: { end: "192.168.4.82" }
            }
        ) {
            edges {
                node {
                    respAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {respAddr: \"192.168.4.80\"}}, {node: {respAddr: \"192.168.4.81\"}}]}}"
    );

    // Both start and end respAddr are provided (Retrieves all events where respAddr is within the
    // range from the given start respAddr (inclusive) to end respAddr (exclusive)).
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                respAddr: { start: "192.168.4.80", end: "192.168.4.82"}
            }
        ) {
            edges {
                node {
                    respAddr,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {respAddr: \"192.168.4.80\"}}, {node: {respAddr: \"192.168.4.81\"}}]}}"
    );

    // Only the start value of origPort is provided (Retrieves all events where origPort is greater
    // than or equal to the given start value)
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                origPort: { start: 100 }
            }
        ) {
            edges {
                node {
                    origPort
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origPort: 100}}, {node: {origPort: 101}}, {node: {origPort: 102}}]}}"
    );

    // Only the end value of origPort is provided (Retrieves all events where origPort is less
    // than the given end value)
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                origPort: { end: 102 }
            }
        ) {
            edges {
                node {
                    origPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origPort: 100}}, {node: {origPort: 101}}]}}"
    );

    // Both start and end origPort are provided (Retrieves all events where origPort is within the
    // range from the given start origPort (inclusive) to end origPort (exclusive)).
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                origPort: { start: 100, end: 102}
            }
        ) {
            edges {
                node {
                    origPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origPort: 100}}, {node: {origPort: 101}}]}}"
    );

    // Only the start value of respPort is provided (Retrieves all events where respPort is greater
    // than or equal to the given start value)
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                respPort: { start: 200 }
            }
        ) {
            edges {
                node {
                    respPort
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {respPort: 200}}, {node: {respPort: 201}}, {node: {respPort: 202}}]}}"
    );

    // Only the end value of respPort is provided (Retrieves all events where respPort is less
    // than the given end value)
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                respPort: { end: 202 }
            }
        ) {
            edges {
                node {
                    respPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {respPort: 200}}, {node: {respPort: 201}}]}}"
    );

    // Both start and end respPort are provided (Retrieves all events where respPort is within the
    // range from the given start respPort (inclusive) to end respPort (exclusive)).
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                sensor: "src 1"
                respPort: { start: 200, end: 202}
            }
        ) {
            edges {
                node {
                    respPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {respPort: 200}}, {node: {respPort: 201}}]}}"
    );
}

fn insert_conn_raw_event_with_addr_port(
    store: &RawEventStore<Conn>,
    sensor: &str,
    timestamp: i64,
    orig_addr: Option<IpAddr>,
    orig_port: Option<u16>,
    resp_addr: Option<IpAddr>,
    resp_port: Option<u16>,
) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let conn_body = create_conn_body(orig_addr, orig_port, resp_addr, resp_port);
    let ser_conn_body = encode_legacy(&conn_body).unwrap();
    store.append(&key, &ser_conn_body).unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn union() {
    let schema = TestSchema::new();
    let conn_store = schema.db.conn_store().unwrap();
    let dns_store = schema.db.dns_store().unwrap();
    let http_store = schema.db.http_store().unwrap();
    let rdp_store = schema.db.rdp_store().unwrap();
    let ntlm_store = schema.db.ntlm_store().unwrap();
    let kerberos_store = schema.db.kerberos_store().unwrap();
    let ssh_store = schema.db.ssh_store().unwrap();
    let dce_rpc_store = schema.db.dce_rpc_store().unwrap();
    let ftp_store = schema.db.ftp_store().unwrap();
    let mqtt_store = schema.db.mqtt_store().unwrap();
    let ldap_store = schema.db.ldap_store().unwrap();
    let tls_store = schema.db.tls_store().unwrap();
    let smb_store = schema.db.smb_store().unwrap();
    let nfs_store = schema.db.nfs_store().unwrap();
    let smtp_store = schema.db.smtp_store().unwrap();
    let bootp_store = schema.db.bootp_store().unwrap();
    let dhcp_store = schema.db.dhcp_store().unwrap();

    let bootp_time = Utc.with_ymd_and_hms(2019, 12, 31, 23, 59, 59).unwrap();
    insert_bootp_raw_event(&bootp_store, SENSOR, timestamp_ns(bootp_time));

    let ssh_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap();
    insert_ssh_raw_event(&ssh_store, SENSOR, timestamp_ns(ssh_time));

    let smtp_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 5).unwrap();
    insert_smtp_raw_event(&smtp_store, SENSOR, timestamp_ns(smtp_time));

    let conn_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap();
    insert_conn_raw_event(&conn_store, SENSOR, timestamp_ns(conn_time));

    let rdp_time = Utc.with_ymd_and_hms(2020, 1, 5, 0, 1, 1).unwrap();
    insert_rdp_raw_event(&rdp_store, SENSOR, timestamp_ns(rdp_time));

    let dce_rpc_time = Utc.with_ymd_and_hms(2020, 1, 5, 6, 5, 0).unwrap();
    insert_dce_rpc_raw_event(&dce_rpc_store, SENSOR, timestamp_ns(dce_rpc_time));

    let http_time = Utc.with_ymd_and_hms(2020, 6, 1, 0, 1, 1).unwrap();
    insert_http_raw_event(&http_store, SENSOR, timestamp_ns(http_time));

    let dns_time = Utc.with_ymd_and_hms(2021, 1, 1, 0, 1, 1).unwrap();
    insert_dns_raw_event(&dns_store, SENSOR, timestamp_ns(dns_time));

    let ntlm_time = Utc.with_ymd_and_hms(2022, 1, 5, 0, 1, 1).unwrap();
    insert_ntlm_raw_event(&ntlm_store, SENSOR, timestamp_ns(ntlm_time));

    let kerberos_time = Utc.with_ymd_and_hms(2023, 1, 5, 0, 1, 1).unwrap();
    insert_kerberos_raw_event(&kerberos_store, SENSOR, timestamp_ns(kerberos_time));

    let ftp_time = Utc.with_ymd_and_hms(2023, 1, 5, 12, 12, 0).unwrap();
    insert_ftp_raw_event(&ftp_store, SENSOR, timestamp_ns(ftp_time));

    let mqtt_time = Utc.with_ymd_and_hms(2023, 1, 5, 12, 12, 0).unwrap();
    insert_mqtt_raw_event(&mqtt_store, SENSOR, timestamp_ns(mqtt_time));

    let tls_time = Utc.with_ymd_and_hms(2023, 1, 6, 11, 11, 0).unwrap();
    insert_tls_raw_event(&tls_store, SENSOR, timestamp_ns(tls_time));

    let ldap_time = Utc.with_ymd_and_hms(2023, 1, 6, 12, 12, 0).unwrap();
    insert_ldap_raw_event(&ldap_store, SENSOR, timestamp_ns(ldap_time));

    let smb_time = Utc.with_ymd_and_hms(2023, 1, 6, 12, 12, 10).unwrap();
    insert_smb_raw_event(&smb_store, SENSOR, timestamp_ns(smb_time));

    let nfs_time = Utc.with_ymd_and_hms(2023, 1, 6, 12, 13, 0).unwrap();
    insert_nfs_raw_event(&nfs_store, SENSOR, timestamp_ns(nfs_time));

    let dhcp_time = Utc.with_ymd_and_hms(2023, 1, 6, 12, 13, 10).unwrap();
    insert_dhcp_raw_event(&dhcp_store, SENSOR, timestamp_ns(dhcp_time));

    let query = include_str!("../client/schema/network_raw_events.graphql");
    let request = Request::new(query).variables(Variables::from_json(json!({
        "filter": {
            "sensor": SENSOR,
            "time": {
                "start": "2019-01-01T00:00:00Z",
                "end": "2024-01-01T00:00:00Z"
            }
        },
        "after": Value::Null,
        "before": Value::Null,
        "last": Value::Null,
        "first": 20
    })));

    let res = schema.schema.execute(request).await;
    assert!(res.errors.is_empty(), "{:?}", res.errors);
    let data = res.data.into_json().unwrap();
    let edges = data["networkRawEvents"]["edges"]
        .as_array()
        .expect("edges should exist");
    let mut nodes: HashMap<String, Value> = HashMap::new();
    for edge in edges {
        let node = edge["node"].clone();
        let typename = node["__typename"].as_str().expect("typename").to_string();
        nodes.insert(typename, node);
    }

    assert_eq!(
        nodes.remove("BootpRawEvent").expect("bootp node"),
        expected_bootp_node(bootp_time)
    );
    assert_eq!(
        nodes.remove("SshRawEvent").expect("ssh node"),
        expected_ssh_node(ssh_time)
    );
    assert_eq!(
        nodes.remove("SmtpRawEvent").expect("smtp node"),
        expected_smtp_node(smtp_time)
    );
    assert_eq!(
        nodes.remove("ConnRawEvent").expect("conn node"),
        expected_conn_node(conn_time)
    );
    assert_eq!(
        nodes.remove("RdpRawEvent").expect("rdp node"),
        expected_rdp_node(rdp_time)
    );
    assert_eq!(
        nodes.remove("DceRpcRawEvent").expect("dce rpc node"),
        expected_dce_rpc_node(dce_rpc_time)
    );
    assert_eq!(
        nodes.remove("HttpRawEvent").expect("http node"),
        expected_http_node(http_time)
    );
    assert_eq!(
        nodes.remove("DnsRawEvent").expect("dns node"),
        expected_dns_node(dns_time)
    );
    assert_eq!(
        nodes.remove("NtlmRawEvent").expect("ntlm node"),
        expected_ntlm_node(ntlm_time)
    );
    assert_eq!(
        nodes.remove("KerberosRawEvent").expect("kerberos node"),
        expected_kerberos_node(kerberos_time)
    );
    assert_eq!(
        nodes.remove("FtpRawEvent").expect("ftp node"),
        expected_ftp_node(ftp_time)
    );
    assert_eq!(
        nodes.remove("MqttRawEvent").expect("mqtt node"),
        expected_mqtt_node(mqtt_time)
    );
    assert_eq!(
        nodes.remove("TlsRawEvent").expect("tls node"),
        expected_tls_node(tls_time)
    );
    assert_eq!(
        nodes.remove("LdapRawEvent").expect("ldap node"),
        expected_ldap_node(ldap_time)
    );
    assert_eq!(
        nodes.remove("SmbRawEvent").expect("smb node"),
        expected_smb_node(smb_time)
    );
    assert_eq!(
        nodes.remove("NfsRawEvent").expect("nfs node"),
        expected_nfs_node(nfs_time)
    );
    assert_eq!(
        nodes.remove("DhcpRawEvent").expect("dhcp node"),
        expected_dhcp_node(dhcp_time)
    );

    assert!(
        nodes.is_empty(),
        "unexpected node types present: {:?}",
        nodes.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn search_empty() {
    let schema = TestSchema::new();
    let query = r#"
    {
        searchHttpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 46377, end: 46380 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{searchHttpRawEvents: []}");
}

#[tokio::test]
async fn search_http_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.http_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_http_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchHttpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchHttpRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_conn_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.conn_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_conn_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchConnRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchConnRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_conn_with_data_giganto_cluster() {
    let query = r#"
    {
        searchConnRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "searchConnRawEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
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
        "{searchConnRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_dns_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.dns_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_dns_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchDnsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 70, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchDnsRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_dns_with_data_giganto_cluster() {
    let query = r#"
    {
        searchDnsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 70, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "searchDnsRawEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
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
        "{searchDnsRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_malformed_dns_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.malformed_dns_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap();
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap();
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap();
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap();

    insert_malformed_dns_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_malformed_dns_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_malformed_dns_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_malformed_dns_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchMalformedDnsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 70, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchMalformedDnsRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_malformed_dns_with_data_giganto_cluster() {
    let query = r#"
    {
        searchMalformedDnsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 70, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "searchMalformedDnsRawEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
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
        "{searchMalformedDnsRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_rdp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.rdp_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_rdp_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchRdpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchRdpRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_rdp_with_data_giganto_cluster() {
    let query = r#"
    {
        searchRdpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "searchRdpRawEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
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
        "{searchRdpRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_smtp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.smtp_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_smtp_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchSmtpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchSmtpRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_smtp_with_data_giganto_cluster() {
    let query = r#"
    {
        searchSmtpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "searchSmtpRawEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
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
        "{searchSmtpRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_ntlm_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ntlm_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ntlm_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchNtlmRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchNtlmRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_ntlm_with_data_giganto_cluster() {
    let query = r#"
    {
        searchNtlmRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;

    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "searchNtlmRawEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
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
        "{searchNtlmRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_kerberos_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.kerberos_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_kerberos_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchKerberosRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchKerberosRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_kerberos_with_data_giganto_cluster() {
    let query = r#"
    {
        searchKerberosRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let mut peer_server = mockito::Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "searchKerberosRawEvents": [
                "2020-01-01T00:01:01+00:00",
                "2020-01-01T01:01:01+00:00"
            ]
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
        "{searchKerberosRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_ssh_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ssh_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ssh_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchSshRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchSshRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_dce_rpc_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.dce_rpc_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_dce_rpc_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchDceRpcRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchDceRpcRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_ftp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ftp_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ftp_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchFtpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchFtpRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_mqtt_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.mqtt_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_mqtt_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchMqttRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchMqttRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_ldap_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ldap_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ldap_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchLdapRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchLdapRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_tls_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.tls_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_tls_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchTlsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchTlsRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_smb_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.smb_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_smb_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchSmbRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchSmbRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_nfs_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.nfs_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_nfs_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchNfsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchNfsRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_bootp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.bootp_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_bootp_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_bootp_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_bootp_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_bootp_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchBootpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchBootpRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_dhcp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.dhcp_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_dhcp_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_dhcp_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_dhcp_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_dhcp_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchDhcpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchDhcpRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_radius_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.radius_store().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_radius_raw_event(&store, SENSOR, time1.timestamp_nanos_opt().unwrap());
    insert_radius_raw_event(&store, SENSOR, time2.timestamp_nanos_opt().unwrap());
    insert_radius_raw_event(&store, SENSOR, time3.timestamp_nanos_opt().unwrap());
    insert_radius_raw_event(&store, SENSOR, time4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchRadiusRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                sensor: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 1810, end: 1815 }
                respPort: { start: 1810, end: 1815 }
                times:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchRadiusRawEvents: [\"2020-01-01T00:01:01+00:00\", \"2020-01-01T01:01:01+00:00\"]}"
    );
}
