use std::mem;
use std::net::{IpAddr, SocketAddr};

use chrono::{TimeZone, Utc};
use giganto_client::ingest::network::{
    Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, FtpCommand, Http, Kerberos, Ldap, MalformedDns, Mqtt, Nfs,
    Ntlm, Radius, Rdp, Smb, Smtp, Ssh, Tls,
};
use mockito;

use crate::graphql::tests::TestSchema;
use crate::storage::WritableRawEventStore;

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
    let store = schema.db.conn_store_writable().unwrap();

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
         origBytes: \"77\", respBytes: \"295\", origPkts: \
         \"397\", respPkts: \"511\", origL2Bytes: \"21515\", respL2Bytes: \"27889\"}}]}}"
    );
}

pub(crate) fn insert_conn_raw_event(
    store: &dyn WritableRawEventStore<Conn>,
    sensor: &str,
    timestamp: i64,
) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let conn_body = create_conn_body(None, None, None, None);
    let ser_conn_body = bincode::serialize(&conn_body).unwrap();
    store.append(&key, &ser_conn_body).unwrap();
}

fn create_conn_body(
    orig_addr: Option<IpAddr>,
    orig_port: Option<u16>,
    resp_addr: Option<IpAddr>,
    resp_port: Option<u16>,
) -> Conn {
    Conn {
        orig_addr: orig_addr.unwrap_or("192.168.4.76".parse::<IpAddr>().unwrap()),
        orig_port: orig_port.unwrap_or(46378),
        resp_addr: resp_addr.unwrap_or("192.168.4.76".parse::<IpAddr>().unwrap()),
        resp_port: resp_port.unwrap_or(80),
        proto: 6,
        conn_state: "sf".to_string(),
        start_time: Utc
            .with_ymd_and_hms(2023, 1, 20, 0, 0, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
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
         origBytes: \"0\", respBytes: \"0\", \
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
    let store = schema.db.dns_store_writable().unwrap();

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

pub(crate) fn insert_dns_raw_event(
    store: &dyn WritableRawEventStore<Dns>,
    sensor: &str,
    timestamp: i64,
) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let dns_body = Dns {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_dns_body = bincode::serialize(&dns_body).unwrap();

    store.append(&key, &ser_dns_body).unwrap();
}

fn insert_malformed_dns_raw_event(
    store: &dyn WritableRawEventStore<MalformedDns>,
    sensor: &str,
    timestamp: i64,
) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let malformed_dns_body = MalformedDns {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_malformed_dns_body = bincode::serialize(&malformed_dns_body).unwrap();

    store.append(&key, &ser_malformed_dns_body).unwrap();
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
    let store = schema.db.malformed_dns_store_writable().unwrap();

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
    let store = schema.db.http_store_writable().unwrap();

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

pub(crate) fn insert_http_raw_event(
    store: &dyn WritableRawEventStore<Http>,
    sensor: &str,
    timestamp: i64,
) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let http_body = Http {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: Utc
            .with_ymd_and_hms(1992, 6, 5, 12, 0, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
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
    };
    let ser_http_body = bincode::serialize(&http_body).unwrap();

    store.append(&key, &ser_http_body).unwrap();
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
    let store = schema.db.rdp_store_writable().unwrap();

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

fn insert_rdp_raw_event(store: &dyn WritableRawEventStore<Rdp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let rdp_body = Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: Utc
            .with_ymd_and_hms(1992, 6, 5, 12, 0, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        cookie: "rdp_test".to_string(),
    };
    let ser_rdp_body = bincode::serialize(&rdp_body).unwrap();

    store.append(&key, &ser_rdp_body).unwrap();
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
    let store = schema.db.smtp_store_writable().unwrap();

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

fn insert_smtp_raw_event(store: &dyn WritableRawEventStore<Smtp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let smtp_body = Smtp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_smtp_body = bincode::serialize(&smtp_body).unwrap();

    store.append(&key, &ser_smtp_body).unwrap();
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
    let store = schema.db.ntlm_store_writable().unwrap();

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

fn insert_ntlm_raw_event(store: &dyn WritableRawEventStore<Ntlm>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ntlm_body = Ntlm {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_ntlm_body = bincode::serialize(&ntlm_body).unwrap();

    store.append(&key, &ser_ntlm_body).unwrap();
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
    let store = schema.db.kerberos_store_writable().unwrap();

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

fn insert_kerberos_raw_event(
    store: &dyn WritableRawEventStore<Kerberos>,
    sensor: &str,
    timestamp: i64,
) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let kerberos_body = Kerberos {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_kerberos_body = bincode::serialize(&kerberos_body).unwrap();

    store.append(&key, &ser_kerberos_body).unwrap();
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
    let store = schema.db.ssh_store_writable().unwrap();

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

fn insert_ssh_raw_event(store: &dyn WritableRawEventStore<Ssh>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ssh_body = Ssh {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_ssh_body = bincode::serialize(&ssh_body).unwrap();

    store.append(&key, &ser_ssh_body).unwrap();
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
    let store = schema.db.dce_rpc_store_writable().unwrap();

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

fn insert_dce_rpc_raw_event(
    store: &dyn WritableRawEventStore<DceRpc>,
    sensor: &str,
    timestamp: i64,
) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let dce_rpc_body = DceRpc {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        rtt: 3,
        named_pipe: "named_pipe".to_string(),
        endpoint: "endpoint".to_string(),
        operation: "operation".to_string(),
    };
    let ser_dce_rpc_body = bincode::serialize(&dce_rpc_body).unwrap();

    store.append(&key, &ser_dce_rpc_body).unwrap();
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
    let store = schema.db.ftp_store_writable().unwrap();

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

fn insert_ftp_raw_event(store: &dyn WritableRawEventStore<Ftp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ftp_body = Ftp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_ftp_body = bincode::serialize(&ftp_body).unwrap();

    store.append(&key, &ser_ftp_body).unwrap();
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
    let store = schema.db.mqtt_store_writable().unwrap();

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

fn insert_mqtt_raw_event(store: &dyn WritableRawEventStore<Mqtt>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let mqtt_body = Mqtt {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_mqtt_body = bincode::serialize(&mqtt_body).unwrap();

    store.append(&key, &ser_mqtt_body).unwrap();
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
    let store = schema.db.ldap_store_writable().unwrap();

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

fn insert_ldap_raw_event(store: &dyn WritableRawEventStore<Ldap>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ldap_body = Ldap {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_ldap_body = bincode::serialize(&ldap_body).unwrap();

    store.append(&key, &ser_ldap_body).unwrap();
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
    let store = schema.db.tls_store_writable().unwrap();

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

fn insert_tls_raw_event(store: &dyn WritableRawEventStore<Tls>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tls_body = Tls {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_tls_body = bincode::serialize(&tls_body).unwrap();

    store.append(&key, &ser_tls_body).unwrap();
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
    let store = schema.db.smb_store_writable().unwrap();

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

fn insert_smb_raw_event(store: &dyn WritableRawEventStore<Smb>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let smb_body = Smb {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_smb_body = bincode::serialize(&smb_body).unwrap();

    store.append(&key, &ser_smb_body).unwrap();
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
    let store = schema.db.nfs_store_writable().unwrap();

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

fn insert_nfs_raw_event(store: &dyn WritableRawEventStore<Nfs>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let nfs_body = Nfs {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        read_files: vec![],
        write_files: vec![],
    };
    let ser_nfs_body = bincode::serialize(&nfs_body).unwrap();

    store.append(&key, &ser_nfs_body).unwrap();
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
    let store = schema.db.bootp_store_writable().unwrap();

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

fn insert_bootp_raw_event(store: &dyn WritableRawEventStore<Bootp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let bootp_body = Bootp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_bootp_body = bincode::serialize(&bootp_body).unwrap();

    store.append(&key, &ser_bootp_body).unwrap();
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
    let store = schema.db.dhcp_store_writable().unwrap();

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

fn insert_dhcp_raw_event(store: &dyn WritableRawEventStore<Dhcp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let dhcp_body = Dhcp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_dhcp_body = bincode::serialize(&dhcp_body).unwrap();

    store.append(&key, &ser_dhcp_body).unwrap();
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
    let store = schema.db.radius_store_writable().unwrap();

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

fn insert_radius_raw_event(
    store: &dyn WritableRawEventStore<Radius>,
    sensor: &str,
    timestamp: i64,
) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let radius_body = Radius {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 1812,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 1813,
        proto: 17,
        start_time: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
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
    };
    let ser_radius_body = bincode::serialize(&radius_body).unwrap();

    store.append(&key, &ser_radius_body).unwrap();
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
    let store = schema.db.conn_store_writable().unwrap();

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
    store: &dyn WritableRawEventStore<Conn>,
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
    let ser_conn_body = bincode::serialize(&conn_body).unwrap();
    store.append(&key, &ser_conn_body).unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn union() {
    let schema = TestSchema::new();
    let conn_store = schema.db.conn_store_writable().unwrap();
    let dns_store = schema.db.dns_store_writable().unwrap();
    let http_store = schema.db.http_store_writable().unwrap();
    let rdp_store = schema.db.rdp_store_writable().unwrap();
    let ntlm_store = schema.db.ntlm_store_writable().unwrap();
    let kerberos_store = schema.db.kerberos_store_writable().unwrap();
    let ssh_store = schema.db.ssh_store_writable().unwrap();
    let dce_rpc_store = schema.db.dce_rpc_store_writable().unwrap();
    let ftp_store = schema.db.ftp_store_writable().unwrap();
    let mqtt_store = schema.db.mqtt_store_writable().unwrap();
    let ldap_store = schema.db.ldap_store_writable().unwrap();
    let tls_store = schema.db.tls_store_writable().unwrap();
    let smb_store = schema.db.smb_store_writable().unwrap();
    let nfs_store = schema.db.nfs_store_writable().unwrap();
    let smtp_store = schema.db.smtp_store_writable().unwrap();
    let bootp_store = schema.db.bootp_store_writable().unwrap();
    let dhcp_store = schema.db.dhcp_store_writable().unwrap();

    insert_conn_raw_event(
        &conn_store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_dns_raw_event(
        &dns_store,
        "src 1",
        Utc.with_ymd_and_hms(2021, 1, 1, 0, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_http_raw_event(
        &http_store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 6, 1, 0, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_rdp_raw_event(
        &rdp_store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 1, 5, 0, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_ntlm_raw_event(
        &ntlm_store,
        "src 1",
        Utc.with_ymd_and_hms(2022, 1, 5, 0, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_kerberos_raw_event(
        &kerberos_store,
        "src 1",
        Utc.with_ymd_and_hms(2023, 1, 5, 0, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_ssh_raw_event(
        &ssh_store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_dce_rpc_raw_event(
        &dce_rpc_store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 1, 5, 6, 5, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_ftp_raw_event(
        &ftp_store,
        "src 1",
        Utc.with_ymd_and_hms(2023, 1, 5, 12, 12, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_mqtt_raw_event(
        &mqtt_store,
        "src 1",
        Utc.with_ymd_and_hms(2023, 1, 5, 12, 12, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_ldap_raw_event(
        &ldap_store,
        "src 1",
        Utc.with_ymd_and_hms(2023, 1, 6, 12, 12, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_tls_raw_event(
        &tls_store,
        "src 1",
        Utc.with_ymd_and_hms(2023, 1, 6, 11, 11, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_smb_raw_event(
        &smb_store,
        "src 1",
        Utc.with_ymd_and_hms(2023, 1, 6, 12, 12, 10)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_nfs_raw_event(
        &nfs_store,
        "src 1",
        Utc.with_ymd_and_hms(2023, 1, 6, 12, 13, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_smtp_raw_event(
        &smtp_store,
        "src 1",
        Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 5)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_bootp_raw_event(
        &bootp_store,
        "src 1",
        Utc.with_ymd_and_hms(2019, 12, 31, 23, 59, 59)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_dhcp_raw_event(
        &dhcp_store,
        "src 1",
        Utc.with_ymd_and_hms(2023, 1, 6, 12, 13, 10)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap(),
    );

    // order: bootp, ssh, smtp, conn, rdp, dce_rpc, http, dns, ntlm, kerberos, ftp, mqtt, tls, ldap, smb, nfs, dhcp
    let query = r#"
    {
        networkRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                sensor: "src 1"
            }
            first: 20
            ) {
            edges {
                node {
                    ... on ConnRawEvent {
                        time
                    }
                    ... on DnsRawEvent {
                        time
                    }
                    ... on HttpRawEvent {
                        time
                    }
                    ... on RdpRawEvent {
                        time
                    }
                    ... on NtlmRawEvent {
                        time
                    }
                    ... on KerberosRawEvent {
                        time
                    }
                    ... on SshRawEvent {
                        time
                    }
                    ... on DceRpcRawEvent {
                        time
                    }
                    ... on FtpRawEvent {
                        time
                    }
                    ... on MqttRawEvent {
                        time
                    }
                    ... on LdapRawEvent {
                        time
                    }
                    ... on TlsRawEvent {
                        time
                    }
                    ... on SmbRawEvent {
                        time
                    }
                    ... on NfsRawEvent {
                        time
                    }
                    ... on SmtpRawEvent {
                        time
                    }
                    ... on BootpRawEvent {
                        time
                    }
                    ... on DhcpRawEvent {
                        time
                    }
                    __typename
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{networkRawEvents: {edges: [{node: {time: \"2019-12-31T23:59:59+00:00\", __typename: \"BootpRawEvent\"}}, {node: {time: \"2020-01-01T00:00:01+00:00\", __typename: \"SshRawEvent\"}}, {node: {time: \"2020-01-01T00:00:05+00:00\", __typename: \"SmtpRawEvent\"}}, {node: {time: \"2020-01-01T00:01:01+00:00\", __typename: \"ConnRawEvent\"}}, {node: {time: \"2020-01-05T00:01:01+00:00\", __typename: \"RdpRawEvent\"}}, {node: {time: \"2020-01-05T06:05:00+00:00\", __typename: \"DceRpcRawEvent\"}}, {node: {time: \"2020-06-01T00:01:01+00:00\", __typename: \"HttpRawEvent\"}}, {node: {time: \"2021-01-01T00:01:01+00:00\", __typename: \"DnsRawEvent\"}}, {node: {time: \"2022-01-05T00:01:01+00:00\", __typename: \"NtlmRawEvent\"}}, {node: {time: \"2023-01-05T00:01:01+00:00\", __typename: \"KerberosRawEvent\"}}, {node: {time: \"2023-01-05T12:12:00+00:00\", __typename: \"FtpRawEvent\"}}, {node: {time: \"2023-01-05T12:12:00+00:00\", __typename: \"MqttRawEvent\"}}, {node: {time: \"2023-01-06T11:11:00+00:00\", __typename: \"TlsRawEvent\"}}, {node: {time: \"2023-01-06T12:12:00+00:00\", __typename: \"LdapRawEvent\"}}, {node: {time: \"2023-01-06T12:12:10+00:00\", __typename: \"SmbRawEvent\"}}, {node: {time: \"2023-01-06T12:13:00+00:00\", __typename: \"NfsRawEvent\"}}, {node: {time: \"2023-01-06T12:13:10+00:00\", __typename: \"DhcpRawEvent\"}}]}}"
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
    let store = schema.db.http_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_http_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.conn_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_conn_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.dns_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_dns_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.malformed_dns_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap();
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap();
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap();
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap();

    insert_malformed_dns_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_malformed_dns_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_malformed_dns_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_malformed_dns_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.rdp_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_rdp_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.smtp_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_smtp_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.ntlm_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ntlm_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.kerberos_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_kerberos_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.ssh_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ssh_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.dce_rpc_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_dce_rpc_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.ftp_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ftp_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.mqtt_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_mqtt_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.ldap_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ldap_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.tls_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_tls_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.smb_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_smb_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.nfs_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_nfs_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.bootp_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_bootp_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_bootp_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_bootp_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_bootp_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.dhcp_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_dhcp_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_dhcp_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_dhcp_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_dhcp_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
    let store = schema.db.radius_store_writable().unwrap();

    let time1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let time2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let time3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let time4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_radius_raw_event(&store, "src 1", time1.timestamp_nanos_opt().unwrap());
    insert_radius_raw_event(&store, "src 1", time2.timestamp_nanos_opt().unwrap());
    insert_radius_raw_event(&store, "src 1", time3.timestamp_nanos_opt().unwrap());
    insert_radius_raw_event(&store, "src 1", time4.timestamp_nanos_opt().unwrap());

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
