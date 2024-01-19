use crate::graphql::tests::TestSchema;
use crate::storage::RawEventStore;
use chrono::{Duration, TimeZone, Utc};
use giganto_client::ingest::network::{
    Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
};
use mockito;
use std::mem;
use std::net::{IpAddr, SocketAddr};

#[tokio::test]
async fn conn_empty() {
    let schema = TestSchema::new();
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                source: "ingest_source_1"
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
                source: "ingest src 2"
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
                source: "src 1"
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
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
    );
}

fn insert_conn_raw_event(store: &RawEventStore<Conn>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let conn_body = Conn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        duration: tmp_dur.num_nanoseconds().unwrap(),
        service: "-".to_string(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
    };
    let ser_conn_body = bincode::serialize(&conn_body).unwrap();

    store.append(&key, &ser_conn_body).unwrap();
}

#[tokio::test]
async fn conn_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                source: "ingest src 2"
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
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 46378,
                            "respPort": 443,
                            "proto": 6,
                            "service": "-",
                            "duration": 324234,
                            "origBytes": 0,
                            "respBytes": 0,
                            "origPkts": 6,
                            "respPkts": 0
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
        "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
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
                source: "einsis"
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
        "{dnsRawEvents: {edges: [],pageInfo: {hasPreviousPage: false}}}"
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
                source: "src 2"
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
        "{dnsRawEvents: {edges: [],pageInfo: {hasPreviousPage: false}}}"
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
                source: "src 1"
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
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{dnsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"31.3.245.133\",origPort: 46378}}]}}"
    );
}

fn insert_dns_raw_event(store: &RawEventStore<Dns>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let dns_body = Dns {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
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

#[tokio::test]
async fn dns_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        dnsRawEvents(
            filter: {
                source: "src 2"
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
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "31.3.245.133",
                            "origPort": 46378,
                            "respPort": 443,
                            "lastTime": 123456789,
                            "proto": 6,
                            "query": "example.com",
                            "answer": [
                                "192.168.1.1"
                            ],
                            "transId": 12345,
                            "rtt": 567,
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
        "{dnsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"31.3.245.133\",origPort: 46378}}]}}"
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
                source: "einsis"
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
            source: "src 2"
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

    insert_http_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        httpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                source: "src 1"
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
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{httpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
    );
}

fn insert_http_raw_event(store: &RawEventStore<Http>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let http_body = Http {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        method: "POST".to_string(),
        host: "einsis".to_string(),
        uri: "/einsis.gif".to_string(),
        referrer: "einsis.com".to_string(),
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
        orig_filenames: Vec::new(),
        orig_mime_types: Vec::new(),
        resp_filenames: Vec::new(),
        resp_mime_types: Vec::new(),
    };
    let ser_http_body = bincode::serialize(&http_body).unwrap();

    store.append(&key, &ser_http_body).unwrap();
}

#[tokio::test]
async fn http_with_data_giganto_cluster() {
    // given
    let query = r#"
    {
        httpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                source: "src 2"
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
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 46378,
                            "respPort": 443,
                            "proto": 6,
                            "lastTime": 123456789,
                            "method": "GET",
                            "host": "example.com",
                            "uri": "/path/to/resource",
                            "referrer": "http://referrer.com",
                            "version": "HTTP/1.1",
                            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                            "requestLen": 1024,
                            "responseLen": 2048,
                            "statusCode": 200,
                            "statusMsg": "OK",
                            "username": "user123",
                            "password": "pass456",
                            "cookie": "session=abc123",
                            "contentEncoding": "gzip",
                            "contentType": "text/html",
                            "cacheControl": "no-cache",
                            "origFilenames": [
                                "file1.txt",
                                "file2.txt"
                            ],
                            "origMimeTypes": [
                                "text/plain",
                                "text/plain"
                            ],
                            "respFilenames": [
                                "response1.txt",
                                "response2.txt"
                            ],
                            "respMimeTypes": [
                                "text/plain",
                                "text/plain"
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
        "{httpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
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
                source: "einsis"
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
                source: "ingest src 2"
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

    insert_rdp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        rdpRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                source: "src 1"
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
        "{rdpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
    );
}

fn insert_rdp_raw_event(store: &RawEventStore<Rdp>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let rdp_body = Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
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
                source: "src 2"
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
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 46378,
                            "respPort": 54321,
                            "proto": 6,
                            "lastTime": 987654321,
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
        "{rdpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378}}]}}"
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
                source: "src 1"
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

fn insert_smtp_raw_event(store: &RawEventStore<Smtp>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let smtp_body = Smtp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        mailfrom: "mailfrom".to_string(),
        date: "date".to_string(),
        from: "from".to_string(),
        to: "to".to_string(),
        subject: "subject".to_string(),
        agent: "agent".to_string(),
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
                source: "src 2"
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
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 25,
                            "respPort": 587,
                            "proto": 6,
                            "lastTime": 987654321,
                            "mailfrom": "sender@example.com",
                            "date": "2023-11-16T15:03:45+00:00",
                            "from": "sender@example.com",
                            "to": "recipient@example.com",
                            "subject": "Test Email",
                            "agent": "SMTP Client 1.0"
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
                source: "src 1"
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

fn insert_ntlm_raw_event(store: &RawEventStore<Ntlm>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ntlm_body = Ntlm {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        username: "bly".to_string(),
        hostname: "host".to_string(),
        domainname: "domain".to_string(),
        server_nb_computer_name: "NB".to_string(),
        server_dns_computer_name: "dns".to_string(),
        server_tree_name: "tree".to_string(),
        success: "tf".to_string(),
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
                source: "src 2"
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
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.1.200",
                            "origPort": 12345,
                            "respPort": 6789,
                            "proto": 6,
                            "lastTime": 987654321,
                            "username": "john_doe",
                            "hostname": "client_machine",
                            "domainname": "example.com",
                            "serverNbComputerName": "server_nb_computer",
                            "serverDnsComputerName": "server_dns_computer",
                            "serverTreeName": "server_tree",
                            "success": "true"
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
                source: "src 1"
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

fn insert_kerberos_raw_event(store: &RawEventStore<Kerberos>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let kerberos_body = Kerberos {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
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
                source: "src 2"
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
            "kerberosRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.1.200",
                            "origPort": 12345,
                            "respPort": 6789,
                            "proto": 17,
                            "lastTime": 987654321,
                            "clientTime": 123456789,
                            "serverTime": 987654321,
                            "errorCode": 0,
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
        "{kerberosRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
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
                source: "src 1"
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

fn insert_ssh_raw_event(store: &RawEventStore<Ssh>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ssh_body = Ssh {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        version: 01,
        auth_success: "auth_success".to_string(),
        auth_attempts: 3,
        direction: "direction".to_string(),
        client: "client".to_string(),
        server: "server".to_string(),
        cipher_alg: "cipher_alg".to_string(),
        mac_alg: "mac_alg".to_string(),
        compression_alg: "compression_alg".to_string(),
        kex_alg: "kex_alg".to_string(),
        host_key_alg: "host_key_alg".to_string(),
        host_key: "host_key".to_string(),
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
                source: "src 2"
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
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 22,
                            "respPort": 54321,
                            "proto": 6,
                            "lastTime": 987654321,
                            "version": 2,
                            "authSuccess": "true",
                            "authAttempts": 3,
                            "direction": "inbound",
                            "client": "ssh_client",
                            "server": "ssh_server",
                            "cipherAlg": "aes256-ctr",
                            "macAlg": "hmac-sha2-256",
                            "compressionAlg": "none",
                            "kexAlg": "diffie-hellman-group14-sha1",
                            "hostKeyAlg": "ssh-rsa",
                            "hostKey": "ssh_host_key"
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
                source: "src 1"
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

fn insert_dce_rpc_raw_event(store: &RawEventStore<DceRpc>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let dce_rpc_body = DceRpc {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
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
                source: "src 2"
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
            "dceRpcRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 135,
                            "respPort": 54321,
                            "proto": 6,
                            "lastTime": 987654321,
                            "rtt": 123456,
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
        "{dceRpcRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
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
                source: "src 1"
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

fn insert_ftp_raw_event(store: &RawEventStore<Ftp>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ftp_body = Ftp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        user: "einsis".to_string(),
        password: "aice".to_string(),
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
                source: "src 2"
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
            "ftpRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 21,
                            "respPort": 12345,
                            "proto": 6,
                            "lastTime": 987654321,
                            "user": "example_user",
                            "password": "example_password",
                            "command": "example_command",
                            "replyCode": "200",
                            "replyMsg": "Command OK",
                            "dataPassive": true,
                            "dataOrigAddr": "192.168.4.76",
                            "dataRespAddr": "192.168.4.76",
                            "dataRespPort": 54321,
                            "file": "example_file.txt",
                            "fileSize": 1024,
                            "fileId": "123456789"
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
        "{ftpRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
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
                source: "src 1"
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

fn insert_mqtt_raw_event(store: &RawEventStore<Mqtt>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let mqtt_body = Mqtt {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
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
                source: "src 2"
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
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 1883,
                            "respPort": 5678,
                            "proto": 6,
                            "lastTime": 987654321,
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
                source: "src 1"
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

fn insert_ldap_raw_event(store: &RawEventStore<Ldap>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ldap_body = Ldap {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
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
                source: "src 2"
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
            "ldapRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 389,
                            "respPort": 636,
                            "proto": 6,
                            "lastTime": 987654321,
                            "messageId": 123,
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
        "{ldapRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
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
                source: "src 1"
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

fn insert_tls_raw_event(store: &RawEventStore<Tls>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tls_body = Tls {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        server_name: "server_name".to_string(),
        alpn_protocol: "alpn_protocol".to_string(),
        ja3: "ja3".to_string(),
        version: "version".to_string(),
        cipher: 10,
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
                source: "src 2"
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
            "tlsRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 443,
                            "respPort": 54321,
                            "proto": 6,
                            "lastTime": 987654321,
                            "serverName": "example.com",
                            "alpnProtocol": "h2",
                            "ja3": "aabbccddeeff",
                            "version": "TLSv1.2",
                            "cipher": 256,
                            "ja3S": "1122334455",
                            "serial": "1234567890",
                            "subjectCountry": "US",
                            "subjectOrgName": "Organization",
                            "subjectCommonName": "CommonName",
                            "validityNotBefore": 1637076000,
                            "validityNotAfter": 1668612000,
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
        "{tlsRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
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
                source: "src 1"
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
        "{smbRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
    );
}

fn insert_smb_raw_event(store: &RawEventStore<Smb>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let smb_body = Smb {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        command: 0,
        path: "something/path".to_string(),
        service: "service".to_string(),
        file_name: "fine_name".to_string(),
        file_size: 10,
        resource_type: 20,
        fid: 30,
        create_time: 10000000,
        access_time: 20000000,
        write_time: 10000000,
        change_time: 20000000,
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
                source: "src 2"
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
            "smbRawEvents": {
                "pageInfo": {
                    "hasPreviousPage": true,
                    "hasNextPage": false
                },
                "edges": [
                    {
                        "cursor": "cGl0YTIwMjNNQlAAF5gitjR0HIM=",
                        "node": {
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.77",
                            "origPort": 445,
                            "respPort": 12345,
                            "proto": 6,
                            "lastTime": 987654321,
                            "command": 1,
                            "path": "\\share\\folder\\file.txt",
                            "service": "IPC",
                            "fileName": "file.txt",
                            "fileSize": 1024,
                            "resourceType": 1,
                            "fid": 123,
                            "createTime": 1609459200,
                            "accessTime": 1637076000,
                            "writeTime": 1668612000,
                            "changeTime": 1700148000
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
        "{smbRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\"}}]}}"
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
                source: "src 1"
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

fn insert_nfs_raw_event(store: &RawEventStore<Nfs>, source: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let nfs_body = Nfs {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
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
                source: "src 2"
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
                            "timestamp": "2023-11-16T15:03:45.291779203+00:00",
                            "origAddr": "192.168.4.76",
                            "respAddr": "192.168.4.76",
                            "origPort": 2049,
                            "respPort": 54321,
                            "proto": 6,
                            "lastTime": 987654321,
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
async fn conn_with_start_or_end() {
    let schema = TestSchema::new();
    let store = schema.db.conn_store().unwrap();

    insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        connRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2050-09-22T00:00:00Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.76" }
                origPort: { end: 46380 }
            }
            first: 1
        ) {
            edges {
                node {
                    origAddr,
                    respAddr,
                    origPort,
                    respPort,
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{connRawEvents: {edges: [{node: {origAddr: \"192.168.4.76\",respAddr: \"192.168.4.76\",origPort: 46378,respPort: 80}}]}}"
    );
}

#[tokio::test]
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

    // order: ssh, smtp, conn, rdp, dce_rpc, http, dns, ntlm, kerberos, ftp, mqtt, tls, ldap, smb, nfs
    let query = r#"
    {
        networkRawEvents(
            filter: {
                time: { start: "1992-06-05T00:00:00Z", end: "2025-09-22T00:00:00Z" }
                source: "src 1"
            }
            first: 20
            ) {
            edges {
                node {
                    ... on ConnRawEvent {
                        timestamp
                    }
                    ... on DnsRawEvent {
                        timestamp
                    }
                    ... on HttpRawEvent {
                        timestamp
                    }
                    ... on RdpRawEvent {
                        timestamp
                    }
                    ... on NtlmRawEvent {
                        timestamp
                    }
                    ... on KerberosRawEvent {
                        timestamp
                    }
                    ... on SshRawEvent {
                        timestamp
                    }
                    ... on DceRpcRawEvent {
                        timestamp
                    }
                    ... on FtpRawEvent {
                        timestamp
                    }
                    ... on MqttRawEvent {
                        timestamp
                    }
                    ... on LdapRawEvent {
                        timestamp
                    }
                    ... on TlsRawEvent {
                        timestamp
                    }
                    ... on SmbRawEvent {
                        timestamp
                    }
                    ... on NfsRawEvent {
                        timestamp
                    }
                    ... on SmtpRawEvent {
                        timestamp
                    }
                    __typename
                }
            }
        }
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{networkRawEvents: {edges: [{node: {timestamp: \"2020-01-01T00:00:01+00:00\",__typename: \"SshRawEvent\"}},{node: {timestamp: \"2020-01-01T00:00:05+00:00\",__typename: \"SmtpRawEvent\"}},{node: {timestamp: \"2020-01-01T00:01:01+00:00\",__typename: \"ConnRawEvent\"}},{node: {timestamp: \"2020-01-05T00:01:01+00:00\",__typename: \"RdpRawEvent\"}},{node: {timestamp: \"2020-01-05T06:05:00+00:00\",__typename: \"DceRpcRawEvent\"}},{node: {timestamp: \"2020-06-01T00:01:01+00:00\",__typename: \"HttpRawEvent\"}},{node: {timestamp: \"2021-01-01T00:01:01+00:00\",__typename: \"DnsRawEvent\"}},{node: {timestamp: \"2022-01-05T00:01:01+00:00\",__typename: \"NtlmRawEvent\"}},{node: {timestamp: \"2023-01-05T00:01:01+00:00\",__typename: \"KerberosRawEvent\"}},{node: {timestamp: \"2023-01-05T12:12:00+00:00\",__typename: \"FtpRawEvent\"}},{node: {timestamp: \"2023-01-05T12:12:00+00:00\",__typename: \"MqttRawEvent\"}},{node: {timestamp: \"2023-01-06T11:11:00+00:00\",__typename: \"TlsRawEvent\"}},{node: {timestamp: \"2023-01-06T12:12:00+00:00\",__typename: \"LdapRawEvent\"}},{node: {timestamp: \"2023-01-06T12:12:10+00:00\",__typename: \"SmbRawEvent\"}},{node: {timestamp: \"2023-01-06T12:13:00+00:00\",__typename: \"NfsRawEvent\"}}]}}");
}

#[tokio::test]
async fn search_empty() {
    let schema = TestSchema::new();
    let query = r#"
    {
        searchHttpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 46377, end: 46380 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
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

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_http_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_http_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchHttpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchHttpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_conn_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.conn_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_conn_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchConnRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchConnRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_conn_with_data_giganto_cluster() {
    let query = r#"
    {
        searchConnRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
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
        "{searchConnRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_dns_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.dns_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_dns_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchDnsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 70, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchDnsRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_dns_with_data_giganto_cluster() {
    let query = r#"
    {
        searchDnsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 70, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
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
        "{searchDnsRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_rdp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.rdp_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_rdp_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchRdpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchRdpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_rdp_with_data_giganto_cluster() {
    let query = r#"
    {
        searchRdpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
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
        "{searchRdpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_smtp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.smtp_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_smtp_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchSmtpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchSmtpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_smtp_with_data_giganto_cluster() {
    let query = r#"
    {
        searchSmtpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
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
        "{searchSmtpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_ntlm_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ntlm_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ntlm_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchNtlmRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchNtlmRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_ntlm_with_data_giganto_cluster() {
    let query = r#"
    {
        searchNtlmRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
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
        "{searchNtlmRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_kerberos_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.kerberos_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_kerberos_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchKerberosRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchKerberosRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_kerberos_with_data_giganto_cluster() {
    let query = r#"
    {
        searchKerberosRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 2"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
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
        "{searchKerberosRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn search_ssh_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ssh_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ssh_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchSshRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchSshRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_dce_rpc_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.dce_rpc_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_dce_rpc_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchDceRpcRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchDceRpcRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_ftp_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ftp_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ftp_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchFtpRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchFtpRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_mqtt_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.mqtt_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_mqtt_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchMqttRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchMqttRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_ldap_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.ldap_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_ldap_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchLdapRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchLdapRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_tls_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.tls_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_tls_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchTlsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchTlsRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_smb_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.smb_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_smb_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchSmbRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchSmbRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}

#[tokio::test]
async fn search_nfs_with_data() {
    let schema = TestSchema::new();
    let store = schema.db.nfs_store().unwrap();

    let timestamp1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap(); //2020-01-01T00:00:01Z
    let timestamp2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 1, 1).unwrap(); //2020-01-01T00:01:01Z
    let timestamp3 = Utc.with_ymd_and_hms(2020, 1, 1, 1, 1, 1).unwrap(); //2020-01-01T01:01:01Z
    let timestamp4 = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 1).unwrap(); //2020-01-02T00:00:01Z

    insert_nfs_raw_event(&store, "src 1", timestamp1.timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, "src 1", timestamp2.timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, "src 1", timestamp3.timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(&store, "src 1", timestamp4.timestamp_nanos_opt().unwrap());

    let query = r#"
    {
        searchNfsRawEvents(
            filter: {
                time: { start: "2020-01-01T00:01:01Z", end: "2020-01-01T01:01:02Z" }
                source: "src 1"
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "31.3.245.130", end: "31.3.245.135" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 75, end: 85 }
                timestamps:["2020-01-01T00:00:01Z","2020-01-01T00:01:01Z","2020-01-01T01:01:01Z","2020-01-02T00:00:01Z"]
            }
        )
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(
        res.data.to_string(),
        "{searchNfsRawEvents: [\"2020-01-01T00:01:01+00:00\",\"2020-01-01T01:01:01+00:00\"]}"
    );
}
