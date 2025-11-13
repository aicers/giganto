use std::mem;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use giganto_client::ingest::{
    log::{Log, OpLog, OpLogLevel},
    network::{
        Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, FtpCommand, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm,
        Rdp, Smb, Smtp, Ssh, Tls,
    },
    timeseries::PeriodicTimeSeries,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::bincode_utils::{decode_legacy, encode_legacy};
use crate::comm::ingest::generation::SequenceGenerator;
use crate::graphql::tests::TestSchema;
use crate::storage::RawEventStore;

fn ip(addr: &str) -> IpAddr {
    addr.parse().expect("invalid test IP address")
}

#[tokio::test]
async fn invalid_query() {
    let schema = TestSchema::new();

    // invalid filter combine1 (log + addr)
    let query = r#"
    {
        export(
            filter:{
                protocol: "log",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "null");

    // invalid filter combine2 (network proto + kind)
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "src1",
                kind: "log1"
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "null");

    // invalid export format
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "src1",
            }
            ,exportType:"ppt")
    }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "null");

    // invalid protocol format
    let query = r#"
     {
         export(
             filter:{
                 protocol: "invalid_proto",
                 sensorId: "src1",
             }
             ,exportType:"json")
     }"#;
    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "null");
}

#[tokio::test]
async fn export_conn() {
    let schema = TestSchema::new();
    let store = schema.db.conn_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_conn_raw_event(&store, "src1", csv_timestamp);
    insert_conn_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "conn", None, "csv");

    let csv_event: Conn = fetch_event(&store, "src1", csv_timestamp);
    assert_eq!(csv_event.start_time, expected_time);
    assert_eq!(csv_event.end_time, expected_time);
    assert_eq!(csv_event.duration, 1_000_000_000);
    assert_eq!(csv_event.orig_addr.to_string(), "192.168.4.76");
    assert_eq!(csv_event.resp_addr.to_string(), "192.168.4.76");
    assert_eq!(csv_event.orig_bytes, 77);
    assert_eq!(csv_event.resp_bytes, 295);
    assert_eq!(csv_event.orig_pkts, 397);
    assert_eq!(csv_event.resp_pkts, 511);
    assert_eq!(csv_event.orig_l2_bytes, 21515);
    assert_eq!(csv_event.resp_l2_bytes, 27889);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "conn", None, "json");

    let json_event: Conn = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_eq!(json_event.start_time, expected_time);
    assert_eq!(json_event.end_time, expected_time);
    assert_eq!(json_event.duration, 1_000_000_000);
    assert_eq!(json_event.orig_addr.to_string(), "192.168.4.76");
    assert_eq!(json_event.resp_addr.to_string(), "192.168.4.76");
    assert_eq!(json_event.orig_bytes, 77);
    assert_eq!(json_event.resp_bytes, 295);
    assert_eq!(json_event.orig_pkts, 397);
    assert_eq!(json_event.resp_pkts, 511);
    assert_eq!(json_event.orig_l2_bytes, 21515);
    assert_eq!(json_event.resp_l2_bytes, 27889);
}

fn insert_conn_raw_event(store: &RawEventStore<Conn>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let conn_body = Conn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        conn_state: "sf".to_string(),
        start_time: chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap()),
        end_time: chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap()),
        duration: 1_000_000_000,
        service: "-".to_string(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
        orig_l2_bytes: 21515,
        resp_l2_bytes: 27889,
    };
    let ser_conn_body = encode_legacy(&conn_body).unwrap();

    store.append(&key, &ser_conn_body).unwrap();
}

#[tokio::test]
async fn export_dns() {
    let schema = TestSchema::new();
    let store = schema.db.dns_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_dns_raw_event(&store, "src1", csv_timestamp);
    insert_dns_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dns",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "dns", None, "csv");

    let csv_event: Dns = fetch_event(&store, "src1", csv_timestamp);
    assert_dns_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dns",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "dns", None, "json");

    let json_event: Dns = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_dns_event(&json_event, expected_time);
}

fn insert_dns_raw_event(store: &RawEventStore<Dns>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let dns_body = Dns {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time,
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
    let ser_dns_body = encode_legacy(&dns_body).unwrap();

    store.append(&key, &ser_dns_body).unwrap();
}

fn assert_dns_event(event: &Dns, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("31.3.245.133"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.query, "Hello Server Hello Server Hello Server");
    assert_eq!(event.answer, vec!["1.1.1.1".to_string()]);
    assert_eq!(event.trans_id, 1);
    assert_eq!(event.rtt, 1);
    assert_eq!(event.qclass, 0);
    assert_eq!(event.qtype, 0);
    assert_eq!(event.rcode, 0);
    assert!(!event.aa_flag);
    assert!(!event.tc_flag);
    assert!(!event.rd_flag);
    assert!(!event.ra_flag);
    assert_eq!(event.ttl, vec![1; 5]);
}

#[tokio::test]
async fn export_http() {
    let schema = TestSchema::new();
    let store = schema.db.http_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_http_raw_event(&store, "src1", csv_timestamp);
    insert_http_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "http",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "http", None, "csv");

    let csv_event: Http = fetch_event(&store, "src1", csv_timestamp);
    assert_http_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "http",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "http", None, "json");

    let json_event: Http = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_http_event(&json_event, expected_time);
}

fn insert_http_raw_event(store: &RawEventStore<Http>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let http_body = Http {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: time,
        end_time: time,
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
    let ser_http_body = encode_legacy(&http_body).unwrap();

    store.append(&key, &ser_http_body).unwrap();
}

fn assert_http_event(event: &Http, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("192.168.4.76"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 6);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.method, "POST");
    assert_eq!(event.host, "cluml");
    assert_eq!(event.uri, "/cluml.gif");
    assert_eq!(event.referer, "cluml.com");
    assert!(event.version.is_empty());
    assert_eq!(event.user_agent, "giganto");
    assert_eq!(event.request_len, 0);
    assert_eq!(event.response_len, 0);
    assert_eq!(event.status_code, 200);
    assert!(event.status_msg.is_empty());
    assert!(event.username.is_empty());
    assert!(event.password.is_empty());
    assert!(event.cookie.is_empty());
    assert!(event.content_encoding.is_empty());
    assert!(event.content_type.is_empty());
    assert!(event.cache_control.is_empty());
    assert!(event.filenames.is_empty());
    assert!(event.mime_types.is_empty());
    assert!(event.body.is_empty());
    assert!(event.state.is_empty());
}

#[tokio::test]
async fn export_rdp() {
    let schema = TestSchema::new();
    let store = schema.db.rdp_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_rdp_raw_event(&store, "src1", csv_timestamp);
    insert_rdp_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "rdp",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "rdp", None, "csv");

    let csv_event: Rdp = fetch_event(&store, "src1", csv_timestamp);
    assert_rdp_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "rdp",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "rdp", None, "json");

    let json_event: Rdp = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_rdp_event(&json_event, expected_time);
}

fn insert_rdp_raw_event(store: &RawEventStore<Rdp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let rdp_body = Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: time,
        end_time: time,
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        cookie: "rdp_test".to_string(),
    };
    let ser_rdp_body = encode_legacy(&rdp_body).unwrap();

    store.append(&key, &ser_rdp_body).unwrap();
}

fn assert_rdp_event(event: &Rdp, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("192.168.4.76"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 6);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.cookie, "rdp_test");
}

#[tokio::test]
async fn export_smtp() {
    let schema = TestSchema::new();
    let store = schema.db.smtp_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_smtp_raw_event(&store, "src1", csv_timestamp);
    insert_smtp_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "smtp",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "smtp", None, "csv");

    let csv_event: Smtp = fetch_event(&store, "src1", csv_timestamp);
    assert_smtp_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "smtp",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "smtp", None, "json");

    let json_event: Smtp = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_smtp_event(&json_event, expected_time);
}

fn insert_smtp_raw_event(store: &RawEventStore<Smtp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let smtp_body = Smtp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: time,
        end_time: time,
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
    let ser_smtp_body = encode_legacy(&smtp_body).unwrap();

    store.append(&key, &ser_smtp_body).unwrap();
}

fn assert_smtp_event(event: &Smtp, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("192.168.4.76"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 6);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.mailfrom, "mailfrom");
    assert_eq!(event.date, "date");
    assert_eq!(event.from, "from");
    assert_eq!(event.to, "to");
    assert_eq!(event.subject, "subject");
    assert_eq!(event.agent, "agent");
    assert!(event.state.is_empty());
}

#[tokio::test]
async fn export_ntlm() {
    let schema = TestSchema::new();
    let store = schema.db.ntlm_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_ntlm_raw_event(&store, "src1", csv_timestamp);
    insert_ntlm_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ntlm",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "ntlm", None, "csv");

    let csv_event: Ntlm = fetch_event(&store, "src1", csv_timestamp);
    assert_ntlm_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ntlm",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "ntlm", None, "json");

    let json_event: Ntlm = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_ntlm_event(&json_event, expected_time);
}

fn insert_ntlm_raw_event(store: &RawEventStore<Ntlm>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let ntlm_body = Ntlm {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: time,
        end_time: time,
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
    let ser_ntlm_body = encode_legacy(&ntlm_body).unwrap();

    store.append(&key, &ser_ntlm_body).unwrap();
}

fn assert_ntlm_event(event: &Ntlm, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("192.168.4.76"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 6);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.username, "bly");
    assert_eq!(event.hostname, "host");
    assert_eq!(event.domainname, "domain");
    assert_eq!(event.success, "tf");
    assert_eq!(event.protocol, "protocol");
}

#[tokio::test]
async fn export_kerberos() {
    let schema = TestSchema::new();
    let store = schema.db.kerberos_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_kerberos_raw_event(&store, "src1", csv_timestamp);
    insert_kerberos_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "kerberos",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "kerberos", None, "csv");

    let csv_event: Kerberos = fetch_event(&store, "src1", csv_timestamp);
    assert_kerberos_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "kerberos",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "kerberos", None, "json");

    let json_event: Kerberos = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_kerberos_event(&json_event, expected_time);
}

fn insert_kerberos_raw_event(store: &RawEventStore<Kerberos>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let kerberos_body = Kerberos {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: time,
        end_time: time,
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
    let ser_kerberos_body = encode_legacy(&kerberos_body).unwrap();

    store.append(&key, &ser_kerberos_body).unwrap();
}

fn assert_kerberos_event(event: &Kerberos, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("192.168.4.76"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 6);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.client_time, 1);
    assert_eq!(event.server_time, 1);
    assert_eq!(event.error_code, 1);
    assert_eq!(event.client_realm, "client_realm");
    assert_eq!(event.cname_type, 1);
    assert_eq!(event.client_name, vec!["client_name".to_string()]);
    assert_eq!(event.realm, "realm");
    assert_eq!(event.sname_type, 1);
    assert_eq!(event.service_name, vec!["service_name".to_string()]);
}

#[tokio::test]
async fn export_ssh() {
    let schema = TestSchema::new();
    let store = schema.db.ssh_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_ssh_raw_event(&store, "src1", csv_timestamp);
    insert_ssh_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ssh",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "ssh", None, "csv");

    let csv_event: Ssh = fetch_event(&store, "src1", csv_timestamp);
    assert_ssh_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ssh",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "ssh", None, "json");

    let json_event: Ssh = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_ssh_event(&json_event, expected_time);
}
fn insert_ssh_raw_event(store: &RawEventStore<Ssh>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let ssh_body = Ssh {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: time,
        end_time: time,
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
    let ser_ssh_body = encode_legacy(&ssh_body).unwrap();

    store.append(&key, &ser_ssh_body).unwrap();
}

fn assert_ssh_event(event: &Ssh, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("192.168.4.76"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 6);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.client, "client");
    assert_eq!(event.server, "server");
    assert_eq!(event.cipher_alg, "cipher_alg");
    assert_eq!(event.mac_alg, "mac_alg");
    assert_eq!(event.compression_alg, "compression_alg");
    assert_eq!(event.kex_alg, "kex_alg");
    assert_eq!(event.host_key_alg, "host_key_alg");
    assert_eq!(event.hassh_algorithms, "hassh_algorithms");
    assert_eq!(event.hassh, "hassh");
    assert_eq!(event.hassh_server_algorithms, "hassh_server_algorithms");
    assert_eq!(event.hassh_server, "hassh_server");
    assert_eq!(event.client_shka, "client_shka");
    assert_eq!(event.server_shka, "server_shka");
}

#[tokio::test]
async fn export_dce_rpc() {
    let schema = TestSchema::new();
    let store = schema.db.dce_rpc_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_dce_rpc_raw_event(&store, "src1", csv_timestamp);
    insert_dce_rpc_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dce rpc",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "dce rpc", None, "csv");

    let csv_event: DceRpc = fetch_event(&store, "src1", csv_timestamp);
    assert_dce_rpc_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dce rpc",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "dce rpc", None, "json");

    let json_event: DceRpc = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_dce_rpc_event(&json_event, expected_time);
}
fn insert_dce_rpc_raw_event(store: &RawEventStore<DceRpc>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let dce_rpc_body = DceRpc {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: time,
        end_time: time,
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
    let ser_dce_rpc_body = encode_legacy(&dce_rpc_body).unwrap();

    store.append(&key, &ser_dce_rpc_body).unwrap();
}

fn assert_dce_rpc_event(event: &DceRpc, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("192.168.4.76"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 6);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.rtt, 3);
    assert_eq!(event.named_pipe, "named_pipe");
    assert_eq!(event.endpoint, "endpoint");
    assert_eq!(event.operation, "operation");
}

#[tokio::test]
async fn export_log() {
    let schema = TestSchema::new();
    let store = schema.db.log_store().unwrap();

    insert_log_raw_event(
        &store,
        "src1",
        Utc::now().timestamp_nanos_opt().unwrap(),
        "kind1",
        b"log1",
    );
    insert_log_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
        "kind2",
        b"log2",
    );

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "log",
                sensorId: "src1",
                kind: "kind1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "log", Some("kind1"), "csv");

    // export json file
    let query = r#"
            {
                export(
                    filter:{
                        protocol: "log",
                        sensorId: "ingest src 1",
                        kind: "kind2",
                        time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    }
                    ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "log", Some("kind2"), "json");
}

fn insert_log_raw_event(
    store: &RawEventStore<Log>,
    sensor: &str,
    timestamp: i64,
    kind: &str,
    body: &[u8],
) {
    let mut key: Vec<u8> = Vec::new();
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend_from_slice(kind.as_bytes());
    key.push(0);
    key.extend_from_slice(&timestamp.to_be_bytes());
    let log_body = Log {
        kind: kind.to_string(),
        log: body.to_vec(),
    };
    let value = encode_legacy(&log_body).unwrap();
    store.append(&key, &value).unwrap();
}

#[tokio::test]
async fn export_time_series() {
    let schema = TestSchema::new();
    let store = schema.db.periodic_time_series_store().unwrap();

    insert_time_series(
        &store,
        "src1",
        Utc::now().timestamp_nanos_opt().unwrap(),
        vec![0.0; 12],
    );
    insert_time_series(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
        vec![0.0; 12],
    );

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "periodic time series",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "periodic time series", None, "csv");

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "periodic time series",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "periodic time series", None, "json");
}

fn insert_time_series(
    store: &RawEventStore<PeriodicTimeSeries>,
    id: &str,
    start: i64,
    data: Vec<f64>,
) {
    let mut key: Vec<u8> = Vec::new();
    key.extend_from_slice(id.as_bytes());
    key.push(0);
    key.extend_from_slice(&start.to_be_bytes());
    let time_series_data = PeriodicTimeSeries {
        id: id.to_string(),
        data,
    };
    let value = encode_legacy(&time_series_data).unwrap();
    store.append(&key, &value).unwrap();
}

#[tokio::test]
async fn export_op_log() {
    let schema = TestSchema::new();
    let store = schema.db.op_log_store().unwrap();
    let generator: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();

    insert_op_log_raw_event(&store, "agent1", "src1", 1, &generator);
    insert_op_log_raw_event(&store, "agent2", "src1", 1, &generator);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "op_log",
                sensorId: "src1",
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "op_log", None, "csv");

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "op_log",
                sensorId: "src1",
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "op_log", None, "json");
}

fn insert_op_log_raw_event(
    store: &RawEventStore<'_, OpLog>,
    agent_name: &str,
    sensor: &str,
    timestamp: i64,
    generator: &OnceLock<Arc<SequenceGenerator>>,
) {
    let generator = generator.get_or_init(SequenceGenerator::init_generator);
    let sequence_number = generator.generate_sequence_number();

    let mut key: Vec<u8> = Vec::new();
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.extend_from_slice(&sequence_number.to_be_bytes());

    let op_log_body = OpLog {
        sensor: sensor.to_string(),
        agent_name: agent_name.to_string(),
        log_level: OpLogLevel::Info,
        contents: "op_log".to_string(),
    };

    let value = encode_legacy(&op_log_body).unwrap();

    store.append(&key, &value).unwrap();
}

#[tokio::test]
async fn export_ftp() {
    let schema = TestSchema::new();
    let store = schema.db.ftp_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_ftp_raw_event(&store, "src1", csv_timestamp);
    insert_ftp_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ftp",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "ftp", None, "csv");

    let csv_event: Ftp = fetch_event(&store, "src1", csv_timestamp);
    assert_ftp_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ftp",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "ftp", None, "json");

    let json_event: Ftp = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_ftp_event(&json_event, expected_time);
}

fn insert_ftp_raw_event(store: &RawEventStore<Ftp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let ftp_body = Ftp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time,
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
    let ser_ftp_body = encode_legacy(&ftp_body).unwrap();

    store.append(&key, &ser_ftp_body).unwrap();
}

fn assert_ftp_event(event: &Ftp, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("31.3.245.133"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.user, "cluml");
    assert_eq!(event.password, "aice");
    assert_eq!(event.commands.len(), 1);
    let command = &event.commands[0];
    assert_eq!(command.command, "command");
    assert_eq!(command.reply_code, "500");
    assert_eq!(command.reply_msg, "reply_message");
    assert!(!command.data_passive);
    assert_eq!(command.data_orig_addr, ip("192.168.4.76"));
    assert_eq!(command.data_resp_addr, ip("31.3.245.133"));
    assert_eq!(command.data_resp_port, 80);
    assert_eq!(command.file, "ftp_file");
    assert_eq!(command.file_size, 100);
    assert_eq!(command.file_id, "1");
}

#[tokio::test]
async fn export_mqtt() {
    let schema = TestSchema::new();
    let store = schema.db.mqtt_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_mqtt_raw_event(&store, "src1", csv_timestamp);
    insert_mqtt_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "mqtt",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "mqtt", None, "csv");

    let csv_event: Mqtt = fetch_event(&store, "src1", csv_timestamp);
    assert_mqtt_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "mqtt",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "mqtt", None, "json");

    let json_event: Mqtt = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_mqtt_event(&json_event, expected_time);
}

fn insert_mqtt_raw_event(store: &RawEventStore<Mqtt>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let mqtt_body = Mqtt {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time,
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        protocol: "protocol".to_string(),
        version: 1,
        client_id: "client".to_string(),
        connack_reason: 1,
        subscribe: vec!["subscribe".to_string()],
        suback_reason: vec![1],
    };
    let ser_mqtt_body = encode_legacy(&mqtt_body).unwrap();

    store.append(&key, &ser_mqtt_body).unwrap();
}

fn assert_mqtt_event(event: &Mqtt, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("31.3.245.133"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.protocol, "protocol");
    assert_eq!(event.version, 1);
    assert_eq!(event.client_id, "client");
    assert_eq!(event.connack_reason, 1);
    assert_eq!(event.subscribe, vec!["subscribe".to_string()]);
    assert_eq!(event.suback_reason, vec![1]);
}

#[tokio::test]
async fn export_ldap() {
    let schema = TestSchema::new();
    let store = schema.db.ldap_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_ldap_raw_event(&store, "src1", csv_timestamp);
    insert_ldap_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ldap",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "ldap", None, "csv");

    let csv_event: Ldap = fetch_event(&store, "src1", csv_timestamp);
    assert_ldap_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ldap",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "ldap", None, "json");

    let json_event: Ldap = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_ldap_event(&json_event, expected_time);
}

fn insert_ldap_raw_event(store: &RawEventStore<Ldap>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let ldap_body = Ldap {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time,
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
    let ser_ldap_body = encode_legacy(&ldap_body).unwrap();

    store.append(&key, &ser_ldap_body).unwrap();
}

fn assert_ldap_event(event: &Ldap, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("31.3.245.133"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.message_id, 1);
    assert_eq!(event.version, 1);
    assert_eq!(event.opcode, vec!["opcode".to_string()]);
    assert_eq!(event.result, vec!["result".to_string()]);
    assert!(event.diagnostic_message.is_empty());
    assert!(event.object.is_empty());
    assert!(event.argument.is_empty());
}

#[tokio::test]
async fn export_tls() {
    let schema = TestSchema::new();
    let store = schema.db.tls_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_tls_raw_event(&store, "src1", csv_timestamp);
    insert_tls_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "tls",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "tls", None, "csv");

    let csv_event: Tls = fetch_event(&store, "src1", csv_timestamp);
    assert_tls_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "tls",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "tls", None, "json");

    let json_event: Tls = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_tls_event(&json_event, expected_time);
}

fn insert_tls_raw_event(store: &RawEventStore<Tls>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let tls_body = Tls {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time,
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
    let ser_tls_body = encode_legacy(&tls_body).unwrap();

    store.append(&key, &ser_tls_body).unwrap();
}

fn assert_tls_event(event: &Tls, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("31.3.245.133"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.server_name, "server_name");
    assert_eq!(event.alpn_protocol, "alpn_protocol");
    assert_eq!(event.ja3, "ja3");
    assert_eq!(event.version, "version");
    assert_eq!(event.client_cipher_suites, vec![771, 769, 770]);
    assert_eq!(event.client_extensions, vec![0, 1, 2]);
    assert_eq!(event.cipher, 10);
    assert_eq!(event.extensions, vec![0, 1]);
    assert_eq!(event.ja3s, "ja3s");
    assert_eq!(event.serial, "serial");
    assert_eq!(event.subject_country, "sub_country");
    assert_eq!(event.subject_org_name, "sub_org");
    assert_eq!(event.subject_common_name, "sub_comm");
    assert_eq!(event.validity_not_before, 11);
    assert_eq!(event.validity_not_after, 12);
    assert_eq!(event.subject_alt_name, "sub_alt");
    assert_eq!(event.issuer_country, "issuer_country");
    assert_eq!(event.issuer_org_name, "issuer_org");
    assert_eq!(event.issuer_org_unit_name, "issuer_org_unit");
    assert_eq!(event.issuer_common_name, "issuer_comm");
    assert_eq!(event.last_alert, 13);
}

#[tokio::test]
async fn export_smb() {
    let schema = TestSchema::new();
    let store = schema.db.smb_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_smb_raw_event(&store, "src1", csv_timestamp);
    insert_smb_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "smb",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "smb", None, "csv");

    let csv_event: Smb = fetch_event(&store, "src1", csv_timestamp);
    assert_smb_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "smb",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "smb", None, "json");

    let json_event: Smb = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_smb_event(&json_event, expected_time);
}

fn insert_smb_raw_event(store: &RawEventStore<Smb>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let smb_body = Smb {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time,
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
    let ser_smb_body = encode_legacy(&smb_body).unwrap();

    store.append(&key, &ser_smb_body).unwrap();
}

fn assert_smb_event(event: &Smb, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("31.3.245.133"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.command, 0);
    assert_eq!(event.path, "something/path");
    assert_eq!(event.service, "service");
    assert_eq!(event.file_name, "fine_name");
    assert_eq!(event.file_size, 10);
    assert_eq!(event.resource_type, 20);
    assert_eq!(event.fid, 30);
    assert_eq!(event.create_time, 10_000_000);
    assert_eq!(event.access_time, 20_000_000);
    assert_eq!(event.write_time, 10_000_000);
    assert_eq!(event.change_time, 20_000_000);
}

#[tokio::test]
async fn export_nfs() {
    let schema = TestSchema::new();
    let store = schema.db.nfs_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_nfs_raw_event(&store, "src1", csv_timestamp);
    insert_nfs_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "nfs",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "nfs", None, "csv");

    let csv_event: Nfs = fetch_event(&store, "src1", csv_timestamp);
    assert_nfs_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "nfs",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "nfs", None, "json");

    let json_event: Nfs = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_nfs_event(&json_event, expected_time);
}

fn insert_nfs_raw_event(store: &RawEventStore<Nfs>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    let nfs_body = Nfs {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time,
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        read_files: vec![],
        write_files: vec![],
    };
    let ser_nfs_body = encode_legacy(&nfs_body).unwrap();

    store.append(&key, &ser_nfs_body).unwrap();
}

fn assert_nfs_event(event: &Nfs, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("31.3.245.133"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert!(event.read_files.is_empty());
    assert!(event.write_files.is_empty());
}

#[tokio::test]
async fn export_bootp() {
    let schema = TestSchema::new();
    let store = schema.db.bootp_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_bootp_raw_event(&store, "src1", csv_timestamp);
    insert_bootp_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "bootp",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "bootp", None, "csv");

    let csv_event: Bootp = fetch_event(&store, "src1", csv_timestamp);
    assert_bootp_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "bootp",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "bootp", None, "json");

    let json_event: Bootp = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_bootp_event(&json_event, expected_time);
}

fn insert_bootp_raw_event(store: &RawEventStore<Bootp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let bootp_body = Bootp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time,
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
    let ser_bootp_body = encode_legacy(&bootp_body).unwrap();

    store.append(&key, &ser_bootp_body).unwrap();
}

fn assert_bootp_event(event: &Bootp, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("31.3.245.133"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.op, 0);
    assert_eq!(event.htype, 0);
    assert_eq!(event.hops, 0);
    assert_eq!(event.xid, 0);
    assert_eq!(event.ciaddr, ip("192.168.4.1"));
    assert_eq!(event.yiaddr, ip("192.168.4.2"));
    assert_eq!(event.siaddr, ip("192.168.4.3"));
    assert_eq!(event.giaddr, ip("192.168.4.4"));
    assert_eq!(event.chaddr, vec![0, 1, 2]);
    assert_eq!(event.sname, "sname");
    assert_eq!(event.file, "file");
}

#[tokio::test]
async fn export_dhcp() {
    let schema = TestSchema::new();
    let store = schema.db.dhcp_store().unwrap();

    let csv_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let json_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    let tmp_dur = Duration::nanoseconds(12345);
    let expected_time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());

    insert_dhcp_raw_event(&store, "src1", csv_timestamp);
    insert_dhcp_raw_event(&store, "ingest src 1", json_timestamp);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dhcp",
                sensorId: "src1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    let csv_data = res.data.into_json().unwrap();
    let csv_path = export_path_from_response(&csv_data);
    assert_export_filename(&csv_path, "dhcp", None, "csv");

    let csv_event: Dhcp = fetch_event(&store, "src1", csv_timestamp);
    assert_dhcp_event(&csv_event, expected_time);

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dhcp",
                sensorId: "ingest src 1",
                time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    let json_data = res.data.into_json().unwrap();
    let json_path = export_path_from_response(&json_data);
    assert_export_filename(&json_path, "dhcp", None, "json");

    let json_event: Dhcp = fetch_event(&store, "ingest src 1", json_timestamp);
    assert_dhcp_event(&json_event, expected_time);
}

fn insert_dhcp_raw_event(store: &RawEventStore<Dhcp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let tmp_dur = Duration::nanoseconds(12345);
    let time = chrono::DateTime::from_timestamp_nanos(tmp_dur.num_nanoseconds().unwrap());
    let dhcp_body = Dhcp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: time,
        end_time: time,
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
    let ser_dhcp_body = encode_legacy(&dhcp_body).unwrap();

    store.append(&key, &ser_dhcp_body).unwrap();
}

fn assert_dhcp_event(event: &Dhcp, expected_time: DateTime<Utc>) {
    assert_eq!(event.start_time, expected_time);
    assert_eq!(event.end_time, expected_time);
    assert_eq!(event.duration, 1_000_000_000);
    assert_eq!(event.orig_addr, ip("192.168.4.76"));
    assert_eq!(event.orig_port, 46378);
    assert_eq!(event.resp_addr, ip("31.3.245.133"));
    assert_eq!(event.resp_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.orig_pkts, 1);
    assert_eq!(event.resp_pkts, 1);
    assert_eq!(event.orig_l2_bytes, 100);
    assert_eq!(event.resp_l2_bytes, 200);
    assert_eq!(event.msg_type, 0);
    assert_eq!(event.ciaddr, ip("192.168.4.1"));
    assert_eq!(event.yiaddr, ip("192.168.4.2"));
    assert_eq!(event.siaddr, ip("192.168.4.3"));
    assert_eq!(event.giaddr, ip("192.168.4.4"));
    assert_eq!(event.subnet_mask, ip("192.168.4.5"));
    assert_eq!(event.router, vec![ip("192.168.1.11"), ip("192.168.1.22")]);
    assert_eq!(
        event.domain_name_server,
        vec![ip("192.168.1.33"), ip("192.168.1.44")]
    );
    assert_eq!(event.req_ip_addr, ip("192.168.4.6"));
    assert_eq!(event.lease_time, 1);
    assert_eq!(event.server_id, ip("192.168.4.7"));
    assert_eq!(event.param_req_list, vec![0, 1, 2]);
    assert_eq!(event.message, "message");
    assert_eq!(event.renewal_time, 1);
    assert_eq!(event.rebinding_time, 1);
    assert_eq!(event.class_id, vec![0, 1, 2]);
    assert_eq!(event.client_id_type, 1);
    assert_eq!(event.client_id, vec![0, 1, 2]);
}

fn fetch_event<T: DeserializeOwned>(
    store: &RawEventStore<'_, T>,
    sensor: &str,
    timestamp: i64,
) -> T {
    let (_, _, raw) = store
        .batched_multi_get_with_sensor(sensor, &[timestamp])
        .into_iter()
        .next()
        .expect("expected at least one stored event");
    decode_legacy(&raw).expect("failed to decode stored event")
}

fn export_path_from_response(data: &Value) -> PathBuf {
    let export_str = data["export"]
        .as_str()
        .expect("export response should be a string");
    let (path, node) = export_str
        .rsplit_once('@')
        .expect("export download path should contain node name");
    assert_eq!(node, "giganto1");
    PathBuf::from(path)
}

fn assert_export_filename(path: &Path, protocol: &str, kind: Option<&str>, ext: &str) {
    let filename = path
        .file_name()
        .expect("export path should have a filename")
        .to_string_lossy();
    let filename = filename.as_ref();
    assert!(
        filename.ends_with(&format!(".{ext}")),
        "expected {filename} to end with .{ext}"
    );
    let stem = filename.trim_end_matches(&format!(".{ext}"));
    let kind_segment = kind.map(|k| format!("{k}_")).unwrap_or_default();
    let prefix = format!("{protocol}_{kind_segment}").replace(' ', "");
    assert!(
        stem.starts_with(&prefix),
        "expected {filename} to start with {prefix}"
    );

    let timestamp_segment = stem[prefix.len()..].trim_start_matches('_');
    assert!(
        !timestamp_segment.is_empty(),
        "expected {stem} to contain timestamp after {prefix}"
    );
    assert!(
        NaiveDateTime::parse_from_str(timestamp_segment, "%Y%m%d_%H%M%S").is_ok(),
        "expected timestamp segment {timestamp_segment} to match %Y%m%d_%H%M%S"
    );
}
