use std::mem;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use chrono::{Duration, Utc};
use giganto_client::ingest::{
    log::{Log, OpLog, OpLogLevel},
    network::{
        Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, FtpCommand, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm,
        Rdp, Smb, Smtp, Ssh, Tls,
    },
    timeseries::PeriodicTimeSeries,
};

use crate::comm::ingest::generation::SequenceGenerator;
use crate::graphql::tests::TestSchema;
use crate::storage::RawEventStore;

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

    insert_conn_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_conn_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("conn"));

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
    assert!(res.data.to_string().contains("conn"));
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
    let ser_conn_body = bincode::serialize(&conn_body).unwrap();

    store.append(&key, &ser_conn_body).unwrap();
}

#[tokio::test]
async fn export_dns() {
    let schema = TestSchema::new();
    let store = schema.db.dns_store().unwrap();

    insert_dns_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_dns_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("dns"));

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
    assert!(res.data.to_string().contains("dns"));
}

fn insert_dns_raw_event(store: &RawEventStore<Dns>, sensor: &str, timestamp: i64) {
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
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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

#[tokio::test]
async fn export_http() {
    let schema = TestSchema::new();
    let store = schema.db.http_store().unwrap();

    insert_http_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_http_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("http"));

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
    assert!(res.data.to_string().contains("http"));
}

fn insert_http_raw_event(store: &RawEventStore<Http>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let http_body = Http {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_rdp() {
    let schema = TestSchema::new();
    let store = schema.db.rdp_store().unwrap();

    insert_rdp_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_rdp_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("rdp"));

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
    assert!(res.data.to_string().contains("rdp"));
}

fn insert_rdp_raw_event(store: &RawEventStore<Rdp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let rdp_body = Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_smtp() {
    let schema = TestSchema::new();
    let store = schema.db.smtp_store().unwrap();

    insert_smtp_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_smtp_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("smtp"));

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
    assert!(res.data.to_string().contains("smtp"));
}

fn insert_smtp_raw_event(store: &RawEventStore<Smtp>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let smtp_body = Smtp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_ntlm() {
    let schema = TestSchema::new();
    let store = schema.db.ntlm_store().unwrap();

    insert_ntlm_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_ntlm_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("ntlm"));

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
    assert!(res.data.to_string().contains("ntlm"));
}

fn insert_ntlm_raw_event(store: &RawEventStore<Ntlm>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ntlm_body = Ntlm {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_kerberos() {
    let schema = TestSchema::new();
    let store = schema.db.kerberos_store().unwrap();

    insert_kerberos_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_kerberos_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("kerberos"));

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
    assert!(res.data.to_string().contains("kerberos"));
}

fn insert_kerberos_raw_event(store: &RawEventStore<Kerberos>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let kerberos_body = Kerberos {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_ssh() {
    let schema = TestSchema::new();
    let store = schema.db.ssh_store().unwrap();

    insert_ssh_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_ssh_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("ssh"));

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
    assert!(res.data.to_string().contains("ssh"));
}
fn insert_ssh_raw_event(store: &RawEventStore<Ssh>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let ssh_body = Ssh {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_dce_rpc() {
    let schema = TestSchema::new();
    let store = schema.db.dce_rpc_store().unwrap();

    insert_dce_rpc_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_dce_rpc_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("dcerpc"));

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
    assert!(res.data.to_string().contains("dcerpc"));
}
fn insert_dce_rpc_raw_event(store: &RawEventStore<DceRpc>, sensor: &str, timestamp: i64) {
    let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());

    let dce_rpc_body = DceRpc {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
    assert!(res.data.to_string().contains("log"));

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
    assert!(res.data.to_string().contains("log"));
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
    let value = bincode::serialize(&log_body).unwrap();
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
    assert!(res.data.to_string().contains("periodictimeseries"));

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
    assert!(res.data.to_string().contains("periodictimeseries"));
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
    let value = bincode::serialize(&time_series_data).unwrap();
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
    assert!(res.data.to_string().contains("op_log"));

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
    assert!(res.data.to_string().contains("op_log"));
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

    let value = bincode::serialize(&op_log_body).unwrap();

    store.append(&key, &value).unwrap();
}

#[tokio::test]
async fn export_ftp() {
    let schema = TestSchema::new();
    let store = schema.db.ftp_store().unwrap();

    insert_ftp_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_ftp_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("ftp"));

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
    assert!(res.data.to_string().contains("ftp"));
}

fn insert_ftp_raw_event(store: &RawEventStore<Ftp>, sensor: &str, timestamp: i64) {
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
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_mqtt() {
    let schema = TestSchema::new();
    let store = schema.db.mqtt_store().unwrap();

    insert_mqtt_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_mqtt_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("mqtt"));

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
    assert!(res.data.to_string().contains("mqtt"));
}

fn insert_mqtt_raw_event(store: &RawEventStore<Mqtt>, sensor: &str, timestamp: i64) {
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
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
    let ser_mqtt_body = bincode::serialize(&mqtt_body).unwrap();

    store.append(&key, &ser_mqtt_body).unwrap();
}

#[tokio::test]
async fn export_ldap() {
    let schema = TestSchema::new();
    let store = schema.db.ldap_store().unwrap();

    insert_ldap_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_ldap_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("ldap"));

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
    assert!(res.data.to_string().contains("ldap"));
}

fn insert_ldap_raw_event(store: &RawEventStore<Ldap>, sensor: &str, timestamp: i64) {
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
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_tls() {
    let schema = TestSchema::new();
    let store = schema.db.tls_store().unwrap();

    insert_tls_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_tls_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("tls"));

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
    assert!(res.data.to_string().contains("tls"));
}

fn insert_tls_raw_event(store: &RawEventStore<Tls>, sensor: &str, timestamp: i64) {
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
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_smb() {
    let schema = TestSchema::new();
    let store = schema.db.smb_store().unwrap();

    insert_smb_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_smb_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("smb"));

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
    assert!(res.data.to_string().contains("smb"));
}

fn insert_smb_raw_event(store: &RawEventStore<Smb>, sensor: &str, timestamp: i64) {
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
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_nfs() {
    let schema = TestSchema::new();
    let store = schema.db.nfs_store().unwrap();

    insert_nfs_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_nfs_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("nfs"));

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
    assert!(res.data.to_string().contains("nfs"));
}

fn insert_nfs_raw_event(store: &RawEventStore<Nfs>, sensor: &str, timestamp: i64) {
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
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_bootp() {
    let schema = TestSchema::new();
    let store = schema.db.bootp_store().unwrap();

    insert_bootp_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_bootp_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("bootp"));

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
    assert!(res.data.to_string().contains("bootp"));
}

fn insert_bootp_raw_event(store: &RawEventStore<Bootp>, sensor: &str, timestamp: i64) {
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
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
async fn export_dhcp() {
    let schema = TestSchema::new();
    let store = schema.db.dhcp_store().unwrap();

    insert_dhcp_raw_event(&store, "src1", Utc::now().timestamp_nanos_opt().unwrap());
    insert_dhcp_raw_event(
        &store,
        "ingest src 1",
        Utc::now().timestamp_nanos_opt().unwrap(),
    );

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
    assert!(res.data.to_string().contains("dhcp"));

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
    assert!(res.data.to_string().contains("dhcp"));
}

fn insert_dhcp_raw_event(store: &RawEventStore<Dhcp>, sensor: &str, timestamp: i64) {
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
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
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
