use super::Server;
use crate::{
    storage::{Database, DbOptions},
    to_cert_chain, to_private_key,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use chrono::{Duration, Utc};
use giganto_client::{
    connection::client_handshake,
    frame::recv_bytes,
    ingest::{
        log::{Log, OpLogLevel, Oplog},
        network::{Conn, DceRpc, Dns, Ftp, Http, Kerberos, Mqtt, Ntlm, Rdp, Smtp, Ssh},
        receive_ack_timestamp, send_event, send_record_header,
        timeseries::PeriodicTimeSeries,
        Packet, RecordType,
    },
};
use lazy_static::lazy_static;
use quinn::{Connection, Endpoint};
use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
};
use tempfile::TempDir;
use tokio::{
    sync::{Mutex, Notify, RwLock},
    task::JoinHandle,
};

lazy_static! {
    pub(crate) static ref TOKEN: Mutex<u32> = Mutex::new(0);
}

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/root.pem";
const HOST: &str = "localhost";
const TEST_PORT: u16 = 60190;
const PROTOCOL_VERSION: &str = "0.11.0";

struct TestClient {
    conn: Connection,
    endpoint: Endpoint,
}

impl TestClient {
    async fn new() -> Self {
        let endpoint = init_client();
        let conn = endpoint
            .connect(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT),
                HOST,
            )
            .expect(
                "Failed to connect server's endpoint, Please check if the setting value is correct",
            )
            .await
            .expect("Failed to connect server's endpoint, Please make sure the Server is alive");
        client_handshake(&conn, PROTOCOL_VERSION).await.unwrap();
        Self { conn, endpoint }
    }
}

fn server() -> Server {
    let cert_pem = fs::read(CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert = fs::read("tests/root.pem").unwrap();

    Server::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT),
        cert,
        key,
        vec![ca_cert],
    )
}

fn init_client() -> Endpoint {
    let (cert, key) = match fs::read(CERT_PATH)
        .map(|x| (x, fs::read(KEY_PATH).expect("Failed to Read key file")))
    {
        Ok(x) => x,
        Err(_) => {
            panic!(
                "failed to read (cert, key) file, {}, {} read file error. Cert or key doesn't exist in default test folder",
                CERT_PATH,
                KEY_PATH,
            );
        }
    };

    let pv_key = if Path::new(KEY_PATH)
        .extension()
        .map_or(false, |x| x == "der")
    {
        rustls::PrivateKey(key)
    } else {
        let pkcs8 =
            rustls_pemfile::pkcs8_private_keys(&mut &*key).expect("malformed PKCS #8 private key");
        match pkcs8.into_iter().next() {
            Some(x) => rustls::PrivateKey(x),
            None => {
                let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                    .expect("malformed PKCS #1 private key");
                match rsa.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        panic!(
                            "no private keys found. Private key doesn't exist in default test folder"
                        );
                    }
                }
            }
        }
    };
    let cert_chain = if Path::new(CERT_PATH)
        .extension()
        .map_or(false, |x| x == "der")
    {
        vec![rustls::Certificate(cert)]
    } else {
        rustls_pemfile::certs(&mut &*cert)
            .expect("invalid PEM-encoded certificate")
            .into_iter()
            .map(rustls::Certificate)
            .collect()
    };

    let mut server_root = rustls::RootCertStore::empty();
    let file = fs::read(CA_CERT_PATH).expect("Failed to read file");
    let root_cert: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*file)
        .expect("invalid PEM-encoded certificate")
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    if let Some(cert) = root_cert.get(0) {
        server_root.add(cert).expect("Failed to add cert");
    }

    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(server_root)
        .with_single_cert(cert_chain, pv_key)
        .expect("the server root, cert chain or private key are not valid");

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
    endpoint
}

#[tokio::test]
async fn conn() {
    const RECORD_TYPE_CONN: RecordType = RecordType::Conn;

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_conn, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_conn, RECORD_TYPE_CONN)
        .await
        .unwrap();
    send_event(&mut send_conn, Utc::now().timestamp_nanos(), conn_body)
        .await
        .unwrap();

    send_conn.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"conn_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn dns() {
    const RECORD_TYPE_DNS: RecordType = RecordType::Dns;

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_dns, _) = client.conn.open_bi().await.expect("failed to open stream");

    let dns_body = Dns {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        query: "Hello Server".to_string(),
        answer: vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
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

    send_record_header(&mut send_dns, RECORD_TYPE_DNS)
        .await
        .unwrap();
    send_event(&mut send_dns, Utc::now().timestamp_nanos(), dns_body)
        .await
        .unwrap();

    send_dns.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"dns_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn log() {
    const RECORD_TYPE_LOG: RecordType = RecordType::Log;

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_log, _) = client.conn.open_bi().await.expect("failed to open stream");

    let log_body = Log {
        kind: String::from("Hello"),
        log: base64_engine.decode("aGVsbG8gd29ybGQ=").unwrap(),
    };

    send_record_header(&mut send_log, RECORD_TYPE_LOG)
        .await
        .unwrap();
    send_event(&mut send_log, Utc::now().timestamp_nanos(), log_body)
        .await
        .unwrap();

    send_log.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn http() {
    const RECORD_TYPE_HTTP: RecordType = RecordType::Http;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_http, _) = client.conn.open_bi().await.expect("failed to open stream");

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
    };

    send_record_header(&mut send_http, RECORD_TYPE_HTTP)
        .await
        .unwrap();
    send_event(&mut send_http, Utc::now().timestamp_nanos(), http_body)
        .await
        .unwrap();

    send_http.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"http_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn rdp() {
    const RECORD_TYPE_RDP: RecordType = RecordType::Rdp;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_rdp, _) = client.conn.open_bi().await.expect("failed to open stream");

    let rdp_body = Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        cookie: "rdp_test".to_string(),
    };

    send_record_header(&mut send_rdp, RECORD_TYPE_RDP)
        .await
        .unwrap();
    send_event(&mut send_rdp, Utc::now().timestamp_nanos(), rdp_body)
        .await
        .unwrap();

    send_rdp.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn periodic_time_series() {
    const RECORD_TYPE_PERIOD_TIME_SERIES: RecordType = RecordType::PeriodicTimeSeries;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_periodic_time_series, _) =
        client.conn.open_bi().await.expect("failed to open stream");

    let periodic_time_series_body = PeriodicTimeSeries {
        id: String::from("model_one"),
        data: vec![1.1, 2.2, 3.3, 4.4, 5.5, 6.6],
    };

    send_record_header(
        &mut send_periodic_time_series,
        RECORD_TYPE_PERIOD_TIME_SERIES,
    )
    .await
    .unwrap();
    send_event(
        &mut send_periodic_time_series,
        Utc::now().timestamp_nanos(),
        periodic_time_series_body,
    )
    .await
    .unwrap();

    send_periodic_time_series
        .finish()
        .await
        .expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"periodic_time_series_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn smtp() {
    const RECORD_TYPE_SMTP: RecordType = RecordType::Smtp;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_smtp, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_smtp, RECORD_TYPE_SMTP)
        .await
        .unwrap();
    send_event(&mut send_smtp, Utc::now().timestamp_nanos(), smtp_body)
        .await
        .unwrap();

    send_smtp.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"smtp_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ntlm() {
    const RECORD_TYPE_NTLM: RecordType = RecordType::Ntlm;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_ntlm, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_ntlm, RECORD_TYPE_NTLM)
        .await
        .unwrap();
    send_event(&mut send_ntlm, Utc::now().timestamp_nanos(), ntlm_body)
        .await
        .unwrap();

    send_ntlm.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ntlm_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn kerberos() {
    const RECORD_TYPE_KERBEROS: RecordType = RecordType::Kerberos;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_kerberos, _) = client.conn.open_bi().await.expect("failed to open stream");

    let kerberos_body = Kerberos {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        request_type: "req_type".to_string(),
        client: "client".to_string(),
        service: "service".to_string(),
        success: "tf".to_string(),
        error_msg: "err_msg".to_string(),
        from: 5454,
        till: 2345,
        cipher: "cipher".to_string(),
        forwardable: "forwardable".to_string(),
        renewable: "renewable".to_string(),
        client_cert_subject: "client_cert".to_string(),
        server_cert_subject: "server_cert".to_string(),
    };

    send_record_header(&mut send_kerberos, RECORD_TYPE_KERBEROS)
        .await
        .unwrap();
    send_event(
        &mut send_kerberos,
        Utc::now().timestamp_nanos(),
        kerberos_body,
    )
    .await
    .unwrap();

    send_kerberos
        .finish()
        .await
        .expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"kerberos_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ssh() {
    const RECORD_TYPE_SSH: RecordType = RecordType::Ssh;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_ssh, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_ssh, RECORD_TYPE_SSH)
        .await
        .unwrap();
    send_event(&mut send_ssh, Utc::now().timestamp_nanos(), ssh_body)
        .await
        .unwrap();

    send_ssh.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ssh_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn dce_rpc() {
    const RECORD_TYPE_DCE_RPC: RecordType = RecordType::DceRpc;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_dce_rpc, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_dce_rpc, RECORD_TYPE_DCE_RPC)
        .await
        .unwrap();
    send_event(
        &mut send_dce_rpc,
        Utc::now().timestamp_nanos(),
        dce_rpc_body,
    )
    .await
    .unwrap();

    send_dce_rpc
        .finish()
        .await
        .expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"dce_rpc_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn oplog() {
    const RECORD_TYPE_OPLOG: RecordType = RecordType::Oplog;

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_oplog, _) = client.conn.open_bi().await.expect("failed to open stream");

    let oplog_body = Oplog {
        agent_name: "giganto".to_string(),
        log_level: OpLogLevel::Info,
        contents: "oplog".to_string(),
    };

    send_record_header(&mut send_oplog, RECORD_TYPE_OPLOG)
        .await
        .unwrap();
    send_event(&mut send_oplog, Utc::now().timestamp_nanos(), oplog_body)
        .await
        .unwrap();

    send_oplog
        .finish()
        .await
        .expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"oplog_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn packet() {
    const RECORD_TYPE_PACKET: RecordType = RecordType::Packet;

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_packet, _) = client.conn.open_bi().await.expect("failed to open stream");

    let packet: Vec<u8> = vec![0, 1, 0, 1, 0, 1];
    let packet_body = Packet {
        packet_timestamp: Utc::now().timestamp_nanos(),
        packet,
    };

    send_record_header(&mut send_packet, RECORD_TYPE_PACKET)
        .await
        .unwrap();
    send_event(&mut send_packet, Utc::now().timestamp_nanos(), packet_body)
        .await
        .unwrap();

    send_packet
        .finish()
        .await
        .expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"packet_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ftp() {
    const RECORD_TYPE_FTP: RecordType = RecordType::Ftp;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_ftp, _) = client.conn.open_bi().await.expect("failed to open stream");

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
        file: "fpt_file".to_string(),
        file_size: 100,
        file_id: "1".to_string(),
    };

    send_record_header(&mut send_ftp, RECORD_TYPE_FTP)
        .await
        .unwrap();
    send_event(&mut send_ftp, Utc::now().timestamp_nanos(), ftp_body)
        .await
        .unwrap();

    send_ftp.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ftp_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn mqtt() {
    const RECORD_TYPE_MQTT: RecordType = RecordType::Mqtt;
    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_mqtt, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_mqtt, RECORD_TYPE_MQTT)
        .await
        .unwrap();
    send_event(&mut send_mqtt, Utc::now().timestamp_nanos(), mqtt_body)
        .await
        .unwrap();

    send_mqtt.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"mqtt_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ack_info() {
    const RECORD_TYPE_LOG: RecordType = RecordType::Log;

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_log, mut recv_log) = client.conn.open_bi().await.expect("failed to open stream");

    let log_body = Log {
        kind: String::from("Hello Server I am Log"),
        log: vec![0; 10],
    };

    send_record_header(&mut send_log, RECORD_TYPE_LOG)
        .await
        .unwrap();
    send_event(&mut send_log, Utc::now().timestamp_nanos(), log_body)
        .await
        .unwrap();

    let mut last_timestamp: i64 = 0;
    for _ in 0..127 {
        let log_body: Log = Log {
            kind: String::from("Hello Server I am Log"),
            log: vec![0; 10],
        };

        last_timestamp = Utc::now().timestamp_nanos();
        send_event(&mut send_log, last_timestamp, log_body)
            .await
            .unwrap();
    }

    let recv_timestamp = receive_ack_timestamp(&mut recv_log).await.unwrap();

    send_log.finish().await.expect("failed to shutdown stream");
    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
    assert_eq!(last_timestamp, recv_timestamp);
}

#[tokio::test]
async fn one_short_reproduce_channel_close() {
    const RECORD_TYPE_LOG: RecordType = RecordType::Log;
    const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
    const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_log, mut recv_log) = client.conn.open_bi().await.expect("failed to open stream");

    send_record_header(&mut send_log, RECORD_TYPE_LOG)
        .await
        .unwrap();
    send_event(
        &mut send_log,
        CHANNEL_CLOSE_TIMESTAMP,
        CHANNEL_CLOSE_MESSAGE,
    )
    .await
    .unwrap();

    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    recv_bytes(&mut recv_log, &mut ts_buf).await.unwrap();
    let recv_timestamp = i64::from_be_bytes(ts_buf);

    send_log.finish().await.expect("failed to shutdown stream");
    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
    assert_eq!(CHANNEL_CLOSE_TIMESTAMP, recv_timestamp);
}

fn run_server(db_dir: TempDir) -> JoinHandle<()> {
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let packet_sources = Arc::new(RwLock::new(HashMap::new()));
    let sources = Arc::new(RwLock::new(HashMap::new()));
    let stream_direct_channel = Arc::new(RwLock::new(HashMap::new()));
    tokio::spawn(server().run(
        db,
        packet_sources,
        sources,
        stream_direct_channel,
        Arc::new(Notify::new()),
    ))
}
