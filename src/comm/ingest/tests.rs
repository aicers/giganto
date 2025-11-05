#![allow(clippy::items_after_statements)]

use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, OnceLock},
};

use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use chrono::{Duration, Utc};
use giganto_client::{
    RawEventKind,
    connection::client_handshake,
    frame::{recv_bytes, send_raw},
    ingest::{
        Packet,
        log::{Log, OpLog, OpLogLevel},
        network::{
            Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, FtpCommand, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm,
            Rdp, Smb, Smtp, Ssh, Tls,
        },
        receive_ack_timestamp, send_record_header,
        statistics::Statistics,
        timeseries::PeriodicTimeSeries,
    },
};
use quinn::{Connection, Endpoint};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use tempfile::TempDir;
static INIT: OnceLock<()> = OnceLock::new();

fn init_crypto() {
    INIT.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

use tokio::{
    sync::{Mutex, Notify},
    task::JoinHandle,
};

use super::Server;
use crate::{
    bincode_utils::encode_legacy,
    comm::{
        new_ingest_sensors, new_pcap_sensors, new_runtime_ingest_sensors,
        new_stream_direct_channels, to_cert_chain, to_private_key, to_root_cert,
    },
    server::Certs,
    storage::{Database, DbOptions},
};

fn get_token() -> &'static Mutex<u32> {
    static TOKEN: OnceLock<Mutex<u32>> = OnceLock::new();

    TOKEN.get_or_init(|| Mutex::new(0))
}

const CERT_PATH: &str = "tests/certs/node1/cert.pem";
const KEY_PATH: &str = "tests/certs/node1/key.pem";
const CA_CERT_PATH: &str = "tests/certs/ca_cert.pem";
const HOST: &str = "node1";
const TEST_PORT: u16 = 60190;
const PROTOCOL_VERSION: &str = "0.26.0-alpha.6";

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
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    Server::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT),
        &certs,
    )
}

fn init_client() -> Endpoint {
    let (cert, key): (Vec<u8>, Vec<u8>) = if let Ok(x) =
        fs::read(CERT_PATH).map(|x| (x, fs::read(KEY_PATH).expect("Failed to Read key file")))
    {
        x
    } else {
        panic!(
            "failed to read (cert, key) file, {CERT_PATH}, {KEY_PATH} read file error. Cert or key doesn't exist in default test folder"
        );
    };

    let pv_key = if Path::new(KEY_PATH).extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &*key)
            .expect("malformed PKCS #1 private key")
            .expect("no private keys found")
    };

    let cert_chain = if Path::new(CERT_PATH).extension().is_some_and(|x| x == "der") {
        vec![CertificateDer::from(cert)]
    } else {
        rustls_pemfile::certs(&mut &*cert)
            .collect::<Result<_, _>>()
            .expect("invalid PEM-encoded certificate")
    };
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let server_root = to_root_cert(&ca_cert_path).unwrap();

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(server_root)
        .with_client_auth_cert(cert_chain, pv_key)
        .expect("the server root, cert chain or private key are not valid");

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("Failed to generate QuicClientConfig"),
    )));
    endpoint
}

#[tokio::test]
async fn conn() {
    init_crypto();
    const RAW_EVENT_KIND_CONN: RawEventKind = RawEventKind::Conn;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();

    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_conn, _) = client.conn.open_bi().await.expect("failed to open stream");

    let tmp_dur = Duration::nanoseconds(12345);
    let start_time = chrono::Utc::now();
    let end_time = start_time + chrono::Duration::nanoseconds(tmp_dur.num_nanoseconds().unwrap());
    let conn_body = Conn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        conn_state: "sf".to_string(),
        start_time,
        end_time,
        duration: tmp_dur.num_nanoseconds().unwrap(),
        service: "-".to_string(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
        orig_l2_bytes: 21515,
        resp_l2_bytes: 27889,
    };

    send_record_header(&mut send_conn, RAW_EVENT_KIND_CONN)
        .await
        .unwrap();
    send_events(
        &mut send_conn,
        Utc::now().timestamp_nanos_opt().unwrap(),
        conn_body,
    )
    .await
    .unwrap();

    send_conn.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"conn_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn dns() {
    init_crypto();
    const RAW_EVENT_KIND_DNS: RawEventKind = RawEventKind::Dns;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_dns, _) = client.conn.open_bi().await.expect("failed to open stream");

    let start_time = chrono::Utc::now();
    let end_time = start_time + chrono::Duration::seconds(1);
    let dns_body = Dns {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time,
        end_time,
        duration: 1_000_000_000, // 1 second in nanoseconds
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
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

    send_record_header(&mut send_dns, RAW_EVENT_KIND_DNS)
        .await
        .unwrap();
    send_events(
        &mut send_dns,
        Utc::now().timestamp_nanos_opt().unwrap(),
        dns_body,
    )
    .await
    .unwrap();

    send_dns.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"dns_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn log() {
    init_crypto();
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_log, _) = client.conn.open_bi().await.expect("failed to open stream");

    let log_body = Log {
        kind: String::from("Hello"),
        log: base64_engine.decode("aGVsbG8gd29ybGQ=").unwrap(),
    };

    send_record_header(&mut send_log, RAW_EVENT_KIND_LOG)
        .await
        .unwrap();
    send_events(
        &mut send_log,
        Utc::now().timestamp_nanos_opt().unwrap(),
        log_body,
    )
    .await
    .unwrap();

    send_log.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn http() {
    init_crypto();
    const RAW_EVENT_KIND_HTTP: RawEventKind = RawEventKind::Http;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_http, _) = client.conn.open_bi().await.expect("failed to open stream");

    let http_body = Http {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
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

    send_record_header(&mut send_http, RAW_EVENT_KIND_HTTP)
        .await
        .unwrap();
    send_events(
        &mut send_http,
        Utc::now().timestamp_nanos_opt().unwrap(),
        http_body,
    )
    .await
    .unwrap();

    send_http.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"http_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn rdp() {
    init_crypto();
    const RAW_EVENT_KIND_RDP: RawEventKind = RawEventKind::Rdp;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_rdp, _) = client.conn.open_bi().await.expect("failed to open stream");

    let rdp_body = Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now() + chrono::Duration::seconds(1),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        cookie: "rdp_test".to_string(),
    };

    send_record_header(&mut send_rdp, RAW_EVENT_KIND_RDP)
        .await
        .unwrap();
    send_events(
        &mut send_rdp,
        Utc::now().timestamp_nanos_opt().unwrap(),
        rdp_body,
    )
    .await
    .unwrap();

    send_rdp.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn periodic_time_series() {
    init_crypto();
    const RAW_EVENT_KIND_PERIOD_TIME_SERIES: RawEventKind = RawEventKind::PeriodicTimeSeries;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_periodic_time_series, _) =
        client.conn.open_bi().await.expect("failed to open stream");

    let periodic_time_series_body = PeriodicTimeSeries {
        id: String::from("model_one"),
        data: vec![1.1, 2.2, 3.3, 4.4, 5.5, 6.6],
    };

    send_record_header(
        &mut send_periodic_time_series,
        RAW_EVENT_KIND_PERIOD_TIME_SERIES,
    )
    .await
    .unwrap();
    send_events(
        &mut send_periodic_time_series,
        Utc::now().timestamp_nanos_opt().unwrap(),
        periodic_time_series_body,
    )
    .await
    .unwrap();

    send_periodic_time_series
        .finish()
        .expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"periodic_time_series_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn smtp() {
    init_crypto();
    const RAW_EVENT_KIND_SMTP: RawEventKind = RawEventKind::Smtp;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_smtp, _) = client.conn.open_bi().await.expect("failed to open stream");

    let smtp_body = Smtp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
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

    send_record_header(&mut send_smtp, RAW_EVENT_KIND_SMTP)
        .await
        .unwrap();
    send_events(
        &mut send_smtp,
        Utc::now().timestamp_nanos_opt().unwrap(),
        smtp_body,
    )
    .await
    .unwrap();

    send_smtp.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"smtp_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ntlm() {
    init_crypto();
    const RAW_EVENT_KIND_NTLM: RawEventKind = RawEventKind::Ntlm;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_ntlm, _) = client.conn.open_bi().await.expect("failed to open stream");

    let ntlm_body = Ntlm {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
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

    send_record_header(&mut send_ntlm, RAW_EVENT_KIND_NTLM)
        .await
        .unwrap();
    send_events(
        &mut send_ntlm,
        Utc::now().timestamp_nanos_opt().unwrap(),
        ntlm_body,
    )
    .await
    .unwrap();

    send_ntlm.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ntlm_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn kerberos() {
    init_crypto();
    const RAW_EVENT_KIND_KERBEROS: RawEventKind = RawEventKind::Kerberos;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_kerberos, _) = client.conn.open_bi().await.expect("failed to open stream");

    let kerberos_body = Kerberos {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
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

    send_record_header(&mut send_kerberos, RAW_EVENT_KIND_KERBEROS)
        .await
        .unwrap();
    send_events(
        &mut send_kerberos,
        Utc::now().timestamp_nanos_opt().unwrap(),
        kerberos_body,
    )
    .await
    .unwrap();

    send_kerberos.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"kerberos_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ssh() {
    init_crypto();
    const RAW_EVENT_KIND_SSH: RawEventKind = RawEventKind::Ssh;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_ssh, _) = client.conn.open_bi().await.expect("failed to open stream");

    let ssh_body = Ssh {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
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

    send_record_header(&mut send_ssh, RAW_EVENT_KIND_SSH)
        .await
        .unwrap();
    send_events(
        &mut send_ssh,
        Utc::now().timestamp_nanos_opt().unwrap(),
        ssh_body,
    )
    .await
    .unwrap();

    send_ssh.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ssh_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn dce_rpc() {
    init_crypto();
    const RAW_EVENT_KIND_DCE_RPC: RawEventKind = RawEventKind::DceRpc;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_dce_rpc, _) = client.conn.open_bi().await.expect("failed to open stream");

    let dce_rpc_body = DceRpc {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
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

    send_record_header(&mut send_dce_rpc, RAW_EVENT_KIND_DCE_RPC)
        .await
        .unwrap();
    send_events(
        &mut send_dce_rpc,
        Utc::now().timestamp_nanos_opt().unwrap(),
        dce_rpc_body,
    )
    .await
    .unwrap();

    send_dce_rpc.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"dce_rpc_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn op_log() {
    init_crypto();
    const RAW_EVENT_KIND_OPLOG: RawEventKind = RawEventKind::OpLog;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_op_log, _) = client.conn.open_bi().await.expect("failed to open stream");

    let op_log_body = OpLog {
        sensor: String::new(),
        agent_name: "giganto".to_string(),
        log_level: OpLogLevel::Info,
        contents: "op_log".to_string(),
    };

    send_record_header(&mut send_op_log, RAW_EVENT_KIND_OPLOG)
        .await
        .unwrap();
    send_events(
        &mut send_op_log,
        Utc::now().timestamp_nanos_opt().unwrap(),
        op_log_body,
    )
    .await
    .unwrap();

    send_op_log.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"oplog_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn packet() {
    init_crypto();
    const RAW_EVENT_KIND_PACKET: RawEventKind = RawEventKind::Packet;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_packet, _) = client.conn.open_bi().await.expect("failed to open stream");

    let packet: Vec<u8> = vec![0, 1, 0, 1, 0, 1];
    let packet_body = Packet {
        packet_timestamp: Utc::now().timestamp_nanos_opt().unwrap(),
        packet,
    };

    send_record_header(&mut send_packet, RAW_EVENT_KIND_PACKET)
        .await
        .unwrap();
    send_events(
        &mut send_packet,
        Utc::now().timestamp_nanos_opt().unwrap(),
        packet_body,
    )
    .await
    .unwrap();

    send_packet.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"packet_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ftp() {
    init_crypto();
    const RAW_EVENT_KIND_FTP: RawEventKind = RawEventKind::Ftp;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_ftp, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_ftp, RAW_EVENT_KIND_FTP)
        .await
        .unwrap();
    send_events(
        &mut send_ftp,
        Utc::now().timestamp_nanos_opt().unwrap(),
        ftp_body,
    )
    .await
    .unwrap();

    send_ftp.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ftp_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn mqtt() {
    init_crypto();
    const RAW_EVENT_KIND_MQTT: RawEventKind = RawEventKind::Mqtt;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_mqtt, _) = client.conn.open_bi().await.expect("failed to open stream");

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
        client_id: "1".to_string(),
        connack_reason: 1,
        subscribe: vec!["subscribe".to_string()],
        suback_reason: vec![1],
    };

    send_record_header(&mut send_mqtt, RAW_EVENT_KIND_MQTT)
        .await
        .unwrap();
    send_events(
        &mut send_mqtt,
        Utc::now().timestamp_nanos_opt().unwrap(),
        mqtt_body,
    )
    .await
    .unwrap();

    send_mqtt.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"mqtt_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ldap() {
    init_crypto();
    const RAW_EVENT_KIND_LDAP: RawEventKind = RawEventKind::Ldap;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_ldap, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_ldap, RAW_EVENT_KIND_LDAP)
        .await
        .unwrap();
    send_events(
        &mut send_ldap,
        Utc::now().timestamp_nanos_opt().unwrap(),
        ldap_body,
    )
    .await
    .unwrap();

    send_ldap.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ldap_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn tls() {
    init_crypto();
    const RAW_EVENT_KIND_TLS: RawEventKind = RawEventKind::Tls;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_tls, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_tls, RAW_EVENT_KIND_TLS)
        .await
        .unwrap();
    send_events(
        &mut send_tls,
        Utc::now().timestamp_nanos_opt().unwrap(),
        tls_body,
    )
    .await
    .unwrap();

    send_tls.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"tls_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn smb() {
    init_crypto();
    const RAW_EVENT_KIND_SMB: RawEventKind = RawEventKind::Smb;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_smb, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_smb, RAW_EVENT_KIND_SMB)
        .await
        .unwrap();
    send_events(
        &mut send_smb,
        Utc::now().timestamp_nanos_opt().unwrap(),
        smb_body,
    )
    .await
    .unwrap();

    send_smb.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"smb_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn nfs() {
    init_crypto();
    const RAW_EVENT_KIND_NFS: RawEventKind = RawEventKind::Nfs;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_nfs, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_nfs, RAW_EVENT_KIND_NFS)
        .await
        .unwrap();
    send_events(
        &mut send_nfs,
        Utc::now().timestamp_nanos_opt().unwrap(),
        nfs_body,
    )
    .await
    .unwrap();

    send_nfs.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"nfs_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn bootp() {
    init_crypto();
    const RAW_EVENT_KIND_BOOTP: RawEventKind = RawEventKind::Bootp;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_bootp, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_bootp, RAW_EVENT_KIND_BOOTP)
        .await
        .unwrap();
    send_events(
        &mut send_bootp,
        Utc::now().timestamp_nanos_opt().unwrap(),
        bootp_body,
    )
    .await
    .unwrap();

    send_bootp.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"bootp_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn dhcp() {
    init_crypto();
    const RAW_EVENT_KIND_DHCP: RawEventKind = RawEventKind::Dhcp;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_dhcp, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_dhcp, RAW_EVENT_KIND_DHCP)
        .await
        .unwrap();
    send_events(
        &mut send_dhcp,
        Utc::now().timestamp_nanos_opt().unwrap(),
        dhcp_body,
    )
    .await
    .unwrap();

    send_dhcp.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"dhcp_done");
    client.endpoint.wait_idle().await;
}
#[tokio::test]
async fn statistics() {
    init_crypto();
    const RAW_EVENT_KIND_STATISTICS: RawEventKind = RawEventKind::Statistics;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_statistics, _) = client.conn.open_bi().await.expect("failed to open stream");

    let statistics_body = Statistics {
        core: 1,
        period: 600,
        stats: vec![(RAW_EVENT_KIND_STATISTICS, 1000, 10_001_000)],
    };

    send_record_header(&mut send_statistics, RAW_EVENT_KIND_STATISTICS)
        .await
        .unwrap();
    send_events(
        &mut send_statistics,
        Utc::now().timestamp_nanos_opt().unwrap(),
        statistics_body,
    )
    .await
    .unwrap();

    send_statistics.finish().expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"statistics_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ack_info() {
    init_crypto();
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_log, mut recv_log) = client.conn.open_bi().await.expect("failed to open stream");

    let log_body = Log {
        kind: String::from("Hello Server I am Log"),
        log: vec![0; 10],
    };

    send_record_header(&mut send_log, RAW_EVENT_KIND_LOG)
        .await
        .unwrap();
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
    send_events(
        &mut send_log,
        Utc::now().timestamp_nanos_opt().unwrap(),
        log_body,
    )
    .await
    .unwrap();

    for i in 0..1023 {
        let log_body: Log = Log {
            kind: String::from("Hello Server I am Log"),
            log: vec![0; 10],
        };
        send_events(&mut send_log, timestamp + i64::from(i + 1), log_body)
            .await
            .unwrap();
    }

    let recv_timestamp = receive_ack_timestamp(&mut recv_log).await.unwrap();

    send_log.finish().expect("failed to shutdown stream");
    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
    assert_eq!(timestamp + 1023, recv_timestamp);
}

#[tokio::test]
async fn one_short_reproduce_channel_close() {
    init_crypto();
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;
    const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
    const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let client = TestClient::new().await;
    let (mut send_log, mut recv_log) = client.conn.open_bi().await.expect("failed to open stream");

    send_record_header(&mut send_log, RAW_EVENT_KIND_LOG)
        .await
        .unwrap();
    send_events(
        &mut send_log,
        CHANNEL_CLOSE_TIMESTAMP,
        CHANNEL_CLOSE_MESSAGE,
    )
    .await
    .unwrap();

    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    recv_bytes(&mut recv_log, &mut ts_buf).await.unwrap();
    let recv_timestamp = i64::from_be_bytes(ts_buf);

    send_log.finish().expect("failed to shutdown stream");
    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
    assert_eq!(CHANNEL_CLOSE_TIMESTAMP, recv_timestamp);
}

fn run_server(db_dir: &TempDir) -> JoinHandle<()> {
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let ingest_sensors = new_ingest_sensors(&db);
    let runtime_ingest_sensors = new_runtime_ingest_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    tokio::spawn(server().run(
        db,
        pcap_sensors,
        ingest_sensors,
        runtime_ingest_sensors,
        stream_direct_channels,
        Arc::new(Notify::new()),
        Some(Arc::new(Notify::new())),
        1024_u16,
    ))
}

async fn send_events<T: Serialize>(
    send: &mut quinn::SendStream,
    timestamp: i64,
    msg: T,
) -> anyhow::Result<()> {
    let msg_buf = encode_legacy(&msg)?;
    let buf = encode_legacy(&vec![(timestamp, msg_buf)])?;
    send_raw(send, &buf).await?;
    Ok(())
}

#[cfg(test)]
mod chrono_regression_tests {
    //! Regression tests for Chrono crate time handling in ingest module.
    //!
    //! These tests ensure that all time-related behaviors using the Chrono crate
    //! remain consistent when migrating to the Jiff crate. They focus on:
    //! - `Utc::now()` usage for sensor connection timestamps
    //! - `DateTime<Utc>` usage in `SensorInfo`
    //! - Duration operations

    use chrono::{DateTime, Duration, Utc};

    #[test]
    fn test_utc_now_sensor_timestamp() {
        // Test Utc::now() which is used in ingest.rs lines 186, 199, 1121 for sensor timestamps

        let timestamp1 = Utc::now();
        let timestamp2 = Utc::now();

        // Timestamps should be valid
        assert!(timestamp1.timestamp_nanos_opt().is_some());
        assert!(timestamp2.timestamp_nanos_opt().is_some());

        // Second timestamp should be >= first (monotonic)
        assert!(timestamp2 >= timestamp1);

        // Should be after Unix epoch
        assert!(timestamp1.timestamp() > 0);
    }

    #[test]
    fn test_datetime_utc_type_sensor_info() {
        // Test DateTime<Utc> type used in SensorInfo tuple (ingest.rs:63)
        // type SensorInfo = (String, DateTime<Utc>, ConnState);

        let sensor_name = "test_sensor".to_string();
        let connection_time = Utc::now();

        // Create a tuple similar to SensorInfo
        let sensor_info: (String, DateTime<Utc>) = (sensor_name.clone(), connection_time);

        assert_eq!(sensor_info.0, "test_sensor");
        assert_eq!(sensor_info.1, connection_time);
        assert!(sensor_info.1.timestamp_nanos_opt().is_some());
    }

    #[test]
    fn test_datetime_utc_ordering() {
        // Test DateTime ordering for sensor connection tracking

        let early = Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let late = Utc::now();

        assert!(late > early);
        assert!(late >= early);
        assert_eq!(early, early);
        assert_ne!(early, late);
    }

    #[test]
    fn test_duration_nanoseconds() {
        // Test Duration::nanoseconds() used in tests (tests.rs:169)

        let duration = Duration::nanoseconds(12345);

        assert_eq!(duration.num_nanoseconds().unwrap(), 12345);
        assert!(duration.num_microseconds().is_some());
        assert!(duration.num_milliseconds() > 0 || duration.num_nanoseconds().unwrap() < 1_000_000);
    }

    #[test]
    fn test_duration_seconds() {
        // Test Duration::seconds() used in tests (tests.rs:221)

        let one_second = Duration::seconds(1);

        assert_eq!(one_second.num_seconds(), 1);
        assert_eq!(one_second.num_milliseconds(), 1000);
        assert_eq!(one_second.num_nanoseconds().unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_datetime_duration_arithmetic() {
        // Test DateTime + Duration arithmetic used in tests

        let base_time = Utc::now();
        let duration = Duration::nanoseconds(12345);

        let later_time = base_time + duration;

        assert!(later_time > base_time);
        assert_eq!(
            (later_time.timestamp_nanos_opt().unwrap() - base_time.timestamp_nanos_opt().unwrap()),
            12345
        );

        // Test with seconds
        let one_second = Duration::seconds(1);
        let time_plus_second = base_time + one_second;

        assert_eq!(
            time_plus_second.timestamp_nanos_opt().unwrap(),
            base_time.timestamp_nanos_opt().unwrap() + 1_000_000_000
        );
    }

    #[test]
    fn test_timestamp_nanos_opt_usage() {
        // Test timestamp_nanos_opt() which is used throughout the tests

        let now = Utc::now();
        let timestamp_opt = now.timestamp_nanos_opt();

        // Should always succeed for current time
        assert!(timestamp_opt.is_some());

        let timestamp = timestamp_opt.unwrap();

        // Should be positive (after Unix epoch)
        assert!(timestamp > 0);

        // Round-trip conversion
        let dt_from_timestamp = chrono::TimeZone::timestamp_nanos(&Utc, timestamp);
        assert_eq!(dt_from_timestamp.timestamp_nanos_opt().unwrap(), timestamp);
    }

    #[test]
    fn test_duration_num_nanoseconds_unwrap() {
        // Test that Duration::num_nanoseconds() is safe to unwrap for reasonable values

        let durations = vec![
            Duration::nanoseconds(1),
            Duration::nanoseconds(12345),
            Duration::milliseconds(100),
            Duration::seconds(1),
            Duration::seconds(60),
            Duration::hours(1),
        ];

        for dur in durations {
            // All these should unwrap successfully
            let nanos = dur.num_nanoseconds().unwrap();
            assert!(nanos > 0);
        }
    }

    #[test]
    fn test_utc_now_multiple_calls_consistency() {
        // Test that multiple Utc::now() calls within a short time frame are consistent

        let timestamps: Vec<DateTime<Utc>> = (0..5).map(|_| Utc::now()).collect();

        // All should be valid
        for ts in &timestamps {
            assert!(ts.timestamp_nanos_opt().is_some());
        }

        // Should be monotonically increasing or equal
        for i in 1..timestamps.len() {
            assert!(timestamps[i] >= timestamps[i - 1]);
        }

        // All should be within a reasonable time window (1 second)
        let first = timestamps.first().unwrap();
        let last = timestamps.last().unwrap();
        let diff_ns = last.timestamp_nanos_opt().unwrap() - first.timestamp_nanos_opt().unwrap();

        assert!(diff_ns >= 0);
        assert!(diff_ns < 1_000_000_000); // Less than 1 second
    }

    #[test]
    fn test_datetime_properties_for_sensor_tracking() {
        // Test DateTime properties needed for sensor connection/disconnection tracking

        let connect_time = Utc::now();

        // Should have UTC timezone
        assert_eq!(connect_time.timezone(), Utc);

        // Should have valid timestamp
        assert!(connect_time.timestamp() > 0);
        assert!(connect_time.timestamp_nanos_opt().is_some());

        // Should be comparable
        let disconnect_time = Utc::now();
        assert!(disconnect_time >= connect_time);
    }
}
