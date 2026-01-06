#![allow(clippy::items_after_statements)]

use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, OnceLock},
};

use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use chrono::{Duration, TimeZone, Utc};
use giganto_client::{
    RawEventKind,
    connection::client_handshake,
    frame::{recv_bytes, send_bytes, send_raw},
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
const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

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

fn load_test_certs() -> Arc<Certs> {
    let cert_pem = fs::read(CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    Arc::new(Certs {
        certs: cert,
        key,
        root,
    })
}

fn server() -> Server {
    let certs = load_test_certs();
    Server::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT),
        &certs,
    )
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
    let msg_buf = bincode::serialize(&msg)?;
    let buf = bincode::serialize(&vec![(timestamp, msg_buf)])?;
    send_raw(send, &buf).await?;
    Ok(())
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

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

fn default_start_time() -> i64 {
    Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
        .unwrap()
        .timestamp_nanos_opt()
        .unwrap()
}

fn now_ts() -> i64 {
    Utc::now().timestamp_nanos_opt().unwrap()
}

// Common test data constants
mod test_constants {
    pub const TEST_ORIG_ADDR: &str = "192.168.4.76";
    pub const TEST_ORIG_PORT: u16 = 46378;
    pub const TEST_RESP_ADDR: &str = "31.3.245.133";
    pub const TEST_RESP_PORT: u16 = 80;
    pub const TEST_PROTO: u8 = 17;
    pub const TEST_DURATION: i64 = 1_000_000_000;
    pub const TEST_ORIG_PKTS: u64 = 1;
    pub const TEST_RESP_PKTS: u64 = 1;
    pub const TEST_ORIG_L2_BYTES: u64 = 100;
    pub const TEST_RESP_L2_BYTES: u64 = 200;
}

// Helper to create common network fields
struct NetworkEventBase {
    orig_addr: IpAddr,
    orig_port: u16,
    resp_addr: IpAddr,
    resp_port: u16,
    proto: u8,
    start_time: i64,
    duration: i64,
    orig_pkts: u64,
    resp_pkts: u64,
    orig_l2_bytes: u64,
    resp_l2_bytes: u64,
}

impl Default for NetworkEventBase {
    fn default() -> Self {
        Self {
            orig_addr: ip(test_constants::TEST_ORIG_ADDR),
            orig_port: test_constants::TEST_ORIG_PORT,
            resp_addr: ip(test_constants::TEST_RESP_ADDR),
            resp_port: test_constants::TEST_RESP_PORT,
            proto: test_constants::TEST_PROTO,
            start_time: default_start_time(),
            duration: test_constants::TEST_DURATION,
            orig_pkts: test_constants::TEST_ORIG_PKTS,
            resp_pkts: test_constants::TEST_RESP_PKTS,
            orig_l2_bytes: test_constants::TEST_ORIG_L2_BYTES,
            resp_l2_bytes: test_constants::TEST_RESP_L2_BYTES,
        }
    }
}

struct TestHarness {
    _lock: tokio::sync::MutexGuard<'static, u32>,
    _db_dir: TempDir,
    client: TestClient,
}

impl TestHarness {
    async fn new() -> Self {
        init_crypto();
        let lock = get_token().lock().await;
        let db_dir = tempfile::tempdir().unwrap();
        run_server(&db_dir);
        let client = TestClient::new().await;
        Self {
            _lock: lock,
            _db_dir: db_dir,
            client,
        }
    }

    async fn open_bi(&self) -> (quinn::SendStream, quinn::RecvStream) {
        self.client
            .conn
            .open_bi()
            .await
            .expect("failed to open stream")
    }

    async fn shutdown(self, reason: &[u8]) {
        self.client.conn.close(0u32.into(), reason);
        self.client.endpoint.wait_idle().await;
    }
}

async fn run_single_event_test<T: Serialize>(kind: RawEventKind, body: T, close_reason: &[u8]) {
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;
    send_record(&mut send, kind, now_ts(), body).await.unwrap();
    send.finish().expect("failed to shutdown stream");
    harness.shutdown(close_reason).await;
}

async fn send_record<T: Serialize>(
    send: &mut quinn::SendStream,
    kind: RawEventKind,
    timestamp: i64,
    msg: T,
) -> anyhow::Result<()> {
    send_record_header(send, kind).await?;
    send_events(send, timestamp, msg).await
}

// Macro to generate simple network event tests with common fields
macro_rules! simple_network_event_test {
    ($test_name:ident, $event_kind:ident, $event_type:ty, $body:expr) => {
        #[tokio::test]
        async fn $test_name() {
            let base = NetworkEventBase::default();
            let body: $event_type = {
                let build = $body;
                build(base)
            };
            run_single_event_test(
                RawEventKind::$event_kind,
                body,
                concat!(stringify!($test_name), "_done").as_bytes(),
            )
            .await;
        }
    };
}

#[tokio::test]
async fn conn() {
    const RAW_EVENT_KIND_CONN: RawEventKind = RawEventKind::Conn;

    let tmp_dur = Duration::nanoseconds(12345);
    let conn_body = Conn {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("192.168.4.76"),
        resp_port: 80,
        proto: 6,
        conn_state: "sf".to_string(),
        start_time: default_start_time(),
        duration: tmp_dur.num_nanoseconds().unwrap(),
        service: "-".to_string(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
        orig_l2_bytes: 21515,
        resp_l2_bytes: 27889,
    };

    run_single_event_test(RAW_EVENT_KIND_CONN, conn_body, b"conn_done").await;
}

#[tokio::test]
async fn dns() {
    const RAW_EVENT_KIND_DNS: RawEventKind = RawEventKind::Dns;

    let dns_body = Dns {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("31.3.245.133"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_DNS, dns_body, b"dns_done").await;
}

#[tokio::test]
async fn malformed_dns() {
    use giganto_client::ingest::network::MalformedDns;
    const RAW_EVENT_KIND_MALFORMED_DNS: RawEventKind = RawEventKind::MalformedDns;

    let body = MalformedDns {
        orig_addr: ip("192.168.1.1"),
        orig_port: 1234,
        resp_addr: ip("192.168.1.2"),
        resp_port: 53,
        proto: 17,
        start_time: 1000,
        trans_id: 0,
        flags: 0,
        additional_count: 0,
        answer_count: 0,
        authority_count: 0,
        query_count: 0,
        resp_count: 0,
        query_bytes: 0,
        resp_bytes: 0,
        duration: 0,
        query_body: vec![],
        resp_body: vec![],
        question_count: 0,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 100,
    };

    run_single_event_test(RAW_EVENT_KIND_MALFORMED_DNS, body, b"done").await;
}

#[tokio::test]
async fn log() {
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;

    let log_body = Log {
        kind: String::from("Hello"),
        log: base64_engine.decode("aGVsbG8gd29ybGQ=").unwrap(),
    };

    run_single_event_test(RAW_EVENT_KIND_LOG, log_body, b"log_done").await;
}

#[tokio::test]
async fn http() {
    const RAW_EVENT_KIND_HTTP: RawEventKind = RawEventKind::Http;

    let http_body = Http {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("192.168.4.76"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_HTTP, http_body, b"http_done").await;
}

simple_network_event_test!(rdp, Rdp, Rdp, |base: NetworkEventBase| Rdp {
    orig_addr: base.orig_addr,
    orig_port: base.orig_port,
    resp_addr: base.resp_addr,
    resp_port: base.resp_port,
    proto: base.proto,
    start_time: base.start_time,
    duration: base.duration,
    orig_pkts: base.orig_pkts,
    resp_pkts: base.resp_pkts,
    orig_l2_bytes: base.orig_l2_bytes,
    resp_l2_bytes: base.resp_l2_bytes,
    cookie: "rdp_test".to_string(),
});

#[tokio::test]
async fn periodic_time_series() {
    const RAW_EVENT_KIND_PERIOD_TIME_SERIES: RawEventKind = RawEventKind::PeriodicTimeSeries;

    let periodic_time_series_body = PeriodicTimeSeries {
        id: String::from("model_one"),
        data: vec![1.1, 2.2, 3.3, 4.4, 5.5, 6.6],
    };

    run_single_event_test(
        RAW_EVENT_KIND_PERIOD_TIME_SERIES,
        periodic_time_series_body,
        b"periodic_time_series_done",
    )
    .await;
}

#[tokio::test]
async fn smtp() {
    const RAW_EVENT_KIND_SMTP: RawEventKind = RawEventKind::Smtp;

    let smtp_body = Smtp {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("192.168.4.76"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_SMTP, smtp_body, b"smtp_done").await;
}

#[tokio::test]
async fn ntlm() {
    const RAW_EVENT_KIND_NTLM: RawEventKind = RawEventKind::Ntlm;

    let ntlm_body = Ntlm {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("192.168.4.76"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_NTLM, ntlm_body, b"ntlm_done").await;
}

#[tokio::test]
async fn kerberos() {
    const RAW_EVENT_KIND_KERBEROS: RawEventKind = RawEventKind::Kerberos;

    let kerberos_body = Kerberos {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("192.168.4.76"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_KERBEROS, kerberos_body, b"kerberos_done").await;
}

#[tokio::test]
async fn ssh() {
    const RAW_EVENT_KIND_SSH: RawEventKind = RawEventKind::Ssh;

    let ssh_body = Ssh {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("192.168.4.76"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_SSH, ssh_body, b"ssh_done").await;
}

#[tokio::test]
async fn dce_rpc() {
    const RAW_EVENT_KIND_DCE_RPC: RawEventKind = RawEventKind::DceRpc;

    let dce_rpc_body = DceRpc {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("192.168.4.76"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_DCE_RPC, dce_rpc_body, b"dce_rpc_done").await;
}

#[tokio::test]
async fn statistics() {
    const RAW_EVENT_KIND_STATISTICS: RawEventKind = RawEventKind::Statistics;

    let statistics_body = Statistics {
        core: 1,
        period: 600,
        stats: vec![(RAW_EVENT_KIND_STATISTICS, 1000, 10_001_000)],
    };

    run_single_event_test(
        RAW_EVENT_KIND_STATISTICS,
        statistics_body,
        b"statistics_done",
    )
    .await;
}

#[tokio::test]
async fn op_log() {
    const RAW_EVENT_KIND_OPLOG: RawEventKind = RawEventKind::OpLog;

    let op_log_body = OpLog {
        sensor: String::new(),
        agent_name: "giganto".to_string(),
        log_level: OpLogLevel::Info,
        contents: "op_log".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_OPLOG, op_log_body, b"oplog_done").await;
}

#[tokio::test]
async fn packet() {
    const RAW_EVENT_KIND_PACKET: RawEventKind = RawEventKind::Packet;

    let packet: Vec<u8> = vec![0, 1, 0, 1, 0, 1];
    let packet_body = Packet {
        packet_timestamp: now_ts(),
        packet,
    };

    run_single_event_test(RAW_EVENT_KIND_PACKET, packet_body, b"packet_done").await;
}

#[tokio::test]
async fn ftp() {
    const RAW_EVENT_KIND_FTP: RawEventKind = RawEventKind::Ftp;

    let ftp_body = Ftp {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("31.3.245.133"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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
            data_orig_addr: ip("192.168.4.76"),
            data_resp_addr: ip("31.3.245.133"),
            data_resp_port: 80,
            file: "ftp_file".to_string(),
            file_size: 100,
            file_id: "1".to_string(),
        }],
    };

    run_single_event_test(RAW_EVENT_KIND_FTP, ftp_body, b"ftp_done").await;
}

#[tokio::test]
async fn mqtt() {
    const RAW_EVENT_KIND_MQTT: RawEventKind = RawEventKind::Mqtt;

    let mqtt_body = Mqtt {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("31.3.245.133"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_MQTT, mqtt_body, b"mqtt_done").await;
}

#[tokio::test]
async fn ldap() {
    const RAW_EVENT_KIND_LDAP: RawEventKind = RawEventKind::Ldap;

    let ldap_body = Ldap {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("31.3.245.133"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_LDAP, ldap_body, b"ldap_done").await;
}

#[tokio::test]
async fn tls() {
    const RAW_EVENT_KIND_TLS: RawEventKind = RawEventKind::Tls;

    let tls_body = Tls {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("31.3.245.133"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_TLS, tls_body, b"tls_done").await;
}

#[tokio::test]
async fn smb() {
    const RAW_EVENT_KIND_SMB: RawEventKind = RawEventKind::Smb;

    let smb_body = Smb {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("31.3.245.133"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
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

    run_single_event_test(RAW_EVENT_KIND_SMB, smb_body, b"smb_done").await;
}

#[tokio::test]
async fn nfs() {
    const RAW_EVENT_KIND_NFS: RawEventKind = RawEventKind::Nfs;

    let nfs_body = Nfs {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("31.3.245.133"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        read_files: vec![],
        write_files: vec![],
    };

    run_single_event_test(RAW_EVENT_KIND_NFS, nfs_body, b"nfs_done").await;
}

#[tokio::test]
async fn bootp() {
    const RAW_EVENT_KIND_BOOTP: RawEventKind = RawEventKind::Bootp;

    let bootp_body = Bootp {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("31.3.245.133"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        op: 0,
        htype: 0,
        hops: 0,
        xid: 0,
        ciaddr: ip("192.168.4.1"),
        yiaddr: ip("192.168.4.2"),
        siaddr: ip("192.168.4.3"),
        giaddr: ip("192.168.4.4"),
        chaddr: vec![0, 1, 2],
        sname: "sname".to_string(),
        file: "file".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_BOOTP, bootp_body, b"bootp_done").await;
}

#[tokio::test]
async fn dhcp() {
    const RAW_EVENT_KIND_DHCP: RawEventKind = RawEventKind::Dhcp;

    let dhcp_body = Dhcp {
        orig_addr: ip("192.168.4.76"),
        orig_port: 46378,
        resp_addr: ip("31.3.245.133"),
        resp_port: 80,
        proto: 17,
        start_time: default_start_time(),
        duration: 1_000_000_000,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 200,
        msg_type: 0,
        ciaddr: ip("192.168.4.1"),
        yiaddr: ip("192.168.4.2"),
        siaddr: ip("192.168.4.3"),
        giaddr: ip("192.168.4.4"),
        subnet_mask: ip("192.168.4.5"),
        router: vec![ip("192.168.1.11"), ip("192.168.1.22")],
        domain_name_server: vec![ip("192.168.1.33"), ip("192.168.1.44")],
        req_ip_addr: ip("192.168.4.6"),
        lease_time: 1,
        server_id: ip("192.168.4.7"),
        param_req_list: vec![0, 1, 2],
        message: "message".to_string(),
        renewal_time: 1,
        rebinding_time: 1,
        class_id: vec![0, 1, 2],
        client_id_type: 1,
        client_id: vec![0, 1, 2],
    };

    run_single_event_test(RAW_EVENT_KIND_DHCP, dhcp_body, b"dhcp_done").await;
}

#[tokio::test]
async fn radius() {
    use giganto_client::ingest::network::Radius;
    const RAW_EVENT_KIND_RADIUS: RawEventKind = RawEventKind::Radius;

    let body = Radius {
        orig_addr: ip("192.168.1.1"),
        orig_port: 1234,
        resp_addr: ip("192.168.1.2"),
        resp_port: 1812,
        proto: 17,
        start_time: 1000,
        code: 1,
        id: 1,
        auth: "auth".to_string(),
        chap_passwd: "pass".as_bytes().to_vec(),
        user_name: "user".as_bytes().to_vec(),
        nas_ip: ip("192.168.1.3"),
        nas_port: 123,
        nas_id: "nas".as_bytes().to_vec(),
        nas_port_type: 1,
        message: "msg".to_string(),
        state: vec![],
        resp_code: 2,
        resp_auth: "resp_auth".to_string(),
        user_passwd: "user_pass".as_bytes().to_vec(),
        duration: 0,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 100,
    };

    run_single_event_test(RAW_EVENT_KIND_RADIUS, body, b"done").await;
}

#[tokio::test]
async fn process_create() {
    use giganto_client::ingest::sysmon::ProcessCreate;
    const RAW_EVENT_KIND_PROCESS_CREATE: RawEventKind = RawEventKind::ProcessCreate;

    let body = ProcessCreate {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        file_version: "1.0".to_string(),
        description: "desc".to_string(),
        product: "product".to_string(),
        company: "company".to_string(),
        original_file_name: "orig".to_string(),
        command_line: "cmd".to_string(),
        current_directory: "dir".to_string(),
        user: "user".to_string(),
        logon_guid: "logon".to_string(),
        logon_id: 1,
        terminal_session_id: 1,
        integrity_level: "high".to_string(),
        hashes: vec!["hash".to_string()],
        parent_process_guid: "pguid".to_string(),
        parent_process_id: 1,
        parent_image: "pimage".to_string(),
        parent_command_line: "pcmd".to_string(),
        agent_id: "agent_id".to_string(),
        parent_user: "puser".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_PROCESS_CREATE, body, b"done").await;
}

#[tokio::test]
async fn file_create_time() {
    use giganto_client::ingest::sysmon::FileCreationTimeChanged;
    const RAW_EVENT_KIND_FILE_CREATE_TIME: RawEventKind = RawEventKind::FileCreateTime;

    let body = FileCreationTimeChanged {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        target_filename: "target".to_string(),
        creation_utc_time: 1000,
        previous_creation_utc_time: 900,
        agent_id: "agent_id".to_string(),
        user: "user".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_FILE_CREATE_TIME, body, b"done").await;
}

#[tokio::test]
async fn network_connect() {
    use giganto_client::ingest::sysmon::NetworkConnection;
    const RAW_EVENT_KIND_NETWORK_CONNECT: RawEventKind = RawEventKind::NetworkConnect;

    let body = NetworkConnection {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        user: "user".to_string(),
        protocol: "tcp".to_string(),
        initiated: true,
        source_is_ipv6: false,
        source_ip: ip("192.168.1.1"),
        source_hostname: "src".to_string(),
        source_port: 1234,
        source_port_name: "port".to_string(),
        destination_is_ipv6: false,
        destination_ip: ip("1.1.1.1"),
        destination_hostname: "dst".to_string(),
        destination_port: 80,
        destination_port_name: "http".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_NETWORK_CONNECT, body, b"done").await;
}

#[tokio::test]
async fn process_terminate() {
    use giganto_client::ingest::sysmon::ProcessTerminated;
    const RAW_EVENT_KIND_PROCESS_TERMINATE: RawEventKind = RawEventKind::ProcessTerminate;

    let body = ProcessTerminated {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        user: "user".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_PROCESS_TERMINATE, body, b"done").await;
}

#[tokio::test]
async fn image_load() {
    use giganto_client::ingest::sysmon::ImageLoaded;
    const RAW_EVENT_KIND_IMAGE_LOAD: RawEventKind = RawEventKind::ImageLoad;

    let body = ImageLoaded {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        image_loaded: "loaded".to_string(),
        file_version: "1.0".to_string(),
        description: "desc".to_string(),
        product: "product".to_string(),
        company: "company".to_string(),
        original_file_name: "orig".to_string(),
        hashes: vec!["hash".to_string()],
        signed: true,
        signature: "sig".to_string(),
        signature_status: "status".to_string(),
        user: "user".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_IMAGE_LOAD, body, b"done").await;
}

#[tokio::test]
async fn file_create() {
    use giganto_client::ingest::sysmon::FileCreate;
    const RAW_EVENT_KIND_FILE_CREATE: RawEventKind = RawEventKind::FileCreate;

    let body = FileCreate {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        target_filename: "target".to_string(),
        creation_utc_time: 1000,
        agent_id: "agent_id".to_string(),
        user: "user".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_FILE_CREATE, body, b"done").await;
}

#[tokio::test]
async fn registry_value_set() {
    use giganto_client::ingest::sysmon::RegistryValueSet;
    const RAW_EVENT_KIND_REGISTRY_VALUE_SET: RawEventKind = RawEventKind::RegistryValueSet;

    let body = RegistryValueSet {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        target_object: "target".to_string(),
        details: "details".to_string(),
        event_type: "type".to_string(),
        user: "user".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_REGISTRY_VALUE_SET, body, b"done").await;
}

#[tokio::test]
async fn registry_key_rename() {
    use giganto_client::ingest::sysmon::RegistryKeyValueRename;
    const RAW_EVENT_KIND_REGISTRY_KEY_RENAME: RawEventKind = RawEventKind::RegistryKeyRename;

    let body = RegistryKeyValueRename {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        target_object: "target".to_string(),
        new_name: "new".to_string(),
        event_type: "type".to_string(),
        user: "user".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_REGISTRY_KEY_RENAME, body, b"done").await;
}

#[tokio::test]
async fn file_create_stream_hash() {
    use giganto_client::ingest::sysmon::FileCreateStreamHash;
    const RAW_EVENT_KIND_FILE_CREATE_STREAM_HASH: RawEventKind = RawEventKind::FileCreateStreamHash;

    let body = FileCreateStreamHash {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        target_filename: "target".to_string(),
        creation_utc_time: 1000,
        hash: vec!["hash".to_string()],
        contents: "contents".to_string(),
        user: "user".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_FILE_CREATE_STREAM_HASH, body, b"done").await;
}

#[tokio::test]
async fn pipe_event() {
    use giganto_client::ingest::sysmon::PipeEvent;
    const RAW_EVENT_KIND_PIPE_EVENT: RawEventKind = RawEventKind::PipeEvent;

    let body = PipeEvent {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        pipe_name: "pipe".to_string(),
        image: "image".to_string(),
        event_type: "type".to_string(),
        user: "user".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_PIPE_EVENT, body, b"done").await;
}

#[tokio::test]
async fn dns_query() {
    use giganto_client::ingest::sysmon::DnsEvent;
    const RAW_EVENT_KIND_DNS_QUERY: RawEventKind = RawEventKind::DnsQuery;

    let body = DnsEvent {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        query_name: "query".to_string(),
        query_status: 0,
        query_results: vec!["result".to_string()],
        image: "image".to_string(),
        user: "user".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_DNS_QUERY, body, b"done").await;
}

#[tokio::test]
async fn file_delete() {
    use giganto_client::ingest::sysmon::FileDelete;
    const RAW_EVENT_KIND_FILE_DELETE: RawEventKind = RawEventKind::FileDelete;

    let body = FileDelete {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        target_filename: "target".to_string(),
        agent_id: "agent_id".to_string(),
        hashes: vec!["hash".to_string()],
        is_executable: true,
        archived: true,
        user: "user".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_FILE_DELETE, body, b"done").await;
}

#[tokio::test]
async fn process_tamper() {
    use giganto_client::ingest::sysmon::ProcessTampering;
    const RAW_EVENT_KIND_PROCESS_TAMPER: RawEventKind = RawEventKind::ProcessTamper;

    let body = ProcessTampering {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        tamper_type: "type".to_string(),
        user: "user".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_PROCESS_TAMPER, body, b"done").await;
}

#[tokio::test]
async fn file_delete_detected() {
    use giganto_client::ingest::sysmon::FileDeleteDetected;
    const RAW_EVENT_KIND_FILE_DELETE_DETECTED: RawEventKind = RawEventKind::FileDeleteDetected;

    let body = FileDeleteDetected {
        agent_name: "agent".to_string(),
        process_guid: "guid".to_string(),
        process_id: 123,
        image: "image".to_string(),
        target_filename: "target".to_string(),
        hashes: vec!["hash".to_string()],
        is_executable: true,
        user: "user".to_string(),
        agent_id: "agent_id".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_FILE_DELETE_DETECTED, body, b"done").await;
}

#[tokio::test]
async fn netflow5() {
    use giganto_client::ingest::netflow::Netflow5;
    const RAW_EVENT_KIND_NETFLOW5: RawEventKind = RawEventKind::Netflow5;

    let body = Netflow5 {
        src_addr: ip("192.168.1.1"),
        dst_addr: ip("192.168.1.2"),
        next_hop: ip("10.0.0.1"),
        input: 1,
        output: 2,
        d_pkts: 10,
        d_octets: 1000,
        first: 100,
        last: 200,
        src_port: 1234,
        dst_port: 80,
        tcp_flags: 0,
        prot: 6,
        tos: 0,
        src_as: 0,
        dst_as: 0,
        src_mask: 24,
        dst_mask: 24,
        sampling_mode: 0,
        sampling_rate: 0,
        engine_type: 0,
        engine_id: 0,
        sequence: 0,
    };

    run_single_event_test(RAW_EVENT_KIND_NETFLOW5, body, b"done").await;
}

#[tokio::test]
async fn netflow9() {
    use giganto_client::ingest::netflow::Netflow9;
    const RAW_EVENT_KIND_NETFLOW9: RawEventKind = RawEventKind::Netflow9;

    let body = Netflow9 {
        orig_addr: ip("192.168.1.1"),
        orig_port: 1234,
        resp_addr: ip("192.168.1.2"),
        resp_port: 80,
        proto: 6,
        contents: "payload".to_string(),
        sequence: 1,
        source_id: 1,
        template_id: 256,
    };

    run_single_event_test(RAW_EVENT_KIND_NETFLOW9, body, b"done").await;
}

#[tokio::test]
async fn secu_log() {
    use giganto_client::ingest::log::SecuLog;
    const RAW_EVENT_KIND_SECU_LOG: RawEventKind = RawEventKind::SecuLog;

    let body = SecuLog {
        log_type: "type".to_string(),
        version: "1.0".to_string(),
        orig_addr: Some(ip("192.168.1.1")),
        orig_port: Some(1234),
        resp_addr: Some(ip("192.168.1.2")),
        resp_port: Some(80),
        proto: Some(6),
        contents: "content".to_string(),
        kind: "kind".to_string(),
    };

    run_single_event_test(RAW_EVENT_KIND_SECU_LOG, body, b"done").await;
}

#[tokio::test]
async fn ack_info() {
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;

    let harness = TestHarness::new().await;
    let (mut send_log, mut recv_log) = harness.open_bi().await;

    let log_body = Log {
        kind: String::from("Hello Server I am Log"),
        log: vec![0; 10],
    };

    send_record_header(&mut send_log, RAW_EVENT_KIND_LOG)
        .await
        .unwrap();
    let base_timestamp = now_ts();
    send_events(&mut send_log, now_ts(), log_body)
        .await
        .unwrap();

    for i in 0..1023 {
        let log_body: Log = Log {
            kind: String::from("Hello Server I am Log"),
            log: vec![0; 10],
        };
        send_events(&mut send_log, base_timestamp + i64::from(i + 1), log_body)
            .await
            .unwrap();
    }

    let recv_timestamp = receive_ack_timestamp(&mut recv_log).await.unwrap();

    send_log.finish().expect("failed to shutdown stream");
    harness.shutdown(b"log_done").await;
    assert_eq!(base_timestamp + 1023, recv_timestamp);
}

#[tokio::test]
async fn one_short_reproduce_channel_close() {
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;
    const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
    const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";

    let harness = TestHarness::new().await;
    let (mut send_log, mut recv_log) = harness.open_bi().await;

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
    harness.shutdown(b"log_done").await;
    assert_eq!(CHANNEL_CLOSE_TIMESTAMP, recv_timestamp);
}

#[tokio::test]
async fn invalid_record_header() {
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    // Send random bytes as header
    let invalid_header = b"invalid_header_data";
    send_raw(&mut send, invalid_header)
        .await
        .expect("failed to send data");

    // The server should close the stream or log an error, but the connection might stay open or close depending on error handling.
    // We verify that the client can finish without panic, implying the server handled the bad data gracefully (e.g. by closing the stream).
    // In this test setup, we just expect the send operation to succeed. The verification is that the server doesn't crash.

    send.finish().expect("failed to shutdown stream");
    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn invalid_body() {
    const RAW_EVENT_KIND_DNS: RawEventKind = RawEventKind::Dns;
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    send_record_header(&mut send, RAW_EVENT_KIND_DNS)
        .await
        .unwrap();

    // Send invalid body (random bytes instead of Dns struct)
    let invalid_body = b"invalid_body_data";
    send_raw(&mut send, invalid_body)
        .await
        .expect("failed to send data");

    send.finish().expect("failed to shutdown stream");
    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn test_send_ack_timestamp() {
    init_crypto();
    let _lock = get_token().lock().await;

    // Use a unique port for isolation
    const TEST_PORT_ACK_ISOLATED: u16 = 60197;
    let certs = load_test_certs();

    let server_config = crate::server::config_server(&certs).unwrap();
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT_ACK_ISOLATED);
    let endpoint = quinn::Endpoint::server(server_config, server_addr).unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (_mut_send, mut recv) = conn.accept_bi().await.unwrap();

        let mut buf = [0u8; 8];
        recv_bytes(&mut recv, &mut buf).await.unwrap();

        // return the data to be verified
        buf.to_vec()
    });

    let client_endpoint = init_client();
    let conn = client_endpoint
        .connect(server_addr, HOST)
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();

    let timestamp: i64 = 123_456_789;
    super::send_ack_timestamp(&mut send, timestamp)
        .await
        .unwrap();
    send.finish().unwrap();

    let received_data = server_task.await.unwrap();
    assert_eq!(received_data, timestamp.to_be_bytes());

    conn.close(0u32.into(), b"done");
}

#[tokio::test]
async fn test_check_sensors_conn() {
    use tokio::sync::mpsc;

    use crate::comm::ingest::ConnState;

    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let ingest_sensors = new_ingest_sensors(&db);
    let runtime_ingest_sensors = new_runtime_ingest_sensors();
    let (tx, rx) = mpsc::channel(10);
    let notify_shutdown = Arc::new(Notify::new());

    let db_clone = db.clone();
    let pcap_sensors_clone = pcap_sensors.clone();
    let ingest_sensors_clone = ingest_sensors.clone();
    let runtime_ingest_sensors_clone = runtime_ingest_sensors.clone();
    let notify_shutdown_clone = notify_shutdown.clone();

    tokio::spawn(async move {
        super::check_sensors_conn(
            db_clone,
            pcap_sensors_clone,
            ingest_sensors_clone,
            runtime_ingest_sensors_clone,
            rx,
            None,
            notify_shutdown_clone,
        )
        .await
        .unwrap();
    });

    let sensor_name = "test_sensor".to_string();
    let now = Utc::now();

    // Test Connection
    tx.send((sensor_name.clone(), now, ConnState::Connected, false))
        .await
        .unwrap();

    // Yield to let check_sensors_conn process
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert!(ingest_sensors.read().await.contains(&sensor_name));
    assert!(
        runtime_ingest_sensors
            .read()
            .await
            .get(&sensor_name)
            .is_some()
    );

    // Test Disconnection
    tx.send((sensor_name.clone(), now, ConnState::Disconnected, false))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert!(
        !runtime_ingest_sensors
            .read()
            .await
            .contains_key(&sensor_name)
    );

    notify_shutdown.notify_one();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
}

#[tokio::test]
async fn test_check_sensors_conn_pcap() {
    // Verifies that the internal state management logic (check_sensors_conn) behaves correctly
    // when sensors (such as "piglet") responsible for packet capture (PCAP) are connected or disconnected.
    use tokio::sync::mpsc;

    use crate::comm::ingest::ConnState;

    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let ingest_sensors = new_ingest_sensors(&db);
    let runtime_ingest_sensors = new_runtime_ingest_sensors();
    let (tx, rx) = mpsc::channel::<super::SensorInfo>(10);
    let notify_shutdown = Arc::new(Notify::new());

    let db_clone = db.clone();
    let pcap_sensors_clone = pcap_sensors.clone();
    let ingest_sensors_clone = ingest_sensors.clone();
    let runtime_ingest_sensors_clone = runtime_ingest_sensors.clone();
    let notify_shutdown_clone = notify_shutdown.clone();

    tokio::spawn(async move {
        super::check_sensors_conn(
            db_clone,
            pcap_sensors_clone,
            ingest_sensors_clone,
            runtime_ingest_sensors_clone,
            rx,
            None,
            notify_shutdown_clone,
        )
        .await
        .unwrap();
    });

    let sensor_name = "piglet_sensor".to_string(); // "piglet" implies pcap sensor logic in handle_connection, but here we explicitly set is_pcap_sensor
    let now = Utc::now();

    tx.send((sensor_name.clone(), now, ConnState::Connected, true))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    tx.send((sensor_name.clone(), now, ConnState::Disconnected, true))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert!(
        !runtime_ingest_sensors
            .read()
            .await
            .contains_key(&sensor_name)
    );

    notify_shutdown.notify_one();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
}

#[tokio::test]
async fn test_handle_connection_handshake_failure() {
    init_crypto();
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(&db_dir);

    let endpoint = init_client();
    let conn = endpoint
        .connect(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT),
            HOST,
        )
        .expect("Failed to connect")
        .await
        .expect("Failed to finish connection");

    let (mut send, _) = conn.open_bi().await.expect("failed to open stream");

    // send_bytes sends [len][data]. Data is empty, so it sends [0,0,0,0].
    send_bytes(&mut send, &[]).await.unwrap();
    send.finish().unwrap();

    let err = conn.closed().await; // Waits for connection close
    assert!(matches!(err, quinn::ConnectionError::ApplicationClosed(_)));

    let _err_msg = conn.close_reason();
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    endpoint.wait_idle().await;
}

#[tokio::test]
async fn test_send_ack_timestamp_failure() {
    let harness = TestHarness::new().await;
    let (mut send, _recv) = harness.open_bi().await;

    super::send_ack_timestamp(&mut send, 100).await.unwrap();

    // Now FINISH/CLOSE the stream to force a failure on next send?
    send.finish().unwrap(); // Half-closed

    // Sending on a finished stream should fail?
    // Quic SendStream: "Writing to a stream that has been finished or reset will return an error."
    let res = super::send_ack_timestamp(&mut send, 200).await;
    assert!(res.is_err());

    harness.shutdown(b"done").await;
}
