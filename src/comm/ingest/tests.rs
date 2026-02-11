#![allow(clippy::items_after_statements)]

use std::{
    fs,
    future::IntoFuture,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicI64, Ordering},
    },
};

use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use chrono::{Duration, TimeZone, Utc};
use giganto_client::frame::SendError;
use giganto_client::ingest::log::SecuLog;
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use giganto_client::ingest::network::{MalformedDns, Radius};
use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};
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
use serde::{Serialize, de::DeserializeOwned};
use tempfile::TempDir;
static INIT: OnceLock<()> = OnceLock::new();

fn init_crypto() {
    INIT.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

use tokio::{
    sync::{Notify, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};

use super::Server;
use crate::{
    comm::{
        IngestSensors, PcapSensors, RunTimeIngestSensors, StreamDirectChannels, new_ingest_sensors,
        new_pcap_sensors, new_runtime_ingest_sensors, new_stream_direct_channels, to_cert_chain,
        to_private_key, to_root_cert,
    },
    server::{Certs, subject_from_cert},
    storage::{Database, DbOptions, RawEventStore, StorageKey},
};

const CERT_PATH: &str = "tests/certs/node1/cert.pem";
const KEY_PATH: &str = "tests/certs/node1/key.pem";
const CA_CERT_PATH: &str = "tests/certs/ca_cert.pem";
const HOST: &str = "node1";
const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const STOREABLE_RAW_EVENT_KINDS: &[RawEventKind] = &[
    RawEventKind::Conn,
    RawEventKind::Dns,
    RawEventKind::MalformedDns,
    RawEventKind::Log,
    RawEventKind::Http,
    RawEventKind::Rdp,
    RawEventKind::PeriodicTimeSeries,
    RawEventKind::Smtp,
    RawEventKind::Ntlm,
    RawEventKind::Kerberos,
    RawEventKind::Ssh,
    RawEventKind::DceRpc,
    RawEventKind::Statistics,
    RawEventKind::OpLog,
    RawEventKind::Packet,
    RawEventKind::Ftp,
    RawEventKind::Mqtt,
    RawEventKind::Ldap,
    RawEventKind::Tls,
    RawEventKind::Smb,
    RawEventKind::Nfs,
    RawEventKind::Bootp,
    RawEventKind::Dhcp,
    RawEventKind::Radius,
    RawEventKind::ProcessCreate,
    RawEventKind::FileCreateTime,
    RawEventKind::NetworkConnect,
    RawEventKind::ProcessTerminate,
    RawEventKind::ImageLoad,
    RawEventKind::FileCreate,
    RawEventKind::RegistryValueSet,
    RawEventKind::RegistryKeyRename,
    RawEventKind::FileCreateStreamHash,
    RawEventKind::PipeEvent,
    RawEventKind::DnsQuery,
    RawEventKind::FileDelete,
    RawEventKind::ProcessTamper,
    RawEventKind::FileDeleteDetected,
    RawEventKind::Netflow5,
    RawEventKind::Netflow9,
    RawEventKind::SecuLog,
];

struct TestClient {
    conn: Connection,
    endpoint: Endpoint,
}

impl TestClient {
    async fn new(server_addr: SocketAddr) -> Self {
        let endpoint = init_client();
        let conn = endpoint
            .connect(server_addr, HOST)
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

fn server(addr: SocketAddr) -> Server {
    let certs = load_test_certs();
    Server::new(addr, &certs)
}

#[allow(clippy::too_many_arguments)]
async fn run_server_with_ready(
    server: Server,
    db: Database,
    pcap_sensors: PcapSensors,
    ingest_sensors: IngestSensors,
    runtime_ingest_sensors: RunTimeIngestSensors,
    stream_direct_channels: StreamDirectChannels,
    notify_shutdown: Arc<Notify>,
    notify_sensor: Option<Arc<Notify>>,
    ack_transmission_cnt: u16,
    ready: oneshot::Sender<SocketAddr>,
) {
    let endpoint =
        Endpoint::server(server.server_config, server.server_address).expect("ingest endpoint");
    let local_addr = endpoint.local_addr().expect("ingest local addr");
    let _ = ready.send(local_addr);

    let (tx, rx) = mpsc::channel(100);
    let sensor_db = db.clone();
    tokio::spawn(super::check_sensors_conn(
        sensor_db,
        pcap_sensors.clone(),
        ingest_sensors.clone(),
        runtime_ingest_sensors.clone(),
        rx,
        notify_sensor,
        notify_shutdown.clone(),
    ));

    let shutdown_signal = Arc::new(std::sync::atomic::AtomicBool::new(false));

    loop {
        tokio::select! {
            Some(conn) = endpoint.accept() => {
                let sender = tx.clone();
                let db = db.clone();
                let pcap_sensors = pcap_sensors.clone();
                let stream_direct_channels = stream_direct_channels.clone();
                let notify_shutdown = notify_shutdown.clone();
                let shutdown_signal = shutdown_signal.clone();
                tokio::spawn(async move {
                    if let Err(e) = super::handle_connection(
                        conn,
                        db,
                        pcap_sensors,
                        sender,
                        stream_direct_channels,
                        notify_shutdown,
                        shutdown_signal,
                        ack_transmission_cnt,
                    )
                    .await
                    {
                        tracing::error!("Connection error: {e}");
                    }
                });
            }
            () = notify_shutdown.notified() => {
                endpoint.close(0_u32.into(), &[]);
                break;
            }
        }
    }
}

async fn spawn_server(db: Database) -> (SocketAddr, Arc<Notify>, JoinHandle<()>) {
    let pcap_sensors = new_pcap_sensors();
    let ingest_sensors = new_ingest_sensors(&db);
    let runtime_ingest_sensors = new_runtime_ingest_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let notify_shutdown = Arc::new(Notify::new());
    let (ready_tx, ready_rx) = oneshot::channel();
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
    let server = server(server_addr);
    let handle = tokio::spawn(run_server_with_ready(
        server,
        db,
        pcap_sensors,
        ingest_sensors,
        runtime_ingest_sensors,
        stream_direct_channels,
        notify_shutdown.clone(),
        Some(Arc::new(Notify::new())),
        1024_u16,
        ready_tx,
    ));
    let local_addr = tokio::time::timeout(std::time::Duration::from_secs(2), ready_rx)
        .await
        .expect("ingest server ready timeout")
        .expect("ingest server did not report addr");
    (local_addr, notify_shutdown, handle)
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

fn next_timestamp() -> i64 {
    static NEXT_TS: AtomicI64 = AtomicI64::new(1_700_000_000_000_000_000);
    NEXT_TS.fetch_add(1, Ordering::Relaxed)
}

struct TestHarness {
    _db_dir: TempDir,
    db: Database,
    client: TestClient,
    notify_shutdown: Arc<Notify>,
    server_handle: Option<JoinHandle<()>>,
}

impl TestHarness {
    async fn new() -> Self {
        init_crypto();
        let db_dir = tempfile::tempdir().expect("create ingest temp dir");
        let db = Database::open(db_dir.path(), &DbOptions::default())
            .expect("open ingest test database");
        let (server_addr, notify_shutdown, server_handle) = spawn_server(db.clone()).await;
        let client = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            TestClient::new(server_addr),
        )
        .await
        .expect("ingest client connect timeout");
        Self {
            _db_dir: db_dir,
            db,
            client,
            notify_shutdown,
            server_handle: Some(server_handle),
        }
    }

    async fn open_bi(&self) -> (quinn::SendStream, quinn::RecvStream) {
        self.client
            .conn
            .open_bi()
            .await
            .expect("failed to open stream")
    }

    async fn shutdown(mut self, reason: &[u8]) {
        self.client.conn.close(0u32.into(), reason);
        self.client.endpoint.wait_idle().await;
        self.notify_shutdown.notify_waiters();
        if let Some(handle) = self.server_handle.take() {
            tokio::time::timeout(std::time::Duration::from_secs(2), handle)
                .await
                .expect("ingest server shutdown timeout")
                .expect("ingest server task failed");
        }
    }
}

fn test_sensor_name() -> String {
    static TEST_SENSOR: OnceLock<String> = OnceLock::new();
    TEST_SENSOR
        .get_or_init(|| {
            let certs = load_test_certs();
            let (_agent, sensor) =
                subject_from_cert(&certs.certs).expect("failed to parse test certificate");
            sensor
        })
        .clone()
}

fn expected_raw_event_bytes(kind: RawEventKind, body_bytes: Vec<u8>) -> Vec<u8> {
    match kind {
        RawEventKind::OpLog => {
            let mut op_log: OpLog =
                bincode::deserialize(&body_bytes).expect("failed to deserialize OpLog");
            op_log.sensor = test_sensor_name();
            bincode::serialize(&op_log).expect("failed to serialize OpLog")
        }
        _ => body_bytes,
    }
}

fn read_single_raw_event<T: DeserializeOwned>(store: &RawEventStore<'_, T>) -> Option<Vec<u8>> {
    let mut iter = store.iter_forward();
    let first = match iter.next() {
        None => return None,
        Some(value) => value.expect("failed to read stored event"),
    };
    assert!(iter.next().is_none(), "expected exactly one stored event");
    let (_key, value) = first;
    Some(value.to_vec())
}

fn read_single_raw_event_kv<T: DeserializeOwned>(
    store: &RawEventStore<'_, T>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut iter = store.iter_forward();
    let first = match iter.next() {
        None => return None,
        Some(value) => value.expect("failed to read stored event"),
    };
    assert!(iter.next().is_none(), "expected exactly one stored event");
    let (key, value) = first;
    Some((key.to_vec(), value.to_vec()))
}

fn read_raw_event_from_db(db: &Database, kind: RawEventKind) -> Option<Vec<u8>> {
    match kind {
        RawEventKind::Conn => read_single_raw_event(&db.conn_store().unwrap()),
        RawEventKind::Dns => read_single_raw_event(&db.dns_store().unwrap()),
        RawEventKind::MalformedDns => read_single_raw_event(&db.malformed_dns_store().unwrap()),
        RawEventKind::Log => read_single_raw_event(&db.log_store().unwrap()),
        RawEventKind::Http => read_single_raw_event(&db.http_store().unwrap()),
        RawEventKind::Rdp => read_single_raw_event(&db.rdp_store().unwrap()),
        RawEventKind::PeriodicTimeSeries => {
            read_single_raw_event(&db.periodic_time_series_store().unwrap())
        }
        RawEventKind::Smtp => read_single_raw_event(&db.smtp_store().unwrap()),
        RawEventKind::Ntlm => read_single_raw_event(&db.ntlm_store().unwrap()),
        RawEventKind::Kerberos => read_single_raw_event(&db.kerberos_store().unwrap()),
        RawEventKind::Ssh => read_single_raw_event(&db.ssh_store().unwrap()),
        RawEventKind::DceRpc => read_single_raw_event(&db.dce_rpc_store().unwrap()),
        RawEventKind::Statistics => read_single_raw_event(&db.statistics_store().unwrap()),
        RawEventKind::OpLog => read_single_raw_event(&db.op_log_store().unwrap()),
        RawEventKind::Packet => read_single_raw_event(&db.packet_store().unwrap()),
        RawEventKind::Ftp => read_single_raw_event(&db.ftp_store().unwrap()),
        RawEventKind::Mqtt => read_single_raw_event(&db.mqtt_store().unwrap()),
        RawEventKind::Ldap => read_single_raw_event(&db.ldap_store().unwrap()),
        RawEventKind::Tls => read_single_raw_event(&db.tls_store().unwrap()),
        RawEventKind::Smb => read_single_raw_event(&db.smb_store().unwrap()),
        RawEventKind::Nfs => read_single_raw_event(&db.nfs_store().unwrap()),
        RawEventKind::Bootp => read_single_raw_event(&db.bootp_store().unwrap()),
        RawEventKind::Dhcp => read_single_raw_event(&db.dhcp_store().unwrap()),
        RawEventKind::Radius => read_single_raw_event(&db.radius_store().unwrap()),
        RawEventKind::ProcessCreate => read_single_raw_event(&db.process_create_store().unwrap()),
        RawEventKind::FileCreateTime => {
            read_single_raw_event(&db.file_create_time_store().unwrap())
        }
        RawEventKind::NetworkConnect => read_single_raw_event(&db.network_connect_store().unwrap()),
        RawEventKind::ProcessTerminate => {
            read_single_raw_event(&db.process_terminate_store().unwrap())
        }
        RawEventKind::ImageLoad => read_single_raw_event(&db.image_load_store().unwrap()),
        RawEventKind::FileCreate => read_single_raw_event(&db.file_create_store().unwrap()),
        RawEventKind::RegistryValueSet => {
            read_single_raw_event(&db.registry_value_set_store().unwrap())
        }
        RawEventKind::RegistryKeyRename => {
            read_single_raw_event(&db.registry_key_rename_store().unwrap())
        }
        RawEventKind::FileCreateStreamHash => {
            read_single_raw_event(&db.file_create_stream_hash_store().unwrap())
        }
        RawEventKind::PipeEvent => read_single_raw_event(&db.pipe_event_store().unwrap()),
        RawEventKind::DnsQuery => read_single_raw_event(&db.dns_query_store().unwrap()),
        RawEventKind::FileDelete => read_single_raw_event(&db.file_delete_store().unwrap()),
        RawEventKind::ProcessTamper => read_single_raw_event(&db.process_tamper_store().unwrap()),
        RawEventKind::FileDeleteDetected => {
            read_single_raw_event(&db.file_delete_detected_store().unwrap())
        }
        RawEventKind::Netflow5 => read_single_raw_event(&db.netflow5_store().unwrap()),
        RawEventKind::Netflow9 => read_single_raw_event(&db.netflow9_store().unwrap()),
        RawEventKind::SecuLog => read_single_raw_event(&db.secu_log_store().unwrap()),
        _ => panic!("no test storage mapping for {kind:?}"),
    }
}

fn read_raw_event_kv_from_db(db: &Database, kind: RawEventKind) -> Option<(Vec<u8>, Vec<u8>)> {
    match kind {
        RawEventKind::Log => read_single_raw_event_kv(&db.log_store().unwrap()),
        RawEventKind::PeriodicTimeSeries => {
            read_single_raw_event_kv(&db.periodic_time_series_store().unwrap())
        }
        RawEventKind::Packet => read_single_raw_event_kv(&db.packet_store().unwrap()),
        RawEventKind::Statistics => read_single_raw_event_kv(&db.statistics_store().unwrap()),
        RawEventKind::SecuLog => read_single_raw_event_kv(&db.secu_log_store().unwrap()),
        _ => panic!("no test storage key mapping for {kind:?}"),
    }
}

async fn wait_for_raw_event(db: &Database, kind: RawEventKind) -> Vec<u8> {
    let deadline = Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(value) = read_raw_event_from_db(db, kind) {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for stored {kind:?} event"
        );
        sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn wait_for_raw_event_kv(db: &Database, kind: RawEventKind) -> (Vec<u8>, Vec<u8>) {
    let deadline = Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(value) = read_raw_event_kv_from_db(db, kind) {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for stored {kind:?} event"
        );
        sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn with_timeout<F, T>(label: &str, dur: std::time::Duration, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    timeout(dur, fut)
        .await
        .unwrap_or_else(|_| panic!("{label} timed out after {dur:?}"))
}

async fn wait_until<F, Fut>(label: &str, dur: std::time::Duration, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + dur;
    loop {
        if cond().await {
            return;
        }
        assert!(Instant::now() < deadline, "{label} timed out after {dur:?}");
        sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn assert_no_raw_events(db: &Database, kinds: &[RawEventKind]) {
    let deadline = Instant::now() + std::time::Duration::from_millis(200);
    loop {
        for kind in kinds {
            assert!(
                read_raw_event_from_db(db, *kind).is_none(),
                "unexpected stored {kind:?} event"
            );
        }
        if Instant::now() >= deadline {
            break;
        }
        sleep(std::time::Duration::from_millis(10)).await;
    }
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

struct SingleEventCase {
    name: &'static str,
    kind: RawEventKind,
    body: Vec<u8>,
}

fn single_event_case<T: Serialize>(
    name: &'static str,
    kind: RawEventKind,
    body: T,
) -> SingleEventCase {
    SingleEventCase {
        name,
        kind,
        body: bincode::serialize(&body).expect("serialize test body"),
    }
}

async fn run_single_event_case(case: &SingleEventCase) {
    let expected_bytes = expected_raw_event_bytes(case.kind, case.body.clone());
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;
    send_record_header(&mut send, case.kind).await.unwrap();
    let timestamp = next_timestamp();
    let buf = bincode::serialize(&vec![(timestamp, case.body.clone())]).unwrap();
    send_raw(&mut send, &buf).await.unwrap();
    send.finish().expect("failed to shutdown stream");
    let stored = wait_for_raw_event(&harness.db, case.kind).await;
    harness.shutdown(b"done").await;
    assert_eq!(expected_bytes, stored, "case {}", case.name);
}

#[allow(clippy::too_many_lines)]
fn single_event_cases() -> Vec<SingleEventCase> {
    let tmp_dur = Duration::nanoseconds(12345);
    vec![
        single_event_case(
            "conn",
            RawEventKind::Conn,
            Conn {
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
            },
        ),
        single_event_case(
            "dns",
            RawEventKind::Dns,
            Dns {
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
            },
        ),
        single_event_case(
            "malformed_dns",
            RawEventKind::MalformedDns,
            MalformedDns {
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
            },
        ),
        single_event_case(
            "log",
            RawEventKind::Log,
            Log {
                kind: String::from("Hello"),
                log: base64_engine.decode("aGVsbG8gd29ybGQ=").unwrap(),
            },
        ),
        single_event_case(
            "http",
            RawEventKind::Http,
            Http {
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
            },
        ),
        single_event_case(
            "rdp",
            RawEventKind::Rdp,
            Rdp {
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
                resp_l2_bytes: 100,
                cookie: "rdp_test".to_string(),
            },
        ),
        single_event_case(
            "periodic_time_series",
            RawEventKind::PeriodicTimeSeries,
            PeriodicTimeSeries {
                id: String::from("model_one"),
                data: vec![1.1, 2.2, 3.3, 4.4, 5.5, 6.6],
            },
        ),
        single_event_case(
            "smtp",
            RawEventKind::Smtp,
            Smtp {
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
            },
        ),
        single_event_case(
            "ntlm",
            RawEventKind::Ntlm,
            Ntlm {
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
            },
        ),
        single_event_case(
            "kerberos",
            RawEventKind::Kerberos,
            Kerberos {
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
            },
        ),
        single_event_case(
            "ssh",
            RawEventKind::Ssh,
            Ssh {
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
            },
        ),
        single_event_case(
            "dce_rpc",
            RawEventKind::DceRpc,
            DceRpc {
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
            },
        ),
        single_event_case(
            "statistics",
            RawEventKind::Statistics,
            Statistics {
                core: 1,
                period: 600,
                stats: vec![(RawEventKind::Statistics, 1000, 10_001_000)],
            },
        ),
        single_event_case(
            "op_log",
            RawEventKind::OpLog,
            OpLog {
                sensor: String::new(),
                agent_name: "giganto".to_string(),
                log_level: OpLogLevel::Info,
                contents: "op_log".to_string(),
            },
        ),
        single_event_case(
            "packet",
            RawEventKind::Packet,
            Packet {
                packet_timestamp: next_timestamp(),
                packet: vec![0, 1, 0, 1, 0, 1],
            },
        ),
        single_event_case(
            "ftp",
            RawEventKind::Ftp,
            Ftp {
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
            },
        ),
        single_event_case(
            "mqtt",
            RawEventKind::Mqtt,
            Mqtt {
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
            },
        ),
        single_event_case(
            "ldap",
            RawEventKind::Ldap,
            Ldap {
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
            },
        ),
        single_event_case(
            "tls",
            RawEventKind::Tls,
            Tls {
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
            },
        ),
        single_event_case(
            "smb",
            RawEventKind::Smb,
            Smb {
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
            },
        ),
        single_event_case(
            "nfs",
            RawEventKind::Nfs,
            Nfs {
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
            },
        ),
        single_event_case(
            "bootp",
            RawEventKind::Bootp,
            Bootp {
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
            },
        ),
        single_event_case(
            "dhcp",
            RawEventKind::Dhcp,
            Dhcp {
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
            },
        ),
        single_event_case(
            "radius",
            RawEventKind::Radius,
            Radius {
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
            },
        ),
        single_event_case(
            "process_create",
            RawEventKind::ProcessCreate,
            ProcessCreate {
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
            },
        ),
        single_event_case(
            "file_create_time",
            RawEventKind::FileCreateTime,
            FileCreationTimeChanged {
                agent_name: "agent".to_string(),
                process_guid: "guid".to_string(),
                process_id: 123,
                image: "image".to_string(),
                target_filename: "target".to_string(),
                creation_utc_time: 1000,
                previous_creation_utc_time: 900,
                agent_id: "agent_id".to_string(),
                user: "user".to_string(),
            },
        ),
        single_event_case(
            "network_connect",
            RawEventKind::NetworkConnect,
            NetworkConnection {
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
            },
        ),
        single_event_case(
            "process_terminate",
            RawEventKind::ProcessTerminate,
            ProcessTerminated {
                agent_name: "agent".to_string(),
                process_guid: "guid".to_string(),
                process_id: 123,
                image: "image".to_string(),
                user: "user".to_string(),
                agent_id: "agent_id".to_string(),
            },
        ),
        single_event_case(
            "image_load",
            RawEventKind::ImageLoad,
            ImageLoaded {
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
            },
        ),
        single_event_case(
            "file_create",
            RawEventKind::FileCreate,
            FileCreate {
                agent_name: "agent".to_string(),
                process_guid: "guid".to_string(),
                process_id: 123,
                image: "image".to_string(),
                target_filename: "target".to_string(),
                creation_utc_time: 1000,
                agent_id: "agent_id".to_string(),
                user: "user".to_string(),
            },
        ),
        single_event_case(
            "registry_value_set",
            RawEventKind::RegistryValueSet,
            RegistryValueSet {
                agent_name: "agent".to_string(),
                process_guid: "guid".to_string(),
                process_id: 123,
                image: "image".to_string(),
                target_object: "target".to_string(),
                details: "details".to_string(),
                event_type: "type".to_string(),
                user: "user".to_string(),
                agent_id: "agent_id".to_string(),
            },
        ),
        single_event_case(
            "registry_key_rename",
            RawEventKind::RegistryKeyRename,
            RegistryKeyValueRename {
                agent_name: "agent".to_string(),
                process_guid: "guid".to_string(),
                process_id: 123,
                image: "image".to_string(),
                target_object: "target".to_string(),
                new_name: "new".to_string(),
                event_type: "type".to_string(),
                user: "user".to_string(),
                agent_id: "agent_id".to_string(),
            },
        ),
        single_event_case(
            "file_create_stream_hash",
            RawEventKind::FileCreateStreamHash,
            FileCreateStreamHash {
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
            },
        ),
        single_event_case(
            "pipe_event",
            RawEventKind::PipeEvent,
            PipeEvent {
                agent_name: "agent".to_string(),
                process_guid: "guid".to_string(),
                process_id: 123,
                pipe_name: "pipe".to_string(),
                image: "image".to_string(),
                event_type: "type".to_string(),
                user: "user".to_string(),
                agent_id: "agent_id".to_string(),
            },
        ),
        single_event_case(
            "dns_query",
            RawEventKind::DnsQuery,
            DnsEvent {
                agent_name: "agent".to_string(),
                process_guid: "guid".to_string(),
                process_id: 123,
                query_name: "query".to_string(),
                query_status: 0,
                query_results: vec!["result".to_string()],
                image: "image".to_string(),
                user: "user".to_string(),
                agent_id: "agent_id".to_string(),
            },
        ),
        single_event_case(
            "file_delete",
            RawEventKind::FileDelete,
            FileDelete {
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
            },
        ),
        single_event_case(
            "process_tamper",
            RawEventKind::ProcessTamper,
            ProcessTampering {
                agent_name: "agent".to_string(),
                process_guid: "guid".to_string(),
                process_id: 123,
                image: "image".to_string(),
                tamper_type: "type".to_string(),
                user: "user".to_string(),
                agent_id: "agent_id".to_string(),
            },
        ),
        single_event_case(
            "file_delete_detected",
            RawEventKind::FileDeleteDetected,
            FileDeleteDetected {
                agent_name: "agent".to_string(),
                process_guid: "guid".to_string(),
                process_id: 123,
                image: "image".to_string(),
                target_filename: "target".to_string(),
                hashes: vec!["hash".to_string()],
                is_executable: true,
                user: "user".to_string(),
                agent_id: "agent_id".to_string(),
            },
        ),
        single_event_case(
            "netflow5",
            RawEventKind::Netflow5,
            Netflow5 {
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
            },
        ),
        single_event_case(
            "netflow9",
            RawEventKind::Netflow9,
            Netflow9 {
                orig_addr: ip("192.168.1.1"),
                orig_port: 1234,
                resp_addr: ip("192.168.1.2"),
                resp_port: 80,
                proto: 6,
                contents: "payload".to_string(),
                sequence: 1,
                source_id: 1,
                template_id: 256,
            },
        ),
        single_event_case(
            "secu_log",
            RawEventKind::SecuLog,
            SecuLog {
                log_type: "type".to_string(),
                version: "1.0".to_string(),
                orig_addr: Some(ip("192.168.1.1")),
                orig_port: Some(1234),
                resp_addr: Some(ip("192.168.1.2")),
                resp_port: Some(80),
                proto: Some(6),
                contents: "content".to_string(),
                kind: "kind".to_string(),
            },
        ),
    ]
}

#[tokio::test]
async fn single_event_roundtrip_all_kinds() {
    for case in single_event_cases() {
        run_single_event_case(&case).await;
    }
}

#[tokio::test]
async fn log_key_includes_sensor_and_kind() {
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    let timestamp = next_timestamp();
    let log_body = Log {
        kind: "log_kind".to_string(),
        log: vec![1, 2, 3],
    };

    send_record(&mut send, RAW_EVENT_KIND_LOG, timestamp, &log_body)
        .await
        .unwrap();
    send.finish().expect("failed to shutdown stream");

    let (key, _value) = wait_for_raw_event_kv(&harness.db, RAW_EVENT_KIND_LOG).await;
    let expected_key = StorageKey::builder()
        .start_key(&test_sensor_name())
        .mid_key(Some(log_body.kind.as_bytes().to_vec()))
        .end_key(timestamp)
        .build()
        .key();
    assert_eq!(expected_key, key);

    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn periodic_time_series_key_uses_id() {
    const RAW_EVENT_KIND_PERIODIC: RawEventKind = RawEventKind::PeriodicTimeSeries;
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    let timestamp = next_timestamp();
    let body = PeriodicTimeSeries {
        id: String::from("series_id"),
        data: vec![1.0, 2.0],
    };

    send_record(&mut send, RAW_EVENT_KIND_PERIODIC, timestamp, &body)
        .await
        .unwrap();
    send.finish().expect("failed to shutdown stream");

    let (key, _value) = wait_for_raw_event_kv(&harness.db, RAW_EVENT_KIND_PERIODIC).await;
    let expected_key = StorageKey::builder()
        .start_key(&body.id)
        .end_key(timestamp)
        .build()
        .key();
    assert_eq!(expected_key, key);

    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn packet_key_includes_ingest_timestamp_and_packet_timestamp() {
    const RAW_EVENT_KIND_PACKET: RawEventKind = RawEventKind::Packet;
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    let timestamp = next_timestamp();
    let body = Packet {
        packet_timestamp: next_timestamp(),
        packet: vec![0, 1, 2, 3],
    };

    send_record(&mut send, RAW_EVENT_KIND_PACKET, timestamp, &body)
        .await
        .unwrap();
    send.finish().expect("failed to shutdown stream");

    let (key, _value) = wait_for_raw_event_kv(&harness.db, RAW_EVENT_KIND_PACKET).await;
    let expected_key = StorageKey::builder()
        .start_key(&test_sensor_name())
        .mid_key(Some(timestamp.to_be_bytes().to_vec()))
        .end_key(body.packet_timestamp)
        .build()
        .key();
    assert_eq!(expected_key, key);

    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn statistics_key_includes_core() {
    const RAW_EVENT_KIND_STATISTICS: RawEventKind = RawEventKind::Statistics;
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    let timestamp = next_timestamp();
    let body = Statistics {
        core: 7,
        period: 600,
        stats: vec![(RAW_EVENT_KIND_STATISTICS, 1000, 10_001_000)],
    };

    send_record(&mut send, RAW_EVENT_KIND_STATISTICS, timestamp, &body)
        .await
        .unwrap();
    send.finish().expect("failed to shutdown stream");

    let (key, _value) = wait_for_raw_event_kv(&harness.db, RAW_EVENT_KIND_STATISTICS).await;
    let expected_key = StorageKey::builder()
        .start_key(&test_sensor_name())
        .mid_key(Some(body.core.to_be_bytes().to_vec()))
        .end_key(timestamp)
        .build()
        .key();
    assert_eq!(expected_key, key);

    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn secu_log_key_includes_kind() {
    const RAW_EVENT_KIND_SECU_LOG: RawEventKind = RawEventKind::SecuLog;
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    let timestamp = next_timestamp();
    let body = SecuLog {
        log_type: "type".to_string(),
        version: "1.0".to_string(),
        orig_addr: Some(ip("192.168.1.1")),
        orig_port: Some(1234),
        resp_addr: Some(ip("192.168.1.2")),
        resp_port: Some(80),
        proto: Some(6),
        contents: "content".to_string(),
        kind: "secu_kind".to_string(),
    };

    send_record(&mut send, RAW_EVENT_KIND_SECU_LOG, timestamp, &body)
        .await
        .unwrap();
    send.finish().expect("failed to shutdown stream");

    let (key, _value) = wait_for_raw_event_kv(&harness.db, RAW_EVENT_KIND_SECU_LOG).await;
    let expected_key = StorageKey::builder()
        .start_key(&test_sensor_name())
        .mid_key(Some(body.kind.as_bytes().to_vec()))
        .end_key(timestamp)
        .build()
        .key();
    assert_eq!(expected_key, key);

    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn ack_interval_sends_last_timestamp() {
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
    let base_timestamp = next_timestamp();
    send_events(&mut send_log, base_timestamp, log_body)
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

    let recv_timestamp = with_timeout(
        "receive_ack_timestamp",
        std::time::Duration::from_secs(2),
        receive_ack_timestamp(&mut recv_log),
    )
    .await
    .unwrap();

    send_log.finish().expect("failed to shutdown stream");
    harness.shutdown(b"log_done").await;
    assert_eq!(base_timestamp + 1023, recv_timestamp);
}

#[tokio::test]
async fn channel_close_sends_ack_timestamp() {
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
    with_timeout(
        "recv_ack_timestamp_bytes",
        std::time::Duration::from_secs(2),
        recv_bytes(&mut recv_log, &mut ts_buf),
    )
    .await
    .unwrap();
    let recv_timestamp = i64::from_be_bytes(ts_buf);

    send_log.finish().expect("failed to shutdown stream");
    harness.shutdown(b"log_done").await;
    assert_eq!(CHANNEL_CLOSE_TIMESTAMP, recv_timestamp);
}

#[tokio::test]
async fn invalid_record_header() {
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    // Send an unknown RawEventKind value as the header.
    let invalid_header = u32::MAX.to_le_bytes();
    send_bytes(&mut send, &invalid_header)
        .await
        .expect("failed to send data");

    send.finish().expect("failed to shutdown stream");
    assert_no_raw_events(&harness.db, STOREABLE_RAW_EVENT_KINDS).await;
    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn incomplete_record_header() {
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    // Send fewer than 4 bytes for the header.
    send_raw(&mut send, &[0x01, 0x00])
        .await
        .expect("failed to send data");
    send.finish().expect("failed to shutdown stream");

    assert_no_raw_events(&harness.db, STOREABLE_RAW_EVENT_KINDS).await;
    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn invalid_body_all_kinds() {
    let invalid_body = b"invalid_body_data";

    for kind in STOREABLE_RAW_EVENT_KINDS {
        let harness = TestHarness::new().await;
        let (mut send, _) = harness.open_bi().await;

        send_record_header(&mut send, *kind).await.unwrap();
        send_raw(&mut send, invalid_body)
            .await
            .expect("failed to send data");
        send.finish().expect("failed to shutdown stream");

        assert_no_raw_events(&harness.db, STOREABLE_RAW_EVENT_KINDS).await;
        harness.shutdown(b"done").await;
    }
}

#[tokio::test]
async fn send_ack_timestamp_sends_be_bytes() {
    init_crypto();
    let certs = load_test_certs();

    let server_config = crate::server::config_server(&certs).unwrap();
    let endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    )
    .unwrap();
    let server_addr = endpoint.local_addr().expect("ack server addr");

    let server_task = tokio::spawn(async move {
        let incoming = with_timeout(
            "ack_server_accept",
            std::time::Duration::from_secs(2),
            endpoint.accept(),
        )
        .await
        .unwrap();
        let conn = with_timeout(
            "ack_server_incoming",
            std::time::Duration::from_secs(2),
            incoming.into_future(),
        )
        .await
        .unwrap();
        let (_mut_send, mut recv) = with_timeout(
            "ack_server_accept_bi",
            std::time::Duration::from_secs(2),
            conn.accept_bi(),
        )
        .await
        .unwrap();

        let mut buf = [0u8; 8];
        with_timeout(
            "ack_server_recv_bytes",
            std::time::Duration::from_secs(2),
            recv_bytes(&mut recv, &mut buf),
        )
        .await
        .unwrap();

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

    let received_data = with_timeout(
        "ack_server_task",
        std::time::Duration::from_secs(2),
        server_task,
    )
    .await
    .unwrap();
    assert_eq!(received_data, timestamp.to_be_bytes());

    conn.close(0u32.into(), b"done");
}

#[tokio::test]
async fn check_sensors_conn_updates_runtime_state() {
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

    wait_until(
        "sensor connected",
        std::time::Duration::from_secs(1),
        || async {
            let ingest_has = ingest_sensors.read().await.contains(&sensor_name);
            let runtime_has = runtime_ingest_sensors
                .read()
                .await
                .get(&sensor_name)
                .is_some();
            ingest_has && runtime_has
        },
    )
    .await;

    // Test Disconnection
    tx.send((sensor_name.clone(), now, ConnState::Disconnected, false))
        .await
        .unwrap();
    wait_until(
        "sensor disconnected",
        std::time::Duration::from_secs(1),
        || async {
            !runtime_ingest_sensors
                .read()
                .await
                .contains_key(&sensor_name)
        },
    )
    .await;

    notify_shutdown.notify_one();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn notify_sensor_on_connect_updates_state_and_db() {
    use tokio::sync::mpsc;

    use crate::comm::ingest::ConnState;

    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let ingest_sensors = new_ingest_sensors(&db);
    let runtime_ingest_sensors = new_runtime_ingest_sensors();
    let (tx, rx) = mpsc::channel(10);
    let notify_shutdown = Arc::new(Notify::new());
    let notify_sensor = Arc::new(Notify::new());

    let db_clone = db.clone();
    let pcap_sensors_clone = pcap_sensors.clone();
    let ingest_sensors_clone = ingest_sensors.clone();
    let runtime_ingest_sensors_clone = runtime_ingest_sensors.clone();
    let notify_shutdown_clone = notify_shutdown.clone();
    let notify_sensor_clone = notify_sensor.clone();

    tokio::spawn(async move {
        super::check_sensors_conn(
            db_clone,
            pcap_sensors_clone,
            ingest_sensors_clone,
            runtime_ingest_sensors_clone,
            rx,
            Some(notify_sensor_clone),
            notify_shutdown_clone,
        )
        .await
        .unwrap();
    });

    let sensor_name = "notify_sensor".to_string();
    let now = Utc::now();

    tx.send((sensor_name, now, ConnState::Connected, false))
        .await
        .unwrap();

    with_timeout(
        "notify_sensor",
        std::time::Duration::from_secs(1),
        notify_sensor.notified(),
    )
    .await;

    wait_until(
        "notify_sensor_state",
        std::time::Duration::from_secs(1),
        || async {
            let ingest_has = ingest_sensors.read().await.contains("notify_sensor");
            let runtime_has = runtime_ingest_sensors
                .read()
                .await
                .contains_key("notify_sensor");
            ingest_has && runtime_has
        },
    )
    .await;

    let second_notify = timeout(
        std::time::Duration::from_millis(200),
        notify_sensor.notified(),
    )
    .await;
    let _ = second_notify.expect_err("notify_sensor fired more than once");

    let sensor_store = db.sensors_store().unwrap();
    assert!(
        sensor_store.sensor_list().contains("notify_sensor"),
        "sensor_store not updated on connect"
    );

    // Duplicate connect should notify again.
    tx.send((
        "notify_sensor".to_string(),
        now,
        ConnState::Connected,
        false,
    ))
    .await
    .unwrap();
    with_timeout(
        "notify_sensor_duplicate",
        std::time::Duration::from_secs(1),
        notify_sensor.notified(),
    )
    .await;

    // Disconnect then reconnect should notify again and restore runtime state.
    tx.send((
        "notify_sensor".to_string(),
        now,
        ConnState::Disconnected,
        false,
    ))
    .await
    .unwrap();
    wait_until(
        "notify_sensor_disconnected",
        std::time::Duration::from_secs(1),
        || async {
            !runtime_ingest_sensors
                .read()
                .await
                .contains_key("notify_sensor")
        },
    )
    .await;
    tx.send((
        "notify_sensor".to_string(),
        now,
        ConnState::Connected,
        false,
    ))
    .await
    .unwrap();
    with_timeout(
        "notify_sensor_reconnect",
        std::time::Duration::from_secs(1),
        notify_sensor.notified(),
    )
    .await;
    wait_until(
        "notify_sensor_state_reconnected",
        std::time::Duration::from_secs(1),
        || async {
            runtime_ingest_sensors
                .read()
                .await
                .contains_key("notify_sensor")
        },
    )
    .await;

    notify_shutdown.notify_one();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
}

#[tokio::test]
async fn notify_sensor_and_pcap_disconnect_behaviors() {
    use tokio::sync::mpsc;

    use crate::comm::ingest::ConnState;

    let harness = TestHarness::new().await;
    let db = harness.db.clone();
    let pcap_sensors = new_pcap_sensors();
    let ingest_sensors = new_ingest_sensors(&db);
    let runtime_ingest_sensors = new_runtime_ingest_sensors();
    let (tx, rx) = mpsc::channel(10);
    let notify_shutdown = Arc::new(Notify::new());
    let notify_sensor = Arc::new(Notify::new());

    let db_clone = db.clone();
    let pcap_sensors_clone = pcap_sensors.clone();
    let ingest_sensors_clone = ingest_sensors.clone();
    let runtime_ingest_sensors_clone = runtime_ingest_sensors.clone();
    let notify_shutdown_clone = notify_shutdown.clone();
    let notify_sensor_clone = notify_sensor.clone();

    tokio::spawn(async move {
        super::check_sensors_conn(
            db_clone,
            pcap_sensors_clone,
            ingest_sensors_clone,
            runtime_ingest_sensors_clone,
            rx,
            Some(notify_sensor_clone),
            notify_shutdown_clone,
        )
        .await
        .unwrap();
    });

    let sensor_name = "notify_sensor_disconnect".to_string();
    let now = Utc::now();

    pcap_sensors
        .write()
        .await
        .insert(sensor_name.clone(), vec![harness.client.conn.clone()]);

    tx.send((sensor_name, now, ConnState::Disconnected, false))
        .await
        .unwrap();

    let res = timeout(
        std::time::Duration::from_millis(200),
        notify_sensor.notified(),
    )
    .await;
    let _ = res.expect_err("notify_sensor fired on disconnect");

    let ingest_has = ingest_sensors
        .read()
        .await
        .contains("notify_sensor_disconnect");
    let runtime_has = runtime_ingest_sensors
        .read()
        .await
        .contains_key("notify_sensor_disconnect");
    assert!(!ingest_has, "ingest_sensors updated on disconnect");
    assert!(!runtime_has, "runtime_ingest_sensors updated on disconnect");

    let pcap_len = pcap_sensors
        .read()
        .await
        .get("notify_sensor_disconnect")
        .map(Vec::len)
        .unwrap_or_default();
    assert_eq!(pcap_len, 1, "pcap_sensors should not change on non-pcap");

    // Pcap disconnect should remove one connection without notifying.
    tx.send((
        "notify_sensor_disconnect".to_string(),
        now,
        ConnState::Disconnected,
        true,
    ))
    .await
    .unwrap();
    let res = timeout(
        std::time::Duration::from_millis(200),
        notify_sensor.notified(),
    )
    .await;
    let _ = res.expect_err("notify_sensor fired on pcap disconnect");

    let pcap_len = pcap_sensors
        .read()
        .await
        .get("notify_sensor_disconnect")
        .map(Vec::len)
        .unwrap_or_default();
    assert_eq!(pcap_len, 0, "pcap_sensors not updated on pcap disconnect");

    notify_shutdown.notify_one();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    harness.shutdown(b"done").await;
}

#[tokio::test]
async fn check_sensors_conn_pcap_removes_runtime_on_disconnect() {
    // Verifies that runtime sensors update correctly for pcap sensors on connect/disconnect.
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
    wait_until(
        "pcap_sensor_connected",
        std::time::Duration::from_secs(1),
        || async {
            runtime_ingest_sensors
                .read()
                .await
                .contains_key(&sensor_name)
        },
    )
    .await;

    tx.send((sensor_name.clone(), now, ConnState::Disconnected, true))
        .await
        .unwrap();
    wait_until(
        "pcap_sensor_disconnected",
        std::time::Duration::from_secs(1),
        || async {
            !runtime_ingest_sensors
                .read()
                .await
                .contains_key(&sensor_name)
        },
    )
    .await;

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
async fn handle_connection_closes_on_handshake_failure() {
    init_crypto();
    let db_dir = tempfile::tempdir().expect("create ingest temp dir");
    let db =
        Database::open(db_dir.path(), &DbOptions::default()).expect("open ingest test database");
    let (server_addr, notify_shutdown, _server_handle) = spawn_server(db).await;

    let endpoint = init_client();
    let conn = endpoint
        .connect(server_addr, HOST)
        .expect("Failed to connect")
        .await
        .expect("Failed to finish connection");

    let (mut send, _) = conn.open_bi().await.expect("failed to open stream");

    // send_bytes sends [len][data]. Data is empty, so it sends [0,0,0,0].
    send_bytes(&mut send, &[]).await.unwrap();
    send.finish().unwrap();

    let err = with_timeout(
        "connection_close_after_handshake_failure",
        std::time::Duration::from_secs(2),
        conn.closed(),
    )
    .await; // Waits for connection close
    assert!(matches!(err, quinn::ConnectionError::ApplicationClosed(_)));
    endpoint.wait_idle().await;
    notify_shutdown.notify_waiters();
}

#[tokio::test]
async fn send_ack_timestamp_after_finish_fails() {
    let harness = TestHarness::new().await;
    let (mut send, _recv) = harness.open_bi().await;

    super::send_ack_timestamp(&mut send, 100).await.unwrap();

    // Now FINISH/CLOSE the stream to force a failure on next send?
    send.finish().unwrap(); // Half-closed

    // Sending on a finished stream should fail?
    // Quic SendStream: "Writing to a stream that has been finished or reset will return an error."
    let res = super::send_ack_timestamp(&mut send, 200).await;
    assert!(matches!(res.unwrap_err(), SendError::WriteError(_)));

    harness.shutdown(b"done").await;
}
