#![allow(clippy::items_after_statements)]

#[cfg(not(feature = "bootroot"))]
use std::fs;
use std::{
    cell::RefCell,
    future::IntoFuture,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicI64, Ordering},
    },
};

use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use giganto_client::frame::SendError;
use giganto_client::ingest::log::SecuLog;
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use giganto_client::ingest::network::{Icmp, MalformedDns, Radius};
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
            Bootp, Conn, DceRpc, DceRpcContext, Dhcp, Dns, Ftp, FtpCommand, Http, Kerberos, Ldap,
            Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
        },
        receive_ack_timestamp, send_record_header,
        statistics::Statistics,
        timeseries::PeriodicTimeSeries,
    },
};
use quinn::{Connection, Endpoint};
use serde::{Serialize, de::DeserializeOwned};
use tempfile::TempDir;

use crate::datetime::DateTime;
static INIT: OnceLock<()> = OnceLock::new();

fn init_crypto() {
    INIT.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

use tokio::{
    sync::{Notify, watch},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use super::Server;
#[cfg(not(feature = "bootroot"))]
use crate::comm::to_cert_chain;
#[cfg(feature = "bootroot")]
use crate::test_bootroot::{
    bootroot_chain_node1_client_certs, bootroot_chain_node1_fixture,
    bootroot_chain_node1_server_certs,
};
use crate::{
    comm::{
        IngestSensors, PcapSensors, RunTimeIngestSensors, new_ingest_sensors, new_pcap_sensors,
        new_runtime_ingest_sensors, new_stream_direct_channels,
    },
    server::{Certs, config_client, host_fqdn_from_cert, service_fqdn_from_cert},
    storage::{Database, DbOptions, RawEventStore, StorageKey},
    tls_reload::{TlsMaterial, TlsWatch},
};

const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const FIXED_CONN_DURATION_NANOS: i64 = 12_345;
/// How long a test waits for a cancelled ingest entry task to drain and
/// return. Generous enough that a slow machine does not fail the test, short
/// enough that a task which never observes cancellation does.
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
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
    RawEventKind::Icmp,
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

#[cfg(not(feature = "bootroot"))]
fn test_server_name() -> &'static str {
    "node1"
}

#[cfg(feature = "bootroot")]
fn test_server_name() -> &'static str {
    &bootroot_chain_node1_fixture().server_name
}

struct TestClient {
    conn: Connection,
    endpoint: Endpoint,
}

impl TestClient {
    async fn new(server_addr: SocketAddr) -> Self {
        let endpoint = init_client();
        let conn = endpoint
            .connect(server_addr, test_server_name())
            .expect(
                "Failed to connect server's endpoint, Please check if the setting value is correct",
            )
            .await
            .expect("Failed to connect server's endpoint, Please make sure the Server is alive");
        client_handshake(&conn, PROTOCOL_VERSION).await.unwrap();
        Self { conn, endpoint }
    }
}

fn load_test_client_certs() -> Arc<Certs> {
    #[cfg(not(feature = "bootroot"))]
    {
        let cert_pem = fs::read("tests/certs/node1/cert.pem").unwrap();
        let cert = to_cert_chain(&cert_pem).unwrap();
        let key_pem = fs::read("tests/certs/node1/key.pem").unwrap();
        let key = crate::comm::to_private_key(&key_pem).unwrap();
        let root = crate::comm::to_root_cert(&["tests/certs/ca_cert.pem".to_string()]).unwrap();

        Arc::new(Certs {
            certs: cert,
            key,
            root,
        })
    }

    #[cfg(feature = "bootroot")]
    {
        Arc::new(bootroot_chain_node1_client_certs())
    }
}

fn load_test_server_certs() -> Arc<Certs> {
    #[cfg(not(feature = "bootroot"))]
    {
        load_test_client_certs()
    }

    #[cfg(feature = "bootroot")]
    {
        Arc::new(bootroot_chain_node1_server_certs())
    }
}

#[test]
fn logs_connected_client_identity() {
    let certs = load_test_client_certs();

    super::log_connected_client(&certs.certs).expect("log connected ingest client");
}

fn server(addr: SocketAddr) -> Server {
    let certs = load_test_server_certs();
    Server::new(addr, &certs)
}

/// Publishes the test TLS material the ingest listener reloads from.
///
/// The sender is handed back so the caller can keep it alive: a `TlsWatch`
/// whose sender has been dropped reports the closure to the listener, which
/// then stops watching for reloads.
fn test_tls_watch(certs: Arc<Certs>) -> (watch::Sender<Arc<TlsMaterial>>, TlsWatch) {
    watch::channel(Arc::new(TlsMaterial {
        certs,
        cert_pem: Vec::new(),
        key_pem: Vec::new(),
        ca_pem: Vec::new(),
        generation: 0,
    }))
}

/// Starts the real ingest entry task and reports the address it bound.
///
/// The tests drive the production `BoundServer::run` rather than a copy of its
/// accept loop, so what they assert about admission, draining, and ACK
/// behavior is what the running node does.
fn spawn_server_with(
    db: Database,
    ack_transmission_cnt: u16,
    notify_sensor: Option<Arc<Notify>>,
) -> TestServer {
    init_crypto();
    let pcap_sensors = new_pcap_sensors();
    let ingest_sensors = new_ingest_sensors(&db);
    let runtime_ingest_sensors = new_runtime_ingest_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
    let bound = server(server_addr).bind().expect("bind ingest test server");
    let local_addr = bound.local_addr();
    let (tls_sender, tls_watch) = test_tls_watch(load_test_server_certs());
    let token = CancellationToken::new();
    let handle = tokio::spawn(bound.run(
        db,
        pcap_sensors.clone(),
        ingest_sensors.clone(),
        runtime_ingest_sensors.clone(),
        stream_direct_channels,
        notify_sensor,
        ack_transmission_cnt,
        tls_watch,
        token.clone(),
    ));
    TestServer {
        local_addr,
        token,
        handle: Some(handle),
        pcap_sensors,
        ingest_sensors,
        runtime_ingest_sensors,
        _tls_sender: tls_sender,
    }
}

/// A running ingest entry task, plus the shared state it maintains.
struct TestServer {
    local_addr: SocketAddr,
    token: CancellationToken,
    handle: Option<JoinHandle<anyhow::Result<()>>>,
    pcap_sensors: PcapSensors,
    ingest_sensors: IngestSensors,
    runtime_ingest_sensors: RunTimeIngestSensors,
    _tls_sender: watch::Sender<Arc<TlsMaterial>>,
}

impl TestServer {
    /// Cancels the entry task and waits for it to drain and return.
    async fn shutdown(&mut self) {
        self.token.cancel();
        let handle = self.handle.take().expect("ingest server already shut down");
        with_timeout("ingest server drain", SHUTDOWN_TIMEOUT, handle)
            .await
            .expect("ingest server task should not panic")
            .expect("ingest server should shut down cleanly");
    }
}

fn spawn_server(db: Database) -> TestServer {
    spawn_server_with(db, 1024_u16, Some(Arc::new(Notify::new())))
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
    let certs = load_test_client_certs();
    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(config_client(&certs).expect("ingest test client config"));
    endpoint
}

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

const DEFAULT_START_TIME_NANOS: i64 = 1_740_787_200_000_000_000;

fn default_start_time() -> i64 {
    DEFAULT_START_TIME_NANOS
}

fn next_timestamp() -> i64 {
    static NEXT_TS: AtomicI64 = AtomicI64::new(1_700_000_000_000_000_000);
    NEXT_TS.fetch_add(1, Ordering::Relaxed)
}

struct TestHarness {
    _db_dir: TempDir,
    db: Database,
    client: TestClient,
    server: TestServer,
}

impl TestHarness {
    async fn new() -> Self {
        Self::with_ack_transmission(1024_u16).await
    }

    async fn with_ack_transmission(ack_transmission_cnt: u16) -> Self {
        init_crypto();
        let db_dir = tempfile::tempdir().expect("create ingest temp dir");
        let db = Database::open(db_dir.path(), &DbOptions::default())
            .expect("open ingest test database");
        let server = spawn_server_with(
            db.clone(),
            ack_transmission_cnt,
            Some(Arc::new(Notify::new())),
        );
        let client = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            TestClient::new(server.local_addr),
        )
        .await
        .expect("ingest client connect timeout");
        Self {
            _db_dir: db_dir,
            db,
            client,
            server,
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
        self.server.shutdown().await;
    }

    /// Cancels the ingest entry task while the client is still connected, and
    /// waits for the drain to finish.
    async fn cancel_and_drain(&mut self) {
        self.server.shutdown().await;
    }
}

fn test_sensor_name() -> String {
    static TEST_SENSOR: OnceLock<String> = OnceLock::new();
    TEST_SENSOR
        .get_or_init(|| {
            let certs = load_test_client_certs();
            let (_service, sensor) =
                service_fqdn_from_cert(&certs.certs).expect("failed to parse test certificate");
            sensor
        })
        .clone()
}

fn test_host_fqdn() -> String {
    static TEST_HOST_FQDN: OnceLock<String> = OnceLock::new();
    TEST_HOST_FQDN
        .get_or_init(|| {
            let certs = load_test_client_certs();
            host_fqdn_from_cert(&certs.certs).expect("failed to parse test certificate")
        })
        .clone()
}

fn expected_raw_event_bytes(kind: RawEventKind, body_bytes: Vec<u8>) -> Vec<u8> {
    match kind {
        RawEventKind::OpLog => {
            let mut op_log: OpLog =
                bincode::deserialize(&body_bytes).expect("failed to deserialize OpLog");
            op_log.sensor = test_host_fqdn();
            bincode::serialize(&op_log).expect("failed to serialize OpLog")
        }
        _ => body_bytes,
    }
}

fn read_single_raw_event<T: DeserializeOwned>(store: &RawEventStore<'_, T>) -> Option<Vec<u8>> {
    let mut iter = store.iter_forward();
    let first = {
        let value = iter.next()?;
        value.expect("failed to read stored event")
    };
    assert!(iter.next().is_none(), "expected exactly one stored event");
    let (_key, value) = first;
    Some(value.to_vec())
}

fn read_single_raw_event_kv<T: DeserializeOwned>(
    store: &RawEventStore<'_, T>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut iter = store.iter_forward();
    let first = {
        let value = iter.next()?;
        value.expect("failed to read stored event")
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
        RawEventKind::Icmp => read_single_raw_event(&db.icmp_store().unwrap()),
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
                duration: FIXED_CONN_DURATION_NANOS,
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
                cname: vec!["client_name".to_string()],
                realm: "realm".to_string(),
                sname_type: 1,
                sname: vec!["service_name".to_string()],
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
                context: vec![DceRpcContext::default()],
                request: vec!["request_op".to_string()],
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
                service_name: "giganto".to_string(),
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
                options: vec![(53, vec![1]), (12, vec![0x74, 0x65, 0x73, 0x74])],
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
            "icmp",
            RawEventKind::Icmp,
            Icmp {
                orig_addr: ip("192.168.4.76"),
                resp_addr: ip("192.168.4.77"),
                proto: 1,
                start_time: default_start_time(),
                duration: 1_000_000,
                orig_pkts: 1,
                resp_pkts: 1,
                orig_l2_bytes: 84,
                resp_l2_bytes: 84,
                icmp_type: 8,
                icmp_code: 0,
                id: 12345,
                seq_num: 1,
                data_len: 56,
                payload: vec![0x61, 0x62, 0x63, 0x64],
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
async fn op_log_sensor_uses_host_fqdn() {
    const RAW_EVENT_KIND_OP_LOG: RawEventKind = RawEventKind::OpLog;
    let harness = TestHarness::new().await;
    let (mut send, _) = harness.open_bi().await;

    let timestamp = next_timestamp();
    let body = OpLog {
        sensor: String::new(),
        service_name: "data-broker".to_string(),
        log_level: OpLogLevel::Info,
        contents: "op_log content".to_string(),
    };

    send_record(&mut send, RAW_EVENT_KIND_OP_LOG, timestamp, &body)
        .await
        .unwrap();
    send.finish().expect("failed to shutdown stream");

    let stored = wait_for_raw_event(&harness.db, RAW_EVENT_KIND_OP_LOG).await;
    let stored_op_log: OpLog =
        bincode::deserialize(&stored).expect("failed to deserialize stored OpLog");

    assert_eq!(stored_op_log.sensor, test_host_fqdn());
    #[cfg(feature = "bootroot")]
    assert_eq!(stored_op_log.sensor, "node1.example.test");
    #[cfg(not(feature = "bootroot"))]
    assert_eq!(stored_op_log.sensor, "node1");

    harness.shutdown(b"done").await;
}

/// The count-triggered ACK: exactly `ack_transmission_cnt` events arrive, so
/// the threshold trips without the interval deadline being involved. The
/// interval path is covered separately, further down.
#[tokio::test]
async fn ack_count_threshold_sends_last_timestamp() {
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
    let certs = load_test_server_certs();

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
        .connect(server_addr, test_server_name())
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
    let sensor_token = CancellationToken::new();

    let db_clone = db.clone();
    let pcap_sensors_clone = pcap_sensors.clone();
    let ingest_sensors_clone = ingest_sensors.clone();
    let runtime_ingest_sensors_clone = runtime_ingest_sensors.clone();
    let sensor_token_clone = sensor_token.clone();

    let sensor_state = tokio::spawn(async move {
        super::check_sensors_conn(
            db_clone,
            pcap_sensors_clone,
            ingest_sensors_clone,
            runtime_ingest_sensors_clone,
            rx,
            None,
            sensor_token_clone,
        )
        .await
        .unwrap();
    });

    let sensor_name = "test_sensor".to_string();
    let now = DateTime::now();

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

    sensor_token.cancel();
    drop(tx);
    with_timeout("sensor-state drain", SHUTDOWN_TIMEOUT, sensor_state)
        .await
        .expect("sensor-state task should not panic");
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
    let sensor_token = CancellationToken::new();
    let notify_sensor = Arc::new(Notify::new());

    let db_clone = db.clone();
    let pcap_sensors_clone = pcap_sensors.clone();
    let ingest_sensors_clone = ingest_sensors.clone();
    let runtime_ingest_sensors_clone = runtime_ingest_sensors.clone();
    let sensor_token_clone = sensor_token.clone();
    let notify_sensor_clone = notify_sensor.clone();

    let sensor_state = tokio::spawn(async move {
        super::check_sensors_conn(
            db_clone,
            pcap_sensors_clone,
            ingest_sensors_clone,
            runtime_ingest_sensors_clone,
            rx,
            Some(notify_sensor_clone),
            sensor_token_clone,
        )
        .await
        .unwrap();
    });

    let sensor_name = "notify_sensor".to_string();
    let now = DateTime::now();

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

    sensor_token.cancel();
    drop(tx);
    with_timeout("sensor-state drain", SHUTDOWN_TIMEOUT, sensor_state)
        .await
        .expect("sensor-state task should not panic");
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
    let sensor_token = CancellationToken::new();
    let notify_sensor = Arc::new(Notify::new());

    let db_clone = db.clone();
    let pcap_sensors_clone = pcap_sensors.clone();
    let ingest_sensors_clone = ingest_sensors.clone();
    let runtime_ingest_sensors_clone = runtime_ingest_sensors.clone();
    let sensor_token_clone = sensor_token.clone();
    let notify_sensor_clone = notify_sensor.clone();

    let sensor_state = tokio::spawn(async move {
        super::check_sensors_conn(
            db_clone,
            pcap_sensors_clone,
            ingest_sensors_clone,
            runtime_ingest_sensors_clone,
            rx,
            Some(notify_sensor_clone),
            sensor_token_clone,
        )
        .await
        .unwrap();
    });

    let sensor_name = "notify_sensor_disconnect".to_string();
    let now = DateTime::now();

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

    sensor_token.cancel();
    drop(tx);
    with_timeout("sensor-state drain", SHUTDOWN_TIMEOUT, sensor_state)
        .await
        .expect("sensor-state task should not panic");
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
    let sensor_token = CancellationToken::new();

    let db_clone = db.clone();
    let pcap_sensors_clone = pcap_sensors.clone();
    let ingest_sensors_clone = ingest_sensors.clone();
    let runtime_ingest_sensors_clone = runtime_ingest_sensors.clone();
    let sensor_token_clone = sensor_token.clone();

    let sensor_state = tokio::spawn(async move {
        super::check_sensors_conn(
            db_clone,
            pcap_sensors_clone,
            ingest_sensors_clone,
            runtime_ingest_sensors_clone,
            rx,
            None,
            sensor_token_clone,
        )
        .await
        .unwrap();
    });

    let sensor_name = "piglet_sensor".to_string(); // "piglet" implies pcap sensor logic in handle_connection, but here we explicitly set is_pcap_sensor
    let now = DateTime::now();

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

    sensor_token.cancel();
    drop(tx);
    with_timeout("sensor-state drain", SHUTDOWN_TIMEOUT, sensor_state)
        .await
        .expect("sensor-state task should not panic");
}

#[tokio::test]
async fn handle_connection_closes_on_handshake_failure() {
    init_crypto();
    let db_dir = tempfile::tempdir().expect("create ingest temp dir");
    let db =
        Database::open(db_dir.path(), &DbOptions::default()).expect("open ingest test database");
    let mut server = spawn_server(db);
    let server_addr = server.local_addr;

    let endpoint = init_client();
    let conn = endpoint
        .connect(server_addr, test_server_name())
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
    server.shutdown().await;
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

thread_local! {
    /// Where this thread's log events are collected while a capture is active.
    static LOG_SINK: RefCell<Option<Arc<StdMutex<Vec<u8>>>>> = const { RefCell::new(None) };
}

/// Writer the process-wide test subscriber sends every event through. Events
/// from a thread with no active capture are dropped.
struct ThreadLocalLogWriter;

impl std::io::Write for ThreadLocalLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG_SINK.with(|sink| {
            if let Some(sink) = sink.borrow().as_ref() {
                sink.lock().expect("log sink lock").extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Detaches this thread's sink when the capture goes out of scope.
struct LogCaptureGuard;

impl Drop for LogCaptureGuard {
    fn drop(&mut self) {
        LOG_SINK.with(|sink| sink.borrow_mut().take());
    }
}

/// Starts collecting this thread's log events.
///
/// The subscriber is installed once for the whole test binary rather than per
/// thread, because callsite interest is cached process-wide the first time an
/// event is emitted: a parallel test reaching one of these callsites while no
/// subscriber was installed anywhere would cache it as "never" and leave every
/// later capture empty. A global subscriber that routes to a thread-local sink
/// keeps the callsites live while still giving each test its own buffer, and
/// events from threads that are not capturing are dropped.
fn capture_logs() -> (Arc<StdMutex<Vec<u8>>>, LogCaptureGuard) {
    static INSTALL: OnceLock<()> = OnceLock::new();
    INSTALL.get_or_init(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(|| ThreadLocalLogWriter)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });

    let buf = Arc::new(StdMutex::new(Vec::new()));
    LOG_SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buf)));
    (buf, LogCaptureGuard)
}

fn captured(buf: &Arc<StdMutex<Vec<u8>>>) -> String {
    String::from_utf8(buf.lock().expect("log sink lock").clone()).expect("utf8 log output")
}

fn test_log_body() -> Log {
    Log {
        kind: String::from("shutdown test log"),
        log: vec![0; 10],
    }
}

/// A cancelled ingest listener stops accepting: a sensor that arrives after
/// the drain gets no connection at all.
#[tokio::test]
async fn cancellation_rejects_new_connections() {
    init_crypto();
    let db_dir = tempfile::tempdir().expect("create ingest temp dir");
    let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open ingest test db");
    let mut server = spawn_server(db);
    let server_addr = server.local_addr;

    server.shutdown().await;

    let endpoint = init_client();
    let connecting = endpoint
        .connect(server_addr, test_server_name())
        .expect("client config should build");
    match timeout(std::time::Duration::from_secs(2), connecting).await {
        // Either no answer at all or an outright refusal is fine; what must
        // not happen is a connection.
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(_conn)) => panic!("ingest accepted a connection after shutdown"),
    }
}

/// Cancellation releases a connection parked on `accept_bi`. The client does
/// nothing to help it along, and no fixed delay is waited out.
#[tokio::test]
async fn cancellation_releases_an_idle_connection() {
    let mut harness = TestHarness::new().await;

    harness.cancel_and_drain().await;

    let reason = with_timeout(
        "client observes close",
        SHUTDOWN_TIMEOUT,
        harness.client.conn.closed(),
    )
    .await;
    assert!(
        matches!(reason, quinn::ConnectionError::ApplicationClosed(_)),
        "ingest should close the connection itself, got: {reason:?}"
    );
}

/// A sensor that finished the QUIC handshake and then went quiet is parked in
/// `server_handshake` on the ingest side. It must not hold the drain open.
#[tokio::test]
async fn cancellation_releases_a_connection_stalled_before_the_version_handshake() {
    init_crypto();
    let db_dir = tempfile::tempdir().expect("create ingest temp dir");
    let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open ingest test db");
    let mut server = spawn_server(db);

    let endpoint = init_client();
    let conn = with_timeout(
        "stalled client connect",
        std::time::Duration::from_secs(2),
        endpoint
            .connect(server.local_addr, test_server_name())
            .expect("client config should build"),
    )
    .await
    .expect("the QUIC handshake should complete");
    // `client_handshake` is deliberately skipped, so the ingest side stays
    // parked waiting for a version message that never comes.

    server.shutdown().await;
    drop(conn);
}

/// Once ingest has drained, the connection is gone, so the sensor cannot open
/// another stream on it and nothing it tries to send is stored.
#[tokio::test]
async fn cancellation_rejects_new_streams_on_an_existing_connection() {
    let mut harness = TestHarness::new().await;

    harness.cancel_and_drain().await;

    assert!(
        harness.client.conn.open_bi().await.is_err(),
        "ingest admitted a stream after shutdown"
    );
    assert_no_raw_events(&harness.db, STOREABLE_RAW_EVENT_KINDS).await;
}

/// What a handler appended before cancellation survives the shutdown, and by
/// the time the ingest entry task has returned no ingest task is still holding
/// the database — the next generation can reopen the same directory, which
/// RocksDB's file lock would refuse otherwise.
#[tokio::test]
async fn appended_events_survive_the_drain_and_the_database_is_released() {
    init_crypto();
    let db_dir = tempfile::tempdir().expect("create ingest temp dir");
    let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open ingest test db");
    // A threshold this high keeps the count-triggered ACK and its flush out of
    // the way, so the only flush left is the one the handler owes on its way
    // out.
    let mut server = spawn_server_with(db.clone(), 1024_u16, Some(Arc::new(Notify::new())));
    let client = TestClient::new(server.local_addr).await;
    let (mut send, _recv) = client.conn.open_bi().await.expect("failed to open stream");

    send_record(
        &mut send,
        RawEventKind::Log,
        next_timestamp(),
        test_log_body(),
    )
    .await
    .expect("failed to send log");
    let stored = wait_for_raw_event(&db, RawEventKind::Log).await;

    // The handler is now parked in `recv_raw` with an un-ACKed event behind
    // it: cancellation has to flush that event, not drop it.
    server.shutdown().await;

    client.conn.close(0u32.into(), b"done");
    client.endpoint.wait_idle().await;
    drop(db);

    let reopened = Database::open(db_dir.path(), &DbOptions::default())
        .expect("the next generation should be able to reopen the data directory");
    assert_eq!(
        read_raw_event_from_db(&reopened, RawEventKind::Log).as_deref(),
        Some(stored.as_slice()),
        "an event appended before cancellation was lost"
    );
}

/// Cancellation lands on a handler parked inside `recv_raw` with a frame only
/// half on the wire. That half frame is what the loss tolerance allows to go:
/// it was never fully received, so nothing in it is stored and nothing about
/// it is acknowledged. The batch that completed before it is what the
/// tolerance keeps, and it is still there once ingest has drained.
#[tokio::test]
async fn cancellation_drops_a_half_received_frame_and_keeps_the_completed_batch() {
    let mut harness = TestHarness::with_ack_transmission(1024_u16).await;
    let (mut send, mut recv) = harness.open_bi().await;

    send_record_header(&mut send, RawEventKind::Log)
        .await
        .expect("failed to send record header");
    send_events(&mut send, next_timestamp(), test_log_body())
        .await
        .expect("failed to send log");
    // Waiting for the append is what puts the handler back in `recv_raw`: it
    // could not have stored this batch without having read all of it.
    let stored = wait_for_raw_event(&harness.db, RawEventKind::Log).await;

    // Announce a frame and then send only part of it. `recv_raw` reads a
    // length header and then the body it announces, so the handler cannot get
    // past this until the rest arrives, and the rest never does.
    let batch = bincode::serialize(&vec![(
        next_timestamp(),
        bincode::serialize(&test_log_body()).expect("failed to serialize the log body"),
    )])
    .expect("failed to serialize the log batch");
    let len = u32::try_from(batch.len()).expect("the batch length should fit in a u32");
    send_bytes(&mut send, &len.to_le_bytes())
        .await
        .expect("failed to send the frame length");
    send_bytes(&mut send, &batch[..batch.len() / 2])
        .await
        .expect("failed to send the partial frame");

    // The drain returning at all is the first assertion: a handler stuck
    // mid-frame has to be released by cancellation, not waited out.
    harness.cancel_and_drain().await;

    let ack = timeout(SHUTDOWN_TIMEOUT, receive_ack_timestamp(&mut recv)).await;
    assert!(
        !matches!(ack, Ok(Ok(_))),
        "a half-received frame was acknowledged: {ack:?}"
    );
    // `read_raw_event_from_db` asserts that the store holds a single event, so
    // this also pins that nothing was salvaged out of the half frame.
    assert_eq!(
        read_raw_event_from_db(&harness.db, RawEventKind::Log).as_deref(),
        Some(stored.as_slice()),
        "the batch appended before cancellation was lost"
    );
}

/// Builds a client that grants each stream only `window` bytes of receive
/// window, so a server that writes more than that on one stream blocks until
/// the client reads — which these tests never do.
fn init_client_with_stream_window(window: u32) -> Endpoint {
    let certs = load_test_client_certs();
    let mut config = config_client(&certs).expect("ingest test client config");
    let mut transport = quinn::TransportConfig::default();
    // The connection window is left alone: shrinking it would stall the
    // version handshake as well, and the point here is one stalled stream.
    transport.stream_receive_window(quinn::VarInt::from_u32(window));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    config.transport_config(Arc::new(transport));
    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("failed to parse endpoint addr"))
            .expect("failed to create endpoint");
    endpoint.set_default_client_config(config);
    endpoint
}

fn stored_log_count(db: &Database) -> usize {
    db.log_store()
        .expect("open the log store")
        .iter_forward()
        .count()
}

/// Waits until the handler stops appending, and reports where it stopped.
///
/// The handler appends a batch and then acknowledges it, so a count that has
/// climbed above zero and then held still for several polls is a handler
/// parked in the acknowledgement write rather than one still working through
/// the events behind it.
async fn wait_for_append_to_stall(db: &Database) -> usize {
    const STILL_ROUNDS: usize = 5;
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let mut last = 0;
    let mut still = 0;
    loop {
        let count = stored_log_count(db);
        if count > 0 && count == last {
            still += 1;
            if still >= STILL_ROUNDS {
                return count;
            }
        } else {
            still = 0;
            last = count;
        }
        assert!(
            Instant::now() < deadline,
            "the append count never settled, last seen {count}"
        );
        sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A sensor that stops reading its acknowledgements parks the request handler
/// in the middle of a write, and the handler's own cancellation arm cannot
/// reach it there: `select!` is not polling anything while that write is
/// awaited. What releases it is the connection handler closing the connection
/// on its way out, so this pins the drain finishing anyway — and everything
/// appended behind the blocked write still being flushed.
#[tokio::test]
async fn cancellation_releases_a_handler_blocked_writing_an_ack() {
    // Eight bytes per acknowledgement, so this window is out after 32 of
    // them, and the events below produce four times that many.
    const STREAM_WINDOW: u32 = 256;
    const EVENTS: usize = 128;

    init_crypto();
    let db_dir = tempfile::tempdir().expect("create ingest temp dir");
    let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open ingest test db");
    // One acknowledgement per event, so the window runs out on the events
    // this test can send without waiting.
    let mut server = spawn_server_with(db.clone(), 1_u16, Some(Arc::new(Notify::new())));

    let endpoint = init_client_with_stream_window(STREAM_WINDOW);
    let conn = with_timeout(
        "stalled-reader connect",
        std::time::Duration::from_secs(2),
        endpoint
            .connect(server.local_addr, test_server_name())
            .expect("client config should build"),
    )
    .await
    .expect("the QUIC handshake should complete");
    client_handshake(&conn, PROTOCOL_VERSION)
        .await
        .expect("the version handshake should complete");

    // `recv` is held and never read, which is what keeps the window shut.
    let (mut send, _recv) = conn.open_bi().await.expect("failed to open stream");
    send_record_header(&mut send, RawEventKind::Log)
        .await
        .expect("failed to send record header");
    // Distinct timestamps, so every event lands under a key of its own and
    // the row count below is the number appended.
    for _ in 0..EVENTS {
        send_events(&mut send, next_timestamp(), test_log_body())
            .await
            .expect("failed to send log");
    }

    let appended = wait_for_append_to_stall(&db).await;
    assert!(
        appended < EVENTS,
        "the acknowledgement window should have run out before the last event, \
         but all {EVENTS} were appended"
    );

    // The assertion is `shutdown` returning at all: a handler nothing releases
    // would hold the drain past `SHUTDOWN_TIMEOUT`.
    server.shutdown().await;

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    drop(db);

    let reopened = Database::open(db_dir.path(), &DbOptions::default())
        .expect("the next generation should be able to reopen the data directory");
    assert_eq!(
        stored_log_count(&reopened),
        appended,
        "events appended behind the blocked acknowledgement were not flushed"
    );
}

/// One request handler driven directly, with the connection under the test's
/// control rather than a connection handler's.
///
/// The entry-task tests above cancel the whole subsystem, and there the
/// connection handler closes the connection on its way out, so a stream on it
/// fails its read whether or not the request handler ever looks at its own
/// token. That hides the handler's cancellation arm behind an I/O error. Here
/// nothing closes the connection, so the token is the only thing that can
/// release the handler.
struct DirectRequestHandler {
    _server_endpoint: Endpoint,
    _server_conn: Connection,
    _client_endpoint: Endpoint,
    client_conn: Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    token: CancellationToken,
    handle: JoinHandle<anyhow::Result<()>>,
}

/// Connects a client to a bare ingest listener and hands the server side of
/// one `Log` stream to [`super::handle_request`].
async fn spawn_direct_request_handler(
    db: Database,
    ack_transmission_cnt: u16,
) -> DirectRequestHandler {
    init_crypto();
    let bound = server(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .bind()
        .expect("bind ingest test server");
    let server_addr = bound.local_addr();
    let server_endpoint = bound.endpoint;

    // Neither side of a QUIC handshake finishes without the other being
    // polled, and there is no accept loop here to do it, so both run together.
    let client_endpoint = init_client();
    let connecting = client_endpoint
        .connect(server_addr, test_server_name())
        .expect("client config should build");
    let accepting = async {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("the listener should offer a connection");
        incoming.into_future().await
    };
    let (client_conn, server_conn) = with_timeout(
        "direct handshake",
        std::time::Duration::from_secs(2),
        async { tokio::join!(connecting, accepting) },
    )
    .await;
    let client_conn = client_conn.expect("the client side should finish the handshake");
    let server_conn = server_conn.expect("the server side should finish the handshake");

    // The record header is both what `handle_request` reads first and what
    // makes the freshly opened stream visible to `accept_bi`.
    let (mut send, recv) = client_conn.open_bi().await.expect("failed to open stream");
    send_record_header(&mut send, RawEventKind::Log)
        .await
        .expect("failed to send record header");
    let server_stream = with_timeout(
        "direct server accept_bi",
        std::time::Duration::from_secs(2),
        server_conn.accept_bi(),
    )
    .await
    .expect("the server side should see the stream");

    let token = CancellationToken::new();
    let handle = tokio::spawn(super::handle_request(
        test_sensor_name(),
        test_host_fqdn(),
        server_stream,
        db,
        new_stream_direct_channels(),
        token.clone(),
        ack_transmission_cnt,
    ));

    DirectRequestHandler {
        _server_endpoint: server_endpoint,
        _server_conn: server_conn,
        _client_endpoint: client_endpoint,
        client_conn,
        send,
        recv,
        token,
        handle,
    }
}

/// Cancelling a request handler that is parked inside `recv_raw` releases it
/// on its own, with the connection still up and the stream still readable. It
/// returns cleanly, it acknowledges nothing about the frame it abandoned, and
/// what it appended before is still there.
#[tokio::test]
async fn cancelling_a_request_handler_releases_it_mid_frame() {
    let db_dir = tempfile::tempdir().expect("create ingest temp dir");
    let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open ingest test db");
    // A threshold out of reach keeps the count-triggered ACK away, so any
    // acknowledgement the client sees is one cancellation invented.
    let mut handler = spawn_direct_request_handler(db.clone(), 1024_u16).await;

    send_events(&mut handler.send, next_timestamp(), test_log_body())
        .await
        .expect("failed to send log");
    let stored = wait_for_raw_event(&db, RawEventKind::Log).await;

    // Announce a frame and send only part of it, so the handler is inside
    // `recv_raw` waiting for a body that never finishes arriving.
    let batch = bincode::serialize(&vec![(
        next_timestamp(),
        bincode::serialize(&test_log_body()).expect("failed to serialize the log body"),
    )])
    .expect("failed to serialize the log batch");
    let len = u32::try_from(batch.len()).expect("the batch length should fit in a u32");
    send_bytes(&mut handler.send, &len.to_le_bytes())
        .await
        .expect("failed to send the frame length");
    send_bytes(&mut handler.send, &batch[..batch.len() / 2])
        .await
        .expect("failed to send the partial frame");

    handler.token.cancel();

    let outcome = with_timeout("request handler returns", SHUTDOWN_TIMEOUT, handler.handle)
        .await
        .expect("the request handler should not panic");
    assert!(
        outcome.is_ok(),
        "a cancelled request handler should return cleanly, got: {outcome:?}"
    );
    assert!(
        handler.client_conn.close_reason().is_none(),
        "the token alone should have released the handler, but the connection went away"
    );

    let ack = timeout(
        std::time::Duration::from_millis(200),
        receive_ack_timestamp(&mut handler.recv),
    )
    .await;
    assert!(
        !matches!(ack, Ok(Ok(_))),
        "a cancelled handler acknowledged a frame it never finished reading: {ack:?}"
    );
    assert_eq!(
        read_raw_event_from_db(&db, RawEventKind::Log).as_deref(),
        Some(stored.as_slice()),
        "the batch appended before cancellation was lost"
    );
}

/// The periodic ACK used to be its own task, ticking regardless of what the
/// receive loop was doing. It is now an arm of that loop's `select!`, so this
/// pins the behaviour the rework had to preserve: a batch too small to trip
/// the count threshold is still acknowledged once the interval deadline
/// passes, and the acknowledgement carries the last timestamp appended.
///
/// Time is paused rather than waited out, so the deadline arrives without the
/// test taking `ACK_INTERVAL_TIME` to run. The client's keep-alive is shorter
/// than the idle timeout, so advancing in steps below it keeps the connection
/// up across the jump instead of letting one side time the other out.
#[tokio::test]
async fn ack_interval_acknowledges_a_batch_below_the_count_threshold() {
    let db_dir = tempfile::tempdir().expect("create ingest temp dir");
    let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open ingest test db");
    // Out of reach for the single event below, so the interval is the only
    // thing that can produce an acknowledgement here.
    let mut handler = spawn_direct_request_handler(db.clone(), 1024_u16).await;

    let timestamp = next_timestamp();
    send_events(&mut handler.send, timestamp, test_log_body())
        .await
        .expect("failed to send log");
    // Waiting for the append puts the handler back on `recv_frame` with no
    // frame waiting, which is the only state the interval arm can win from.
    wait_for_raw_event(&db, RawEventKind::Log).await;

    tokio::time::pause();
    // One tick was consumed by the `reset` at the top of `handle_data`, so the
    // deadline is a full interval out from when the handler started.
    for _ in 0..=super::ACK_INTERVAL_TIME {
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }

    let acked = with_timeout(
        "periodic ack",
        std::time::Duration::from_secs(2),
        receive_ack_timestamp(&mut handler.recv),
    )
    .await
    .expect("the interval should have acknowledged the batch");
    assert_eq!(
        acked, timestamp,
        "the periodic ack should carry the last timestamp appended"
    );

    // The arm belongs to the handler, so releasing the handler stops it. A
    // ticker outliving the loop would keep acknowledging past this point.
    handler.token.cancel();
    let outcome = with_timeout("request handler returns", SHUTDOWN_TIMEOUT, handler.handle)
        .await
        .expect("the request handler should not panic");
    assert!(
        outcome.is_ok(),
        "a cancelled request handler should return cleanly, got: {outcome:?}"
    );
    for _ in 0..=super::ACK_INTERVAL_TIME {
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
    let ack = timeout(
        std::time::Duration::from_millis(200),
        receive_ack_timestamp(&mut handler.recv),
    )
    .await;
    assert!(
        !matches!(ack, Ok(Ok(_))),
        "the periodic ack outlived the handler it belongs to: {ack:?}"
    );
}

/// The disconnect a connection handler reports while it is cleaning up is
/// admitted after cancellation, and the sensor-state task still has to apply
/// it before it returns. So once ingest has drained, the runtime sensor map no
/// longer carries the sensor that just went away.
#[tokio::test]
async fn sensor_state_updates_admitted_during_shutdown_are_drained() {
    init_crypto();
    let db_dir = tempfile::tempdir().expect("create ingest temp dir");
    let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open ingest test db");
    let mut server = spawn_server_with(db.clone(), 1024_u16, Some(Arc::new(Notify::new())));
    let client = TestClient::new(server.local_addr).await;
    let sensor = test_sensor_name();

    wait_until(
        "sensor connect recorded",
        std::time::Duration::from_secs(2),
        || async {
            server
                .runtime_ingest_sensors
                .read()
                .await
                .contains_key(&sensor)
        },
    )
    .await;

    server.shutdown().await;

    assert!(
        !server
            .runtime_ingest_sensors
            .read()
            .await
            .contains_key(&sensor),
        "the disconnect admitted during shutdown was not drained"
    );
    assert!(
        server.ingest_sensors.read().await.contains(&sensor),
        "the sensor should stay in the known-sensor set across a disconnect"
    );
    assert!(
        server.pcap_sensors.read().await.is_empty(),
        "a non-pcap sensor should leave no connection behind"
    );
    drop(client);
}

/// Shutdown puts nothing on the wire that the batching rules would not have
/// sent. With the count threshold out of reach and the 60-second interval
/// never coming due, any timestamp the client sees would have to be an ACK
/// shutdown invented.
#[tokio::test]
async fn shutdown_sends_no_extra_ack() {
    let mut harness = TestHarness::with_ack_transmission(1024_u16).await;
    let (mut send, mut recv) = harness.open_bi().await;

    send_record(
        &mut send,
        RawEventKind::Log,
        next_timestamp(),
        test_log_body(),
    )
    .await
    .expect("failed to send log");
    wait_for_raw_event(&harness.db, RawEventKind::Log).await;

    assert!(
        timeout(
            std::time::Duration::from_millis(200),
            receive_ack_timestamp(&mut recv),
        )
        .await
        .is_err(),
        "an ACK arrived before the batching rules called for one"
    );

    harness.cancel_and_drain().await;

    // The connection is closed by now, so the read fails or times out; either
    // way no acknowledgement was produced.
    let ack = timeout(SHUTDOWN_TIMEOUT, receive_ack_timestamp(&mut recv)).await;
    assert!(
        !matches!(ack, Ok(Ok(_))),
        "shutdown sent an extra ack: {ack:?}"
    );
}

/// ACK batching is unchanged by the move into the request handler's own loop:
/// an ACK still lands on every `ack_transmission` events, carrying the last
/// timestamp of that batch, and the counter still restarts afterwards.
#[tokio::test]
async fn ack_batching_acks_once_per_threshold_batch() {
    let harness = TestHarness::with_ack_transmission(2_u16).await;
    let (mut send, mut recv) = harness.open_bi().await;

    send_record_header(&mut send, RawEventKind::Log)
        .await
        .expect("failed to send record header");
    let base = next_timestamp();
    for offset in 0..4 {
        send_events(&mut send, base + offset, test_log_body())
            .await
            .expect("failed to send log");
    }

    let first = with_timeout(
        "first ack",
        std::time::Duration::from_secs(2),
        receive_ack_timestamp(&mut recv),
    )
    .await
    .expect("failed to receive the first ack");
    let second = with_timeout(
        "second ack",
        std::time::Duration::from_secs(2),
        receive_ack_timestamp(&mut recv),
    )
    .await
    .expect("failed to receive the second ack");

    assert_eq!(first, base + 1);
    assert_eq!(second, base + 3);

    send.finish().expect("failed to shutdown stream");
    harness.shutdown(b"done").await;
}

/// A stream that fails names itself: the log line carries the sensor and the
/// QUIC stream id, so a failure can be tied back to the stream it came from.
#[tokio::test]
async fn stream_error_log_names_the_failing_stream() {
    let (logs, _guard) = capture_logs();
    let harness = TestHarness::new().await;
    let (mut send, _recv) = harness.open_bi().await;

    send_record_header(&mut send, RawEventKind::Log)
        .await
        .expect("failed to send record header");
    send_raw(&mut send, b"not a bincode batch")
        .await
        .expect("failed to send body");
    send.finish().expect("failed to shutdown stream");

    let expected = format!("ingest-stream-{}-", test_sensor_name());
    wait_until("stream error logged", SHUTDOWN_TIMEOUT, || async {
        captured(&logs).contains(&expected)
    })
    .await;

    let output = captured(&logs);
    assert!(
        output.contains("Failed to deserialize received message"),
        "the domain error should be logged, got: {output}"
    );

    harness.shutdown(b"done").await;
}
