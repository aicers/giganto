#![allow(clippy::items_after_statements)]

use std::{
    collections::{HashMap, HashSet},
    fs,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration as StdDuration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use giganto_client::{
    connection::{client_handshake, server_handshake},
    ingest::{
        log::Log,
        netflow::{Netflow5, Netflow9},
        network::{
            Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, FtpCommand, Http, Kerberos, Ldap, MalformedDns,
            Mqtt, Nfs, Ntlm, Radius, Rdp, Smb, Smtp, Ssh, Tls,
        },
        sysmon::{
            DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
            FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
            ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
        },
        timeseries::PeriodicTimeSeries,
    },
    publish::{
        PcapFilter,
        range::{MessageCode, RequestRange, RequestRawData, ResponseRangeData},
        receive_range_data, receive_range_data_request, receive_semi_supervised_data,
        receive_semi_supervised_stream_start_message, receive_time_series_generator_data,
        receive_time_series_generator_stream_start_message, recv_ack_response, send_err, send_ok,
        send_range_data, send_range_data_request, send_stream_request,
        stream::{
            RequestSemiSupervisedStream, RequestStreamRecord, RequestTimeSeriesGeneratorStream,
            StreamRequestPayload,
        },
    },
};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tempfile::TempDir;
use tokio::sync::{Notify, RwLock, mpsc, oneshot};
use tracing_subscriber::fmt::MakeWriter;

use super::Server;
use crate::{
    comm::{
        IngestSensors, PcapSensors, StreamDirectChannels,
        ingest::NetworkKey,
        new_pcap_sensors, new_peers_data, new_stream_direct_channels,
        peer::{PeerIdentity, PeerIdents, PeerInfo, Peers},
        publish::{implement::RequestStreamMessage, send_direct_stream},
        to_cert_chain, to_private_key, to_root_cert,
    },
    server::{Certs, config_server},
    storage::{Database, DbOptions, RawEventStore},
};

static INIT: OnceLock<()> = OnceLock::new();

const SENSOR_SEMI_SUPERVISED_ONE: &str = "src1";
const SENSOR_SEMI_SUPERVISED_TWO: &str = "src2";
const SENSOR_TIME_SERIES_GENERATOR_THREE: &str = "src3";
const POLICY_ID: u32 = 1;
const CA_CERT_PATH: &str = "tests/certs/ca_cert.pem";
const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const LOG_KIND: &str = "Hello";
const RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;

const NODE1: NodeConfig = NodeConfig {
    cert_path: "tests/certs/node1/cert.pem",
    key_path: "tests/certs/node1/key.pem",
    host: "node1",
    ingest_sensors: &["src1", "src 1", "ingest src 1"],
};

const NODE2: NodeConfig = NodeConfig {
    cert_path: "tests/certs/node2/cert.pem",
    key_path: "tests/certs/node2/key.pem",
    host: "node2",
    ingest_sensors: &["src2", "src 2", "ingest src 2"],
};

// Stream types that do not have a time-series generator path.
type StreamsWithoutTsgCase = (RequestStreamRecord, &'static str, fn() -> Vec<u8>);

struct ClusterContext<T> {
    publish: TestClient,
    cases: Vec<T>,
    server_handles: Vec<ServerHandle>,
}

struct RangeCase {
    kind: &'static str,
    expected_payload: Vec<u8>,
    expected_done: Vec<u8>,
    min_data: usize,
}

type StreamInsertFn = fn(&Database, &str, i64) -> Vec<u8>;

struct NetworkStreamCase {
    record_type: RequestStreamRecord,
    kind: &'static str,
    semi_payload: fn() -> Vec<u8>,
    direct_payload: fn() -> Vec<u8>,
    insert_db: StreamInsertFn,
}

struct NodeConfig {
    cert_path: &'static str,
    key_path: &'static str,
    host: &'static str,
    ingest_sensors: &'static [&'static str],
}

impl NodeConfig {
    fn build_certs(&self) -> Arc<Certs> {
        build_certs_from_paths(self.cert_path, self.key_path)
    }

    fn build_ingest_sensors(&self) -> IngestSensors {
        build_ingest_sensors_from_list(self.ingest_sensors)
    }

    fn peer_info_with_port(&self, port: u16) -> PeerInfo {
        PeerInfo {
            ingest_sensors: self
                .ingest_sensors
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<HashSet<String>>(),
            graphql_port: None,
            publish_port: Some(port),
        }
    }

    fn peer_identity_with_addr(&self, addr: SocketAddr) -> PeerIdentity {
        PeerIdentity {
            addr,
            hostname: self.host.to_string(),
        }
    }
}

mod fixtures {
    use super::*;
    #[allow(clippy::type_complexity)]
    #[derive(Clone, Copy)]
    pub(super) struct RawEventCase {
        pub(super) kind: &'static str,
        pub(super) insert: fn(&Database, &str, i64) -> Vec<u8>,
        pub(super) build_expected: fn(&[u8], i64, &str) -> Vec<u8>,
        pub(super) validate_payload: Option<fn(&[u8], &str, i64, &[u8])>,
    }

    pub(super) struct RawEventClusterCase {
        pub(super) kind: &'static str,
        pub(super) timestamp: i64,
        pub(super) expected: Vec<u8>,
    }

    pub(super) fn build_expected_response<T: serde::de::DeserializeOwned + ResponseRangeData>(
        ser_body: &[u8],
        timestamp: i64,
        sensor: &str,
    ) -> Vec<u8> {
        bincode::deserialize::<T>(ser_body)
            .unwrap()
            .response_data(timestamp, sensor)
            .unwrap()
    }

    pub(super) struct TestHarness {
        pub(super) _temp_dir: TempDir,
        pub(super) db: Database,
        pub(super) publish: TestClient,
        pub(super) stream_direct_channels: StreamDirectChannels,
        pub(super) pcap_sensors: PcapSensors,
        pub(super) server_handle: ServerHandle,
        pub(super) _server_addr: SocketAddr,
    }

    pub(super) struct TestClient {
        pub(super) send: SendStream,
        pub(super) _recv: RecvStream,
        pub(super) conn: Connection,
        pub(super) endpoint: Endpoint,
    }

    pub(super) struct ServerHandle {
        pub(super) notify: Arc<Notify>,
        pub(super) handle: tokio::task::JoinHandle<()>,
    }

    pub(super) struct PcapFixture {
        pub(super) harness: TestHarness,
        pub(super) filter_rx: mpsc::UnboundedReceiver<PcapFilter>,
        pub(super) _sensor_server_endpoint: Endpoint,
        pub(super) _sensor_client_endpoint: Endpoint,
    }

    pub(super) struct PeerPcapServer {
        pub(super) addr: SocketAddr,
        pub(super) connection_rx: mpsc::UnboundedReceiver<()>,
        pub(super) filter_rx: mpsc::UnboundedReceiver<PcapFilter>,
        pub(super) _endpoint: Endpoint,
    }

    pub(super) struct PeerHandshakeServer {
        pub(super) addr: SocketAddr,
        pub(super) _endpoint: Endpoint,
    }

    pub(super) struct RangeStream {
        pub(super) send: SendStream,
        pub(super) client_conn: Connection,
        pub(super) _server_conn: Connection,
        pub(super) _server_endpoint: Endpoint,
        pub(super) _client_endpoint: Endpoint,
    }

    #[derive(Clone, Default)]
    pub(super) struct LogCapture {
        pub(super) buffer: Arc<StdMutex<Vec<u8>>>,
    }

    impl io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .expect("log capture lock poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogCapture {
        type Writer = LogCapture;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl TestClient {
        pub(super) async fn new(server_addr: SocketAddr, host: &str) -> Self {
            let endpoint = init_client();
            let conn = endpoint
            .connect(server_addr, host)
            .expect(
                "Failed to connect server's endpoint, Please check if the setting value is correct",
            )
            .await
            .expect("Failed to connect server's endpoint, Please make sure the Server is alive");
            let (send, recv) = client_handshake(&conn, PROTOCOL_VERSION).await.unwrap();
            Self {
                send,
                _recv: recv,
                conn,
                endpoint,
            }
        }

        pub(super) async fn send_range_request<T: serde::de::DeserializeOwned>(
            &self,
            message_code: MessageCode,
            message: RequestRange,
        ) -> Vec<Option<T>> {
            let (mut send_pub_req, mut recv_pub_resp) =
                self.conn.open_bi().await.expect("failed to open stream");
            send_range_data_request(&mut send_pub_req, message_code, message)
                .await
                .unwrap();

            let mut result_data = Vec::new();
            loop {
                let resp_data = tokio::time::timeout(
                    StdDuration::from_secs(5),
                    receive_range_data::<Option<T>>(&mut recv_pub_resp),
                )
                .await
                .expect("range response timeout")
                .expect("failed to receive range response");
                let is_done = resp_data.is_none();

                result_data.push(resp_data);
                if is_done {
                    break;
                }
            }

            result_data
        }

        pub(super) async fn close(&self, reason: &'static [u8]) {
            self.conn.close(0u32.into(), reason);
            self.endpoint.wait_idle().await;
        }
    }

    impl ServerHandle {
        pub(super) async fn shutdown(self) {
            self.notify.notify_waiters();
            let _ = self.handle.await;
        }
    }

    impl TestHarness {
        pub(super) async fn shutdown(self) {
            self.server_handle.shutdown().await;
        }
    }

    impl<T> ClusterContext<T> {
        pub(super) async fn shutdown(self) {
            for handle in self.server_handles {
                handle.shutdown().await;
            }
        }
    }

    pub(super) type HarnessFuture<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;

    pub(super) async fn with_test_harness<F>(f: F)
    where
        for<'a> F: FnOnce(&'a mut TestHarness) -> HarnessFuture<'a>,
    {
        let mut harness = setup_test_harness().await;
        f(&mut harness).await;
        harness.publish.close(b"publish_test_done").await;
        harness.shutdown().await;
    }

    pub(super) fn next_timestamp() -> i64 {
        static NEXT_TS: AtomicI64 = AtomicI64::new(1_700_000_000_000_000_000);
        NEXT_TS.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) async fn setup_pcap_fixture(sensor: &str) -> PcapFixture {
        let harness = setup_test_harness().await;

        let (sensor_conn, filter_rx, sensor_server_endpoint, sensor_client_endpoint) =
            setup_pcap_sensor_connection(NODE1.host).await;
        harness
            .pcap_sensors
            .write()
            .await
            .insert(sensor.to_string(), vec![sensor_conn]);

        PcapFixture {
            harness,
            filter_rx,
            _sensor_server_endpoint: sensor_server_endpoint,
            _sensor_client_endpoint: sensor_client_endpoint,
        }
    }

    pub(super) fn assert_filter_matches(received: &PcapFilter, expected: &PcapFilter) {
        assert_eq!(received.sensor, expected.sensor);
        assert_eq!(received.src_addr, expected.src_addr);
        assert_eq!(received.dst_addr, expected.dst_addr);
        assert_eq!(received.src_port, expected.src_port);
        assert_eq!(received.dst_port, expected.dst_port);
        assert_eq!(received.proto, expected.proto);
        assert_eq!(received.start_time, expected.start_time);
        assert_eq!(received.end_time, expected.end_time);
    }

    // Use in tests running on current_thread; subscriber is thread-local.
    pub(super) fn start_log_capture() -> (LogCapture, tracing::dispatcher::DefaultGuard) {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .with_level(false)
            .with_target(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }

    pub(super) async fn assert_log_contains(capture: &LogCapture, expected: &str) {
        let deadline = Instant::now() + StdDuration::from_secs(1);
        let expected_bytes = expected.as_bytes();
        loop {
            let found = {
                let guard = capture.buffer.lock().expect("log capture lock poisoned");
                guard
                    .windows(expected_bytes.len())
                    .any(|window| window == expected_bytes)
            };
            if found {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "log not found: {expected}\nlogs:\n{}",
                String::from_utf8_lossy(&capture.buffer.lock().expect("log capture lock poisoned"))
            );
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    }

    pub(super) async fn recv_with_timeout<T>(
        rx: &mut mpsc::UnboundedReceiver<T>,
        label: &str,
        timeout: StdDuration,
    ) -> T {
        tokio::time::timeout(timeout, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("{label} did not respond"))
            .unwrap_or_else(|| panic!("{label} channel closed"))
    }

    pub(super) async fn send_range_request_and_collect<T: serde::de::DeserializeOwned>(
        publish: &TestClient,
        request: RequestRange,
    ) -> Vec<Option<(i64, String, T)>> {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        send_range_data_request(&mut send_pub_req, RANGE_MESSAGE_CODE, request)
            .await
            .expect("failed to send range request");
        let mut result_data = Vec::new();
        loop {
            let resp_data = receive_range_data::<Option<(i64, String, T)>>(&mut recv_pub_resp)
                .await
                .unwrap();
            result_data.push(resp_data);
            if result_data.last().unwrap().is_none() {
                break;
            }
        }
        result_data
    }

    pub(super) async fn open_range_stream(host: &str) -> (SendStream, Connection) {
        let RangeStream {
            send,
            client_conn,
            _server_endpoint,
            _client_endpoint,
            _server_conn: _,
        } = setup_range_stream(host).await;
        (send, client_conn)
    }

    pub(super) fn build_filter_for_sensor(
        sensor: &str,
        start_time: i64,
        end_time: i64,
    ) -> PcapFilter {
        build_pcap_filter(
            sensor,
            start_time,
            end_time,
            "192.168.0.1",
            1234,
            "192.168.0.2",
            80,
            6,
        )
    }

    pub(super) async fn run_pcap_filters_and_recv_single(
        filters: Vec<PcapFilter>,
        pcap_sensors: PcapSensors,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        peer_idents: Arc<RwLock<HashSet<PeerIdentity>>>,
        rx: &mut mpsc::UnboundedReceiver<PcapFilter>,
        label: &str,
        timeout: StdDuration,
    ) -> PcapFilter {
        run_process_pcap_extract_filters(filters, pcap_sensors, peers, peer_idents).await;
        recv_with_timeout(rx, label, timeout).await
    }

    pub(super) async fn with_log_capture<F, Fut>(f: F)
    where
        F: FnOnce(LogCapture) -> Fut,
        Fut: Future<Output = ()>,
    {
        let (capture, _guard) = start_log_capture();
        f(capture).await;
    }

    pub(super) fn init_crypto() {
        INIT.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    pub(super) fn build_ingest_sensors_from_list(list: &[&str]) -> IngestSensors {
        Arc::new(RwLock::new(
            list.iter()
                .copied()
                .map(str::to_string)
                .collect::<HashSet<String>>(),
        ))
    }

    pub(super) fn build_ingest_sensors() -> IngestSensors {
        NODE1.build_ingest_sensors()
    }

    pub(super) fn build_certs_from_paths(cert_path: &str, key_path: &str) -> Arc<Certs> {
        let cert_pem = fs::read(cert_path).unwrap();
        let cert = to_cert_chain(&cert_pem).unwrap();
        let key_pem = fs::read(key_path).unwrap();
        let key = to_private_key(&key_pem).unwrap();
        let ca_cert_path = vec![CA_CERT_PATH.to_string()];
        let root = to_root_cert(&ca_cert_path).unwrap();

        Arc::new(Certs {
            certs: cert,
            key,
            root,
        })
    }

    pub(super) fn build_test_certs() -> Arc<Certs> {
        NODE1.build_certs()
    }

    pub(super) async fn setup_test_harness() -> TestHarness {
        init_crypto();

        let temp_dir = tempfile::tempdir().expect("create publish temp dir");
        let db = Database::open(temp_dir.path(), &DbOptions::default())
            .expect("open publish test database");
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = build_ingest_sensors();
        let (peers, peer_idents) = new_peers_data(None);
        let certs = build_test_certs();

        let (server_addr, server_handle) = spawn_server(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            db.clone(),
            pcap_sensors.clone(),
            stream_direct_channels.clone(),
            ingest_sensors,
            peers,
            peer_idents,
            certs,
        )
        .await;

        let publish = tokio::time::timeout(
            StdDuration::from_secs(2),
            TestClient::new(server_addr, NODE1.host),
        )
        .await
        .expect("publish client connect timeout");

        TestHarness {
            _temp_dir: temp_dir,
            db,
            publish,
            stream_direct_channels,
            pcap_sensors,
            server_handle,
            _server_addr: server_addr,
        }
    }

    pub(super) fn assert_range_result_common<T>(
        result_data: &[Option<(i64, String, T)>],
        request: &RequestRange,
        expected_payload: &[u8],
        expected_done: &[u8],
        min_data: usize,
        context: &str,
    ) where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq,
    {
        assert!(!result_data.is_empty(), "range response empty: {context}");
        let (done_message, data_messages) = result_data.split_last().expect("range response empty");

        let done_payload = bincode::serialize(done_message).unwrap();
        assert_eq!(
            expected_done, done_payload,
            "done payload mismatch: {context}"
        );
        assert!(
            data_messages.len() >= min_data,
            "expected at least {min_data} data messages: {context}"
        );
        assert!(
            data_messages.iter().all(Option::is_some),
            "unexpected done message before end: {context}"
        );
        assert!(
            data_messages.len() <= request.count,
            "more messages than requested count: {context}"
        );

        let expected_value: Option<(i64, String, T)> =
            bincode::deserialize(expected_payload).unwrap();
        let expected_value = expected_value.expect("expected payload should be Some");
        let matched = data_messages
            .iter()
            .any(|message| message.as_ref() == Some(&expected_value));
        assert!(matched, "expected payload not found: {context}");

        for message in data_messages.iter().flatten() {
            let (timestamp, sensor, _payload) = message;
            assert_eq!(sensor, &request.sensor, "sensor mismatch: {context}");
            assert!(
                *timestamp >= request.start && *timestamp < request.end,
                "timestamp out of range: {context}"
            );
        }
    }

    pub(super) fn validate_range_payload(kind: &str, timestamp: i64, sensor: &str, payload: &[u8]) {
        if kind == LOG_KIND {
            return;
        }

        let payload_str =
            std::str::from_utf8(payload).expect("range payload must be utf-8 for non-log kinds");

        match kind {
            "netflow5" | "netflow9" => {
                let mut parts = payload_str.splitn(2, '\t');
                let ts_part = parts.next().expect("missing timestamp");
                let rest = parts.next().expect("missing netflow payload");
                assert_eq!(
                    ts_part,
                    format_zeek_time(timestamp),
                    "netflow timestamp mismatch"
                );
                assert!(!rest.is_empty(), "netflow payload is empty");
            }
            _ => {
                let mut parts = payload_str.splitn(3, '\t');
                let ts_part = parts.next().expect("missing timestamp");
                let sensor_part = parts.next().expect("missing sensor");
                let rest = parts.next().expect("missing payload body");
                assert_eq!(
                    ts_part,
                    format_zeek_time(timestamp),
                    "range payload timestamp mismatch"
                );
                assert_eq!(sensor_part, sensor, "range payload sensor mismatch");
                assert!(!rest.is_empty(), "range payload body is empty");
            }
        }
    }

    pub(super) async fn assert_range_cases(
        publish: &TestClient,
        sensor: &str,
        cases: &[RangeCase],
    ) {
        for case in cases {
            let request = build_range_request(sensor, case.kind);
            let result_data = publish
                .send_range_request::<(i64, String, Vec<u8>)>(RANGE_MESSAGE_CODE, request.clone())
                .await;

            assert_range_result_common(
                &result_data,
                &request,
                case.expected_payload.as_slice(),
                case.expected_done.as_slice(),
                case.min_data,
                case.kind,
            );

            for message in result_data.iter().flatten() {
                let (timestamp, sensor, payload) = message;
                validate_range_payload(&request.kind, *timestamp, sensor, payload);
            }
        }
    }

    pub(super) async fn assert_range_cases_series(
        publish: &TestClient,
        sensor: &str,
        cases: &[RangeCase],
    ) {
        for case in cases {
            let request = build_range_request(sensor, case.kind);
            let result_data = publish
                .send_range_request::<(i64, String, Vec<f64>)>(RANGE_MESSAGE_CODE, request.clone())
                .await;

            assert_range_result_common(
                &result_data,
                &request,
                case.expected_payload.as_slice(),
                case.expected_done.as_slice(),
                case.min_data,
                case.kind,
            );
        }
    }

    pub(super) async fn fetch_raw_data(
        publish: &TestClient,
        kind: &str,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<(i64, String, Vec<u8>)> {
        fetch_raw_data_with_payload(publish, kind, sensor, timestamp).await
    }

    pub(super) async fn fetch_raw_data_with_payload<T: serde::de::DeserializeOwned>(
        publish: &TestClient,
        kind: &str,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<(i64, String, T)> {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");

        let message = RequestRawData {
            kind: String::from(kind),
            input: vec![(String::from(sensor), vec![timestamp])],
        };

        send_range_data_request(&mut send_pub_req, MessageCode::RawData, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data = receive_range_data::<Option<(i64, String, T)>>(&mut recv_pub_resp)
                .await
                .unwrap();

            if let Some(data) = resp_data {
                result_data.push(data);
            } else {
                break;
            }
        }

        result_data
    }

    pub(super) async fn setup_pcap_sensor_connection(
        host: &str,
    ) -> (
        Connection,
        mpsc::UnboundedReceiver<PcapFilter>,
        Endpoint,
        Endpoint,
    ) {
        let (sensor_server_conn, sensor_client_conn, sensor_server, sensor_client_endpoint) =
            setup_quic_loopback(host, "sensor").await;

        let (filter_tx, filter_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let conn = sensor_server_conn;
            while let Ok((send, recv)) = conn.accept_bi().await {
                if let Ok(filter) = giganto_client::publish::pcap_extract_response(send, recv).await
                {
                    let _ = filter_tx.send(filter);
                }
            }
        });

        (
            sensor_client_conn,
            filter_rx,
            sensor_server,
            sensor_client_endpoint,
        )
    }

    pub(super) async fn setup_quic_loopback(
        host: &str,
        label: &str,
    ) -> (Connection, Connection, Endpoint, Endpoint) {
        let label = label.to_string();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![host.to_string()])
                .expect("Failed to generate loopback cert");
        let cert_der = cert.der().clone();
        let cert_chain = vec![cert_der.clone()];
        let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());

        let server_config =
            quinn::ServerConfig::with_single_cert(cert_chain.clone(), PrivateKeyDer::Pkcs8(key))
                .expect("Failed to build loopback server config");

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).expect("Failed to add loopback cert");
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .expect("Failed to build loopback client config"),
        ));
        client_config.transport_config(Arc::new(quinn::TransportConfig::default()));

        let server = Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        )
        .unwrap_or_else(|_| panic!("Failed to start {label} server endpoint"));
        let server_addr = server
            .local_addr()
            .unwrap_or_else(|_| panic!("Failed to get {label} server addr"));

        let server_for_accept = server.clone();
        let label_for_accept = label.clone();
        let accept_handle = tokio::spawn(async move {
            server_for_accept
                .accept()
                .await
                .unwrap_or_else(|| panic!("Failed to accept {label_for_accept} connection"))
                .await
                .unwrap_or_else(|_| panic!("Failed to build {label_for_accept} connection"))
        });

        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
            .unwrap_or_else(|_| panic!("Failed to create {label} client endpoint"));
        client.set_default_client_config(client_config);

        let client_conn = client
            .connect(server_addr, host)
            .unwrap_or_else(|_| panic!("Failed to connect to {label} server"))
            .await
            .unwrap_or_else(|_| panic!("Failed to establish {label} connection"));
        let server_conn = accept_handle
            .await
            .unwrap_or_else(|_| panic!("{label} accept task failed"));

        (server_conn, client_conn, server, client)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_pcap_filter(
        sensor: &str,
        start_time: i64,
        end_time: i64,
        src_addr: &str,
        src_port: u16,
        dst_addr: &str,
        dst_port: u16,
        proto: u8,
    ) -> PcapFilter {
        PcapFilter {
            start_time,
            sensor: sensor.to_string(),
            src_addr: src_addr.parse::<IpAddr>().unwrap(),
            src_port,
            dst_addr: dst_addr.parse::<IpAddr>().unwrap(),
            dst_port,
            proto,
            end_time,
        }
    }

    pub(super) async fn setup_local_pcap_sensor(
        sensor: &str,
    ) -> (PcapSensors, mpsc::UnboundedReceiver<PcapFilter>) {
        let (sensor_conn, filter_rx, _sensor_server_endpoint, _sensor_client_endpoint) =
            setup_pcap_sensor_connection(NODE1.host).await;

        let pcap_sensors = new_pcap_sensors();
        pcap_sensors
            .write()
            .await
            .insert(sensor.to_string(), vec![sensor_conn]);

        (pcap_sensors, filter_rx)
    }

    pub(super) fn build_peers_for_sensor(
        sensor: &str,
        peer_addr: SocketAddr,
    ) -> Arc<RwLock<HashMap<String, PeerInfo>>> {
        Arc::new(RwLock::new(HashMap::from([(
            peer_addr.ip().to_string(),
            PeerInfo {
                ingest_sensors: HashSet::from([sensor.to_string()]),
                graphql_port: None,
                publish_port: Some(peer_addr.port()),
            },
        )])))
    }

    pub(super) fn build_peer_idents(
        peer_addr: SocketAddr,
        hostname: &str,
    ) -> Arc<RwLock<HashSet<PeerIdentity>>> {
        Arc::new(RwLock::new(HashSet::from([PeerIdentity {
            addr: peer_addr,
            hostname: hostname.to_string(),
        }])))
    }

    pub(super) async fn run_process_pcap_extract_filters(
        filters: Vec<PcapFilter>,
        pcap_sensors: PcapSensors,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        peer_idents: Arc<RwLock<HashSet<PeerIdentity>>>,
    ) {
        let certs = build_test_certs();
        let (mut server_send, _ack_server, _ack_client) = build_ack_stream("ack.local").await;

        crate::comm::publish::process_pcap_extract_filters(
            filters,
            pcap_sensors,
            peers,
            peer_idents,
            certs,
            &mut server_send,
        )
        .await
        .expect("process_pcap_extract_filters failed");
    }

    pub(super) async fn assert_no_peer_connection(mut connection_rx: mpsc::UnboundedReceiver<()>) {
        let err = tokio::time::timeout(StdDuration::from_millis(200), connection_rx.recv())
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "deadline has elapsed");
    }

    pub(super) async fn build_ack_stream(host: &str) -> (SendStream, Endpoint, Endpoint) {
        let (server_conn, _client_conn, ack_server, ack_client) =
            setup_quic_loopback(host, "ack").await;
        let server_send = server_conn.open_uni().await.expect("server uni");

        (server_send, ack_server, ack_client)
    }

    pub(super) async fn setup_peer_pcap_server(certs: Arc<Certs>) -> PeerPcapServer {
        setup_peer_pcap_server_with_ack(certs, None).await
    }

    #[allow(clippy::unused_async)]
    pub(super) async fn setup_peer_pcap_server_with_ack(
        certs: Arc<Certs>,
        ack_error: Option<&'static str>,
    ) -> PeerPcapServer {
        let server_config = config_server(&certs).expect("peer publish server config");
        let endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("Failed to start peer publish server");
        let addr = endpoint
            .local_addr()
            .expect("Failed to get peer publish server addr");
        let (conn_tx, conn_rx) = mpsc::unbounded_channel();
        let (filter_tx, filter_rx) = mpsc::unbounded_channel();

        let endpoint_for_accept = endpoint.clone();
        let ack_error = ack_error.map(str::to_string);
        tokio::spawn(async move {
            let Some(connecting) = endpoint_for_accept.accept().await else {
                return;
            };
            let _ = conn_tx.send(());
            let Ok(connection) = connecting.await else {
                return;
            };
            if server_handshake(&connection, crate::comm::publish::PUBLISH_VERSION_REQ)
                .await
                .is_err()
            {
                return;
            }
            if let Ok((mut send, mut recv)) = connection.accept_bi().await {
                if let Ok((msg_code, data)) = receive_range_data_request(&mut recv).await
                    && msg_code == MessageCode::Pcap
                    && let Ok(filter) = bincode::deserialize::<PcapFilter>(&data)
                {
                    let _ = filter_tx.send(filter);
                }

                let mut buf = Vec::new();
                if let Some(message) = ack_error {
                    let _ = send_err(&mut send, &mut buf, message).await;
                } else {
                    let _ = send_ok(&mut send, &mut buf, ()).await;
                }
            }
        });

        PeerPcapServer {
            addr,
            connection_rx: conn_rx,
            filter_rx,
            _endpoint: endpoint,
        }
    }

    #[allow(clippy::unused_async)]
    pub(super) async fn setup_peer_handshake_mismatch_server(
        certs: Arc<Certs>,
        version_req: &'static str,
    ) -> PeerHandshakeServer {
        let server_config = config_server(&certs).expect("peer publish server config");
        let endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("Failed to start peer publish server");
        let addr = endpoint
            .local_addr()
            .expect("Failed to get peer publish server addr");

        let endpoint_for_accept = endpoint.clone();
        tokio::spawn(async move {
            let Some(connecting) = endpoint_for_accept.accept().await else {
                return;
            };
            let Ok(connection) = connecting.await else {
                return;
            };
            let _ = server_handshake(&connection, version_req).await;
        });

        PeerHandshakeServer {
            addr,
            _endpoint: endpoint,
        }
    }

    pub(super) async fn setup_range_stream(host: &str) -> RangeStream {
        let (server_conn, client_conn, server, client) = setup_quic_loopback(host, "range").await;
        let server_send = server_conn.open_uni().await.expect("range server uni");

        RangeStream {
            send: server_send,
            client_conn,
            _server_conn: server_conn,
            _server_endpoint: server,
            _client_endpoint: client,
        }
    }

    pub(super) async fn collect_range_data(
        recv: &mut RecvStream,
    ) -> Vec<Option<(i64, String, Vec<u8>)>> {
        let mut result = Vec::new();
        loop {
            let item = receive_range_data::<Option<(i64, String, Vec<u8>)>>(recv)
                .await
                .unwrap();
            let done = item.is_none();
            result.push(item);
            if done {
                break;
            }
        }
        result
    }

    pub(super) fn setup_peer_range_server(
        certs: &Arc<Certs>,
        responses: Vec<(i64, String, Conn)>,
    ) -> PeerHandshakeServer {
        let server_config = config_server(certs).expect("peer range server config");
        let endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("Failed to start peer range server");
        let addr = endpoint
            .local_addr()
            .expect("Failed to get peer range server addr");

        let endpoint_for_accept = endpoint.clone();
        tokio::spawn(async move {
            let Some(connecting) = endpoint_for_accept.accept().await else {
                return;
            };
            let Ok(connection) = connecting.await else {
                return;
            };

            if server_handshake(&connection, crate::comm::publish::PUBLISH_VERSION_REQ)
                .await
                .is_err()
            {
                return;
            }
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                return;
            };
            let Ok((_msg_code, _buf)) = receive_range_data_request(&mut recv).await else {
                return;
            };
            for (timestamp, sensor, conn) in responses {
                let _ = send_range_data(&mut send, Some((conn, timestamp, sensor.as_str()))).await;
            }
            let _ = send_range_data::<Conn>(&mut send, None).await;
            let _ = send.finish();
            let _ = connection.closed().await;
        });

        PeerHandshakeServer {
            addr,
            _endpoint: endpoint,
        }
    }

    pub(super) fn setup_peer_range_server_without_done(
        certs: &Arc<Certs>,
        responses: Vec<(i64, String, Conn)>,
    ) -> PeerHandshakeServer {
        let server_config = config_server(certs).expect("peer range server config");
        let endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("Failed to start peer range server");
        let addr = endpoint
            .local_addr()
            .expect("Failed to get peer range server addr");

        let endpoint_for_accept = endpoint.clone();
        tokio::spawn(async move {
            let Some(connecting) = endpoint_for_accept.accept().await else {
                return;
            };
            let Ok(connection) = connecting.await else {
                return;
            };

            if server_handshake(&connection, crate::comm::publish::PUBLISH_VERSION_REQ)
                .await
                .is_err()
            {
                return;
            }
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                return;
            };
            let Ok((_msg_code, _buf)) = receive_range_data_request(&mut recv).await else {
                return;
            };
            for (timestamp, sensor, conn) in responses {
                let _ = send_range_data(&mut send, Some((conn, timestamp, sensor.as_str()))).await;
            }
            let _ = send.finish();
            let _ = connection.closed().await;
        });

        PeerHandshakeServer {
            addr,
            _endpoint: endpoint,
        }
    }

    pub(super) struct RangeCaseSpec {
        pub(super) kind: &'static str,
        pub(super) build_expected: fn(&Database, &str, i64) -> Vec<u8>,
    }

    pub(super) fn done_bytes() -> Vec<u8> {
        Conn::response_done().unwrap()
    }

    pub(super) fn done_series() -> Vec<u8> {
        PeriodicTimeSeries::response_done().unwrap()
    }

    pub(super) fn build_conn_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_conn_raw_event(&db.conn_store().unwrap(), sensor, timestamp);
        build_expected_response::<Conn>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_dns_range_expected(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        let ser_body = insert_dns_raw_event(&db.dns_store().unwrap(), sensor, timestamp);
        build_expected_response::<Dns>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_malformed_dns_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body =
            insert_malformed_dns_raw_event(&db.malformed_dns_store().unwrap(), sensor, timestamp);
        build_expected_response::<MalformedDns>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_http_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_http_raw_event(&db.http_store().unwrap(), sensor, timestamp);
        build_expected_response::<Http>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_rdp_range_expected(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        let ser_body = insert_rdp_raw_event(&db.rdp_store().unwrap(), sensor, timestamp);
        build_expected_response::<Rdp>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_smtp_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_smtp_raw_event(&db.smtp_store().unwrap(), sensor, timestamp);
        build_expected_response::<Smtp>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_ntlm_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_ntlm_raw_event(&db.ntlm_store().unwrap(), sensor, timestamp);
        build_expected_response::<Ntlm>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_kerberos_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_kerberos_raw_event(&db.kerberos_store().unwrap(), sensor, timestamp);
        build_expected_response::<Kerberos>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_ssh_range_expected(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        let ser_body = insert_ssh_raw_event(&db.ssh_store().unwrap(), sensor, timestamp);
        build_expected_response::<Ssh>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_dce_rpc_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_dce_rpc_raw_event(&db.dce_rpc_store().unwrap(), sensor, timestamp);
        build_expected_response::<DceRpc>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_ftp_range_expected(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        let ser_body = insert_ftp_raw_event(&db.ftp_store().unwrap(), sensor, timestamp);
        build_expected_response::<Ftp>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_mqtt_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_mqtt_raw_event(&db.mqtt_store().unwrap(), sensor, timestamp);
        build_expected_response::<Mqtt>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_ldap_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_ldap_raw_event(&db.ldap_store().unwrap(), sensor, timestamp);
        build_expected_response::<Ldap>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_tls_range_expected(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        let ser_body = insert_tls_raw_event(&db.tls_store().unwrap(), sensor, timestamp);
        build_expected_response::<Tls>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_smb_range_expected(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        let ser_body = insert_smb_raw_event(&db.smb_store().unwrap(), sensor, timestamp);
        build_expected_response::<Smb>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_nfs_range_expected(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        let ser_body = insert_nfs_raw_event(&db.nfs_store().unwrap(), sensor, timestamp);
        build_expected_response::<Nfs>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_bootp_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_bootp_raw_event(&db.bootp_store().unwrap(), sensor, timestamp);
        build_expected_response::<Bootp>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_dhcp_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_dhcp_raw_event(&db.dhcp_store().unwrap(), sensor, timestamp);
        build_expected_response::<Dhcp>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_radius_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_radius_raw_event(&db.radius_store().unwrap(), sensor, timestamp);
        build_expected_response::<Radius>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_process_create_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body =
            insert_process_create_raw_event(&db.process_create_store().unwrap(), sensor, timestamp);
        build_expected_response::<ProcessCreate>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_file_create_time_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_file_create_time_raw_event(
            &db.file_create_time_store().unwrap(),
            sensor,
            timestamp,
        );
        build_expected_response::<FileCreationTimeChanged>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_network_connect_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_network_connect_raw_event(
            &db.network_connect_store().unwrap(),
            sensor,
            timestamp,
        );
        build_expected_response::<NetworkConnection>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_process_terminate_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_process_terminate_raw_event(
            &db.process_terminate_store().unwrap(),
            sensor,
            timestamp,
        );
        build_expected_response::<ProcessTerminated>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_image_load_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body =
            insert_image_load_raw_event(&db.image_load_store().unwrap(), sensor, timestamp);
        build_expected_response::<ImageLoaded>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_file_create_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body =
            insert_file_create_raw_event(&db.file_create_store().unwrap(), sensor, timestamp);
        build_expected_response::<FileCreate>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_registry_value_set_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_registry_value_set_raw_event(
            &db.registry_value_set_store().unwrap(),
            sensor,
            timestamp,
        );
        build_expected_response::<RegistryValueSet>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_registry_key_rename_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_registry_key_rename_raw_event(
            &db.registry_key_rename_store().unwrap(),
            sensor,
            timestamp,
        );
        build_expected_response::<RegistryKeyValueRename>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_file_create_stream_hash_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_file_create_stream_hash_raw_event(
            &db.file_create_stream_hash_store().unwrap(),
            sensor,
            timestamp,
        );
        build_expected_response::<FileCreateStreamHash>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_pipe_event_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body =
            insert_pipe_event_raw_event(&db.pipe_event_store().unwrap(), sensor, timestamp);
        build_expected_response::<PipeEvent>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_dns_query_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body =
            insert_dns_query_raw_event(&db.dns_query_store().unwrap(), sensor, timestamp);
        build_expected_response::<DnsEvent>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_file_delete_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body =
            insert_file_delete_raw_event(&db.file_delete_store().unwrap(), sensor, timestamp);
        build_expected_response::<FileDelete>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_process_tamper_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body =
            insert_process_tamper_raw_event(&db.process_tamper_store().unwrap(), sensor, timestamp);
        build_expected_response::<ProcessTampering>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_file_delete_detected_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_file_delete_detected_raw_event(
            &db.file_delete_detected_store().unwrap(),
            sensor,
            timestamp,
        );
        build_expected_response::<FileDeleteDetected>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_netflow5_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_netflow5_raw_event(&db.netflow5_store().unwrap(), sensor, timestamp);
        build_expected_response::<Netflow5>(&ser_body, timestamp, sensor)
    }

    pub(super) fn build_netflow9_range_expected(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let ser_body = insert_netflow9_raw_event(&db.netflow9_store().unwrap(), sensor, timestamp);
        build_expected_response::<Netflow9>(&ser_body, timestamp, sensor)
    }

    pub(super) const NETWORK_RANGE_SPECS: &[RangeCaseSpec] = &[
        RangeCaseSpec {
            kind: "conn",
            build_expected: build_conn_range_expected,
        },
        RangeCaseSpec {
            kind: "dns",
            build_expected: build_dns_range_expected,
        },
        RangeCaseSpec {
            kind: "malformed_dns",
            build_expected: build_malformed_dns_range_expected,
        },
        RangeCaseSpec {
            kind: "http",
            build_expected: build_http_range_expected,
        },
        RangeCaseSpec {
            kind: "rdp",
            build_expected: build_rdp_range_expected,
        },
        RangeCaseSpec {
            kind: "smtp",
            build_expected: build_smtp_range_expected,
        },
        RangeCaseSpec {
            kind: "ntlm",
            build_expected: build_ntlm_range_expected,
        },
        RangeCaseSpec {
            kind: "kerberos",
            build_expected: build_kerberos_range_expected,
        },
        RangeCaseSpec {
            kind: "ssh",
            build_expected: build_ssh_range_expected,
        },
        RangeCaseSpec {
            kind: "dce rpc",
            build_expected: build_dce_rpc_range_expected,
        },
        RangeCaseSpec {
            kind: "ftp",
            build_expected: build_ftp_range_expected,
        },
        RangeCaseSpec {
            kind: "mqtt",
            build_expected: build_mqtt_range_expected,
        },
        RangeCaseSpec {
            kind: "ldap",
            build_expected: build_ldap_range_expected,
        },
        RangeCaseSpec {
            kind: "tls",
            build_expected: build_tls_range_expected,
        },
        RangeCaseSpec {
            kind: "smb",
            build_expected: build_smb_range_expected,
        },
        RangeCaseSpec {
            kind: "nfs",
            build_expected: build_nfs_range_expected,
        },
        RangeCaseSpec {
            kind: "bootp",
            build_expected: build_bootp_range_expected,
        },
        RangeCaseSpec {
            kind: "dhcp",
            build_expected: build_dhcp_range_expected,
        },
        RangeCaseSpec {
            kind: "radius",
            build_expected: build_radius_range_expected,
        },
    ];

    pub(super) const SYSMON_RANGE_SPECS: &[RangeCaseSpec] = &[
        RangeCaseSpec {
            kind: "process_create",
            build_expected: build_process_create_range_expected,
        },
        RangeCaseSpec {
            kind: "file_create_time",
            build_expected: build_file_create_time_range_expected,
        },
        RangeCaseSpec {
            kind: "network_connect",
            build_expected: build_network_connect_range_expected,
        },
        RangeCaseSpec {
            kind: "process_terminate",
            build_expected: build_process_terminate_range_expected,
        },
        RangeCaseSpec {
            kind: "image_load",
            build_expected: build_image_load_range_expected,
        },
        RangeCaseSpec {
            kind: "file_create",
            build_expected: build_file_create_range_expected,
        },
        RangeCaseSpec {
            kind: "registry_value_set",
            build_expected: build_registry_value_set_range_expected,
        },
        RangeCaseSpec {
            kind: "registry_key_rename",
            build_expected: build_registry_key_rename_range_expected,
        },
        RangeCaseSpec {
            kind: "file_create_stream_hash",
            build_expected: build_file_create_stream_hash_range_expected,
        },
        RangeCaseSpec {
            kind: "pipe_event",
            build_expected: build_pipe_event_range_expected,
        },
        RangeCaseSpec {
            kind: "dns_query",
            build_expected: build_dns_query_range_expected,
        },
        RangeCaseSpec {
            kind: "file_delete",
            build_expected: build_file_delete_range_expected,
        },
        RangeCaseSpec {
            kind: "process_tamper",
            build_expected: build_process_tamper_range_expected,
        },
        RangeCaseSpec {
            kind: "file_delete_detected",
            build_expected: build_file_delete_detected_range_expected,
        },
    ];

    pub(super) const NETFLOW_RANGE_SPECS: &[RangeCaseSpec] = &[
        RangeCaseSpec {
            kind: "netflow5",
            build_expected: build_netflow5_range_expected,
        },
        RangeCaseSpec {
            kind: "netflow9",
            build_expected: build_netflow9_range_expected,
        },
    ];

    pub(super) const NETWORK_RAW_EVENT_CASES: &[RawEventCase] = &[
        RawEventCase {
            kind: "conn",
            insert: insert_conn_stream,
            build_expected: build_expected_response::<Conn>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Conn>),
        },
        RawEventCase {
            kind: "dns",
            insert: insert_dns_stream,
            build_expected: build_expected_response::<Dns>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Dns>),
        },
        RawEventCase {
            kind: "malformed_dns",
            insert: insert_malformed_dns_stream,
            build_expected: build_expected_response::<MalformedDns>,
            validate_payload: Some(validate_csv_payload_with_sensor::<MalformedDns>),
        },
        RawEventCase {
            kind: "http",
            insert: insert_http_stream,
            build_expected: build_expected_response::<Http>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Http>),
        },
        RawEventCase {
            kind: "rdp",
            insert: insert_rdp_stream,
            build_expected: build_expected_response::<Rdp>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Rdp>),
        },
        RawEventCase {
            kind: "smtp",
            insert: insert_smtp_stream,
            build_expected: build_expected_response::<Smtp>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Smtp>),
        },
        RawEventCase {
            kind: "ntlm",
            insert: insert_ntlm_stream,
            build_expected: build_expected_response::<Ntlm>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Ntlm>),
        },
        RawEventCase {
            kind: "kerberos",
            insert: insert_kerberos_stream,
            build_expected: build_expected_response::<Kerberos>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Kerberos>),
        },
        RawEventCase {
            kind: "ssh",
            insert: insert_ssh_stream,
            build_expected: build_expected_response::<Ssh>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Ssh>),
        },
        RawEventCase {
            kind: "dce rpc",
            insert: insert_dce_rpc_stream,
            build_expected: build_expected_response::<DceRpc>,
            validate_payload: Some(validate_csv_payload_with_sensor::<DceRpc>),
        },
        RawEventCase {
            kind: "ftp",
            insert: insert_ftp_stream,
            build_expected: build_expected_response::<Ftp>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Ftp>),
        },
        RawEventCase {
            kind: "mqtt",
            insert: insert_mqtt_stream,
            build_expected: build_expected_response::<Mqtt>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Mqtt>),
        },
        RawEventCase {
            kind: "ldap",
            insert: insert_ldap_stream,
            build_expected: build_expected_response::<Ldap>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Ldap>),
        },
        RawEventCase {
            kind: "tls",
            insert: insert_tls_stream,
            build_expected: build_expected_response::<Tls>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Tls>),
        },
        RawEventCase {
            kind: "smb",
            insert: insert_smb_stream,
            build_expected: build_expected_response::<Smb>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Smb>),
        },
        RawEventCase {
            kind: "nfs",
            insert: insert_nfs_stream,
            build_expected: build_expected_response::<Nfs>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Nfs>),
        },
        RawEventCase {
            kind: "bootp",
            insert: insert_bootp_stream,
            build_expected: build_expected_response::<Bootp>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Bootp>),
        },
        RawEventCase {
            kind: "dhcp",
            insert: insert_dhcp_stream,
            build_expected: build_expected_response::<Dhcp>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Dhcp>),
        },
        RawEventCase {
            kind: "radius",
            insert: insert_radius_stream,
            build_expected: build_expected_response::<Radius>,
            validate_payload: Some(validate_csv_payload_with_sensor::<Radius>),
        },
    ];

    pub(super) const SYSMON_RAW_EVENT_CASES: &[RawEventCase] = &[
        RawEventCase {
            kind: "process_create",
            insert: insert_process_create_stream,
            build_expected: build_expected_response::<ProcessCreate>,
            validate_payload: Some(validate_csv_payload_with_sensor::<ProcessCreate>),
        },
        RawEventCase {
            kind: "file_create_time",
            insert: insert_file_create_time_stream,
            build_expected: build_expected_response::<FileCreationTimeChanged>,
            validate_payload: Some(validate_csv_payload_with_sensor::<FileCreationTimeChanged>),
        },
        RawEventCase {
            kind: "network_connect",
            insert: insert_network_connect_stream,
            build_expected: build_expected_response::<NetworkConnection>,
            validate_payload: Some(validate_csv_payload_with_sensor::<NetworkConnection>),
        },
        RawEventCase {
            kind: "process_terminate",
            insert: insert_process_terminate_stream,
            build_expected: build_expected_response::<ProcessTerminated>,
            validate_payload: Some(validate_csv_payload_with_sensor::<ProcessTerminated>),
        },
        RawEventCase {
            kind: "image_load",
            insert: insert_image_load_stream,
            build_expected: build_expected_response::<ImageLoaded>,
            validate_payload: Some(validate_csv_payload_with_sensor::<ImageLoaded>),
        },
        RawEventCase {
            kind: "file_create",
            insert: insert_file_create_stream,
            build_expected: build_expected_response::<FileCreate>,
            validate_payload: Some(validate_csv_payload_with_sensor::<FileCreate>),
        },
        RawEventCase {
            kind: "registry_value_set",
            insert: insert_registry_value_set_stream,
            build_expected: build_expected_response::<RegistryValueSet>,
            validate_payload: Some(validate_csv_payload_with_sensor::<RegistryValueSet>),
        },
        RawEventCase {
            kind: "registry_key_rename",
            insert: insert_registry_key_rename_stream,
            build_expected: build_expected_response::<RegistryKeyValueRename>,
            validate_payload: Some(validate_csv_payload_with_sensor::<RegistryKeyValueRename>),
        },
        RawEventCase {
            kind: "file_create_stream_hash",
            insert: insert_file_create_stream_hash_stream,
            build_expected: build_expected_response::<FileCreateStreamHash>,
            validate_payload: Some(validate_csv_payload_with_sensor::<FileCreateStreamHash>),
        },
        RawEventCase {
            kind: "pipe_event",
            insert: insert_pipe_event_stream,
            build_expected: build_expected_response::<PipeEvent>,
            validate_payload: Some(validate_csv_payload_with_sensor::<PipeEvent>),
        },
        RawEventCase {
            kind: "dns_query",
            insert: insert_dns_query_stream,
            build_expected: build_expected_response::<DnsEvent>,
            validate_payload: Some(validate_csv_payload_with_sensor::<DnsEvent>),
        },
        RawEventCase {
            kind: "file_delete",
            insert: insert_file_delete_stream,
            build_expected: build_expected_response::<FileDelete>,
            validate_payload: Some(validate_csv_payload_with_sensor::<FileDelete>),
        },
        RawEventCase {
            kind: "process_tamper",
            insert: insert_process_tamper_stream,
            build_expected: build_expected_response::<ProcessTampering>,
            validate_payload: Some(validate_csv_payload_with_sensor::<ProcessTampering>),
        },
        RawEventCase {
            kind: "file_delete_detected",
            insert: insert_file_delete_detected_stream,
            build_expected: build_expected_response::<FileDeleteDetected>,
            validate_payload: Some(validate_csv_payload_with_sensor::<FileDeleteDetected>),
        },
    ];

    pub(super) const NETFLOW_RAW_EVENT_CASES: &[RawEventCase] = &[
        RawEventCase {
            kind: "netflow5",
            insert: insert_netflow5_stream,
            build_expected: build_expected_response::<Netflow5>,
            validate_payload: Some(validate_csv_payload_without_sensor::<Netflow5>),
        },
        RawEventCase {
            kind: "netflow9",
            insert: insert_netflow9_stream,
            build_expected: build_expected_response::<Netflow9>,
            validate_payload: Some(validate_csv_payload_without_sensor::<Netflow9>),
        },
    ];

    pub(super) fn network_raw_event_cases() -> Vec<RawEventCase> {
        NETWORK_RAW_EVENT_CASES.to_vec()
    }

    pub(super) fn sysmon_raw_event_cases() -> Vec<RawEventCase> {
        SYSMON_RAW_EVENT_CASES.to_vec()
    }

    pub(super) fn netflow_raw_event_cases() -> Vec<RawEventCase> {
        NETFLOW_RAW_EVENT_CASES.to_vec()
    }

    pub(super) fn insert_log_raw_event_case(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_log_body = gen_log_raw_event();
        db.log_store().unwrap().append(&key, &ser_log_body).unwrap();
        ser_log_body
    }

    pub(super) fn build_log_raw_expected(ser_body: &[u8], timestamp: i64, sensor: &str) -> Vec<u8> {
        bincode::deserialize::<Log>(ser_body)
            .unwrap()
            .response_data(timestamp, sensor)
            .unwrap()
    }

    pub(super) fn insert_periodic_time_series_raw_event_case(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_periodic_time_series_raw_event(
            &db.periodic_time_series_store().unwrap(),
            sensor,
            timestamp,
        )
    }

    pub(super) fn build_periodic_time_series_raw_expected(
        ser_body: &[u8],
        timestamp: i64,
        sensor: &str,
    ) -> Vec<u8> {
        bincode::deserialize::<PeriodicTimeSeries>(ser_body)
            .unwrap()
            .response_data(timestamp, sensor)
            .unwrap()
    }

    pub(super) fn log_raw_event_case() -> RawEventCase {
        RawEventCase {
            kind: LOG_KIND,
            insert: insert_log_raw_event_case,
            build_expected: build_log_raw_expected,
            validate_payload: Some(validate_log_payload),
        }
    }

    pub(super) fn periodic_time_series_raw_event_case() -> RawEventCase {
        RawEventCase {
            kind: "timeseries",
            insert: insert_periodic_time_series_raw_event_case,
            build_expected: build_periodic_time_series_raw_expected,
            validate_payload: None,
        }
    }

    pub(super) fn prepare_raw_event(
        db: &Database,
        sensor: &str,
        case: &RawEventCase,
    ) -> (i64, Vec<u8>, Vec<u8>) {
        let timestamp = next_timestamp();
        let ser_body = (case.insert)(db, sensor, timestamp);
        let expected_resp = (case.build_expected)(&ser_body, timestamp, sensor);

        (timestamp, expected_resp, ser_body)
    }

    pub(super) fn cluster_raw_event_cases() -> Vec<RawEventCase> {
        vec![
            conn_raw_event_case(),
            periodic_time_series_raw_event_case(),
            log_raw_event_case(),
        ]
    }

    pub(super) fn conn_raw_event_case() -> RawEventCase {
        NETWORK_RAW_EVENT_CASES
            .iter()
            .copied()
            .find(|case| case.kind == "conn")
            .expect("conn raw event case")
    }

    pub(super) async fn assert_raw_event_cases(
        publish: &TestClient,
        db: &Database,
        sensor: &str,
        cases: &[RawEventCase],
    ) {
        for case in cases {
            let (timestamp, expected_resp, ser_body) = prepare_raw_event(db, sensor, case);
            let mut result_data = fetch_raw_data(publish, case.kind, sensor, timestamp).await;

            assert_eq!(result_data.len(), 1, "Failed for kind: {}", case.kind);
            assert_eq!(result_data[0].0, timestamp);
            assert_eq!(&result_data[0].1, sensor);
            if let Some(validator) = case.validate_payload {
                validator(&result_data[0].2, sensor, timestamp, &ser_body);
            }
            assert_eq!(
                expected_resp,
                bincode::serialize(&Some(result_data.pop().unwrap())).unwrap()
            );
        }
    }

    pub(super) fn decode_semi_supervised_frame(buf: &[u8]) -> (i64, String, Vec<u8>) {
        assert!(buf.len() >= 8, "semi-supervised frame too short");
        let (ts_bytes, rest) = buf.split_at(8);
        let timestamp = i64::from_le_bytes(ts_bytes.try_into().expect("timestamp slice"));

        let mut cursor = io::Cursor::new(rest);
        let sensor: String = bincode::deserialize_from(&mut cursor).expect("sensor decode failed");
        let consumed =
            usize::try_from(cursor.position()).expect("consumed position conversion failed");
        assert!(rest.len() >= consumed, "sensor bytes exceed frame length");
        let payload = rest[consumed..].to_vec();

        (timestamp, sensor, payload)
    }

    pub(super) async fn assert_semi_supervised_stream(
        publish: &mut TestClient,
        record_type: RequestStreamRecord,
        request: &RequestSemiSupervisedStream,
        stream_direct_channels: &StreamDirectChannels,
        kind: &str,
        sensors: &[&str],
        payload_fn: fn() -> Vec<u8>,
    ) {
        send_stream_request(
            &mut publish.send,
            StreamRequestPayload::SemiSupervised {
                record_type,
                request: request.clone(),
            },
        )
        .await
        .unwrap();

        let mut stream = publish.conn.accept_uni().await.unwrap();
        let start_msg = receive_semi_supervised_stream_start_message(&mut stream)
            .await
            .unwrap();
        assert_eq!(start_msg, record_type);

        for sensor in sensors {
            let send_time = next_timestamp();
            let key = NetworkKey::new(sensor, kind);
            let payload = payload_fn();

            send_direct_stream(
                &key,
                &payload,
                send_time,
                sensor,
                stream_direct_channels.clone(),
            )
            .await
            .unwrap();

            let recv_data = receive_semi_supervised_data(&mut stream).await.unwrap();
            let (recv_timestamp, recv_sensor, recv_payload) =
                decode_semi_supervised_frame(&recv_data);
            assert_eq!(recv_timestamp, send_time, "timestamp mismatch");
            assert_eq!(recv_sensor, *sensor, "sensor mismatch");
            assert_eq!(recv_payload, payload, "payload mismatch");
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn assert_time_series_generator_stream(
        publish: &mut TestClient,
        record_type: RequestStreamRecord,
        request: &RequestTimeSeriesGeneratorStream,
        stream_direct_channels: &StreamDirectChannels,
        kind: &str,
        sensor: &str,
        policy_id: u32,
        db_timestamp: i64,
        db_payload: Vec<u8>,
        direct_timestamp: i64,
        direct_payload: Vec<u8>,
    ) {
        send_stream_request(
            &mut publish.send,
            StreamRequestPayload::TimeSeriesGenerator {
                record_type,
                request: request.clone(),
            },
        )
        .await
        .unwrap();

        let mut stream = publish.conn.accept_uni().await.unwrap();
        let start_msg = receive_time_series_generator_stream_start_message(&mut stream)
            .await
            .unwrap();
        assert_eq!(start_msg, policy_id);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut stream)
            .await
            .unwrap();
        assert_eq!(db_timestamp, recv_timestamp);
        assert_eq!(db_payload, recv_data);

        let key = NetworkKey::new(sensor, kind);
        send_direct_stream(
            &key,
            &direct_payload,
            direct_timestamp,
            sensor,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut stream)
            .await
            .unwrap();
        assert_eq!(direct_timestamp, recv_timestamp);
        assert_eq!(direct_payload, recv_data);
    }

    pub(super) fn insert_stream_from_store<T, StoreFn>(
        db: &Database,
        sensor: &str,
        timestamp: i64,
        store_fn: StoreFn,
        insert_fn: fn(&RawEventStore<T>, &str, i64) -> Vec<u8>,
    ) -> Vec<u8>
    where
        StoreFn: Fn(&Database) -> RawEventStore<T>,
    {
        insert_fn(&store_fn(db), sensor, timestamp)
    }

    pub(super) fn insert_conn_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.conn_store().unwrap(),
            insert_conn_raw_event,
        )
    }

    pub(super) fn insert_dns_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.dns_store().unwrap(),
            insert_dns_raw_event,
        )
    }

    pub(super) fn insert_malformed_dns_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.malformed_dns_store().unwrap(),
            insert_malformed_dns_raw_event,
        )
    }

    pub(super) fn insert_rdp_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.rdp_store().unwrap(),
            insert_rdp_raw_event,
        )
    }

    pub(super) fn insert_http_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.http_store().unwrap(),
            insert_http_raw_event,
        )
    }

    pub(super) fn insert_smtp_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.smtp_store().unwrap(),
            insert_smtp_raw_event,
        )
    }

    pub(super) fn insert_ntlm_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.ntlm_store().unwrap(),
            insert_ntlm_raw_event,
        )
    }

    pub(super) fn insert_kerberos_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.kerberos_store().unwrap(),
            insert_kerberos_raw_event,
        )
    }

    pub(super) fn insert_ssh_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.ssh_store().unwrap(),
            insert_ssh_raw_event,
        )
    }

    pub(super) fn insert_dce_rpc_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.dce_rpc_store().unwrap(),
            insert_dce_rpc_raw_event,
        )
    }

    pub(super) fn insert_ftp_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.ftp_store().unwrap(),
            insert_ftp_raw_event,
        )
    }

    pub(super) fn insert_mqtt_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.mqtt_store().unwrap(),
            insert_mqtt_raw_event,
        )
    }

    pub(super) fn insert_ldap_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.ldap_store().unwrap(),
            insert_ldap_raw_event,
        )
    }

    pub(super) fn insert_tls_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.tls_store().unwrap(),
            insert_tls_raw_event,
        )
    }

    pub(super) fn insert_smb_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.smb_store().unwrap(),
            insert_smb_raw_event,
        )
    }

    pub(super) fn insert_nfs_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.nfs_store().unwrap(),
            insert_nfs_raw_event,
        )
    }

    pub(super) fn insert_bootp_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.bootp_store().unwrap(),
            insert_bootp_raw_event,
        )
    }

    pub(super) fn insert_dhcp_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.dhcp_store().unwrap(),
            insert_dhcp_raw_event,
        )
    }

    pub(super) fn insert_radius_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.radius_store().unwrap(),
            insert_radius_raw_event,
        )
    }

    pub(super) fn insert_netflow5_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.netflow5_store().unwrap(),
            insert_netflow5_raw_event,
        )
    }

    pub(super) fn insert_netflow9_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.netflow9_store().unwrap(),
            insert_netflow9_raw_event,
        )
    }

    pub(super) fn insert_process_create_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.process_create_store().unwrap(),
            insert_process_create_raw_event,
        )
    }

    pub(super) fn insert_file_create_time_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.file_create_time_store().unwrap(),
            insert_file_create_time_raw_event,
        )
    }

    pub(super) fn insert_network_connect_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.network_connect_store().unwrap(),
            insert_network_connect_raw_event,
        )
    }

    pub(super) fn insert_process_terminate_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.process_terminate_store().unwrap(),
            insert_process_terminate_raw_event,
        )
    }

    pub(super) fn insert_image_load_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.image_load_store().unwrap(),
            insert_image_load_raw_event,
        )
    }

    pub(super) fn insert_file_create_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.file_create_store().unwrap(),
            insert_file_create_raw_event,
        )
    }

    pub(super) fn insert_registry_value_set_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.registry_value_set_store().unwrap(),
            insert_registry_value_set_raw_event,
        )
    }

    pub(super) fn insert_registry_key_rename_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.registry_key_rename_store().unwrap(),
            insert_registry_key_rename_raw_event,
        )
    }

    pub(super) fn insert_file_create_stream_hash_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.file_create_stream_hash_store().unwrap(),
            insert_file_create_stream_hash_raw_event,
        )
    }

    pub(super) fn insert_pipe_event_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.pipe_event_store().unwrap(),
            insert_pipe_event_raw_event,
        )
    }

    pub(super) fn insert_dns_query_stream(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.dns_query_store().unwrap(),
            insert_dns_query_raw_event,
        )
    }

    pub(super) fn insert_file_delete_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.file_delete_store().unwrap(),
            insert_file_delete_raw_event,
        )
    }

    pub(super) fn insert_process_tamper_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.process_tamper_store().unwrap(),
            insert_process_tamper_raw_event,
        )
    }

    pub(super) fn insert_file_delete_detected_stream(
        db: &Database,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_stream_from_store(
            db,
            sensor,
            timestamp,
            |db| db.file_delete_detected_store().unwrap(),
            insert_file_delete_detected_raw_event,
        )
    }

    pub(super) fn init_client() -> Endpoint {
        let (cert, key): (Vec<u8>, Vec<u8>) = if let Ok(x) = fs::read(NODE1.cert_path).map(|x| {
            (
                x,
                fs::read(NODE1.key_path).expect("Failed to Read key file"),
            )
        }) {
            x
        } else {
            panic!(
                "failed to read (cert, key) file, {}, {} read file error. Cert or key doesn't exist in default test folder",
                NODE1.cert_path, NODE1.key_path
            );
        };

        let pv_key = if Path::new(NODE1.key_path)
            .extension()
            .is_some_and(|x| x == "der")
        {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
        } else {
            rustls_pemfile::private_key(&mut &*key)
                .expect("malformed PKCS #1 private key")
                .expect("no private keys found")
        };

        let cert_chain = if Path::new(NODE1.cert_path)
            .extension()
            .is_some_and(|x| x == "der")
        {
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
            Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
                .expect("Failed to create endpoint");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .expect("Failed to generate QuicClientConfig"),
        )));
        endpoint
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_server_with_ready(
        server: Server,
        db: Database,
        pcap_sensors: PcapSensors,
        stream_direct_channels: StreamDirectChannels,
        ingest_sensors: IngestSensors,
        peers: Peers,
        peer_idents: PeerIdents,
        certs: Arc<Certs>,
        notify_shutdown: Arc<Notify>,
        ready: oneshot::Sender<SocketAddr>,
    ) {
        let endpoint = Endpoint::server(server.server_config, server.server_address)
            .expect("publish endpoint");
        let local_addr = endpoint.local_addr().expect("publish local addr");
        let _ = ready.send(local_addr);

        let mut conn_hdl: Option<tokio::task::JoinHandle<()>> = None;
        loop {
            tokio::select! {
                Some(conn) = endpoint.accept() => {
                    let db = db.clone();
                    let pcap_sensors = pcap_sensors.clone();
                    let stream_direct_channels = stream_direct_channels.clone();
                    let notify_shutdown = notify_shutdown.clone();
                    let ingest_sensors = ingest_sensors.clone();
                    let peers = peers.clone();
                    let peer_idents = peer_idents.clone();
                    let certs = certs.clone();
                    conn_hdl = Some(tokio::spawn(async move {
                        if let Err(err) = crate::comm::publish::handle_connection(
                            conn,
                            db,
                            pcap_sensors,
                            stream_direct_channels,
                            ingest_sensors,
                            peers,
                            peer_idents,
                            certs,
                            notify_shutdown,
                        )
                        .await {
                            panic!("publish connection handler failed: {err}");
                        }
                    }));
                }
                () = notify_shutdown.notified() => {
                    endpoint.close(0_u32.into(), &[]);
                    if let Some(handle) = conn_hdl {
                        let _ = tokio::join!(handle);
                    }
                    break;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn spawn_server(
        addr: SocketAddr,
        db: Database,
        pcap_sensors: PcapSensors,
        stream_direct_channels: StreamDirectChannels,
        ingest_sensors: IngestSensors,
        peers: Peers,
        peer_idents: PeerIdents,
        certs: Arc<Certs>,
    ) -> (SocketAddr, ServerHandle) {
        let notify_shutdown = Arc::new(Notify::new());
        let notify_for_run = notify_shutdown.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let server = Server::new(addr, &certs);

        let handle = tokio::spawn(async move {
            run_server_with_ready(
                server,
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
                certs,
                notify_for_run,
                ready_tx,
            )
            .await;
        });

        let local_addr = ready_rx
            .await
            .expect("publish server did not report local addr");

        (
            local_addr,
            ServerHandle {
                notify: notify_shutdown,
                handle,
            },
        )
    }

    pub(super) fn default_time_range() -> (i64, i64) {
        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(0, 0, 0)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        (
            start.timestamp_nanos_opt().unwrap(),
            end.timestamp_nanos_opt().unwrap(),
        )
    }

    pub(super) fn build_range_request(sensor: &str, kind: &str) -> RequestRange {
        let (start, end) = default_time_range();
        RequestRange {
            sensor: sensor.to_string(),
            kind: kind.to_string(),
            start,
            end,
            count: 5,
        }
    }

    pub(super) fn gen_network_event_key(
        sensor: &str,
        kind: Option<&str>,
        timestamp: i64,
    ) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(sensor.as_bytes());
        key.push(0);
        if let Some(kind) = kind {
            key.extend_from_slice(kind.as_bytes());
            key.push(0);
        }
        key.extend(timestamp.to_be_bytes());
        key
    }

    pub(super) fn gen_conn_raw_event() -> Vec<u8> {
        let tmp_dur = Duration::nanoseconds(12345);
        let conn_body = Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: "sf".to_string(),
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: tmp_dur.num_nanoseconds().unwrap(),
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 21515,
            resp_l2_bytes: 27889,
        };

        bincode::serialize(&conn_body).unwrap()
    }

    pub(super) fn gen_dns_raw_event() -> Vec<u8> {
        let dns_body = Dns {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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
        };

        bincode::serialize(&dns_body).unwrap()
    }

    pub(super) fn gen_malformed_dns_raw_event() -> Vec<u8> {
        let malformed_dns_body = MalformedDns {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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
            query_body: vec![b"malformed query".to_vec()],
            resp_body: vec![b"malformed response".to_vec()],
        };

        bincode::serialize(&malformed_dns_body).unwrap()
    }

    pub(super) fn gen_rdp_raw_event() -> Vec<u8> {
        let rdp_body = Rdp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
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

        bincode::serialize(&rdp_body).unwrap()
    }

    pub(super) fn gen_http_raw_event() -> Vec<u8> {
        let http_body = Http {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
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

        bincode::serialize(&http_body).unwrap()
    }

    pub(super) fn gen_smtp_raw_event() -> Vec<u8> {
        let smtp_body = Smtp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 1_000_000_000,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 100,
            resp_l2_bytes: 200,
            mailfrom: "google".to_string(),
            date: "2022-11-28".to_string(),
            from: "safe2@cluml.com".to_string(),
            to: "safe1@cluml.com".to_string(),
            subject: "hello giganto".to_string(),
            agent: "giganto".to_string(),
            state: String::new(),
        };

        bincode::serialize(&smtp_body).unwrap()
    }

    pub(super) fn gen_ntlm_raw_event() -> Vec<u8> {
        let ntlm_body = Ntlm {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&ntlm_body).unwrap()
    }

    pub(super) fn gen_kerberos_raw_event() -> Vec<u8> {
        let kerberos_body = Kerberos {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&kerberos_body).unwrap()
    }

    pub(super) fn gen_ssh_raw_event() -> Vec<u8> {
        let ssh_body = Ssh {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&ssh_body).unwrap()
    }

    pub(super) fn gen_dce_rpc_raw_event() -> Vec<u8> {
        let dce_rpc_body = DceRpc {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&dce_rpc_body).unwrap()
    }

    pub(super) fn gen_log_raw_event() -> Vec<u8> {
        let log_body = Log {
            kind: String::from("Hello"),
            log: base64_engine.decode("aGVsbG8gd29ybGQ=").unwrap(),
        };

        bincode::serialize(&log_body).unwrap()
    }

    pub(super) fn gen_periodic_time_series_raw_event() -> Vec<u8> {
        let periodic_time_series_body: PeriodicTimeSeries = PeriodicTimeSeries {
            id: String::from("policy_one"),
            data: vec![1.1, 2.2, 3.3, 4.4, 5.5, 6.6],
        };

        bincode::serialize(&periodic_time_series_body).unwrap()
    }

    pub(super) fn format_zeek_time(timestamp: i64) -> String {
        pub(super) const A_BILLION: i64 = 1_000_000_000;

        if timestamp > 0 {
            format!("{}.{:09}", timestamp / A_BILLION, timestamp % A_BILLION)
        } else {
            format!("{}.{:09}", timestamp / A_BILLION, -timestamp % A_BILLION)
        }
    }

    pub(super) fn validate_csv_payload_with_sensor<
        T: serde::de::DeserializeOwned + std::fmt::Display,
    >(
        payload: &[u8],
        sensor: &str,
        timestamp: i64,
        ser_body: &[u8],
    ) {
        let record = bincode::deserialize::<T>(ser_body).unwrap();
        let payload_str = std::str::from_utf8(payload).expect("payload must be utf-8");
        let mut parts = payload_str.splitn(3, '\t');
        let ts_part = parts.next().expect("missing timestamp");
        let sensor_part = parts.next().expect("missing sensor");
        let rest = parts.collect::<Vec<_>>().join("\t");

        assert_eq!(ts_part, format_zeek_time(timestamp), "timestamp mismatch");
        assert_eq!(sensor_part, sensor, "sensor mismatch");
        assert_eq!(rest, record.to_string(), "payload mismatch");
    }

    pub(super) fn validate_csv_payload_without_sensor<
        T: serde::de::DeserializeOwned + std::fmt::Display,
    >(
        payload: &[u8],
        _sensor: &str,
        timestamp: i64,
        ser_body: &[u8],
    ) {
        let record = bincode::deserialize::<T>(ser_body).unwrap();
        let payload_str = std::str::from_utf8(payload).expect("payload must be utf-8");
        let mut parts = payload_str.splitn(2, '\t');
        let ts_part = parts.next().expect("missing timestamp");
        let rest = parts.collect::<Vec<_>>().join("\t");

        assert_eq!(ts_part, format_zeek_time(timestamp), "timestamp mismatch");
        assert_eq!(rest, record.to_string(), "payload mismatch");
    }

    pub(super) fn validate_log_payload(
        payload: &[u8],
        _sensor: &str,
        _timestamp: i64,
        ser_body: &[u8],
    ) {
        let record = bincode::deserialize::<Log>(ser_body).unwrap();
        assert_eq!(payload, record.log.as_slice(), "log payload mismatch");
    }

    pub(super) fn gen_ftp_raw_event() -> Vec<u8> {
        let ftp_body = Ftp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&ftp_body).unwrap()
    }

    pub(super) fn gen_mqtt_raw_event() -> Vec<u8> {
        let mqtt_body = Mqtt {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&mqtt_body).unwrap()
    }

    pub(super) fn gen_ldap_raw_event() -> Vec<u8> {
        let ldap_body = Ldap {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&ldap_body).unwrap()
    }

    pub(super) fn gen_tls_raw_event() -> Vec<u8> {
        let tls_body = Tls {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&tls_body).unwrap()
    }

    pub(super) fn gen_smb_raw_event() -> Vec<u8> {
        let smb_body = Smb {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&smb_body).unwrap()
    }

    pub(super) fn gen_nfs_raw_event() -> Vec<u8> {
        let nfs_body = Nfs {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 1_000_000_000,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 100,
            resp_l2_bytes: 200,
            read_files: vec![],
            write_files: vec![],
        };

        bincode::serialize(&nfs_body).unwrap()
    }

    pub(super) fn gen_bootp_raw_event() -> Vec<u8> {
        let bootp_body = Bootp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&bootp_body).unwrap()
    }

    pub(super) fn gen_dhcp_raw_event() -> Vec<u8> {
        let dhcp_body = Dhcp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
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

        bincode::serialize(&dhcp_body).unwrap()
    }

    pub(super) fn gen_radius_raw_event() -> Vec<u8> {
        let radius_body = Radius {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 1812,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 1813,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 2_000_000_000,
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

        bincode::serialize(&radius_body).unwrap()
    }

    pub(super) fn insert_network_raw_event<T>(
        store: &RawEventStore<T>,
        sensor: &str,
        timestamp: i64,
        gen_fn: fn() -> Vec<u8>,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_fn();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn insert_conn_raw_event(
        store: &RawEventStore<Conn>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_conn_raw_event)
    }

    pub(super) fn insert_dns_raw_event(
        store: &RawEventStore<Dns>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_dns_raw_event)
    }

    pub(super) fn insert_malformed_dns_raw_event(
        store: &RawEventStore<MalformedDns>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_malformed_dns_raw_event)
    }

    pub(super) fn insert_rdp_raw_event(
        store: &RawEventStore<Rdp>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_rdp_raw_event)
    }

    pub(super) fn insert_http_raw_event(
        store: &RawEventStore<Http>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_http_raw_event)
    }

    pub(super) fn insert_smtp_raw_event(
        store: &RawEventStore<Smtp>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_smtp_raw_event)
    }

    pub(super) fn insert_ntlm_raw_event(
        store: &RawEventStore<Ntlm>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_ntlm_raw_event)
    }

    pub(super) fn insert_kerberos_raw_event(
        store: &RawEventStore<Kerberos>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_kerberos_raw_event)
    }

    pub(super) fn insert_ssh_raw_event(
        store: &RawEventStore<Ssh>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_ssh_raw_event)
    }

    pub(super) fn insert_dce_rpc_raw_event(
        store: &RawEventStore<DceRpc>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_dce_rpc_raw_event)
    }

    pub(super) fn insert_ftp_raw_event(
        store: &RawEventStore<Ftp>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_ftp_raw_event)
    }

    pub(super) fn insert_mqtt_raw_event(
        store: &RawEventStore<Mqtt>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_mqtt_raw_event)
    }

    pub(super) fn insert_ldap_raw_event(
        store: &RawEventStore<Ldap>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_ldap_raw_event)
    }

    pub(super) fn insert_tls_raw_event(
        store: &RawEventStore<Tls>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_tls_raw_event)
    }

    pub(super) fn insert_smb_raw_event(
        store: &RawEventStore<Smb>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_smb_raw_event)
    }

    pub(super) fn insert_nfs_raw_event(
        store: &RawEventStore<Nfs>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_nfs_raw_event)
    }

    pub(super) fn insert_bootp_raw_event(
        store: &RawEventStore<Bootp>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_bootp_raw_event)
    }

    pub(super) fn insert_dhcp_raw_event(
        store: &RawEventStore<Dhcp>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_dhcp_raw_event)
    }

    pub(super) fn insert_radius_raw_event(
        store: &RawEventStore<Radius>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        insert_network_raw_event(store, sensor, timestamp, gen_radius_raw_event)
    }

    pub(super) fn insert_log_raw_event(
        store: &RawEventStore<Log>,
        sensor: &str,
        kind: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, Some(kind), timestamp);
        let ser_log_body = gen_log_raw_event();
        store.append(&key, &ser_log_body).unwrap();
        ser_log_body
    }

    pub(super) fn insert_periodic_time_series_raw_event(
        store: &RawEventStore<PeriodicTimeSeries>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_periodic_time_series_body = gen_periodic_time_series_raw_event();
        store.append(&key, &ser_periodic_time_series_body).unwrap();
        ser_periodic_time_series_body
    }

    pub(super) fn gen_process_create_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_process_create_raw_event(
        store: &RawEventStore<ProcessCreate>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_process_create_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_file_create_time_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_file_create_time_raw_event(
        store: &RawEventStore<FileCreationTimeChanged>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_file_create_time_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_network_connect_raw_event() -> Vec<u8> {
        let body = NetworkConnection {
            agent_name: "agent".to_string(),
            process_guid: "guid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            user: "user".to_string(),
            protocol: "tcp".to_string(),
            initiated: true,
            source_is_ipv6: false,
            source_ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            source_hostname: "src".to_string(),
            source_port: 1234,
            source_port_name: "port".to_string(),
            destination_is_ipv6: false,
            destination_ip: "1.1.1.1".parse::<IpAddr>().unwrap(),
            destination_hostname: "dst".to_string(),
            destination_port: 80,
            destination_port_name: "http".to_string(),
            agent_id: "agent_id".to_string(),
        };
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_network_connect_raw_event(
        store: &RawEventStore<NetworkConnection>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_network_connect_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_process_terminate_raw_event() -> Vec<u8> {
        let body = ProcessTerminated {
            agent_name: "agent".to_string(),
            process_guid: "guid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            user: "user".to_string(),
            agent_id: "agent_id".to_string(),
        };
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_process_terminate_raw_event(
        store: &RawEventStore<ProcessTerminated>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_process_terminate_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_image_load_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_image_load_raw_event(
        store: &RawEventStore<ImageLoaded>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_image_load_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_file_create_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_file_create_raw_event(
        store: &RawEventStore<FileCreate>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_file_create_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_registry_value_set_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_registry_value_set_raw_event(
        store: &RawEventStore<RegistryValueSet>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_registry_value_set_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_registry_key_rename_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_registry_key_rename_raw_event(
        store: &RawEventStore<RegistryKeyValueRename>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_registry_key_rename_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_file_create_stream_hash_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_file_create_stream_hash_raw_event(
        store: &RawEventStore<FileCreateStreamHash>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_file_create_stream_hash_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_pipe_event_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_pipe_event_raw_event(
        store: &RawEventStore<PipeEvent>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_pipe_event_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_dns_query_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_dns_query_raw_event(
        store: &RawEventStore<DnsEvent>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_dns_query_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_file_delete_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_file_delete_raw_event(
        store: &RawEventStore<FileDelete>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_file_delete_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_process_tamper_raw_event() -> Vec<u8> {
        let body = ProcessTampering {
            agent_name: "agent".to_string(),
            process_guid: "guid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            tamper_type: "type".to_string(),
            user: "user".to_string(),
            agent_id: "agent_id".to_string(),
        };
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_process_tamper_raw_event(
        store: &RawEventStore<ProcessTampering>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_process_tamper_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_file_delete_detected_raw_event() -> Vec<u8> {
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_file_delete_detected_raw_event(
        store: &RawEventStore<FileDeleteDetected>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_file_delete_detected_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_netflow5_raw_event() -> Vec<u8> {
        let body = Netflow5 {
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            next_hop: "10.0.0.1".parse::<IpAddr>().unwrap(),
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
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_netflow5_raw_event(
        store: &RawEventStore<Netflow5>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_netflow5_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn gen_netflow9_raw_event() -> Vec<u8> {
        let body = Netflow9 {
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            orig_port: 1234,
            resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            contents: "payload".to_string(),
            sequence: 1,
            source_id: 1,
            template_id: 256,
        };
        bincode::serialize(&body).unwrap()
    }

    pub(super) fn insert_netflow9_raw_event(
        store: &RawEventStore<Netflow9>,
        sensor: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let key = gen_network_event_key(sensor, None, timestamp);
        let ser_body = gen_netflow9_raw_event();
        store.append(&key, &ser_body).unwrap();
        ser_body
    }

    pub(super) fn build_network_semi_supervised_request() -> RequestSemiSupervisedStream {
        RequestSemiSupervisedStream {
            start: 0,
            sensor: Some(vec![
                String::from(SENSOR_SEMI_SUPERVISED_ONE),
                String::from(SENSOR_SEMI_SUPERVISED_TWO),
            ]),
        }
    }

    pub(super) fn build_network_time_series_generator_request() -> RequestTimeSeriesGeneratorStream
    {
        RequestTimeSeriesGeneratorStream {
            start: 0,
            id: POLICY_ID.to_string(),
            src_ip: Some("192.168.4.76".parse::<IpAddr>().unwrap()),
            dst_ip: Some("31.3.245.133".parse::<IpAddr>().unwrap()),
            sensor: Some(String::from(SENSOR_TIME_SERIES_GENERATOR_THREE)),
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn build_network_stream_cases() -> Vec<NetworkStreamCase> {
        vec![
            NetworkStreamCase {
                record_type: RequestStreamRecord::Conn,
                kind: "conn",
                semi_payload: gen_conn_raw_event,
                direct_payload: gen_conn_raw_event,
                insert_db: insert_conn_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Dns,
                kind: "dns",
                semi_payload: gen_dns_raw_event,
                direct_payload: gen_dns_raw_event,
                insert_db: insert_dns_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Rdp,
                kind: "rdp",
                semi_payload: gen_rdp_raw_event,
                direct_payload: gen_rdp_raw_event,
                insert_db: insert_rdp_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Http,
                kind: "http",
                semi_payload: gen_http_raw_event,
                direct_payload: gen_http_raw_event,
                insert_db: insert_http_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Smtp,
                kind: "smtp",
                semi_payload: gen_smtp_raw_event,
                direct_payload: gen_smtp_raw_event,
                insert_db: insert_smtp_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Ntlm,
                kind: "ntlm",
                semi_payload: gen_ntlm_raw_event,
                direct_payload: gen_ntlm_raw_event,
                insert_db: insert_ntlm_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Kerberos,
                kind: "kerberos",
                semi_payload: gen_kerberos_raw_event,
                direct_payload: gen_kerberos_raw_event,
                insert_db: insert_kerberos_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Ssh,
                kind: "ssh",
                semi_payload: gen_ssh_raw_event,
                direct_payload: gen_ssh_raw_event,
                insert_db: insert_ssh_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::DceRpc,
                kind: "dce rpc",
                semi_payload: gen_dce_rpc_raw_event,
                direct_payload: gen_dce_rpc_raw_event,
                insert_db: insert_dce_rpc_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Ftp,
                kind: "ftp",
                semi_payload: gen_ftp_raw_event,
                direct_payload: gen_ftp_raw_event,
                insert_db: insert_ftp_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Mqtt,
                kind: "mqtt",
                semi_payload: gen_mqtt_raw_event,
                direct_payload: gen_mqtt_raw_event,
                insert_db: insert_mqtt_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Ldap,
                kind: "ldap",
                semi_payload: gen_ldap_raw_event,
                direct_payload: gen_ldap_raw_event,
                insert_db: insert_ldap_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Tls,
                kind: "tls",
                semi_payload: gen_tls_raw_event,
                direct_payload: gen_tls_raw_event,
                insert_db: insert_tls_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Smb,
                kind: "smb",
                semi_payload: gen_smb_raw_event,
                direct_payload: gen_smb_raw_event,
                insert_db: insert_smb_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Nfs,
                kind: "nfs",
                semi_payload: gen_nfs_raw_event,
                direct_payload: gen_nfs_raw_event,
                insert_db: insert_nfs_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Bootp,
                kind: "bootp",
                semi_payload: gen_bootp_raw_event,
                direct_payload: gen_bootp_raw_event,
                insert_db: insert_bootp_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Dhcp,
                kind: "dhcp",
                semi_payload: gen_dhcp_raw_event,
                direct_payload: gen_dhcp_raw_event,
                insert_db: insert_dhcp_stream,
            },
            NetworkStreamCase {
                record_type: RequestStreamRecord::Radius,
                kind: "radius",
                semi_payload: gen_radius_raw_event,
                direct_payload: gen_radius_raw_event,
                insert_db: insert_radius_stream,
            },
        ]
    }

    pub(super) fn build_streams_without_tsg() -> Vec<StreamsWithoutTsgCase> {
        vec![
            (
                RequestStreamRecord::MalformedDns,
                "malformed_dns",
                gen_malformed_dns_raw_event,
            ),
            (
                RequestStreamRecord::FileCreate,
                "file_create",
                gen_file_create_raw_event,
            ),
            (
                RequestStreamRecord::FileDelete,
                "file_delete",
                gen_file_delete_raw_event,
            ),
            (RequestStreamRecord::Log, "log", gen_log_raw_event),
        ]
    }

    pub(super) fn prepare_network_range_cases(db: &Database, sensor: &str) -> Vec<RangeCase> {
        NETWORK_RANGE_SPECS
            .iter()
            .map(|spec| {
                let send_time = next_timestamp();
                RangeCase {
                    kind: spec.kind,
                    expected_payload: (spec.build_expected)(db, sensor, send_time),
                    expected_done: done_bytes(),
                    min_data: 1,
                }
            })
            .collect()
    }

    pub(super) fn prepare_sysmon_range_cases(db: &Database, sensor: &str) -> Vec<RangeCase> {
        SYSMON_RANGE_SPECS
            .iter()
            .map(|spec| {
                let send_time = next_timestamp();
                RangeCase {
                    kind: spec.kind,
                    expected_payload: (spec.build_expected)(db, sensor, send_time),
                    expected_done: done_bytes(),
                    min_data: 1,
                }
            })
            .collect()
    }

    pub(super) fn prepare_netflow_range_cases(db: &Database, sensor: &str) -> Vec<RangeCase> {
        NETFLOW_RANGE_SPECS
            .iter()
            .map(|spec| {
                let send_time = next_timestamp();
                RangeCase {
                    kind: spec.kind,
                    expected_payload: (spec.build_expected)(db, sensor, send_time),
                    expected_done: done_bytes(),
                    min_data: 1,
                }
            })
            .collect()
    }

    pub(super) fn prepare_log_range_cases(
        db: &Database,
        sensor: &str,
        kind: &'static str,
    ) -> Vec<RangeCase> {
        let log_store = db.log_store().unwrap();
        let send_log_time = next_timestamp();
        let log_data = bincode::deserialize::<Log>(&insert_log_raw_event(
            &log_store,
            sensor,
            kind,
            send_log_time,
        ))
        .unwrap();

        vec![RangeCase {
            kind,
            expected_payload: log_data.response_data(send_log_time, sensor).unwrap(),
            expected_done: Conn::response_done().unwrap(),
            min_data: 1,
        }]
    }

    pub(super) fn prepare_periodic_time_series_range_cases(
        db: &Database,
        sensor: &str,
    ) -> Vec<RangeCase> {
        let time_series_store = db.periodic_time_series_store().unwrap();
        let send_time_series_time = next_timestamp();
        let time_series_data =
            bincode::deserialize::<PeriodicTimeSeries>(&insert_periodic_time_series_raw_event(
                &time_series_store,
                sensor,
                send_time_series_time,
            ))
            .unwrap();

        vec![RangeCase {
            kind: "timeseries",
            expected_payload: time_series_data
                .response_data(send_time_series_time, sensor)
                .unwrap(),
            expected_done: done_series(),
            min_data: 1,
        }]
    }

    pub(super) async fn setup_cluster_with_cases<T, F>(prepare_cases: F) -> ClusterContext<T>
    where
        F: FnOnce(&Database) -> Vec<T>,
    {
        init_crypto();
        let node2_dir = tempfile::tempdir().expect("create node2 temp dir");
        let node2_db = Database::open(node2_dir.path(), &DbOptions::default())
            .expect("open node2 test database");
        let node2_pcap_sensors = new_pcap_sensors();
        let node2_stream_direct_channels = new_stream_direct_channels();
        let node2_ingest_sensors = NODE2.build_ingest_sensors();
        let node2_certs = NODE2.build_certs();

        let prepared_cluster_cases = prepare_cases(&node2_db);

        let node2_peers = Arc::new(RwLock::new(HashMap::new()));
        let node2_peer_idents = Arc::new(RwLock::new(HashSet::new()));

        let (node2_addr, node2_handle) = spawn_server(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            node2_db,
            node2_pcap_sensors,
            node2_stream_direct_channels,
            node2_ingest_sensors,
            node2_peers.clone(),
            node2_peer_idents.clone(),
            node2_certs.clone(),
        )
        .await;

        let db_dir = tempfile::tempdir().expect("create node1 temp dir");
        let db =
            Database::open(db_dir.path(), &DbOptions::default()).expect("open node1 test database");
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = build_ingest_sensors();

        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));

        let certs = build_test_certs();

        let (node1_addr, node1_handle) = spawn_server(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            db.clone(),
            pcap_sensors,
            stream_direct_channels,
            ingest_sensors,
            peers.clone(),
            peer_idents.clone(),
            certs,
        )
        .await;

        {
            let mut node2_peers_guard = node2_peers.write().await;
            node2_peers_guard.insert(
                node1_addr.ip().to_string(),
                NODE1.peer_info_with_port(node1_addr.port()),
            );
        }
        {
            let mut node2_peer_idents_guard = node2_peer_idents.write().await;
            node2_peer_idents_guard.insert(NODE1.peer_identity_with_addr(node1_addr));
        }
        {
            let mut peers_guard = peers.write().await;
            peers_guard.insert(
                node2_addr.ip().to_string(),
                NODE2.peer_info_with_port(node2_addr.port()),
            );
        }
        {
            let mut peer_idents_guard = peer_idents.write().await;
            peer_idents_guard.insert(NODE2.peer_identity_with_addr(node2_addr));
        }

        let publish = TestClient::new(node1_addr, NODE1.host).await;

        ClusterContext {
            publish,
            cases: prepared_cluster_cases,
            server_handles: vec![node1_handle, node2_handle],
        }
    }

    pub(super) async fn request_range_data_on_cluster_network<F>(sensor: &str, prepare_cases: F)
    where
        F: FnOnce(&Database) -> Vec<RangeCase>,
    {
        let context = setup_cluster_with_cases(prepare_cases).await;
        let ClusterContext {
            publish,
            cases: range_cases,
            ..
        } = &context;

        assert_range_cases(publish, sensor, range_cases).await;
        context.shutdown().await;
    }

    pub(super) async fn request_range_data_on_cluster_series<F>(sensor: &str, prepare_cases: F)
    where
        F: FnOnce(&Database) -> Vec<RangeCase>,
    {
        let context = setup_cluster_with_cases(prepare_cases).await;
        let ClusterContext {
            publish,
            cases: range_cases,
            ..
        } = &context;

        assert_range_cases_series(publish, sensor, range_cases).await;
        context.shutdown().await;
    }
} // mod fixtures

use fixtures::*;
#[tokio::test]
async fn publish_server_run_accepts_connection_and_shutdown() {
    init_crypto();

    let temp_dir = tempfile::tempdir().expect("create publish temp dir");
    let db =
        Database::open(temp_dir.path(), &DbOptions::default()).expect("open publish test database");
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = build_ingest_sensors();
    let (peers, peer_idents) = new_peers_data(None);
    let certs = build_test_certs();
    let notify_shutdown = Arc::new(Notify::new());

    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
    let server = Server::new(server_addr, &certs);
    let (ready_tx, ready_rx) = oneshot::channel();

    let server_task = tokio::spawn(run_server_with_ready(
        server,
        db,
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        notify_shutdown.clone(),
        ready_tx,
    ));

    let server_addr = tokio::time::timeout(StdDuration::from_secs(2), ready_rx)
        .await
        .expect("publish server ready timeout")
        .expect("publish server did not report addr");

    let publish = TestClient::new(server_addr, NODE1.host).await;
    assert_eq!(publish.conn.remote_address().port(), server_addr.port());

    publish.close(b"publish_run_done").await;

    notify_shutdown.notify_waiters();
    let join_result = tokio::time::timeout(StdDuration::from_secs(2), server_task)
        .await
        .expect("publish server shutdown timeout");
    assert!(join_result.is_ok(), "publish server task failed");
}

#[tokio::test]
async fn request_range_data_with_network_kinds() {
    const SENSOR: &str = "ingest src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let cases = prepare_network_range_cases(&harness.db, SENSOR);
            assert_range_cases(&harness.publish, SENSOR, &cases).await;
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_with_log() {
    const SENSOR: &str = "src1";
    const KIND: &str = LOG_KIND;

    with_test_harness(|harness| {
        Box::pin(async move {
            let cases = prepare_log_range_cases(&harness.db, SENSOR, KIND);
            assert_range_cases(&harness.publish, SENSOR, &cases).await;
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_allows_empty_result() {
    const SENSOR: &str = "src1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let request = build_range_request(SENSOR, "conn");
            let result = send_range_request_and_collect::<Vec<u8>>(&harness.publish, request).await;

            assert_eq!(result, vec![None], "expected done-only response");
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_with_zero_count_returns_done_only() {
    const SENSOR: &str = "src1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let store = harness.db.conn_store().unwrap();

            let ts1 = next_timestamp();
            insert_conn_raw_event(&store, SENSOR, ts1);

            let mut request = build_range_request(SENSOR, "conn");
            request.start = ts1 - 1;
            request.end = ts1 + 1;
            request.count = 0;

            let result = send_range_request_and_collect::<Vec<u8>>(&harness.publish, request).await;

            assert_eq!(result, vec![None], "expected done-only response");
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_count_larger_than_results_returns_all_and_done() {
    const SENSOR: &str = "src1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let store = harness.db.conn_store().unwrap();

            let ts1 = next_timestamp();
            let ts2 = ts1 + 1;
            insert_conn_raw_event(&store, SENSOR, ts1);
            insert_conn_raw_event(&store, SENSOR, ts2);

            let mut request = build_range_request(SENSOR, "conn");
            request.start = ts1 - 1;
            request.end = ts2 + 1;
            request.count = 10;

            let result = send_range_request_and_collect::<Vec<u8>>(&harness.publish, request).await;

            let (done_message, data_messages) = result.split_last().expect("range response empty");
            assert!(done_message.is_none(), "missing done message");
            assert_eq!(data_messages.len(), 2, "expected all data messages");

            let mut timestamps: Vec<i64> = data_messages
                .iter()
                .map(|item| item.as_ref().expect("expected data message").0)
                .collect();
            timestamps.sort_unstable();
            assert_eq!(timestamps, vec![ts1, ts2]);
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_respects_count_limit() {
    const SENSOR: &str = "src1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let store = harness.db.conn_store().unwrap();

            let ts1 = next_timestamp();
            let ts2 = ts1 + 1;
            let ts3 = ts2 + 1;
            let ser_body_ts1 = insert_conn_raw_event(&store, SENSOR, ts1);
            insert_conn_raw_event(&store, SENSOR, ts2);
            insert_conn_raw_event(&store, SENSOR, ts3);

            let mut request = build_range_request(SENSOR, "conn");
            request.start = ts1 - 1;
            request.end = ts3 + 1;
            request.count = 1;

            let result = send_range_request_and_collect::<Vec<u8>>(&harness.publish, request).await;

            assert!(!result.is_empty(), "range response empty");
            let (done_message, data_messages) = result.split_last().expect("range response empty");
            assert!(done_message.is_none(), "missing done message");
            assert_eq!(data_messages.len(), 1, "expected exactly one data message");
            let (timestamp, sensor, payload) =
                data_messages[0].as_ref().expect("expected data message");
            assert_eq!(sensor, SENSOR);
            assert_eq!(*timestamp, ts1, "expected earliest timestamp");
            let conn = bincode::deserialize::<Conn>(&ser_body_ts1).unwrap();
            let expected_payload = bincode::deserialize::<Option<(i64, String, Vec<u8>)>>(
                &conn.response_data(ts1, SENSOR).unwrap(),
            )
            .unwrap()
            .expect("expected response payload")
            .2;
            assert_eq!(payload, &expected_payload, "unexpected payload");
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_with_inverted_time_range_returns_empty() {
    const SENSOR: &str = "src1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let store = harness.db.conn_store().unwrap();

            let ts1 = next_timestamp();
            insert_conn_raw_event(&store, SENSOR, ts1);

            let mut request = build_range_request(SENSOR, "conn");
            request.start = ts1 + 10;
            request.end = ts1 - 10;

            let result = send_range_request_and_collect::<Vec<u8>>(&harness.publish, request).await;

            assert_eq!(result, vec![None], "expected done-only response");
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_with_equal_start_end_returns_empty() {
    const SENSOR: &str = "src1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let store = harness.db.conn_store().unwrap();

            let ts1 = next_timestamp();
            insert_conn_raw_event(&store, SENSOR, ts1);

            let mut request = build_range_request(SENSOR, "conn");
            request.start = ts1;
            request.end = ts1;

            let result = send_range_request_and_collect::<Vec<u8>>(&harness.publish, request).await;

            assert_eq!(result, vec![None], "expected done-only response");
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_excludes_end_bound() {
    const SENSOR: &str = "src1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let store = harness.db.conn_store().unwrap();

            let ts1 = next_timestamp();
            let ts2 = ts1 + 1;
            let ser_body_ts1 = insert_conn_raw_event(&store, SENSOR, ts1);
            insert_conn_raw_event(&store, SENSOR, ts2);

            let mut request = build_range_request(SENSOR, "conn");
            request.start = ts1;
            request.end = ts2;
            request.count = 10;

            let result = harness
                .publish
                .send_range_request::<(i64, String, Vec<u8>)>(RANGE_MESSAGE_CODE, request)
                .await;

            let (done_message, data_messages) = result.split_last().expect("range response empty");
            assert!(done_message.is_none(), "missing done message");
            assert_eq!(data_messages.len(), 1, "expected single data message");
            let (timestamp, sensor, payload) =
                data_messages[0].as_ref().expect("expected data message");
            assert_eq!(sensor, SENSOR);
            assert_eq!(*timestamp, ts1, "end bound should be exclusive");
            let conn = bincode::deserialize::<Conn>(&ser_body_ts1).unwrap();
            let expected_payload = bincode::deserialize::<Option<(i64, String, Vec<u8>)>>(
                &conn.response_data(ts1, SENSOR).unwrap(),
            )
            .unwrap()
            .expect("expected response payload")
            .2;
            assert_eq!(payload, &expected_payload, "unexpected payload");
        })
    })
    .await;
}
#[tokio::test]
async fn request_range_data_fails_with_unknown_kind() {
    const SENSOR: &str = "src1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let request = build_range_request(SENSOR, "not-a-kind");
            let (mut send_pub_req, mut recv_pub_resp) = harness
                .publish
                .conn
                .open_bi()
                .await
                .expect("failed to open stream");
            send_range_data_request(&mut send_pub_req, RANGE_MESSAGE_CODE, request)
                .await
                .expect("failed to send range request");

            let err = tokio::time::timeout(
                StdDuration::from_secs(2),
                recv_ack_response(&mut recv_pub_resp),
            )
            .await
            .expect("range error response timeout")
            .expect_err("expected range request to fail");
            assert_eq!(
                err.to_string(),
                "Cannot serialize/deserialize a publish message"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_with_sysmon() {
    const SENSOR: &str = "ingest src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let cases = prepare_sysmon_range_cases(&harness.db, SENSOR);
            assert_range_cases(&harness.publish, SENSOR, &cases).await;
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_with_netflow() {
    const SENSOR: &str = "ingest src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let cases = prepare_netflow_range_cases(&harness.db, SENSOR);
            assert_range_cases(&harness.publish, SENSOR, &cases).await;
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_with_periodic_time_series() {
    const SAMPLING_POLICY_ID_AS_SENSOR: &str = "ingest src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let cases =
                prepare_periodic_time_series_range_cases(&harness.db, SAMPLING_POLICY_ID_AS_SENSOR);
            assert_range_cases_series(&harness.publish, SAMPLING_POLICY_ID_AS_SENSOR, &cases).await;
        })
    })
    .await;
}

#[tokio::test]
async fn request_streams_semi_supervised_and_time_series_generator() {
    with_test_harness(|harness| {
        Box::pin(async move {
            let db = &harness.db;
            let publish = &mut harness.publish;
            let stream_direct_channels = harness.stream_direct_channels.clone();

            let semi_supervised_msg = build_network_semi_supervised_request();
            let time_series_generator_msg = build_network_time_series_generator_request();

            for case in build_network_stream_cases() {
                assert_semi_supervised_stream(
                    publish,
                    case.record_type,
                    &semi_supervised_msg,
                    &stream_direct_channels,
                    case.kind,
                    &[SENSOR_SEMI_SUPERVISED_ONE, SENSOR_SEMI_SUPERVISED_TWO],
                    case.semi_payload,
                )
                .await;

                let db_timestamp = next_timestamp();
                let db_payload =
                    (case.insert_db)(db, SENSOR_TIME_SERIES_GENERATOR_THREE, db_timestamp);
                let direct_timestamp = next_timestamp();
                let direct_payload = (case.direct_payload)();

                assert_time_series_generator_stream(
                    publish,
                    case.record_type,
                    &time_series_generator_msg,
                    &stream_direct_channels,
                    case.kind,
                    SENSOR_TIME_SERIES_GENERATOR_THREE,
                    POLICY_ID,
                    db_timestamp,
                    db_payload,
                    direct_timestamp,
                    direct_payload,
                )
                .await;
            }

            for (record_type, kind, payload_fn) in build_streams_without_tsg() {
                assert_semi_supervised_stream(
                    publish,
                    record_type,
                    &semi_supervised_msg,
                    &stream_direct_channels,
                    kind,
                    &[SENSOR_SEMI_SUPERVISED_ONE],
                    payload_fn,
                )
                .await;
            }
        })
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_stream_time_series_generator_missing_sensor_logs_error() {
    with_log_capture(|log_capture| async move {
        with_test_harness(|harness| {
            Box::pin(async move {
                let request = RequestTimeSeriesGeneratorStream {
                    start: 0,
                    id: "p1".to_string(),
                    src_ip: None,
                    dst_ip: None,
                    sensor: None,
                };

                send_stream_request(
                    &mut harness.publish.send,
                    StreamRequestPayload::TimeSeriesGenerator {
                        record_type: RequestStreamRecord::Conn,
                        request,
                    },
                )
                .await
                .expect("sending time series generator stream request failed");

                let expected_log =
                    "Failed to generate the Time Series Generator channel key, sensor is required.";
                assert_log_contains(&log_capture, expected_log).await;
            })
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn stream_direct_channels_cleared_after_client_disconnect() {
    with_test_harness(|harness| {
        Box::pin(async move {
            let request = build_network_semi_supervised_request();
            send_stream_request(
                &mut harness.publish.send,
                StreamRequestPayload::SemiSupervised {
                    record_type: RequestStreamRecord::Conn,
                    request,
                },
            )
            .await
            .expect("sending semi-supervised stream request failed");

            let mut stream = harness.publish.conn.accept_uni().await.unwrap();
            let start_msg = receive_semi_supervised_stream_start_message(&mut stream)
                .await
                .unwrap();
            assert_eq!(start_msg, RequestStreamRecord::Conn);

            assert!(
                !harness.stream_direct_channels.read().await.is_empty(),
                "expected stream channels to be registered"
            );

            let _ = stream.stop(quinn::VarInt::from_u32(0));
            drop(stream);
            harness.publish.close(b"client_done").await;

            let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "conn");
            let payload = gen_conn_raw_event();
            send_direct_stream(
                &key,
                &payload,
                next_timestamp(),
                SENSOR_SEMI_SUPERVISED_ONE,
                harness.stream_direct_channels.clone(),
            )
            .await
            .expect("send_direct_stream failed");

            let deadline = Instant::now() + StdDuration::from_secs(1);
            loop {
                if harness.stream_direct_channels.read().await.is_empty() {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "stream channels not cleared after disconnect"
                );
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
    })
    .await;
}

#[tokio::test]
async fn request_raw_events() {
    const SENSOR: &str = "src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let cases = network_raw_event_cases();
            assert_raw_event_cases(&harness.publish, &harness.db, SENSOR, &cases).await;
        })
    })
    .await;
}

#[tokio::test]
async fn request_raw_events_sysmon() {
    const SENSOR: &str = "src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let cases = sysmon_raw_event_cases();
            assert_raw_event_cases(&harness.publish, &harness.db, SENSOR, &cases).await;
        })
    })
    .await;
}

#[tokio::test]
async fn request_raw_events_netflow() {
    const SENSOR: &str = "src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let cases = netflow_raw_event_cases();
            assert_raw_event_cases(&harness.publish, &harness.db, SENSOR, &cases).await;
        })
    })
    .await;
}

#[tokio::test]
async fn request_raw_events_with_unknown_kind_falls_back_to_log() {
    const SENSOR: &str = "src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let timestamp = next_timestamp();
            let ser_body = insert_log_raw_event_case(&harness.db, SENSOR, timestamp);
            let expected = build_log_raw_expected(&ser_body, timestamp, SENSOR);

            let mut result_data =
                fetch_raw_data(&harness.publish, "not-a-kind", SENSOR, timestamp).await;

            assert_eq!(result_data.len(), 1, "unexpected raw data count");
            assert_eq!(result_data[0].0, timestamp);
            assert_eq!(&result_data[0].1, SENSOR);
            validate_log_payload(&result_data[0].2, SENSOR, timestamp, &ser_body);
            assert_eq!(
                expected,
                bincode::serialize(&Some(result_data.pop().unwrap())).unwrap()
            );
        })
    })
    .await;
}

#[tokio::test]
async fn request_raw_events_log() {
    const SENSOR: &str = "src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let case = log_raw_event_case();
            let (timestamp, expected, ser_body) = prepare_raw_event(&harness.db, SENSOR, &case);

            let mut result_data =
                fetch_raw_data(&harness.publish, case.kind, SENSOR, timestamp).await;

            assert_eq!(result_data.len(), 1, "Failed for kind: {}", case.kind);
            assert_eq!(result_data[0].0, timestamp);
            assert_eq!(&result_data[0].1, SENSOR);
            if let Some(validator) = case.validate_payload {
                validator(&result_data[0].2, SENSOR, timestamp, &ser_body);
            }
            assert_eq!(
                expected,
                bincode::serialize(&Some(result_data.pop().unwrap())).unwrap()
            );
        })
    })
    .await;
}

#[tokio::test]
async fn request_raw_events_periodic_time_series() {
    const SENSOR: &str = "src 1";

    with_test_harness(|harness| {
        Box::pin(async move {
            let case = periodic_time_series_raw_event_case();
            let (timestamp, expected, _ser_body) = prepare_raw_event(&harness.db, SENSOR, &case);

            let mut result_data = fetch_raw_data_with_payload::<Vec<f64>>(
                &harness.publish,
                case.kind,
                SENSOR,
                timestamp,
            )
            .await;

            assert_eq!(result_data.len(), 1, "Failed for kind: {}", case.kind);
            assert_eq!(result_data[0].0, timestamp);
            assert_eq!(&result_data[0].1, SENSOR);
            assert_eq!(
                expected,
                bincode::serialize(&Some(result_data.pop().unwrap())).unwrap()
            );
        })
    })
    .await;
}

#[tokio::test]
async fn request_range_data_with_network_kinds_giganto_cluster() {
    const SENSOR: &str = "ingest src 2";

    request_range_data_on_cluster_network(SENSOR, |db| prepare_network_range_cases(db, SENSOR))
        .await;
}

#[tokio::test]
async fn request_range_data_with_periodic_time_series_giganto_cluster() {
    const SAMPLING_POLICY_ID_AS_SENSOR: &str = "ingest src 2";

    request_range_data_on_cluster_series(SAMPLING_POLICY_ID_AS_SENSOR, |db| {
        prepare_periodic_time_series_range_cases(db, SAMPLING_POLICY_ID_AS_SENSOR)
    })
    .await;
}

#[tokio::test]
async fn request_raw_events_giganto_cluster() {
    const SENSOR: &str = "src 2";

    let mut context = setup_cluster_with_cases(|node2_db| {
        let cases = cluster_raw_event_cases();
        cases
            .iter()
            .map(|case| {
                let (timestamp, expected, _ser_body) = prepare_raw_event(node2_db, SENSOR, case);
                RawEventClusterCase {
                    kind: case.kind,
                    timestamp,
                    expected,
                }
            })
            .collect()
    })
    .await;
    let publish = &context.publish;
    let prepared_cases = std::mem::take(&mut context.cases);

    for RawEventClusterCase {
        kind,
        timestamp,
        expected,
    } in prepared_cases
    {
        if kind == "timeseries" {
            let mut result_data =
                fetch_raw_data_with_payload::<Vec<f64>>(publish, kind, SENSOR, timestamp).await;

            assert_eq!(result_data.len(), 1, "Failed for kind: {kind}");
            assert_eq!(result_data[0].0, timestamp);
            assert_eq!(&result_data[0].1, SENSOR);
            assert_eq!(
                expected,
                bincode::serialize(&Some(result_data.pop().unwrap())).unwrap()
            );
        } else {
            let mut result_data = fetch_raw_data(publish, kind, SENSOR, timestamp).await;

            assert_eq!(result_data.len(), 1, "Failed for kind: {kind}");
            assert_eq!(result_data[0].0, timestamp);
            assert_eq!(&result_data[0].1, SENSOR);
            assert_eq!(
                expected,
                bincode::serialize(&Some(result_data.pop().unwrap())).unwrap()
            );
        }
    }

    publish.close(b"publish_raw_events_done").await;
    context.shutdown().await;
}

#[tokio::test]
async fn process_raw_events_errors_when_peer_handshake_fails() {
    init_crypto();
    const SENSOR: &str = "raw_peer_handshake_fail";

    let temp_dir = tempfile::tempdir().unwrap();
    let db = Database::open(temp_dir.path(), &DbOptions::default()).unwrap();
    let store = db.conn_store().unwrap();

    let peer_certs = NODE2.build_certs();
    let peer_server = setup_peer_handshake_mismatch_server(peer_certs, ">=99.0.0").await;

    let ingest_sensors = build_ingest_sensors_from_list(&[]);
    let peers = build_peers_for_sensor(SENSOR, peer_server.addr);
    let peer_idents = build_peer_idents(peer_server.addr, NODE2.host);
    let certs = build_test_certs();

    let (mut send, _client_conn) = open_range_stream("raw.peer.handshake").await;

    let request = RequestRawData {
        kind: "conn".to_string(),
        input: vec![(SENSOR.to_string(), vec![next_timestamp()])],
    };

    let err = super::process_raw_events::<Conn, u8>(
        &mut send,
        store,
        request,
        ingest_sensors,
        peers,
        peer_idents,
        &certs,
    )
    .await
    .expect_err("process_raw_events should fail when peer handshake fails");
    assert_eq!(err.to_string(), "Cannot receive a message");
}

#[tokio::test]
async fn process_raw_events_errors_when_peer_name_missing() {
    init_crypto();
    const SENSOR: &str = "raw_peer_missing_ident";

    let temp_dir = tempfile::tempdir().unwrap();
    let db = Database::open(temp_dir.path(), &DbOptions::default()).unwrap();
    let store = db.conn_store().unwrap();

    let peer_certs = NODE2.build_certs();
    let peer_server = setup_peer_pcap_server(peer_certs).await;

    let ingest_sensors = build_ingest_sensors_from_list(&[]);
    let peers = build_peers_for_sensor(SENSOR, peer_server.addr);
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));
    let certs = build_test_certs();

    let (mut send, _client_conn) = open_range_stream("raw.peer.missing_ident").await;

    let request = RequestRawData {
        kind: "conn".to_string(),
        input: vec![(SENSOR.to_string(), vec![next_timestamp()])],
    };

    let err = super::process_raw_events::<Conn, u8>(
        &mut send,
        store,
        request,
        ingest_sensors,
        peers,
        peer_idents,
        &certs,
    )
    .await
    .expect_err("process_raw_events should fail when peer name is missing");
    assert_eq!(
        err.to_string(),
        "Peer giganto's server name cannot be identitified"
    );
}

#[tokio::test]
async fn request_pcap_extract() {
    const SENSOR: &str = "pcap_sensor_1";

    let PcapFixture {
        harness,
        mut filter_rx,
        _sensor_server_endpoint,
        _sensor_client_endpoint,
    } = setup_pcap_fixture(SENSOR).await;
    let publish = &harness.publish;

    let filter = build_filter_for_sensor(SENSOR, 12345, 13345);

    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");
    send_range_data_request(&mut send_pub_req, MessageCode::Pcap, vec![filter.clone()])
        .await
        .unwrap();
    recv_ack_response(&mut recv_pub_resp).await.unwrap();

    let received_filter =
        recv_with_timeout(&mut filter_rx, "pcap sensor", StdDuration::from_secs(15)).await;

    assert_filter_matches(&received_filter, &filter);

    publish.close(b"pcap_extract_done").await;
    harness.shutdown().await;
}

#[tokio::test]
async fn request_pcap_extract_via_stream_request() {
    const SENSOR: &str = "pcap_stream_sensor";

    let PcapFixture {
        mut harness,
        mut filter_rx,
        _sensor_server_endpoint,
        _sensor_client_endpoint,
    } = setup_pcap_fixture(SENSOR).await;
    let publish = &mut harness.publish;

    let filter = build_filter_for_sensor(SENSOR, 321, 654);

    send_stream_request(
        &mut publish.send,
        StreamRequestPayload::PcapExtraction {
            filter: vec![filter.clone()],
        },
    )
    .await
    .expect("sending pcap extraction stream request failed");

    let received_filter =
        recv_with_timeout(&mut filter_rx, "pcap sensor", StdDuration::from_secs(5)).await;

    assert_filter_matches(&received_filter, &filter);

    publish.close(b"pcap_extract_stream_done").await;
    harness.shutdown().await;
}

#[tokio::test]
async fn peer_in_charge_publish_addr_returns_peer() {
    let peers = Arc::new(RwLock::new(HashMap::from([(
        "10.0.0.2".to_string(),
        PeerInfo {
            ingest_sensors: HashSet::from(["sensor_a".to_string()]),
            graphql_port: None,
            publish_port: Some(61000),
        },
    )])));

    let addr = super::peer_in_charge_publish_addr(peers, "sensor_a").await;
    assert_eq!(
        addr,
        Some(SocketAddr::new(
            "10.0.0.2".parse::<IpAddr>().unwrap(),
            61000
        ))
    );
}

#[tokio::test]
async fn peer_in_charge_publish_addr_returns_none_without_match() {
    let peers = Arc::new(RwLock::new(HashMap::from([(
        "10.0.0.3".to_string(),
        PeerInfo {
            ingest_sensors: HashSet::from(["other_sensor".to_string()]),
            graphql_port: None,
            publish_port: Some(62000),
        },
    )])));

    let addr_missing_sensor = super::peer_in_charge_publish_addr(peers.clone(), "unknown").await;
    assert!(addr_missing_sensor.is_none());
}

#[tokio::test]
async fn process_range_data_sends_local_results_and_done() {
    init_crypto();
    const SENSOR: &str = "range_local_sensor";

    let temp_dir = tempfile::tempdir().unwrap();
    let db = Database::open(temp_dir.path(), &DbOptions::default()).unwrap();
    let store = db.conn_store().unwrap();

    let ts1 = next_timestamp();
    let ts2 = ts1 + 1;
    insert_conn_raw_event(&store, SENSOR, ts1);
    insert_conn_raw_event(&store, SENSOR, ts2);

    let request = RequestRange {
        sensor: SENSOR.to_string(),
        kind: "conn".to_string(),
        start: ts1 - 1,
        end: ts2 + 1,
        count: 5,
    };

    let ingest_sensors = build_ingest_sensors_from_list(&[SENSOR]);
    let peers = Arc::new(RwLock::new(HashMap::new()));
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));
    let certs = build_test_certs();

    let (mut send, client_conn) = open_range_stream("range.local").await;
    super::process_range_data::<Conn, u8>(
        &mut send,
        store,
        request,
        ingest_sensors,
        peers,
        peer_idents,
        &certs,
        false,
    )
    .await
    .expect("process_range_data failed");

    let mut recv = client_conn.accept_uni().await.expect("range client uni");
    let responses = collect_range_data(&mut recv).await;
    assert!(responses.last().unwrap().is_none(), "missing done message");

    let mut timestamps = HashSet::new();
    for (timestamp, sensor, payload) in responses.into_iter().flatten() {
        assert_eq!(sensor, SENSOR);
        assert!(!payload.is_empty());
        timestamps.insert(timestamp);
    }

    assert!(timestamps.contains(&ts1));
    assert!(timestamps.contains(&ts2));
}

#[tokio::test]
async fn process_range_data_prefers_local_over_peer() {
    init_crypto();
    const SENSOR: &str = "range_local_preferred";

    let temp_dir = tempfile::tempdir().unwrap();
    let db = Database::open(temp_dir.path(), &DbOptions::default()).unwrap();
    let store = db.conn_store().unwrap();

    let ts_local = next_timestamp();
    insert_conn_raw_event(&store, SENSOR, ts_local);

    let ts_peer = ts_local + 1;
    let conn = bincode::deserialize::<Conn>(&gen_conn_raw_event()).unwrap();
    let peer_certs = NODE2.build_certs();
    let peer_server =
        setup_peer_range_server(&peer_certs, vec![(ts_peer, SENSOR.to_string(), conn)]);

    let ingest_sensors = build_ingest_sensors_from_list(&[SENSOR]);
    let peers = build_peers_for_sensor(SENSOR, peer_server.addr);
    let peer_idents = build_peer_idents(peer_server.addr, NODE2.host);
    let certs = build_test_certs();

    let request = RequestRange {
        sensor: SENSOR.to_string(),
        kind: "conn".to_string(),
        start: ts_local - 1,
        end: ts_peer + 1,
        count: 5,
    };

    let (mut send, client_conn) = open_range_stream("range.local.preferred").await;
    super::process_range_data::<Conn, u8>(
        &mut send,
        store,
        request,
        ingest_sensors,
        peers,
        peer_idents,
        &certs,
        false,
    )
    .await
    .expect("process_range_data failed");

    let mut recv = client_conn.accept_uni().await.expect("range client uni");
    let responses = collect_range_data(&mut recv).await;
    assert!(responses.last().unwrap().is_none(), "missing done message");

    let timestamps: HashSet<i64> = responses
        .into_iter()
        .flatten()
        .map(|(ts, _, _)| ts)
        .collect();
    assert!(timestamps.contains(&ts_local), "local data missing");
    assert!(
        !timestamps.contains(&ts_peer),
        "peer data should not be included"
    );
}

#[tokio::test]
async fn process_range_data_forwards_peer_results() {
    init_crypto();
    const SENSOR: &str = "range_peer_sensor";

    let temp_dir = tempfile::tempdir().unwrap();
    let db = Database::open(temp_dir.path(), &DbOptions::default()).unwrap();
    let store = db.conn_store().unwrap();

    let ts1 = next_timestamp();
    let ser_body = gen_conn_raw_event();
    let conn = bincode::deserialize::<Conn>(&ser_body).unwrap();
    let expected_payload = bincode::deserialize::<Option<(i64, String, Vec<u8>)>>(
        &conn.response_data(ts1, SENSOR).unwrap(),
    )
    .unwrap()
    .expect("expected response payload")
    .2;

    let peer_certs = NODE2.build_certs();
    let peer_server = setup_peer_range_server(&peer_certs, vec![(ts1, SENSOR.to_string(), conn)]);

    let ingest_sensors = build_ingest_sensors_from_list(&[]);
    let peers = build_peers_for_sensor(SENSOR, peer_server.addr);
    let peer_idents = build_peer_idents(peer_server.addr, NODE2.host);
    let certs = build_test_certs();

    let request = RequestRange {
        sensor: SENSOR.to_string(),
        kind: "conn".to_string(),
        start: ts1 - 1,
        end: ts1 + 1,
        count: 5,
    };

    let (mut send, client_conn) = open_range_stream("range.peer").await;
    super::process_range_data::<Conn, u8>(
        &mut send,
        store,
        request,
        ingest_sensors,
        peers,
        peer_idents,
        &certs,
        false,
    )
    .await
    .expect("process_range_data failed");

    let mut recv = client_conn.accept_uni().await.expect("range client uni");
    let responses = collect_range_data(&mut recv).await;
    assert!(responses.last().unwrap().is_none(), "missing done message");
    let data_messages: Vec<_> = responses.into_iter().flatten().collect();
    assert_eq!(data_messages.len(), 1, "expected single peer response");
    let (timestamp, sensor, payload) = &data_messages[0];
    assert_eq!(sensor, SENSOR);
    assert_eq!(*timestamp, ts1);
    assert_eq!(payload, &expected_payload, "unexpected peer payload");
}

#[tokio::test]
async fn process_range_data_errors_when_peer_done_missing() {
    init_crypto();
    const SENSOR: &str = "range_peer_missing_done";

    let temp_dir = tempfile::tempdir().unwrap();
    let db = Database::open(temp_dir.path(), &DbOptions::default()).unwrap();
    let store = db.conn_store().unwrap();

    let ts1 = next_timestamp();
    let conn = bincode::deserialize::<Conn>(&gen_conn_raw_event()).unwrap();

    let peer_certs = NODE2.build_certs();
    let peer_server =
        setup_peer_range_server_without_done(&peer_certs, vec![(ts1, SENSOR.to_string(), conn)]);

    let ingest_sensors = build_ingest_sensors_from_list(&[]);
    let peers = build_peers_for_sensor(SENSOR, peer_server.addr);
    let peer_idents = build_peer_idents(peer_server.addr, NODE2.host);
    let certs = build_test_certs();

    let request = RequestRange {
        sensor: SENSOR.to_string(),
        kind: "conn".to_string(),
        start: ts1 - 1,
        end: ts1 + 1,
        count: 5,
    };

    let (mut send, _client_conn) = open_range_stream("range.peer.missing_done").await;
    let err = super::process_range_data::<Conn, u8>(
        &mut send,
        store,
        request,
        ingest_sensors,
        peers,
        peer_idents,
        &certs,
        false,
    )
    .await
    .expect_err("process_range_data should fail when peer omits done");
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Connection closed by peer") || err_msg.contains("Failed to write"),
        "unexpected error: {err_msg}"
    );
}

#[tokio::test]
async fn process_range_data_returns_error_without_owner() {
    init_crypto();
    const SENSOR: &str = "range_orphan";

    let temp_dir = tempfile::tempdir().unwrap();
    let db = Database::open(temp_dir.path(), &DbOptions::default()).unwrap();
    let store = db.conn_store().unwrap();

    let request = RequestRange {
        sensor: SENSOR.to_string(),
        kind: "conn".to_string(),
        start: 0,
        end: 1,
        count: 5,
    };

    let ingest_sensors = build_ingest_sensors_from_list(&[]);
    let peers = Arc::new(RwLock::new(HashMap::new()));
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));
    let certs = build_test_certs();

    let (mut send, _client_conn) = open_range_stream("range.orphan").await;
    let err = super::process_range_data::<Conn, u8>(
        &mut send,
        store,
        request,
        ingest_sensors,
        peers,
        peer_idents,
        &certs,
        false,
    )
    .await
    .expect_err("process_range_data should fail without owner");

    assert_eq!(
        err.to_string(),
        format!("Neither current nor peer gigantos are in charge of requested sensor {SENSOR}")
    );
}

#[tokio::test]
async fn process_pcap_extract_filters_sends_to_local_sensor() {
    init_crypto();
    const SENSOR: &str = "pcap_local";
    let filter = build_filter_for_sensor(SENSOR, 11111, 22222);

    let (pcap_sensors, mut filter_rx) = setup_local_pcap_sensor(SENSOR).await;
    let peers = Arc::new(RwLock::new(HashMap::new()));
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));

    let received_filter = run_pcap_filters_and_recv_single(
        vec![filter.clone()],
        pcap_sensors,
        peers,
        peer_idents,
        &mut filter_rx,
        "pcap sensor",
        StdDuration::from_secs(5),
    )
    .await;
    assert_filter_matches(&received_filter, &filter);
}

#[tokio::test]
async fn process_pcap_extract_filters_handles_multiple_filters() {
    init_crypto();
    const SENSOR: &str = "pcap_multi";
    let filter_one = build_filter_for_sensor(SENSOR, 1, 2);
    let filter_two = build_filter_for_sensor(SENSOR, 3, 4);

    let (pcap_sensors, mut filter_rx) = setup_local_pcap_sensor(SENSOR).await;
    let peers = Arc::new(RwLock::new(HashMap::new()));
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));

    run_process_pcap_extract_filters(
        vec![filter_one.clone(), filter_two.clone()],
        pcap_sensors,
        peers,
        peer_idents,
    )
    .await;

    let recv_one = recv_with_timeout(
        &mut filter_rx,
        "first pcap sensor message",
        StdDuration::from_secs(5),
    )
    .await;
    let recv_two = recv_with_timeout(
        &mut filter_rx,
        "second pcap sensor message",
        StdDuration::from_secs(5),
    )
    .await;

    let mut received = [recv_one, recv_two];
    received.sort_by_key(|f| f.start_time);
    assert_eq!(received[0].start_time, filter_one.start_time);
    assert_eq!(received[1].start_time, filter_two.start_time);
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_continues_after_failure() {
    init_crypto();
    const SENSOR_FAIL: &str = "pcap_peer_fail";
    const SENSOR_OK: &str = "pcap_local_ok";

    let filter_fail = build_filter_for_sensor(SENSOR_FAIL, 11, 12);
    let filter_ok = build_filter_for_sensor(SENSOR_OK, 21, 22);

    let (pcap_sensors, mut filter_rx) = setup_local_pcap_sensor(SENSOR_OK).await;

    let peer_certs = NODE2.build_certs();
    let PeerHandshakeServer {
        addr: peer_addr, ..
    } = setup_peer_handshake_mismatch_server(peer_certs, ">=99.0.0").await;

    let peers = build_peers_for_sensor(SENSOR_FAIL, peer_addr);
    let peer_idents = build_peer_idents(peer_addr, NODE2.host);

    let received_filter = run_pcap_filters_and_recv_single(
        vec![filter_fail, filter_ok.clone()],
        pcap_sensors,
        peers,
        peer_idents,
        &mut filter_rx,
        "pcap sensor",
        StdDuration::from_secs(5),
    )
    .await;
    assert_filter_matches(&received_filter, &filter_ok);
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_continues_after_peer_partial_failure() {
    init_crypto();
    const SENSOR_FAIL: &str = "pcap_peer_fail_partial";
    const SENSOR_OK: &str = "pcap_peer_ok_partial";

    let filter_fail = build_filter_for_sensor(SENSOR_FAIL, 31, 32);
    let filter_ok = build_filter_for_sensor(SENSOR_OK, 41, 42);

    let peer_certs_fail = NODE2.build_certs();
    let PeerHandshakeServer {
        addr: peer_fail_addr,
        ..
    } = setup_peer_handshake_mismatch_server(peer_certs_fail, ">=99.0.0").await;

    let peer_certs_ok = NODE2.build_certs();
    let PeerPcapServer {
        addr: peer_ok_addr,
        filter_rx: mut peer_ok_rx,
        ..
    } = setup_peer_pcap_server(peer_certs_ok).await;

    let peers = Arc::new(RwLock::new(HashMap::from([
        (
            peer_fail_addr.ip().to_string(),
            PeerInfo {
                ingest_sensors: HashSet::from([SENSOR_FAIL.to_string()]),
                graphql_port: None,
                publish_port: Some(peer_fail_addr.port()),
            },
        ),
        (
            peer_ok_addr.ip().to_string(),
            PeerInfo {
                ingest_sensors: HashSet::from([SENSOR_OK.to_string()]),
                graphql_port: None,
                publish_port: Some(peer_ok_addr.port()),
            },
        ),
    ])));

    let peer_idents = Arc::new(RwLock::new(HashSet::from([
        PeerIdentity {
            addr: peer_fail_addr,
            hostname: NODE2.host.to_string(),
        },
        PeerIdentity {
            addr: peer_ok_addr,
            hostname: NODE2.host.to_string(),
        },
    ])));

    let pcap_sensors = new_pcap_sensors();
    let received_filter = run_pcap_filters_and_recv_single(
        vec![filter_fail, filter_ok.clone()],
        pcap_sensors,
        peers,
        peer_idents,
        &mut peer_ok_rx,
        "peer ok pcap request",
        StdDuration::from_secs(5),
    )
    .await;
    assert_filter_matches(&received_filter, &filter_ok);
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_local_failure_then_next_peer_filter_succeeds() {
    init_crypto();
    const SENSOR_FAIL: &str = "pcap_local_fail";
    const SENSOR_OK: &str = "pcap_peer_ok_after_local_fail";

    let filter_fail = build_filter_for_sensor(SENSOR_FAIL, 51, 52);
    let filter_ok = build_filter_for_sensor(SENSOR_OK, 61, 62);

    let (sensor_conn, _filter_rx, _sensor_server_endpoint, _sensor_client_endpoint) =
        setup_pcap_sensor_connection(NODE1.host).await;
    sensor_conn.close(0_u32.into(), b"closed");

    let peer_certs_ok = NODE2.build_certs();
    let PeerPcapServer {
        addr: peer_ok_addr,
        filter_rx: mut peer_ok_rx,
        ..
    } = setup_peer_pcap_server(peer_certs_ok).await;

    let pcap_sensors = new_pcap_sensors();
    pcap_sensors
        .write()
        .await
        .insert(SENSOR_FAIL.to_string(), vec![sensor_conn]);

    let peers = build_peers_for_sensor(SENSOR_OK, peer_ok_addr);
    let peer_idents = build_peer_idents(peer_ok_addr, NODE2.host);

    let received_filter = run_pcap_filters_and_recv_single(
        vec![filter_fail, filter_ok.clone()],
        pcap_sensors,
        peers,
        peer_idents,
        &mut peer_ok_rx,
        "peer ok pcap request",
        StdDuration::from_secs(5),
    )
    .await;
    assert_filter_matches(&received_filter, &filter_ok);
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_local_failure_does_not_fallback_to_peer() {
    init_crypto();
    const SENSOR: &str = "pcap_local_fail_no_fallback";

    let filter = build_filter_for_sensor(SENSOR, 131, 132);

    let (sensor_conn, _filter_rx, _sensor_server_endpoint, _sensor_client_endpoint) =
        setup_pcap_sensor_connection(NODE1.host).await;
    sensor_conn.close(0_u32.into(), b"closed");

    let peer_certs = NODE2.build_certs();
    let PeerPcapServer {
        addr: peer_addr,
        connection_rx,
        ..
    } = setup_peer_pcap_server(peer_certs).await;

    let pcap_sensors = new_pcap_sensors();
    pcap_sensors
        .write()
        .await
        .insert(SENSOR.to_string(), vec![sensor_conn]);

    let peers = build_peers_for_sensor(SENSOR, peer_addr);
    let peer_idents = build_peer_idents(peer_addr, NODE2.host);

    run_process_pcap_extract_filters(vec![filter], pcap_sensors, peers, peer_idents).await;

    assert_no_peer_connection(connection_rx).await;
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_peer_ack_failure_then_local_success() {
    init_crypto();
    const SENSOR_FAIL: &str = "pcap_peer_ack_fail_then_local";
    const SENSOR_OK: &str = "pcap_local_ok_after_ack";

    let filter_fail = build_filter_for_sensor(SENSOR_FAIL, 71, 72);
    let filter_ok = build_filter_for_sensor(SENSOR_OK, 81, 82);

    let (pcap_sensors, mut local_rx) = setup_local_pcap_sensor(SENSOR_OK).await;

    let peer_certs = NODE2.build_certs();
    let PeerPcapServer {
        addr: peer_addr,
        filter_rx: mut _peer_rx,
        ..
    } = setup_peer_pcap_server_with_ack(peer_certs, Some("ack_failed")).await;

    let peers = build_peers_for_sensor(SENSOR_FAIL, peer_addr);
    let peer_idents = build_peer_idents(peer_addr, NODE2.host);

    let received_filter = run_pcap_filters_and_recv_single(
        vec![filter_fail, filter_ok.clone()],
        pcap_sensors,
        peers,
        peer_idents,
        &mut local_rx,
        "local pcap sensor",
        StdDuration::from_secs(5),
    )
    .await;
    assert_filter_matches(&received_filter, &filter_ok);
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_peer_name_missing_then_local_success() {
    init_crypto();
    const SENSOR_FAIL: &str = "pcap_peer_missing_ident_then_local";
    const SENSOR_OK: &str = "pcap_local_ok_after_missing_ident";

    let filter_fail = build_filter_for_sensor(SENSOR_FAIL, 91, 92);
    let filter_ok = build_filter_for_sensor(SENSOR_OK, 101, 102);

    let (pcap_sensors, mut local_rx) = setup_local_pcap_sensor(SENSOR_OK).await;

    let peer_certs = NODE2.build_certs();
    let PeerPcapServer {
        addr: peer_addr, ..
    } = setup_peer_pcap_server(peer_certs).await;

    let peers = build_peers_for_sensor(SENSOR_FAIL, peer_addr);
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));

    let received_filter = run_pcap_filters_and_recv_single(
        vec![filter_fail, filter_ok.clone()],
        pcap_sensors,
        peers,
        peer_idents,
        &mut local_rx,
        "local pcap sensor",
        StdDuration::from_secs(5),
    )
    .await;
    assert_filter_matches(&received_filter, &filter_ok);
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_orphan_then_local_success() {
    init_crypto();
    const SENSOR_FAIL: &str = "pcap_orphan_then_local";
    const SENSOR_OK: &str = "pcap_local_ok_after_orphan";

    let filter_fail = build_filter_for_sensor(SENSOR_FAIL, 111, 112);
    let filter_ok = build_filter_for_sensor(SENSOR_OK, 121, 122);

    let (pcap_sensors, mut local_rx) = setup_local_pcap_sensor(SENSOR_OK).await;

    let peers = Arc::new(RwLock::new(HashMap::new()));
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));

    let received_filter = run_pcap_filters_and_recv_single(
        vec![filter_fail, filter_ok.clone()],
        pcap_sensors,
        peers,
        peer_idents,
        &mut local_rx,
        "local pcap sensor",
        StdDuration::from_secs(5),
    )
    .await;
    assert_filter_matches(&received_filter, &filter_ok);
}

#[tokio::test]
async fn process_pcap_extract_filters_sends_to_peer_when_no_local_sensor() {
    init_crypto();
    const SENSOR: &str = "pcap_peer";
    let filter = build_filter_for_sensor(SENSOR, 10, 20);

    let peer_certs = NODE2.build_certs();
    let PeerPcapServer {
        addr: peer_addr,
        mut filter_rx,
        ..
    } = setup_peer_pcap_server(peer_certs).await;

    let peers = build_peers_for_sensor(SENSOR, peer_addr);
    let peer_idents = build_peer_idents(peer_addr, NODE2.host);

    let pcap_sensors = new_pcap_sensors();
    let received_filter = run_pcap_filters_and_recv_single(
        vec![filter.clone()],
        pcap_sensors,
        peers,
        peer_idents,
        &mut filter_rx,
        "peer pcap request",
        StdDuration::from_secs(5),
    )
    .await;
    assert_filter_matches(&received_filter, &filter);
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_skips_when_peer_name_missing() {
    init_crypto();
    const SENSOR: &str = "pcap_peer_missing_ident";
    let filter = build_filter_for_sensor(SENSOR, 30, 40);

    let peer_certs = NODE2.build_certs();
    let PeerPcapServer {
        addr: peer_addr,
        connection_rx,
        ..
    } = setup_peer_pcap_server(peer_certs).await;

    let peers = build_peers_for_sensor(SENSOR, peer_addr);
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));

    let pcap_sensors = new_pcap_sensors();
    with_log_capture(|log_capture| async move {
        run_process_pcap_extract_filters(vec![filter], pcap_sensors, peers, peer_idents).await;

        assert_no_peer_connection(connection_rx).await;
        let expected_log = format!(
            "Peer's server name cannot be identitified. addr: {peer_addr}, sensor: {SENSOR}"
        );
        assert_log_contains(&log_capture, &expected_log).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_logs_peer_ack_failure() {
    init_crypto();
    const SENSOR: &str = "pcap_peer_ack_fail";
    let filter = build_filter_for_sensor(SENSOR, 70, 80);

    let peer_certs = NODE2.build_certs();
    let PeerPcapServer {
        addr: peer_addr,
        mut filter_rx,
        ..
    } = setup_peer_pcap_server_with_ack(peer_certs, Some("ack_failed")).await;

    let peers = build_peers_for_sensor(SENSOR, peer_addr);
    let peer_idents = build_peer_idents(peer_addr, NODE2.host);

    let pcap_sensors = new_pcap_sensors();
    with_log_capture(|log_capture| async move {
        run_process_pcap_extract_filters(vec![filter.clone()], pcap_sensors, peers, peer_idents)
            .await;

        let received_filter = recv_with_timeout(
            &mut filter_rx,
            "peer pcap request",
            StdDuration::from_secs(5),
        )
        .await;
        assert_filter_matches(&received_filter, &filter);

        let expected_log = format!(
            "Failed to receive ack response from peer. addr: {peer_addr} name: {}",
            NODE2.host
        );
        assert_log_contains(&log_capture, &expected_log).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_logs_peer_connect_failure() {
    init_crypto();
    const SENSOR: &str = "pcap_peer_connect_fail";
    let filter = build_filter_for_sensor(SENSOR, 90, 100);

    let peer_certs = NODE2.build_certs();
    let PeerHandshakeServer {
        addr: peer_addr, ..
    } = setup_peer_handshake_mismatch_server(peer_certs, ">=99.0.0").await;

    let peers = build_peers_for_sensor(SENSOR, peer_addr);
    let peer_idents = build_peer_idents(peer_addr, NODE2.host);

    let pcap_sensors = new_pcap_sensors();
    with_log_capture(|log_capture| async move {
        run_process_pcap_extract_filters(vec![filter], pcap_sensors, peers, peer_idents).await;

        let expected_log = format!(
            "Failed to connect to peer's publish module. addr: {peer_addr} name: {}",
            NODE2.host
        );
        assert_log_contains(&log_capture, &expected_log).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn process_pcap_extract_filters_skips_when_no_peer_in_charge() {
    init_crypto();
    const SENSOR: &str = "pcap_orphan";
    let filter = build_filter_for_sensor(SENSOR, 50, 60);

    let peer_certs = NODE2.build_certs();
    let PeerPcapServer { connection_rx, .. } = setup_peer_pcap_server(peer_certs).await;

    let peers = Arc::new(RwLock::new(HashMap::new()));
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));

    let pcap_sensors = new_pcap_sensors();
    with_log_capture(|log_capture| async move {
        run_process_pcap_extract_filters(vec![filter], pcap_sensors, peers, peer_idents).await;

        assert_no_peer_connection(connection_rx).await;
        let expected_log =
            format!("Neither this node nor peers are in charge of requested pcap sensor {SENSOR}");
        assert_log_contains(&log_capture, &expected_log).await;
    })
    .await;
}

#[test]
fn filter_ip_semi_supervised_always_true() {
    let semi = RequestSemiSupervisedStream {
        start: 0,
        sensor: None,
    };
    assert!(semi.filter_ip("1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()));
}

#[test]
fn filter_ip_time_series_generator_matches_all_when_no_ips() {
    let tsg = RequestTimeSeriesGeneratorStream {
        start: 0,
        id: "p1".to_string(),
        src_ip: None,
        dst_ip: None,
        sensor: Some("s1".to_string()),
    };
    assert!(tsg.filter_ip("1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()));
}

#[test]
fn filter_ip_time_series_generator_matches_src_only() {
    let tsg = RequestTimeSeriesGeneratorStream {
        start: 0,
        id: "p1".to_string(),
        src_ip: Some("1.1.1.1".parse().unwrap()),
        dst_ip: None,
        sensor: Some("s1".to_string()),
    };
    assert!(tsg.filter_ip("1.1.1.1".parse().unwrap(), "5.5.5.5".parse().unwrap()));
    assert!(!tsg.filter_ip("9.9.9.9".parse().unwrap(), "5.5.5.5".parse().unwrap()));
}

#[test]
fn filter_ip_time_series_generator_matches_dst_only() {
    let tsg = RequestTimeSeriesGeneratorStream {
        start: 0,
        id: "p1".to_string(),
        src_ip: None,
        dst_ip: Some("2.2.2.2".parse().unwrap()),
        sensor: Some("s1".to_string()),
    };
    assert!(tsg.filter_ip("9.9.9.9".parse().unwrap(), "2.2.2.2".parse().unwrap()));
    assert!(!tsg.filter_ip("9.9.9.9".parse().unwrap(), "8.8.8.8".parse().unwrap()));
}

#[test]
fn filter_ip_time_series_generator_matches_both() {
    let tsg = RequestTimeSeriesGeneratorStream {
        start: 0,
        id: "p1".to_string(),
        src_ip: Some("1.1.1.1".parse().unwrap()),
        dst_ip: Some("2.2.2.2".parse().unwrap()),
        sensor: Some("s1".to_string()),
    };
    assert!(tsg.filter_ip("1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()));
    assert!(!tsg.filter_ip("1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()));
    assert!(!tsg.filter_ip("9.9.9.9".parse().unwrap(), "2.2.2.2".parse().unwrap()));
}

#[tokio::test]
async fn peer_name_returns_hostname_when_match() {
    let addr = SocketAddr::new("10.0.0.4".parse::<IpAddr>().unwrap(), 61001);
    let peer_idents = Arc::new(RwLock::new(HashSet::from([PeerIdentity {
        addr,
        hostname: "node-a".to_string(),
    }])));

    let name = super::peer_name(peer_idents, &addr)
        .await
        .expect("peer_name should resolve");

    assert_eq!(name, "node-a");
}

#[tokio::test]
async fn peer_name_returns_error_without_match() {
    let addr = SocketAddr::new("10.0.0.5".parse::<IpAddr>().unwrap(), 61002);
    let peer_idents = Arc::new(RwLock::new(HashSet::new()));

    let err = super::peer_name(peer_idents, &addr)
        .await
        .expect_err("peer_name should return error when missing");

    assert_eq!(
        err.to_string(),
        "Peer giganto's server name cannot be identitified"
    );
}

#[tokio::test]
async fn connect_supports_ipv6() {
    init_crypto();

    let certs = build_test_certs();
    let server_config = config_server(&certs).expect("server config");
    let endpoint = Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    )
    .expect("Failed to start ipv6 server");
    let server_addr = endpoint.local_addr().expect("ipv6 server addr");
    let (handshake_tx, handshake_rx) = oneshot::channel();

    let server_task = tokio::spawn(async move {
        let Some(connecting) = endpoint.accept().await else {
            return;
        };
        let Ok(connection) = connecting.await else {
            return;
        };
        if server_handshake(&connection, crate::comm::publish::PUBLISH_VERSION_REQ)
            .await
            .is_ok()
        {
            let _ = handshake_tx.send(());
        }
        let _ = connection.closed().await;
    });

    let connection = super::connect(server_addr, NODE1.host, &certs)
        .await
        .expect("ipv6 connect failed");
    let remote_addr = connection.remote_address();
    assert!(remote_addr.ip().is_ipv6(), "remote address is not ipv6");
    assert_eq!(remote_addr.ip(), server_addr.ip(), "remote ip mismatch");
    assert_eq!(
        remote_addr.port(),
        server_addr.port(),
        "remote port mismatch"
    );
    tokio::time::timeout(StdDuration::from_secs(2), handshake_rx)
        .await
        .expect("handshake timeout")
        .expect("handshake signal missing");
    connection.close(0u32.into(), b"done");

    let _ = server_task.await;
}
