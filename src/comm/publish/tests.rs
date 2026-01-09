#![allow(clippy::items_after_statements)]

use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, OnceLock},
};

use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use giganto_client::{
    connection::client_handshake,
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
        range::{MessageCode, RequestRange, RequestRawData, ResponseRangeData},
        receive_range_data, receive_semi_supervised_data,
        receive_semi_supervised_stream_start_message, receive_time_series_generator_data,
        receive_time_series_generator_stream_start_message, send_range_data_request,
        send_stream_request,
        stream::{
            RequestSemiSupervisedStream, RequestStreamRecord, RequestTimeSeriesGeneratorStream,
            StreamRequestPayload,
        },
    },
};
use quinn::{Connection, Endpoint, SendStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serial_test::serial;
use tempfile::TempDir;
use tokio::sync::{Mutex, MutexGuard, Notify, RwLock};

static INIT: OnceLock<()> = OnceLock::new();

fn init_crypto() {
    INIT.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

use super::Server;
use crate::{
    comm::{
        IngestSensors, StreamDirectChannels,
        ingest::NetworkKey,
        new_pcap_sensors, new_peers_data, new_stream_direct_channels,
        peer::{PeerIdentity, PeerInfo},
        publish::send_direct_stream,
        to_cert_chain, to_private_key, to_root_cert,
    },
    server::Certs,
    storage::{Database, DbOptions, RawEventStore},
};

fn get_token() -> &'static Mutex<u32> {
    static TOKEN: OnceLock<Mutex<u32>> = OnceLock::new();

    TOKEN.get_or_init(|| Mutex::new(0))
}

struct TestHarness {
    _lock: MutexGuard<'static, u32>,
    _temp_dir: TempDir,
    db: Database,
    publish: TestClient,
    stream_direct_channels: StreamDirectChannels,
}

fn build_ingest_sensors_from_list(list: &[&str]) -> IngestSensors {
    Arc::new(RwLock::new(
        list.iter()
            .copied()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ))
}

fn build_ingest_sensors() -> IngestSensors {
    NODE1.build_ingest_sensors()
}

fn build_certs_from_paths(cert_path: &str, key_path: &str) -> Arc<Certs> {
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

fn build_test_certs() -> Arc<Certs> {
    NODE1.build_certs()
}

async fn setup_test_harness() -> TestHarness {
    init_crypto();

    let lock = get_token().lock().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let db = Database::open(temp_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = build_ingest_sensors();
    let (peers, peer_idents) = new_peers_data(None);
    let certs = build_test_certs();

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels.clone(),
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));

    let publish = TestClient::new().await;

    TestHarness {
        _lock: lock,
        _temp_dir: temp_dir,
        db,
        publish,
        stream_direct_channels,
    }
}

fn assert_range_result<T: serde::Serialize>(
    mut result_data: Vec<Option<T>>,
    expected: &[u8],
    done: &[u8],
    context: &str,
) {
    let done_payload = bincode::serialize(&result_data.pop().unwrap()).unwrap();
    assert_eq!(done, done_payload, "done payload mismatch: {context}");
    let payload = bincode::serialize(&result_data.pop().unwrap()).unwrap();
    assert_eq!(expected, payload, "response payload mismatch: {context}");
}

async fn fetch_raw_data(
    publish: &TestClient,
    kind: &str,
    sensor: &str,
    timestamp: i64,
) -> Vec<(i64, String, Vec<u8>)> {
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
        let resp_data = receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
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

macro_rules! build_network_expected_case {
    ($kind:expr, $type:ty, $insert_fn:ident, $store_fn:ident, $db:expr, $sensor:expr, $timestamp:expr, $done_type:ty) => {{
        let ser_body = $insert_fn(&$db.$store_fn().unwrap(), $sensor, $timestamp);
        let expected = bincode::deserialize::<$type>(&ser_body)
            .unwrap()
            .response_data($timestamp, $sensor)
            .unwrap();
        (expected, <$done_type>::response_done().unwrap())
    }};
}

#[allow(clippy::too_many_lines)]
fn build_network_expected(
    db: &Database,
    kind: &str,
    sensor: &str,
    timestamp: i64,
) -> (Vec<u8>, Vec<u8>) {
    match kind {
        "conn" => build_network_expected_case!(
            kind,
            Conn,
            insert_conn_raw_event,
            conn_store,
            db,
            sensor,
            timestamp,
            Conn
        ),
        "dns" => build_network_expected_case!(
            kind,
            Dns,
            insert_dns_raw_event,
            dns_store,
            db,
            sensor,
            timestamp,
            Dns
        ),
        "malformed_dns" => build_network_expected_case!(
            kind,
            MalformedDns,
            insert_malformed_dns_raw_event,
            malformed_dns_store,
            db,
            sensor,
            timestamp,
            MalformedDns
        ),
        "http" => build_network_expected_case!(
            kind,
            Http,
            insert_http_raw_event,
            http_store,
            db,
            sensor,
            timestamp,
            Http
        ),
        "rdp" => build_network_expected_case!(
            kind,
            Rdp,
            insert_rdp_raw_event,
            rdp_store,
            db,
            sensor,
            timestamp,
            Rdp
        ),
        "smtp" => build_network_expected_case!(
            kind,
            Smtp,
            insert_smtp_raw_event,
            smtp_store,
            db,
            sensor,
            timestamp,
            Conn
        ),
        "ntlm" => build_network_expected_case!(
            kind,
            Ntlm,
            insert_ntlm_raw_event,
            ntlm_store,
            db,
            sensor,
            timestamp,
            Ntlm
        ),
        "kerberos" => build_network_expected_case!(
            kind,
            Kerberos,
            insert_kerberos_raw_event,
            kerberos_store,
            db,
            sensor,
            timestamp,
            Kerberos
        ),
        "ssh" => build_network_expected_case!(
            kind,
            Ssh,
            insert_ssh_raw_event,
            ssh_store,
            db,
            sensor,
            timestamp,
            Ssh
        ),
        "dce rpc" => build_network_expected_case!(
            kind,
            DceRpc,
            insert_dce_rpc_raw_event,
            dce_rpc_store,
            db,
            sensor,
            timestamp,
            DceRpc
        ),
        "ftp" => build_network_expected_case!(
            kind,
            Ftp,
            insert_ftp_raw_event,
            ftp_store,
            db,
            sensor,
            timestamp,
            Ftp
        ),
        "mqtt" => build_network_expected_case!(
            kind,
            Mqtt,
            insert_mqtt_raw_event,
            mqtt_store,
            db,
            sensor,
            timestamp,
            Mqtt
        ),
        "ldap" => build_network_expected_case!(
            kind,
            Ldap,
            insert_ldap_raw_event,
            ldap_store,
            db,
            sensor,
            timestamp,
            Ldap
        ),
        "tls" => build_network_expected_case!(
            kind,
            Tls,
            insert_tls_raw_event,
            tls_store,
            db,
            sensor,
            timestamp,
            Tls
        ),
        "smb" => build_network_expected_case!(
            kind,
            Smb,
            insert_smb_raw_event,
            smb_store,
            db,
            sensor,
            timestamp,
            Smb
        ),
        "nfs" => build_network_expected_case!(
            kind,
            Nfs,
            insert_nfs_raw_event,
            nfs_store,
            db,
            sensor,
            timestamp,
            Nfs
        ),
        "bootp" => build_network_expected_case!(
            kind,
            Bootp,
            insert_bootp_raw_event,
            bootp_store,
            db,
            sensor,
            timestamp,
            Bootp
        ),
        "dhcp" => build_network_expected_case!(
            kind,
            Dhcp,
            insert_dhcp_raw_event,
            dhcp_store,
            db,
            sensor,
            timestamp,
            Dhcp
        ),
        "radius" => build_network_expected_case!(
            kind,
            Radius,
            insert_radius_raw_event,
            radius_store,
            db,
            sensor,
            timestamp,
            Radius
        ),
        _ => unreachable!("unknown network kind: {kind}"),
    }
}

macro_rules! build_sysmon_expected_case {
    ($type:ty, $insert_fn:ident, $store_fn:ident, $db:expr, $sensor:expr, $timestamp:expr) => {{
        let ser_body = $insert_fn(&$db.$store_fn().unwrap(), $sensor, $timestamp);
        bincode::deserialize::<$type>(&ser_body)
            .unwrap()
            .response_data($timestamp, $sensor)
            .unwrap()
    }};
}

#[allow(clippy::too_many_lines)]
fn build_sysmon_expected(db: &Database, kind: &str, sensor: &str, timestamp: i64) -> Vec<u8> {
    match kind {
        "process_create" => build_sysmon_expected_case!(
            ProcessCreate,
            insert_process_create_raw_event,
            process_create_store,
            db,
            sensor,
            timestamp
        ),
        "file_create_time" => build_sysmon_expected_case!(
            FileCreationTimeChanged,
            insert_file_create_time_raw_event,
            file_create_time_store,
            db,
            sensor,
            timestamp
        ),
        "network_connect" => build_sysmon_expected_case!(
            NetworkConnection,
            insert_network_connect_raw_event,
            network_connect_store,
            db,
            sensor,
            timestamp
        ),
        "process_terminate" => build_sysmon_expected_case!(
            ProcessTerminated,
            insert_process_terminate_raw_event,
            process_terminate_store,
            db,
            sensor,
            timestamp
        ),
        "image_load" => build_sysmon_expected_case!(
            ImageLoaded,
            insert_image_load_raw_event,
            image_load_store,
            db,
            sensor,
            timestamp
        ),
        "file_create" => build_sysmon_expected_case!(
            FileCreate,
            insert_file_create_raw_event,
            file_create_store,
            db,
            sensor,
            timestamp
        ),
        "registry_value_set" => build_sysmon_expected_case!(
            RegistryValueSet,
            insert_registry_value_set_raw_event,
            registry_value_set_store,
            db,
            sensor,
            timestamp
        ),
        "registry_key_rename" => build_sysmon_expected_case!(
            RegistryKeyValueRename,
            insert_registry_key_rename_raw_event,
            registry_key_rename_store,
            db,
            sensor,
            timestamp
        ),
        "file_create_stream_hash" => build_sysmon_expected_case!(
            FileCreateStreamHash,
            insert_file_create_stream_hash_raw_event,
            file_create_stream_hash_store,
            db,
            sensor,
            timestamp
        ),
        "pipe_event" => build_sysmon_expected_case!(
            PipeEvent,
            insert_pipe_event_raw_event,
            pipe_event_store,
            db,
            sensor,
            timestamp
        ),
        "dns_query" => build_sysmon_expected_case!(
            DnsEvent,
            insert_dns_query_raw_event,
            dns_query_store,
            db,
            sensor,
            timestamp
        ),
        "file_delete" => build_sysmon_expected_case!(
            FileDelete,
            insert_file_delete_raw_event,
            file_delete_store,
            db,
            sensor,
            timestamp
        ),
        "process_tamper" => build_sysmon_expected_case!(
            ProcessTampering,
            insert_process_tamper_raw_event,
            process_tamper_store,
            db,
            sensor,
            timestamp
        ),
        "file_delete_detected" => build_sysmon_expected_case!(
            FileDeleteDetected,
            insert_file_delete_detected_raw_event,
            file_delete_detected_store,
            db,
            sensor,
            timestamp
        ),
        _ => unreachable!("unknown sysmon kind: {kind}"),
    }
}

type StreamInsertFn = fn(&Database, &str, i64) -> Vec<u8>;

struct NetworkStreamCase {
    record_type: RequestStreamRecord,
    kind: &'static str,
    semi_payload: fn() -> Vec<u8>,
    direct_payload: fn() -> Vec<u8>,
    insert_db: StreamInsertFn,
}

async fn assert_semi_supervised_stream(
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
        let send_time = Utc::now().timestamp_nanos_opt().unwrap();
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
        assert_eq!(payload, recv_data[20..]);
    }
}

#[allow(clippy::too_many_arguments)]
async fn assert_time_series_generator_stream(
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

macro_rules! impl_insert_stream {
    ($($name:ident, $raw_fn:ident, $store_fn:ident);+ $(;)?) => {
        $(
            fn $name(db: &Database, sensor: &str, timestamp: i64) -> Vec<u8> {
                $raw_fn(&db.$store_fn().unwrap(), sensor, timestamp)
            }
        )+
    };
}

impl_insert_stream! {
    insert_conn_stream, insert_conn_raw_event, conn_store;
    insert_dns_stream, insert_dns_raw_event, dns_store;
    insert_rdp_stream, insert_rdp_raw_event, rdp_store;
    insert_http_stream, insert_http_raw_event, http_store;
    insert_smtp_stream, insert_smtp_raw_event, smtp_store;
    insert_ntlm_stream, insert_ntlm_raw_event, ntlm_store;
    insert_kerberos_stream, insert_kerberos_raw_event, kerberos_store;
    insert_ssh_stream, insert_ssh_raw_event, ssh_store;
    insert_dce_rpc_stream, insert_dce_rpc_raw_event, dce_rpc_store;
    insert_ftp_stream, insert_ftp_raw_event, ftp_store;
    insert_mqtt_stream, insert_mqtt_raw_event, mqtt_store;
    insert_ldap_stream, insert_ldap_raw_event, ldap_store;
    insert_tls_stream, insert_tls_raw_event, tls_store;
    insert_smb_stream, insert_smb_raw_event, smb_store;
    insert_nfs_stream, insert_nfs_raw_event, nfs_store;
    insert_bootp_stream, insert_bootp_raw_event, bootp_store;
    insert_dhcp_stream, insert_dhcp_raw_event, dhcp_store;
    insert_radius_stream, insert_radius_raw_event, radius_store;
}

const CA_CERT_PATH: &str = "tests/certs/ca_cert.pem";
const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

struct NodeConfig {
    cert_path: &'static str,
    key_path: &'static str,
    host: &'static str,
    port: u16,
    ingest_sensors: &'static [&'static str],
}

impl NodeConfig {
    fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.port)
    }

    fn socket_addr_v4(&self) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), self.port)
    }

    fn build_certs(&self) -> Arc<Certs> {
        build_certs_from_paths(self.cert_path, self.key_path)
    }

    fn build_ingest_sensors(&self) -> IngestSensors {
        build_ingest_sensors_from_list(self.ingest_sensors)
    }

    fn peer_info(&self) -> PeerInfo {
        PeerInfo {
            ingest_sensors: self
                .ingest_sensors
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<HashSet<String>>(),
            graphql_port: None,
            publish_port: Some(self.port),
        }
    }

    fn peer_identity(&self) -> PeerIdentity {
        PeerIdentity {
            addr: self.socket_addr(),
            hostname: self.host.to_string(),
        }
    }

    fn peer_identity_v4(&self) -> PeerIdentity {
        PeerIdentity {
            addr: self.socket_addr_v4(),
            hostname: self.host.to_string(),
        }
    }
}

const NODE1: NodeConfig = NodeConfig {
    cert_path: "tests/certs/node1/cert.pem",
    key_path: "tests/certs/node1/key.pem",
    host: "node1",
    port: 60191,
    ingest_sensors: &["src1", "src 1", "ingest src 1"],
};

const NODE2: NodeConfig = NodeConfig {
    cert_path: "tests/certs/node2/cert.pem",
    key_path: "tests/certs/node2/key.pem",
    host: "node2",
    port: 60192,
    ingest_sensors: &["src2", "src 2", "ingest src 2"],
};

struct TestClient {
    send: SendStream,
    conn: Connection,
    endpoint: Endpoint,
}

impl TestClient {
    async fn new() -> Self {
        let endpoint = init_client();
        let conn = endpoint
            .connect(NODE1.socket_addr(), NODE1.host)
            .expect(
                "Failed to connect server's endpoint, Please check if the setting value is correct",
            )
            .await
            .expect("Failed to connect server's endpoint, Please make sure the Server is alive");
        let (send, _) = client_handshake(&conn, PROTOCOL_VERSION).await.unwrap();
        Self {
            send,
            conn,
            endpoint,
        }
    }

    async fn send_range_request<T: serde::de::DeserializeOwned>(
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
            let resp_data = receive_range_data::<Option<T>>(&mut recv_pub_resp)
                .await
                .unwrap();
            let is_done = resp_data.is_none();

            result_data.push(resp_data);
            if is_done {
                break;
            }
        }

        result_data
    }
}

fn server() -> Server {
    let certs = build_test_certs();

    Server::new(NODE1.socket_addr(), &certs)
}

fn init_client() -> Endpoint {
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

    let mut endpoint = Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
        .expect("Failed to create endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("Failed to generate QuicClientConfig"),
    )));
    endpoint
}

fn default_time_range() -> (i64, i64) {
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

fn build_range_request(sensor: &str, kind: &str) -> RequestRange {
    let (start, end) = default_time_range();
    RequestRange {
        sensor: sensor.to_string(),
        kind: kind.to_string(),
        start,
        end,
        count: 5,
    }
}

fn gen_network_event_key(sensor: &str, kind: Option<&str>, timestamp: i64) -> Vec<u8> {
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

fn gen_conn_raw_event() -> Vec<u8> {
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

fn gen_dns_raw_event() -> Vec<u8> {
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

fn gen_malformed_dns_raw_event() -> Vec<u8> {
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

fn gen_rdp_raw_event() -> Vec<u8> {
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

fn gen_http_raw_event() -> Vec<u8> {
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

fn gen_smtp_raw_event() -> Vec<u8> {
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

fn gen_ntlm_raw_event() -> Vec<u8> {
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

fn gen_kerberos_raw_event() -> Vec<u8> {
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

fn gen_ssh_raw_event() -> Vec<u8> {
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

fn gen_dce_rpc_raw_event() -> Vec<u8> {
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

fn gen_log_raw_event() -> Vec<u8> {
    let log_body = Log {
        kind: String::from("Hello"),
        log: base64_engine.decode("aGVsbG8gd29ybGQ=").unwrap(),
    };

    bincode::serialize(&log_body).unwrap()
}

fn gen_periodic_time_series_raw_event() -> Vec<u8> {
    let periodic_time_series_body: PeriodicTimeSeries = PeriodicTimeSeries {
        id: String::from("policy_one"),
        data: vec![1.1, 2.2, 3.3, 4.4, 5.5, 6.6],
    };

    bincode::serialize(&periodic_time_series_body).unwrap()
}

fn gen_ftp_raw_event() -> Vec<u8> {
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

fn gen_mqtt_raw_event() -> Vec<u8> {
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

fn gen_ldap_raw_event() -> Vec<u8> {
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

fn gen_tls_raw_event() -> Vec<u8> {
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

fn gen_smb_raw_event() -> Vec<u8> {
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

fn gen_nfs_raw_event() -> Vec<u8> {
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

fn gen_bootp_raw_event() -> Vec<u8> {
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

fn gen_dhcp_raw_event() -> Vec<u8> {
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

fn gen_radius_raw_event() -> Vec<u8> {
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

macro_rules! impl_insert_network_raw_event {
    ($($name:ident, $type:ty, $gen_fn:ident);+ $(;)?) => {
        $(
            fn $name(store: &RawEventStore<$type>, sensor: &str, timestamp: i64) -> Vec<u8> {
                let key = gen_network_event_key(sensor, None, timestamp);
                let ser_body = $gen_fn();
                store.append(&key, &ser_body).unwrap();
                ser_body
            }
        )+
    };
}

impl_insert_network_raw_event! {
    insert_conn_raw_event, Conn, gen_conn_raw_event;
    insert_dns_raw_event, Dns, gen_dns_raw_event;
    insert_malformed_dns_raw_event, MalformedDns, gen_malformed_dns_raw_event;
    insert_rdp_raw_event, Rdp, gen_rdp_raw_event;
    insert_http_raw_event, Http, gen_http_raw_event;
    insert_smtp_raw_event, Smtp, gen_smtp_raw_event;
    insert_ntlm_raw_event, Ntlm, gen_ntlm_raw_event;
    insert_kerberos_raw_event, Kerberos, gen_kerberos_raw_event;
    insert_ssh_raw_event, Ssh, gen_ssh_raw_event;
    insert_dce_rpc_raw_event, DceRpc, gen_dce_rpc_raw_event;
    insert_ftp_raw_event, Ftp, gen_ftp_raw_event;
    insert_mqtt_raw_event, Mqtt, gen_mqtt_raw_event;
    insert_ldap_raw_event, Ldap, gen_ldap_raw_event;
    insert_tls_raw_event, Tls, gen_tls_raw_event;
    insert_smb_raw_event, Smb, gen_smb_raw_event;
    insert_nfs_raw_event, Nfs, gen_nfs_raw_event;
    insert_bootp_raw_event, Bootp, gen_bootp_raw_event;
    insert_dhcp_raw_event, Dhcp, gen_dhcp_raw_event;
    insert_radius_raw_event, Radius, gen_radius_raw_event;
}

fn insert_log_raw_event(
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

fn insert_periodic_time_series_raw_event(
    store: &RawEventStore<PeriodicTimeSeries>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_periodic_time_series_body = gen_periodic_time_series_raw_event();
    store.append(&key, &ser_periodic_time_series_body).unwrap();
    ser_periodic_time_series_body
}

fn gen_process_create_raw_event() -> Vec<u8> {
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

fn insert_process_create_raw_event(
    store: &RawEventStore<ProcessCreate>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_process_create_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_file_create_time_raw_event() -> Vec<u8> {
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

fn insert_file_create_time_raw_event(
    store: &RawEventStore<FileCreationTimeChanged>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_file_create_time_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_network_connect_raw_event() -> Vec<u8> {
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

fn insert_network_connect_raw_event(
    store: &RawEventStore<NetworkConnection>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_network_connect_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_process_terminate_raw_event() -> Vec<u8> {
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

fn insert_process_terminate_raw_event(
    store: &RawEventStore<ProcessTerminated>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_process_terminate_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_image_load_raw_event() -> Vec<u8> {
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

fn insert_image_load_raw_event(
    store: &RawEventStore<ImageLoaded>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_image_load_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_file_create_raw_event() -> Vec<u8> {
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

fn insert_file_create_raw_event(
    store: &RawEventStore<FileCreate>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_file_create_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_registry_value_set_raw_event() -> Vec<u8> {
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

fn insert_registry_value_set_raw_event(
    store: &RawEventStore<RegistryValueSet>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_registry_value_set_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_registry_key_rename_raw_event() -> Vec<u8> {
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

fn insert_registry_key_rename_raw_event(
    store: &RawEventStore<RegistryKeyValueRename>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_registry_key_rename_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_file_create_stream_hash_raw_event() -> Vec<u8> {
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

fn insert_file_create_stream_hash_raw_event(
    store: &RawEventStore<FileCreateStreamHash>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_file_create_stream_hash_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_pipe_event_raw_event() -> Vec<u8> {
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

fn insert_pipe_event_raw_event(
    store: &RawEventStore<PipeEvent>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_pipe_event_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_dns_query_raw_event() -> Vec<u8> {
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

fn insert_dns_query_raw_event(
    store: &RawEventStore<DnsEvent>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_dns_query_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_file_delete_raw_event() -> Vec<u8> {
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

fn insert_file_delete_raw_event(
    store: &RawEventStore<FileDelete>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_file_delete_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_process_tamper_raw_event() -> Vec<u8> {
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

fn insert_process_tamper_raw_event(
    store: &RawEventStore<ProcessTampering>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_process_tamper_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_file_delete_detected_raw_event() -> Vec<u8> {
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

fn insert_file_delete_detected_raw_event(
    store: &RawEventStore<FileDeleteDetected>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_file_delete_detected_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_netflow5_raw_event() -> Vec<u8> {
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

fn insert_netflow5_raw_event(
    store: &RawEventStore<Netflow5>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_netflow5_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

fn gen_netflow9_raw_event() -> Vec<u8> {
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

fn insert_netflow9_raw_event(
    store: &RawEventStore<Netflow9>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_body = gen_netflow9_raw_event();
    store.append(&key, &ser_body).unwrap();
    ser_body
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn request_range_data_with_protocol() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "ingest src 1";
    const CONN_KIND: &str = "conn";
    const DNS_KIND: &str = "dns";
    const MALFORMED_DNS_KIND: &str = "malformed_dns";
    const HTTP_KIND: &str = "http";
    const RDP_KIND: &str = "rdp";
    const SMTP_KIND: &str = "smtp";
    const NTLM_KIND: &str = "ntlm";
    const KERBEROS_KIND: &str = "kerberos";
    const SSH_KIND: &str = "ssh";
    const DCE_RPC_KIND: &str = "dce rpc";
    const FTP_KIND: &str = "ftp";
    const MQTT_KIND: &str = "mqtt";
    const LDAP_KIND: &str = "ldap";
    const TLS_KIND: &str = "tls";
    const SMB_KIND: &str = "smb";
    const NFS_KIND: &str = "nfs";
    const BOOTP_KIND: &str = "bootp";
    const DHCP_KIND: &str = "dhcp";
    const RADIUS_KIND: &str = "radius";

    let harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &harness.publish;

    let kinds = [
        CONN_KIND,
        DNS_KIND,
        MALFORMED_DNS_KIND,
        HTTP_KIND,
        RDP_KIND,
        SMTP_KIND,
        NTLM_KIND,
        KERBEROS_KIND,
        SSH_KIND,
        DCE_RPC_KIND,
        FTP_KIND,
        MQTT_KIND,
        LDAP_KIND,
        TLS_KIND,
        SMB_KIND,
        NFS_KIND,
        BOOTP_KIND,
        DHCP_KIND,
        RADIUS_KIND,
    ];

    for kind in kinds {
        let send_time = Utc::now().timestamp_nanos_opt().unwrap();
        let (expected, done) = build_network_expected(db, kind, SENSOR, send_time);
        let result_data = publish
            .send_range_request::<(i64, String, Vec<u8>)>(
                PUBLISH_RANGE_MESSAGE_CODE,
                build_range_request(SENSOR, kind),
            )
            .await;

        assert_range_result(result_data, expected.as_slice(), done.as_slice(), kind);
    }

    publish.conn.close(0u32.into(), b"publish_protocol_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_range_data_with_log() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "src1";
    const KIND: &str = "Hello";

    let harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &harness.publish;

    let log_store = db.log_store().unwrap();
    let send_log_time = Utc::now().timestamp_nanos_opt().unwrap();
    let log_data = bincode::deserialize::<Log>(&insert_log_raw_event(
        &log_store,
        SENSOR,
        KIND,
        send_log_time,
    ))
    .unwrap();

    let result_data = publish
        .send_range_request::<(i64, String, Vec<u8>)>(
            PUBLISH_RANGE_MESSAGE_CODE,
            build_range_request(SENSOR, KIND),
        )
        .await;

    let expected = log_data.response_data(send_log_time, SENSOR).unwrap();
    assert_range_result(
        result_data,
        expected.as_slice(),
        Conn::response_done().unwrap().as_slice(),
        KIND,
    );

    publish.conn.close(0u32.into(), b"publish_log_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn request_range_data_with_sysmon() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "ingest src 1";

    let harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &harness.publish;

    let kinds = [
        "process_create",
        "file_create_time",
        "network_connect",
        "process_terminate",
        "image_load",
        "file_create",
        "registry_value_set",
        "registry_key_rename",
        "file_create_stream_hash",
        "pipe_event",
        "dns_query",
        "file_delete",
        "process_tamper",
        "file_delete_detected",
    ];

    for kind in kinds {
        let send_time = Utc::now().timestamp_nanos_opt().unwrap();
        let expected_resp = build_sysmon_expected(db, kind, SENSOR, send_time);
        let result_data = publish
            .send_range_request::<(i64, String, Vec<u8>)>(
                PUBLISH_RANGE_MESSAGE_CODE,
                build_range_request(SENSOR, kind),
            )
            .await;

        assert_range_result(
            result_data,
            expected_resp.as_slice(),
            Conn::response_done().unwrap().as_slice(),
            kind,
        );
    }

    publish.conn.close(0u32.into(), b"publish_sysmon_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_range_data_with_netflow() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "ingest src 1";

    let harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &harness.publish;

    let kinds = ["netflow5", "netflow9"];

    for kind in kinds {
        let send_time = Utc::now().timestamp_nanos_opt().unwrap();

        let ser_body = match kind {
            "netflow5" => {
                insert_netflow5_raw_event(&db.netflow5_store().unwrap(), SENSOR, send_time)
            }
            "netflow9" => {
                insert_netflow9_raw_event(&db.netflow9_store().unwrap(), SENSOR, send_time)
            }
            _ => unreachable!(),
        };

        let result_data = publish
            .send_range_request::<(i64, String, Vec<u8>)>(
                PUBLISH_RANGE_MESSAGE_CODE,
                build_range_request(SENSOR, kind),
            )
            .await;

        let expected_resp = match kind {
            "netflow5" => bincode::deserialize::<Netflow5>(&ser_body)
                .unwrap()
                .response_data(send_time, SENSOR)
                .unwrap(),
            "netflow9" => bincode::deserialize::<Netflow9>(&ser_body)
                .unwrap()
                .response_data(send_time, SENSOR)
                .unwrap(),
            _ => unreachable!(),
        };

        assert_range_result(
            result_data,
            expected_resp.as_slice(),
            Conn::response_done().unwrap().as_slice(),
            kind,
        );
    }

    publish.conn.close(0u32.into(), b"publish_netflow_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_range_data_with_period_time_series() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SAMPLING_POLICY_ID_AS_SENSOR: &str = "ingest src 1";
    const KIND: &str = "timeseries";

    let harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &harness.publish;

    let time_series_store = db.periodic_time_series_store().unwrap();
    let send_time_series_time = Utc::now().timestamp_nanos_opt().unwrap();
    let time_series_data =
        bincode::deserialize::<PeriodicTimeSeries>(&insert_periodic_time_series_raw_event(
            &time_series_store,
            SAMPLING_POLICY_ID_AS_SENSOR,
            send_time_series_time,
        ))
        .unwrap();

    let result_data = publish
        .send_range_request::<(i64, String, Vec<f64>)>(
            PUBLISH_RANGE_MESSAGE_CODE,
            build_range_request(SAMPLING_POLICY_ID_AS_SENSOR, KIND),
        )
        .await;

    let expected = time_series_data
        .response_data(send_time_series_time, SAMPLING_POLICY_ID_AS_SENSOR)
        .unwrap();
    assert_range_result(
        result_data,
        expected.as_slice(),
        PeriodicTimeSeries::response_done().unwrap().as_slice(),
        KIND,
    );

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn request_network_event_stream() {
    const NETWORK_STREAM_CONN: RequestStreamRecord = RequestStreamRecord::Conn;
    const NETWORK_STREAM_DNS: RequestStreamRecord = RequestStreamRecord::Dns;
    const NETWORK_STREAM_RDP: RequestStreamRecord = RequestStreamRecord::Rdp;
    const NETWORK_STREAM_HTTP: RequestStreamRecord = RequestStreamRecord::Http;
    const NETWORK_STREAM_SMTP: RequestStreamRecord = RequestStreamRecord::Smtp;
    const NETWORK_STREAM_NTLM: RequestStreamRecord = RequestStreamRecord::Ntlm;
    const NETWORK_STREAM_KERBEROS: RequestStreamRecord = RequestStreamRecord::Kerberos;
    const NETWORK_STREAM_SSH: RequestStreamRecord = RequestStreamRecord::Ssh;
    const NETWORK_STREAM_DCE_RPC: RequestStreamRecord = RequestStreamRecord::DceRpc;
    const NETWORK_STREAM_FTP: RequestStreamRecord = RequestStreamRecord::Ftp;
    const NETWORK_STREAM_MQTT: RequestStreamRecord = RequestStreamRecord::Mqtt;
    const NETWORK_STREAM_LDAP: RequestStreamRecord = RequestStreamRecord::Ldap;
    const NETWORK_STREAM_TLS: RequestStreamRecord = RequestStreamRecord::Tls;
    const NETWORK_STREAM_SMB: RequestStreamRecord = RequestStreamRecord::Smb;
    const NETWORK_STREAM_NFS: RequestStreamRecord = RequestStreamRecord::Nfs;
    const NETWORK_STREAM_BOOTP: RequestStreamRecord = RequestStreamRecord::Bootp;
    const NETWORK_STREAM_DHCP: RequestStreamRecord = RequestStreamRecord::Dhcp;
    const NETWORK_STREAM_RADIUS: RequestStreamRecord = RequestStreamRecord::Radius;
    const NETWORK_STREAM_FILE_CREATE: RequestStreamRecord = RequestStreamRecord::FileCreate;
    const NETWORK_STREAM_FILE_DELETE: RequestStreamRecord = RequestStreamRecord::FileDelete;
    const NETWORK_STREAM_MALFORMED_DNS: RequestStreamRecord = RequestStreamRecord::MalformedDns;

    const SENSOR_SEMI_SUPERVISED_ONE: &str = "src1";
    const SENSOR_SEMI_SUPERVISED_TWO: &str = "src2";
    const SENSOR_TIME_SERIES_GENERATOR_THREE: &str = "src3";
    const POLICY_ID: u32 = 1;

    let mut harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &mut harness.publish;
    let stream_direct_channels = harness.stream_direct_channels.clone();

    let semi_supervised_msg = RequestSemiSupervisedStream {
        start: 0,
        sensor: Some(vec![
            String::from(SENSOR_SEMI_SUPERVISED_ONE),
            String::from(SENSOR_SEMI_SUPERVISED_TWO),
        ]),
    };
    let time_series_generator_msg = RequestTimeSeriesGeneratorStream {
        start: 0,
        id: POLICY_ID.to_string(),
        src_ip: Some("192.168.4.76".parse::<IpAddr>().unwrap()),
        dst_ip: Some("31.3.245.133".parse::<IpAddr>().unwrap()),
        sensor: Some(String::from(SENSOR_TIME_SERIES_GENERATOR_THREE)),
    };
    let cases = [
        NetworkStreamCase {
            record_type: NETWORK_STREAM_CONN,
            kind: "conn",
            semi_payload: gen_conn_raw_event,
            direct_payload: gen_conn_raw_event,
            insert_db: insert_conn_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_DNS,
            kind: "dns",
            semi_payload: gen_conn_raw_event,
            direct_payload: gen_dns_raw_event,
            insert_db: insert_dns_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_RDP,
            kind: "rdp",
            semi_payload: gen_conn_raw_event,
            direct_payload: gen_rdp_raw_event,
            insert_db: insert_rdp_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_HTTP,
            kind: "http",
            semi_payload: gen_conn_raw_event,
            direct_payload: gen_http_raw_event,
            insert_db: insert_http_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_SMTP,
            kind: "smtp",
            semi_payload: gen_smtp_raw_event,
            direct_payload: gen_smtp_raw_event,
            insert_db: insert_smtp_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_NTLM,
            kind: "ntlm",
            semi_payload: gen_ntlm_raw_event,
            direct_payload: gen_ntlm_raw_event,
            insert_db: insert_ntlm_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_KERBEROS,
            kind: "kerberos",
            semi_payload: gen_kerberos_raw_event,
            direct_payload: gen_kerberos_raw_event,
            insert_db: insert_kerberos_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_SSH,
            kind: "ssh",
            semi_payload: gen_ssh_raw_event,
            direct_payload: gen_ssh_raw_event,
            insert_db: insert_ssh_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_DCE_RPC,
            kind: "dce rpc",
            semi_payload: gen_dce_rpc_raw_event,
            direct_payload: gen_dce_rpc_raw_event,
            insert_db: insert_dce_rpc_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_FTP,
            kind: "ftp",
            semi_payload: gen_ftp_raw_event,
            direct_payload: gen_ftp_raw_event,
            insert_db: insert_ftp_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_MQTT,
            kind: "mqtt",
            semi_payload: gen_mqtt_raw_event,
            direct_payload: gen_mqtt_raw_event,
            insert_db: insert_mqtt_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_LDAP,
            kind: "ldap",
            semi_payload: gen_ldap_raw_event,
            direct_payload: gen_ldap_raw_event,
            insert_db: insert_ldap_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_TLS,
            kind: "tls",
            semi_payload: gen_tls_raw_event,
            direct_payload: gen_tls_raw_event,
            insert_db: insert_tls_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_SMB,
            kind: "smb",
            semi_payload: gen_smb_raw_event,
            direct_payload: gen_smb_raw_event,
            insert_db: insert_smb_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_NFS,
            kind: "nfs",
            semi_payload: gen_nfs_raw_event,
            direct_payload: gen_nfs_raw_event,
            insert_db: insert_nfs_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_BOOTP,
            kind: "bootp",
            semi_payload: gen_bootp_raw_event,
            direct_payload: gen_bootp_raw_event,
            insert_db: insert_bootp_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_DHCP,
            kind: "dhcp",
            semi_payload: gen_dhcp_raw_event,
            direct_payload: gen_dhcp_raw_event,
            insert_db: insert_dhcp_stream,
        },
        NetworkStreamCase {
            record_type: NETWORK_STREAM_RADIUS,
            kind: "radius",
            semi_payload: gen_radius_raw_event,
            direct_payload: gen_radius_raw_event,
            insert_db: insert_radius_stream,
        },
    ];

    for case in cases {
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

        let db_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        let db_payload = (case.insert_db)(db, SENSOR_TIME_SERIES_GENERATOR_THREE, db_timestamp);
        let direct_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
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

    let semi_only_cases = [
        (
            NETWORK_STREAM_MALFORMED_DNS,
            "malformed_dns",
            gen_malformed_dns_raw_event as fn() -> Vec<u8>,
        ),
        (
            NETWORK_STREAM_FILE_CREATE,
            "file_create",
            gen_file_create_raw_event as fn() -> Vec<u8>,
        ),
        (
            NETWORK_STREAM_FILE_DELETE,
            "file_delete",
            gen_file_delete_raw_event as fn() -> Vec<u8>,
        ),
    ];

    for (record_type, kind, payload_fn) in semi_only_cases {
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

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn request_raw_events_sysmon() {
    const SENSOR: &str = "src 1";

    let harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &harness.publish;

    let kinds = [
        ("process_create", "ProcessCreate"),
        ("file_create_time", "FileCreationTimeChanged"),
        ("network_connect", "NetworkConnection"),
        ("process_terminate", "ProcessTerminated"),
        ("image_load", "ImageLoaded"),
        ("file_create", "FileCreate"),
        ("registry_value_set", "RegistryValueSet"),
        ("registry_key_rename", "RegistryKeyValueRename"),
        ("file_create_stream_hash", "FileCreateStreamHash"),
        ("pipe_event", "PipeEvent"),
        ("dns_query", "DnsEvent"),
        ("file_delete", "FileDelete"),
        ("process_tamper", "ProcessTampering"),
        ("file_delete_detected", "FileDeleteDetected"),
    ];

    for (kind, _) in kinds {
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();

        let ser_body = match kind {
            "process_create" => insert_process_create_raw_event(
                &db.process_create_store().unwrap(),
                SENSOR,
                timestamp,
            ),
            "file_create_time" => insert_file_create_time_raw_event(
                &db.file_create_time_store().unwrap(),
                SENSOR,
                timestamp,
            ),
            "network_connect" => insert_network_connect_raw_event(
                &db.network_connect_store().unwrap(),
                SENSOR,
                timestamp,
            ),
            "process_terminate" => insert_process_terminate_raw_event(
                &db.process_terminate_store().unwrap(),
                SENSOR,
                timestamp,
            ),
            "image_load" => {
                insert_image_load_raw_event(&db.image_load_store().unwrap(), SENSOR, timestamp)
            }
            "file_create" => {
                insert_file_create_raw_event(&db.file_create_store().unwrap(), SENSOR, timestamp)
            }
            "registry_value_set" => insert_registry_value_set_raw_event(
                &db.registry_value_set_store().unwrap(),
                SENSOR,
                timestamp,
            ),
            "registry_key_rename" => insert_registry_key_rename_raw_event(
                &db.registry_key_rename_store().unwrap(),
                SENSOR,
                timestamp,
            ),
            "file_create_stream_hash" => insert_file_create_stream_hash_raw_event(
                &db.file_create_stream_hash_store().unwrap(),
                SENSOR,
                timestamp,
            ),
            "pipe_event" => {
                insert_pipe_event_raw_event(&db.pipe_event_store().unwrap(), SENSOR, timestamp)
            }
            "dns_query" => {
                insert_dns_query_raw_event(&db.dns_query_store().unwrap(), SENSOR, timestamp)
            }
            "file_delete" => {
                insert_file_delete_raw_event(&db.file_delete_store().unwrap(), SENSOR, timestamp)
            }
            "process_tamper" => insert_process_tamper_raw_event(
                &db.process_tamper_store().unwrap(),
                SENSOR,
                timestamp,
            ),
            "file_delete_detected" => insert_file_delete_detected_raw_event(
                &db.file_delete_detected_store().unwrap(),
                SENSOR,
                timestamp,
            ),
            _ => unreachable!(),
        };

        let result_data = fetch_raw_data(publish, kind, SENSOR, timestamp).await;
        assert_eq!(result_data.len(), 1, "Failed for kind: {kind}");
        assert_eq!(result_data[0].0, timestamp);
        assert_eq!(&result_data[0].1, SENSOR);
        let expected_resp = match kind {
            "process_create" => bincode::deserialize::<ProcessCreate>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "file_create_time" => bincode::deserialize::<FileCreationTimeChanged>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "network_connect" => bincode::deserialize::<NetworkConnection>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "process_terminate" => bincode::deserialize::<ProcessTerminated>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "image_load" => bincode::deserialize::<ImageLoaded>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "file_create" => bincode::deserialize::<FileCreate>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "registry_value_set" => bincode::deserialize::<RegistryValueSet>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "registry_key_rename" => bincode::deserialize::<RegistryKeyValueRename>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "file_create_stream_hash" => bincode::deserialize::<FileCreateStreamHash>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "pipe_event" => bincode::deserialize::<PipeEvent>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "dns_query" => bincode::deserialize::<DnsEvent>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "file_delete" => bincode::deserialize::<FileDelete>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "process_tamper" => bincode::deserialize::<ProcessTampering>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "file_delete_detected" => bincode::deserialize::<FileDeleteDetected>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            _ => unreachable!(),
        };

        assert_eq!(
            expected_resp,
            bincode::serialize(&Some(result_data[0].clone())).unwrap()
        );
    }
}

#[tokio::test]
async fn request_raw_events_netflow() {
    const SENSOR: &str = "src 1";

    let harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &harness.publish;

    let kinds = ["netflow5", "netflow9"];

    for kind in kinds {
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();

        let ser_body = match kind {
            "netflow5" => {
                insert_netflow5_raw_event(&db.netflow5_store().unwrap(), SENSOR, timestamp)
            }
            "netflow9" => {
                insert_netflow9_raw_event(&db.netflow9_store().unwrap(), SENSOR, timestamp)
            }
            _ => unreachable!(),
        };

        let result_data = fetch_raw_data(publish, kind, SENSOR, timestamp).await;
        assert_eq!(result_data.len(), 1, "Failed for kind: {kind}");
        assert_eq!(result_data[0].0, timestamp);
        assert_eq!(&result_data[0].1, SENSOR);
        let expected_resp = match kind {
            "netflow5" => bincode::deserialize::<Netflow5>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            "netflow9" => bincode::deserialize::<Netflow9>(&ser_body)
                .unwrap()
                .response_data(timestamp, SENSOR)
                .unwrap(),
            _ => unreachable!(),
        };
        assert_eq!(
            expected_resp,
            bincode::serialize(&Some(result_data[0].clone())).unwrap()
        );
    }
}

#[tokio::test]
async fn request_raw_events() {
    const SENSOR: &str = "src 1";
    const KIND: &str = "conn";
    const TIMESTAMP: i64 = 100;

    let harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &harness.publish;

    let conn_store = db.conn_store().unwrap();
    let send_conn_time = TIMESTAMP;
    let conn_raw_data = insert_conn_raw_event(&conn_store, SENSOR, send_conn_time);
    let conn_data = bincode::deserialize::<Conn>(&conn_raw_data).unwrap();
    let raw_data = conn_data.response_data(TIMESTAMP, SENSOR).unwrap();

    let mut result_data = fetch_raw_data(publish, KIND, SENSOR, TIMESTAMP).await;
    assert_eq!(result_data.len(), 1);
    assert_eq!(result_data[0].0, TIMESTAMP);
    assert_eq!(&result_data[0].1, SENSOR);
    assert_eq!(
        raw_data,
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop()).unwrap()
    );
}

#[tokio::test]
async fn request_malformed_dns_raw_events() {
    const SENSOR: &str = "src 1";
    const KIND: &str = "malformed_dns";
    const TIMESTAMP: i64 = 200;

    let harness = setup_test_harness().await;
    let db = &harness.db;
    let publish = &harness.publish;

    let malformed_dns_store = db.malformed_dns_store().unwrap();
    let send_malformed_dns_time = TIMESTAMP;
    let malformed_dns_raw =
        insert_malformed_dns_raw_event(&malformed_dns_store, SENSOR, send_malformed_dns_time);
    let malformed_dns_data: MalformedDns =
        bincode::deserialize::<MalformedDns>(&malformed_dns_raw).unwrap();
    let raw_data = malformed_dns_data.response_data(TIMESTAMP, SENSOR).unwrap();

    let mut result_data = fetch_raw_data(publish, KIND, SENSOR, TIMESTAMP).await;
    assert_eq!(result_data.len(), 1);
    assert_eq!(result_data[0].0, TIMESTAMP);
    assert_eq!(&result_data[0].1, SENSOR);
    assert_eq!(raw_data, bincode::serialize(&result_data.pop()).unwrap());
}

#[tokio::test]
#[serial]
async fn request_range_data_with_protocol_giganto_cluster() {
    init_crypto();
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "ingest src 2";
    const CONN_KIND: &str = "conn";

    let (oneshot_send, oneshot_recv) = tokio::sync::oneshot::channel();

    // spawn node2 publish server
    tokio::spawn(async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = NODE2.build_ingest_sensors();

        let certs = NODE2.build_certs();

        let peers = Arc::new(RwLock::new(HashMap::from([(
            Ipv6Addr::LOCALHOST.to_string(),
            NODE1.peer_info(),
        )])));

        let mut peer_identities = HashSet::new();
        peer_identities.insert(NODE1.peer_identity());
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        let notify_shutdown = Arc::new(Notify::new());

        // prepare data in node2 database
        let conn_store = db.conn_store().unwrap();
        let send_conn_time = Utc::now().timestamp_nanos_opt().unwrap();
        let conn_data = bincode::deserialize::<Conn>(&insert_conn_raw_event(
            &conn_store,
            SENSOR,
            send_conn_time,
        ))
        .unwrap();

        if oneshot_send
            .send(conn_data.response_data(send_conn_time, SENSOR).unwrap())
            .is_err()
        {
            eprintln!("the receiver is dropped");
        }

        let node2_server = Server::new(NODE2.socket_addr_v4(), &certs);
        node2_server
            .run(
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
                certs,
                notify_shutdown,
            )
            .await;
    });

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = build_ingest_sensors();

    let peers = Arc::new(RwLock::new(HashMap::from([(
        "127.0.0.1".to_string(),
        NODE2.peer_info(),
    )])));
    let mut peer_identities = HashSet::new();
    let _addr_to_peers = NODE2.socket_addr_v4();
    peer_identities.insert(NODE2.peer_identity_v4());
    let peer_idents = Arc::new(RwLock::new(peer_identities));

    let certs = build_test_certs();

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));

    let publish = TestClient::new().await;

    let result_data = publish
        .send_range_request::<(i64, String, Vec<u8>)>(
            PUBLISH_RANGE_MESSAGE_CODE,
            build_range_request(SENSOR, CONN_KIND),
        )
        .await;

    let raw_data = if let Ok(v) = oneshot_recv.await {
        v
    } else {
        eprintln!("the sender dropped");
        Vec::new()
    };

    assert_range_result(
        result_data,
        raw_data.as_slice(),
        Conn::response_done().unwrap().as_slice(),
        CONN_KIND,
    );

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[serial]
async fn request_range_data_with_log_giganto_cluster() {
    init_crypto();
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "src2";
    const KIND: &str = "Hello";

    let (oneshot_send, oneshot_recv) = tokio::sync::oneshot::channel();

    // spawn node2 publish server
    tokio::spawn(async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = NODE2.build_ingest_sensors();

        let certs = NODE2.build_certs();

        let peers = Arc::new(RwLock::new(HashMap::from([(
            Ipv6Addr::LOCALHOST.to_string(),
            NODE1.peer_info(),
        )])));

        let mut peer_identities = HashSet::new();
        peer_identities.insert(NODE1.peer_identity());
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        let notify_shutdown = Arc::new(Notify::new());

        // prepare data in node2 database
        let log_store = db.log_store().unwrap();
        let send_log_time = Utc::now().timestamp_nanos_opt().unwrap();
        let log_data = bincode::deserialize::<Log>(&insert_log_raw_event(
            &log_store,
            SENSOR,
            KIND,
            send_log_time,
        ))
        .unwrap();

        if oneshot_send
            .send(log_data.response_data(send_log_time, SENSOR).unwrap())
            .is_err()
        {
            eprintln!("the receiver is dropped");
        }

        let node2_server = Server::new(NODE2.socket_addr_v4(), &certs);
        node2_server
            .run(
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
                certs,
                notify_shutdown,
            )
            .await;
    });

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = build_ingest_sensors();

    let peers = Arc::new(RwLock::new(HashMap::from([(
        "127.0.0.1".to_string(),
        NODE2.peer_info(),
    )])));
    let mut peer_identities = HashSet::new();
    let _addr_to_peers = NODE2.socket_addr_v4();
    peer_identities.insert(NODE2.peer_identity_v4());
    let peer_idents = Arc::new(RwLock::new(peer_identities));

    let certs = build_test_certs();

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;
    let result_data = publish
        .send_range_request::<(i64, String, Vec<u8>)>(
            PUBLISH_RANGE_MESSAGE_CODE,
            build_range_request(SENSOR, KIND),
        )
        .await;

    let raw_data = if let Ok(v) = oneshot_recv.await {
        v
    } else {
        eprintln!("the sender dropped");
        Vec::new()
    };

    assert_range_result(
        result_data,
        raw_data.as_slice(),
        Conn::response_done().unwrap().as_slice(),
        KIND,
    );

    publish.conn.close(0u32.into(), b"publish_log_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[serial]
async fn request_range_data_with_period_time_series_giganto_cluster() {
    init_crypto();
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SAMPLING_POLICY_ID_AS_SENSOR: &str = "ingest src 2";
    const KIND: &str = "timeseries";

    let (oneshot_send, oneshot_recv) = tokio::sync::oneshot::channel();

    // spawn node2 publish server
    tokio::spawn(async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = NODE2.build_ingest_sensors();

        let certs = NODE2.build_certs();

        let peers = Arc::new(RwLock::new(HashMap::from([(
            Ipv6Addr::LOCALHOST.to_string(),
            NODE1.peer_info(),
        )])));

        let mut peer_identities = HashSet::new();
        peer_identities.insert(NODE1.peer_identity());
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        let notify_shutdown = Arc::new(Notify::new());

        // prepare data in node2 database
        let time_series_store = db.periodic_time_series_store().unwrap();
        let send_time_series_time = Utc::now().timestamp_nanos_opt().unwrap();
        let time_series_data =
            bincode::deserialize::<PeriodicTimeSeries>(&insert_periodic_time_series_raw_event(
                &time_series_store,
                SAMPLING_POLICY_ID_AS_SENSOR,
                send_time_series_time,
            ))
            .unwrap();

        if oneshot_send
            .send(
                time_series_data
                    .response_data(send_time_series_time, SAMPLING_POLICY_ID_AS_SENSOR)
                    .unwrap(),
            )
            .is_err()
        {
            eprintln!("the receiver is dropped");
        }

        let node2_server = Server::new(NODE2.socket_addr_v4(), &certs);
        node2_server
            .run(
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
                certs,
                notify_shutdown,
            )
            .await;
    });

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = build_ingest_sensors();

    let peers = Arc::new(RwLock::new(HashMap::from([(
        "127.0.0.1".to_string(),
        NODE2.peer_info(),
    )])));

    let mut peer_identities = HashSet::new();
    let _addr_to_peers = NODE2.socket_addr_v4();
    peer_identities.insert(NODE2.peer_identity_v4());
    let peer_idents = Arc::new(RwLock::new(peer_identities));

    let certs = build_test_certs();

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;
    let result_data = publish
        .send_range_request::<(i64, String, Vec<f64>)>(
            PUBLISH_RANGE_MESSAGE_CODE,
            build_range_request(SAMPLING_POLICY_ID_AS_SENSOR, KIND),
        )
        .await;

    let raw_data = if let Ok(v) = oneshot_recv.await {
        v
    } else {
        eprintln!("the sender dropped");
        Vec::new()
    };

    assert_range_result(
        result_data,
        raw_data.as_slice(),
        PeriodicTimeSeries::response_done().unwrap().as_slice(),
        KIND,
    );

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[serial]
async fn request_raw_events_giganto_cluster() {
    init_crypto();
    const SENSOR: &str = "src 2";
    const KIND: &str = "conn";
    const TIMESTAMP: i64 = 100;

    let (oneshot_send, oneshot_recv) = tokio::sync::oneshot::channel();

    // spawn node2 publish server
    tokio::spawn(async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = NODE2.build_ingest_sensors();

        let certs = NODE2.build_certs();

        let peers = Arc::new(RwLock::new(HashMap::from([(
            Ipv6Addr::LOCALHOST.to_string(),
            NODE1.peer_info(),
        )])));

        let mut peer_identities = HashSet::new();
        peer_identities.insert(NODE1.peer_identity());
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        let notify_shutdown = Arc::new(Notify::new());

        // prepare data in node2 database
        let conn_store = db.conn_store().unwrap();
        let send_conn_time = TIMESTAMP;
        let conn_raw_data = insert_conn_raw_event(&conn_store, SENSOR, send_conn_time);
        let conn_data = bincode::deserialize::<Conn>(&conn_raw_data).unwrap();
        let raw_data = conn_data.response_data(TIMESTAMP, SENSOR).unwrap();

        if oneshot_send.send(raw_data).is_err() {
            eprintln!("the receiver is dropped");
        }

        let node2_server = Server::new(NODE2.socket_addr_v4(), &certs);
        node2_server
            .run(
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
                certs,
                notify_shutdown,
            )
            .await;
    });

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = build_ingest_sensors();

    let peers = Arc::new(RwLock::new(HashMap::from([(
        "127.0.0.1".to_string(),
        NODE2.peer_info(),
    )])));

    let mut peer_identities = HashSet::new();
    let _addr_to_peers = NODE2.socket_addr_v4();
    peer_identities.insert(NODE2.peer_identity_v4());
    let peer_idents = Arc::new(RwLock::new(peer_identities));

    let certs = build_test_certs();

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;

    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let message = RequestRawData {
        kind: String::from(KIND),
        input: vec![(String::from(SENSOR), vec![TIMESTAMP])],
    };

    send_range_data_request(&mut send_pub_req, MessageCode::RawData, message)
        .await
        .unwrap();

    let mut result_data = vec![];
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        if let Some(data) = resp_data {
            result_data.push(data);
        } else {
            break;
        }
    }

    let raw_data = if let Ok(v) = oneshot_recv.await {
        v
    } else {
        eprintln!("the sender dropped");
        Vec::new()
    };

    assert_eq!(result_data.len(), 1);
    assert_eq!(result_data[0].0, TIMESTAMP);
    assert_eq!(&result_data[0].1, SENSOR);
    assert_eq!(
        raw_data,
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop()).unwrap()
    );
}
