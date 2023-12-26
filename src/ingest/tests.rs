use super::Server;
use crate::{
    new_ingest_sources, new_pcap_sources, new_stream_direct_channels,
    storage::{Database, DbOptions},
    to_cert_chain, to_private_key, to_root_cert, Certs,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use chrono::{Duration, Utc};
use giganto_client::{
    connection::client_handshake,
    frame::recv_bytes,
    ingest::{
        log::{Log, OpLog, OpLogLevel},
        network::{
            Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
        },
        receive_ack_timestamp, send_event, send_record_header,
        statistics::Statistics,
        timeseries::PeriodicTimeSeries,
        Packet,
    },
    RawEventKind,
};
use quinn::{Connection, Endpoint};
use std::path::PathBuf;
use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, OnceLock},
};
use tempfile::TempDir;
use tokio::{
    sync::{Mutex, Notify, RwLock},
    task::JoinHandle,
};

fn get_token() -> &'static Mutex<u32> {
    static TOKEN: OnceLock<Mutex<u32>> = OnceLock::new();

    TOKEN.get_or_init(|| Mutex::new(0))
}

const CERT_PATH: &str = "tests/certs/node1/cert.pem";
const KEY_PATH: &str = "tests/certs/node1/key.pem";
const CA_CERT_PATH: &str = "tests/certs/root.pem";
const HOST: &str = "node1";
const TEST_PORT: u16 = 60190;
const PROTOCOL_VERSION: &str = "0.15.2";

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
    let ca_cert_path: Vec<PathBuf> = vec![PathBuf::from(CA_CERT_PATH)];
    let ca_certs = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        ca_certs,
    });

    Server::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT),
        &certs,
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
        .with_client_auth_cert(cert_chain, pv_key)
        .expect("the server root, cert chain or private key are not valid");

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
    endpoint
}

#[tokio::test]
async fn conn() {
    const RAW_EVENT_KIND_CONN: RawEventKind = RawEventKind::Conn;

    let _lock = get_token().lock().await;
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

    send_record_header(&mut send_conn, RAW_EVENT_KIND_CONN)
        .await
        .unwrap();
    send_event(
        &mut send_conn,
        Utc::now().timestamp_nanos_opt().unwrap(),
        conn_body,
    )
    .await
    .unwrap();

    send_conn.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"conn_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn dns() {
    const RAW_EVENT_KIND_DNS: RawEventKind = RawEventKind::Dns;

    let _lock = get_token().lock().await;
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

    send_record_header(&mut send_dns, RAW_EVENT_KIND_DNS)
        .await
        .unwrap();
    send_event(
        &mut send_dns,
        Utc::now().timestamp_nanos_opt().unwrap(),
        dns_body,
    )
    .await
    .unwrap();

    send_dns.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"dns_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn log() {
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_log, _) = client.conn.open_bi().await.expect("failed to open stream");

    let log_body = Log {
        kind: String::from("Hello"),
        log: base64_engine.decode("aGVsbG8gd29ybGQ=").unwrap(),
    };

    send_record_header(&mut send_log, RAW_EVENT_KIND_LOG)
        .await
        .unwrap();
    send_event(
        &mut send_log,
        Utc::now().timestamp_nanos_opt().unwrap(),
        log_body,
    )
    .await
    .unwrap();

    send_log.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn http() {
    const RAW_EVENT_KIND_HTTP: RawEventKind = RawEventKind::Http;
    let _lock = get_token().lock().await;
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
        orig_filenames: Vec::new(),
        orig_mime_types: Vec::new(),
        resp_filenames: Vec::new(),
        resp_mime_types: Vec::new(),
    };

    send_record_header(&mut send_http, RAW_EVENT_KIND_HTTP)
        .await
        .unwrap();
    send_event(
        &mut send_http,
        Utc::now().timestamp_nanos_opt().unwrap(),
        http_body,
    )
    .await
    .unwrap();

    send_http.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"http_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn rdp() {
    const RAW_EVENT_KIND_RDP: RawEventKind = RawEventKind::Rdp;
    let _lock = get_token().lock().await;
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

    send_record_header(&mut send_rdp, RAW_EVENT_KIND_RDP)
        .await
        .unwrap();
    send_event(
        &mut send_rdp,
        Utc::now().timestamp_nanos_opt().unwrap(),
        rdp_body,
    )
    .await
    .unwrap();

    send_rdp.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn periodic_time_series() {
    const RAW_EVENT_KIND_PERIOD_TIME_SERIES: RawEventKind = RawEventKind::PeriodicTimeSeries;
    let _lock = get_token().lock().await;
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
        RAW_EVENT_KIND_PERIOD_TIME_SERIES,
    )
    .await
    .unwrap();
    send_event(
        &mut send_periodic_time_series,
        Utc::now().timestamp_nanos_opt().unwrap(),
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
    const RAW_EVENT_KIND_SMTP: RawEventKind = RawEventKind::Smtp;
    let _lock = get_token().lock().await;
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

    send_record_header(&mut send_smtp, RAW_EVENT_KIND_SMTP)
        .await
        .unwrap();
    send_event(
        &mut send_smtp,
        Utc::now().timestamp_nanos_opt().unwrap(),
        smtp_body,
    )
    .await
    .unwrap();

    send_smtp.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"smtp_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ntlm() {
    const RAW_EVENT_KIND_NTLM: RawEventKind = RawEventKind::Ntlm;
    let _lock = get_token().lock().await;
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

    send_record_header(&mut send_ntlm, RAW_EVENT_KIND_NTLM)
        .await
        .unwrap();
    send_event(
        &mut send_ntlm,
        Utc::now().timestamp_nanos_opt().unwrap(),
        ntlm_body,
    )
    .await
    .unwrap();

    send_ntlm.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ntlm_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn kerberos() {
    const RAW_EVENT_KIND_KERBEROS: RawEventKind = RawEventKind::Kerberos;
    let _lock = get_token().lock().await;
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
    send_event(
        &mut send_kerberos,
        Utc::now().timestamp_nanos_opt().unwrap(),
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
    const RAW_EVENT_KIND_SSH: RawEventKind = RawEventKind::Ssh;
    let _lock = get_token().lock().await;
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

    send_record_header(&mut send_ssh, RAW_EVENT_KIND_SSH)
        .await
        .unwrap();
    send_event(
        &mut send_ssh,
        Utc::now().timestamp_nanos_opt().unwrap(),
        ssh_body,
    )
    .await
    .unwrap();

    send_ssh.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ssh_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn dce_rpc() {
    const RAW_EVENT_KIND_DCE_RPC: RawEventKind = RawEventKind::DceRpc;
    let _lock = get_token().lock().await;
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

    send_record_header(&mut send_dce_rpc, RAW_EVENT_KIND_DCE_RPC)
        .await
        .unwrap();
    send_event(
        &mut send_dce_rpc,
        Utc::now().timestamp_nanos_opt().unwrap(),
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
async fn op_log() {
    const RAW_EVENT_KIND_OPLOG: RawEventKind = RawEventKind::OpLog;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_op_log, _) = client.conn.open_bi().await.expect("failed to open stream");

    let op_log_body = OpLog {
        agent_name: "giganto".to_string(),
        log_level: OpLogLevel::Info,
        contents: "op_log".to_string(),
    };

    send_record_header(&mut send_op_log, RAW_EVENT_KIND_OPLOG)
        .await
        .unwrap();
    send_event(
        &mut send_op_log,
        Utc::now().timestamp_nanos_opt().unwrap(),
        op_log_body,
    )
    .await
    .unwrap();

    send_op_log
        .finish()
        .await
        .expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"oplog_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn packet() {
    const RAW_EVENT_KIND_PACKET: RawEventKind = RawEventKind::Packet;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

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
    send_event(
        &mut send_packet,
        Utc::now().timestamp_nanos_opt().unwrap(),
        packet_body,
    )
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
    const RAW_EVENT_KIND_FTP: RawEventKind = RawEventKind::Ftp;
    let _lock = get_token().lock().await;
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
        file: "ftp_file".to_string(),
        file_size: 100,
        file_id: "1".to_string(),
    };

    send_record_header(&mut send_ftp, RAW_EVENT_KIND_FTP)
        .await
        .unwrap();
    send_event(
        &mut send_ftp,
        Utc::now().timestamp_nanos_opt().unwrap(),
        ftp_body,
    )
    .await
    .unwrap();

    send_ftp.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ftp_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn mqtt() {
    const RAW_EVENT_KIND_MQTT: RawEventKind = RawEventKind::Mqtt;
    let _lock = get_token().lock().await;
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

    send_record_header(&mut send_mqtt, RAW_EVENT_KIND_MQTT)
        .await
        .unwrap();
    send_event(
        &mut send_mqtt,
        Utc::now().timestamp_nanos_opt().unwrap(),
        mqtt_body,
    )
    .await
    .unwrap();

    send_mqtt.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"mqtt_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ldap() {
    const RAW_EVENT_KIND_LDAP: RawEventKind = RawEventKind::Ldap;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_ldap, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_ldap, RAW_EVENT_KIND_LDAP)
        .await
        .unwrap();
    send_event(
        &mut send_ldap,
        Utc::now().timestamp_nanos_opt().unwrap(),
        ldap_body,
    )
    .await
    .unwrap();

    send_ldap.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"ldap_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn tls() {
    const RAW_EVENT_KIND_TLS: RawEventKind = RawEventKind::Tls;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_tls, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_tls, RAW_EVENT_KIND_TLS)
        .await
        .unwrap();
    send_event(
        &mut send_tls,
        Utc::now().timestamp_nanos_opt().unwrap(),
        tls_body,
    )
    .await
    .unwrap();

    send_tls.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"tls_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn smb() {
    const RAW_EVENT_KIND_SMB: RawEventKind = RawEventKind::Smb;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_smb, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_smb, RAW_EVENT_KIND_SMB)
        .await
        .unwrap();
    send_event(
        &mut send_smb,
        Utc::now().timestamp_nanos_opt().unwrap(),
        smb_body,
    )
    .await
    .unwrap();

    send_smb.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"smb_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn nfs() {
    const RAW_EVENT_KIND_NFS: RawEventKind = RawEventKind::Nfs;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_nfs, _) = client.conn.open_bi().await.expect("failed to open stream");

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

    send_record_header(&mut send_nfs, RAW_EVENT_KIND_NFS)
        .await
        .unwrap();
    send_event(
        &mut send_nfs,
        Utc::now().timestamp_nanos_opt().unwrap(),
        nfs_body,
    )
    .await
    .unwrap();

    send_nfs.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"nfs_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn statistics() {
    const RAW_EVENT_KIND_STATISTICS: RawEventKind = RawEventKind::Statistics;
    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_statistics, _) = client.conn.open_bi().await.expect("failed to open stream");

    let statistics_body = Statistics {
        core: 1,
        period: 600,
        stats: vec![(RAW_EVENT_KIND_STATISTICS, 1000, 10001000)],
    };

    send_record_header(&mut send_statistics, RAW_EVENT_KIND_STATISTICS)
        .await
        .unwrap();
    send_event(
        &mut send_statistics,
        Utc::now().timestamp_nanos_opt().unwrap(),
        statistics_body,
    )
    .await
    .unwrap();

    send_statistics
        .finish()
        .await
        .expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"statistics_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn ack_info() {
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_log, mut recv_log) = client.conn.open_bi().await.expect("failed to open stream");

    let log_body = Log {
        kind: String::from("Hello Server I am Log"),
        log: vec![0; 10],
    };

    send_record_header(&mut send_log, RAW_EVENT_KIND_LOG)
        .await
        .unwrap();
    send_event(
        &mut send_log,
        Utc::now().timestamp_nanos_opt().unwrap(),
        log_body,
    )
    .await
    .unwrap();

    let mut last_timestamp: i64 = 0;
    for _ in 0..1023 {
        let log_body: Log = Log {
            kind: String::from("Hello Server I am Log"),
            log: vec![0; 10],
        };

        last_timestamp = Utc::now().timestamp_nanos_opt().unwrap();
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
    const RAW_EVENT_KIND_LOG: RawEventKind = RawEventKind::Log;
    const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
    const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    run_server(db_dir);

    let client = TestClient::new().await;
    let (mut send_log, mut recv_log) = client.conn.open_bi().await.expect("failed to open stream");

    send_record_header(&mut send_log, RAW_EVENT_KIND_LOG)
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
    let pcap_sources = new_pcap_sources();
    let ingest_sources = new_ingest_sources();
    let stream_direct_channels = new_stream_direct_channels();
    tokio::spawn(server().run(
        db,
        pcap_sources,
        ingest_sources,
        stream_direct_channels,
        Arc::new(Notify::new()),
        Some(Arc::new(Notify::new())),
        Arc::new(RwLock::new(1024)),
    ))
}
