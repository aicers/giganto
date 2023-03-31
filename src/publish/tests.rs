use super::Server;
use crate::{
    storage::{Database, DbOptions, RawEventStore},
    to_cert_chain, to_private_key,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use giganto_client::{
    connection::client_handshake,
    ingest::{
        log::Log,
        network::{Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ntlm, Rdp, Smtp, Ssh},
        timeseries::PeriodicTimeSeries,
    },
    publish::{
        range::{
            MessageCode, RequestRange, RequestRawData, RequestTimeSeriesRange, ResponseRangeData,
        },
        receive_crusher_data, receive_crusher_stream_start_message, receive_hog_data,
        receive_hog_stream_start_message, receive_range_data, receive_raw_events,
        send_range_data_request, send_stream_request,
        stream::{NodeType, RequestCrusherStream, RequestHogStream, RequestStreamRecord},
    },
};
use lazy_static::lazy_static;
use quinn::{Connection, Endpoint, SendStream};
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
};
use tokio::sync::{Mutex, Notify, RwLock};

lazy_static! {
    pub(crate) static ref TOKEN: Mutex<u32> = Mutex::new(0);
}

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/root.pem";
const HOST: &str = "localhost";
const TEST_PORT: u16 = 60191;
const PROTOCOL_VERSION: &str = "0.9.0";

struct TestClient {
    send: SendStream,
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
        let (send, _) = client_handshake(&conn, PROTOCOL_VERSION).await.unwrap();
        Self {
            send,
            conn,
            endpoint,
        }
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

fn gen_network_event_key(source: &str, kind: Option<&str>, timestamp: i64) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(source.as_bytes());
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
        duration: tmp_dur.num_nanoseconds().unwrap(),
        service: "-".to_string(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
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

    bincode::serialize(&dns_body).unwrap()
}

fn gen_rdp_raw_event() -> Vec<u8> {
    let rdp_body = Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
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

    bincode::serialize(&http_body).unwrap()
}

fn gen_smtp_raw_event() -> Vec<u8> {
    let smtp_body = Smtp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        mailfrom: "google".to_string(),
        date: "2022-11-28".to_string(),
        from: "safe2@einsis.com".to_string(),
        to: "safe1@einsis.com".to_string(),
        subject: "hello giganto".to_string(),
        agent: "giganto".to_string(),
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
        last_time: 1,
        username: "bly".to_string(),
        hostname: "host".to_string(),
        domainname: "domain".to_string(),
        server_nb_computer_name: "NB".to_string(),
        server_dns_computer_name: "dns".to_string(),
        server_tree_name: "tree".to_string(),
        success: "tf".to_string(),
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

    bincode::serialize(&kerberos_body).unwrap()
}

fn gen_ssh_raw_event() -> Vec<u8> {
    let ssh_body = Ssh {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
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

    bincode::serialize(&ssh_body).unwrap()
}

fn gen_dce_rpc_raw_event() -> Vec<u8> {
    let dce_rpc_body = DceRpc {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
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

    bincode::serialize(&ftp_body).unwrap()
}

fn insert_conn_raw_event(store: &RawEventStore<Conn>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_conn_body = gen_conn_raw_event();
    store.append(&key, &ser_conn_body).unwrap();
    ser_conn_body
}

fn insert_dns_raw_event(store: &RawEventStore<Dns>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_dns_body = gen_dns_raw_event();
    store.append(&key, &ser_dns_body).unwrap();
    ser_dns_body
}

fn insert_rdp_raw_event(store: &RawEventStore<Rdp>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_rdp_body = gen_rdp_raw_event();
    store.append(&key, &ser_rdp_body).unwrap();
    ser_rdp_body
}

fn insert_http_raw_event(store: &RawEventStore<Http>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_http_body = gen_http_raw_event();
    store.append(&key, &ser_http_body).unwrap();
    ser_http_body
}

fn insert_smtp_raw_event(store: &RawEventStore<Smtp>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_smtp_body = gen_smtp_raw_event();
    store.append(&key, &ser_smtp_body).unwrap();
    ser_smtp_body
}

fn insert_ntlm_raw_event(store: &RawEventStore<Ntlm>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_ntlm_body = gen_ntlm_raw_event();
    store.append(&key, &ser_ntlm_body).unwrap();
    ser_ntlm_body
}

fn insert_kerberos_raw_event(
    store: &RawEventStore<Kerberos>,
    source: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_kerberos_body = gen_kerberos_raw_event();
    store.append(&key, &ser_kerberos_body).unwrap();
    ser_kerberos_body
}

fn insert_ssh_raw_event(store: &RawEventStore<Ssh>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_ssh_body = gen_ssh_raw_event();
    store.append(&key, &ser_ssh_body).unwrap();
    ser_ssh_body
}

fn insert_dce_rpc_raw_event(
    store: &RawEventStore<DceRpc>,
    source: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_dce_rpc_body = gen_dce_rpc_raw_event();
    store.append(&key, &ser_dce_rpc_body).unwrap();
    ser_dce_rpc_body
}

fn insert_log_raw_event(
    store: &RawEventStore<Log>,
    source: &str,
    kind: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(source, Some(kind), timestamp);
    let ser_log_body = gen_log_raw_event();
    store.append(&key, &ser_log_body).unwrap();
    ser_log_body
}

fn insert_periodic_time_series_raw_event(
    store: &RawEventStore<PeriodicTimeSeries>,
    source: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_periodic_time_series_body = gen_periodic_time_series_raw_event();
    store.append(&key, &ser_periodic_time_series_body).unwrap();
    ser_periodic_time_series_body
}

fn insert_ftp_raw_event(store: &RawEventStore<Ftp>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, None, timestamp);
    let ser_ftp_body = gen_ftp_raw_event();
    store.append(&key, &ser_ftp_body).unwrap();
    ser_ftp_body
}

#[tokio::test]
async fn request_range_data_with_protocol() {
    const PUBLISH_LOG_MESSAGE_CODE: MessageCode = MessageCode::Log;
    const SOURCE: &str = "einsis";
    const CONN_KIND: &str = "conn";
    const DNS_KIND: &str = "dns";
    const HTTP_KIND: &str = "http";
    const RDP_KIND: &str = "rdp";
    const SMTP_KIND: &str = "smtp";
    const NTLM_KIND: &str = "ntlm";
    const KERBEROS_KIND: &str = "kerberos";
    const SSH_KIND: &str = "ssh";
    const DCE_RPC_KIND: &str = "dce rpc";
    const FTP_KIND: &str = "ftp";

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let packet_sources = Arc::new(RwLock::new(HashMap::new()));
    let stream_direct_channel = Arc::new(RwLock::new(HashMap::new()));
    tokio::spawn(server().run(
        db.clone(),
        packet_sources,
        stream_direct_channel,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;

    // conn protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let conn_store = db.conn_store().unwrap();
        let send_conn_time = Utc::now().timestamp_nanos();
        let conn_data = bincode::deserialize::<Conn>(&insert_conn_raw_event(
            &conn_store,
            SOURCE,
            send_conn_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(CONN_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Conn::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            conn_data.response_data(send_conn_time, SOURCE).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // dns protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let dns_store = db.dns_store().unwrap();
        let send_dns_time = Utc::now().timestamp_nanos();
        let dns_data =
            bincode::deserialize::<Dns>(&insert_dns_raw_event(&dns_store, SOURCE, send_dns_time))
                .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(DNS_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Dns::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            dns_data.response_data(send_dns_time, SOURCE).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // http protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let http_store = db.http_store().unwrap();
        let send_http_time = Utc::now().timestamp_nanos();
        let http_data = bincode::deserialize::<Http>(&insert_http_raw_event(
            &http_store,
            SOURCE,
            send_http_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(HTTP_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Http::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            http_data.response_data(send_http_time, SOURCE).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // rdp protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let rdp_store = db.rdp_store().unwrap();
        let send_rdp_time = Utc::now().timestamp_nanos();
        let rdp_data =
            bincode::deserialize::<Rdp>(&insert_rdp_raw_event(&rdp_store, SOURCE, send_rdp_time))
                .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(RDP_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Rdp::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            rdp_data.response_data(send_rdp_time, SOURCE).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // smtp protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let smtp_store = db.smtp_store().unwrap();
        let send_smtp_time = Utc::now().timestamp_nanos();
        let smtp_data = bincode::deserialize::<Smtp>(&insert_smtp_raw_event(
            &smtp_store,
            SOURCE,
            send_smtp_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(SMTP_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Conn::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            smtp_data.response_data(send_smtp_time, SOURCE).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // ntlm protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let ntlm_store = db.ntlm_store().unwrap();
        let send_ntlm_time = Utc::now().timestamp_nanos();
        let ntlm_data = bincode::deserialize::<Ntlm>(&insert_ntlm_raw_event(
            &ntlm_store,
            SOURCE,
            send_ntlm_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(NTLM_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Ntlm::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            ntlm_data.response_data(send_ntlm_time, SOURCE).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // kerberos protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let kerberos_store = db.kerberos_store().unwrap();
        let send_kerberos_time = Utc::now().timestamp_nanos();
        let kerberos_data = bincode::deserialize::<Kerberos>(&insert_kerberos_raw_event(
            &kerberos_store,
            SOURCE,
            send_kerberos_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(KERBEROS_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Kerberos::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            kerberos_data
                .response_data(send_kerberos_time, SOURCE)
                .unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // ssh protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let ssh_store = db.ssh_store().unwrap();
        let send_ssh_time = Utc::now().timestamp_nanos();
        let ssh_data =
            bincode::deserialize::<Ssh>(&insert_ssh_raw_event(&ssh_store, SOURCE, send_ssh_time))
                .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(SSH_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Ssh::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            ssh_data.response_data(send_ssh_time, SOURCE).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // dce_rpc protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let dce_rpc_store = db.dce_rpc_store().unwrap();
        let send_dce_rpc_time = Utc::now().timestamp_nanos();
        let dce_rpc_data = bincode::deserialize::<DceRpc>(&insert_dce_rpc_raw_event(
            &dce_rpc_store,
            SOURCE,
            send_dce_rpc_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(DCE_RPC_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            DceRpc::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            dce_rpc_data
                .response_data(send_dce_rpc_time, SOURCE)
                .unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // ftp protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let ftp_store = db.ftp_store().unwrap();
        let send_ftp_time = Utc::now().timestamp_nanos();
        let ftp_data =
            bincode::deserialize::<Ftp>(&insert_ftp_raw_event(&ftp_store, SOURCE, send_ftp_time))
                .unwrap();

        let start = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("vaild date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            source: String::from(SOURCE),
            kind: String::from(FTP_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            DceRpc::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            ftp_data.response_data(send_ftp_time, SOURCE).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    publish.conn.close(0u32.into(), b"publish_protocol_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_range_data_with_log() {
    const PUBLISH_LOG_MESSAGE_CODE: MessageCode = MessageCode::Log;
    const SOURCE: &str = "einsis";
    const KIND: &str = "Hello";

    #[derive(Serialize)]
    struct RequestRangeMessage {
        source: String,
        kind: String,
        start: i64,
        end: i64,
        count: usize,
    }

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let packet_sources = Arc::new(RwLock::new(HashMap::new()));
    let stream_direct_channel = Arc::new(RwLock::new(HashMap::new()));
    tokio::spawn(server().run(
        db.clone(),
        packet_sources,
        stream_direct_channel,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;
    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let log_store = db.log_store().unwrap();
    let send_log_time = Utc::now().timestamp_nanos();
    let log_data = bincode::deserialize::<Log>(&insert_log_raw_event(
        &log_store,
        SOURCE,
        KIND,
        send_log_time,
    ))
    .unwrap();

    let start = DateTime::<Utc>::from_utc(
        NaiveDate::from_ymd_opt(1970, 1, 1)
            .expect("vaild date")
            .and_hms_opt(00, 00, 00)
            .expect("valid time"),
        Utc,
    );
    let end = DateTime::<Utc>::from_utc(
        NaiveDate::from_ymd_opt(2050, 12, 31)
            .expect("valid date")
            .and_hms_opt(23, 59, 59)
            .expect("valid time"),
        Utc,
    );
    let message = RequestRange {
        source: String::from(SOURCE),
        kind: String::from(KIND),
        start: start.timestamp_nanos(),
        end: end.timestamp_nanos(),
        count: 5,
    };

    send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
        .await
        .unwrap();

    let mut result_data = Vec::new();
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        result_data.push(resp_data.clone());
        if resp_data.is_none() {
            break;
        }
    }

    assert_eq!(
        Conn::response_done().unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap()).unwrap()
    );
    assert_eq!(
        log_data.response_data(send_log_time, SOURCE).unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap()).unwrap()
    );

    publish.conn.close(0u32.into(), b"publish_log_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_range_data_with_period_time_series() {
    const PUBLISH_LOG_MESSAGE_CODE: MessageCode = MessageCode::PeriodicTimeSeries;
    const SAMPLING_POLICY_ID: &str = "policy_one";

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let packet_sources = Arc::new(RwLock::new(HashMap::new()));
    let stream_direct_channel = Arc::new(RwLock::new(HashMap::new()));
    tokio::spawn(server().run(
        db.clone(),
        packet_sources,
        stream_direct_channel,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;
    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let time_series_store = db.periodic_time_series_store().unwrap();
    let send_time_series_time = Utc::now().timestamp_nanos();
    let time_series_data =
        bincode::deserialize::<PeriodicTimeSeries>(&insert_periodic_time_series_raw_event(
            &time_series_store,
            SAMPLING_POLICY_ID,
            send_time_series_time,
        ))
        .unwrap();

    let start = DateTime::<Utc>::from_utc(
        NaiveDate::from_ymd_opt(1970, 1, 1)
            .expect("vaild date")
            .and_hms_opt(00, 00, 00)
            .expect("valid time"),
        Utc,
    );
    let end = DateTime::<Utc>::from_utc(
        NaiveDate::from_ymd_opt(2050, 12, 31)
            .expect("valid date")
            .and_hms_opt(23, 59, 59)
            .expect("valid time"),
        Utc,
    );
    let message = RequestTimeSeriesRange {
        source: String::from(SAMPLING_POLICY_ID),
        start: start.timestamp_nanos(),
        end: end.timestamp_nanos(),
        count: 5,
    };

    send_range_data_request(&mut send_pub_req, PUBLISH_LOG_MESSAGE_CODE, message)
        .await
        .unwrap();

    let mut result_data = Vec::new();
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<f64>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        result_data.push(resp_data.clone());
        if resp_data.is_none() {
            break;
        }
    }

    assert_eq!(
        PeriodicTimeSeries::response_done().unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<f64>)>>(&result_data.pop().unwrap()).unwrap()
    );
    assert_eq!(
        time_series_data
            .response_data(send_time_series_time, SAMPLING_POLICY_ID)
            .unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<f64>)>>(&result_data.pop().unwrap()).unwrap()
    );

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_network_event_stream() {
    use crate::ingest::NetworkKey;
    use crate::publish::send_direct_stream;

    const HOG_TYPE: NodeType = NodeType::Hog;
    const CRUSHER_TYPE: NodeType = NodeType::Crusher;
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

    const SOURCE_HOG_ONE: &str = "src1";
    const SOURCE_HOG_TWO: &str = "src2";
    const SOURCE_CRUSHER_THREE: &str = "src3";
    const POLICY_ID: u32 = 1;

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();

    let hog_msg = RequestHogStream {
        start: 0,
        source: Some(vec![
            String::from(SOURCE_HOG_ONE),
            String::from(SOURCE_HOG_TWO),
        ]),
    };
    let crusher_msg = RequestCrusherStream {
        start: 0,
        id: POLICY_ID.to_string(),
        src_ip: Some("192.168.4.76".parse::<IpAddr>().unwrap()),
        dst_ip: Some("31.3.245.133".parse::<IpAddr>().unwrap()),
        source: Some(String::from(SOURCE_CRUSHER_THREE)),
    };
    let packet_sources = Arc::new(RwLock::new(HashMap::new()));
    let stream_direct_channel = Arc::new(RwLock::new(HashMap::new()));
    tokio::spawn(server().run(
        db.clone(),
        packet_sources,
        stream_direct_channel.clone(),
        Arc::new(Notify::new()),
    ));
    let mut publish = TestClient::new().await;

    {
        let conn_store = db.conn_store().unwrap();

        // direct conn network event for hog (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_CONN,
            HOG_TYPE,
            hog_msg.clone(),
        )
        .await
        .unwrap();

        let send_conn_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let conn_start_msg =
            receive_hog_stream_start_message(&mut (*send_conn_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(conn_start_msg, NETWORK_STREAM_CONN);

        let send_conn_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "conn");
        let conn_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &conn_data,
            send_conn_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_conn_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(conn_data, recv_data[20..]);

        let send_conn_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "conn");
        let conn_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &conn_data,
            send_conn_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();
        let recv_data = receive_hog_data(&mut (*send_conn_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(conn_data, recv_data[20..]);

        // database conn network event for crusher
        let send_conn_time = Utc::now().timestamp_nanos();
        let conn_data = insert_conn_raw_event(&conn_store, SOURCE_CRUSHER_THREE, send_conn_time);
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_CONN,
            CRUSHER_TYPE,
            crusher_msg.clone(),
        )
        .await
        .unwrap();

        let send_conn_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let conn_start_msg =
            receive_crusher_stream_start_message(&mut (*send_conn_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(conn_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_conn_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_conn_time, recv_timestamp);
        assert_eq!(conn_data, recv_data);

        // direct conn network event for crusher
        let send_conn_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "conn");
        let conn_data = gen_conn_raw_event();

        send_direct_stream(
            &key,
            &conn_data,
            send_conn_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_conn_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_conn_time, recv_timestamp);
        assert_eq!(conn_data, recv_data);
    }

    {
        let dns_store = db.dns_store().unwrap();

        // direct dns network event for hog (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DNS,
            HOG_TYPE,
            hog_msg.clone(),
        )
        .await
        .unwrap();

        let send_dns_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let dns_start_msg = receive_hog_stream_start_message(&mut (*send_dns_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(dns_start_msg, NETWORK_STREAM_DNS);

        let send_dns_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "dns");
        let dns_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &dns_data,
            send_dns_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_dns_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(dns_data, recv_data[20..]);

        let send_dns_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "dns");
        let dns_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &dns_data,
            send_dns_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_dns_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(dns_data, recv_data[20..]);

        // database dns network event for crusher
        let send_dns_time = Utc::now().timestamp_nanos();
        let dns_data = insert_dns_raw_event(&dns_store, SOURCE_CRUSHER_THREE, send_dns_time);

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DNS,
            CRUSHER_TYPE,
            crusher_msg.clone(),
        )
        .await
        .unwrap();

        let send_dns_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let dns_start_msg =
            receive_crusher_stream_start_message(&mut (*send_dns_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(dns_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_dns_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_dns_time, recv_timestamp);
        assert_eq!(dns_data, recv_data);

        // direct dns network event for crusher
        let send_dns_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "dns");
        let dns_data = gen_dns_raw_event();

        send_direct_stream(
            &key,
            &dns_data,
            send_dns_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_dns_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_dns_time, recv_timestamp);
        assert_eq!(dns_data, recv_data);
    }

    {
        let rdp_store = db.rdp_store().unwrap();

        // direct rdp network event for hog (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_RDP,
            HOG_TYPE,
            hog_msg.clone(),
        )
        .await
        .unwrap();

        let send_rdp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let rdp_start_msg = receive_hog_stream_start_message(&mut (*send_rdp_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(rdp_start_msg, NETWORK_STREAM_RDP);

        let send_rdp_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "rdp");
        let rdp_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &rdp_data,
            send_rdp_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_rdp_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(rdp_data, recv_data[20..]);

        let send_rdp_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "rdp");
        let rdp_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &rdp_data,
            send_rdp_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_rdp_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(rdp_data, recv_data[20..]);

        // database rdp network event for crusher
        let send_rdp_time = Utc::now().timestamp_nanos();
        let rdp_data = insert_rdp_raw_event(&rdp_store, SOURCE_CRUSHER_THREE, send_rdp_time);

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_RDP,
            CRUSHER_TYPE,
            crusher_msg.clone(),
        )
        .await
        .unwrap();

        let send_rdp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let rdp_start_msg =
            receive_crusher_stream_start_message(&mut (*send_rdp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(rdp_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_rdp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_rdp_time, recv_timestamp);
        assert_eq!(rdp_data, recv_data);

        // direct rdp network event for crusher
        let send_rdp_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "rdp");
        let rdp_data = gen_rdp_raw_event();
        send_direct_stream(
            &key,
            &rdp_data,
            send_rdp_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_rdp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_rdp_time, recv_timestamp);
        assert_eq!(rdp_data, recv_data);
    }

    {
        let http_store = db.http_store().unwrap();

        // direct http network event for hog (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_HTTP,
            HOG_TYPE,
            hog_msg.clone(),
        )
        .await
        .unwrap();

        let send_http_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let http_start_msg =
            receive_hog_stream_start_message(&mut (*send_http_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(http_start_msg, NETWORK_STREAM_HTTP);

        let send_http_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "http");
        let http_data = gen_conn_raw_event();

        send_direct_stream(
            &key,
            &http_data,
            send_http_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_http_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(http_data, recv_data[20..]);

        let send_http_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "http");
        let http_data = gen_conn_raw_event();

        send_direct_stream(
            &key,
            &http_data,
            send_http_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_http_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(http_data, recv_data[20..]);

        // database http network event for crusher
        let send_http_time = Utc::now().timestamp_nanos();
        let http_data = insert_http_raw_event(&http_store, SOURCE_CRUSHER_THREE, send_http_time);

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_HTTP,
            CRUSHER_TYPE,
            crusher_msg.clone(),
        )
        .await
        .unwrap();

        let send_http_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let http_start_msg =
            receive_crusher_stream_start_message(&mut (*send_http_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(http_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_http_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_http_time, recv_timestamp);
        assert_eq!(http_data, recv_data);

        // direct http network event for crusher
        let send_http_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "http");
        let http_data = gen_http_raw_event();
        send_direct_stream(
            &key,
            &http_data,
            send_http_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_http_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_http_time, recv_timestamp);
        assert_eq!(http_data, recv_data);
    }

    {
        let smtp_store = db.smtp_store().unwrap();

        // direct smtp network event for hog (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SMTP,
            HOG_TYPE,
            hog_msg.clone(),
        )
        .await
        .unwrap();

        let send_smtp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let smtp_start_msg =
            receive_hog_stream_start_message(&mut (*send_smtp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(smtp_start_msg, NETWORK_STREAM_SMTP);

        let send_smtp_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "smtp");
        let smtp_data = gen_smtp_raw_event();

        send_direct_stream(
            &key,
            &smtp_data,
            send_smtp_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_smtp_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(smtp_data, recv_data[20..]);

        let send_smtp_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "smtp");
        let smtp_data = gen_smtp_raw_event();

        send_direct_stream(
            &key,
            &smtp_data,
            send_smtp_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_smtp_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(smtp_data, recv_data[20..]);

        // database smtp network event for crusher
        let send_smtp_time = Utc::now().timestamp_nanos();
        let smtp_data = insert_smtp_raw_event(&smtp_store, SOURCE_CRUSHER_THREE, send_smtp_time);

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SMTP,
            CRUSHER_TYPE,
            crusher_msg.clone(),
        )
        .await
        .unwrap();

        let send_smtp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let smtp_start_msg =
            receive_crusher_stream_start_message(&mut (*send_smtp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(smtp_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_smtp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_smtp_time, recv_timestamp);
        assert_eq!(smtp_data, recv_data);

        // direct smtp network event for crusher
        let send_smtp_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "smtp");
        let smtp_data = gen_smtp_raw_event();
        send_direct_stream(
            &key,
            &smtp_data,
            send_smtp_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_smtp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_smtp_time, recv_timestamp);
        assert_eq!(smtp_data, recv_data);
    }

    {
        let ntlm_store = db.ntlm_store().unwrap();

        // direct ntlm network event for hog (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_NTLM,
            HOG_TYPE,
            hog_msg.clone(),
        )
        .await
        .unwrap();

        let send_ntlm_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let ntlm_start_msg =
            receive_hog_stream_start_message(&mut (*send_ntlm_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(ntlm_start_msg, NETWORK_STREAM_NTLM);

        let send_ntlm_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "ntlm");
        let ntlm_data = gen_ntlm_raw_event();

        send_direct_stream(
            &key,
            &ntlm_data,
            send_ntlm_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_ntlm_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(ntlm_data, recv_data[20..]);

        let send_ntlm_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "ntlm");
        let ntlm_data = gen_ntlm_raw_event();

        send_direct_stream(
            &key,
            &ntlm_data,
            send_ntlm_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_ntlm_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(ntlm_data, recv_data[20..]);

        // database ntlm network event for crusher
        let send_ntlm_time = Utc::now().timestamp_nanos();
        let ntlm_data = insert_ntlm_raw_event(&ntlm_store, SOURCE_CRUSHER_THREE, send_ntlm_time);

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_NTLM,
            CRUSHER_TYPE,
            crusher_msg.clone(),
        )
        .await
        .unwrap();

        let send_ntlm_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let ntlm_start_msg =
            receive_crusher_stream_start_message(&mut (*send_ntlm_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(ntlm_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_ntlm_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_ntlm_time, recv_timestamp);
        assert_eq!(ntlm_data, recv_data);

        //direct ntlm network event for crusher
        let send_ntlm_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "ntlm");
        let ntlm_data = gen_ntlm_raw_event();
        send_direct_stream(
            &key,
            &ntlm_data,
            send_ntlm_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_ntlm_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_ntlm_time, recv_timestamp);
        assert_eq!(ntlm_data, recv_data);
    }

    {
        let kerberos_store = db.kerberos_store().unwrap();

        // direct kerberos network event for hog (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_KERBEROS,
            HOG_TYPE,
            hog_msg.clone(),
        )
        .await
        .unwrap();

        let send_kerberos_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let kerberos_start_msg =
            receive_hog_stream_start_message(&mut (*send_kerberos_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(kerberos_start_msg, NETWORK_STREAM_KERBEROS);

        let send_kerberos_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "kerberos");
        let kerberos_data = gen_kerberos_raw_event();

        send_direct_stream(
            &key,
            &kerberos_data,
            send_kerberos_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_kerberos_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(kerberos_data, recv_data[20..]);

        let send_kerberos_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "kerberos");
        let kerberos_data = gen_kerberos_raw_event();

        send_direct_stream(
            &key,
            &kerberos_data,
            send_kerberos_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_kerberos_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(kerberos_data, recv_data[20..]);

        // database kerberos network event for crusher
        let send_kerberos_time = Utc::now().timestamp_nanos();
        let kerberos_data =
            insert_kerberos_raw_event(&kerberos_store, SOURCE_CRUSHER_THREE, send_kerberos_time);

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_KERBEROS,
            CRUSHER_TYPE,
            crusher_msg.clone(),
        )
        .await
        .unwrap();

        let send_kerberos_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let kerberos_start_msg =
            receive_crusher_stream_start_message(&mut (*send_kerberos_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(kerberos_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_kerberos_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_kerberos_time, recv_timestamp);
        assert_eq!(kerberos_data, recv_data);

        //direct kerberos network event for crusher
        let send_kerberos_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "kerberos");
        let kerberos_data = gen_kerberos_raw_event();
        send_direct_stream(
            &key,
            &kerberos_data,
            send_kerberos_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_kerberos_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_kerberos_time, recv_timestamp);
        assert_eq!(kerberos_data, recv_data);
    }

    {
        let ssh_store = db.ssh_store().unwrap();

        // direct ssh network event for hog (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SSH,
            HOG_TYPE,
            hog_msg.clone(),
        )
        .await
        .unwrap();

        let send_ssh_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let ssh_start_msg = receive_hog_stream_start_message(&mut (*send_ssh_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(ssh_start_msg, NETWORK_STREAM_SSH);

        let send_ssh_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "ssh");
        let ssh_data = gen_ssh_raw_event();

        send_direct_stream(
            &key,
            &ssh_data,
            send_ssh_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_ssh_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(ssh_data, recv_data[20..]);

        let send_ssh_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "ssh");
        let ssh_data = gen_ssh_raw_event();

        send_direct_stream(
            &key,
            &ssh_data,
            send_ssh_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_ssh_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(ssh_data, recv_data[20..]);

        // database ssh network event for crusher
        let send_ssh_time = Utc::now().timestamp_nanos();
        let ssh_data = insert_ssh_raw_event(&ssh_store, SOURCE_CRUSHER_THREE, send_ssh_time);

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SSH,
            CRUSHER_TYPE,
            crusher_msg.clone(),
        )
        .await
        .unwrap();

        let send_ssh_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let ssh_start_msg =
            receive_crusher_stream_start_message(&mut (*send_ssh_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(ssh_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_ssh_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_ssh_time, recv_timestamp);
        assert_eq!(ssh_data, recv_data);

        //direct ssh network event for crusher
        let send_ssh_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "ssh");
        let ssh_data = gen_ssh_raw_event();
        send_direct_stream(
            &key,
            &ssh_data,
            send_ssh_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_ssh_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_ssh_time, recv_timestamp);
        assert_eq!(ssh_data, recv_data);
    }

    {
        let dce_rpc_store = db.dce_rpc_store().unwrap();

        // direct dce_rpc network event for hog (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DCE_RPC,
            HOG_TYPE,
            hog_msg.clone(),
        )
        .await
        .unwrap();

        let send_dce_rpc_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let dce_rpc_start_msg =
            receive_hog_stream_start_message(&mut (*send_dce_rpc_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(dce_rpc_start_msg, NETWORK_STREAM_DCE_RPC);

        let send_dce_rpc_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "dce rpc");
        let dce_rpc_data = gen_dce_rpc_raw_event();

        send_direct_stream(
            &key,
            &dce_rpc_data,
            send_dce_rpc_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_dce_rpc_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(dce_rpc_data, recv_data[20..]);

        let send_dce_rpc_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "dce rpc");
        let dce_rpc_data = gen_dce_rpc_raw_event();

        send_direct_stream(
            &key,
            &dce_rpc_data,
            send_dce_rpc_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_dce_rpc_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(dce_rpc_data, recv_data[20..]);

        // database dce_rpc network event for crusher
        let send_dce_rpc_time = Utc::now().timestamp_nanos();
        let dce_rpc_data =
            insert_dce_rpc_raw_event(&dce_rpc_store, SOURCE_CRUSHER_THREE, send_dce_rpc_time);

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DCE_RPC,
            CRUSHER_TYPE,
            crusher_msg.clone(),
        )
        .await
        .unwrap();

        let send_dce_rpc_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let dce_rpc_start_msg =
            receive_crusher_stream_start_message(&mut (*send_dce_rpc_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(dce_rpc_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_dce_rpc_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_dce_rpc_time, recv_timestamp);
        assert_eq!(dce_rpc_data, recv_data);

        //direct dce_rpc network event for crusher
        let send_dce_rpc_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "dce rpc");
        let dce_rpc_data = gen_dce_rpc_raw_event();
        send_direct_stream(
            &key,
            &dce_rpc_data,
            send_dce_rpc_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_dce_rpc_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_dce_rpc_time, recv_timestamp);
        assert_eq!(dce_rpc_data, recv_data);
    }

    {
        let ftp_store = db.ftp_store().unwrap();

        // direct ftp network event for hog (src1,src2)
        send_stream_request(&mut publish.send, NETWORK_STREAM_FTP, HOG_TYPE, hog_msg)
            .await
            .unwrap();

        let send_ftp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let ftp_start_msg = receive_hog_stream_start_message(&mut (*send_ftp_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(ftp_start_msg, NETWORK_STREAM_FTP);

        let send_ftp_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_ONE, "ftp");
        let ftp_data = gen_ftp_raw_event();

        send_direct_stream(
            &key,
            &ftp_data,
            send_ftp_time,
            SOURCE_HOG_ONE,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_ftp_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(ftp_data, recv_data[20..]);

        let send_ftp_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_HOG_TWO, "ftp");
        let ftp_data = gen_dce_rpc_raw_event();

        send_direct_stream(
            &key,
            &ftp_data,
            send_ftp_time,
            SOURCE_HOG_TWO,
            stream_direct_channel.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_hog_data(&mut (*send_ftp_stream.borrow_mut()))
            .await
            .unwrap();
        assert_eq!(ftp_data, recv_data[20..]);

        // database ftp network event for crusher
        let send_ftp_time = Utc::now().timestamp_nanos();
        let ftp_data = insert_ftp_raw_event(&ftp_store, SOURCE_CRUSHER_THREE, send_ftp_time);

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_FTP,
            CRUSHER_TYPE,
            crusher_msg,
        )
        .await
        .unwrap();

        let send_ftp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));

        let ftp_start_msg =
            receive_crusher_stream_start_message(&mut (*send_ftp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(ftp_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_ftp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_ftp_time, recv_timestamp);
        assert_eq!(ftp_data, recv_data);

        //direct ftp network event for crusher
        let send_ftp_time = Utc::now().timestamp_nanos();
        let key = NetworkKey::new(SOURCE_CRUSHER_THREE, "ftp");
        let ftp_data = gen_ftp_raw_event();
        send_direct_stream(
            &key,
            &ftp_data,
            send_ftp_time,
            SOURCE_CRUSHER_THREE,
            stream_direct_channel,
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_crusher_data(&mut (*send_ftp_stream.borrow_mut()))
                .await
                .unwrap();
        assert_eq!(send_ftp_time, recv_timestamp);
        assert_eq!(ftp_data, recv_data);
    }

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_raw_events() {
    const PUBLISH_RAW_DATA_MESSAGE_CODE: MessageCode = MessageCode::RawData;
    const SOURCE: &str = "src 1";
    const KIND: &str = "conn";

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let packet_sources = Arc::new(RwLock::new(HashMap::new()));
    let stream_direct_channel = Arc::new(RwLock::new(HashMap::new()));
    tokio::spawn(server().run(
        db.clone(),
        packet_sources,
        stream_direct_channel,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;

    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let conn_store = db.conn_store().unwrap();
    let send_conn_time = 1;
    let conn_raw_data = insert_conn_raw_event(&conn_store, SOURCE, send_conn_time);

    let message = RequestRawData {
        kind: String::from(KIND),
        input: vec![(String::from(SOURCE), vec![1])],
    };

    send_range_data_request(&mut send_pub_req, PUBLISH_RAW_DATA_MESSAGE_CODE, message)
        .await
        .unwrap();

    let resp_data = receive_raw_events(&mut recv_pub_resp).await.unwrap();

    assert_eq!(&resp_data[0].0, "src 1");
    assert_eq!(resp_data[0].1, conn_raw_data);
}
