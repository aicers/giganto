use super::Server;
use crate::ingestion::{
    Conn, DceRpc, Dns, Http, Kerberos, Log, Ntlm, PeriodicTimeSeries, Rdp, Smtp, Ssh,
};
use crate::{
    storage::{Database, RawEventStore},
    to_cert_chain, to_private_key,
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use lazy_static::lazy_static;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use serde::Serialize;
use std::{
    cell::RefCell,
    fs, mem,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
};
use tokio::sync::Mutex;

lazy_static! {
    pub(crate) static ref TOKEN: Mutex<u32> = Mutex::new(0);
}

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/root.pem";
const HOST: &str = "localhost";
const TEST_PORT: u16 = 60191;
const PROTOCOL_VERSION: &str = "0.7.0-alpha.1";

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
        let send = connection_handshake(&conn).await;
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

async fn connection_handshake(conn: &Connection) -> SendStream {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .expect("Failed to open bidirection channel");
    let version_len = u64::try_from(PROTOCOL_VERSION.len())
        .expect("less than u64::MAX")
        .to_le_bytes();

    let mut handshake_buf = Vec::with_capacity(version_len.len() + PROTOCOL_VERSION.len());
    handshake_buf.extend(version_len);
    handshake_buf.extend(PROTOCOL_VERSION.as_bytes());
    send.write_all(&handshake_buf)
        .await
        .expect("Failed to send handshake data");

    let mut resp_len_buf = [0; std::mem::size_of::<u64>()];
    recv.read_exact(&mut resp_len_buf)
        .await
        .expect("Failed to receive handshake data");
    let len = u64::from_le_bytes(resp_len_buf);

    let mut resp_buf = Vec::new();
    resp_buf.resize(len.try_into().expect("Failed to convert data type"), 0);
    recv.read_exact(resp_buf.as_mut_slice()).await.unwrap();

    bincode::deserialize::<Option<&str>>(&resp_buf)
        .expect("Failed to deserialize recv data")
        .expect("Incompatible version");
    send
}

async fn send_request_network_stream(
    send: &mut SendStream,
    msg_code: u32,
    node_type: u8,
    mut msg: Vec<u8>,
) {
    let mut req_data: Vec<u8> = Vec::new();
    req_data.append(&mut node_type.to_le_bytes().to_vec());
    req_data.append(&mut msg_code.to_le_bytes().to_vec());
    req_data.append(&mut (msg.len() as u32).to_le_bytes().to_vec());
    req_data.append(&mut msg);

    send.write_all(&req_data)
        .await
        .expect("failed to send network stream");
}

async fn recv_network_stream(recv: Arc<RefCell<RecvStream>>) -> (i64, Vec<u8>) {
    let mut ts_buf = [0; mem::size_of::<u64>()];
    let mut len_buf = [0; mem::size_of::<u32>()];
    let mut body_buf = Vec::new();

    recv.borrow_mut().read_exact(&mut ts_buf).await.unwrap();
    let timestamp = i64::from_le_bytes(ts_buf);

    recv.borrow_mut().read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_le_bytes(len_buf) as usize;

    body_buf.resize(len, 0);
    recv.borrow_mut()
        .read_exact(body_buf.as_mut_slice())
        .await
        .unwrap();
    (timestamp, body_buf)
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
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 6,
        duration: tmp_dur.num_nanoseconds().unwrap(),
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
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 17,
        query:
            "Hello ServerHello ServerHello ServerHello ServerHello ServerHello ServerHello Server"
                .to_string(),
        answer: vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
    };

    bincode::serialize(&dns_body).unwrap()
}

fn gen_rdp_raw_event() -> Vec<u8> {
    let rdp_body = Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        cookie: "rdp_test".to_string(),
    };

    bincode::serialize(&rdp_body).unwrap()
}

fn gen_http_raw_event() -> Vec<u8> {
    let http_body = Http {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        method: "POST".to_string(),
        host: "einsis".to_string(),
        uri: "/einsis.gif".to_string(),
        referrer: "einsis.com".to_string(),
        user_agent: "giganto".to_string(),
        status_code: 200,
    };

    bincode::serialize(&http_body).unwrap()
}

fn gen_smtp_raw_event() -> Vec<u8> {
    let smtp_body = Smtp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
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
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
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
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
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
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
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
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
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
        log: base64::decode("aGVsbG8gd29ybGQ=").unwrap(),
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

#[test]
fn protocol_version() {
    use semver::{Version, VersionReq};

    let compat_versions = ["0.7.0-alpha.1"];
    let incompat_versions = ["0.6.0", "0.8.0"];

    let req = VersionReq::parse(super::PUBLISH_VERSION_REQ).unwrap();
    for version in &compat_versions {
        assert!(req.matches(&Version::parse(version).unwrap()));
    }
    for version in &incompat_versions {
        assert!(!req.matches(&Version::parse(version).unwrap()));
    }
}

#[tokio::test]
async fn request_publish_protocol() {
    use crate::publish::PubMessage;

    const PUBLISH_LOG_MESSAGE_CODE: u32 = 0x00;
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

    #[derive(Serialize)]
    struct Message {
        source: String,
        kind: String,
        start: i64,
        end: i64,
        count: usize,
    }

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    tokio::spawn(server().run(db.clone()));
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
        let message = Message {
            source: String::from(SOURCE),
            kind: String::from(CONN_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        let mut message_buf = bincode::serialize(&message).unwrap();

        let mut request_buf: Vec<u8> = Vec::new();
        request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
        request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
        request_buf.append(&mut message_buf);

        send_pub_req
            .write_all(&request_buf)
            .await
            .expect("failed to send request");

        let mut result_data: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut len_buf = [0; std::mem::size_of::<u32>()];
            recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf);

            let mut resp_data = vec![0; len.try_into().unwrap()];
            recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
            let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
            result_data.push(resp_data);
            if resp.is_none() {
                break;
            }
        }

        assert_eq!(Conn::done().unwrap(), result_data.pop().unwrap());
        assert_eq!(
            conn_data.message(send_conn_time, SOURCE).unwrap(),
            result_data.pop().unwrap()
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
        let message = Message {
            source: String::from(SOURCE),
            kind: String::from(DNS_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        let mut message_buf = bincode::serialize(&message).unwrap();

        let mut request_buf: Vec<u8> = Vec::new();
        request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
        request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
        request_buf.append(&mut message_buf);

        send_pub_req
            .write_all(&request_buf)
            .await
            .expect("failed to send request");

        let mut result_data: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut len_buf = [0; std::mem::size_of::<u32>()];
            recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf);

            let mut resp_data = vec![0; len.try_into().unwrap()];
            recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
            let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
            result_data.push(resp_data);
            if resp.is_none() {
                break;
            }
        }

        assert_eq!(Dns::done().unwrap(), result_data.pop().unwrap());
        assert_eq!(
            dns_data.message(send_dns_time, SOURCE).unwrap(),
            result_data.pop().unwrap()
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
        let message = Message {
            source: String::from(SOURCE),
            kind: String::from(HTTP_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        let mut message_buf = bincode::serialize(&message).unwrap();

        let mut request_buf: Vec<u8> = Vec::new();
        request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
        request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
        request_buf.append(&mut message_buf);

        send_pub_req
            .write_all(&request_buf)
            .await
            .expect("failed to send request");

        let mut result_data: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut len_buf = [0; std::mem::size_of::<u32>()];
            recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf);

            let mut resp_data = vec![0; len.try_into().unwrap()];
            recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
            let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
            result_data.push(resp_data);
            if resp.is_none() {
                break;
            }
        }

        assert_eq!(Http::done().unwrap(), result_data.pop().unwrap());
        assert_eq!(
            http_data.message(send_http_time, SOURCE).unwrap(),
            result_data.pop().unwrap()
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
        let message = Message {
            source: String::from(SOURCE),
            kind: String::from(RDP_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        let mut message_buf = bincode::serialize(&message).unwrap();

        let mut request_buf: Vec<u8> = Vec::new();
        request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
        request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
        request_buf.append(&mut message_buf);

        send_pub_req
            .write_all(&request_buf)
            .await
            .expect("failed to send request");

        let mut result_data: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut len_buf = [0; std::mem::size_of::<u32>()];
            recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf);

            let mut resp_data = vec![0; len.try_into().unwrap()];
            recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
            let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
            result_data.push(resp_data);
            if resp.is_none() {
                break;
            }
        }

        assert_eq!(Rdp::done().unwrap(), result_data.pop().unwrap());
        assert_eq!(
            rdp_data.message(send_rdp_time, SOURCE).unwrap(),
            result_data.pop().unwrap()
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
        let message = Message {
            source: String::from(SOURCE),
            kind: String::from(SMTP_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        let mut message_buf = bincode::serialize(&message).unwrap();

        let mut request_buf: Vec<u8> = Vec::new();
        request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
        request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
        request_buf.append(&mut message_buf);

        send_pub_req
            .write_all(&request_buf)
            .await
            .expect("failed to send request");

        let mut result_data: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut len_buf = [0; std::mem::size_of::<u32>()];
            recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf);

            let mut resp_data = vec![0; len.try_into().unwrap()];
            recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
            let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
            result_data.push(resp_data);
            if resp.is_none() {
                break;
            }
        }

        assert_eq!(Smtp::done().unwrap(), result_data.pop().unwrap());
        assert_eq!(
            smtp_data.message(send_smtp_time, SOURCE).unwrap(),
            result_data.pop().unwrap()
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
        let message = Message {
            source: String::from(SOURCE),
            kind: String::from(NTLM_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        let mut message_buf = bincode::serialize(&message).unwrap();

        let mut request_buf: Vec<u8> = Vec::new();
        request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
        request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
        request_buf.append(&mut message_buf);

        send_pub_req
            .write_all(&request_buf)
            .await
            .expect("failed to send request");

        let mut result_data: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut len_buf = [0; std::mem::size_of::<u32>()];
            recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf);

            let mut resp_data = vec![0; len.try_into().unwrap()];
            recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
            let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
            result_data.push(resp_data);
            if resp.is_none() {
                break;
            }
        }

        assert_eq!(Ntlm::done().unwrap(), result_data.pop().unwrap());
        assert_eq!(
            ntlm_data.message(send_ntlm_time, SOURCE).unwrap(),
            result_data.pop().unwrap()
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
        let message = Message {
            source: String::from(SOURCE),
            kind: String::from(KERBEROS_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        let mut message_buf = bincode::serialize(&message).unwrap();

        let mut request_buf: Vec<u8> = Vec::new();
        request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
        request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
        request_buf.append(&mut message_buf);

        send_pub_req
            .write_all(&request_buf)
            .await
            .expect("failed to send request");

        let mut result_data: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut len_buf = [0; std::mem::size_of::<u32>()];
            recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf);

            let mut resp_data = vec![0; len.try_into().unwrap()];
            recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
            let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
            result_data.push(resp_data);
            if resp.is_none() {
                break;
            }
        }

        assert_eq!(Kerberos::done().unwrap(), result_data.pop().unwrap());
        assert_eq!(
            kerberos_data.message(send_kerberos_time, SOURCE).unwrap(),
            result_data.pop().unwrap()
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
        let message = Message {
            source: String::from(SOURCE),
            kind: String::from(SSH_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        let mut message_buf = bincode::serialize(&message).unwrap();

        let mut request_buf: Vec<u8> = Vec::new();
        request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
        request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
        request_buf.append(&mut message_buf);

        send_pub_req
            .write_all(&request_buf)
            .await
            .expect("failed to send request");

        let mut result_data: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut len_buf = [0; std::mem::size_of::<u32>()];
            recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf);

            let mut resp_data = vec![0; len.try_into().unwrap()];
            recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
            let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
            result_data.push(resp_data);
            if resp.is_none() {
                break;
            }
        }

        assert_eq!(Ssh::done().unwrap(), result_data.pop().unwrap());
        assert_eq!(
            ssh_data.message(send_ssh_time, SOURCE).unwrap(),
            result_data.pop().unwrap()
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
        let message = Message {
            source: String::from(SOURCE),
            kind: String::from(DCE_RPC_KIND),
            start: start.timestamp_nanos(),
            end: end.timestamp_nanos(),
            count: 5,
        };
        let mut message_buf = bincode::serialize(&message).unwrap();

        let mut request_buf: Vec<u8> = Vec::new();
        request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
        request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
        request_buf.append(&mut message_buf);

        send_pub_req
            .write_all(&request_buf)
            .await
            .expect("failed to send request");

        let mut result_data: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut len_buf = [0; std::mem::size_of::<u32>()];
            recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf);

            let mut resp_data = vec![0; len.try_into().unwrap()];
            recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
            let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
            result_data.push(resp_data);
            if resp.is_none() {
                break;
            }
        }

        assert_eq!(DceRpc::done().unwrap(), result_data.pop().unwrap());
        assert_eq!(
            dce_rpc_data.message(send_dce_rpc_time, SOURCE).unwrap(),
            result_data.pop().unwrap()
        );
    }

    publish.conn.close(0u32.into(), b"publish_protocol_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_publish_log() {
    use crate::publish::PubMessage;

    const PUBLISH_LOG_MESSAGE_CODE: u32 = 0x00;
    const SOURCE: &str = "einsis";
    const KIND: &str = "Hello";

    #[derive(Serialize)]
    struct Message {
        source: String,
        kind: String,
        start: i64,
        end: i64,
        count: usize,
    }

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    tokio::spawn(server().run(db.clone()));
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
    let message = Message {
        source: String::from(SOURCE),
        kind: String::from(KIND),
        start: start.timestamp_nanos(),
        end: end.timestamp_nanos(),
        count: 5,
    };
    let mut message_buf = bincode::serialize(&message).unwrap();

    let mut request_buf: Vec<u8> = Vec::new();
    request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
    request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
    request_buf.append(&mut message_buf);

    send_pub_req
        .write_all(&request_buf)
        .await
        .expect("failed to send request");

    let mut result_data: Vec<Vec<u8>> = Vec::new();
    loop {
        let mut len_buf = [0; std::mem::size_of::<u32>()];
        recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_le_bytes(len_buf);

        let mut resp_data = vec![0; len.try_into().unwrap()];
        recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
        let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
        result_data.push(resp_data);
        if resp.is_none() {
            break;
        }
    }
    assert_eq!(Log::done().unwrap(), result_data.pop().unwrap());
    assert_eq!(
        log_data.message(send_log_time, SOURCE).unwrap(),
        result_data.pop().unwrap()
    );

    publish.conn.close(0u32.into(), b"publish_log_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_publish_period_time_series() {
    use crate::publish::PubMessage;

    const PUBLISH_PERIOD_TIME_SERIES_MESSAGE_CODE: u32 = 0x01;
    const SAMPLING_POLICY_ID: &str = "policy_one";

    #[derive(Serialize)]
    struct Message {
        source: String,
        start: i64,
        end: i64,
        count: usize,
    }

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    tokio::spawn(server().run(db.clone()));
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
    let mesaage = Message {
        source: String::from(SAMPLING_POLICY_ID),
        start: start.timestamp_nanos(),
        end: end.timestamp_nanos(),
        count: 5,
    };
    let mut message_buf = bincode::serialize(&mesaage).unwrap();

    let mut request_buf: Vec<u8> = Vec::new();
    request_buf.append(
        &mut PUBLISH_PERIOD_TIME_SERIES_MESSAGE_CODE
            .to_le_bytes()
            .to_vec(),
    );
    request_buf.append(&mut (message_buf.len() as u32).to_le_bytes().to_vec());
    request_buf.append(&mut message_buf);

    send_pub_req
        .write_all(&request_buf)
        .await
        .expect("failed to send request");

    let mut result_data: Vec<Vec<u8>> = Vec::new();
    loop {
        let mut len_buf = [0; std::mem::size_of::<u32>()];
        recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_le_bytes(len_buf);

        let mut resp_data = vec![0; len.try_into().unwrap()];
        recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
        let resp = bincode::deserialize::<Option<(i64, Vec<f64>)>>(&resp_data).unwrap();
        result_data.push(resp_data);
        if resp.is_none() {
            break;
        }
    }

    assert_eq!(
        PeriodicTimeSeries::done().unwrap(),
        result_data.pop().unwrap()
    );
    assert_eq!(
        time_series_data
            .message(send_time_series_time, SAMPLING_POLICY_ID)
            .unwrap(),
        result_data.pop().unwrap()
    );

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_network_event_stream() {
    use crate::ingestion::gen_network_key;
    use crate::publish::send_direct_network_stream;

    const HOG_TYPE: u8 = 0x00;
    const CRUSHER_TYPE: u8 = 0x01;
    const NETWORK_STREAM_CONN: u32 = 0x00;
    const NETWORK_STREAM_DNS: u32 = 0x01;
    const NETWORK_STREAM_RDP: u32 = 0x02;
    const NETWORK_STREAM_HTTP: u32 = 0x03;
    const NETWORK_STREAM_SMTP: u32 = 0x05;
    const NETWORK_STREAM_NTLM: u32 = 0x06;
    const NETWORK_STREAM_KERBEROS: u32 = 0x07;
    const NETWORK_STREAM_SSH: u32 = 0x08;
    const NETWORK_STREAM_DCE_RPC: u32 = 0x09;

    const SOURCE_ONE: &str = "src1";
    const SOURCE_TWO: &str = "src2";
    const POLICY_ID: &str = "model_one";

    #[derive(Serialize, Clone)]
    struct TestHogStreamMsg {
        start: i64,
        source: Option<String>,
    }

    #[derive(Serialize)]
    struct TestCrusherStreamMsg {
        start: i64,
        id: String,
        src_ip: Option<IpAddr>,
        des_ip: Option<IpAddr>,
        source: Option<String>,
    }

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();

    let hog_msg = TestHogStreamMsg {
        start: 0,
        source: Some(String::from(SOURCE_ONE)),
    };
    let hog_stream_msg = bincode::serialize(&hog_msg).unwrap();

    let crusher_msg = TestCrusherStreamMsg {
        start: 0,
        id: String::from(POLICY_ID),
        src_ip: Some("192.168.4.76".parse::<IpAddr>().unwrap()),
        des_ip: Some("31.3.245.133".parse::<IpAddr>().unwrap()),
        source: Some(String::from(SOURCE_TWO)),
    };
    let crusher_stream_msg = bincode::serialize(&crusher_msg).unwrap();

    tokio::spawn(server().run(db.clone()));
    let mut publish = TestClient::new().await;

    {
        let conn_store = db.conn_store().unwrap();

        // direct conn network event for hog
        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_CONN,
            HOG_TYPE,
            hog_stream_msg.clone(),
        )
        .await;

        let send_conn_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut start_buf = [0; mem::size_of::<u32>()];
        send_conn_stream
            .borrow_mut()
            .read_exact(&mut start_buf)
            .await
            .unwrap();
        let conn_start_msg = u32::from_le_bytes(start_buf);
        assert_eq!(conn_start_msg, NETWORK_STREAM_CONN);

        let send_conn_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_ONE, "conn");
        let conn_data = gen_conn_raw_event();

        send_direct_network_stream(&key, &conn_data, send_conn_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_conn_stream).await;
        assert_eq!(send_conn_time, recv_timestamp);
        assert_eq!(conn_data, recv_data);

        // database conn network event for crusher
        let send_conn_time = Utc::now().timestamp_nanos();
        let conn_data = insert_conn_raw_event(&conn_store, SOURCE_TWO, send_conn_time);

        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_CONN,
            CRUSHER_TYPE,
            crusher_stream_msg.clone(),
        )
        .await;

        let send_conn_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut id_len_buf = [0_u8; mem::size_of::<u32>()];
        send_conn_stream
            .borrow_mut()
            .read_exact(&mut id_len_buf)
            .await
            .unwrap();
        let len = usize::try_from(u32::from_le_bytes(id_len_buf)).unwrap();
        let mut id_buf = vec![0; len];
        send_conn_stream
            .borrow_mut()
            .read_exact(&mut id_buf)
            .await
            .unwrap();
        let id = String::from_utf8(id_buf).unwrap();
        assert_eq!(id, POLICY_ID);

        let (recv_timestamp, recv_data) = recv_network_stream(send_conn_stream.clone()).await;
        assert_eq!(send_conn_time, recv_timestamp);
        assert_eq!(conn_data, recv_data);

        // direct conn network event for crusher
        let send_conn_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_TWO, "conn");
        let conn_data = gen_conn_raw_event();

        send_direct_network_stream(&key, &conn_data, send_conn_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_conn_stream).await;
        assert_eq!(send_conn_time, recv_timestamp);
        assert_eq!(conn_data, recv_data);
    }

    {
        let dns_store = db.dns_store().unwrap();

        // direct dns network event for hog
        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_DNS,
            HOG_TYPE,
            hog_stream_msg.clone(),
        )
        .await;

        let send_dns_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut start_buf = [0; mem::size_of::<u32>()];
        send_dns_stream
            .borrow_mut()
            .read_exact(&mut start_buf)
            .await
            .unwrap();
        let dns_start_msg = u32::from_le_bytes(start_buf);
        assert_eq!(dns_start_msg, NETWORK_STREAM_DNS);

        let send_dns_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_ONE, "dns");
        let dns_data = gen_conn_raw_event();

        send_direct_network_stream(&key, &dns_data, send_dns_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_dns_stream).await;
        assert_eq!(send_dns_time, recv_timestamp);
        assert_eq!(dns_data, recv_data);

        // database dns network event for crusher
        let send_dns_time = Utc::now().timestamp_nanos();
        let dns_data = insert_dns_raw_event(&dns_store, SOURCE_TWO, send_dns_time);

        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_DNS,
            CRUSHER_TYPE,
            crusher_stream_msg.clone(),
        )
        .await;

        let send_dns_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut id_len_buf = [0_u8; mem::size_of::<u32>()];
        send_dns_stream
            .borrow_mut()
            .read_exact(&mut id_len_buf)
            .await
            .unwrap();
        let len = usize::try_from(u32::from_le_bytes(id_len_buf)).unwrap();
        let mut id_buf = vec![0; len];
        send_dns_stream
            .borrow_mut()
            .read_exact(&mut id_buf)
            .await
            .unwrap();
        let id = String::from_utf8(id_buf).unwrap();
        assert_eq!(id, POLICY_ID);

        let (recv_timestamp, recv_data) = recv_network_stream(send_dns_stream.clone()).await;
        assert_eq!(send_dns_time, recv_timestamp);
        assert_eq!(dns_data, recv_data);

        // direct dns network event for crusher
        let send_dns_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_TWO, "dns");
        let dns_data = gen_dns_raw_event();

        send_direct_network_stream(&key, &dns_data, send_dns_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_dns_stream).await;
        assert_eq!(send_dns_time, recv_timestamp);
        assert_eq!(dns_data, recv_data);
    }

    {
        let rdp_store = db.rdp_store().unwrap();

        // direct rdp network event for hog
        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_RDP,
            HOG_TYPE,
            hog_stream_msg.clone(),
        )
        .await;

        let send_rdp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut start_buf = [0; mem::size_of::<u32>()];
        send_rdp_stream
            .borrow_mut()
            .read_exact(&mut start_buf)
            .await
            .unwrap();
        let rdp_start_msg = u32::from_le_bytes(start_buf);
        assert_eq!(rdp_start_msg, NETWORK_STREAM_RDP);

        let send_rdp_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_ONE, "rdp");
        let rdp_data = gen_conn_raw_event();

        send_direct_network_stream(&key, &rdp_data, send_rdp_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_rdp_stream).await;
        assert_eq!(send_rdp_time, recv_timestamp);
        assert_eq!(rdp_data, recv_data);

        // database rdp network event for crusher
        let send_rdp_time = Utc::now().timestamp_nanos();
        let rdp_data = insert_rdp_raw_event(&rdp_store, SOURCE_TWO, send_rdp_time);

        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_RDP,
            CRUSHER_TYPE,
            crusher_stream_msg.clone(),
        )
        .await;

        let send_rdp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut id_len_buf = [0_u8; mem::size_of::<u32>()];
        send_rdp_stream
            .borrow_mut()
            .read_exact(&mut id_len_buf)
            .await
            .unwrap();
        let len = usize::try_from(u32::from_le_bytes(id_len_buf)).unwrap();
        let mut id_buf = vec![0; len];
        send_rdp_stream
            .borrow_mut()
            .read_exact(&mut id_buf)
            .await
            .unwrap();
        let id = String::from_utf8(id_buf).unwrap();
        assert_eq!(id, POLICY_ID);

        let (recv_timestamp, recv_data) = recv_network_stream(send_rdp_stream.clone()).await;
        assert_eq!(send_rdp_time, recv_timestamp);
        assert_eq!(rdp_data, recv_data);

        // direct rdp network event for crusher
        let send_rdp_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_TWO, "rdp");
        let rdp_data = gen_rdp_raw_event();
        send_direct_network_stream(&key, &rdp_data, send_rdp_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_rdp_stream).await;
        assert_eq!(send_rdp_time, recv_timestamp);
        assert_eq!(rdp_data, recv_data);
    }

    {
        let http_store = db.http_store().unwrap();

        // direct http network event for hog
        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_HTTP,
            HOG_TYPE,
            hog_stream_msg.clone(),
        )
        .await;

        let send_http_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut start_buf = [0; mem::size_of::<u32>()];
        send_http_stream
            .borrow_mut()
            .read_exact(&mut start_buf)
            .await
            .unwrap();
        let http_start_msg = u32::from_le_bytes(start_buf);
        assert_eq!(http_start_msg, NETWORK_STREAM_HTTP);

        let send_http_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_ONE, "http");
        let http_data = gen_conn_raw_event();

        send_direct_network_stream(&key, &http_data, send_http_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_http_stream).await;
        assert_eq!(send_http_time, recv_timestamp);
        assert_eq!(http_data, recv_data);

        // database http network event for crusher
        let send_http_time = Utc::now().timestamp_nanos();
        let http_data = insert_http_raw_event(&http_store, SOURCE_TWO, send_http_time);

        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_HTTP,
            CRUSHER_TYPE,
            crusher_stream_msg.clone(),
        )
        .await;

        let send_http_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut id_len_buf = [0_u8; mem::size_of::<u32>()];
        send_http_stream
            .borrow_mut()
            .read_exact(&mut id_len_buf)
            .await
            .unwrap();
        let len = usize::try_from(u32::from_le_bytes(id_len_buf)).unwrap();
        let mut id_buf = vec![0; len];
        send_http_stream
            .borrow_mut()
            .read_exact(&mut id_buf)
            .await
            .unwrap();
        let id = String::from_utf8(id_buf).unwrap();
        assert_eq!(id, POLICY_ID);

        let (recv_timestamp, recv_data) = recv_network_stream(send_http_stream.clone()).await;
        assert_eq!(send_http_time, recv_timestamp);
        assert_eq!(http_data, recv_data);

        // direct http network event for crusher
        let send_http_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_TWO, "http");
        let http_data = gen_http_raw_event();
        send_direct_network_stream(&key, &http_data, send_http_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_http_stream).await;
        assert_eq!(send_http_time, recv_timestamp);
        assert_eq!(http_data, recv_data);
    }

    {
        let smtp_store = db.smtp_store().unwrap();

        // direct smtp network event for hog
        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_SMTP,
            HOG_TYPE,
            hog_stream_msg.clone(),
        )
        .await;

        let send_smtp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut start_buf = [0; mem::size_of::<u32>()];
        send_smtp_stream
            .borrow_mut()
            .read_exact(&mut start_buf)
            .await
            .unwrap();
        let smtp_start_msg = u32::from_le_bytes(start_buf);
        assert_eq!(smtp_start_msg, NETWORK_STREAM_SMTP);

        let send_smtp_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_ONE, "smtp");
        let smtp_data = gen_smtp_raw_event();

        send_direct_network_stream(&key, &smtp_data, send_smtp_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_smtp_stream).await;
        assert_eq!(send_smtp_time, recv_timestamp);
        assert_eq!(smtp_data, recv_data);

        // database smtp network event for crusher
        let send_smtp_time = Utc::now().timestamp_nanos();
        let smtp_data = insert_smtp_raw_event(&smtp_store, SOURCE_TWO, send_smtp_time);

        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_SMTP,
            CRUSHER_TYPE,
            crusher_stream_msg.clone(),
        )
        .await;

        let send_smtp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut id_len_buf = [0_u8; mem::size_of::<u32>()];
        send_smtp_stream
            .borrow_mut()
            .read_exact(&mut id_len_buf)
            .await
            .unwrap();
        let len = usize::try_from(u32::from_le_bytes(id_len_buf)).unwrap();
        let mut id_buf = vec![0; len];
        send_smtp_stream
            .borrow_mut()
            .read_exact(&mut id_buf)
            .await
            .unwrap();
        let id = String::from_utf8(id_buf).unwrap();
        assert_eq!(id, POLICY_ID);

        let (recv_timestamp, recv_data) = recv_network_stream(send_smtp_stream.clone()).await;
        assert_eq!(send_smtp_time, recv_timestamp);
        assert_eq!(smtp_data, recv_data);

        // direct smtp network event for crusher
        let send_smtp_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_TWO, "smtp");
        let smtp_data = gen_smtp_raw_event();
        send_direct_network_stream(&key, &smtp_data, send_smtp_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_smtp_stream).await;
        assert_eq!(send_smtp_time, recv_timestamp);
        assert_eq!(smtp_data, recv_data);
    }

    {
        let ntlm_store = db.ntlm_store().unwrap();

        // direct ntlm network event for hog
        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_NTLM,
            HOG_TYPE,
            hog_stream_msg.clone(),
        )
        .await;

        let send_ntlm_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut start_buf = [0; mem::size_of::<u32>()];
        send_ntlm_stream
            .borrow_mut()
            .read_exact(&mut start_buf)
            .await
            .unwrap();
        let ntlm_start_msg = u32::from_le_bytes(start_buf);
        assert_eq!(ntlm_start_msg, NETWORK_STREAM_NTLM);

        let send_ntlm_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_ONE, "ntlm");
        let ntlm_data = gen_ntlm_raw_event();

        send_direct_network_stream(&key, &ntlm_data, send_ntlm_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_ntlm_stream).await;
        assert_eq!(send_ntlm_time, recv_timestamp);
        assert_eq!(ntlm_data, recv_data);

        // database ntlm network event for crusher
        let send_ntlm_time = Utc::now().timestamp_nanos();
        let ntlm_data = insert_ntlm_raw_event(&ntlm_store, SOURCE_TWO, send_ntlm_time);

        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_NTLM,
            CRUSHER_TYPE,
            crusher_stream_msg.clone(),
        )
        .await;

        let send_ntlm_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut id_len_buf = [0_u8; mem::size_of::<u32>()];
        send_ntlm_stream
            .borrow_mut()
            .read_exact(&mut id_len_buf)
            .await
            .unwrap();
        let len = usize::try_from(u32::from_le_bytes(id_len_buf)).unwrap();
        let mut id_buf = vec![0; len];
        send_ntlm_stream
            .borrow_mut()
            .read_exact(&mut id_buf)
            .await
            .unwrap();
        let id = String::from_utf8(id_buf).unwrap();
        assert_eq!(id, POLICY_ID);

        let (recv_timestamp, recv_data) = recv_network_stream(send_ntlm_stream.clone()).await;
        assert_eq!(send_ntlm_time, recv_timestamp);
        assert_eq!(ntlm_data, recv_data);

        //direct ntlm network event for crusher
        let send_ntlm_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_TWO, "ntlm");
        let ntlm_data = gen_ntlm_raw_event();
        send_direct_network_stream(&key, &ntlm_data, send_ntlm_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_ntlm_stream).await;
        assert_eq!(send_ntlm_time, recv_timestamp);
        assert_eq!(ntlm_data, recv_data);
    }

    {
        let kerberos_store = db.kerberos_store().unwrap();

        // direct kerberos network event for hog
        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_KERBEROS,
            HOG_TYPE,
            hog_stream_msg.clone(),
        )
        .await;

        let send_kerberos_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut start_buf = [0; mem::size_of::<u32>()];
        send_kerberos_stream
            .borrow_mut()
            .read_exact(&mut start_buf)
            .await
            .unwrap();
        let kerberos_start_msg = u32::from_le_bytes(start_buf);
        assert_eq!(kerberos_start_msg, NETWORK_STREAM_KERBEROS);

        let send_kerberos_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_ONE, "kerberos");
        let kerberos_data = gen_kerberos_raw_event();

        send_direct_network_stream(&key, &kerberos_data, send_kerberos_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_kerberos_stream).await;
        assert_eq!(send_kerberos_time, recv_timestamp);
        assert_eq!(kerberos_data, recv_data);

        // database kerberos network event for crusher
        let send_kerberos_time = Utc::now().timestamp_nanos();
        let kerberos_data =
            insert_kerberos_raw_event(&kerberos_store, SOURCE_TWO, send_kerberos_time);

        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_KERBEROS,
            CRUSHER_TYPE,
            crusher_stream_msg.clone(),
        )
        .await;

        let send_kerberos_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut id_len_buf = [0_u8; mem::size_of::<u32>()];
        send_kerberos_stream
            .borrow_mut()
            .read_exact(&mut id_len_buf)
            .await
            .unwrap();
        let len = usize::try_from(u32::from_le_bytes(id_len_buf)).unwrap();
        let mut id_buf = vec![0; len];
        send_kerberos_stream
            .borrow_mut()
            .read_exact(&mut id_buf)
            .await
            .unwrap();
        let id = String::from_utf8(id_buf).unwrap();
        assert_eq!(id, POLICY_ID);

        let (recv_timestamp, recv_data) = recv_network_stream(send_kerberos_stream.clone()).await;
        assert_eq!(send_kerberos_time, recv_timestamp);
        assert_eq!(kerberos_data, recv_data);

        //direct kerberos network event for crusher
        let send_kerberos_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_TWO, "kerberos");
        let kerberos_data = gen_kerberos_raw_event();
        send_direct_network_stream(&key, &kerberos_data, send_kerberos_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_kerberos_stream).await;
        assert_eq!(send_kerberos_time, recv_timestamp);
        assert_eq!(kerberos_data, recv_data);
    }

    {
        let ssh_store = db.ssh_store().unwrap();

        // direct ssh network event for hog
        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_SSH,
            HOG_TYPE,
            hog_stream_msg.clone(),
        )
        .await;

        let send_ssh_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut start_buf = [0; mem::size_of::<u32>()];
        send_ssh_stream
            .borrow_mut()
            .read_exact(&mut start_buf)
            .await
            .unwrap();
        let ssh_start_msg = u32::from_le_bytes(start_buf);
        assert_eq!(ssh_start_msg, NETWORK_STREAM_SSH);

        let send_ssh_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_ONE, "ssh");
        let ssh_data = gen_ssh_raw_event();

        send_direct_network_stream(&key, &ssh_data, send_ssh_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_ssh_stream).await;
        assert_eq!(send_ssh_time, recv_timestamp);
        assert_eq!(ssh_data, recv_data);

        // database ssh network event for crusher
        let send_ssh_time = Utc::now().timestamp_nanos();
        let ssh_data = insert_ssh_raw_event(&ssh_store, SOURCE_TWO, send_ssh_time);

        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_SSH,
            CRUSHER_TYPE,
            crusher_stream_msg.clone(),
        )
        .await;

        let send_ssh_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut id_len_buf = [0_u8; mem::size_of::<u32>()];
        send_ssh_stream
            .borrow_mut()
            .read_exact(&mut id_len_buf)
            .await
            .unwrap();
        let len = usize::try_from(u32::from_le_bytes(id_len_buf)).unwrap();
        let mut id_buf = vec![0; len];
        send_ssh_stream
            .borrow_mut()
            .read_exact(&mut id_buf)
            .await
            .unwrap();
        let id = String::from_utf8(id_buf).unwrap();
        assert_eq!(id, POLICY_ID);

        let (recv_timestamp, recv_data) = recv_network_stream(send_ssh_stream.clone()).await;
        assert_eq!(send_ssh_time, recv_timestamp);
        assert_eq!(ssh_data, recv_data);

        //direct ssh network event for crusher
        let send_ssh_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_TWO, "ssh");
        let ssh_data = gen_ssh_raw_event();
        send_direct_network_stream(&key, &ssh_data, send_ssh_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_ssh_stream).await;
        assert_eq!(send_ssh_time, recv_timestamp);
        assert_eq!(ssh_data, recv_data);
    }

    {
        let dce_rpc_store = db.dce_rpc_store().unwrap();

        // direct dce_rpc network event for hog
        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_DCE_RPC,
            HOG_TYPE,
            hog_stream_msg,
        )
        .await;

        let send_dce_rpc_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut start_buf = [0; mem::size_of::<u32>()];
        send_dce_rpc_stream
            .borrow_mut()
            .read_exact(&mut start_buf)
            .await
            .unwrap();
        let dce_rpc_start_msg = u32::from_le_bytes(start_buf);
        assert_eq!(dce_rpc_start_msg, NETWORK_STREAM_DCE_RPC);

        let send_dce_rpc_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_ONE, "dce rpc");
        let dce_rpc_data = gen_dce_rpc_raw_event();

        send_direct_network_stream(&key, &dce_rpc_data, send_dce_rpc_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_dce_rpc_stream).await;
        assert_eq!(send_dce_rpc_time, recv_timestamp);
        assert_eq!(dce_rpc_data, recv_data);

        // database dce_rpc network event for crusher
        let send_dce_rpc_time = Utc::now().timestamp_nanos();
        let dce_rpc_data = insert_dce_rpc_raw_event(&dce_rpc_store, SOURCE_TWO, send_dce_rpc_time);

        send_request_network_stream(
            &mut publish.send,
            NETWORK_STREAM_DCE_RPC,
            CRUSHER_TYPE,
            crusher_stream_msg,
        )
        .await;

        let send_dce_rpc_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let mut id_len_buf = [0_u8; mem::size_of::<u32>()];
        send_dce_rpc_stream
            .borrow_mut()
            .read_exact(&mut id_len_buf)
            .await
            .unwrap();
        let len = usize::try_from(u32::from_le_bytes(id_len_buf)).unwrap();
        let mut id_buf = vec![0; len];
        send_dce_rpc_stream
            .borrow_mut()
            .read_exact(&mut id_buf)
            .await
            .unwrap();
        let id = String::from_utf8(id_buf).unwrap();
        assert_eq!(id, POLICY_ID);

        let (recv_timestamp, recv_data) = recv_network_stream(send_dce_rpc_stream.clone()).await;
        assert_eq!(send_dce_rpc_time, recv_timestamp);
        assert_eq!(dce_rpc_data, recv_data);

        //direct dce_rpc network event for crusher
        let send_dce_rpc_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE_TWO, "dce rpc");
        let dce_rpc_data = gen_dce_rpc_raw_event();
        send_direct_network_stream(&key, &dce_rpc_data, send_dce_rpc_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_dce_rpc_stream).await;
        assert_eq!(send_dce_rpc_time, recv_timestamp);
        assert_eq!(dce_rpc_data, recv_data);
    }

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}
