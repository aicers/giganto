use super::Server;
use crate::ingestion::{Conn, DnsConn, HttpConn, RdpConn};
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
const PROTOCOL_VERSION: &str = "0.4.0";

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
        .and_then(|x| Ok((x, fs::read(KEY_PATH).expect("Failed to Read key file"))))
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
    source: &str,
    timestamp: i64,
) {
    let mut req_data: Vec<u8> = Vec::new();
    req_data.append(&mut msg_code.to_le_bytes().to_vec());

    let mut req_val = bincode::serialize(&(String::from(source), timestamp)).unwrap();
    req_data.append(&mut (req_val.len() as u32).to_le_bytes().to_vec());
    req_data.append(&mut req_val);

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

fn gen_network_event_key(source: &str, timestamp: i64) -> Vec<u8> {
    let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
    key.extend_from_slice(source.as_bytes());
    key.push(0);
    key.extend(timestamp.to_be_bytes());
    key
}

fn gen_conn_raw_event() -> Vec<u8> {
    let tmp_dur = Duration::nanoseconds(12345);
    let conn_body = Conn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 6,
        duration: tmp_dur.num_nanoseconds().unwrap(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
    };
    let ser_conn_body = bincode::serialize(&conn_body).unwrap();
    ser_conn_body
}

fn gen_dns_raw_event() -> Vec<u8> {
    let dns_body = DnsConn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 17,
        query:
            "Hello ServerHello ServerHello ServerHello ServerHello ServerHello ServerHello Server"
                .to_string(),
        answer: vec![
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "2.2.2.2".parse::<IpAddr>().unwrap(),
        ],
    };
    let ser_dns_body = bincode::serialize(&dns_body).unwrap();
    ser_dns_body
}

fn gen_rdp_raw_event() -> Vec<u8> {
    let rdp_body = RdpConn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        cookie: "rdp_test".to_string(),
    };
    let ser_rdp_body = bincode::serialize(&rdp_body).unwrap();
    ser_rdp_body
}

fn gen_http_raw_event() -> Vec<u8> {
    let http_body = HttpConn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        method: "POST".to_string(),
        host: "einsis".to_string(),
        uri: "/einsis.gif".to_string(),
        referrer: "einsis.com".to_string(),
        user_agent: "giganto".to_string(),
        status_code: 200,
    };
    let ser_http_body = bincode::serialize(&http_body).unwrap();
    ser_http_body
}

fn insert_conn_raw_event(store: &RawEventStore<Conn>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, timestamp);
    let ser_conn_body = gen_conn_raw_event();
    store.append(&key, &ser_conn_body).unwrap();
    ser_conn_body
}

fn insert_dns_raw_event(store: &RawEventStore<DnsConn>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, timestamp);
    let ser_dns_body = gen_dns_raw_event();
    store.append(&key, &ser_dns_body).unwrap();
    ser_dns_body
}

fn insert_rdp_raw_event(store: &RawEventStore<RdpConn>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, timestamp);
    let ser_rdp_body = gen_rdp_raw_event();
    store.append(&key, &ser_rdp_body).unwrap();
    ser_rdp_body
}

fn insert_http_raw_event(store: &RawEventStore<HttpConn>, source: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(source, timestamp);
    let ser_http_body = gen_http_raw_event();
    store.append(&key, &ser_http_body).unwrap();
    ser_http_body
}

#[tokio::test]
async fn request_publish_log() {
    const PUBLISH_LOG_MESSAGE_CODE: u32 = 0x00;

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
    tokio::spawn(server().run(db));

    let publish = TestClient::new().await;
    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let start = DateTime::<Utc>::from_utc(NaiveDate::from_ymd(1970, 1, 1).and_hms(00, 00, 00), Utc);
    let end = DateTime::<Utc>::from_utc(NaiveDate::from_ymd(2050, 12, 31).and_hms(23, 59, 59), Utc);
    let message = Message {
        source: String::from("einsis"),
        kind: String::from("Hello"),
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

    loop {
        let mut len_buf = [0; std::mem::size_of::<u32>()];
        recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_le_bytes(len_buf);

        let mut resp_data = vec![0; len.try_into().unwrap()];
        recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
        let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
        if resp.is_none() {
            break;
        }
    }

    publish.conn.close(0u32.into(), b"publish_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_publish_period_time_series() {
    const PUBLISH_PERIOD_TIME_SERIES_MESSAGE_CODE: u32 = 0x01;

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
    tokio::spawn(server().run(db));

    let publish = TestClient::new().await;
    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let start = DateTime::<Utc>::from_utc(NaiveDate::from_ymd(1970, 1, 1).and_hms(00, 00, 00), Utc);
    let end = DateTime::<Utc>::from_utc(NaiveDate::from_ymd(2050, 12, 31).and_hms(23, 59, 59), Utc);
    let mesaage = Message {
        source: String::from("einsis"),
        kind: String::from("Hello"),
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
    println!("send test:{:?}", send_pub_req);

    loop {
        let mut len_buf = [0; std::mem::size_of::<u32>()];
        recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_le_bytes(len_buf);

        let mut resp_data = vec![0; len.try_into().unwrap()];
        recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
        let resp = bincode::deserialize::<Option<(i64, Vec<f64>)>>(&resp_data).unwrap();
        if resp.is_none() {
            break;
        }
    }

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_network_event_stream() {
    use crate::ingestion::gen_network_key;
    use crate::publish::send_direct_network_stream;
    const NETWORK_STREAM_CONN: u32 = 0x00;
    const NETWORK_STREAM_DNS: u32 = 0x01;
    const NETWORK_STREAM_RDP: u32 = 0x02;
    const NETWORK_STREAM_HTTP: u32 = 0x03;
    const SOURCE: &str = "src1";

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();

    tokio::spawn(server().run(db.clone()));
    let mut publish = TestClient::new().await;

    {
        //database conn network event
        let conn_store = db.conn_store().unwrap();
        let send_conn_time = Utc::now().timestamp_nanos();
        let conn_data = insert_conn_raw_event(&conn_store, SOURCE, send_conn_time);
        send_request_network_stream(&mut publish.send, NETWORK_STREAM_CONN, SOURCE, 0).await;

        let send_conn_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let (recv_timestamp, recv_data) = recv_network_stream(send_conn_stream.clone()).await;

        assert_eq!(send_conn_time, recv_timestamp);
        assert_eq!(conn_data, recv_data);

        //direct conn network event
        let send_conn_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE, "conn");
        let conn_data = gen_conn_raw_event();
        send_direct_network_stream(&key, &conn_data, send_conn_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_conn_stream).await;
        assert_eq!(send_conn_time, recv_timestamp);
        assert_eq!(conn_data, recv_data);
    }

    {
        //database dns network event
        let dns_store = db.dns_store().unwrap();
        let send_dns_time = Utc::now().timestamp_nanos();
        let dns_data = insert_dns_raw_event(&dns_store, SOURCE, send_dns_time);
        send_request_network_stream(&mut publish.send, NETWORK_STREAM_DNS, SOURCE, 0).await;

        let send_dns_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let (recv_timestamp, recv_data) = recv_network_stream(send_dns_stream.clone()).await;

        assert_eq!(send_dns_time, recv_timestamp);
        assert_eq!(dns_data, recv_data);

        //direct dns network event
        let send_dns_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE, "dns");
        let dns_data = gen_dns_raw_event();
        send_direct_network_stream(&key, &dns_data, send_dns_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_dns_stream).await;
        assert_eq!(send_dns_time, recv_timestamp);
        assert_eq!(dns_data, recv_data);
    }

    {
        //database rdp network event
        let rdp_store = db.rdp_store().unwrap();
        let send_rdp_time = Utc::now().timestamp_nanos();
        let rdp_data = insert_rdp_raw_event(&rdp_store, SOURCE, send_rdp_time);
        send_request_network_stream(&mut publish.send, NETWORK_STREAM_RDP, SOURCE, 0).await;

        let send_rdp_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let (recv_timestamp, recv_data) = recv_network_stream(send_rdp_stream.clone()).await;

        assert_eq!(send_rdp_time, recv_timestamp);
        assert_eq!(rdp_data, recv_data);

        //direct rdp network event
        let send_rdp_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE, "rdp");
        let rdp_data = gen_rdp_raw_event();
        send_direct_network_stream(&key, &rdp_data, send_rdp_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_rdp_stream).await;
        assert_eq!(send_rdp_time, recv_timestamp);
        assert_eq!(rdp_data, recv_data);
    }

    {
        //database http network event
        let http_store = db.http_store().unwrap();
        let send_http_time = Utc::now().timestamp_nanos();
        let http_data = insert_http_raw_event(&http_store, SOURCE, send_http_time);
        send_request_network_stream(&mut publish.send, NETWORK_STREAM_HTTP, SOURCE, 0).await;

        let send_http_stream = Arc::new(RefCell::new(publish.conn.accept_uni().await.unwrap()));
        let (recv_timestamp, recv_data) = recv_network_stream(send_http_stream.clone()).await;

        assert_eq!(send_http_time, recv_timestamp);
        assert_eq!(http_data, recv_data);

        //direct http network event
        let send_http_time = Utc::now().timestamp_nanos();
        let key = gen_network_key(SOURCE, "http");
        let http_data = gen_http_raw_event();
        send_direct_network_stream(&key, &http_data, send_http_time)
            .await
            .unwrap();

        let (recv_timestamp, recv_data) = recv_network_stream(send_http_stream).await;
        assert_eq!(send_http_time, recv_timestamp);
        assert_eq!(http_data, recv_data);
    }
    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}
