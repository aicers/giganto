use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
};

use chrono::{Duration, Utc};
use lazy_static::lazy_static;
use quinn::{Connection, Endpoint};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::{storage::Database, to_cert_chain, to_private_key};

use super::Server;

lazy_static! {
    pub(crate) static ref TOKEN: Mutex<u32> = Mutex::new(0);
}

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/root.pem";
const HOST: &str = "localhost";
const TEST_PORT: u16 = 60190;
const PROTOCOL_VERSION: &str = "0.2.0";

struct TestClient {
    conn: Connection,
    endpoint: Endpoint,
}

impl TestClient {
    async fn new() -> Self {
        let endpoint = init_client();
        let new_conn = endpoint
            .connect(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT),
                HOST,
            )
            .expect(
                "Failed to connect server's endpoint, Please check if the setting value is correct",
            )
            .await
            .expect("Failed to connect server's endpoint, Please make sure the Server is alive");
        let quinn::NewConnection {
            connection: conn, ..
        } = new_conn;
        connection_handshake(&conn).await;
        Self { conn, endpoint }
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

async fn connection_handshake(conn: &Connection) {
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
}

#[tokio::test]
async fn conn() {
    const RECORD_TYPE_CONN: u32 = 0x00;

    #[derive(Serialize)]
    struct Conn {
        orig_addr: IpAddr,
        resp_addr: IpAddr,
        orig_port: u16,
        resp_port: u16,
        proto: u8,
        duration: i64,
        orig_bytes: u64,
        resp_bytes: u64,
        orig_pkts: u64,
        resp_pkts: u64,
    }

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    tokio::spawn(server().run(db));

    let client = TestClient::new().await;
    let (mut send_conn, _) = client.conn.open_bi().await.expect("failed to open stream");

    let mut conn_data: Vec<u8> = Vec::new();
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
    let mut ser_conn_body = bincode::serialize(&conn_body).unwrap();

    conn_data.append(&mut RECORD_TYPE_CONN.to_le_bytes().to_vec());
    conn_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    conn_data.append(&mut (ser_conn_body.len() as u32).to_le_bytes().to_vec());
    conn_data.append(&mut ser_conn_body);

    send_conn
        .write_all(&conn_data)
        .await
        .expect("failed to send request");

    send_conn.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"conn_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn dns() {
    const RECORD_TYPE_DNS: u32 = 0x01;

    #[derive(Serialize)]
    struct DNSConn {
        orig_addr: IpAddr,
        resp_addr: IpAddr,
        orig_port: u16,
        resp_port: u16,
        proto: u8,
        query: String,
    }

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    tokio::spawn(server().run(db));

    let client = TestClient::new().await;
    let (mut send_dns, _) = client.conn.open_bi().await.expect("failed to open stream");

    let mut dns_data: Vec<u8> = Vec::new();
    let dns_body = DNSConn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 17,
        query:
            "Hello ServerHello ServerHello ServerHello ServerHello ServerHello ServerHello Server"
                .to_string(),
    };
    let mut ser_dns_body = bincode::serialize(&dns_body).unwrap();

    dns_data.append(&mut RECORD_TYPE_DNS.to_le_bytes().to_vec());
    dns_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    dns_data.append(&mut (ser_dns_body.len() as u32).to_le_bytes().to_vec());
    dns_data.append(&mut ser_dns_body);

    send_dns
        .write_all(&dns_data)
        .await
        .expect("failed to send request");

    send_dns.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"dns_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn log() {
    const RECORD_TYPE_LOG: u32 = 0x02;

    type Log = (String, Vec<u8>);

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    tokio::spawn(server().run(db));

    let client = TestClient::new().await;
    let (mut send_log, _) = client.conn.open_bi().await.expect("failed to open stream");

    let mut log_data: Vec<u8> = Vec::new();
    let log_body: Log = (
        String::from("Hello"),
        base64::decode("aGVsbG8gd29ybGQ=").unwrap(),
    );
    let mut ser_log_body = bincode::serialize(&log_body).unwrap();

    log_data.append(&mut RECORD_TYPE_LOG.to_le_bytes().to_vec());
    log_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    log_data.append(&mut (ser_log_body.len() as u32).to_le_bytes().to_vec());
    log_data.append(&mut ser_log_body);

    send_log
        .write_all(&log_data)
        .await
        .expect("failed to send request");
    send_log.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn http() {
    const RECORD_TYPE_HTTP: u32 = 0x03;

    #[derive(Serialize)]
    struct HttpConn {
        orig_addr: IpAddr,
        resp_addr: IpAddr,
        orig_port: u16,
        resp_port: u16,
        method: String,
        host: String,
        uri: String,
        referrer: String,
        user_agent: String,
        status_code: u16,
    }

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    tokio::spawn(server().run(db));

    let client = TestClient::new().await;
    let (mut send_http, _) = client.conn.open_bi().await.expect("failed to open stream");

    let mut http_data: Vec<u8> = Vec::new();
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
    let mut ser_http_body = bincode::serialize(&http_body).unwrap();

    http_data.append(&mut RECORD_TYPE_HTTP.to_le_bytes().to_vec());
    http_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    http_data.append(&mut (ser_http_body.len() as u32).to_le_bytes().to_vec());
    http_data.append(&mut ser_http_body);

    send_http
        .write_all(&http_data)
        .await
        .expect("failed to send request");

    send_http.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"http_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn rdp() {
    const RECORD_TYPE_RDP: u32 = 0x04;

    #[derive(Serialize)]
    struct RdpConn {
        orig_addr: IpAddr,
        resp_addr: IpAddr,
        orig_port: u16,
        resp_port: u16,
        cookie: String,
    }

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    tokio::spawn(server().run(db));

    let client = TestClient::new().await;
    let (mut send_rdp, _) = client.conn.open_bi().await.expect("failed to open stream");

    let mut rdp_data: Vec<u8> = Vec::new();
    let rdp_body = RdpConn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        cookie: "rdp_test".to_string(),
    };
    let mut ser_rdp_body = bincode::serialize(&rdp_body).unwrap();

    rdp_data.append(&mut RECORD_TYPE_RDP.to_le_bytes().to_vec());
    rdp_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    rdp_data.append(&mut (ser_rdp_body.len() as u32).to_le_bytes().to_vec());
    rdp_data.append(&mut ser_rdp_body);

    send_rdp
        .write_all(&rdp_data)
        .await
        .expect("failed to send request");
    send_rdp.finish().await.expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"log_done");
    client.endpoint.wait_idle().await;
}

#[tokio::test]
async fn periodic_time_series() {
    const RECORD_TYPE_PERIOD_TIME_SERIES: u32 = 0x05;

    type PeriodicTimeSeries = (String, i64, i64, Vec<f64>);

    let _lock = TOKEN.lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    tokio::spawn(server().run(db));

    let client = TestClient::new().await;
    let (mut send_periodic_time_series, _) =
        client.conn.open_bi().await.expect("failed to open stream");

    let mut periodic_time_series_data: Vec<u8> = Vec::new();
    let periodic_time_series_body: PeriodicTimeSeries = (
        String::from("Hello"),
        Utc::now().timestamp_nanos(),
        10,
        Vec::new(),
    );
    let mut ser_periodic_time_series_body = bincode::serialize(&periodic_time_series_body).unwrap();

    periodic_time_series_data.append(&mut RECORD_TYPE_PERIOD_TIME_SERIES.to_le_bytes().to_vec());
    periodic_time_series_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    periodic_time_series_data.append(
        &mut (ser_periodic_time_series_body.len() as u32)
            .to_le_bytes()
            .to_vec(),
    );
    periodic_time_series_data.append(&mut ser_periodic_time_series_body);

    send_periodic_time_series
        .write_all(&periodic_time_series_data)
        .await
        .expect("failed to send request");
    send_periodic_time_series
        .finish()
        .await
        .expect("failed to shutdown stream");

    client.conn.close(0u32.into(), b"periodic_time_series_done");
    client.endpoint.wait_idle().await;
}
