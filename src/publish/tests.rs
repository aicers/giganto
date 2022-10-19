use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
};

use chrono::{DateTime, NaiveDate, Utc};
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
const TEST_PORT: u16 = 60191;
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
