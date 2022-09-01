use crate::storage::Database;
use crate::{settings::Settings, storage::RawEventStore};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{prelude::DateTime, Duration, NaiveDateTime, Utc};
use futures_util::StreamExt;
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use serde::{de::DeserializeOwned, Deserialize};
use std::{
    fmt::Debug,
    fs, mem,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        atomic::{AtomicI64, AtomicU8, Ordering},
        Arc,
    },
};
use tokio::{select, sync::mpsc::channel, sync::Mutex, task, time};
use x509_parser::nom::Parser;

const ACK_ROTATION_CNT: u8 = 128;
const ACK_INTERVAL_TIME: u64 = 60 * 60;
const ITV_RESET: bool = true;
const NO_TIMESTAMP: i64 = 0;

#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct Conn {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub orig_port: u16,
    pub resp_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
}
#[allow(unused)]
#[derive(Debug, Deserialize)]
struct DnsConn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    query: String,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
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

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct RdpConn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    cookie: String,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct Log {
    pub log: (String, Vec<u8>),
}

#[derive(Clone, Copy, Debug)]
enum RecordType {
    Conn = 0,
    Dns = 1,
    Log = 2,
    Http = 3,
    Rdp = 4,
}

impl TryFrom<u32> for RecordType {
    type Error = ();
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == RecordType::Conn as u32 => Ok(RecordType::Conn),
            x if x == RecordType::Dns as u32 => Ok(RecordType::Dns),
            x if x == RecordType::Log as u32 => Ok(RecordType::Log),
            x if x == RecordType::Http as u32 => Ok(RecordType::Http),
            x if x == RecordType::Rdp as u32 => Ok(RecordType::Rdp),
            _ => Err(()),
        }
    }
}

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

impl Server {
    pub fn new(s: &Settings) -> Self {
        let server_config =
            config_server(&s.cert, &s.key, &s.roots).expect("server configuration error");
        Server {
            server_config,
            server_address: server_addr(&s.ingestion_address),
        }
    }

    pub async fn run(self, db: Database) {
        let (endpoint, mut incoming) =
            Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        println!(
            "listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        while let Some(conn) = incoming.next().await {
            let db = db.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, db).await {
                    eprintln!("connection failed: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(conn: quinn::Connecting, db: Database) -> Result<()> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;

    let mut source = String::new();
    if let Some(conn_info) = connection.peer_identity() {
        if let Some(cert_info) = conn_info.downcast_ref::<Vec<rustls::Certificate>>() {
            if let Some(cert) = cert_info.get(0) {
                let mut parser = x509_parser::certificate::X509CertificateParser::new()
                    .with_deep_parse_extensions(false);
                let res = parser.parse(cert.as_ref());
                match res {
                    Ok((_, x509)) => {
                        let issuer = x509
                            .issuer()
                            .iter_common_name()
                            .next()
                            .and_then(|cn| cn.as_str().ok())
                            .unwrap();
                        source.push_str(issuer);
                        println!("Connected Client Name : {}", issuer);
                    }
                    _ => anyhow::bail!("x509 parsing failed: {:?}", res),
                }
            }
        }
    }

    async {
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };

            let source = source.clone();
            let db = db.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_request(source, stream, db).await {
                    eprintln!("failed: {}", e);
                }
            });
        }
        Ok(())
    }
    .await?;
    Ok(())
}

async fn handle_request(
    source: String,
    (send, mut recv): (SendStream, RecvStream),
    db: Database,
) -> Result<()> {
    let mut buf = [0; 4];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow!("failed to read record type: {}", e))?;
    if let Ok(record_type) = RecordType::try_from(u32::from_le_bytes(buf)) {
        match record_type {
            RecordType::Conn => {
                handle_data::<Conn>(send, recv, record_type, source, db.conn_store()?).await?;
            }
            RecordType::Dns => {
                handle_data::<DnsConn>(send, recv, record_type, source, db.dns_store()?).await?;
            }
            RecordType::Log => {
                handle_data::<Log>(send, recv, record_type, source, db.log_store()?).await?;
            }
            RecordType::Http => {
                handle_data::<HttpConn>(send, recv, record_type, source, db.http_store()?).await?;
            }
            RecordType::Rdp => {
                handle_data::<RdpConn>(send, recv, record_type, source, db.rdp_store()?).await?;
            }
        };
    } else {
        bail!("failed to convert RecordType, invalid record type");
    }

    Ok(())
}

///Print the raw data
fn print_record_format<'a, T>(record_type: RecordType, timestamp: i64, raw_event: &'a [u8])
where
    T: Debug + Deserialize<'a>,
{
    println!(
        "record_type: {:?}\ntimestamp: {:?}\nrecord: {:?}",
        record_type,
        client_utc_time(timestamp),
        bincode::deserialize::<T>(raw_event).unwrap()
    );
}

fn client_utc_time(timestamp: i64) -> String {
    let duration = Duration::nanoseconds(timestamp).num_seconds();
    let datetime: DateTime<Utc> =
        DateTime::from_utc(NaiveDateTime::from_timestamp(duration, 0), Utc);
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn server_addr(addr: &str) -> SocketAddr {
    addr.parse::<SocketAddr>().unwrap()
}

fn config_server(
    cert_path: &str,
    key_path: &str,
    roots_path: &Vec<String>,
) -> Result<ServerConfig> {
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(_) => {
            bail!(
                "failed to read (cert, key) file, {}, {} read file error",
                cert_path,
                key_path
            );
        }
    };

    let pv_key = if Path::new(key_path)
        .extension()
        .map_or(false, |x| x == "der")
    {
        rustls::PrivateKey(key)
    } else {
        let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)
            .context("malformed PKCS #8 private key")?;
        match pkcs8.into_iter().next() {
            Some(x) => rustls::PrivateKey(x),
            None => {
                let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                    .context("malformed PKCS #1 private key")?;
                match rsa.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        anyhow::bail!("no private keys found");
                    }
                }
            }
        }
    };
    let cert_chain = if Path::new(cert_path)
        .extension()
        .map_or(false, |x| x == "der")
    {
        vec![rustls::Certificate(cert)]
    } else {
        rustls_pemfile::certs(&mut &*cert)
            .context("invalid PEM-encoded certificate")?
            .into_iter()
            .map(rustls::Certificate)
            .collect()
    };

    let mut client_auth_roots = rustls::RootCertStore::empty();
    for root in roots_path {
        let file = fs::read(root).expect("Failed to read file");
        let root_cert: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*file)
            .context("invalid PEM-encoded certificate")?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        if let Some(cert) = root_cert.get(0) {
            client_auth_roots.add(cert)?;
        }
    }
    let client_auth = rustls::server::AllowAnyAuthenticatedClient::new(client_auth_roots);
    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(cert_chain, pv_key)?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
}

async fn handle_data<T>(
    send: SendStream,
    mut recv: RecvStream,
    record_type: RecordType,
    source: String,
    store: RawEventStore<'_>,
) -> Result<()>
where
    T: Debug + DeserializeOwned,
{
    let sender_rotation = Arc::new(Mutex::new(send));
    let sender_interval = Arc::clone(&sender_rotation);

    let ack_cnt_rotation = Arc::new(AtomicU8::new(0));
    let ack_cnt_interval = Arc::clone(&ack_cnt_rotation);

    let ack_time_rotation = Arc::new(AtomicI64::new(NO_TIMESTAMP));
    let ack_time_interval = Arc::clone(&ack_time_rotation);

    let mut itv = time::interval(time::Duration::from_secs(ACK_INTERVAL_TIME));
    let (tx, mut rx) = channel(1);

    let handler = task::spawn(async move {
        loop {
            select! {
                _ = itv.tick() => {
                    let last_timestamp = ack_time_interval.load(Ordering::SeqCst);
                    if last_timestamp !=  NO_TIMESTAMP {
                        if sender_interval
                            .lock()
                            .await
                            .write_all(&last_timestamp.to_be_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                        ack_cnt_interval.store(0, Ordering::SeqCst);
                    }
                }
                Some(_) = rx.recv() => {
                    itv.reset();
                }
            }
        }
    });

    loop {
        match handle_body(&mut recv).await {
            Ok((raw_event, timestamp)) => {
                print_record_format::<T>(record_type, timestamp, &raw_event);
                store.append(&source, timestamp, &raw_event)?;
                if store.flush().is_ok() {
                    ack_cnt_rotation.fetch_add(1, Ordering::SeqCst);
                    ack_time_rotation.store(timestamp, Ordering::SeqCst);
                    if ACK_ROTATION_CNT <= ack_cnt_rotation.load(Ordering::SeqCst) {
                        sender_rotation
                            .lock()
                            .await
                            .write_all(&timestamp.to_be_bytes())
                            .await
                            .expect("failed to send request");
                        ack_cnt_rotation.store(0, Ordering::SeqCst);
                        tx.send(ITV_RESET).await?;
                    }
                }
            }
            Err(quinn::ReadExactError::FinishedEarly) => {
                handler.abort();
                break;
            }
            Err(e) => {
                handler.abort();
                bail!("handle {:?} error: {}", record_type, e)
            }
        }
    }

    Ok(())
}

async fn handle_body(recv: &mut RecvStream) -> Result<(Vec<u8>, i64), quinn::ReadExactError> {
    let mut ts_buf = [0; mem::size_of::<u64>()];
    let mut len_buf = [0; mem::size_of::<u32>()];
    let mut body_buf = Vec::new();

    recv.read_exact(&mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;

    body_buf.resize(len, 0);
    recv.read_exact(body_buf.as_mut_slice()).await?;

    Ok((body_buf, timestamp))
}
