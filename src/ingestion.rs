use crate::settings::Settings;
use crate::storage::Database;
use anyhow::{anyhow, bail, Context, Result};
use chrono::{prelude::DateTime, Duration, NaiveDateTime, Utc};
use futures_util::StreamExt;
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use serde::Deserialize;
use std::{
    fmt::Debug,
    fs, mem,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
};
use x509_parser::nom::Parser;

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

async fn handle_request<'a>(
    source: String,
    (mut _send, mut recv): (SendStream, RecvStream),
    db: Database,
) -> Result<()> {
    let mut buf = [0; 4];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow!("failed to read record type: {}", e))?;

    if let Ok(record_type) = RecordType::try_from(u32::from_le_bytes(buf)) {
        match record_type {
            RecordType::Conn => {
                let conn_store = db.conn_store()?;
                loop {
                    match handle_body(&mut recv).await {
                        Ok((raw_event, timestamp)) => {
                            print_record_format::<Conn>(record_type, timestamp, &raw_event);
                            conn_store.append(&source, timestamp, &raw_event)?;
                        }
                        Err(quinn::ReadExactError::FinishedEarly) => {
                            break;
                        }
                        Err(e) => bail!("handle tcpudp error: {}", e),
                    }
                }
            }
            RecordType::Dns => {
                let dns_store = db.dns_store()?;
                loop {
                    match handle_body(&mut recv).await {
                        Ok((raw_event, timestamp)) => {
                            print_record_format::<DnsConn>(record_type, timestamp, &raw_event);
                            dns_store.append(&source, timestamp, &raw_event)?;
                        }
                        Err(quinn::ReadExactError::FinishedEarly) => {
                            break;
                        }
                        Err(e) => bail!("handle dns error: {}", e),
                    }
                }
            }
            RecordType::Log => {
                let log_store = db.log_store()?;
                loop {
                    match handle_body(&mut recv).await {
                        Ok((raw_event, timestamp)) => {
                            print_record_format::<Log>(record_type, timestamp, &raw_event);
                            log_store.append(&source, timestamp, &raw_event)?;
                        }
                        Err(quinn::ReadExactError::FinishedEarly) => {
                            break;
                        }
                        Err(e) => bail!("handle log error: {}", e),
                    }
                }
            }
            RecordType::Http => {
                let http_store = db.http_store()?;
                loop {
                    match handle_body(&mut recv).await {
                        Ok((raw_event, timestamp)) => {
                            print_record_format::<HttpConn>(record_type, timestamp, &raw_event);
                            http_store.append(&source, timestamp, &raw_event)?;
                        }
                        Err(quinn::ReadExactError::FinishedEarly) => {
                            break;
                        }
                        Err(e) => bail!("handle httpconn error: {}", e),
                    }
                }
            }
            RecordType::Rdp => {
                let rdp_store = db.rdp_store()?;
                loop {
                    match handle_body(&mut recv).await {
                        Ok((raw_event, timestamp)) => {
                            print_record_format::<RdpConn>(record_type, timestamp, &raw_event);
                            rdp_store.append(&source, timestamp, &raw_event)?;
                        }
                        Err(quinn::ReadExactError::FinishedEarly) => {
                            break;
                        }
                        Err(e) => bail!("handle rdpconn error: {}", e),
                    }
                }
            }
        };
    } else {
        bail!("failed to convert RecordType, invalid record type");
    }

    Ok(())
}

///print the raw data
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
