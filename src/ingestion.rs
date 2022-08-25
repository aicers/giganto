use anyhow::{anyhow, bail, Context, Result};
use chrono::prelude::DateTime;
use chrono::{Duration, NaiveDateTime, Utc};
use futures_util::StreamExt;
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use serde::Deserialize;
use std::mem;
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
};
use x509_parser::nom::Parser;

use crate::settings::Settings;

#[allow(unused)]
#[derive(Debug, Deserialize)]
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

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct DNSConn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    query: String,
}

type Log = (String, Vec<u8>);

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

    pub async fn run(self) {
        let (endpoint, mut incoming) =
            Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        println!(
            "listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        while let Some(conn) = incoming.next().await {
            let fut = handle_connection(conn);
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    eprintln!("connection failed: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;

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
            let fut = handle_request(stream);
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    eprintln!("failed: {}", e);
                }
            });
        }
        Ok(())
    }
    .await?;
    Ok(())
}

async fn handle_request((mut _send, mut recv): (SendStream, RecvStream)) -> Result<()> {
    let mut buf = [0; 4];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow!("failed to read record type: {}", e))?;
    let record_type = u32::from_le_bytes(buf);
    match record_type {
        0 => loop {
            match handle_body(&mut recv, record_type).await {
                Ok(r) => {
                    println!("{:?}", bincode::deserialize::<Conn>(&r)?);
                }
                Err(quinn::ReadExactError::FinishedEarly) => {
                    break;
                }
                Err(e) => bail!("handle tcpudp error: {}", e),
            }
        },
        1 => loop {
            match handle_body(&mut recv, record_type).await {
                Ok(r) => {
                    println!("{:?}", bincode::deserialize::<DNSConn>(&r)?);
                }
                Err(quinn::ReadExactError::FinishedEarly) => {
                    break;
                }
                Err(e) => bail!("handle dns error: {}", e),
            }
        },
        2 => loop {
            match handle_body(&mut recv, record_type).await {
                Ok(r) => {
                    println!("{:?}", bincode::deserialize::<Log>(&r)?);
                }
                Err(quinn::ReadExactError::FinishedEarly) => {
                    break;
                }
                Err(e) => bail!("handle log error: {}", e),
            }
        },
        _ => bail!("invalid record type"),
    };

    Ok(())
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

async fn handle_body(
    recv: &mut RecvStream,
    record_type: u32,
) -> Result<Vec<u8>, quinn::ReadExactError> {
    let mut ts_buf = [0; mem::size_of::<u64>()];
    let mut len_buf = [0; mem::size_of::<u32>()];
    let mut body_buf = Vec::new();

    recv.read_exact(&mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    println!(
        "record_type: {:?}\ntimestamp: {:?}",
        record_type,
        client_utc_time(timestamp),
    );
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;

    body_buf.resize(len, 0);
    recv.read_exact(body_buf.as_mut_slice()).await?;

    Ok(body_buf)
}
