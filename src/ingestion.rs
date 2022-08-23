use anyhow::{anyhow, bail, Context, Result};
use chrono::prelude::DateTime;
use chrono::{Duration, NaiveDateTime, Utc};
use futures_util::StreamExt;
use quinn::{Endpoint, ServerConfig};
use std::{fs, net::SocketAddr, path::Path, sync::Arc};
use x509_parser::nom::Parser;

use crate::settings::Settings;

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

const REC_TYPE_LOC: usize = 0;
const REC_TYPE_SIZE: usize = 4;
const TIMESTAMP_LOC: usize = 4;
const TIMESTAMP_SIZE: usize = 8;
const RECODE_LOC: usize = 12;
const RECODE_SIZE: usize = 4;

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

async fn handle_request((mut _send, recv): (quinn::SendStream, quinn::RecvStream)) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed to reading request: {}", e))?;

    let record_type =
        u32::from_le_bytes(req[REC_TYPE_LOC..REC_TYPE_LOC + REC_TYPE_SIZE].try_into()?);
    let timstamp =
        i64::from_le_bytes(req[TIMESTAMP_LOC..TIMESTAMP_LOC + TIMESTAMP_SIZE].try_into()?);
    let _record = u32::from_le_bytes(req[RECODE_LOC..RECODE_LOC + RECODE_SIZE].try_into()?);

    println!(
        "record_type: {:?}\ntimestamp: {:?}",
        record_type,
        client_utc_time(timstamp)
    );
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
