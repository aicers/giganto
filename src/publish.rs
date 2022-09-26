use crate::settings::Settings;
use crate::storage::Database;
use anyhow::{anyhow, bail, Context, Result};
use futures_util::StreamExt;
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use std::{net::SocketAddr, path::Path, sync::Arc};
use tracing::{error, info};

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

impl Server {
    pub fn new(s: &Settings, cert: Vec<u8>, key: Vec<u8>, files: Vec<Vec<u8>>) -> Self {
        let server_config = config_server(&s.cert, &s.key, cert, key, files)
            .expect("server configuration error with cert, key or root");
        Server {
            server_config,
            server_address: s.publish_address,
        }
    }

    pub async fn run(self, db: Database) {
        let (endpoint, mut incoming) =
            Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        info!(
            "listening on {}",
            endpoint.local_addr().expect("for local addr display")
        );

        while let Some(conn) = incoming.next().await {
            let db = db.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, db).await {
                    error!("connection failed: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(conn: quinn::Connecting, db: Database) -> Result<()> {
    let quinn::NewConnection { mut bi_streams, .. } = conn.await?;

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

            let db = db.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_request(stream, db).await {
                    error!("failed: {}", e);
                }
            });
        }
        Ok(())
    }
    .await?;
    Ok(())
}

async fn handle_request((_send, mut recv): (SendStream, RecvStream), _db: Database) -> Result<()> {
    let mut buf = [0; 4];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow!("failed to read record type: {}", e))?;

    Ok(())
}

fn config_server(
    cert_path: &Path,
    key_path: &Path,
    cert: Vec<u8>,
    key: Vec<u8>,
    files: Vec<Vec<u8>>,
) -> Result<ServerConfig> {
    let pv_key = if key_path.extension().map_or(false, |x| x == "der") {
        rustls::PrivateKey(key)
    } else {
        let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)
            .context("malformed PKCS #8 private key")?;
        if let Some(x) = pkcs8.into_iter().next() {
            rustls::PrivateKey(x)
        } else {
            let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                .context("malformed PKCS #1 private key")?;
            match rsa.into_iter().next() {
                Some(x) => rustls::PrivateKey(x),
                None => {
                    bail!("no private keys found. Check the location of the private key and try again.");
                }
            }
        }
    };
    let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
        vec![rustls::Certificate(cert)]
    } else {
        rustls_pemfile::certs(&mut &*cert)
            .context("invalid PEM-encoded certificate")?
            .into_iter()
            .map(rustls::Certificate)
            .collect()
    };

    let mut client_auth_roots = rustls::RootCertStore::empty();
    for file in files {
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
