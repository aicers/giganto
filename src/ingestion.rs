use anyhow::{anyhow, bail, Context, Result};
use futures_util::StreamExt;
use quinn::{Endpoint, ServerConfig};
use std::{fs, net::SocketAddr, sync::Arc};

pub struct Server {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

impl Server {
    pub fn new(server_address: &str) -> Self {
        let server_config = config_server().expect("server configuration error");
        Server {
            server_config,
            server_address: server_addr(server_address),
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
    let _req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed to reading request: {}", e))?;
    // let resp = str::from_utf8(&req)?;
    // println!("{}", resp); // resp 확인

    Ok(())
}

fn server_addr(addr: &str) -> SocketAddr {
    addr.parse::<SocketAddr>().unwrap()
}

fn config_server() -> Result<ServerConfig> {
    let dirs = directories::ProjectDirs::from("com", "einsis", "giganto").expect("unreachable");
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");
    fs::create_dir_all(&path).context("failed to create cert dir")?;
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(e) => {
            bail!("failed to read cert file, $HOME/Library/Application Support/com.einsis.giganto/('key.der', 'cert.der') {} ", e);
        }
    };

    let pv_key = rustls::PrivateKey(key);
    let cert_chain = vec![rustls::Certificate(cert)];
    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, pv_key)?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
}
