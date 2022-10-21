use anyhow::{bail, Context, Result};
use quinn::{Connection, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use std::{
    cmp::Ordering::{Equal, Greater, Less},
    mem,
    sync::Arc,
};
use tracing::info;
use x509_parser::nom::Parser;

#[allow(clippy::module_name_repetitions)]
pub fn config_server(
    certs: Vec<Certificate>,
    key: PrivateKey,
    files: Vec<Vec<u8>>,
) -> Result<ServerConfig> {
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
        .with_single_cert(certs, key)?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
}

pub fn certificate_info(connection: &Connection) -> Result<String> {
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
                            .expect("the issuer of the certificate is not valid");
                        info!("Connected Client Name : {}", issuer);
                        return Ok(String::from(issuer));
                    }
                    _ => bail!("Failed to parse x509: {:?}", res),
                }
            }
            bail!("Failed to get certificate info")
        }
        bail!("Failed to convert certificate info")
    }
    bail!("Failed to read peer identity")
}

#[allow(clippy::module_name_repetitions)]
pub async fn server_handshake(
    send: &mut SendStream,
    recv: &mut RecvStream,
    min_version: &str,
    max_version: &str,
) -> Result<()> {
    let mut version_len = [0; mem::size_of::<u64>()];
    recv.read_exact(&mut version_len).await?;
    let len = u64::from_le_bytes(version_len);

    let mut version_buf = Vec::new();
    version_buf.resize(len.try_into()?, 0);
    recv.read_exact(version_buf.as_mut_slice()).await?;
    let version = String::from_utf8(version_buf).unwrap();

    match min_version.cmp(&version) {
        Less | Equal => match max_version.cmp(&version) {
            Greater => {
                send.write_all(&handshake_buffer(Some(env!("CARGO_PKG_VERSION"))))
                    .await?;
                info!("Compatible Version");
            }
            Less | Equal => {
                send.write_all(&handshake_buffer(None)).await?;
                bail!("Incompatible version")
            }
        },
        Greater => {
            send.write_all(&handshake_buffer(None)).await?;
            bail!("Incompatible version")
        }
    }
    Ok(())
}

fn handshake_buffer(resp: Option<&str>) -> Vec<u8> {
    let resp_data = bincode::serialize::<Option<&str>>(&resp).unwrap();
    let resp_data_len = u64::try_from(resp_data.len())
        .expect("less than u64::MAX")
        .to_le_bytes();
    let mut resp_buf = Vec::with_capacity(resp_data_len.len() + resp_data.len());
    resp_buf.extend(resp_data_len);
    resp_buf.extend(resp_data);
    resp_buf
}
