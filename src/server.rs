use anyhow::{bail, Context, Result};
use quinn::{Connection, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use semver::{Version, VersionReq};
use std::{mem, sync::Arc};
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
        .expect("safevalue")
        .max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
}

pub fn certificate_info(connection: &Connection) -> Result<String> {
    let Some(conn_info) = connection.peer_identity() else {
        bail!("no peer identity");
    };
    let Some(cert_info) = conn_info.downcast_ref::<Vec<rustls::Certificate>>() else {
        bail!("non-certificate identity");
    };
    let Some(cert) = cert_info.get(0) else {
        bail!("no certificate in identity");
    };
    let mut parser =
        x509_parser::certificate::X509CertificateParser::new().with_deep_parse_extensions(false);
    let Ok((_, x509)) = parser.parse(cert.as_ref()) else {
        bail!("invalid X.509 certificate");
    };
    let subject = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .context("the subject of the certificate is not valid")?;
    info!("Connected Client Name : {}", subject);
    Ok(String::from(subject))
}

#[allow(clippy::module_name_repetitions)]
pub async fn server_handshake(
    send: &mut SendStream,
    recv: &mut RecvStream,
    std_version: &str,
) -> Result<()> {
    let mut version_len = [0; mem::size_of::<u64>()];
    recv.read_exact(&mut version_len).await?;
    let len = u64::from_le_bytes(version_len);

    let mut version_buf = Vec::new();
    version_buf.resize(len.try_into()?, 0);
    recv.read_exact(version_buf.as_mut_slice()).await?;

    let version =
        Version::parse(&String::from_utf8(version_buf).context("invalid byte conversion")?)?;
    let req_version = VersionReq::parse(std_version)?;

    info!(
        "Handshaking: required = {}, requested = {}",
        std_version, version
    );
    if req_version.matches(&version) {
        send.write_all(&handshake_buffer(Some(env!("CARGO_PKG_VERSION")))?)
            .await?;
        info!("Compatible version");
    } else {
        send.write_all(&handshake_buffer(None)?).await?;
        bail!("Incompatible version")
    }

    Ok(())
}

fn handshake_buffer(resp: Option<&str>) -> Result<Vec<u8>> {
    let resp_data = bincode::serialize::<Option<&str>>(&resp)?;
    let resp_data_len = u64::try_from(resp_data.len())
        .context("less than u64::MAX")?
        .to_le_bytes();
    let mut resp_buf = Vec::with_capacity(resp_data_len.len() + resp_data.len());
    resp_buf.extend(resp_data_len);
    resp_buf.extend(resp_data);
    Ok(resp_buf)
}
