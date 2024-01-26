use anyhow::{bail, Context, Result};
use quinn::{ClientConfig, Connection, ServerConfig, TransportConfig};
use rustls::{Certificate, PrivateKey, RootCertStore};
use std::{sync::Arc, time::Duration};
use tracing::info;
use x509_parser::nom::Parser;

pub const SERVER_REBOOT_DELAY: u64 = 3000;
pub const SERVER_ENDPOINT_DELAY: u64 = 300;
pub const SERVER_CONNNECTION_DELAY: u64 = 200;
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(5_000);

#[allow(clippy::module_name_repetitions, clippy::struct_field_names)]
#[derive(Clone)]
pub struct Certs {
    pub certs: Vec<Certificate>,
    pub key: PrivateKey,
    pub ca_certs: RootCertStore,
}

#[allow(clippy::module_name_repetitions)]
pub fn config_server(certs: &Arc<Certs>) -> Result<ServerConfig> {
    let client_auth =
        rustls::server::AllowAnyAuthenticatedClient::new(certs.ca_certs.clone()).boxed();
    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs.certs.clone(), certs.key.clone())
        .context("server config error")?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

    Arc::get_mut(&mut server_config.transport)
        .expect("safe value")
        .max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
}

pub fn extract_cert_from_conn(connection: &Connection) -> Result<Vec<Certificate>> {
    let Some(conn_info) = connection.peer_identity() else {
        bail!("no peer identity");
    };
    let Some(cert_info) = conn_info
        .downcast_ref::<Vec<rustls::Certificate>>()
        .cloned()
    else {
        bail!("non-certificate identity");
    };
    Ok(cert_info)
}

pub fn certificate_info(cert_info: &[Certificate]) -> Result<(String, String)> {
    let Some(cert) = cert_info.first() else {
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
    if subject.contains('@') {
        info!("Connected client name : {subject}");
        let parsed = subject.split('@').collect::<Vec<&str>>();

        Ok((String::from(parsed[0]), String::from(parsed[1])))
    } else {
        bail!("the subject of the certificate is not valid");
    }
}

pub fn config_client(certs: &Arc<Certs>) -> Result<ClientConfig> {
    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(certs.ca_certs.clone())
        .with_client_auth_cert(certs.certs.clone(), certs.key.clone())?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

    let mut config = ClientConfig::new(Arc::new(tls_config));
    config.transport_config(Arc::new(transport));
    Ok(config)
}
