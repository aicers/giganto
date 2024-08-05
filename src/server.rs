use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig, Connection, ServerConfig, TransportConfig,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use tracing::info;
use x509_parser::nom::Parser;

pub const SERVER_REBOOT_DELAY: u64 = 3000;
pub const SERVER_ENDPOINT_DELAY: u64 = 300;
pub const SERVER_CONNNECTION_DELAY: u64 = 200;
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(5_000);

#[allow(clippy::module_name_repetitions, clippy::struct_field_names)]
pub struct Certs {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub root: RootCertStore,
}

impl Clone for Certs {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
            root: self.root.clone(),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub fn config_server(certs: &Arc<Certs>) -> Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_auth = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(certs.root.clone()),
        provider.clone(),
    )
    .build()?;

    let server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs.certs.clone(), certs.key.clone_key())
        .context("server config error")?;

    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

    Arc::get_mut(&mut server_config.transport)
        .expect("safe value")
        .max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
}

pub fn extract_cert_from_conn(connection: &Connection) -> Result<Vec<CertificateDer>> {
    let Some(conn_info) = connection.peer_identity() else {
        bail!("no peer identity");
    };
    let Some(cert_info) = conn_info.downcast_ref::<Vec<CertificateDer>>().cloned() else {
        bail!("non-certificate identity");
    };
    Ok(cert_info)
}

pub fn certificate_info(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    certificate_info_default(cert_info, true)
}

pub fn certificate_info_default(
    cert_info: &[CertificateDer],
    is_print_connected_client_name: bool,
) -> Result<(String, String)> {
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
        if is_print_connected_client_name {
            info!("Connected client name : {subject}");
        }
        let parsed = subject.split('@').collect::<Vec<&str>>();

        Ok((String::from(parsed[0]), String::from(parsed[1])))
    } else {
        bail!("the subject of the certificate is not valid");
    }
}

pub fn config_client(certs: &Arc<Certs>) -> Result<ClientConfig> {
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(certs.root.clone())
    .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key())?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config)?));
    config.transport_config(Arc::new(transport));
    Ok(config)
}
