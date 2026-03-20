use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use quinn::{
    ClientConfig, Connection, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
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
pub fn config_server(certs: &Certs) -> Result<ServerConfig> {
    let client_auth =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(certs.root.clone())).build()?;

    let server_crypto = rustls::ServerConfig::builder()
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

pub fn extract_cert_from_conn(connection: &Connection) -> Result<Vec<CertificateDer<'_>>> {
    let Some(conn_info) = connection.peer_identity() else {
        bail!("no peer identity");
    };
    let Some(cert_info) = conn_info.downcast_ref::<Vec<CertificateDer>>().cloned() else {
        bail!("non-certificate identity");
    };
    Ok(cert_info)
}

pub fn subject_from_cert(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    subject_from_cert_opt(cert_info, false)
}

pub fn subject_from_cert_verbose(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    subject_from_cert_opt(cert_info, true)
}

/// Extracts the `(agent, sensor)` identity from a peer certificate.
///
/// Two identity formats are supported:
///
/// 1. **SAN DNS** (Bootroot): the first `dNSName` SAN with at least four
///    dot-separated labels is mapped as
///    `<instance>.<service>.<hostname>.<domain>` → `(service, instance)`,
///    i.e. `agent = labels[1]`, `sensor = labels[0]`.
/// 2. **Legacy CN**: the Common Name contains `@` and is split as
///    `agent@sensor` → `(agent, sensor)`.
///
/// The SAN path is attempted first; the CN path is used as a fallback.
///
/// # Errors
///
/// Returns an error if neither a valid SAN DNS identity nor a legacy CN
/// identity can be extracted from the certificate.
pub fn subject_from_cert_opt(
    cert_info: &[CertificateDer],
    logging: bool,
) -> Result<(String, String)> {
    let Some(cert) = cert_info.first() else {
        bail!("no certificate in identity");
    };
    let mut parser =
        x509_parser::certificate::X509CertificateParser::new().with_deep_parse_extensions(true);
    let Ok((_, x509)) = parser.parse(cert.as_ref()) else {
        bail!("invalid X.509 certificate");
    };

    // Try SAN DNS first
    let san_err = match identity_from_san(&x509) {
        Ok((agent, sensor)) => {
            if logging {
                info!("Connected client (SAN): agent={agent}, sensor={sensor}");
            }
            return Ok((agent, sensor));
        }
        Err(e) => e,
    };

    // Fall back to legacy CN parsing
    let cn_err = match identity_from_cn(&x509) {
        Ok((agent, sensor)) => {
            if logging {
                info!("Connected client (CN): {agent}@{sensor}");
            }
            return Ok((agent, sensor));
        }
        Err(e) => e,
    };

    bail!("SAN parsing failed: {san_err}; CN parsing failed: {cn_err}")
}

/// Attempts to extract `(agent, sensor)` from the first valid DNS SAN.
///
/// The DNS name must have at least four dot-separated, non-empty labels.
/// Mapping: `labels[1]` → agent (service), `labels[0]` → sensor (instance).
fn identity_from_san(
    x509: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(String, String)> {
    let san_ext = x509
        .subject_alternative_name()
        .ok()
        .flatten()
        .context("no SubjectAlternativeName extension")?;

    for name in &san_ext.value.general_names {
        if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
            let labels: Vec<&str> = dns.split('.').collect();
            if labels.len() >= 4 && labels.iter().all(|l| !l.is_empty()) {
                let sensor = labels[0].to_string();
                let agent = labels[1].to_string();
                return Ok((agent, sensor));
            }
        }
    }

    bail!("no DNS SAN with at least 4 labels found")
}

/// Attempts to extract `(agent, sensor)` from the legacy `CN=agent@sensor`.
fn identity_from_cn(
    x509: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(String, String)> {
    let cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .context("no Common Name in subject")?;

    if let Some((agent, sensor)) = cn.split_once('@') {
        Ok((agent.to_string(), sensor.to_string()))
    } else {
        bail!("CN '{cn}' does not contain '@'")
    }
}

pub fn config_client(certs: &Certs) -> Result<ClientConfig> {
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(certs.root.clone())
        .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key())?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config)?));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::CertificateDer;

    use super::subject_from_cert;

    /// Helper: build a self-signed DER certificate using `rcgen`.
    fn build_cert(cn: &str, san_dns: &[&str]) -> CertificateDer<'static> {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String(cn.to_owned()),
        );
        params.subject_alt_names = san_dns
            .iter()
            .map(|dns| rcgen::SanType::DnsName((*dns).try_into().expect("valid DNS name")))
            .collect();
        let cert = params
            .self_signed(&rcgen::KeyPair::generate().expect("key generation"))
            .expect("self-signed cert");
        CertificateDer::from(cert.der().to_vec())
    }

    #[test]
    fn legacy_cn_identity() {
        let der = build_cert("agentA@sensorA", &[]);
        let (agent, sensor) = subject_from_cert(&[der]).expect("should parse legacy CN");
        assert_eq!(agent, "agentA");
        assert_eq!(sensor, "sensorA");
    }

    #[test]
    fn san_dns_identity() {
        let der = build_cert("irrelevant", &["instance1.service1.host.example.com"]);
        let (agent, sensor) = subject_from_cert(&[der]).expect("should parse SAN DNS");
        assert_eq!(agent, "service1");
        assert_eq!(sensor, "instance1");
    }

    #[test]
    fn san_dns_preferred_over_cn() {
        let der = build_cert("agentA@sensorA", &["instance2.service2.host.example.com"]);
        let (agent, sensor) = subject_from_cert(&[der]).expect("SAN should take priority");
        assert_eq!(agent, "service2");
        assert_eq!(sensor, "instance2");
    }

    #[test]
    fn san_dns_too_few_labels_falls_back_to_cn() {
        let der = build_cert("agentB@sensorB", &["only.three.labels"]);
        let (agent, sensor) = subject_from_cert(&[der]).expect("should fall back to CN");
        assert_eq!(agent, "agentB");
        assert_eq!(sensor, "sensorB");
    }

    #[test]
    fn invalid_identity_reports_both_failures() {
        let der = build_cert("no-at-sign", &[]);
        let err = subject_from_cert(&[der]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("SAN parsing failed"), "msg: {msg}");
        assert!(msg.contains("CN parsing failed"), "msg: {msg}");
    }
}
