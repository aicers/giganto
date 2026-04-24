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
#[cfg(feature = "bootroot")]
use x509_parser::extensions::GeneralName;
use x509_parser::nom::Parser;

pub const SERVER_REBOOT_DELAY: u64 = 3000;
pub const SERVER_ENDPOINT_DELAY: u64 = 300;
pub const SERVER_CONNNECTION_DELAY: u64 = 200;
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

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

#[cfg(feature = "bootroot")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct BootrootIdentity {
    instance_id: String,
    service_name: String,
    hostname: String,
    domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientIdentity {
    #[cfg(not(feature = "bootroot"))]
    Legacy { service: String, hostname: String },
    #[cfg(feature = "bootroot")]
    Bootroot(BootrootIdentity),
}

impl ClientIdentity {
    #[cfg(not(feature = "bootroot"))]
    fn from_legacy_subject(subject: &str) -> Option<Self> {
        let (service, hostname) = subject.split_once('@')?;

        Some(Self::Legacy {
            service: service.to_string(),
            hostname: hostname.to_string(),
        })
    }

    fn service_name(&self) -> &str {
        match self {
            #[cfg(not(feature = "bootroot"))]
            Self::Legacy { service, .. } => service,
            #[cfg(feature = "bootroot")]
            Self::Bootroot(identity) => &identity.service_name,
        }
    }

    fn hostname(&self) -> String {
        match self {
            #[cfg(not(feature = "bootroot"))]
            Self::Legacy { hostname, .. } => hostname.clone(),
            #[cfg(feature = "bootroot")]
            Self::Bootroot(identity) => identity.hostname.clone(),
        }
    }

    /// Returns the service FQDN used as the cert-derived sensor.
    ///
    /// Under `bootroot`, this is the join of SAN DNS labels 2, 3, 4
    /// (`{service_name}.{hostname}.{domain}`). Non-bootroot builds
    /// intentionally return the bare hostname to preserve legacy CN
    /// behavior for existing deployments.
    fn service_fqdn(&self) -> String {
        match self {
            #[cfg(not(feature = "bootroot"))]
            Self::Legacy { hostname, .. } => hostname.clone(),
            #[cfg(feature = "bootroot")]
            Self::Bootroot(identity) => identity.service_fqdn(),
        }
    }

    fn peer_connect_name(&self) -> String {
        match self {
            #[cfg(not(feature = "bootroot"))]
            Self::Legacy { hostname, .. } => hostname.clone(),
            #[cfg(feature = "bootroot")]
            Self::Bootroot(identity) => identity.san(),
        }
    }

    fn peer_dedup_key(&self) -> String {
        match self {
            #[cfg(not(feature = "bootroot"))]
            Self::Legacy { hostname, .. } => hostname.clone(),
            #[cfg(feature = "bootroot")]
            Self::Bootroot(identity) => identity.san(),
        }
    }

    fn into_subject_tuple(self) -> (String, String) {
        (self.service_name().to_string(), self.hostname())
    }
}

#[cfg(feature = "bootroot")]
impl BootrootIdentity {
    fn san(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.instance_id, self.service_name, self.hostname, self.domain
        )
    }

    fn service_fqdn(&self) -> String {
        format!("{}.{}.{}", self.service_name, self.hostname, self.domain)
    }
}

pub fn subject_from_cert(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    parse_client_identity(cert_info).map(ClientIdentity::into_subject_tuple)
}

/// Parses a peer certificate and returns `(service_name, service_fqdn)`.
///
/// Under the `bootroot` feature, `service_fqdn` is the join of SAN DNS labels
/// 2, 3, 4 (`{service_name}.{hostname}.{domain}`). Under legacy builds it
/// equals the bare hostname, so callers see no behavioral change.
///
/// # Errors
///
/// Returns an error if no certificate is present in the chain, the leaf
/// certificate cannot be parsed, or its identity does not match the configured
/// certificate format.
#[cfg(test)]
pub fn service_fqdn_from_cert(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    let identity = parse_client_identity(cert_info)?;
    Ok((identity.service_name().to_string(), identity.service_fqdn()))
}

/// Parses a peer certificate, logs the connected client identity, and returns
/// `(service_name, service_fqdn)`.
///
/// Under the `bootroot` feature, `service_fqdn` is the join of SAN DNS labels
/// 2, 3, 4 (`{service_name}.{hostname}.{domain}`). Under legacy builds it
/// equals the bare hostname.
///
/// # Errors
///
/// Returns an error if no certificate is present in the chain, the leaf
/// certificate cannot be parsed, or its identity does not match the configured
/// certificate format.
pub fn service_fqdn_from_cert_verbose(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    let identity = parse_client_identity(cert_info)?;
    info!(
        "Connected client name : {}@{}",
        identity.service_name(),
        identity.hostname()
    );
    Ok((identity.service_name().to_string(), identity.service_fqdn()))
}

pub fn peer_name_from_cert(cert_info: &[CertificateDer]) -> Result<String> {
    Ok(parse_client_identity(cert_info)?.peer_connect_name())
}

pub fn peer_dedup_key_from_cert(cert_info: &[CertificateDer]) -> Result<String> {
    Ok(parse_client_identity(cert_info)?.peer_dedup_key())
}

fn parse_client_identity(cert_info: &[CertificateDer]) -> Result<ClientIdentity> {
    let Some(cert) = cert_info.first() else {
        bail!("no certificate in identity");
    };
    let mut parser =
        x509_parser::certificate::X509CertificateParser::new().with_deep_parse_extensions(true);
    let Ok((_, x509)) = parser.parse(cert.as_ref()) else {
        bail!("invalid X.509 certificate");
    };

    #[cfg(feature = "bootroot")]
    {
        parse_bootroot_client_identity(&x509)
    }

    #[cfg(not(feature = "bootroot"))]
    {
        parse_legacy_client_identity(&x509)
    }
}

#[cfg(feature = "bootroot")]
fn parse_bootroot_client_identity(
    x509: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<ClientIdentity> {
    if let Some(subject_alt_name) = x509
        .subject_alternative_name()
        .context("failed to parse subject alternative name")?
    {
        for general_name in &subject_alt_name.value.general_names {
            if let GeneralName::DNSName(dns_name) = general_name
                && let Some(identity) = parse_bootroot_dns_identity(dns_name)
            {
                return Ok(ClientIdentity::Bootroot(identity));
            }
        }
    }

    bail!("the SAN DNS identity of the certificate is not valid");
}

#[cfg(not(feature = "bootroot"))]
fn parse_legacy_client_identity(
    x509: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<ClientIdentity> {
    let subject = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .context("the CN identity of the certificate is not valid")?;
    if subject.contains('@') {
        ClientIdentity::from_legacy_subject(subject)
            .context("the CN identity of the certificate is not valid")
    } else {
        bail!("the CN identity of the certificate is not valid");
    }
}

#[cfg(feature = "bootroot")]
fn parse_bootroot_dns_identity(dns_name: &str) -> Option<BootrootIdentity> {
    let mut labels = dns_name.splitn(4, '.');
    let instance = labels.next()?;
    let service = labels.next()?;
    let hostname = labels.next()?;
    let domain = labels.next()?;

    if instance.is_empty() || service.is_empty() || hostname.is_empty() || domain.is_empty() {
        return None;
    }

    Some(BootrootIdentity {
        instance_id: instance.to_string(),
        service_name: service.to_string(),
        hostname: hostname.to_string(),
        domain: domain.to_string(),
    })
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
    use std::fs;

    use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};

    use super::*;
    use crate::comm::{to_cert_chain, to_private_key, to_root_cert};
    #[cfg(feature = "bootroot")]
    use crate::test_bootroot::{
        BundleOrder, PeerPresentation, build_bootroot_chain_fixture, config_client_for_tests,
        config_client_without_cert, init_crypto, load_server_client_certs,
    };

    const LEGACY_CERT_PATH: &str = "tests/certs/node1/cert.pem";
    const LEGACY_KEY_PATH: &str = "tests/certs/node1/key.pem";
    const LEGACY_CA_CERT_PATH: &str = "tests/certs/ca_cert.pem";

    #[cfg(feature = "bootroot")]
    use std::{
        net::{IpAddr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    #[cfg(feature = "bootroot")]
    use quinn::Endpoint;
    #[cfg(feature = "bootroot")]
    use tokio::time::timeout;

    fn build_self_signed_cert_chain(
        common_name: &str,
        dns_name: &str,
    ) -> Vec<CertificateDer<'static>> {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let mut params = CertificateParams::new(vec![dns_name.to_string()]).expect("cert params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params.self_signed(&key_pair).expect("self-signed cert");
        to_cert_chain(cert.pem().as_bytes()).expect("parse in-memory cert")
    }

    fn load_certs(cert_path: &str, key_path: &str, ca_path: &str) -> Certs {
        load_certs_with_ca_paths(cert_path, key_path, &[ca_path.to_string()])
    }

    fn load_certs_with_ca_paths(cert_path: &str, key_path: &str, ca_paths: &[String]) -> Certs {
        let cert_pem = fs::read(cert_path).expect("read cert");
        let key_pem = fs::read(key_path).expect("read key");
        let root = to_root_cert(ca_paths).expect("read ca bundle");

        Certs {
            certs: to_cert_chain(&cert_pem).expect("parse cert"),
            key: to_private_key(&key_pem).expect("parse key"),
            root,
        }
    }

    #[cfg(not(feature = "bootroot"))]
    mod default_build_tests {
        use super::*;

        #[test]
        fn subject_from_cert_accepts_legacy_cn_identity() {
            let certs = load_certs(LEGACY_CERT_PATH, LEGACY_KEY_PATH, LEGACY_CA_CERT_PATH);

            let identity = subject_from_cert(&certs.certs).expect("legacy subject identity");

            assert_eq!(identity, ("giganto".to_string(), "node1".to_string()));
        }

        #[test]
        fn service_fqdn_from_cert_matches_hostname_in_default_build() {
            let certs = load_certs(LEGACY_CERT_PATH, LEGACY_KEY_PATH, LEGACY_CA_CERT_PATH);

            let identity =
                service_fqdn_from_cert(&certs.certs).expect("legacy service fqdn identity");

            assert_eq!(identity, ("giganto".to_string(), "node1".to_string()));
        }

        #[test]
        fn peer_name_from_cert_uses_legacy_hostname_in_default_build() {
            let certs = load_certs(LEGACY_CERT_PATH, LEGACY_KEY_PATH, LEGACY_CA_CERT_PATH);

            let peer_name =
                peer_name_from_cert(&certs.certs).expect("legacy peer connect name should parse");

            assert_eq!(peer_name, "node1");
        }

        #[test]
        fn subject_from_cert_rejects_bootroot_san_identity_in_default_build() {
            let certs = build_self_signed_cert_chain(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );

            let err =
                subject_from_cert(&certs).expect_err("default build should reject SAN-only cert");

            assert!(
                err.to_string()
                    .contains("the CN identity of the certificate is not valid")
            );
        }

        #[test]
        fn subject_from_cert_prefers_legacy_cn_even_when_bootroot_san_is_valid_in_default_build() {
            let certs =
                build_self_signed_cert_chain("giganto@node1", "001.piglet.node1.example.test");

            let identity =
                subject_from_cert(&certs).expect("default build should keep the legacy CN path");

            assert_eq!(identity, ("giganto".to_string(), "node1".to_string()));
        }

        #[test]
        fn subject_from_cert_accepts_legacy_cn_when_bootroot_san_is_invalid_in_default_build() {
            let certs = build_self_signed_cert_chain("giganto@node1", "piglet.node1.example.test");

            let identity = subject_from_cert(&certs).expect("legacy CN fallback");

            assert_eq!(identity, ("giganto".to_string(), "node1".to_string()));
        }
    }

    #[cfg(feature = "bootroot")]
    mod bootroot_tests {
        use super::*;

        async fn assert_bootroot_fixture_mtls_handshake(
            bundle_order: BundleOrder,
            peer_presentation: PeerPresentation,
        ) {
            init_crypto();

            let fixture = build_bootroot_chain_fixture(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );
            let (server_certs, client_certs) =
                load_server_client_certs(&fixture, bundle_order, peer_presentation);
            let server_certs = Arc::new(server_certs);
            let client_certs = Arc::new(client_certs);

            let server = Endpoint::server(
                config_server(&server_certs).expect("server config"),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            )
            .expect("server endpoint");
            let server_addr = server.local_addr().expect("server addr");

            let server_handle = {
                let server = server.clone();
                tokio::spawn(async move {
                    let connection = server
                        .accept()
                        .await
                        .expect("server accept")
                        .await
                        .expect("server connection");
                    let identity =
                        subject_from_cert(&extract_cert_from_conn(&connection).expect("peer cert"))
                            .expect("peer identity");
                    assert_eq!(identity, ("piglet".to_string(), "node1".to_string()));
                    connection.close(0_u32.into(), b"done");
                })
            };

            let client_socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
            let mut client = Endpoint::client(client_socket).expect("client endpoint");
            client.set_default_client_config(config_client(&client_certs).expect("client config"));
            let connection = client
                .connect(server_addr, &fixture.server_name)
                .expect("connect future")
                .await
                .expect("client connection");
            connection.close(0_u32.into(), b"done");

            timeout(Duration::from_secs(2), server_handle)
                .await
                .expect("server task timeout")
                .expect("server task failed");
            client.wait_idle().await;
            server.wait_idle().await;
        }

        async fn assert_bootroot_fixture_mtls_handshake_fails(
            server_certs: Certs,
            client_config: ClientConfig,
            server_name: &str,
        ) -> String {
            init_crypto();

            let server = Endpoint::server(
                config_server(&server_certs).expect("server config"),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            )
            .expect("server endpoint");
            let server_addr = server.local_addr().expect("server addr");

            let server_handle = {
                let server = server.clone();
                tokio::spawn(async move {
                    if let Some(connecting) = server.accept().await {
                        let _ = connecting.await;
                    }
                })
            };

            let client_socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
            let mut client = Endpoint::client(client_socket).expect("client endpoint");
            client.set_default_client_config(client_config);
            let err = timeout(Duration::from_secs(2), async {
                client
                    .connect(server_addr, server_name)
                    .expect("connect future")
                    .await
            })
            .await
            .expect("client connect timeout")
            .expect_err("connection should fail");

            server_handle.abort();
            let _ = server_handle.await;
            drop(client);
            drop(server);

            err.to_string()
        }

        #[test]
        fn subject_from_cert_accepts_bootroot_san_identity() {
            let certs = build_self_signed_cert_chain(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );

            let identity = subject_from_cert(&certs).expect("bootroot SAN identity");

            assert_eq!(identity, ("piglet".to_string(), "node1".to_string()));
        }

        #[test]
        fn service_fqdn_from_cert_joins_labels_2_3_4_under_bootroot() {
            let certs = build_self_signed_cert_chain(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );

            let identity = service_fqdn_from_cert(&certs).expect("bootroot service fqdn identity");

            assert_eq!(
                identity,
                (
                    "piglet".to_string(),
                    "piglet.node1.example.test".to_string()
                )
            );
        }

        #[test]
        fn service_fqdn_omits_instance_id_label_under_bootroot() {
            let certs = build_self_signed_cert_chain(
                "alpha.data-store.node2.example.test",
                "alpha.data-store.node2.example.test",
            );

            let identity = service_fqdn_from_cert(&certs).expect("bootroot service fqdn identity");

            assert_eq!(
                identity,
                (
                    "data-store".to_string(),
                    "data-store.node2.example.test".to_string()
                )
            );
        }

        #[test]
        fn subject_from_cert_accepts_non_numeric_bootroot_instance_id() {
            let certs = build_self_signed_cert_chain(
                "alpha.piglet.node1.example.test",
                "alpha.piglet.node1.example.test",
            );

            let identity = subject_from_cert(&certs).expect("bootroot SAN identity");
            let peer_dedup_key =
                peer_dedup_key_from_cert(&certs).expect("bootroot peer dedup key should parse");

            assert_eq!(identity, ("piglet".to_string(), "node1".to_string()));
            assert_eq!(peer_dedup_key, "alpha.piglet.node1.example.test");
        }

        #[test]
        fn parse_bootroot_identity_preserves_structured_components() {
            let certs = build_self_signed_cert_chain(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );

            let identity = parse_client_identity(&certs).expect("bootroot structured identity");

            assert_eq!(
                identity,
                ClientIdentity::Bootroot(BootrootIdentity {
                    instance_id: "001".to_string(),
                    service_name: "piglet".to_string(),
                    hostname: "node1".to_string(),
                    domain: "example.test".to_string(),
                })
            );
        }

        #[test]
        fn peer_name_from_cert_preserves_full_bootroot_dns_name() {
            let certs = build_self_signed_cert_chain(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );

            let peer_name =
                peer_name_from_cert(&certs).expect("bootroot peer connect name should parse");

            assert_eq!(peer_name, "001.piglet.node1.example.test");
        }

        #[test]
        fn peer_dedup_key_from_cert_preserves_instance_id() {
            let certs = build_self_signed_cert_chain(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );

            let peer_dedup_key =
                peer_dedup_key_from_cert(&certs).expect("bootroot peer dedup key should parse");

            assert_eq!(peer_dedup_key, "001.piglet.node1.example.test");
        }

        #[test]
        fn subject_from_cert_prefers_valid_bootroot_san_over_legacy_cn_in_bootroot_build() {
            let certs =
                build_self_signed_cert_chain("giganto@node1", "001.piglet.node1.example.test");

            let identity = subject_from_cert(&certs).expect("bootroot SAN should take precedence");

            assert_eq!(identity, ("piglet".to_string(), "node1".to_string()));
        }

        #[test]
        fn subject_from_cert_rejects_legacy_cn_without_bootroot_san_in_bootroot_build() {
            let certs = load_certs(LEGACY_CERT_PATH, LEGACY_KEY_PATH, LEGACY_CA_CERT_PATH);

            let err = subject_from_cert(&certs.certs)
                .expect_err("bootroot build should reject legacy-only cert");

            assert!(
                err.to_string()
                    .contains("the SAN DNS identity of the certificate is not valid")
            );
        }

        #[test]
        fn subject_from_cert_rejects_invalid_bootroot_san_without_legacy_cn_fallback() {
            let certs =
                build_self_signed_cert_chain("piglet.node1.example", "piglet.node1.example");

            let err = subject_from_cert(&certs).expect_err("invalid identity should fail");

            assert!(
                err.to_string()
                    .contains("the SAN DNS identity of the certificate is not valid")
            );
        }

        #[tokio::test]
        async fn bootroot_pem_bundle_accepts_intermediate_then_root_with_leaf_only_peers() {
            assert_bootroot_fixture_mtls_handshake(
                BundleOrder::IntermediateThenRoot,
                PeerPresentation::LeafOnly,
            )
            .await;
        }

        #[tokio::test]
        async fn bootroot_pem_bundle_accepts_intermediate_then_root_with_leaf_and_intermediate_peers()
         {
            assert_bootroot_fixture_mtls_handshake(
                BundleOrder::IntermediateThenRoot,
                PeerPresentation::LeafAndIntermediate,
            )
            .await;
        }

        #[tokio::test]
        async fn bootroot_pem_bundle_accepts_root_then_intermediate_with_leaf_only_peers() {
            assert_bootroot_fixture_mtls_handshake(
                BundleOrder::RootThenIntermediate,
                PeerPresentation::LeafOnly,
            )
            .await;
        }

        #[tokio::test]
        async fn bootroot_pem_bundle_accepts_root_then_intermediate_with_leaf_and_intermediate_peers()
         {
            assert_bootroot_fixture_mtls_handshake(
                BundleOrder::RootThenIntermediate,
                PeerPresentation::LeafAndIntermediate,
            )
            .await;
        }

        #[tokio::test]
        async fn bootroot_pem_bundle_missing_client_certificate_has_no_peer_identity() {
            init_crypto();

            let fixture = build_bootroot_chain_fixture(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );
            let server_certs = load_certs(
                &fixture.server_chain_path,
                &fixture.server_key_path,
                &fixture.ca_bundle_intermediate_then_root_path,
            );
            let client_config = config_client_without_cert(std::slice::from_ref(
                &fixture.ca_bundle_intermediate_then_root_path,
            ));

            let server = Endpoint::server(
                config_server(&server_certs).expect("server config"),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            )
            .expect("server endpoint");
            let server_addr = server.local_addr().expect("server addr");
            let server_handle = {
                let server = server.clone();
                tokio::spawn(async move {
                    let err = server
                        .accept()
                        .await
                        .expect("server accept")
                        .await
                        .expect_err("missing client certificate should fail handshake");
                    assert!(err.to_string().contains("peer sent no certificates"));
                })
            };

            let client_socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
            let mut client = Endpoint::client(client_socket).expect("client endpoint");
            client.set_default_client_config(client_config);
            let connection = client
                .connect(server_addr, &fixture.server_name)
                .expect("connect future")
                .await;
            if let Ok(connection) = connection {
                connection.close(0_u32.into(), b"done");
            }

            timeout(Duration::from_secs(2), server_handle)
                .await
                .expect("server task timeout")
                .expect("server task failed");
            client.wait_idle().await;
            server.wait_idle().await;
        }

        #[tokio::test]
        async fn bootroot_pem_bundle_rejects_untrusted_ca() {
            let fixture = build_bootroot_chain_fixture(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );
            let wrong_fixture = build_bootroot_chain_fixture(
                "001.piglet.node2.example.test",
                "001.piglet.node2.example.test",
            );
            let server_certs = load_certs(
                &fixture.server_chain_path,
                &fixture.server_key_path,
                &fixture.ca_bundle_intermediate_then_root_path,
            );
            let client_certs = load_certs_with_ca_paths(
                &fixture.client_chain_path,
                &fixture.client_key_path,
                std::slice::from_ref(&wrong_fixture.root_cert_path),
            );

            let err = assert_bootroot_fixture_mtls_handshake_fails(
                server_certs,
                config_client_for_tests(&client_certs),
                &fixture.server_name,
            )
            .await;

            assert!(
                err.contains("invalid peer certificate: BadSignature"),
                "untrusted CA should surface the current rustls validation error, got: {err}"
            );
        }

        #[tokio::test]
        async fn bootroot_pem_bundle_rejects_server_name_mismatch() {
            let fixture = build_bootroot_chain_fixture(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );
            let server_certs = load_certs(
                &fixture.server_chain_path,
                &fixture.server_key_path,
                &fixture.ca_bundle_intermediate_then_root_path,
            );
            let client_certs = load_certs(
                &fixture.client_chain_path,
                &fixture.client_key_path,
                &fixture.ca_bundle_intermediate_then_root_path,
            );

            let err = assert_bootroot_fixture_mtls_handshake_fails(
                server_certs,
                config_client_for_tests(&client_certs),
                "001.data-store.node2.example.test",
            )
            .await;

            assert!(
                err.contains(
                    "certificate not valid for name \"001.data-store.node2.example.test\""
                ),
                "server_name mismatch should name the invalid DNS target, got: {err}"
            );
        }

        #[tokio::test]
        async fn bootroot_pem_bundle_rejects_invalid_server_certificate_chain() {
            let fixture = build_bootroot_chain_fixture(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );
            let wrong_fixture = build_bootroot_chain_fixture(
                "001.piglet.node2.example.test",
                "001.piglet.node2.example.test",
            );
            let broken_server_pem = format!(
                "{}{}",
                fs::read_to_string(&fixture.server_leaf_path).expect("read server leaf"),
                fs::read_to_string(&wrong_fixture.intermediate_cert_path)
                    .expect("read unrelated intermediate"),
            );
            let server_certs = Certs {
                certs: to_cert_chain(broken_server_pem.as_bytes())
                    .expect("parse broken server chain"),
                key: to_private_key(&fs::read(&fixture.server_key_path).expect("read server key"))
                    .expect("parse server key"),
                root: to_root_cert(std::slice::from_ref(
                    &fixture.ca_bundle_intermediate_then_root_path,
                ))
                .expect("server client-auth roots"),
            };
            let client_certs = load_certs_with_ca_paths(
                &fixture.client_chain_path,
                &fixture.client_key_path,
                std::slice::from_ref(&fixture.root_cert_path),
            );

            let err = assert_bootroot_fixture_mtls_handshake_fails(
                server_certs,
                config_client_for_tests(&client_certs),
                &fixture.server_name,
            )
            .await;

            assert!(
                err.contains("invalid peer certificate: BadSignature"),
                "invalid server certificate chain should surface a signature validation error, got: {err}"
            );
        }
    }
}
