use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use quinn::{
    ClientConfig, Connection, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::pki_types::pem::PemObject;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use senta_protocol::auth::tls::{TELEMETRY_ALPN, ingress_server_config};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::nom::Parser;
use x509_parser::prelude::FromDer;

pub const SERVER_REBOOT_DELAY: u64 = 3000;
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

/// The TLS policy of every Giganto server: TLS 1.3 only, X25519MLKEM768 only.
///
/// `main` installs it as the process default, so Giganto's own clients
/// inherit it as well. Because it carries only TLS 1.3 cipher suites, a
/// builder asking for `DEFAULT_VERSIONS` still gets TLS 1.3 alone.
pub(crate) fn server_crypto_provider() -> rustls::crypto::CryptoProvider {
    let default = rustls::crypto::aws_lc_rs::default_provider();
    let cipher_suites = default
        .cipher_suites
        .iter()
        .copied()
        .filter(|suite| suite.version() == &rustls::version::TLS13)
        .collect();
    rustls::crypto::CryptoProvider {
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
        cipher_suites,
        ..default
    }
}

/// Builds the TLS configuration shared by the QUIC servers and the GraphQL
/// HTTPS server, requiring a client certificate issued under `certs.root`.
///
/// It names [`server_crypto_provider`] and TLS 1.3 explicitly rather than
/// relying on the process default.
fn tls_server_config(certs: &Certs) -> Result<rustls::ServerConfig> {
    let provider = Arc::new(server_crypto_provider());
    let client_auth = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(certs.root.clone()),
        Arc::clone(&provider),
    )
    .build()?;

    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure TLS protocol versions")?
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs.certs.clone(), certs.key.clone_key())
        .context("server config error")
}

#[allow(clippy::module_name_repetitions)]
pub fn config_server(certs: &Certs) -> Result<ServerConfig> {
    let server_crypto = tls_server_config(certs)?;

    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

    Arc::get_mut(&mut server_config.transport)
        .expect("safe value")
        .max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
}

/// Builds the TLS configuration of the GraphQL HTTPS server, offering the
/// `h2` and `http/1.1` ALPN protocols.
pub(crate) fn graphql_server_config(certs: &Certs) -> Result<Arc<rustls::ServerConfig>> {
    let mut config = tls_server_config(certs)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Builds the TLS configuration of the endpoint entry, the port Clumit
/// Endpoint sends telemetry to.
///
/// The configuration is senta-protocol's `ingress_server_config`: TLS 1.3
/// only, over [`server_crypto_provider`], offering `TELEMETRY_ALPN` alone, and
/// verifying clients with its `EndpointClientVerifier`, which accepts the
/// self-signed Ed25519 certificate an endpoint presents and checks the
/// handshake signature made with its key. That verification shares nothing
/// with the module ports' [`tls_server_config`]: endpoints are not issued
/// certificates by the CA the module ports trust.
///
/// Endpoints trust only the root, and the certificate file holds only the
/// node's leaf, so the chain presented is the leaf followed by the
/// intermediate that issued it, chosen from `ca_pem` by
/// [`endpoint_cert_chain`].
///
/// # Errors
///
/// Returns an error if no issuing intermediate can be chosen, or if rustls
/// rejects the chain or the key.
pub(crate) fn endpoint_server_config(
    certs: &Certs,
    ca_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>> {
    let chain = endpoint_cert_chain(&certs.certs, ca_pem)
        .context("cannot choose the endpoint certificate chain")?;
    let config = ingress_server_config(
        Arc::new(server_crypto_provider()),
        chain,
        certs.key.clone_key(),
        TELEMETRY_ALPN,
    )
    .context("cannot build the endpoint TLS configuration")?;
    Ok(Arc::new(config))
}

/// Returns the chain the endpoint entry presents: the first certificate of
/// `certs` (the node's leaf) followed by the intermediate that issued it,
/// chosen from the certificates of `ca_pem`. The root is never added.
///
/// The intermediate is chosen in three steps:
///
/// 1. The candidates are the certificates whose subject is the leaf's issuer
///    and whose Subject Key Identifier is the key identifier of the leaf's
///    Authority Key Identifier. If the leaf carries no key identifier there,
///    the subject alone decides. Certificates with identical DER, as when one
///    bundle file is listed twice in `--ca-certs`, count as one.
/// 2. If two or more candidates remain, only those whose key verifies the
///    leaf's signature are kept. During a CA rotation the bundle holds two
///    generations, which may share the intermediate's subject name.
/// 3. If exactly one remains and it is not self-signed (its subject differs
///    from its issuer), it is chosen. Anything else is no match.
///
/// # Errors
///
/// Returns an error if `certs` is empty, if the leaf or `ca_pem` cannot be
/// parsed, or if the steps above find no match.
fn endpoint_cert_chain(
    certs: &[CertificateDer<'static>],
    ca_pem: &[u8],
) -> Result<Vec<CertificateDer<'static>>> {
    let leaf = certs
        .first()
        .context("the certificate file holds no certificate")?;
    let cas = CertificateDer::pem_slice_iter(ca_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid PEM-encoded certificate in the CA bundle")?;
    let intermediate = choose_issuing_intermediate(leaf, &cas)?;
    Ok(vec![leaf.clone(), intermediate])
}

/// Chooses the intermediate that issued `leaf` from `cas`, by the steps
/// [`endpoint_cert_chain`] describes.
fn choose_issuing_intermediate(
    leaf: &CertificateDer<'_>,
    cas: &[CertificateDer<'static>],
) -> Result<CertificateDer<'static>> {
    let (_, leaf_x509) = X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| anyhow::anyhow!("cannot parse the node certificate: {e}"))?;
    let issuer = leaf_x509.issuer().as_raw();
    let authority_key_id = authority_key_id(&leaf_x509);

    let mut seen: Vec<&[u8]> = Vec::new();
    let mut candidates: Vec<(&CertificateDer<'static>, X509Certificate<'_>)> = Vec::new();
    for der in cas {
        if seen.contains(&der.as_ref()) {
            continue;
        }
        seen.push(der.as_ref());
        // A certificate that does not parse names no subject, so it cannot be
        // the issuer; the bundle itself was already accepted as trust anchors
        // when the TLS material was loaded.
        let Ok((_, ca)) = X509Certificate::from_der(der.as_ref()) else {
            continue;
        };
        if ca.subject().as_raw() != issuer {
            continue;
        }
        if let Some(authority_key_id) = authority_key_id
            && subject_key_id(&ca) != Some(authority_key_id)
        {
            continue;
        }
        candidates.push((der, ca));
    }

    if candidates.len() > 1 {
        candidates.retain(|(_, ca)| leaf_x509.verify_signature(Some(ca.public_key())).is_ok());
    }

    match candidates.as_slice() {
        [(der, ca)] if ca.subject().as_raw() != ca.issuer().as_raw() => Ok((*der).clone()),
        [_] => bail!(
            "the only CA certificate that matches the node certificate's issuer is self-signed, \
             not an intermediate"
        ),
        [] => bail!("no certificate in the CA bundle is the issuer of the node certificate"),
        many => bail!(
            "{} certificates in the CA bundle match the node certificate's issuer and verify \
             its signature",
            many.len()
        ),
    }
}

/// Returns the key identifier of `cert`'s Authority Key Identifier, or `None`
/// if it carries none.
fn authority_key_id<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a [u8]> {
    cert.extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => Some(aki),
            _ => None,
        })
        .and_then(|aki| aki.key_identifier.as_ref())
        .map(|id| id.0)
}

/// Returns `cert`'s Subject Key Identifier, or `None` if it carries none.
fn subject_key_id<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a [u8]> {
    cert.extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0),
            _ => None,
        })
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootrootIdentity {
    instance_id: String,
    service_name: String,
    hostname: String,
    domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientIdentity {
    Bootroot(BootrootIdentity),
}

impl ClientIdentity {
    fn service_name(&self) -> &str {
        match self {
            Self::Bootroot(identity) => &identity.service_name,
        }
    }

    #[cfg(test)]
    fn hostname(&self) -> String {
        match self {
            Self::Bootroot(identity) => identity.hostname.clone(),
        }
    }

    fn host_fqdn(&self) -> String {
        match self {
            Self::Bootroot(identity) => identity.host_fqdn(),
        }
    }

    /// Returns the service FQDN used as the cert-derived sensor.
    ///
    /// This is the join of SAN DNS labels 2, 3, 4
    /// (`{service_name}.{hostname}.{domain}`).
    fn service_fqdn(&self) -> String {
        match self {
            Self::Bootroot(identity) => identity.service_fqdn(),
        }
    }

    fn peer_connect_name(&self) -> String {
        match self {
            Self::Bootroot(identity) => identity.san(),
        }
    }

    fn peer_dedup_key(&self) -> String {
        match self {
            Self::Bootroot(identity) => identity.san(),
        }
    }

    #[cfg(test)]
    fn into_subject_tuple(self) -> (String, String) {
        (self.service_name().to_string(), self.hostname())
    }
}

/// Formats a parsed client identity for connected-client log messages.
///
/// Returns the full SAN-derived identity
/// (`{instance_id}.{service_name}.{hostname}.{domain}`).
fn format_connected_client_display(identity: &ClientIdentity) -> String {
    match identity {
        ClientIdentity::Bootroot(identity) => identity.san(),
    }
}

impl BootrootIdentity {
    fn san(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.instance_id, self.service_name, self.hostname, self.domain
        )
    }

    fn host_fqdn(&self) -> String {
        format!("{}.{}", self.hostname, self.domain)
    }

    fn service_fqdn(&self) -> String {
        format!("{}.{}.{}", self.service_name, self.hostname, self.domain)
    }
}

#[cfg(test)]
pub(crate) fn subject_from_cert(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    parse_client_identity(cert_info).map(ClientIdentity::into_subject_tuple)
}

/// Parses a peer certificate and returns `(service_name, service_fqdn)`.
///
/// `service_fqdn` is the join of SAN DNS labels 2, 3, 4
/// (`{service_name}.{hostname}.{domain}`).
///
/// # Errors
///
/// Returns an error if no certificate is present in the chain, the leaf
/// certificate cannot be parsed, or it does not carry a valid SAN identity.
pub fn service_fqdn_from_cert(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    let identity = parse_client_identity(cert_info)?;
    Ok((identity.service_name().to_string(), identity.service_fqdn()))
}

/// Parses a peer certificate and returns the connected-client display identity.
///
/// Returns the full SAN-derived identity
/// (`{instance_id}.{service_name}.{hostname}.{domain}`).
///
/// # Errors
///
/// Returns an error if no certificate is present in the chain, the leaf
/// certificate cannot be parsed, or it does not carry a valid SAN identity.
pub fn connected_client_display_from_cert(cert_info: &[CertificateDer]) -> Result<String> {
    let identity = parse_client_identity(cert_info)?;
    Ok(format_connected_client_display(&identity))
}

pub fn peer_name_from_cert(cert_info: &[CertificateDer]) -> Result<String> {
    Ok(parse_client_identity(cert_info)?.peer_connect_name())
}

/// Returns the host FQDN identifier for the certificate.
///
/// Returns `{hostname}.{domain}` derived from the SAN DNS labels 3 and 4.
///
/// # Errors
///
/// Returns an error if the certificate cannot be parsed or does not carry a
/// valid SAN identity.
pub fn host_fqdn_from_cert(cert_info: &[CertificateDer]) -> Result<String> {
    Ok(parse_client_identity(cert_info)?.host_fqdn())
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

    parse_bootroot_client_identity(&x509)
}

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

/// Builds the TLS configuration of Giganto's clients to its peers, trusting
/// only `certs.root` and presenting `certs.certs`.
///
/// It is built on the process default provider, which `main` sets to
/// [`server_crypto_provider`]. The server's certificate is verified by rustls's
/// webpki verifier against the server name the connection is made to.
///
/// # Errors
///
/// Returns an error if the client certificate and key cannot be used.
pub(crate) fn tls_client_config(certs: &Certs) -> Result<rustls::ClientConfig> {
    rustls::ClientConfig::builder()
        .with_root_certificates(certs.root.clone())
        .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key())
        .context("client config error")
}

pub fn config_client(certs: &Certs) -> Result<ClientConfig> {
    let tls_config = tls_client_config(certs)?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config)?));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{IpAddr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use quinn::Endpoint;
    use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
    use tokio::time::timeout;

    use super::*;
    use crate::comm::{to_cert_chain, to_private_key, to_root_cert};
    use crate::test_bootroot::{
        BundleOrder, PeerPresentation, build_bootroot_chain_fixture, config_client_for_tests,
        config_client_without_cert, config_client_x25519_only, init_crypto,
        load_server_client_certs,
    };

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

    /// `main` installs this provider as the process default, which every
    /// server configuration also names explicitly.
    #[test]
    fn server_crypto_provider_offers_only_hybrid_post_quantum_key_exchange_over_tls13() {
        let provider = server_crypto_provider();
        assert_eq!(
            provider
                .kx_groups
                .iter()
                .map(|group| group.name())
                .collect::<Vec<_>>(),
            vec![rustls::NamedGroup::X25519MLKEM768],
        );
        // quinn refuses a provider without this suite.
        assert!(
            provider
                .cipher_suites
                .iter()
                .any(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256),
            "the provider must keep TLS13_AES_128_GCM_SHA256: {:?}",
            provider.cipher_suites,
        );
        assert!(
            provider
                .cipher_suites
                .iter()
                .all(|suite| suite.version() == &rustls::version::TLS13),
            "every cipher suite must be a TLS 1.3 suite: {:?}",
            provider.cipher_suites,
        );
    }

    mod bootroot_tests {
        use super::*;

        const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
            let connection = timeout(HANDSHAKE_TIMEOUT, async {
                client
                    .connect(server_addr, &fixture.server_name)
                    .expect("connect future")
                    .await
            })
            .await
            .expect("client connect timeout")
            .expect("client connection");
            connection.close(0_u32.into(), b"done");

            timeout(HANDSHAKE_TIMEOUT, server_handle)
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
            let err = timeout(HANDSHAKE_TIMEOUT, async {
                client
                    .connect(server_addr, server_name)
                    .expect("connect future")
                    .await
            })
            .await
            .expect("client connect timeout")
            .expect_err("connection should fail");

            server_handle.abort();
            let _ = timeout(HANDSHAKE_TIMEOUT, server_handle)
                .await
                .expect("server task timeout");
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
        fn connected_client_display_uses_full_san_identity_under_bootroot() {
            let certs = build_self_signed_cert_chain(
                "001.agent.node1.example.test",
                "001.agent.node1.example.test",
            );

            let display =
                connected_client_display_from_cert(&certs).expect("bootroot display identity");

            assert_eq!(display, "001.agent.node1.example.test");
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
        fn host_fqdn_from_cert_joins_hostname_and_domain_in_bootroot_build() {
            let certs = build_self_signed_cert_chain(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );

            let host_fqdn = host_fqdn_from_cert(&certs).expect("bootroot host_fqdn should parse");

            assert_eq!(host_fqdn, "node1.example.test");
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
            let certs = build_self_signed_cert_chain("giganto@node1", "node1");

            let err = subject_from_cert(&certs).expect_err("legacy-only cert should be rejected");

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
        async fn bootroot_pem_bundle_missing_client_certificate_is_rejected_at_handshake() {
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
            let connection = timeout(HANDSHAKE_TIMEOUT, async {
                client
                    .connect(server_addr, &fixture.server_name)
                    .expect("connect future")
                    .await
            })
            .await
            .expect("client connect timeout");
            if let Ok(connection) = connection {
                connection.close(0_u32.into(), b"done");
            }

            timeout(HANDSHAKE_TIMEOUT, server_handle)
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

        /// The `bootroot_pem_bundle_accepts_*` tests above are the accepting
        /// half: `config_server` completes a handshake with `config_client`.
        #[tokio::test]
        async fn config_server_refuses_x25519_only_client() {
            let fixture = build_bootroot_chain_fixture(
                "001.piglet.node1.example.test",
                "001.piglet.node1.example.test",
            );
            let (server_certs, client_certs) = load_server_client_certs(
                &fixture,
                BundleOrder::IntermediateThenRoot,
                PeerPresentation::LeafOnly,
            );

            let err = assert_bootroot_fixture_mtls_handshake_fails(
                server_certs,
                config_client_x25519_only(&client_certs),
                &fixture.server_name,
            )
            .await;

            assert!(
                err.contains("NoKxGroupsInCommon"),
                "an X25519-only client should be refused for lacking X25519MLKEM768, got: {err}"
            );
        }
    }

    /// The choice of the intermediate the endpoint entry presents after the
    /// node's leaf.
    mod endpoint_chain_tests {
        use super::*;
        use crate::test_bootroot::{CaGeneration, NodeCert, write_node_files};
        use crate::tls_reload::{CertPaths, load_tls_material};

        const NODE: &str = "001.giganto.node1.example.test";

        fn chain(leaf: &NodeCert, bundle: &str) -> Result<Vec<CertificateDer<'static>>> {
            endpoint_cert_chain(std::slice::from_ref(&leaf.der), bundle.as_bytes())
        }

        fn assert_no_match(leaf: &NodeCert, bundle: &str, cause: &str) {
            let error = chain(leaf, bundle).expect_err("no intermediate may be chosen");
            assert!(
                format!("{error:#}").contains(cause),
                "the error should say {cause:?}, got: {error:#}"
            );
        }

        #[test]
        fn the_intermediate_matching_the_leaf_aki_is_chosen() {
            let ca = CaGeneration::new("Single");
            let leaf = ca.issue_node_cert(NODE);
            assert_eq!(
                chain(&leaf, &ca.bundle_pem()).expect("an intermediate is chosen"),
                vec![leaf.der.clone(), ca.intermediate.der().clone()]
            );
            // The bundle's order does not matter.
            let reversed = format!("{}{}", ca.root.pem(), ca.intermediate.pem());
            assert_eq!(
                chain(&leaf, &reversed).expect("an intermediate is chosen"),
                vec![leaf.der.clone(), ca.intermediate.der().clone()]
            );
        }

        #[test]
        fn of_two_generations_with_different_keys_the_aki_decides() {
            // The same intermediate name in both generations: only the key
            // identifiers tell them apart.
            let old = CaGeneration::with_intermediate_identity(
                "Old",
                "Bootroot Intermediate CA",
                &[1; 20],
            );
            let new = CaGeneration::with_intermediate_identity(
                "New",
                "Bootroot Intermediate CA",
                &[2; 20],
            );
            let bundle = format!("{}{}", old.bundle_pem(), new.bundle_pem());
            for (ca, other) in [(&old, &new), (&new, &old)] {
                let leaf = ca.issue_node_cert(NODE);
                let chosen = chain(&leaf, &bundle).expect("an intermediate is chosen");
                assert_eq!(
                    chosen,
                    vec![leaf.der.clone(), ca.intermediate.der().clone()]
                );
                assert!(!chosen.contains(other.intermediate.der()));
            }
        }

        #[test]
        fn of_two_generations_with_the_same_name_and_key_id_the_signature_decides() {
            let old = CaGeneration::with_intermediate_identity(
                "Old",
                "Bootroot Intermediate CA",
                &[9; 20],
            );
            let new = CaGeneration::with_intermediate_identity(
                "New",
                "Bootroot Intermediate CA",
                &[9; 20],
            );
            for bundle in [
                format!("{}{}", old.bundle_pem(), new.bundle_pem()),
                format!("{}{}", new.bundle_pem(), old.bundle_pem()),
            ] {
                for ca in [&old, &new] {
                    let leaf = ca.issue_node_cert(NODE);
                    assert_eq!(
                        chain(&leaf, &bundle).expect("the signature decides"),
                        vec![leaf.der.clone(), ca.intermediate.der().clone()]
                    );
                }
            }
        }

        #[test]
        fn without_an_aki_the_subject_and_then_the_signature_decide() {
            let ca = CaGeneration::new("Single");
            let leaf = ca.issue_node_cert_without_aki(NODE);
            assert_eq!(
                chain(&leaf, &ca.bundle_pem()).expect("the subject decides"),
                vec![leaf.der.clone(), ca.intermediate.der().clone()]
            );

            let old = CaGeneration::new("Rotation");
            let new = CaGeneration::new("Rotation");
            let bundle = format!("{}{}", old.bundle_pem(), new.bundle_pem());
            let leaf = new.issue_node_cert_without_aki(NODE);
            assert_eq!(
                chain(&leaf, &bundle).expect("the signature decides"),
                vec![leaf.der.clone(), new.intermediate.der().clone()]
            );
        }

        #[test]
        fn a_bundle_without_the_issuer_has_no_match() {
            let ca = CaGeneration::new("Issuing");
            let other = CaGeneration::new("Other");
            let leaf = ca.issue_node_cert(NODE);
            assert_no_match(
                &leaf,
                &other.bundle_pem(),
                "no certificate in the CA bundle",
            );
            // The root of the issuing generation alone is not the issuer.
            assert_no_match(&leaf, &ca.root.pem(), "no certificate in the CA bundle");
        }

        #[test]
        fn a_self_signed_issuer_is_not_an_intermediate() {
            let ca = CaGeneration::new("Flat");
            let leaf = ca.issue_node_cert_from_root(NODE);
            assert_no_match(&leaf, &ca.bundle_pem(), "self-signed");
        }

        #[test]
        fn two_candidates_that_both_verify_have_no_match() {
            let ca = CaGeneration::new("Reissued");
            let leaf = ca.issue_node_cert(NODE);
            let reissued_pem = ca.reissued_intermediate_pem();
            let bundle = format!("{}{reissued_pem}", ca.bundle_pem());
            assert_no_match(&leaf, &bundle, "2 certificates in the CA bundle");
        }

        #[test]
        fn the_same_bundle_listed_twice_still_has_a_match() {
            let dir = tempfile::tempdir().expect("tempdir");
            let ca = CaGeneration::new("Twice");
            let leaf = ca.issue_node_cert(NODE);
            let mut paths: CertPaths = write_node_files(dir.path(), &leaf, &ca.bundle_pem());
            paths.ca_certs_paths.push(paths.ca_certs_paths[0].clone());
            init_crypto();
            let material = load_tls_material(&paths).expect("load the TLS material");
            assert_eq!(
                endpoint_cert_chain(&material.certs.certs, &material.ca_pem)
                    .expect("an intermediate is chosen"),
                vec![leaf.der.clone(), ca.intermediate.der().clone()]
            );
            endpoint_server_config(&material.certs, &material.ca_pem)
                .expect("the endpoint TLS configuration is built");
        }

        #[test]
        fn certificates_that_do_not_parse_are_not_chosen() {
            const NOT_A_CERTIFICATE: &str =
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
            let ca = CaGeneration::new("Garbled");
            let leaf = ca.issue_node_cert(NODE);

            // A bundle entry that is not a certificate is skipped.
            let bundle = format!("{NOT_A_CERTIFICATE}{}", ca.bundle_pem());
            assert_eq!(
                chain(&leaf, &bundle).expect("an intermediate is chosen"),
                vec![leaf.der.clone(), ca.intermediate.der().clone()]
            );

            // A node certificate that is not one cannot be chained.
            let garbled = CertificateDer::from(vec![0_u8; 3]);
            let error = endpoint_cert_chain(&[garbled], ca.bundle_pem().as_bytes())
                .expect_err("a garbled node certificate has no chain");
            assert!(
                format!("{error:#}").contains("cannot parse the node certificate"),
                "got: {error:#}"
            );
            let error = endpoint_cert_chain(&[], ca.bundle_pem().as_bytes())
                .expect_err("no node certificate has no chain");
            assert!(
                format!("{error:#}").contains("holds no certificate"),
                "got: {error:#}"
            );
        }

        #[test]
        fn the_configuration_error_names_the_endpoint_chain() {
            let ca = CaGeneration::new("Flat");
            let leaf = ca.issue_node_cert_from_root(NODE);
            let certs = Certs {
                certs: vec![leaf.der.clone()],
                key: to_private_key(leaf.key_pem.as_bytes()).expect("parse key"),
                root: RootCertStore::empty(),
            };
            let error = endpoint_server_config(&certs, ca.bundle_pem().as_bytes())
                .expect_err("no intermediate may be chosen");
            assert!(
                format!("{error:#}").contains("endpoint certificate chain"),
                "got: {error:#}"
            );
        }
    }
}
