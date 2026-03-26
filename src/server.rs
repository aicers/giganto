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
use x509_parser::extensions::GeneralName;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub service: String,
    pub hostname: String,
}

impl ClientIdentity {
    fn from_legacy_subject(subject: &str) -> Option<Self> {
        let parsed = subject.split('@').collect::<Vec<_>>();
        if parsed.len() != 2 {
            return None;
        }

        Some(Self {
            service: parsed[0].to_string(),
            hostname: parsed[1].to_string(),
        })
    }

    fn into_tuple(self) -> (String, String) {
        (self.service, self.hostname)
    }
}

pub fn subject_from_cert(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    parse_client_identity(cert_info).map(ClientIdentity::into_tuple)
}

pub fn subject_from_cert_verbose(cert_info: &[CertificateDer]) -> Result<(String, String)> {
    let identity = parse_client_identity(cert_info)?;
    info!(
        "Connected client name : {}@{}",
        identity.service, identity.hostname
    );
    Ok(identity.into_tuple())
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
    let mut saw_dns_san = false;
    if let Some(subject_alt_name) = x509
        .subject_alternative_name()
        .context("failed to parse subject alternative name")?
    {
        for general_name in &subject_alt_name.value.general_names {
            if let GeneralName::DNSName(dns_name) = general_name {
                saw_dns_san = true;
                if let Some(identity) = parse_bootroot_dns_identity(dns_name) {
                    return Ok(identity);
                }
            }
        }
    }

    let subject = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .context("the CN identity of the certificate is not valid")?;
    if subject.contains('@') {
        ClientIdentity::from_legacy_subject(subject)
            .context("the CN identity of the certificate is not valid")
    } else if saw_dns_san {
        bail!(
            "the SAN DNS identity of the certificate is not valid and the CN identity of the certificate is not valid"
        );
    } else {
        bail!("the CN identity of the certificate is not valid");
    }
}

fn parse_bootroot_dns_identity(dns_name: &str) -> Option<ClientIdentity> {
    let mut labels = dns_name.split('.');
    let instance = labels.next()?;
    let service = labels.next()?;
    let hostname = labels.next()?;
    let domain_labels = labels.collect::<Vec<_>>();

    if !is_bootroot_instance_id(instance)
        || !is_dns_label(service)
        || !is_dns_label(hostname)
        || domain_labels.is_empty()
        || domain_labels.iter().any(|label| !is_dns_label(label))
    {
        return None;
    }

    Some(ClientIdentity {
        service: service.to_string(),
        hostname: hostname.to_string(),
    })
}

fn is_bootroot_instance_id(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit())
}

fn is_dns_label(value: &str) -> bool {
    if value.is_empty() || value.len() > 63 {
        return false;
    }

    let bytes = value.as_bytes();
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
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
    use std::{
        fs,
        net::{IpAddr, Ipv6Addr, SocketAddr},
        sync::OnceLock,
        time::Duration,
    };

    use quinn::Endpoint;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    use tempfile::TempDir;
    use tokio::time::timeout;

    use super::*;
    use crate::comm::{to_cert_chain, to_private_key, to_root_cert};

    const LEGACY_CERT_PATH: &str = "tests/certs/node1/cert.pem";
    const LEGACY_KEY_PATH: &str = "tests/certs/node1/key.pem";
    const LEGACY_CA_CERT_PATH: &str = "tests/certs/ca_cert.pem";

    static INIT: OnceLock<()> = OnceLock::new();

    fn init_crypto() {
        INIT.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[derive(Clone, Copy)]
    enum BundleOrder {
        IntermediateThenRoot,
        RootThenIntermediate,
    }

    #[derive(Clone, Copy)]
    enum PeerPresentation {
        LeafOnly,
        LeafAndIntermediate,
    }

    struct BootrootChainFixture {
        _temp_dir: TempDir,
        server_leaf_path: String,
        server_chain_path: String,
        server_key_path: String,
        client_leaf_path: String,
        client_chain_path: String,
        client_key_path: String,
        ca_bundle_intermediate_then_root_path: String,
        ca_bundle_root_then_intermediate_path: String,
        server_name: String,
    }

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
        let cert_pem = fs::read(cert_path).expect("read cert");
        let key_pem = fs::read(key_path).expect("read key");
        let root = to_root_cert(&[ca_path.to_string()]).expect("read ca bundle");

        Certs {
            certs: to_cert_chain(&cert_pem).expect("parse cert"),
            key: to_private_key(&key_pem).expect("parse key"),
            root,
        }
    }

    fn load_server_client_certs(
        fixture: &BootrootChainFixture,
        bundle_order: BundleOrder,
        peer_presentation: PeerPresentation,
    ) -> (Certs, Certs) {
        let ca_path = match bundle_order {
            BundleOrder::IntermediateThenRoot => &fixture.ca_bundle_intermediate_then_root_path,
            BundleOrder::RootThenIntermediate => &fixture.ca_bundle_root_then_intermediate_path,
        };

        let (server_cert_path, client_cert_path) = match peer_presentation {
            PeerPresentation::LeafOnly => (&fixture.server_leaf_path, &fixture.client_leaf_path),
            PeerPresentation::LeafAndIntermediate => {
                (&fixture.server_chain_path, &fixture.client_chain_path)
            }
        };

        (
            load_certs(server_cert_path, &fixture.server_key_path, ca_path),
            load_certs(client_cert_path, &fixture.client_key_path, ca_path),
        )
    }

    fn new_ca_params(common_name: &str, is_ca: IsCa) -> CertificateParams {
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = is_ca;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.use_authority_key_identifier_extension = true;
        params
    }

    fn new_leaf_params(
        common_name: &str,
        dns_name: &str,
        extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
    ) -> CertificateParams {
        let mut params = CertificateParams::new(vec![dns_name.to_string()]).expect("cert params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.extended_key_usages = extended_key_usages;
        params.use_authority_key_identifier_extension = true;
        params
    }

    fn build_bootroot_chain_fixture(
        client_common_name: &str,
        client_dns_name: &str,
    ) -> BootrootChainFixture {
        let root_key = KeyPair::generate().expect("generate root key");
        let root = CertifiedIssuer::self_signed(
            new_ca_params(
                "Bootroot Root CA",
                IsCa::Ca(BasicConstraints::Unconstrained),
            ),
            root_key,
        )
        .expect("build root CA");

        let intermediate_key = KeyPair::generate().expect("generate intermediate key");
        let intermediate = CertifiedIssuer::signed_by(
            new_ca_params(
                "Bootroot Intermediate CA",
                IsCa::Ca(BasicConstraints::Constrained(0)),
            ),
            intermediate_key,
            &root,
        )
        .expect("build intermediate CA");

        let server_key = KeyPair::generate().expect("generate server key");
        let server_name = "001.data-store.node1.example.test";
        let server_cert = new_leaf_params(
            server_name,
            server_name,
            vec![ExtendedKeyUsagePurpose::ServerAuth],
        )
        .signed_by(&server_key, &intermediate)
        .expect("build server cert");

        let client_key = KeyPair::generate().expect("generate client key");
        let client_cert = new_leaf_params(
            client_common_name,
            client_dns_name,
            vec![ExtendedKeyUsagePurpose::ClientAuth],
        )
        .signed_by(&client_key, &intermediate)
        .expect("build client cert");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let server_leaf_path = temp_dir.path().join("server-leaf.pem");
        let server_chain_path = temp_dir.path().join("server-chain.pem");
        let server_key_path = temp_dir.path().join("server-key.pem");
        let client_leaf_path = temp_dir.path().join("client-leaf.pem");
        let client_chain_path = temp_dir.path().join("client-chain.pem");
        let client_key_path = temp_dir.path().join("client-key.pem");
        let ca_bundle_intermediate_then_root_path =
            temp_dir.path().join("ca-bundle-intermediate-root.pem");
        let ca_bundle_root_then_intermediate_path =
            temp_dir.path().join("ca-bundle-root-intermediate.pem");

        fs::write(&server_leaf_path, server_cert.pem()).expect("write server leaf");
        fs::write(
            &server_chain_path,
            format!("{}{}", server_cert.pem(), intermediate.pem()),
        )
        .expect("write server chain");
        fs::write(&server_key_path, server_key.serialize_pem()).expect("write server key");
        fs::write(&client_leaf_path, client_cert.pem()).expect("write client leaf");
        fs::write(
            &client_chain_path,
            format!("{}{}", client_cert.pem(), intermediate.pem()),
        )
        .expect("write client chain");
        fs::write(&client_key_path, client_key.serialize_pem()).expect("write client key");
        fs::write(
            &ca_bundle_intermediate_then_root_path,
            format!("{}{}", intermediate.pem(), root.pem()),
        )
        .expect("write canonical ca bundle");
        fs::write(
            &ca_bundle_root_then_intermediate_path,
            format!("{}{}", root.pem(), intermediate.pem()),
        )
        .expect("write reversed ca bundle");

        BootrootChainFixture {
            _temp_dir: temp_dir,
            server_leaf_path: server_leaf_path.to_string_lossy().into_owned(),
            server_chain_path: server_chain_path.to_string_lossy().into_owned(),
            server_key_path: server_key_path.to_string_lossy().into_owned(),
            client_leaf_path: client_leaf_path.to_string_lossy().into_owned(),
            client_chain_path: client_chain_path.to_string_lossy().into_owned(),
            client_key_path: client_key_path.to_string_lossy().into_owned(),
            ca_bundle_intermediate_then_root_path: ca_bundle_intermediate_then_root_path
                .to_string_lossy()
                .into_owned(),
            ca_bundle_root_then_intermediate_path: ca_bundle_root_then_intermediate_path
                .to_string_lossy()
                .into_owned(),
            server_name: server_name.to_string(),
        }
    }

    #[test]
    fn subject_from_cert_accepts_legacy_cn_identity() {
        let certs = load_certs(LEGACY_CERT_PATH, LEGACY_KEY_PATH, LEGACY_CA_CERT_PATH);

        let identity = subject_from_cert(&certs.certs).expect("legacy subject identity");

        assert_eq!(identity, ("giganto".to_string(), "node1".to_string()));
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
    fn subject_from_cert_prefers_valid_bootroot_san_over_invalid_cn() {
        let certs =
            build_self_signed_cert_chain("not-a-legacy-cn", "001.piglet.node1.example.test");

        let identity = subject_from_cert(&certs).expect("bootroot SAN should take precedence");

        assert_eq!(identity, ("piglet".to_string(), "node1".to_string()));
    }

    #[test]
    fn subject_from_cert_falls_back_to_legacy_cn_when_bootroot_san_is_invalid() {
        let certs = build_self_signed_cert_chain("giganto@node1", "piglet.node1.example.test");

        let identity = subject_from_cert(&certs).expect("legacy CN fallback");

        assert_eq!(identity, ("giganto".to_string(), "node1".to_string()));
    }

    #[test]
    fn subject_from_cert_rejects_invalid_bootroot_san_without_legacy_cn_fallback() {
        let certs =
            build_self_signed_cert_chain("piglet.node1.example.test", "piglet.node1.example.test");

        let err = subject_from_cert(&certs).expect_err("invalid identity should fail");

        assert!(
            err.to_string()
                .contains("the SAN DNS identity of the certificate is not valid")
        );
    }

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

    #[tokio::test]
    async fn bootroot_pem_bundle_accepts_intermediate_then_root_with_leaf_only_peers() {
        assert_bootroot_fixture_mtls_handshake(
            BundleOrder::IntermediateThenRoot,
            PeerPresentation::LeafOnly,
        )
        .await;
    }

    #[tokio::test]
    async fn bootroot_pem_bundle_accepts_intermediate_then_root_with_leaf_and_intermediate_peers() {
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
    async fn bootroot_pem_bundle_accepts_root_then_intermediate_with_leaf_and_intermediate_peers() {
        assert_bootroot_fixture_mtls_handshake(
            BundleOrder::RootThenIntermediate,
            PeerPresentation::LeafAndIntermediate,
        )
        .await;
    }
}
