use std::{
    fs,
    sync::{Arc, OnceLock},
};

use quinn::ClientConfig;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tempfile::TempDir;

use crate::{
    comm::{to_cert_chain, to_private_key, to_root_cert},
    server::{Certs, config_client},
};

static INIT: OnceLock<()> = OnceLock::new();

pub(crate) fn init_crypto() {
    INIT.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[derive(Clone, Copy)]
pub(crate) enum BundleOrder {
    IntermediateThenRoot,
    RootThenIntermediate,
}

#[derive(Clone, Copy)]
pub(crate) enum PeerPresentation {
    LeafOnly,
    LeafAndIntermediate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TestNode {
    Node1,
    Node2,
}

pub(crate) struct BootrootChainFixture {
    _temp_dir: TempDir,
    pub(crate) server_leaf_path: String,
    pub(crate) server_chain_path: String,
    pub(crate) server_key_path: String,
    pub(crate) client_leaf_path: String,
    pub(crate) client_chain_path: String,
    pub(crate) client_key_path: String,
    pub(crate) intermediate_cert_path: String,
    pub(crate) root_cert_path: String,
    pub(crate) ca_bundle_intermediate_then_root_path: String,
    pub(crate) ca_bundle_root_then_intermediate_path: String,
    pub(crate) server_name: String,
}

pub(crate) struct BootrootNodeFixture {
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
    pub(crate) ca_bundle_path: String,
    pub(crate) server_name: String,
}

pub(crate) struct BootrootClusterFixture {
    _temp_dir: TempDir,
    pub(crate) node1: BootrootNodeFixture,
    pub(crate) node2: BootrootNodeFixture,
}

impl TestNode {
    pub(crate) fn short_hostname(self) -> &'static str {
        match self {
            Self::Node1 => "node1",
            Self::Node2 => "node2",
        }
    }
}

impl BootrootNodeFixture {
    pub(crate) fn load_certs(&self) -> Certs {
        load_certs(&self.cert_path, &self.key_path, &self.ca_bundle_path)
    }
}

impl BootrootClusterFixture {
    pub(crate) fn node(&self, node: TestNode) -> &BootrootNodeFixture {
        match node {
            TestNode::Node1 => &self.node1,
            TestNode::Node2 => &self.node2,
        }
    }
}

pub(crate) fn bootroot_chain_node1_fixture() -> &'static BootrootChainFixture {
    static FIXTURE: OnceLock<BootrootChainFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        build_bootroot_chain_fixture(
            "001.giganto.node1.example.test",
            "001.giganto.node1.example.test",
        )
    })
}

pub(crate) fn bootroot_chain_node1_client_certs() -> Certs {
    let fixture = bootroot_chain_node1_fixture();
    load_certs_with_ca_paths(
        &fixture.client_leaf_path,
        &fixture.client_key_path,
        std::slice::from_ref(&fixture.ca_bundle_intermediate_then_root_path),
    )
}

pub(crate) fn bootroot_chain_node1_server_certs() -> Certs {
    let fixture = bootroot_chain_node1_fixture();
    load_certs_with_ca_paths(
        &fixture.server_leaf_path,
        &fixture.server_key_path,
        std::slice::from_ref(&fixture.ca_bundle_intermediate_then_root_path),
    )
}

pub(crate) fn bootroot_cluster_fixture() -> &'static BootrootClusterFixture {
    static FIXTURE: OnceLock<BootrootClusterFixture> = OnceLock::new();
    FIXTURE.get_or_init(build_bootroot_cluster_fixture)
}

pub(crate) fn bootroot_cluster_server_name(node: TestNode) -> &'static str {
    &bootroot_cluster_fixture().node(node).server_name
}

pub(crate) fn bootroot_cluster_certs(node: TestNode) -> Certs {
    bootroot_cluster_fixture().node(node).load_certs()
}

pub(crate) fn load_certs(cert_path: &str, key_path: &str, ca_path: &str) -> Certs {
    load_certs_with_ca_paths(cert_path, key_path, &[ca_path.to_string()])
}

pub(crate) fn load_certs_with_ca_paths(
    cert_path: &str,
    key_path: &str,
    ca_paths: &[String],
) -> Certs {
    let cert_pem = fs::read(cert_path).expect("read cert");
    let key_pem = fs::read(key_path).expect("read key");
    let root = to_root_cert(ca_paths).expect("read ca bundle");

    Certs {
        certs: to_cert_chain(&cert_pem).expect("parse cert"),
        key: to_private_key(&key_pem).expect("parse key"),
        root,
    }
}

pub(crate) fn config_client_without_cert(ca_paths: &[String]) -> ClientConfig {
    init_crypto();
    let root = to_root_cert(ca_paths).expect("read ca bundle");
    ClientConfig::with_root_certificates(Arc::new(root)).expect("client config")
}

pub(crate) fn config_client_for_tests(certs: &Certs) -> ClientConfig {
    init_crypto();
    config_client(certs).expect("client config")
}

pub(crate) fn load_server_client_certs(
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

fn write_node_fixture(
    temp_dir: &TempDir,
    file_prefix: &str,
    cert_pem: &str,
    key_pem: &str,
    ca_bundle_path: &str,
    server_name: &str,
) -> BootrootNodeFixture {
    let cert_path = temp_dir.path().join(format!("{file_prefix}-cert.pem"));
    let key_path = temp_dir.path().join(format!("{file_prefix}-key.pem"));
    fs::write(&cert_path, cert_pem).expect("write node cert");
    fs::write(&key_path, key_pem).expect("write node key");

    BootrootNodeFixture {
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        ca_bundle_path: ca_bundle_path.to_string(),
        server_name: server_name.to_string(),
    }
}

pub(crate) fn build_bootroot_chain_fixture(
    client_common_name: &str,
    client_dns_name: &str,
) -> BootrootChainFixture {
    build_bootroot_chain_fixture_with_server_name(
        "001.data-store.node1.example.test",
        client_common_name,
        client_dns_name,
    )
}

pub(crate) fn build_bootroot_chain_fixture_with_server_name(
    server_name: &str,
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
    let intermediate_cert_path = temp_dir.path().join("intermediate.pem");
    let root_cert_path = temp_dir.path().join("root.pem");
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
    fs::write(&intermediate_cert_path, intermediate.pem()).expect("write intermediate cert");
    fs::write(&root_cert_path, root.pem()).expect("write root cert");
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
        intermediate_cert_path: intermediate_cert_path.to_string_lossy().into_owned(),
        root_cert_path: root_cert_path.to_string_lossy().into_owned(),
        ca_bundle_intermediate_then_root_path: ca_bundle_intermediate_then_root_path
            .to_string_lossy()
            .into_owned(),
        ca_bundle_root_then_intermediate_path: ca_bundle_root_then_intermediate_path
            .to_string_lossy()
            .into_owned(),
        server_name: server_name.to_string(),
    }
}

pub(crate) fn build_bootroot_cluster_fixture() -> BootrootClusterFixture {
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

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let intermediate_cert_path = temp_dir.path().join("cluster-intermediate.pem");
    let root_cert_path = temp_dir.path().join("cluster-root.pem");
    let ca_bundle_path = temp_dir.path().join("cluster-ca-bundle.pem");

    fs::write(&intermediate_cert_path, intermediate.pem()).expect("write intermediate cert");
    fs::write(&root_cert_path, root.pem()).expect("write root cert");
    fs::write(
        &ca_bundle_path,
        format!("{}{}", intermediate.pem(), root.pem()),
    )
    .expect("write ca bundle");

    let node1_server_name = "001.giganto.node1.example.test";
    let node1_key = KeyPair::generate().expect("generate node1 key");
    let node1_cert = new_leaf_params(
        node1_server_name,
        node1_server_name,
        vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ],
    )
    .signed_by(&node1_key, &intermediate)
    .expect("build node1 cert");
    let node1 = write_node_fixture(
        &temp_dir,
        "node1",
        &node1_cert.pem(),
        &node1_key.serialize_pem(),
        &ca_bundle_path.to_string_lossy(),
        node1_server_name,
    );

    let node2_server_name = "001.giganto.node2.example.test";
    let node2_key = KeyPair::generate().expect("generate node2 key");
    let node2_cert = new_leaf_params(
        node2_server_name,
        node2_server_name,
        vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ],
    )
    .signed_by(&node2_key, &intermediate)
    .expect("build node2 cert");
    let node2 = write_node_fixture(
        &temp_dir,
        "node2",
        &node2_cert.pem(),
        &node2_key.serialize_pem(),
        &ca_bundle_path.to_string_lossy(),
        node2_server_name,
    );

    BootrootClusterFixture {
        _temp_dir: temp_dir,
        node1,
        node2,
    }
}
