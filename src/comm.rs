pub(crate) mod ingest;
pub(crate) mod peer;
pub(crate) mod publish;

use std::{
    collections::{HashMap, HashSet},
    fs::{self},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use quinn::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{RwLock, mpsc::UnboundedSender};

use crate::{
    comm::peer::{PeerIdentity, PeerIdents, PeerInfo, Peers},
    storage::Database,
};

pub type PcapSensors = Arc<RwLock<HashMap<String, Vec<Connection>>>>;
pub type IngestSensors = Arc<RwLock<HashSet<String>>>;
pub type RunTimeIngestSensors = Arc<RwLock<HashMap<String, DateTime<Utc>>>>;
pub type StreamDirectChannels = Arc<RwLock<HashMap<String, UnboundedSender<Vec<u8>>>>>;

pub(crate) fn to_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut &*pem)
        .collect::<Result<_, _>>()
        .context("cannot parse certificate chain")?;
    Ok(certs)
}

pub(crate) fn to_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    match rustls_pemfile::read_one(&mut &*pem)
        .context("cannot parse private key")?
        .ok_or_else(|| anyhow!("empty private key"))?
    {
        rustls_pemfile::Item::Pkcs1Key(key) => Ok(key.into()),
        rustls_pemfile::Item::Pkcs8Key(key) => Ok(key.into()),
        _ => Err(anyhow!("unknown private key format")),
    }
}

pub(crate) fn to_root_cert(ca_certs_paths: &[String]) -> Result<rustls::RootCertStore> {
    if ca_certs_paths.is_empty() {
        bail!("no root certificate paths provided");
    }

    let mut ca_certs_files = Vec::new();
    let mut added_any = false;

    for ca_cert in ca_certs_paths {
        let file = fs::read(ca_cert)
            .with_context(|| format!("failed to read root certificate file: {ca_cert}"))?;

        ca_certs_files.push(file);
    }
    let mut root_cert = rustls::RootCertStore::empty();
    for file in ca_certs_files {
        let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*file)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?;
        if let Some(cert) = root_certs.first() {
            root_cert
                .add(cert.to_owned())
                .context("failed to add root cert")?;
            added_any = true;
        }
    }
    if !added_any {
        bail!("no valid root certificates loaded");
    }

    Ok(root_cert)
}

pub(crate) fn new_pcap_sensors() -> PcapSensors {
    Arc::new(RwLock::new(HashMap::<String, Vec<Connection>>::new()))
}

pub(crate) fn new_ingest_sensors(db: &Database) -> IngestSensors {
    let sensor_store = db.sensors_store().expect("Failed to open sensor store");
    Arc::new(RwLock::new(sensor_store.sensor_list()))
}

pub(crate) fn new_runtime_ingest_sensors() -> RunTimeIngestSensors {
    Arc::new(RwLock::new(HashMap::<String, DateTime<Utc>>::new()))
}

pub(crate) fn new_stream_direct_channels() -> StreamDirectChannels {
    Arc::new(RwLock::new(
        HashMap::<String, UnboundedSender<Vec<u8>>>::new(),
    ))
}

pub(crate) fn new_peers_data(peers_list: Option<HashSet<PeerIdentity>>) -> (Peers, PeerIdents) {
    (
        Arc::new(RwLock::new(HashMap::<String, PeerInfo>::new())),
        Arc::new(RwLock::new(peers_list.unwrap_or_default())),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::tempdir;

    use super::*;

    fn generate_test_cert() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap()
    }

    #[test]
    fn test_to_cert_chain_valid() {
        let cert = generate_test_cert();
        let pem = cert.cert.pem();
        let chain = to_cert_chain(pem.as_bytes());
        assert!(chain.is_ok());
        let chain = chain.unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_to_cert_chain_invalid() {
        let pem = b"invalid pem";
        let chain = to_cert_chain(pem);
        assert!(chain.is_ok());
        assert!(chain.unwrap().is_empty());
    }

    #[test]
    fn test_to_private_key_valid() {
        let cert = generate_test_cert();
        let pem = cert.signing_key.serialize_pem();
        let key = to_private_key(pem.as_bytes());
        assert!(key.is_ok());
    }

    #[test]
    fn test_to_private_key_invalid() {
        let pem = b"invalid pem";
        let key = to_private_key(pem);
        assert!(key.is_err());
    }

    #[test]
    fn test_to_root_cert_valid() {
        let cert = generate_test_cert();
        let pem = cert.cert.pem();

        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("ca.pem");
        let mut file = fs::File::create(&file_path).expect("failed to create ca file");
        file.write_all(pem.as_bytes())
            .expect("failed to write ca file");

        let paths = vec![file_path.to_str().unwrap().to_string()];
        let root_cert = to_root_cert(&paths);
        assert!(root_cert.is_ok());
        assert!(!root_cert.unwrap().is_empty());
    }

    #[test]
    fn test_to_root_cert_invalid_path() {
        let paths = vec!["/non/existent/path".to_string()];
        let root_cert = to_root_cert(&paths);
        assert!(root_cert.is_err());
    }

    #[test]
    fn test_to_root_cert_empty_path() {
        let paths = Vec::new();
        let result = to_root_cert(&paths);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "no root certificate paths provided"
        );
    }

    #[test]
    fn test_to_root_cert_invalid_content() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("invalid.pem");
        let mut file = fs::File::create(&file_path).expect("failed to create invalid file");
        file.write_all(b"invalid content")
            .expect("failed to write invalid file");

        let paths = vec![file_path.to_str().unwrap().to_string()];
        let root_cert = to_root_cert(&paths);
        let result = root_cert;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_new_pcap_sensors() {
        let sensors = new_pcap_sensors();
        assert!(sensors.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_new_runtime_ingest_sensors() {
        let sensors = new_runtime_ingest_sensors();
        assert!(sensors.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_new_stream_direct_channels() {
        let channels = new_stream_direct_channels();
        assert!(channels.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_new_peers_data() {
        let (peers, idents) = new_peers_data(None);
        assert!(peers.read().await.is_empty());
        assert!(idents.read().await.is_empty());

        let mut set = HashSet::new();
        set.insert(PeerIdentity {
            addr: "127.0.0.1:0".parse().unwrap(),
            hostname: "test".to_string(),
        });
        let (peers, idents) = new_peers_data(Some(set));
        assert!(peers.read().await.is_empty());
        assert!(!idents.read().await.is_empty());
    }
}
