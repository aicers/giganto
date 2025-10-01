pub(crate) mod ingest;
pub(crate) mod peer;
pub(crate) mod publish;

use std::{
    collections::{HashMap, HashSet},
    fs::{self},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use jiff::Timestamp;
use quinn::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{RwLock, mpsc::UnboundedSender};

use crate::{
    comm::peer::{PeerIdentity, PeerIdents, PeerInfo, Peers},
    storage::Database,
};

pub type PcapSensors = Arc<RwLock<HashMap<String, Vec<Connection>>>>;
pub type IngestSensors = Arc<RwLock<HashSet<String>>>;
pub type RunTimeIngestSensors = Arc<RwLock<HashMap<String, Timestamp>>>;
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
    let mut ca_certs_files = Vec::new();

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
        }
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
    Arc::new(RwLock::new(HashMap::<String, Timestamp>::new()))
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
