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
    use std::collections::HashSet;
    use std::io::Write;
    use std::path::Path;

    use chrono::TimeZone;
    use rocksdb::{DB, Options};
    use tempfile::tempdir;

    use super::*;
    use crate::storage::{Database, DbOptions};

    fn generate_test_cert() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap()
    }

    async fn assert_string_key_map_inserted<V>(
        map: &Arc<RwLock<std::collections::HashMap<String, V>>>,
        key: &str,
        value: V,
    ) {
        assert!(map.read().await.is_empty());
        map.write().await.insert(key.to_string(), value);
        let map_read = map.read().await;
        assert_eq!(map_read.len(), 1);
        assert!(map_read.contains_key(key));
    }

    fn read_sensor_timestamp(path: &Path, sensor_id: &str) -> i64 {
        let db_opts = Options::default();
        let cf_names = DB::list_cf(&db_opts, path).unwrap_or_default();
        let cf_names_ref: Vec<&str> = cf_names.iter().map(String::as_str).collect();
        let read_only_db = DB::open_cf_for_read_only(&db_opts, path, cf_names_ref, false).unwrap();
        let sensors_cf = read_only_db.cf_handle("sensors").unwrap();
        let value = read_only_db
            .get_cf(sensors_cf, sensor_id)
            .unwrap()
            .expect("sensor timestamp");
        let bytes: [u8; 8] = value.try_into().expect("timestamp bytes");
        i64::from_be_bytes(bytes)
    }

    #[test]
    fn test_to_cert_chain_valid() {
        let cert = generate_test_cert();
        let pem = cert.cert.pem();
        let der = cert.cert.der();

        let chain = to_cert_chain(pem.as_bytes()).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].as_ref(), der.as_ref());
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
        let der_pkcs8 = cert.signing_key.serialize_der();
        let key = to_private_key(pem.as_bytes()).unwrap();

        match key {
            PrivateKeyDer::Pkcs8(pkcs8_key) => {
                assert_eq!(pkcs8_key.secret_pkcs8_der(), der_pkcs8.as_slice());
            }
            _ => panic!("Expected a PKCS#8 key"),
        }
    }

    #[test]
    fn test_to_private_key_invalid() {
        let pem = b"invalid pem";
        let err = to_private_key(pem).expect_err("Operation should have failed");
        assert!(err.to_string().contains("private key"));
    }

    #[test]
    fn test_to_root_cert_valid() {
        let test_cert = generate_test_cert();
        let pem = test_cert.cert.pem();
        let original_der = test_cert.cert.der();

        let dir = tempdir().expect("failed to create temp dir");
        let cert_path = dir.path().join("ca.pem");
        fs::write(&cert_path, pem.as_bytes()).expect("failed to write ca file");

        let paths = vec![cert_path.to_string_lossy().into_owned()];
        let root_cert_store = to_root_cert(&paths).unwrap();

        assert!(!root_cert_store.is_empty());
        let roots = root_cert_store.roots;
        assert_eq!(roots.len(), 1);

        let parsed_der = rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .expect("pem should contain a cert")
            .expect("cert should parse");
        assert_eq!(parsed_der.as_ref(), original_der.as_ref());
    }

    #[test]
    fn test_to_root_cert_invalid_path() {
        let paths = vec!["/non/existent/path".to_string()];
        let err = to_root_cert(&paths).expect_err("Operation should have failed");
        assert!(
            err.to_string()
                .contains("failed to read root certificate file")
        );
    }

    #[test]
    fn test_to_root_cert_empty_path() {
        let paths = Vec::new();
        let err = to_root_cert(&paths).expect_err("Operation should have failed");
        assert!(
            err.to_string()
                .contains("no root certificate paths provided")
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
        let err = root_cert.expect_err("Operation should have failed");
        assert_eq!(err.to_string(), "no valid root certificates loaded");
    }

    #[tokio::test]
    async fn test_new_pcap_sensors() {
        let sensors = new_pcap_sensors();
        assert_string_key_map_inserted(&sensors, "sensor1", Vec::new()).await;
    }

    #[tokio::test]
    async fn test_new_ingest_sensors() {
        let dir = tempdir().unwrap();
        let sensor_id = "sensor1";
        let fixed_time = Utc.with_ymd_and_hms(2026, 1, 20, 10, 0, 0).unwrap();
        {
            let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
            let sensor_store = db.sensors_store().unwrap();
            sensor_store.insert(sensor_id, fixed_time).unwrap();

            let sensors = new_ingest_sensors(&db);
            let sensors_lock = sensors.read().await;
            assert_eq!(sensors_lock.len(), 1);
            assert!(sensors_lock.contains(sensor_id));
            db.shutdown().unwrap();
        }

        let expected_ts = fixed_time.timestamp_nanos_opt().unwrap();
        let stored_ts = read_sensor_timestamp(dir.path(), sensor_id);
        assert_eq!(stored_ts, expected_ts);
    }

    #[tokio::test]
    async fn test_new_runtime_ingest_sensors() {
        let sensors = new_runtime_ingest_sensors();
        let fixed_time = Utc.with_ymd_and_hms(2026, 1, 20, 10, 0, 0).unwrap();
        assert_string_key_map_inserted(&sensors, "sensor1", fixed_time).await;
        let sensors_lock = sensors.read().await;
        assert_eq!(sensors_lock.len(), 1);
        assert_eq!(sensors_lock.get("sensor1"), Some(&fixed_time));
    }

    #[tokio::test]
    async fn test_new_stream_direct_channels() {
        let channels = new_stream_direct_channels();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        assert_string_key_map_inserted(&channels, "channel1", tx).await;
    }

    #[tokio::test]
    async fn test_new_peers_data() {
        let (peers, idents) = new_peers_data(None);
        assert!(peers.read().await.is_empty());
        assert!(idents.read().await.is_empty());

        let mut peer_idents = HashSet::new();
        let peer_identity = PeerIdentity {
            addr: "127.0.0.1:8080".parse().unwrap(),
            hostname: "peer1".to_string(),
        };
        peer_idents.insert(peer_identity.clone());

        let (peers, idents) = new_peers_data(Some(peer_idents));
        assert!(peers.read().await.is_empty());
        let idents_lock = idents.read().await;
        assert_eq!(idents_lock.len(), 1);
        assert!(idents_lock.contains(&peer_identity));
    }
}
