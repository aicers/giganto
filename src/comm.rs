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
use tracing::warn;

use crate::{
    comm::peer::{PeerIdentity, PeerIdents, PeerInfo, Peers},
    storage::Database,
};

pub type PcapSensors = Arc<RwLock<HashMap<String, Vec<Connection>>>>;
pub type IngestSensors = Arc<RwLock<HashSet<String>>>;
pub type RunTimeIngestSensors = Arc<RwLock<HashMap<String, DateTime<Utc>>>>;
pub type StreamDirectChannels = Arc<RwLock<HashMap<String, UnboundedSender<Vec<u8>>>>>;

/// Parses PEM-encoded certificates and returns a certificate chain.
///
/// # Errors
///
/// Returns an error if:
/// * The PEM input cannot be parsed (invalid certificate chain)
/// * The parsed certificate chain is empty (empty certificate chain)
pub(crate) fn to_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*pem)
        .collect::<Result<_, _>>()
        .context("invalid certificate chain")?;
    if certs.is_empty() {
        bail!("empty certificate chain");
    }
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

    let mut root_cert = rustls::RootCertStore::empty();
    let mut added_any = false;

    for path in ca_certs_paths {
        let pem = fs::read(path)
            .with_context(|| format!("failed to read root certificate file: {path}"))?;

        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*pem)
            .collect::<Result<_, _>>()
            .with_context(|| format!("invalid PEM-encoded certificate: {path}"))?;

        let (valid, invalid) = root_cert.add_parsable_certificates(certs.clone());

        added_any |= valid > 0;

        if invalid > 0 {
            warn!("some root certificate(s) were skipped in {certs:?}");
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
    use std::path::Path;

    use chrono::TimeZone;
    use rocksdb::{DB, Options};
    use tempfile::tempdir;

    use super::*;
    use crate::storage::{Database, DbOptions};

    const INVALID_CERT_1: &str = "-----BEGIN CERTIFICATE-----\n\
        SGVsbG8gV29ybGQhIFRoaXMgaXMgbm90IGEgdmFsaWQgY2VydGlmaWNhdGUu\n\
        -----END CERTIFICATE-----\n";
    const INVALID_CERT_2: &str = "-----BEGIN CERTIFICATE-----\n\
        QW5vdGhlciBpbnZhbGlkIGNlcnRpZmljYXRlIGRhdGEgaGVyZS4=\n\
        -----END CERTIFICATE-----\n";

    fn generate_test_cert() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap()
    }

    fn write_pem_file(dir: &Path, filename: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(filename);
        fs::write(&path, contents.as_bytes()).expect("failed to write PEM file");
        path
    }

    fn paths_from_files(files: &[std::path::PathBuf]) -> Vec<String> {
        files
            .iter()
            .map(|path| path.to_str().unwrap().to_string())
            .collect()
    }

    fn assert_root_cert_len(paths: &[String], expected: usize) {
        let root_cert = to_root_cert(paths);
        assert!(root_cert.is_ok());
        let store = root_cert.unwrap();
        assert_eq!(store.len(), expected);
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
    fn test_to_cert_chain_multiple_certs() {
        let cert1 = generate_test_cert();
        let cert2 = generate_test_cert();
        let pem = format!("{}{}", cert1.cert.pem(), cert2.cert.pem());

        let chain = to_cert_chain(pem.as_bytes()).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].as_ref(), cert1.cert.der().as_ref());
        assert_eq!(chain[1].as_ref(), cert2.cert.der().as_ref());
    }

    #[test]
    fn test_to_cert_chain_invalid_base64_returns_error() {
        let pem = b"-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n";
        let err = to_cert_chain(pem).expect_err("Operation should have failed");
        assert!(err.to_string().contains("invalid certificate chain"));
    }

    #[test]
    fn test_to_cert_chain_mixed_valid_and_invalid_returns_error() {
        let cert = generate_test_cert();
        let valid_pem = cert.cert.pem();
        let invalid_pem = "-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n";
        let pem = format!("{valid_pem}{invalid_pem}");

        let err = to_cert_chain(pem.as_bytes()).expect_err("Operation should have failed");
        assert!(err.to_string().contains("invalid certificate chain"));
    }

    #[test]
    fn test_to_cert_chain_empty_pem_returns_error() {
        let pem = b"";
        let err = to_cert_chain(pem).expect_err("Operation should have failed");
        assert!(err.to_string().contains("empty certificate chain"));
    }

    #[test]
    fn test_to_cert_chain_no_certificate_blocks_returns_error() {
        // PEM content without any CERTIFICATE blocks
        let pem = b"some random text without any PEM blocks";
        let err = to_cert_chain(pem).expect_err("Operation should have failed");
        assert!(err.to_string().contains("empty certificate chain"));
    }

    #[test]
    fn test_to_cert_chain_whitespace_only_returns_error() {
        let pem = b"   \n\t\n   ";
        let err = to_cert_chain(pem).expect_err("Operation should have failed");
        assert!(err.to_string().contains("empty certificate chain"));
    }

    #[test]
    fn test_to_private_key_invalid() {
        let pem = b"invalid pem";
        let err = to_private_key(pem).expect_err("Operation should have failed");
        assert!(err.to_string().contains("private key"));
    }

    #[test]
    fn test_to_private_key_pkcs8_der_matches() {
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
    fn test_to_private_key_pkcs1() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIBOgIBAAJBAKvoIyPFzQmQVQMeL4czZ6I1v90DminqhTfXUNK0RvyWLrkomv6w\n\
r/LH5Jk+AXWyJfItHbpxFRdgidLhpsJ7b3cCAwEAAQJAedXckc3us4iHt9388WWN\n\
XXmasZmL+YktQZZowezjIsBjmZkcHd8kwumXew0+9OgqnV8veyeyK0/RE7ixgqSb\n\
AQIhAOP1whbbpKmvfpdh0TuCghNHzVCYTDpGDGuf2R9zl1zPAiEAwQ1RO28tKtkf\n\
AP/Xr6CbkpdFt0t2h0pOlQ2AQSOO/NkCIBcycf67eSUfS6WB+bWxkST/IIB8Dv27\n\
FRZ6nLCbpaJ3AiBxVqw2RJMz8LyvDYVHavdrHLylW/x+eTWhdIeztnigIQIhANhE\n\
gk8wqEpSd+WAAbO1LQBAyBjZWqqrpw7828tkUf7a\n\
-----END RSA PRIVATE KEY-----\n";
        let key = to_private_key(pem.as_bytes()).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs1(_)));
    }

    #[test]
    fn test_to_root_cert_valid() {
        let test_cert = generate_test_cert();
        let pem = test_cert.cert.pem();
        let original_der = test_cert.cert.der();

        let dir = tempdir().expect("failed to create temp dir");
        let cert_path = write_pem_file(dir.path(), "ca.pem", &pem);

        let paths = vec![cert_path.to_string_lossy().into_owned()];
        assert_root_cert_len(paths.as_ref(), 1);

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
    fn test_to_root_cert_non_pem_content_is_rejected() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = write_pem_file(dir.path(), "invalid.pem", "invalid content");

        let paths = vec![file_path.to_str().unwrap().to_string()];
        let root_cert = to_root_cert(&paths);
        let err = root_cert.expect_err("Operation should have failed");
        assert_eq!(err.to_string(), "no valid root certificates loaded");
    }

    #[test]
    fn test_to_root_cert_multiple_certs_single_file() {
        // Generate two distinct certificates
        let cert1 = generate_test_cert();
        let cert2 = generate_test_cert();
        let pem1 = cert1.cert.pem();
        let pem2 = cert2.cert.pem();

        // Combine both certs into a single PEM file
        let combined_pem = format!("{pem1}{pem2}");

        let dir = tempdir().expect("failed to create temp dir");
        let file_path = write_pem_file(dir.path(), "multi_ca.pem", &combined_pem);

        let paths = vec![file_path.to_str().unwrap().to_string()];
        // Both certificates should be loaded
        assert_root_cert_len(paths.as_ref(), 2);
    }

    #[test]
    fn test_to_root_cert_multiple_files_multiple_certs() {
        // Generate three distinct certificates
        let cert1 = generate_test_cert();
        let cert2 = generate_test_cert();
        let cert3 = generate_test_cert();

        let dir = tempdir().expect("failed to create temp dir");

        // First file: single cert
        let file_path1 = write_pem_file(dir.path(), "ca1.pem", &cert1.cert.pem());

        // Second file: two certs combined
        let combined_pem = format!("{}{}", cert2.cert.pem(), cert3.cert.pem());
        let file_path2 = write_pem_file(dir.path(), "ca2.pem", &combined_pem);

        let paths = paths_from_files(&[file_path1, file_path2]);
        // All three certificates should be loaded
        assert_root_cert_len(paths.as_ref(), 3);
    }

    #[test]
    fn test_to_root_cert_mixed_valid_and_invalid_blocks() {
        // Generate a valid certificate
        let cert = generate_test_cert();
        let valid_pem = cert.cert.pem();

        // Create an invalid certificate block (valid PEM structure but invalid cert data)
        let invalid_cert = INVALID_CERT_1;

        // Combine valid and invalid certs in one file
        let combined_pem = format!("{valid_pem}{invalid_cert}");

        let dir = tempdir().expect("failed to create temp dir");
        let file_path = write_pem_file(dir.path(), "mixed_ca.pem", &combined_pem);

        let paths = vec![file_path.to_str().unwrap().to_string()];
        // Should succeed because at least one valid cert exists
        // Only the valid certificate should be loaded
        assert_root_cert_len(paths.as_ref(), 1);
    }

    #[test]
    fn test_to_root_cert_multiple_files_with_invalid_blocks() {
        // Generate valid certificates
        let cert1 = generate_test_cert();
        let cert2 = generate_test_cert();

        let dir = tempdir().expect("failed to create temp dir");

        // First file: valid cert + invalid cert
        let combined_pem1 = format!("{}{}", cert1.cert.pem(), INVALID_CERT_1);
        let file_path1 = write_pem_file(dir.path(), "ca1.pem", &combined_pem1);

        // Second file: valid cert only
        let file_path2 = write_pem_file(dir.path(), "ca2.pem", &cert2.cert.pem());

        let paths = paths_from_files(&[file_path1, file_path2]);

        // Should succeed because valid certs exist
        // Only the two valid certificates should be loaded
        assert_root_cert_len(paths.as_ref(), 2);
    }

    #[test]
    fn test_to_root_cert_all_invalid_blocks() {
        // Create invalid certificate blocks (valid PEM structure but invalid cert data)
        let combined_pem = format!("{INVALID_CERT_1}{INVALID_CERT_2}");

        let dir = tempdir().expect("failed to create temp dir");
        let file_path = write_pem_file(dir.path(), "invalid_ca.pem", &combined_pem);

        let paths = vec![file_path.to_str().unwrap().to_string()];

        // Should fail because no valid certificates were loaded
        let err = to_root_cert(&paths).unwrap_err();
        assert_eq!(err.to_string(), "no valid root certificates loaded");
    }

    #[test]
    fn test_to_root_cert_empty_file_is_rejected() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = write_pem_file(dir.path(), "empty.pem", "");

        let paths = vec![file_path.to_str().unwrap().to_string()];
        let err = to_root_cert(&paths).unwrap_err();
        assert_eq!(err.to_string(), "no valid root certificates loaded");
    }

    #[test]
    fn test_to_root_cert_empty_pem_block_is_rejected() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = write_pem_file(
            dir.path(),
            "empty_block.pem",
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
        );

        let paths = vec![file_path.to_str().unwrap().to_string()];
        let err = to_root_cert(&paths).unwrap_err();
        assert_eq!(err.to_string(), "no valid root certificates loaded");
    }

    #[tokio::test]
    async fn test_new_pcap_sensors() {
        let sensors = new_pcap_sensors();
        assert_string_key_map_inserted(&sensors, "sensor1", Vec::new()).await;
    }

    #[tokio::test]
    async fn test_new_ingest_sensors_reads_from_db() {
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
