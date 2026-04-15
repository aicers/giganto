use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::comm::{to_cert_chain, to_private_key, to_root_cert};
use crate::server::Certs;

pub struct CertPaths {
    pub cert_path: String,
    pub key_path: String,
    pub ca_certs_paths: Vec<String>,
}

/// Loads TLS material (cert chain, private key, root CA store) from
/// the file paths specified in `paths`.
///
/// # Errors
///
/// Returns an error if any file cannot be read or parsed.
pub fn load_tls_material(paths: &CertPaths) -> Result<(Certs, Vec<u8>, Vec<u8>)> {
    let cert_pem = std::fs::read(&paths.cert_path)
        .with_context(|| format!("failed to read certificate file: {}", paths.cert_path))?;
    let certs = to_cert_chain(&cert_pem).context("cannot read certificate chain")?;
    let key_pem = std::fs::read(&paths.key_path)
        .with_context(|| format!("failed to read private key file: {}", paths.key_path))?;
    let key = to_private_key(&key_pem).context("cannot read private key")?;
    let root = to_root_cert(&paths.ca_certs_paths)?;
    Ok((Certs { certs, key, root }, cert_pem, key_pem))
}

pub struct TlsMaterial {
    pub certs: Arc<Certs>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl Clone for TlsMaterial {
    fn clone(&self) -> Self {
        Self {
            certs: Arc::clone(&self.certs),
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
        }
    }
}

pub type TlsWatch = watch::Receiver<Arc<TlsMaterial>>;

pub struct ReloadHandle {
    sender: watch::Sender<Arc<TlsMaterial>>,
    paths: CertPaths,
}

impl ReloadHandle {
    pub fn new(paths: CertPaths, initial: Arc<TlsMaterial>) -> (Self, TlsWatch) {
        let (sender, receiver) = watch::channel(initial);
        (Self { sender, paths }, receiver)
    }

    /// Re-reads cert/key/CA from disk and broadcasts the new material.
    /// On failure, preserves the previous material and logs the error.
    pub fn reload(&self) {
        info!("TLS reload requested");
        match load_tls_material(&self.paths) {
            Ok((certs, cert_pem, key_pem)) => {
                let material = Arc::new(TlsMaterial {
                    certs: Arc::new(certs),
                    cert_pem,
                    key_pem,
                });
                if self.sender.send(material).is_err() {
                    warn!("TLS reload: no active receivers");
                }
                info!("TLS material reloaded successfully");
            }
            Err(e) => {
                error!("TLS reload failed, keeping previous material: {e:#}");
            }
        }
    }

    pub fn subscribe(&self) -> TlsWatch {
        self.sender.subscribe()
    }
}

/// Returns the current TLS material from the watch channel.
pub fn get_current_tls_material(watch: &TlsWatch) -> Arc<TlsMaterial> {
    Arc::clone(&watch.borrow())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    fn generate_self_signed() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate self-signed cert")
    }

    fn write_cert_files(dir: &std::path::Path) -> (String, String, String) {
        let ck = generate_self_signed();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let ca_path = dir.join("ca.pem");
        fs::write(&cert_path, ck.cert.pem().as_bytes()).expect("write cert");
        fs::write(&key_path, ck.signing_key.serialize_pem().as_bytes()).expect("write key");
        fs::write(&ca_path, ck.cert.pem().as_bytes()).expect("write ca");
        (
            cert_path.to_str().expect("cert path").to_string(),
            key_path.to_str().expect("key path").to_string(),
            ca_path.to_str().expect("ca path").to_string(),
        )
    }

    #[test]
    fn load_tls_material_succeeds_with_valid_files() {
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_cert_files(dir.path());
        let paths = CertPaths {
            cert_path: cert,
            key_path: key,
            ca_certs_paths: vec![ca],
        };
        let result = load_tls_material(&paths);
        assert!(result.is_ok());
    }

    #[test]
    fn load_tls_material_fails_with_missing_cert() {
        let paths = CertPaths {
            cert_path: "/nonexistent/cert.pem".to_string(),
            key_path: "/nonexistent/key.pem".to_string(),
            ca_certs_paths: vec!["/nonexistent/ca.pem".to_string()],
        };
        let result = load_tls_material(&paths);
        assert!(result.is_err());
    }

    #[test]
    fn load_tls_material_fails_with_invalid_cert() {
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("ca.pem");
        fs::write(&cert_path, b"not a cert").expect("write");
        fs::write(&key_path, b"not a key").expect("write");
        fs::write(&ca_path, b"not a ca").expect("write");

        let paths = CertPaths {
            cert_path: cert_path.to_str().expect("path").to_string(),
            key_path: key_path.to_str().expect("path").to_string(),
            ca_certs_paths: vec![ca_path.to_str().expect("path").to_string()],
        };
        let result = load_tls_material(&paths);
        assert!(result.is_err());
    }

    #[test]
    fn reload_handle_broadcasts_updated_material() {
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_cert_files(dir.path());
        let paths = CertPaths {
            cert_path: cert,
            key_path: key,
            ca_certs_paths: vec![ca],
        };
        let (certs, cert_pem, key_pem) = load_tls_material(&paths).expect("initial load");
        let initial = Arc::new(TlsMaterial {
            certs: Arc::new(certs),
            cert_pem,
            key_pem,
        });

        let (handle, watch) = ReloadHandle::new(paths, initial);
        let initial_version = Arc::clone(&watch.borrow());

        // Write new cert files so reload picks up different material
        let ck2 = generate_self_signed();
        fs::write(&handle.paths.cert_path, ck2.cert.pem().as_bytes()).expect("write new cert");
        fs::write(
            &handle.paths.key_path,
            ck2.signing_key.serialize_pem().as_bytes(),
        )
        .expect("write new key");
        fs::write(&handle.paths.ca_certs_paths[0], ck2.cert.pem().as_bytes())
            .expect("write new ca");

        handle.reload();

        let updated = get_current_tls_material(&watch);
        assert_ne!(
            initial_version.cert_pem, updated.cert_pem,
            "material should have been updated after reload"
        );
    }

    #[test]
    fn reload_preserves_previous_material_on_failure() {
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_cert_files(dir.path());
        let paths = CertPaths {
            cert_path: cert.clone(),
            key_path: key,
            ca_certs_paths: vec![ca],
        };
        let (certs, cert_pem, key_pem) = load_tls_material(&paths).expect("initial load");
        let initial = Arc::new(TlsMaterial {
            certs: Arc::new(certs),
            cert_pem: cert_pem.clone(),
            key_pem,
        });

        let (handle, watch) = ReloadHandle::new(paths, initial);

        // Break the cert file so reload fails
        fs::write(&cert, b"broken").expect("corrupt cert");

        handle.reload();

        let current = get_current_tls_material(&watch);
        assert_eq!(
            current.cert_pem, cert_pem,
            "previous material should be preserved on reload failure"
        );
    }

    #[test]
    fn subscribe_receives_updates() {
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_cert_files(dir.path());
        let paths = CertPaths {
            cert_path: cert,
            key_path: key,
            ca_certs_paths: vec![ca],
        };
        let (certs, cert_pem, key_pem) = load_tls_material(&paths).expect("initial load");
        let initial = Arc::new(TlsMaterial {
            certs: Arc::new(certs),
            cert_pem,
            key_pem,
        });

        let (handle, _watch) = ReloadHandle::new(paths, initial);
        let subscriber = handle.subscribe();

        handle.reload();

        let current = get_current_tls_material(&subscriber);
        assert!(!current.cert_pem.is_empty());
    }
}
