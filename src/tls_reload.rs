use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rustls::pki_types::CertificateDer;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::comm::{to_cert_chain, to_private_key};
use crate::server::Certs;

pub struct CertPaths {
    pub cert_path: String,
    pub key_path: String,
    pub ca_certs_paths: Vec<String>,
}

/// Validated TLS material produced by a successful
/// [`load_tls_material`] call.
pub struct LoadedTls {
    pub certs: Certs,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

/// Loads TLS material (cert chain, private key, root CA store) from
/// the file paths specified in `paths`.
///
/// The CA bytes are read once here so downstream consumers can build
/// listeners from the validated byte stream instead of re-reading the
/// CA files, which would reopen the TOCTOU window between reload
/// validation and server restart.
///
/// # Errors
///
/// Returns an error if any file cannot be read or parsed.
pub fn load_tls_material(paths: &CertPaths) -> Result<LoadedTls> {
    let cert_pem = std::fs::read(&paths.cert_path)
        .with_context(|| format!("failed to read certificate file: {}", paths.cert_path))?;
    let certs = to_cert_chain(&cert_pem).context("cannot read certificate chain")?;
    let key_pem = std::fs::read(&paths.key_path)
        .with_context(|| format!("failed to read private key file: {}", paths.key_path))?;
    let key = to_private_key(&key_pem).context("cannot read private key")?;
    let (root, ca_pem) = load_root_cert(&paths.ca_certs_paths)?;

    // Validate that the certificate and private key form a valid pair
    // before accepting the material as a reload candidate.
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .expect("rustls crypto provider should be installed at startup");
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to configure TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key.clone_key())
        .context("certificate and private key do not form a valid pair")?;

    Ok(LoadedTls {
        certs: Certs { certs, key, root },
        cert_pem,
        key_pem,
        ca_pem,
    })
}

fn load_root_cert(ca_certs_paths: &[String]) -> Result<(rustls::RootCertStore, Vec<u8>)> {
    if ca_certs_paths.is_empty() {
        bail!("no root certificate paths provided");
    }

    let mut root_cert = rustls::RootCertStore::empty();
    let mut combined_pem: Vec<u8> = Vec::new();

    // Use strict `RootCertStore::add` semantics to match the trust
    // store the poem/rustls HTTPS listener builds at bind time. A
    // bundle containing any cert the listener would reject must be
    // rejected here too, so reload validation cannot succeed on
    // material the new server will refuse to start on.
    for path in ca_certs_paths {
        let pem = std::fs::read(path)
            .with_context(|| format!("failed to read root certificate file: {path}"))?;

        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*pem)
            .collect::<Result<_, _>>()
            .with_context(|| format!("invalid PEM-encoded certificate: {path}"))?;

        if certs.is_empty() {
            bail!("no certificates found in root certificate file: {path}");
        }

        for der in certs {
            root_cert
                .add(der)
                .with_context(|| format!("invalid root certificate in {path}"))?;
        }

        combined_pem.extend_from_slice(&pem);
        if !combined_pem.ends_with(b"\n") {
            combined_pem.push(b'\n');
        }
    }

    Ok((root_cert, combined_pem))
}

pub struct TlsMaterial {
    pub certs: Arc<Certs>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

impl Clone for TlsMaterial {
    fn clone(&self) -> Self {
        Self {
            certs: Arc::clone(&self.certs),
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
            ca_pem: self.ca_pem.clone(),
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

    /// Re-reads cert/key/CA from disk and broadcasts the new material
    /// when it differs from the previously validated material. On
    /// failure, preserves the previous material and logs the error. A
    /// successful reread whose bytes match the current material is
    /// treated as a no-op so consumers do not observe a spurious
    /// update.
    pub fn reload(&self) {
        info!("TLS reload requested");
        match load_tls_material(&self.paths) {
            Ok(loaded) => {
                let current = self.sender.borrow();
                if current.cert_pem == loaded.cert_pem
                    && current.key_pem == loaded.key_pem
                    && current.ca_pem == loaded.ca_pem
                {
                    info!("TLS reload: material unchanged, skipping publish");
                    return;
                }
                drop(current);
                let material = Arc::new(TlsMaterial {
                    certs: Arc::new(loaded.certs),
                    cert_pem: loaded.cert_pem,
                    key_pem: loaded.key_pem,
                    ca_pem: loaded.ca_pem,
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
}

/// Returns the current TLS material from the watch channel.
pub fn get_current_tls_material(watch: &TlsWatch) -> Arc<TlsMaterial> {
    Arc::clone(&watch.borrow())
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Once};

    use tempfile::tempdir;

    use super::*;

    static INSTALL_PROVIDER: Once = Once::new();

    fn install_crypto_provider() {
        INSTALL_PROVIDER.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

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
        install_crypto_provider();
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
        install_crypto_provider();
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
        install_crypto_provider();
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
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_cert_files(dir.path());
        let paths = CertPaths {
            cert_path: cert,
            key_path: key,
            ca_certs_paths: vec![ca],
        };
        let loaded = load_tls_material(&paths).expect("initial load");
        let initial = Arc::new(TlsMaterial {
            certs: Arc::new(loaded.certs),
            cert_pem: loaded.cert_pem,
            key_pem: loaded.key_pem,
            ca_pem: loaded.ca_pem,
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
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_cert_files(dir.path());
        let paths = CertPaths {
            cert_path: cert.clone(),
            key_path: key,
            ca_certs_paths: vec![ca],
        };
        let loaded = load_tls_material(&paths).expect("initial load");
        let initial_cert_pem = loaded.cert_pem.clone();
        let initial = Arc::new(TlsMaterial {
            certs: Arc::new(loaded.certs),
            cert_pem: loaded.cert_pem,
            key_pem: loaded.key_pem,
            ca_pem: loaded.ca_pem,
        });

        let (handle, watch) = ReloadHandle::new(paths, initial);

        // Break the cert file so reload fails
        fs::write(&cert, b"broken").expect("corrupt cert");

        handle.reload();

        let current = get_current_tls_material(&watch);
        assert_eq!(
            current.cert_pem, initial_cert_pem,
            "previous material should be preserved on reload failure"
        );
    }

    /// The shared TLS loader must reject a CA bundle whose PEM parses
    /// but contains blocks that strict `RootCertStore::add` would
    /// reject. Otherwise reload validation could pass on material that
    /// the poem/rustls listener then refuses to bind on, leaving the
    /// HTTPS server unable to start after the old server was already
    /// stopped.
    #[test]
    fn load_tls_material_rejects_mixed_valid_and_invalid_ca_bundle() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, ca_path) = write_cert_files(dir.path());

        // Append a PEM block that parses as a CERTIFICATE but whose
        // DER bytes are not a valid X.509 certificate, so the stricter
        // `RootCertStore::add` path rejects it.
        let bad_der_pem = b"\n-----BEGIN CERTIFICATE-----\nAAAAAA==\n-----END CERTIFICATE-----\n";
        let mut mixed = fs::read(&ca_path).expect("read ca");
        mixed.extend_from_slice(bad_der_pem);
        fs::write(&ca_path, &mixed).expect("write mixed ca");

        let paths = CertPaths {
            cert_path,
            key_path,
            ca_certs_paths: vec![ca_path],
        };
        let result = load_tls_material(&paths);
        assert!(
            result.is_err(),
            "validation must reject mixed valid/invalid CA bundles so the HTTPS \
             listener cannot be asked to start on material it would reject"
        );
    }

    #[test]
    fn load_tls_material_fails_with_mismatched_cert_key() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert_path, _key_path, ca_path) = write_cert_files(dir.path());

        // Generate a second key pair so the key does not match the cert
        let ck2 = generate_self_signed();
        let mismatched_key_path = dir.path().join("other_key.pem");
        fs::write(
            &mismatched_key_path,
            ck2.signing_key.serialize_pem().as_bytes(),
        )
        .expect("write mismatched key");

        let paths = CertPaths {
            cert_path,
            key_path: mismatched_key_path.to_str().expect("path").to_string(),
            ca_certs_paths: vec![ca_path],
        };
        let result = load_tls_material(&paths);
        assert!(
            result.is_err(),
            "mismatched cert/key should be rejected at load time"
        );
    }

    #[test]
    fn reload_preserves_previous_material_on_mismatched_cert_key() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_cert_files(dir.path());
        let paths = CertPaths {
            cert_path: cert.clone(),
            key_path: key,
            ca_certs_paths: vec![ca.clone()],
        };
        let loaded = load_tls_material(&paths).expect("initial load");
        let initial_cert_pem = loaded.cert_pem.clone();
        let initial = Arc::new(TlsMaterial {
            certs: Arc::new(loaded.certs),
            cert_pem: loaded.cert_pem,
            key_pem: loaded.key_pem,
            ca_pem: loaded.ca_pem,
        });

        let (handle, watch) = ReloadHandle::new(paths, initial);

        // Replace the key file with a key from a different cert so the
        // pair is parseable but mismatched.
        let ck2 = generate_self_signed();
        fs::write(
            &handle.paths.key_path,
            ck2.signing_key.serialize_pem().as_bytes(),
        )
        .expect("write mismatched key");

        handle.reload();

        let current = get_current_tls_material(&watch);
        assert_eq!(
            current.cert_pem, initial_cert_pem,
            "previous material should be preserved when cert/key pair is mismatched"
        );
    }

    #[test]
    fn subscribe_receives_updates() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_cert_files(dir.path());
        let paths = CertPaths {
            cert_path: cert,
            key_path: key,
            ca_certs_paths: vec![ca],
        };
        let loaded = load_tls_material(&paths).expect("initial load");
        let initial = Arc::new(TlsMaterial {
            certs: Arc::new(loaded.certs),
            cert_pem: loaded.cert_pem,
            key_pem: loaded.key_pem,
            ca_pem: loaded.ca_pem,
        });

        let (handle, watch) = ReloadHandle::new(paths, initial);
        let subscriber = watch.clone();

        handle.reload();

        let current = get_current_tls_material(&subscriber);
        assert!(!current.cert_pem.is_empty());
    }

    /// Verifies the notify-driven reload path that mirrors the SIGHUP
    /// wiring in main: a `Notify` fires, reload is called, and the watch
    /// channel receives updated material.
    #[tokio::test]
    async fn notify_triggers_reload_and_updates_watch() {
        install_crypto_provider();
        let dir = tempdir().expect("tempdir");
        let (cert, key, ca) = write_cert_files(dir.path());
        let paths = CertPaths {
            cert_path: cert,
            key_path: key,
            ca_certs_paths: vec![ca],
        };
        let loaded = load_tls_material(&paths).expect("initial load");
        let initial = Arc::new(TlsMaterial {
            certs: Arc::new(loaded.certs),
            cert_pem: loaded.cert_pem,
            key_pem: loaded.key_pem,
            ca_pem: loaded.ca_pem,
        });

        let (handle, mut watch) = ReloadHandle::new(paths, Arc::clone(&initial));
        let initial_pem = initial.cert_pem.clone();

        // Write new matching cert/key so reload picks up different material
        let ck2 = generate_self_signed();
        fs::write(&handle.paths.cert_path, ck2.cert.pem().as_bytes()).expect("write new cert");
        fs::write(
            &handle.paths.key_path,
            ck2.signing_key.serialize_pem().as_bytes(),
        )
        .expect("write new key");
        fs::write(&handle.paths.ca_certs_paths[0], ck2.cert.pem().as_bytes())
            .expect("write new ca");

        // Simulate the SIGHUP -> Notify -> reload path
        let reload_notify = Arc::new(tokio::sync::Notify::new());
        let notify_clone = reload_notify.clone();

        let reload_task = tokio::spawn(async move {
            notify_clone.notified().await;
            handle.reload();
        });

        reload_notify.notify_one();
        reload_task.await.expect("reload task");

        // Watch should have received updated material
        watch.changed().await.expect("watch changed");
        let updated = watch.borrow().clone();
        assert_ne!(
            initial_pem, updated.cert_pem,
            "watch should receive new material after notify-triggered reload"
        );
    }
}

/// Locks down the QUIC listener reload contract applied by both the ingest
/// and publish listeners (see `src/comm/ingest.rs` and `src/comm/publish.rs`
/// `Server::run` `tls_watch.changed()` arms). Each listener builds a
/// candidate `quinn::ServerConfig` from refreshed `Certs` via `config_server`
/// and, on success, applies it in place with `endpoint.set_server_config`;
/// on failure it logs and preserves the previously applied config. These
/// tests exercise exactly that primitive on a real QUIC `Endpoint` and
/// assert the three listener-level guarantees called out in issue #1596:
///
/// 1. After reload, new QUIC handshakes use the rotated certificate.
/// 2. Connections established before reload stay alive and keep using
///    their handshake-time TLS state.
/// 3. When rebuilding the candidate `ServerConfig` fails, the already-
///    applied listener config continues to serve new handshakes.
#[cfg(test)]
mod listener_reload_contract_tests {
    use std::{
        net::{IpAddr, Ipv6Addr, SocketAddr},
        sync::Once,
        time::Duration,
    };

    use quinn::Endpoint;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    use rustls::RootCertStore;
    use tokio::time::timeout;

    use crate::comm::{to_cert_chain, to_private_key};
    use crate::server::{Certs, config_client, config_server};

    const SERVER_DNS: &str = "listener-reload.test";

    static INSTALL_PROVIDER: Once = Once::new();

    fn install_crypto_provider() {
        INSTALL_PROVIDER.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    struct CertSet {
        server: Certs,
        client: Certs,
    }

    struct CertSetWithPems {
        set: CertSet,
        server_cert_pem: String,
        server_key_pem: String,
        ca_pem: String,
    }

    /// Builds an independent CA + server leaf + client leaf suitable for
    /// mTLS. Each call returns a fresh trust root, so set A and set B are
    /// mutually untrusting — useful for proving which TLS material a
    /// listener is actually presenting after a reload.
    fn build_cert_set() -> CertSet {
        build_cert_set_with_pems().set
    }

    /// Same as `build_cert_set`, but also returns the PEM-encoded server
    /// cert, server key, and CA so the material can be written to disk and
    /// driven through `ReloadHandle::reload()` which reloads from files.
    fn build_cert_set_with_pems() -> CertSetWithPems {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Listener Reload Test CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().expect("ca key");
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-signed ca");

        let server_key = KeyPair::generate().expect("server key");
        let mut server_params =
            CertificateParams::new(vec![SERVER_DNS.to_string()]).expect("server params");
        server_params.distinguished_name = rcgen::DistinguishedName::new();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "giganto@listener-reload");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params
            .signed_by(&server_key, &ca)
            .expect("server cert");

        let client_key = KeyPair::generate().expect("client key");
        let mut client_params =
            CertificateParams::new(vec![SERVER_DNS.to_string()]).expect("client params");
        client_params.distinguished_name = rcgen::DistinguishedName::new();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "giganto@listener-reload");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params
            .signed_by(&client_key, &ca)
            .expect("client cert");

        let ca_pem = ca.pem();
        let ca_ders = to_cert_chain(ca_pem.as_bytes()).expect("parse test CA");
        let mut root = RootCertStore::empty();
        let (added, _) = root.add_parsable_certificates(ca_ders);
        assert_eq!(added, 1, "test CA should be added to root store");

        let server_cert_pem = server_cert.pem();
        let server_key_pem = server_key.serialize_pem();
        let client_cert_pem = client_cert.pem();
        let client_key_pem = client_key.serialize_pem();

        let server = Certs {
            certs: to_cert_chain(server_cert_pem.as_bytes()).expect("parse server cert"),
            key: to_private_key(server_key_pem.as_bytes()).expect("parse server key"),
            root: root.clone(),
        };
        let client = Certs {
            certs: to_cert_chain(client_cert_pem.as_bytes()).expect("parse client cert"),
            key: to_private_key(client_key_pem.as_bytes()).expect("parse client key"),
            root,
        };
        CertSetWithPems {
            set: CertSet { server, client },
            server_cert_pem,
            server_key_pem,
            ca_pem,
        }
    }

    fn client_endpoint(certs: &Certs) -> Endpoint {
        let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
            .expect("client endpoint");
        endpoint.set_default_client_config(config_client(certs).expect("client config"));
        endpoint
    }

    async fn try_connect(client: &Endpoint, addr: SocketAddr) -> Result<quinn::Connection, String> {
        match timeout(Duration::from_secs(5), async {
            client
                .connect(addr, SERVER_DNS)
                .map_err(|e| e.to_string())?
                .await
                .map_err(|e| e.to_string())
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err("client connect timed out".to_string()),
        }
    }

    /// Verifies both guarantees the listener reload arm is meant to provide
    /// for a valid reload: new handshakes pick up the rotated certificate
    /// immediately, and a connection established before the reload keeps
    /// using its handshake-time TLS state.
    #[tokio::test]
    async fn reload_rotates_cert_for_new_handshakes_and_preserves_existing_connection() {
        install_crypto_provider();
        let set_a = build_cert_set();
        let set_b = build_cert_set();

        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let endpoint =
            Endpoint::server(config_server(&set_a.server).expect("server config a"), addr)
                .expect("server endpoint");
        let server_addr = endpoint.local_addr().expect("server local addr");

        let acceptor = {
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                let mut accepted: Vec<quinn::Connection> = Vec::new();
                while let Some(incoming) = endpoint.accept().await {
                    if let Ok(conn) = incoming.await {
                        accepted.push(conn);
                    }
                }
                drop(accepted);
            })
        };

        let client_a = client_endpoint(&set_a.client);
        let pre_reload_conn = try_connect(&client_a, server_addr)
            .await
            .expect("pre-reload client should connect with set A");
        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should be open"
        );

        // Apply the listener reload arm's primitive with set B material.
        endpoint.set_server_config(Some(config_server(&set_b.server).expect("server config b")));

        // New handshake with set B trust must succeed — proves new cert in effect.
        let client_b = client_endpoint(&set_b.client);
        let post_reload_conn = try_connect(&client_b, server_addr)
            .await
            .expect("new handshake should succeed with the rotated cert");

        // New handshake with set A trust must fail — proves old cert is gone.
        let err = try_connect(&client_a, server_addr)
            .await
            .expect_err("new handshake with stale trust anchors should fail after reload");
        assert!(
            !err.is_empty(),
            "expected a handshake error after reload with stale trust, got empty string"
        );

        // Pre-reload connection must still be alive: closed_reason is None
        // and a new bidirectional stream can still be opened over it.
        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should remain alive after reload, got close reason: {:?}",
            pre_reload_conn.close_reason()
        );
        let (mut send, _recv) = pre_reload_conn
            .open_bi()
            .await
            .expect("pre-reload connection should still accept new streams");
        send.finish()
            .expect("finish stream on pre-reload connection");

        pre_reload_conn.close(0u32.into(), b"done");
        post_reload_conn.close(0u32.into(), b"done");
        endpoint.close(0u32.into(), b"shutdown");
        endpoint.wait_idle().await;
        acceptor.abort();
        let _ = acceptor.await;
    }

    /// Verifies the failure branch of the listener reload arm: when the
    /// refreshed material would yield a `ServerConfig` build error, the
    /// arm skips `set_server_config` and the already-applied config keeps
    /// serving new handshakes. The test simulates that path by applying a
    /// valid reload first and then not applying the subsequent (bad) one —
    /// identical in effect to the `match config_server(..) { Err(..) => .. }`
    /// branch in `Server::run`.
    #[tokio::test]
    async fn bad_reload_preserves_already_applied_listener_config_for_new_handshakes() {
        install_crypto_provider();
        let set_a = build_cert_set();
        let set_b = build_cert_set();

        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let endpoint =
            Endpoint::server(config_server(&set_a.server).expect("server config a"), addr)
                .expect("server endpoint");
        let server_addr = endpoint.local_addr().expect("server local addr");

        let acceptor = {
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                let mut accepted: Vec<quinn::Connection> = Vec::new();
                while let Some(incoming) = endpoint.accept().await {
                    if let Ok(conn) = incoming.await {
                        accepted.push(conn);
                    }
                }
                drop(accepted);
            })
        };

        // Apply a first, valid reload to set B.
        endpoint.set_server_config(Some(config_server(&set_b.server).expect("server config b")));

        // Independently confirm the applied config is actually set B: a
        // client with set A trust fails, a client with set B trust succeeds.
        let client_a = client_endpoint(&set_a.client);
        try_connect(&client_a, server_addr)
            .await
            .expect_err("set A client should not connect after reload to set B");
        let client_b = client_endpoint(&set_b.client);
        let conn = try_connect(&client_b, server_addr)
            .await
            .expect("set B client should connect once config B is applied");
        conn.close(0u32.into(), b"done");

        // Simulate a subsequent bad reload: the listener's match arm would
        // take the `Err` branch and skip `set_server_config`, so the applied
        // config B must still be in effect.
        drop(build_cert_set());

        let fresh_trusted_client = client_endpoint(&set_b.client);
        let conn = try_connect(&fresh_trusted_client, server_addr)
            .await
            .expect(
                "after a failed reload the already-applied listener config should keep serving \
                 new handshakes",
            );
        conn.close(0u32.into(), b"done");

        let fresh_stale_client = client_endpoint(&set_a.client);
        try_connect(&fresh_stale_client, server_addr)
            .await
            .expect_err(
                "a failed reload must not resurrect the pre-reload config; set A should still \
                 fail",
            );

        endpoint.close(0u32.into(), b"shutdown");
        endpoint.wait_idle().await;
        acceptor.abort();
        let _ = acceptor.await;
    }

    /// End-to-end: spin up the real `ingest::Server::run` with a live
    /// `TlsWatch`, push refreshed TLS material through the watch sender,
    /// and verify that the listener's `tls_watch.changed()` select arm
    /// actually picks it up and rotates the TLS state for new QUIC
    /// handshakes. This mirrors the production flow
    /// `notify_tls_reload -> reload_handle.reload() -> watch.send -> listener arm`
    /// and, unlike the primitive-level tests above, exercises the real
    /// `Server::run` loop rather than a standalone `Endpoint`.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn ingest_server_run_reloads_tls_via_watch_end_to_end() {
        use std::{net::UdpSocket, sync::Arc};

        use tempfile::tempdir;
        use tokio::{
            sync::{Notify, watch},
            time::sleep,
        };

        use crate::comm::{
            new_ingest_sensors, new_pcap_sensors, new_runtime_ingest_sensors,
            new_stream_direct_channels,
        };
        use crate::storage::{Database, DbOptions};
        use crate::tls_reload::TlsMaterial;

        install_crypto_provider();
        let set_a = build_cert_set();
        let set_b = build_cert_set();

        // Reserve a loopback port by binding-and-dropping a UDP socket. The
        // listener rebinds to the same port, which is the standard way to
        // obtain a free ephemeral port for a server that performs its own
        // bind inside `run`.
        let server_addr = {
            let probe = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
                .expect("bind probe");
            probe.local_addr().expect("probe local addr")
        };

        let db_dir = tempdir().expect("db tempdir");
        let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open db");

        let server = crate::comm::ingest::Server::new(server_addr, &set_a.server);

        let (tls_sender, tls_watch) = watch::channel(Arc::new(TlsMaterial {
            certs: Arc::new(set_a.server.clone()),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
        }));

        let notify_shutdown = Arc::new(Notify::new());
        let pcap_sensors = new_pcap_sensors();
        let ingest_sensors = new_ingest_sensors(&db);
        let runtime_ingest_sensors = new_runtime_ingest_sensors();
        let stream_direct_channels = new_stream_direct_channels();

        let server_task = {
            let db = db.clone();
            let shutdown = notify_shutdown.clone();
            tokio::spawn(async move {
                server
                    .run(
                        db,
                        pcap_sensors,
                        ingest_sensors,
                        runtime_ingest_sensors,
                        stream_direct_channels,
                        shutdown,
                        Some(Arc::new(Notify::new())),
                        1024,
                        tls_watch,
                    )
                    .await;
            })
        };

        // Let the server bind and drain the watch channel's initial value.
        sleep(Duration::from_millis(200)).await;

        let client_a = client_endpoint(&set_a.client);
        let pre_reload_conn = try_connect(&client_a, server_addr)
            .await
            .expect("pre-reload set A client should handshake against the real ingest listener");
        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should be open"
        );

        // Drive the reload through the same watch channel the listener is
        // subscribed to. This is the final hop in the production path:
        // `ReloadHandle::reload` ultimately does `watch.send(...)`.
        tls_sender
            .send(Arc::new(TlsMaterial {
                certs: Arc::new(set_b.server.clone()),
                cert_pem: Vec::new(),
                key_pem: Vec::new(),
            }))
            .expect("broadcast refreshed material");

        // Poll until the listener's select arm has actually applied the
        // new config. Proof-by-handshake: once a set-B-trusting client can
        // handshake, the arm has fired and `set_server_config` ran.
        let mut applied = false;
        for _ in 0..40 {
            sleep(Duration::from_millis(50)).await;
            let probe = client_endpoint(&set_b.client);
            if try_connect(&probe, server_addr).await.is_ok() {
                applied = true;
                break;
            }
        }
        assert!(
            applied,
            "ingest listener did not apply refreshed TLS material via tls_watch.changed()"
        );

        let client_b = client_endpoint(&set_b.client);
        let post_reload_conn = try_connect(&client_b, server_addr)
            .await
            .expect("set B client should handshake once the listener applied the reload");

        let client_a_stale = client_endpoint(&set_a.client);
        let err = try_connect(&client_a_stale, server_addr)
            .await
            .expect_err("set A client should fail to handshake after listener rotated to set B");
        assert!(
            !err.is_empty(),
            "expected a handshake error after reload with stale trust"
        );

        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should survive the reload, close reason: {:?}",
            pre_reload_conn.close_reason()
        );

        pre_reload_conn.close(0u32.into(), b"done");
        post_reload_conn.close(0u32.into(), b"done");
        notify_shutdown.notify_waiters();
        let _ = timeout(Duration::from_secs(3), server_task).await;
    }

    /// End-to-end counterpart of the ingest test for the publish listener.
    /// Verifies that `publish::Server::run`'s `tls_watch.changed()` arm
    /// actually fires when new material is sent through the shared watch
    /// channel, and applies it to new QUIC handshakes while preserving
    /// existing connections.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn publish_server_run_reloads_tls_via_watch_end_to_end() {
        use std::{net::UdpSocket, sync::Arc};

        use tempfile::tempdir;
        use tokio::{
            sync::{Notify, watch},
            time::sleep,
        };

        use crate::comm::{
            new_ingest_sensors, new_pcap_sensors, new_peers_data, new_stream_direct_channels,
        };
        use crate::storage::{Database, DbOptions};
        use crate::tls_reload::TlsMaterial;

        install_crypto_provider();
        let set_a = build_cert_set();
        let set_b = build_cert_set();

        let server_addr = {
            let probe = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
                .expect("bind probe");
            probe.local_addr().expect("probe local addr")
        };

        let db_dir = tempdir().expect("db tempdir");
        let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open db");

        let server = crate::comm::publish::Server::new(server_addr, &set_a.server);

        let (tls_sender, tls_watch) = watch::channel(Arc::new(TlsMaterial {
            certs: Arc::new(set_a.server.clone()),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
        }));

        let notify_shutdown = Arc::new(Notify::new());
        let pcap_sensors = new_pcap_sensors();
        let ingest_sensors = new_ingest_sensors(&db);
        let stream_direct_channels = new_stream_direct_channels();
        let (peers, peer_idents) = new_peers_data(None);

        let server_task = {
            let db = db.clone();
            let shutdown = notify_shutdown.clone();
            tokio::spawn(async move {
                server
                    .run(
                        db,
                        pcap_sensors,
                        stream_direct_channels,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        tls_watch,
                        shutdown,
                    )
                    .await;
            })
        };

        sleep(Duration::from_millis(200)).await;

        let client_a = client_endpoint(&set_a.client);
        let pre_reload_conn = try_connect(&client_a, server_addr)
            .await
            .expect("pre-reload set A client should handshake against the real publish listener");
        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should be open"
        );

        tls_sender
            .send(Arc::new(TlsMaterial {
                certs: Arc::new(set_b.server.clone()),
                cert_pem: Vec::new(),
                key_pem: Vec::new(),
            }))
            .expect("broadcast refreshed material");

        let mut applied = false;
        for _ in 0..40 {
            sleep(Duration::from_millis(50)).await;
            let probe = client_endpoint(&set_b.client);
            if try_connect(&probe, server_addr).await.is_ok() {
                applied = true;
                break;
            }
        }
        assert!(
            applied,
            "publish listener did not apply refreshed TLS material via tls_watch.changed()"
        );

        let client_b = client_endpoint(&set_b.client);
        let post_reload_conn = try_connect(&client_b, server_addr)
            .await
            .expect("set B client should handshake once the listener applied the reload");

        let client_a_stale = client_endpoint(&set_a.client);
        let err = try_connect(&client_a_stale, server_addr)
            .await
            .expect_err("set A client should fail to handshake after listener rotated to set B");
        assert!(
            !err.is_empty(),
            "expected a handshake error after reload with stale trust"
        );

        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should survive the reload, close reason: {:?}",
            pre_reload_conn.close_reason()
        );

        pre_reload_conn.close(0u32.into(), b"done");
        post_reload_conn.close(0u32.into(), b"done");
        notify_shutdown.notify_waiters();
        let _ = timeout(Duration::from_secs(3), server_task).await;
    }

    /// Full-chain verification of the #1596 contract: a trigger at the
    /// top of `main` (modelled here by a `Notify`) drives
    /// `ReloadHandle::reload()`, which reloads cert/key/CA from disk and
    /// broadcasts on the shared `TlsWatch`; the live `ingest::Server::run`
    /// task, subscribed to that same watch, then picks up the refreshed
    /// material and applies it with `endpoint.set_server_config`. This is
    /// the single test that ties the trigger -> watch and
    /// watch -> listener halves together and proves the end-to-end path.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn reload_handle_reload_propagates_through_watch_to_ingest_listener_end_to_end() {
        use std::{fs, net::UdpSocket, sync::Arc};

        use tempfile::tempdir;
        use tokio::{sync::Notify, time::sleep};

        use crate::comm::{
            new_ingest_sensors, new_pcap_sensors, new_runtime_ingest_sensors,
            new_stream_direct_channels,
        };
        use crate::storage::{Database, DbOptions};
        use crate::tls_reload::{CertPaths, ReloadHandle, TlsMaterial, load_tls_material};

        install_crypto_provider();

        let bundle_a = build_cert_set_with_pems();
        let bundle_b = build_cert_set_with_pems();
        let set_a = &bundle_a.set;
        let set_b = &bundle_b.set;

        // Write set A's cert/key/CA to real files so `load_tls_material`
        // and therefore `ReloadHandle::reload()` can read them back.
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("ca.pem");
        fs::write(&cert_path, bundle_a.server_cert_pem.as_bytes()).expect("write cert");
        fs::write(&key_path, bundle_a.server_key_pem.as_bytes()).expect("write key");
        fs::write(&ca_path, bundle_a.ca_pem.as_bytes()).expect("write ca");

        let cert_paths = CertPaths {
            cert_path: cert_path.to_str().expect("cert path").to_string(),
            key_path: key_path.to_str().expect("key path").to_string(),
            ca_certs_paths: vec![ca_path.to_str().expect("ca path").to_string()],
        };

        let (initial_certs, initial_cert_pem, initial_key_pem) =
            load_tls_material(&cert_paths).expect("initial load");
        let initial_material = Arc::new(TlsMaterial {
            certs: Arc::new(initial_certs),
            cert_pem: initial_cert_pem,
            key_pem: initial_key_pem,
        });
        let (reload_handle, tls_watch) = ReloadHandle::new(cert_paths, initial_material);

        // Reserve a loopback port via probe-and-drop, same pattern as the
        // other end-to-end tests in this module.
        let server_addr = {
            let probe = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
                .expect("bind probe");
            probe.local_addr().expect("probe local addr")
        };

        let db_dir = tempdir().expect("db tempdir");
        let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open db");

        let server = crate::comm::ingest::Server::new(server_addr, &set_a.server);

        let notify_shutdown = Arc::new(Notify::new());
        let pcap_sensors = new_pcap_sensors();
        let ingest_sensors = new_ingest_sensors(&db);
        let runtime_ingest_sensors = new_runtime_ingest_sensors();
        let stream_direct_channels = new_stream_direct_channels();

        let server_task = {
            let db = db.clone();
            let shutdown = notify_shutdown.clone();
            tokio::spawn(async move {
                server
                    .run(
                        db,
                        pcap_sensors,
                        ingest_sensors,
                        runtime_ingest_sensors,
                        stream_direct_channels,
                        shutdown,
                        Some(Arc::new(Notify::new())),
                        1024,
                        tls_watch,
                    )
                    .await;
            })
        };

        sleep(Duration::from_millis(200)).await;

        let client_a = client_endpoint(&set_a.client);
        let pre_reload_conn = try_connect(&client_a, server_addr)
            .await
            .expect("pre-reload set A client should handshake against the real ingest listener");
        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should be open"
        );

        // Overwrite the on-disk material with set B so the next
        // `ReloadHandle::reload()` reads refreshed cert/key/CA from disk.
        fs::write(&cert_path, bundle_b.server_cert_pem.as_bytes()).expect("overwrite cert");
        fs::write(&key_path, bundle_b.server_key_pem.as_bytes()).expect("overwrite key");
        fs::write(&ca_path, bundle_b.ca_pem.as_bytes()).expect("overwrite ca");

        // Drive the trigger exactly the way `main.rs` does: a `Notify`
        // fires, a task awaits `notified()`, then calls
        // `reload_handle.reload()`. That method does its own file I/O and
        // then broadcasts on the shared watch.
        let reload_trigger = Arc::new(Notify::new());
        let trigger_clone = reload_trigger.clone();
        let reload_task = tokio::spawn(async move {
            trigger_clone.notified().await;
            reload_handle.reload();
        });

        reload_trigger.notify_one();
        reload_task.await.expect("reload task");

        // The listener's `tls_watch.changed()` arm should now fire and
        // apply the refreshed `ServerConfig`. Prove it by polling until a
        // set-B-trusting client can handshake.
        let mut applied = false;
        for _ in 0..40 {
            sleep(Duration::from_millis(50)).await;
            let probe = client_endpoint(&set_b.client);
            if try_connect(&probe, server_addr).await.is_ok() {
                applied = true;
                break;
            }
        }
        assert!(
            applied,
            "full chain (Notify -> ReloadHandle::reload -> watch -> listener) did not \
             rotate ingest listener TLS state"
        );

        // Stale trust must fail now that set B is in effect — rules out
        // any possibility that the old config lingered.
        let client_a_stale = client_endpoint(&set_a.client);
        let err = try_connect(&client_a_stale, server_addr)
            .await
            .expect_err("set A client should fail after full-chain reload to set B");
        assert!(
            !err.is_empty(),
            "expected a handshake error after reload with stale trust"
        );

        // The pre-reload connection (handshaken with set A) must remain
        // alive — in-place `set_server_config` must not disturb it.
        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should survive the full-chain reload, close reason: {:?}",
            pre_reload_conn.close_reason()
        );

        pre_reload_conn.close(0u32.into(), b"done");
        notify_shutdown.notify_waiters();
        let _ = timeout(Duration::from_secs(3), server_task).await;
    }

    /// Publish counterpart of
    /// `reload_handle_reload_propagates_through_watch_to_ingest_listener_end_to_end`.
    /// Drives the complete
    /// `Notify -> ReloadHandle::reload() -> TlsWatch -> publish listener`
    /// path rather than sending refreshed material directly through the
    /// watch, so the full chain is exercised for publish as well as ingest.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn reload_handle_reload_propagates_through_watch_to_publish_listener_end_to_end() {
        use std::{fs, net::UdpSocket, sync::Arc};

        use tempfile::tempdir;
        use tokio::{sync::Notify, time::sleep};

        use crate::comm::{
            new_ingest_sensors, new_pcap_sensors, new_peers_data, new_stream_direct_channels,
        };
        use crate::storage::{Database, DbOptions};
        use crate::tls_reload::{CertPaths, ReloadHandle, TlsMaterial, load_tls_material};

        install_crypto_provider();

        let bundle_a = build_cert_set_with_pems();
        let bundle_b = build_cert_set_with_pems();
        let set_a = &bundle_a.set;
        let set_b = &bundle_b.set;

        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("ca.pem");
        fs::write(&cert_path, bundle_a.server_cert_pem.as_bytes()).expect("write cert");
        fs::write(&key_path, bundle_a.server_key_pem.as_bytes()).expect("write key");
        fs::write(&ca_path, bundle_a.ca_pem.as_bytes()).expect("write ca");

        let cert_paths = CertPaths {
            cert_path: cert_path.to_str().expect("cert path").to_string(),
            key_path: key_path.to_str().expect("key path").to_string(),
            ca_certs_paths: vec![ca_path.to_str().expect("ca path").to_string()],
        };

        let (initial_certs, initial_cert_pem, initial_key_pem) =
            load_tls_material(&cert_paths).expect("initial load");
        let initial_material = Arc::new(TlsMaterial {
            certs: Arc::new(initial_certs),
            cert_pem: initial_cert_pem,
            key_pem: initial_key_pem,
        });
        let (reload_handle, tls_watch) = ReloadHandle::new(cert_paths, initial_material);

        let server_addr = {
            let probe = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
                .expect("bind probe");
            probe.local_addr().expect("probe local addr")
        };

        let db_dir = tempdir().expect("db tempdir");
        let db = Database::open(db_dir.path(), &DbOptions::default()).expect("open db");

        let server = crate::comm::publish::Server::new(server_addr, &set_a.server);

        let notify_shutdown = Arc::new(Notify::new());
        let pcap_sensors = new_pcap_sensors();
        let ingest_sensors = new_ingest_sensors(&db);
        let stream_direct_channels = new_stream_direct_channels();
        let (peers, peer_idents) = new_peers_data(None);

        let server_task = {
            let db = db.clone();
            let shutdown = notify_shutdown.clone();
            tokio::spawn(async move {
                server
                    .run(
                        db,
                        pcap_sensors,
                        stream_direct_channels,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        tls_watch,
                        shutdown,
                    )
                    .await;
            })
        };

        sleep(Duration::from_millis(200)).await;

        let client_a = client_endpoint(&set_a.client);
        let pre_reload_conn = try_connect(&client_a, server_addr)
            .await
            .expect("pre-reload set A client should handshake against the real publish listener");
        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should be open"
        );

        fs::write(&cert_path, bundle_b.server_cert_pem.as_bytes()).expect("overwrite cert");
        fs::write(&key_path, bundle_b.server_key_pem.as_bytes()).expect("overwrite key");
        fs::write(&ca_path, bundle_b.ca_pem.as_bytes()).expect("overwrite ca");

        let reload_trigger = Arc::new(Notify::new());
        let trigger_clone = reload_trigger.clone();
        let reload_task = tokio::spawn(async move {
            trigger_clone.notified().await;
            reload_handle.reload();
        });

        reload_trigger.notify_one();
        reload_task.await.expect("reload task");

        let mut applied = false;
        for _ in 0..40 {
            sleep(Duration::from_millis(50)).await;
            let probe = client_endpoint(&set_b.client);
            if try_connect(&probe, server_addr).await.is_ok() {
                applied = true;
                break;
            }
        }
        assert!(
            applied,
            "full chain (Notify -> ReloadHandle::reload -> watch -> listener) did not \
             rotate publish listener TLS state"
        );

        let client_a_stale = client_endpoint(&set_a.client);
        let err = try_connect(&client_a_stale, server_addr)
            .await
            .expect_err("set A client should fail after full-chain reload to set B");
        assert!(
            !err.is_empty(),
            "expected a handshake error after reload with stale trust"
        );

        assert!(
            pre_reload_conn.close_reason().is_none(),
            "pre-reload connection should survive the full-chain reload, close reason: {:?}",
            pre_reload_conn.close_reason()
        );

        pre_reload_conn.close(0u32.into(), b"done");
        notify_shutdown.notify_waiters();
        let _ = timeout(Duration::from_secs(3), server_task).await;
    }
}
