//! Process-boundary lifecycle tests.
//!
//! Everything the in-process `generation_tests` cover stops at the edge of the
//! process: they drive `run_lifecycle` directly, so the OS signal handlers the
//! real binary installs, the exit status a process manager reads, and the
//! deployment path where a brand-new process opens the store a cleanly
//! terminated one left behind are all outside what they can see. This file
//! covers that edge, and only that edge, by running the binary Cargo builds as
//! a child process.
//!
//! The support here is sized for these process tests and no more: spawning a
//! child, watching its `--log-path` file, generating throwaway PKI and a
//! configuration under a temp directory, reading the addresses a port-0 QUIC
//! listener actually bound, picking a loopback port for GraphQL, waiting under
//! a bound on explicit conditions, signalling, and reaping. It is deliberately
//! not a general-purpose process-test framework.

// Signals are the subject, so there is nothing here to run anywhere else.
#![cfg(unix)]

use std::{
    fs::{self, File},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use giganto_client::{
    RawEventKind,
    connection::client_handshake,
    frame::send_raw,
    ingest::{log::Log, receive_ack_timestamp, send_record_header},
};
use quinn::crypto::rustls::QuicClientConfig;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::{Instant, sleep};

// ---------------------------------------------------------------------------
// Bounds
//
// Every one of these is an upper bound on a wait that ends on an explicit
// condition — a log marker, a handshake, an acknowledgement, a reaped child —
// never a settle delay. They are deliberately loose: a clean shutdown alone
// spends `SERVER_REBOOT_DELAY` (3s) on its way out, and the coverage matrix
// runs an instrumented binary, so a bound tight enough to be interesting here
// would only turn slow CI into a flake. What they buy is that a lifecycle that
// never completes fails the test instead of hanging it.
// ---------------------------------------------------------------------------

/// Upper bound on a child reporting that every subsystem is serving.
const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Upper bound on a signalled child exiting.
const EXIT_TIMEOUT: Duration = Duration::from_secs(120);
/// Upper bound on the ingest handshake and the acknowledgement that follows.
const INGEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Upper bound on GraphQL answering with the record the first process stored.
const QUERY_TIMEOUT: Duration = Duration::from_secs(60);
/// Upper bound on the failure path's wait for a child to take its `SIGTERM`
/// before it is escalated to `SIGKILL`.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
/// How often every bounded wait rechecks its condition.
const POLL: Duration = Duration::from_millis(25);

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

/// The four-label SAN DNS name of the node certificate, which is also the
/// server name the QUIC clients ask for.
const NODE_SAN: &str = "001.giganto.node1.example.test";
/// The legacy `{service}@{hostname}` common name of the node certificate.
const NODE_CN: &str = "giganto@node1";
/// The four-label SAN DNS name of the ingest client certificate. The service
/// label is `giganto` rather than `piglet`, so ingest does not class this
/// sensor as a pcap sensor.
const SENSOR_SAN: &str = "001.giganto.sensor1.example.test";
/// The legacy `{service}@{hostname}` common name of the ingest client
/// certificate.
const SENSOR_CN: &str = "giganto@sensor1";

/// The sensor giganto derives from the ingest client certificate.
///
/// It is the client's identity, not the node's: the two certificates carry
/// different names precisely so a query that read the wrong one finds nothing.
/// A default build reads the legacy common name and keeps the bare hostname; a
/// `bootroot` build reads the SAN and keeps the service FQDN, which is the SAN
/// without its instance label.
fn expected_sensor() -> &'static str {
    if cfg!(feature = "bootroot") {
        "giganto.sensor1.example.test"
    } else {
        "sensor1"
    }
}

/// The identity the node certificate carries, read the same way.
///
/// Nothing is stored under it, which is what makes it the control: a filter
/// that answered with the marker here would be answering regardless of the
/// sensor asked for, and the positive query would prove nothing about which
/// certificate the record was attributed to.
fn node_identity() -> &'static str {
    if cfg!(feature = "bootroot") {
        "giganto.node1.example.test"
    } else {
        "node1"
    }
}

/// The `kind` the marker record carries, and the mid-key ingest builds from
/// it.
const LOG_KIND: &str = "process-lifecycle-smoke";

/// The address the configuration names for a QUIC listener whose port the
/// kernel picks at bind time.
const EPHEMERAL: &str = "127.0.0.1:0";

// ---------------------------------------------------------------------------
// Log markers
// ---------------------------------------------------------------------------

/// What a child logs once each of its three listeners is up.
///
/// The two QUIC lines carry the address actually bound, so they double as the
/// readiness signal and as the source of the addresses the restart is pinned
/// to. The GraphQL line carries the address from the configuration instead,
/// which is why the GraphQL port is chosen by the test rather than by the
/// kernel.
const READY_MARKERS: [&str; 3] = [
    "Ingest listening on",
    "Publish listening on",
    "GraphQL web server is starting on",
];

/// The prefix every phase of the shutdown sequence carries.
const PHASE_PREFIX: &str = "shutdown phase";

/// The six phase markers a terminate ending leaves behind, in order.
const TERMINATE_PHASES: [&str; 6] = [
    "web shutdown returned",
    "web reaper drain returned",
    "top-level drain returned",
    "retained handles read",
    "shutting the database down",
    "final action, returning from the lifecycle",
];

/// What must not appear anywhere a cleanly shut down child wrote.
const FORBIDDEN_RECORDS: [&str; 3] = [
    "entry task ended abnormally",
    "generation ended degraded",
    "panicked at",
];

/// What a child logs when the store it was pointed at had to be rebuilt.
const REPAIR_MARKER: &str = "Starting DB repair";

// ---------------------------------------------------------------------------
// Test PKI
// ---------------------------------------------------------------------------

/// Throwaway PKI for one run, written under the run's own temp directory.
///
/// Two leaves under one CA, because the node and the sensor have to be told
/// apart: a single self-signed certificate serving as its own trust anchor can
/// only ever present one identity, and the restart assertion turns on the
/// sensor's being the client's.
struct TestPki {
    ca_path: PathBuf,
    ca_pem: String,
    node_cert_path: PathBuf,
    node_key_path: PathBuf,
    node_cert_pem: String,
    node_key_pem: String,
    sensor_cert_pem: String,
    sensor_key_pem: String,
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.use_authority_key_identifier_extension = true;
    params
}

/// A leaf carrying both identities giganto knows how to read: the legacy
/// `{service}@{hostname}` common name of the default build and the four-label
/// SAN DNS name of the `bootroot` build.
fn leaf_params(common_name: &str, dns_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(vec![dns_name.to_string()]).expect("cert params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.use_authority_key_identifier_extension = true;
    params
}

fn write_test_pki(dir: &Path) -> TestPki {
    let ca_key = KeyPair::generate().expect("generate the CA key");
    let ca = CertifiedIssuer::self_signed(ca_params("Giganto Process Test CA"), ca_key)
        .expect("build the test CA");

    let node_key = KeyPair::generate().expect("generate the node key");
    let node_cert = leaf_params(NODE_CN, NODE_SAN)
        .signed_by(&node_key, &ca)
        .expect("sign the node certificate");

    let sensor_key = KeyPair::generate().expect("generate the sensor key");
    let sensor_cert = leaf_params(SENSOR_CN, SENSOR_SAN)
        .signed_by(&sensor_key, &ca)
        .expect("sign the sensor certificate");

    let ca_pem = ca.pem();
    let node_cert_pem = node_cert.pem();
    let node_key_pem = node_key.serialize_pem();

    let ca_path = dir.join("ca.pem");
    let node_cert_path = dir.join("node-cert.pem");
    let node_key_path = dir.join("node-key.pem");
    fs::write(&ca_path, &ca_pem).expect("write the CA certificate");
    fs::write(&node_cert_path, &node_cert_pem).expect("write the node certificate");
    fs::write(&node_key_path, &node_key_pem).expect("write the node key");

    TestPki {
        ca_path,
        ca_pem,
        node_cert_path,
        node_key_path,
        node_cert_pem,
        node_key_pem,
        sensor_cert_pem: sensor_cert.pem(),
        sensor_key_pem: sensor_key.serialize_pem(),
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Writes the configuration the first child starts from.
///
/// The two QUIC listeners are left on port 0 so nothing has to be reserved for
/// them; GraphQL is given a concrete address because its readiness line
/// reports the configured address rather than the bound one, and a test that
/// could not read the bound port could never reach the endpoint.
fn write_config(path: &Path, data_dir: &Path, export_dir: &Path, graphql_addr: SocketAddr) {
    let config = format!(
        "ingest_srv_addr = \"{EPHEMERAL}\"\n\
         publish_srv_addr = \"{EPHEMERAL}\"\n\
         graphql_srv_addr = \"{graphql_addr}\"\n\
         data_dir = \"{data}\"\n\
         export_dir = \"{export}\"\n\
         retention = \"100d\"\n\
         max_open_files = 500\n\
         max_mb_of_level_base = 512\n\
         num_of_thread = 2\n\
         max_subcompactions = 2\n\
         ack_transmission = 1\n",
        data = data_dir.display(),
        export = export_dir.display(),
    );
    fs::write(path, config).expect("write the child configuration");
}

/// Rewrites the two port-0 entries with the addresses the first process
/// actually bound, leaving GraphQL on the address it was already given.
fn pin_quic_addresses(path: &Path, ingest: SocketAddr, publish: SocketAddr) {
    let config = fs::read_to_string(path).expect("read the child configuration");
    let pinned = config
        .replace(
            &format!("ingest_srv_addr = \"{EPHEMERAL}\""),
            &format!("ingest_srv_addr = \"{ingest}\""),
        )
        .replace(
            &format!("publish_srv_addr = \"{EPHEMERAL}\""),
            &format!("publish_srv_addr = \"{publish}\""),
        );
    assert!(
        !pinned.contains(EPHEMERAL),
        "the restart configuration still names an ephemeral port:\n{pinned}"
    );
    fs::write(path, pinned).expect("rewrite the child configuration");
}

/// A loopback address nothing holds.
///
/// The listener exists only to learn which port the kernel handed out and is
/// dropped before the address is returned. That leaves a window in which
/// another process could take the port, which is why this is called
/// immediately before the child that binds it starts, and why a child that
/// loses the race is reported as a bind failure naming the address rather than
/// as a lifecycle defect.
fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve a loopback port");
    let addr = listener.local_addr().expect("read the reserved address");
    drop(listener);
    addr
}

// ---------------------------------------------------------------------------
// The child process
// ---------------------------------------------------------------------------

/// One `giganto` child process, and the files the test reads it back through.
///
/// The tracing log goes to `--log-path` so every state transition is
/// observable; stdout and stderr are captured separately because an error
/// `main` returns and a panic never reach the tracing log at all.
struct Node {
    label: String,
    child: Child,
    log_path: PathBuf,
    console_path: PathBuf,
    status: Option<ExitStatus>,
}

fn read_text(path: &Path) -> String {
    fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// The child's pid, when it is one that can be signalled.
///
/// A pid is only ever handed to `kill` through this, so a non-positive value —
/// which `kill` would read as a process group or as every process the caller
/// may signal — can never be signalled by accident.
fn signalable_pid(child: &Child) -> Option<libc::pid_t> {
    libc::pid_t::try_from(child.id())
        .ok()
        .filter(|pid| *pid > 0)
}

impl Node {
    fn spawn(label: &str, dir: &Path, cfg_path: &Path, pki: &TestPki) -> Self {
        let log_path = dir.join(format!("{label}.log"));
        let console_path = dir.join(format!("{label}.console"));
        let console = File::create(&console_path).expect("create the console capture");
        let console_err = console.try_clone().expect("clone the console capture");

        let child = Command::new(env!("CARGO_BIN_EXE_giganto"))
            .arg("-c")
            .arg(cfg_path)
            .arg("--cert")
            .arg(&pki.node_cert_path)
            .arg("--key")
            .arg(&pki.node_key_path)
            .arg("--ca-certs")
            .arg(&pki.ca_path)
            .arg("--log-path")
            .arg(&log_path)
            // Every condition this test waits on is an `INFO` record, and the
            // child builds its filter with `EnvFilter::from_env_lossy`, so an
            // ambient `RUST_LOG` would reconfigure the one stream the test
            // reads. Naming the level here is what keeps the run from
            // depending on the shell it was started from.
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::from(console))
            .stderr(Stdio::from(console_err))
            .spawn()
            .expect("spawn the giganto binary");

        Self {
            label: label.to_string(),
            child,
            log_path,
            console_path,
            status: None,
        }
    }

    fn log(&self) -> String {
        read_text(&self.log_path)
    }

    fn console(&self) -> String {
        read_text(&self.console_path)
    }

    /// Everything the child wrote, for a failure to carry with it.
    fn diagnostics(&self) -> String {
        format!(
            "--- {label} log ({log_path}) ---\n{log}\n--- {label} console ({console_path}) ---\n{console}",
            label = self.label,
            log_path = self.log_path.display(),
            log = self.log(),
            console_path = self.console_path.display(),
            console = self.console(),
        )
    }

    fn signal(&self, signal: libc::c_int) {
        let pid = signalable_pid(&self.child).unwrap_or_else(|| {
            panic!("{}: the child has no signalable pid", self.label);
        });
        // SAFETY: `pid` is this test's own child, it is positive, and it has
        // not been reaped, so the pid still names that child and nothing else.
        let sent = unsafe { libc::kill(pid, signal) };
        assert_eq!(
            sent,
            0,
            "{}: could not send signal {signal} to {pid}: {}\n{}",
            self.label,
            std::io::Error::last_os_error(),
            self.diagnostics(),
        );
    }

    /// Reaps the child if it has already exited.
    fn reap_if_exited(&mut self) -> Option<ExitStatus> {
        if self.status.is_none()
            && let Ok(Some(status)) = self.child.try_wait()
        {
            self.status = Some(status);
        }
        self.status
    }

    /// Waits under `EXIT_TIMEOUT` for the child to exit, and reaps it.
    async fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        loop {
            if let Some(status) = self.reap_if_exited() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "{}: the child did not exit within {EXIT_TIMEOUT:?}\n{}",
                self.label,
                self.diagnostics(),
            );
            sleep(POLL).await;
        }
    }

    /// Waits under `READY_TIMEOUT` for every readiness marker to appear.
    ///
    /// A bind failure ends the wait early, because none of the markers is ever
    /// coming and the address that could not be bound is the whole diagnosis.
    async fn wait_until_ready(&mut self, targets: &BindTargets) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let log = self.log();
            if READY_MARKERS.iter().all(|marker| log.contains(marker)) {
                return;
            }
            if let Some(reason) = bind_failure(&log, targets) {
                panic!("{}: {reason}\n{}", self.label, self.diagnostics());
            }
            if let Some(status) = self.reap_if_exited() {
                // `log` was read before the exit was observed, so a child that
                // died of a bind failure in between wrote its diagnosis after
                // that read. Reading again once it has exited is what keeps a
                // lost race for a port from being reported as an unexplained
                // early exit: nothing more is coming, and the child's appender
                // has flushed everything it had.
                if let Some(reason) = bind_failure(&self.log(), targets) {
                    panic!("{}: {reason}\n{}", self.label, self.diagnostics());
                }
                panic!(
                    "{}: the child exited with {status} before it was ready\n{}",
                    self.label,
                    self.diagnostics(),
                );
            }
            assert!(
                Instant::now() < deadline,
                "{}: the child was not ready within {READY_TIMEOUT:?}; \
                 it was told to bind {targets}\n{}",
                self.label,
                self.diagnostics(),
            );
            sleep(POLL).await;
        }
    }
}

/// Leaves no child and no port behind, on the success path and on the failure
/// path alike.
///
/// A child already reaped is nothing to do. Anything still alive — a test that
/// failed before it signalled, or one that failed while waiting for an exit —
/// is asked to go down the same way the test asks, waited for under a bound,
/// and only then killed outright. Either way it is reaped, so no listener
/// survives this scope.
impl Drop for Node {
    fn drop(&mut self) {
        if self.reap_if_exited().is_some() {
            return;
        }
        if let Some(pid) = signalable_pid(&self.child) {
            // SAFETY: as in `signal` — this test's own live, unreaped child.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        let deadline = std::time::Instant::now() + CLEANUP_TIMEOUT;
        while std::time::Instant::now() < deadline {
            if self.reap_if_exited().is_some() {
                return;
            }
            std::thread::sleep(POLL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The addresses a child was told to bind, named in the diagnostics of a
/// listener that could not take one.
struct BindTargets {
    ingest: String,
    publish: String,
    graphql: String,
}

impl std::fmt::Display for BindTargets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ingest {}, publish {}, GraphQL {}",
            self.ingest, self.publish, self.graphql
        )
    }
}

/// The address a listener could not take, when one of them reported a bind
/// failure.
///
/// giganto reports the bind error without the address, so the address comes
/// from what the test put in the configuration. That is what tells a lost race
/// for a port apart from a lifecycle defect.
fn bind_failure(log: &str, targets: &BindTargets) -> Option<String> {
    if log.contains("failed to bind the ingest listener") {
        return Some(format!(
            "the ingest listener could not bind {}",
            targets.ingest
        ));
    }
    if log.contains("failed to bind the publish listener") {
        return Some(format!(
            "the publish listener could not bind {}",
            targets.publish
        ));
    }
    if log.contains("Failed to start GraphQL server") {
        return Some(format!(
            "the GraphQL listener could not bind {}",
            targets.graphql
        ));
    }
    None
}

/// The address a readiness line reports.
fn addr_after(node: &Node, marker: &str) -> SocketAddr {
    let log = node.log();
    let line = log
        .lines()
        .rev()
        .find(|line| line.contains(marker))
        .unwrap_or_else(|| {
            panic!(
                "{}: no {marker:?} line in the child log\n{}",
                node.label,
                node.diagnostics()
            )
        });
    let (_, rest) = line.split_once(marker).expect("the marker is in the line");
    rest.trim().parse().unwrap_or_else(|e| {
        panic!(
            "{}: could not read an address from {line:?}: {e}",
            node.label
        )
    })
}

/// Asserts the child's log carries the six phase markers of a terminate
/// ending, in order, and nothing else that carries the phase prefix.
fn assert_shutdown_sequence(node: &Node, signal: &str) {
    let log = node.log();
    let markers: Vec<&str> = log
        .lines()
        .filter(|line| line.contains(PHASE_PREFIX))
        .collect();
    assert_eq!(
        markers.len(),
        TERMINATE_PHASES.len(),
        "{}: {signal} should leave {} phase markers, got: {markers:#?}\n{}",
        node.label,
        TERMINATE_PHASES.len(),
        node.diagnostics(),
    );
    for (marker, needle) in markers.iter().zip(TERMINATE_PHASES) {
        assert!(
            marker.contains(needle),
            "{}: {signal} should have logged a marker for {needle:?}, got: {markers:#?}",
            node.label,
        );
    }
}

/// Asserts nothing the child wrote says the shutdown was anything but clean.
fn assert_clean_shutdown(node: &Node) {
    let log = node.log();
    let console = node.console();
    for needle in FORBIDDEN_RECORDS {
        assert!(
            !log.contains(needle),
            "{}: a clean shutdown should leave no {needle:?} record\n{}",
            node.label,
            node.diagnostics(),
        );
        assert!(
            !console.contains(needle),
            "{}: a clean shutdown should leave no {needle:?} on the console\n{}",
            node.label,
            node.diagnostics(),
        );
    }
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

fn certs_from_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("read the certificate chain")
}

fn key_from_pem(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .expect("read the private key")
        .expect("the key file should hold a private key")
}

/// The QUIC client configuration the sensor connects with.
///
/// It presents the ingest client certificate, which is what decides the sensor
/// the records land under.
fn sensor_client_config(pki: &TestPki) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs_from_pem(&pki.ca_pem) {
        roots.add(cert).expect("trust the test CA");
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certs_from_pem(&pki.sensor_cert_pem),
            key_from_pem(&pki.sensor_key_pem),
        )
        .expect("build the sensor TLS configuration");
    quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).expect("build the sensor QUIC configuration"),
    ))
}

/// A live ingest connection, held open across the shutdown intent.
///
/// The endpoint is kept alongside the connection so the connection is what
/// ends it, not a dropped driver.
struct IngestClient {
    _endpoint: quinn::Endpoint,
    _connection: quinn::Connection,
}

/// Sends one marker record and waits for the acknowledgement it produces.
///
/// `ack_transmission` is 1 in the configuration, so this single record is a
/// whole batch and the reply needs no second synchronization point.
async fn ingest_marker(
    addr: SocketAddr,
    pki: &TestPki,
    marker: &[u8],
    timestamp: i64,
) -> IngestClient {
    // Bound on IPv4 because the listener is: quinn will not send from a v6
    // socket to a v4 peer.
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .expect("create the sensor endpoint");
    endpoint.set_default_client_config(sensor_client_config(pki));

    let connection = tokio::time::timeout(
        INGEST_TIMEOUT,
        endpoint
            .connect(addr, NODE_SAN)
            .expect("the sensor client configuration should build"),
    )
    .await
    .expect("the sensor should reach the ingest listener within the bound")
    .expect("the sensor should reach the ingest listener");
    tokio::time::timeout(
        INGEST_TIMEOUT,
        client_handshake(&connection, env!("CARGO_PKG_VERSION")),
    )
    .await
    .expect("the version handshake should finish within the bound")
    .expect("the version handshake should succeed");

    let (mut send, mut recv) = connection.open_bi().await.expect("open the sensor stream");
    send_record_header(&mut send, RawEventKind::Log)
        .await
        .expect("send the record header");
    let event = Log {
        kind: LOG_KIND.to_string(),
        log: marker.to_vec(),
    };
    let body = bincode::serialize(&event).expect("serialize the log body");
    let batch = bincode::serialize(&vec![(timestamp, body)]).expect("serialize the log batch");
    send_raw(&mut send, &batch).await.expect("send the marker");

    let acked = tokio::time::timeout(INGEST_TIMEOUT, receive_ack_timestamp(&mut recv))
        .await
        .expect("the marker should be acknowledged within the bound")
        .expect("the acknowledgement should decode");
    assert_eq!(
        acked, timestamp,
        "the acknowledgement should name the marker"
    );

    IngestClient {
        _endpoint: endpoint,
        _connection: connection,
    }
}

/// The mTLS GraphQL client, built the way the node builds its own.
fn graphql_client(pki: &TestPki) -> reqwest::Client {
    let identity = reqwest::Identity::from_pem(
        format!("{}{}", pki.node_cert_pem, pki.node_key_pem).as_bytes(),
    )
    .expect("build the GraphQL client identity");
    reqwest::Client::builder()
        .identity(identity)
        .danger_accept_invalid_certs(true)
        .tls_sni(false)
        .build()
        .expect("build the GraphQL client")
}

/// Posts one GraphQL query, reporting either the answer or why there was
/// none.
///
/// The two failure modes are folded into one string because the caller only
/// retries and, on the way out, reports what it last saw.
async fn post_query(client: &reqwest::Client, url: &str, query: &str) -> Result<String, String> {
    let response = client
        .post(url)
        .json(&serde_json::json!({ "query": query }))
        .send()
        .await
        .map_err(|e| format!("the request failed: {e}"))?;
    response
        .text()
        .await
        .map_err(|e| format!("the response body could not be read: {e}"))
}

/// The query that asks one sensor for the marker kind.
fn marker_query(sensor: &str) -> String {
    format!(
        "{{ logRawEvents(filter: {{ sensor: \"{sensor}\", kind: \"{LOG_KIND}\" }}, first: 100) \
         {{ edges {{ node {{ time log }} }} }} }}"
    )
}

/// The base64 `log` bodies a GraphQL answer carries, refusing an answer that
/// is not one.
fn stored_logs(body: &str) -> Vec<String> {
    let answer: serde_json::Value =
        serde_json::from_str(body).expect("the GraphQL answer should be JSON");
    assert!(
        answer.get("errors").is_none(),
        "the GraphQL answer should carry no errors: {body}"
    );
    let edges = answer["data"]["logRawEvents"]["edges"]
        .as_array()
        .unwrap_or_else(|| panic!("the GraphQL answer should carry edges: {body}"));
    edges
        .iter()
        .filter_map(|edge| edge["node"]["log"].as_str().map(ToOwned::to_owned))
        .collect()
}

/// Queries the restarted node for the marker the first process acknowledged.
///
/// The wait is on the answer carrying the marker rather than on the request
/// succeeding: the endpoint is listening from the moment its readiness line is
/// written, but the first mTLS handshake after a restart is the one thing here
/// that can lose a race with the accept loop, so a refused connection is
/// retried under the bound instead of failing the test.
///
/// The node's own identity is asked the same question afterwards. It has to
/// come back empty: without that, an answer that ignored the sensor filter
/// altogether would look exactly like one that attributed the record to the
/// ingest client's certificate.
async fn assert_marker_is_queryable(
    client: &reqwest::Client,
    addr: SocketAddr,
    node: &Node,
    marker: &[u8],
) {
    let sensor = expected_sensor();
    let encoded = base64_engine.encode(marker);
    let url = format!("https://{addr}/graphql");
    let query = marker_query(sensor);

    let deadline = Instant::now() + QUERY_TIMEOUT;
    let mut last;
    let body = loop {
        last = match post_query(client, &url, &query).await {
            Ok(body) if body.contains(&encoded) => break body,
            Ok(body) => body,
            Err(reason) => reason,
        };
        assert!(
            Instant::now() < deadline,
            "{}: GraphQL did not return the marker for sensor {sensor:?} within \
             {QUERY_TIMEOUT:?}; last answer: {last}\n{}",
            node.label,
            node.diagnostics(),
        );
        sleep(POLL).await;
    };

    assert_eq!(
        stored_logs(&body),
        vec![encoded.clone()],
        "the restarted node should serve exactly the marker the first process acknowledged: {body}"
    );

    let control = node_identity();
    let body = post_query(client, &url, &marker_query(control))
        .await
        .unwrap_or_else(|reason| {
            panic!(
                "{}: the control query for sensor {control:?} failed: {reason}\n{}",
                node.label,
                node.diagnostics(),
            )
        });
    assert!(
        stored_logs(&body).is_empty(),
        "the marker was ingested under {sensor:?}, so the node's own identity \
         {control:?} should hold nothing: {body}"
    );
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// The real binary shuts down on `SIGTERM`, restarts against what it left
/// behind, and shuts down again on `SIGINT`.
///
/// The in-process lifecycle tests already establish the phase order and the
/// store handoff within one process. What only a child process can show is
/// that the OS signal handlers are wired to that lifecycle at all, that the
/// exit a process manager reads is a success, and that a new process opens the
/// store a cleanly terminated one left on disk without being repaired first —
/// the deployment path, not a reopen inside the test's own runtime.
///
/// The two signals are both covered because they are installed as two separate
/// arms: a `SIGTERM` that worked says nothing about `SIGINT`, so each gets a
/// process of its own and each has to leave its own six markers behind.
#[tokio::test]
#[serial_test::serial(runtime_lifecycle_process)]
async fn process_sigterm_sigint_shutdown_and_restart() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let dir = tempfile::tempdir().expect("create the run directory");
    let root = dir.path();
    let data_dir = root.join("data");
    let export_dir = root.join("export");
    fs::create_dir_all(&data_dir).expect("create the data directory");
    fs::create_dir_all(&export_dir).expect("create the export directory");
    let pki = write_test_pki(root);
    let cfg_path = root.join("config.toml");

    // Chosen and released here, immediately before the first child starts, so
    // the window in which another process could take the port is as short as
    // this pattern allows.
    let graphql_addr = free_loopback_addr();
    write_config(&cfg_path, &data_dir, &export_dir, graphql_addr);
    let mut targets = BindTargets {
        ingest: EPHEMERAL.to_string(),
        publish: EPHEMERAL.to_string(),
        graphql: graphql_addr.to_string(),
    };

    // The marker timestamp is the current time rather than a fixed one:
    // retention runs a pass as each generation starts, and a record older than
    // the retention period would be swept before the restart could serve it.
    let timestamp = timestamp_nanos();
    let marker = format!("giganto-process-restart-marker-{timestamp}");

    let (ingest_addr, publish_addr) = {
        let mut first = Node::spawn("sigterm", root, &cfg_path, &pki);
        first.wait_until_ready(&targets).await;

        let ingest_addr = addr_after(&first, "Ingest listening on");
        let publish_addr = addr_after(&first, "Publish listening on");

        let sensor = ingest_marker(ingest_addr, &pki, marker.as_bytes(), timestamp).await;

        first.signal(libc::SIGTERM);
        let status = first.wait_for_exit().await;
        assert!(
            status.success(),
            "SIGTERM should exit the process successfully, got {status}\n{}",
            first.diagnostics(),
        );
        assert_shutdown_sequence(&first, "SIGTERM");
        assert_clean_shutdown(&first);

        // The connection was deliberately open across the intent; the
        // generation had to cancel it to get here.
        drop(sensor);

        // Kept out of the second child's scope: nothing of the first process
        // may still hold the store or a listener when the next one opens them.
        (ingest_addr, publish_addr)
    };

    // The real deployment path: the same configuration, the same store, the
    // same addresses, and a process that has never seen any of them.
    pin_quic_addresses(&cfg_path, ingest_addr, publish_addr);
    targets.ingest = ingest_addr.to_string();
    targets.publish = publish_addr.to_string();

    let mut second = Node::spawn("sigint", root, &cfg_path, &pki);
    // Readiness is what rules out the two failures this restart could have
    // had: a store the first process did not let go of fails `Database::open`
    // and ends the process before any listener comes up, and a listener whose
    // address is taken ends the generation the same way. Either one lands in
    // the wait below rather than in a later assertion, and is reported with
    // the address the child was told to bind and the child's own log.
    second.wait_until_ready(&targets).await;

    let log = second.log();
    assert!(
        !log.contains(REPAIR_MARKER),
        "the restart should not have repaired the store it was handed\n{}",
        second.diagnostics(),
    );
    assert_eq!(
        addr_after(&second, "Ingest listening on"),
        ingest_addr,
        "the restart should have taken the first process's ingest address\n{}",
        second.diagnostics(),
    );
    assert_eq!(
        addr_after(&second, "Publish listening on"),
        publish_addr,
        "the restart should have taken the first process's publish address\n{}",
        second.diagnostics(),
    );

    let client = graphql_client(&pki);
    assert_marker_is_queryable(&client, graphql_addr, &second, marker.as_bytes()).await;

    second.signal(libc::SIGINT);
    let status = second.wait_for_exit().await;
    assert!(
        status.success(),
        "SIGINT should exit the process successfully, got {status}\n{}",
        second.diagnostics(),
    );
    assert_shutdown_sequence(&second, "SIGINT");
    assert_clean_shutdown(&second);
}

fn timestamp_nanos() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock should be after the epoch")
            .as_nanos(),
    )
    .expect("the current time should fit in nanoseconds")
}
