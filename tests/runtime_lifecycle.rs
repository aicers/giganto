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
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
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
/// Upper bound on the whole ingest exchange: the connection, the handshake,
/// the stream the record is written on, and the acknowledgement that follows.
const INGEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Upper bound on GraphQL answering with the record the first process stored.
const QUERY_TIMEOUT: Duration = Duration::from_secs(60);
/// Upper bound on one GraphQL request, from the handshake through the last
/// byte of the answer. A node that accepts the connection and then stalls
/// would otherwise hang the test with no bound of its own, because the retry
/// loop only gets to look at its deadline between attempts.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
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

/// What every subsystem reports after applying refreshed TLS material.
const TLS_RELOAD_MARKERS: [&str; 5] = [
    "TLS material reloaded successfully",
    "Ingest listener: server config reloaded",
    "Publish listener: server config reloaded",
    "peer TLS state reloaded; generation",
    "HTTPS reload: new GraphQL server started",
];

/// What the common reload path reports when validation preserves the current
/// material.
const TLS_RELOAD_FAILURE_MARKER: &str = "TLS reload failed, keeping previous material";

// ---------------------------------------------------------------------------
// Test PKI
// ---------------------------------------------------------------------------

/// Throwaway PKI for one run, written under the run's own temp directory.
///
/// Three leaves are issued under one CA: materials A and B carry the same
/// node identity, while the sensor carries a distinct client identity.
struct TestPki {
    ca_path: PathBuf,
    ca_pem: String,
    node_cert_path: PathBuf,
    node_key_path: PathBuf,
    node_cert_pem: String,
    node_key_pem: String,
    node_cert_b_path: PathBuf,
    node_key_b_path: PathBuf,
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

/// Writes replacement node material under `ca`. Its names deliberately match
/// material A, while its fresh key pair makes the leaf distinguishable.
fn write_additional_node_material(
    dir: &Path,
    ca: &CertifiedIssuer<'_, KeyPair>,
) -> (PathBuf, PathBuf) {
    let key = KeyPair::generate().expect("generate the replacement node key");
    let cert = leaf_params(NODE_CN, NODE_SAN)
        .signed_by(&key, ca)
        .expect("sign the replacement node certificate");
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    let cert_path = dir.join("node-cert-b.pem");
    let key_path = dir.join("node-key-b.pem");
    fs::write(&cert_path, &cert_pem).expect("write the replacement node certificate");
    fs::write(&key_path, &key_pem).expect("write the replacement node key");
    (cert_path, key_path)
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

    let (node_cert_b_path, node_key_b_path) = write_additional_node_material(dir, &ca);

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
        node_cert_b_path,
        node_key_b_path,
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

/// Enables the peer TLS consumer without configuring any outbound peers.
fn enable_ephemeral_peer(path: &Path) {
    let mut config = fs::read_to_string(path).expect("read the child configuration");
    config.push_str("peer_srv_addr = \"127.0.0.1:0\"\npeers = []\n");
    fs::write(path, config).expect("enable the ephemeral peer listener");
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
            .current_dir(dir)
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
        eprintln!("{label}: spawned PID {}", child.id());

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

    /// Waits for every marker to be appended after `start`, without imposing
    /// an ordering on independent subsystem reloads.
    async fn wait_for_log_markers(
        &mut self,
        targets: &BindTargets,
        start: usize,
        markers: &[&str],
        description: &str,
    ) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let log = self.log();
            let appended = log.get(start..).unwrap_or(&log);
            if markers.iter().all(|marker| appended.contains(marker)) {
                return;
            }
            if let Some(reason) = bind_failure(&log, targets) {
                panic!("{}: {reason}\n{}", self.label, self.diagnostics());
            }
            if let Some(status) = self.reap_if_exited() {
                panic!(
                    "{}: the child exited with {status} while waiting for {description}\n{}",
                    self.label,
                    self.diagnostics(),
                );
            }
            assert!(
                Instant::now() < deadline,
                "{}: did not observe {description} within {READY_TIMEOUT:?}; missing: {:?}\n{}",
                self.label,
                markers
                    .iter()
                    .filter(|marker| !appended.contains(**marker))
                    .collect::<Vec<_>>(),
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
    if log.contains("HTTPS reload: failed to start new GraphQL server") {
        return Some(format!(
            "the reloaded GraphQL listener could not bind {}",
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

/// Opens one bounded mTLS connection and returns the presented server leaf's
/// DER. Material A remains a valid client identity after the server
/// rotates because both leaves are signed by the same test CA.
async fn server_leaf_certificate(
    node: &Node,
    addr: SocketAddr,
    pki: &TestPki,
) -> CertificateDer<'static> {
    let handshake = async {
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs_from_pem(&pki.ca_pem) {
            roots
                .add(cert)
                .map_err(|e| format!("the test CA could not be trusted: {e}"))?;
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                certs_from_pem(&pki.node_cert_pem),
                key_from_pem(&pki.node_key_pem),
            )
            .map_err(|e| format!("the mTLS client configuration could not be built: {e}"))?;
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("the GraphQL TCP connection to {addr} failed: {e}"))?;
        let server_name = ServerName::try_from(NODE_SAN)
            .map_err(|e| format!("the node server name is invalid: {e}"))?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("the GraphQL TLS handshake with {addr} failed: {e}"))?;
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or_else(|| "the GraphQL TLS peer presented no leaf certificate".to_string())?;
        Ok::<_, String>(leaf.clone())
    };

    match tokio::time::timeout(REQUEST_TIMEOUT, handshake).await {
        Ok(Ok(certificate)) => certificate,
        Ok(Err(reason)) => panic!("{}: {reason}\n{}", node.label, node.diagnostics()),
        Err(error) => panic!(
            "{}: the GraphQL TLS handshake did not finish within {REQUEST_TIMEOUT:?}: {error}\n{}",
            node.label,
            node.diagnostics(),
        ),
    }
}

/// Replaces one credential file without exposing partially-written contents.
fn atomic_replace(path: &Path, contents: &[u8]) {
    let file_name = path.file_name().expect("credential path has a file name");
    let staged = path.with_file_name(format!(".{}.replacement", file_name.to_string_lossy()));
    fs::write(&staged, contents).expect("write the staged credential");
    fs::rename(&staged, path).expect("atomically replace the credential");
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
///
/// One bound covers the whole exchange rather than one bound per step.
/// Opening the stream and writing to it can park as readily as connecting and
/// waiting for the acknowledgement can — a peer that stops granting stream
/// credit never fails, it simply never returns — and a hang anywhere in here
/// is a hang inside the test body, where the `Node` guard that reaps children
/// never runs. Whatever ends the exchange, the failure carries the child's log
/// with it: once the panic unwinds, the temp directory holding that log is
/// gone.
async fn ingest_marker(
    node: &Node,
    addr: SocketAddr,
    pki: &TestPki,
    marker: &[u8],
    timestamp: i64,
) -> IngestClient {
    let exchange = ingest_exchange(addr, pki, marker, timestamp);
    let Ok(outcome) = tokio::time::timeout(INGEST_TIMEOUT, exchange).await else {
        panic!(
            "{}: the marker exchange with {addr} did not finish within {INGEST_TIMEOUT:?}\n{}",
            node.label,
            node.diagnostics(),
        );
    };
    outcome.unwrap_or_else(|reason| panic!("{}: {reason}\n{}", node.label, node.diagnostics()))
}

/// Connects, handshakes, sends one record, and waits for its acknowledgement.
///
/// Every failure comes back as a string because the caller is what holds the
/// child, and so is what can say which node did not answer and what it logged.
async fn ingest_exchange(
    addr: SocketAddr,
    pki: &TestPki,
    marker: &[u8],
    timestamp: i64,
) -> Result<IngestClient, String> {
    // Bound on IPv4 because the listener is: quinn will not send from a v6
    // socket to a v4 peer.
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|e| format!("the sensor endpoint could not be created: {e}"))?;
    endpoint.set_default_client_config(sensor_client_config(pki));

    let connection = endpoint
        .connect(addr, NODE_SAN)
        .map_err(|e| format!("the connection to {addr} could not be started: {e}"))?
        .await
        .map_err(|e| format!("the sensor could not reach the ingest listener at {addr}: {e}"))?;
    client_handshake(&connection, env!("CARGO_PKG_VERSION"))
        .await
        .map_err(|e| format!("the version handshake failed: {e}"))?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("the sensor stream could not be opened: {e}"))?;
    send_record_header(&mut send, RawEventKind::Log)
        .await
        .map_err(|e| format!("the record header could not be sent: {e}"))?;
    let event = Log {
        kind: LOG_KIND.to_string(),
        log: marker.to_vec(),
    };
    let body = bincode::serialize(&event).expect("serialize the log body");
    let batch = bincode::serialize(&vec![(timestamp, body)]).expect("serialize the log batch");
    send_raw(&mut send, &batch)
        .await
        .map_err(|e| format!("the marker could not be sent: {e}"))?;

    let acked = receive_ack_timestamp(&mut recv)
        .await
        .map_err(|e| format!("the acknowledgement could not be read: {e}"))?;
    if acked != timestamp {
        return Err(format!(
            "the acknowledgement named {acked} rather than the marker's {timestamp}"
        ));
    }

    Ok(IngestClient {
        _endpoint: endpoint,
        _connection: connection,
    })
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

/// Posts one GraphQL query under `budget`, reporting either the answer or why
/// there was none.
///
/// The bound covers the whole exchange, body read included, so a peer that
/// completes the handshake and then says nothing is a failed attempt rather
/// than a hang. The failure modes are folded into one string because the
/// caller only retries and, on the way out, reports what it last saw.
async fn post_query(
    client: &reqwest::Client,
    url: &str,
    query: &str,
    budget: Duration,
) -> Result<String, String> {
    let exchange = async {
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
    };
    tokio::time::timeout(budget, exchange)
        .await
        .map_err(|_| format!("the request did not answer within {budget:?}"))?
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
        let budget = REQUEST_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        last = match post_query(client, &url, &query, budget).await {
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
    let body = post_query(client, &url, &marker_query(control), REQUEST_TIMEOUT)
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

/// SIGHUP rotates every live TLS endpoint without replacing the process, and
/// a rejected follow-up rotation leaves the last validated leaf in service.
#[tokio::test]
#[serial_test::serial(runtime_lifecycle_process)]
async fn process_sighup_tls_reload() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let dir = tempfile::tempdir().expect("create the run directory");
    let root = dir.path();
    let data_dir = root.join("data");
    let export_dir = root.join("export");
    fs::create_dir_all(&data_dir).expect("create the data directory");
    fs::create_dir_all(&export_dir).expect("create the export directory");
    let pki = write_test_pki(root);
    let cfg_path = root.join("config.toml");
    let graphql_addr = free_loopback_addr();
    write_config(&cfg_path, &data_dir, &export_dir, graphql_addr);
    enable_ephemeral_peer(&cfg_path);
    let mut targets = BindTargets {
        ingest: EPHEMERAL.to_string(),
        publish: EPHEMERAL.to_string(),
        graphql: graphql_addr.to_string(),
    };

    let mut node = Node::spawn("sighup", root, &cfg_path, &pki);
    node.wait_until_ready(&targets).await;
    node.wait_for_log_markers(
        &targets,
        0,
        &["INFO listening on"],
        "peer listener readiness",
    )
    .await;
    let ingest_addr = addr_after(&node, "Ingest listening on");
    let publish_addr = addr_after(&node, "Publish listening on");
    targets.ingest = ingest_addr.to_string();
    targets.publish = publish_addr.to_string();

    let cert_a = certs_from_pem(&pki.node_cert_pem)
        .into_iter()
        .next()
        .expect("material A has a leaf certificate");
    let cert_b_pem = read_text(&pki.node_cert_b_path);
    let cert_b = certs_from_pem(&cert_b_pem)
        .into_iter()
        .next()
        .expect("material B has a leaf certificate");
    assert_ne!(
        cert_a,
        cert_b,
        "fresh node key pairs should produce distinguishable leaves\n{}",
        node.diagnostics(),
    );
    assert_eq!(
        server_leaf_certificate(&node, graphql_addr, &pki).await,
        cert_a,
        "the child should initially serve material A\n{}",
        node.diagnostics(),
    );

    let pid = node.child.id();
    let reload_start = node.log().len();
    atomic_replace(
        &pki.node_cert_path,
        &fs::read(&pki.node_cert_b_path).expect("read material B's certificate"),
    );
    atomic_replace(
        &pki.node_key_path,
        &fs::read(&pki.node_key_b_path).expect("read material B's key"),
    );
    node.signal(libc::SIGHUP);
    node.wait_for_log_markers(
        &targets,
        reload_start,
        &TLS_RELOAD_MARKERS,
        "all successful TLS reload markers",
    )
    .await;

    assert_eq!(
        node.child.id(),
        pid,
        "SIGHUP should not replace the child process\n{}",
        node.diagnostics(),
    );
    assert!(
        node.reap_if_exited().is_none(),
        "the child exited after its successful TLS reload\n{}",
        node.diagnostics(),
    );
    let reload_log = node.log();
    for marker in ["shutting the database down", "final action"] {
        assert!(
            !reload_log.contains(marker),
            "SIGHUP should not end the generation ({marker:?})\n{}",
            node.diagnostics(),
        );
    }
    assert_eq!(
        reload_log.matches("Data store started").count(),
        1,
        "SIGHUP should not start a second generation\n{}",
        node.diagnostics(),
    );
    assert_eq!(
        server_leaf_certificate(&node, graphql_addr, &pki).await,
        cert_b,
        "the reloaded GraphQL listener should serve material B\n{}",
        node.diagnostics(),
    );

    let failed_reload_start = node.log().len();
    atomic_replace(
        &pki.node_cert_path,
        &fs::read(&pki.node_cert_b_path).expect("reread material B's certificate"),
    );
    atomic_replace(&pki.node_key_path, pki.node_key_pem.as_bytes());
    node.signal(libc::SIGHUP);
    node.wait_for_log_markers(
        &targets,
        failed_reload_start,
        &[TLS_RELOAD_FAILURE_MARKER],
        "the rejected TLS reload marker",
    )
    .await;
    assert_eq!(
        node.child.id(),
        pid,
        "a rejected SIGHUP reload should not replace the child process\n{}",
        node.diagnostics(),
    );
    assert_eq!(
        server_leaf_certificate(&node, graphql_addr, &pki).await,
        cert_b,
        "a rejected key/certificate pair should leave material B in service\n{}",
        node.diagnostics(),
    );

    node.signal(libc::SIGTERM);
    let status = node.wait_for_exit().await;
    assert!(
        status.success(),
        "SIGTERM should exit the process successfully after reloads, got {status}\n{}",
        node.diagnostics(),
    );
    assert_shutdown_sequence(&node, "SIGTERM");
    assert_clean_shutdown(&node);
}

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

        let sensor = ingest_marker(&first, ingest_addr, &pki, marker.as_bytes(), timestamp).await;

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

#[tokio::test]
#[serial_test::serial(runtime_lifecycle_process)]
async fn process_defaults_directories_and_round_trips_config() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().expect("create the working directory");
    let root = dir.path();
    let pki = write_test_pki(root);
    // Keep the config elsewhere to prove defaults resolve against the working
    // directory rather than the configuration file's parent.
    let config_dir = root.join("config");
    fs::create_dir(&config_dir).expect("create the config directory");
    let cfg_path = config_dir.join("giganto.toml");
    let graphql_addr = free_loopback_addr();
    fs::write(
        &cfg_path,
        format!(
            "ingest_srv_addr = \"{EPHEMERAL}\"\npublish_srv_addr = \"{EPHEMERAL}\"\n\
             graphql_srv_addr = \"{graphql_addr}\"\n"
        ),
    )
    .expect("write the minimal configuration");
    let targets = BindTargets {
        ingest: EPHEMERAL.to_string(),
        publish: EPHEMERAL.to_string(),
        graphql: graphql_addr.to_string(),
    };
    assert!(!root.join("data").exists());
    let mut node = Node::spawn("default-directories", root, &cfg_path, &pki);
    node.wait_until_ready(&targets).await;

    assert!(root.join("data/db/CURRENT").is_file());
    assert_eq!(
        fs::read_to_string(root.join("data/COMPRESSION")).expect("read compression metadata"),
        "disabled"
    );
    assert!(!root.join("export").exists());
    assert!(!config_dir.join("data").exists());

    let client = graphql_client(&pki);
    let url = format!("https://{graphql_addr}/graphql");
    let query = "{ config { ingest_srv_addr: ingestSrvAddr publish_srv_addr: publishSrvAddr \
                 graphql_srv_addr: graphqlSrvAddr data_dir: dataDir export_dir: exportDir \
                 retention ack_transmission: ackTransmission max_open_files: maxOpenFiles \
                 max_mb_of_level_base: maxMbOfLevelBase num_of_thread: numOfThread \
                 max_subcompactions: maxSubcompactions } }";
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let body = loop {
        match post_query(&client, &url, query, REQUEST_TIMEOUT).await {
            Ok(body) => break body,
            Err(error) => assert!(
                Instant::now() < deadline,
                "query the defaulted configuration: {error}\n{}",
                node.diagnostics()
            ),
        }
        sleep(POLL).await;
    };
    let response: serde_json::Value = serde_json::from_str(&body).expect("parse the response");
    assert!(response.get("errors").is_none(), "{body}");
    let mut reported = response["data"]["config"].clone();
    assert_eq!(reported["data_dir"], "data");
    assert_eq!(reported["export_dir"], "export");
    // GraphQL's StringNumber fields serialize as strings; TOML expects integers.
    for key in ["max_mb_of_level_base", "max_subcompactions"] {
        reported[key] = reported[key]
            .as_str()
            .expect("string number")
            .parse::<u64>()
            .expect("unsigned integer")
            .into();
    }
    let old = toml::to_string(&reported).expect("serialize the reported configuration");
    // The strings must differ to reach validation. The parsed configurations
    // are unchanged, which updateConfig already rejects after validation.
    let new = format!("{old}\n");
    let mutation =
        format!("mutation {{ updateConfig(old: {old:?}, new: {new:?}) {{ dataDir exportDir }} }}");
    let body = post_query(&client, &url, &mutation, REQUEST_TIMEOUT)
        .await
        .expect("round trip the defaulted configuration");
    let response: serde_json::Value = serde_json::from_str(&body).expect("parse the response");
    assert_eq!(response["errors"][0]["message"], "No changes", "{body}");

    node.signal(libc::SIGTERM);
    assert!(
        node.wait_for_exit().await.success(),
        "{}",
        node.diagnostics()
    );
    assert_clean_shutdown(&node);

    // A restored minimal config must retain omission information and create
    // the default directory even when the primary config could not be read.
    let backup_path = cfg_path.with_extension("toml.bak");
    fs::rename(&cfg_path, &backup_path).expect("back up the minimal configuration");
    fs::write(&cfg_path, "invalid TOML").expect("corrupt the configuration");
    fs::rename(root.join("data"), root.join("previous-data"))
        .expect("move the previous database aside");
    assert!(!root.join("data").exists());
    let mut restored = Node::spawn("restored-default-directories", root, &cfg_path, &pki);
    restored.wait_until_ready(&targets).await;
    assert_eq!(
        fs::read_to_string(&cfg_path).expect("read the restored configuration"),
        fs::read_to_string(&backup_path).expect("read the backup")
    );
    assert!(root.join("data/db/CURRENT").is_file());
    assert!(!root.join("export").exists());

    // A real update must keep the reported relative paths valid through
    // persistence and the next generation, not only a no-op validation.
    let deadline = Instant::now() + QUERY_TIMEOUT;
    loop {
        let budget = REQUEST_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        if post_query(&client, &url, query, budget).await.is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the restored GraphQL server did not become ready\n{}",
            restored.diagnostics()
        );
        sleep(POLL).await;
    }
    reported["retention"] = "101d".into();
    let new = toml::to_string(&reported).expect("serialize the updated configuration");
    let mutation = format!(
        "mutation {{ updateConfig(old: {old:?}, new: {new:?}) {{ dataDir exportDir retention }} }}"
    );
    let body = post_query(&client, &url, &mutation, REQUEST_TIMEOUT)
        .await
        .expect("update the defaulted configuration");
    let response: serde_json::Value = serde_json::from_str(&body).expect("parse the response");
    assert!(response.get("errors").is_none(), "{body}");
    assert_eq!(response["data"]["updateConfig"]["dataDir"], "data");
    assert_eq!(response["data"]["updateConfig"]["exportDir"], "export");

    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let budget = REQUEST_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        if let Ok(body) = post_query(&client, &url, query, budget).await {
            let response: serde_json::Value =
                serde_json::from_str(&body).expect("parse the response after restart");
            if response["data"]["config"]["retention"] == "101d" {
                assert!(response.get("errors").is_none(), "{body}");
                assert_eq!(response["data"]["config"]["data_dir"], "data");
                assert_eq!(response["data"]["config"]["export_dir"], "export");
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the updated configuration was not served after restart\n{}",
            restored.diagnostics()
        );
        sleep(POLL).await;
    }
    let persisted: toml::Value =
        toml::from_str(&fs::read_to_string(&cfg_path).unwrap()).expect("read persisted settings");
    assert_eq!(persisted["data_dir"].as_str(), Some("data"));
    assert_eq!(persisted["export_dir"].as_str(), Some("export"));
    assert!(!root.join("export").exists());
    restored.signal(libc::SIGTERM);
    assert!(
        restored.wait_for_exit().await.success(),
        "{}",
        restored.diagnostics()
    );
    assert_clean_shutdown(&restored);

    // A new process must reload the persisted defaults, now explicit paths,
    // rather than relying on settings retained by the previous generation.
    let mut restarted = Node::spawn("updated-default-directories", root, &cfg_path, &pki);
    restarted.wait_until_ready(&targets).await;
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let body = loop {
        let budget = REQUEST_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        match post_query(&client, &url, query, budget).await {
            Ok(body) => break body,
            Err(error) => assert!(
                Instant::now() < deadline,
                "query the persisted configuration in a new process: {error}\n{}",
                restarted.diagnostics()
            ),
        }
        sleep(POLL).await;
    };
    let response: serde_json::Value = serde_json::from_str(&body).expect("parse persisted config");
    assert!(response.get("errors").is_none(), "{body}");
    assert_eq!(response["data"]["config"]["retention"], "101d");
    assert_eq!(response["data"]["config"]["data_dir"], "data");
    assert_eq!(response["data"]["config"]["export_dir"], "export");
    assert!(root.join("data/db/CURRENT").is_file());
    assert!(!root.join("export").exists());
    restarted.signal(libc::SIGTERM);
    assert!(
        restarted.wait_for_exit().await.success(),
        "{}",
        restarted.diagnostics()
    );
    assert_clean_shutdown(&restarted);
}

#[tokio::test]
#[serial_test::serial(runtime_lifecycle_process)]
async fn process_reopens_existing_default_directory_with_compression() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().expect("create the working directory");
    let root = dir.path();
    let pki = write_test_pki(root);
    let cfg_path = root.join("config.toml");
    let graphql_addr = free_loopback_addr();
    fs::write(
        &cfg_path,
        format!(
            "ingest_srv_addr = \"{EPHEMERAL}\"\npublish_srv_addr = \"{EPHEMERAL}\"\n\
             graphql_srv_addr = \"{graphql_addr}\"\nack_transmission = 1\ncompression = true\n"
        ),
    )
    .expect("write the configuration without directory settings");
    let targets = BindTargets {
        ingest: EPHEMERAL.to_string(),
        publish: EPHEMERAL.to_string(),
        graphql: graphql_addr.to_string(),
    };
    let timestamp = timestamp_nanos();
    let marker = format!("default-directory-restart-marker-{timestamp}");
    let metadata_path = root.join("data/COMPRESSION");

    let metadata_modified = {
        let mut first = Node::spawn("compressed-default-directories", root, &cfg_path, &pki);
        first.wait_until_ready(&targets).await;
        let ingest_addr = addr_after(&first, "Ingest listening on");
        let sensor = ingest_marker(&first, ingest_addr, &pki, marker.as_bytes(), timestamp).await;
        assert_eq!(fs::read_to_string(&metadata_path).unwrap(), "enabled");
        let metadata_modified = fs::metadata(&metadata_path).unwrap().modified().unwrap();

        // Persist the reported defaults through a real update after storing a
        // record, then verify both the next generation and a fresh process.
        let client = graphql_client(&pki);
        let url = format!("https://{graphql_addr}/graphql");
        let query = "{ config { ingest_srv_addr: ingestSrvAddr publish_srv_addr: publishSrvAddr \
                     graphql_srv_addr: graphqlSrvAddr data_dir: dataDir export_dir: exportDir \
                     retention ack_transmission: ackTransmission max_open_files: maxOpenFiles \
                     max_mb_of_level_base: maxMbOfLevelBase num_of_thread: numOfThread \
                     max_subcompactions: maxSubcompactions } }";
        let body = post_query(&client, &url, query, REQUEST_TIMEOUT)
            .await
            .expect("query configuration before updating retention");
        let response: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(response.get("errors").is_none(), "{body}");
        let mut reported = response["data"]["config"].clone();
        for key in ["max_mb_of_level_base", "max_subcompactions"] {
            reported[key] = reported[key]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                .into();
        }
        let old = toml::to_string(&reported).unwrap();
        reported["retention"] = "101d".into();
        let new = toml::to_string(&reported).unwrap();
        let mutation = format!(
            "mutation {{ updateConfig(old: {old:?}, new: {new:?}) {{ retention dataDir exportDir }} }}"
        );
        let log_start = first.log().len();
        let body = post_query(&client, &url, &mutation, REQUEST_TIMEOUT)
            .await
            .expect("update retention with an existing record");
        let response: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(response.get("errors").is_none(), "{body}");
        first
            .wait_for_log_markers(
                &targets,
                log_start,
                &READY_MARKERS,
                "the generation after the configuration update",
            )
            .await;
        assert_marker_is_queryable(&client, graphql_addr, &first, marker.as_bytes()).await;
        assert_eq!(fs::read_to_string(&metadata_path).unwrap(), "enabled");
        assert_eq!(
            fs::metadata(&metadata_path).unwrap().modified().unwrap(),
            metadata_modified,
            "updating retention must preserve existing compression metadata"
        );
        first.signal(libc::SIGTERM);
        assert!(
            first.wait_for_exit().await.success(),
            "{}",
            first.diagnostics()
        );
        assert_clean_shutdown(&first);
        drop(sensor);
        metadata_modified
    };

    assert_eq!(fs::read_to_string(&metadata_path).unwrap(), "enabled");
    let mut second = Node::spawn("reopened-default-directories", root, &cfg_path, &pki);
    second.wait_until_ready(&targets).await;
    assert_marker_is_queryable(
        &graphql_client(&pki),
        graphql_addr,
        &second,
        marker.as_bytes(),
    )
    .await;
    assert_eq!(fs::read_to_string(&metadata_path).unwrap(), "enabled");
    assert_eq!(
        fs::metadata(&metadata_path).unwrap().modified().unwrap(),
        metadata_modified,
        "restarting must preserve existing compression metadata"
    );
    assert!(!root.join("export").exists());
    assert!(!second.log().contains(REPAIR_MARKER));
    let export_query = format!(
        "{{ export(exportType: \"json\", filter: {{ protocol: \"log\", \
         sensorId: {:?}, kind: \"{LOG_KIND}\" }}) }}",
        expected_sensor()
    );
    let body = post_query(
        &graphql_client(&pki),
        &format!("https://{graphql_addr}/graphql"),
        &export_query,
        REQUEST_TIMEOUT,
    )
    .await
    .expect("export to the default directory");
    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(response.get("errors").is_none(), "{body}");
    let (export_path, _) = response["data"]["export"]
        .as_str()
        .expect("export download path")
        .rsplit_once('@')
        .expect("export node name");
    assert!(Path::new(export_path).starts_with("export"));
    assert!(root.join("export").is_dir());
    second.signal(libc::SIGTERM);
    assert!(
        second.wait_for_exit().await.success(),
        "{}",
        second.diagnostics()
    );
    assert_clean_shutdown(&second);
    // Shutdown drains the accepted export before closing the database.
    let exported: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join(export_path)).unwrap()).unwrap();
    assert_eq!(exported["log"], marker);
}

#[tokio::test]
#[serial_test::serial(runtime_lifecycle_process)]
async fn process_preserves_explicit_relative_directories() {
    assert_explicit_directories_preserved(false).await;
}

#[tokio::test]
#[serial_test::serial(runtime_lifecycle_process)]
async fn process_preserves_explicit_absolute_directories() {
    assert_explicit_directories_preserved(true).await;
}

async fn assert_explicit_directories_preserved(absolute_paths: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().expect("create the working directory");
    let root = dir.path();
    let pki = write_test_pki(root);
    let [configured_data_dir, configured_export_dir] =
        ["custom/store", "custom/exports"].map(|path| {
            if absolute_paths {
                root.join(path)
            } else {
                PathBuf::from(path)
            }
        });
    let data_dir = root.join(&configured_data_dir);
    let export_dir = root.join(&configured_export_dir);
    fs::create_dir_all(&data_dir).expect("create the explicit data directory");
    let config_dir = root.join("config");
    fs::create_dir(&config_dir).expect("create the config directory");
    let cfg_path = config_dir.join("giganto.toml");
    let graphql_addr = free_loopback_addr();
    write_config(
        &cfg_path,
        &configured_data_dir,
        &configured_export_dir,
        graphql_addr,
    );
    let targets = BindTargets {
        ingest: EPHEMERAL.to_string(),
        publish: EPHEMERAL.to_string(),
        graphql: graphql_addr.to_string(),
    };
    let mut node = Node::spawn("explicit-directories", root, &cfg_path, &pki);
    node.wait_until_ready(&targets).await;

    assert!(data_dir.join("db/CURRENT").is_file());
    assert!(!root.join("custom/exports").exists());
    assert!(!config_dir.join("custom").exists());

    let client = graphql_client(&pki);
    let url = format!("https://{graphql_addr}/graphql");
    assert_reported_explicit_directories(
        &node,
        &client,
        &url,
        &configured_data_dir,
        &configured_export_dir,
    )
    .await;

    let timestamp = timestamp_nanos();
    let marker = format!("explicit-directory-restart-marker-{timestamp}");
    let sensor = ingest_marker(
        &node,
        addr_after(&node, "Ingest listening on"),
        &pki,
        marker.as_bytes(),
        timestamp,
    )
    .await;

    node.signal(libc::SIGTERM);
    assert!(
        node.wait_for_exit().await.success(),
        "{}",
        node.diagnostics()
    );
    assert_clean_shutdown(&node);
    drop(sensor);

    let metadata_path = data_dir.join("COMPRESSION");
    let metadata = fs::read(&metadata_path).expect("read compression metadata");
    let metadata_modified = fs::metadata(&metadata_path)
        .expect("stat compression metadata")
        .modified()
        .expect("compression metadata modification time");
    let mut restarted = Node::spawn("reopened-explicit-directories", root, &cfg_path, &pki);
    restarted.wait_until_ready(&targets).await;
    assert_marker_is_queryable(&client, graphql_addr, &restarted, marker.as_bytes()).await;
    assert_eq!(
        fs::read(&metadata_path).expect("read compression metadata after restart"),
        metadata
    );
    assert_eq!(
        fs::metadata(&metadata_path)
            .expect("stat compression metadata")
            .modified()
            .expect("compression metadata modification time"),
        metadata_modified,
        "restarting must preserve explicit-directory compression metadata"
    );
    assert!(!restarted.log().contains(REPAIR_MARKER));
    assert!(!export_dir.exists());

    assert_explicit_export_after_restart(
        &mut restarted,
        &client,
        &url,
        root,
        &configured_export_dir,
        &marker,
    )
    .await;
    assert!(!root.join("data").exists());
    assert!(!root.join("export").exists());
}

async fn assert_reported_explicit_directories(
    node: &Node,
    client: &reqwest::Client,
    url: &str,
    configured_data_dir: &Path,
    configured_export_dir: &Path,
) {
    let query = "{ config { dataDir exportDir } }";
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let body = loop {
        let budget = REQUEST_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        match post_query(client, url, query, budget).await {
            Ok(body) => break body,
            Err(error) => assert!(
                Instant::now() < deadline,
                "query the explicit configuration: {error}\n{}",
                node.diagnostics()
            ),
        }
        sleep(POLL).await;
    };
    let response: serde_json::Value = serde_json::from_str(&body).expect("parse the response");
    assert!(response.get("errors").is_none(), "{body}");
    assert_eq!(
        response["data"]["config"]["dataDir"],
        configured_data_dir.to_str().expect("UTF-8 data path")
    );
    assert_eq!(
        response["data"]["config"]["exportDir"],
        configured_export_dir.to_str().expect("UTF-8 export path")
    );
}

async fn assert_explicit_export_after_restart(
    node: &mut Node,
    client: &reqwest::Client,
    url: &str,
    root: &Path,
    configured_export_dir: &Path,
    marker: &str,
) {
    let export_query = format!(
        "{{ export(exportType: \"json\", filter: {{ protocol: \"log\", \
         sensorId: {:?}, kind: \"{LOG_KIND}\" }}) }}",
        expected_sensor()
    );
    let body = post_query(client, url, &export_query, REQUEST_TIMEOUT)
        .await
        .expect("export to the explicit directory after restart");
    let response: serde_json::Value =
        serde_json::from_str(&body).expect("parse the export response");
    assert!(response.get("errors").is_none(), "{body}");
    let (export_path, _) = response["data"]["export"]
        .as_str()
        .expect("export download path")
        .rsplit_once('@')
        .expect("export node name");
    assert!(Path::new(export_path).starts_with(configured_export_dir));
    assert!(root.join(configured_export_dir).is_dir());

    node.signal(libc::SIGTERM);
    assert!(
        node.wait_for_exit().await.success(),
        "{}",
        node.diagnostics()
    );
    assert_clean_shutdown(node);
    let exported = fs::read_to_string(root.join(export_path)).expect("read the completed export");
    let exported: serde_json::Value =
        serde_json::from_str(&exported).expect("parse the exported log");
    assert_eq!(exported["log"], marker);
}

#[tokio::test]
#[serial_test::serial(runtime_lifecycle_process)]
async fn process_rejects_explicit_missing_directories() {
    for restore_backup in [false, true] {
        for path in ["data", "nested/data", "absolute"] {
            let dir = tempfile::tempdir().expect("create the working directory");
            let root = dir.path();
            let pki = write_test_pki(root);
            let cfg_path = root.join("config.toml");
            let data_dir = if path == "absolute" {
                root.join("missing-absolute")
            } else {
                PathBuf::from(path)
            };
            let config = format!("data_dir = {data_dir:?}\n");
            if restore_backup {
                fs::write(&cfg_path, "invalid TOML").expect("write the invalid configuration");
                fs::write(cfg_path.with_extension("toml.bak"), &config)
                    .expect("write the backup configuration");
            } else {
                fs::write(&cfg_path, &config).expect("write the configuration");
            }
            let mut node = Node::spawn("explicit-missing-data", root, &cfg_path, &pki);
            assert!(!node.wait_for_exit().await.success());
            assert!(
                node.console().contains("data directory is invalid"),
                "{}",
                node.diagnostics()
            );
            assert_eq!(fs::read_to_string(&cfg_path).unwrap(), config);
            assert!(!root.join(&data_dir).exists());
            assert!(!root.join("data").exists());
            assert!(!root.join("nested").exists());
        }
    }
}

#[tokio::test]
#[serial_test::serial(runtime_lifecycle_process)]
async fn process_reports_default_directory_creation_failure_without_restoring_backup() {
    let dir = tempfile::tempdir().expect("create the working directory");
    let root = dir.path();
    let pki = write_test_pki(root);
    let cfg_path = root.join("config.toml");
    let config = "ingest_srv_addr = \"127.0.0.1:0\"\n";
    fs::write(&cfg_path, config).expect("write the configuration");
    fs::write(cfg_path.with_extension("toml.bak"), "data_dir = \".\"\n")
        .expect("write a valid backup");
    fs::write(root.join("data"), "existing file").expect("block directory creation");

    let mut node = Node::spawn("default-data-creation-failure", root, &cfg_path, &pki);
    assert!(!node.wait_for_exit().await.success());
    assert!(
        node.console()
            .contains("failed to create default data directory: data"),
        "{}",
        node.diagnostics()
    );
    assert_eq!(fs::read_to_string(&cfg_path).unwrap(), config);
    assert_eq!(
        fs::read_to_string(root.join("data")).unwrap(),
        "existing file"
    );
    assert!(!root.join("export").exists());
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
