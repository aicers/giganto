mod comm;
mod datetime;
mod graphql;
mod server;
mod settings;
mod storage;
#[cfg(all(test, feature = "bootroot"))]
mod test_bootroot;
mod tls_reload;
mod web;

use std::{
    fs::OpenOptions,
    path::Path,
    process::exit,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use comm::{
    ingest,
    peer::{self},
    publish,
};
use settings::{ConfigVisible, Settings};
use storage::{db_path_and_option, repair_db};
use tokio::{
    runtime, select,
    sync::{
        Notify,
        mpsc::{self},
    },
    task::{self, JoinHandle},
    time::sleep,
};
use tracing::{error, info, metadata::LevelFilter, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, Layer, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

use crate::{
    comm::{
        new_ingest_sensors, new_pcap_sensors, new_peers_data, new_runtime_ingest_sensors,
        new_stream_direct_channels,
    },
    graphql::NodeName,
    server::{SERVER_REBOOT_DELAY, host_fqdn_from_cert},
    settings::Args,
    storage::{migrate_data_dir, validate_compression_metadata},
    tls_reload::{CertPaths, ReloadHandle, TlsMaterial, load_tls_material},
    web::WebController,
};

const ONE_DAY: Duration = Duration::from_hours(24);
const WAIT_SHUTDOWN: u64 = 15;

/// Creates a reqwest client configured for mTLS GraphQL communication.
///
/// # Arguments
///
/// * `cert_pem` - The client certificate in PEM format
/// * `key_pem` - The private key in PEM format
///
/// # Returns
///
/// Returns a configured `reqwest::Client` with client certificate authentication.
///
/// # Errors
///
/// This function will return an error if:
/// * The certificate and key cannot be combined into a PKCS#12 identity
/// * The reqwest client cannot be built with the provided configuration
fn create_graphql_client(cert_pem: &[u8], key_pem: &[u8]) -> Result<reqwest::Client> {
    let identity = reqwest::Identity::from_pem(&[cert_pem, key_pem].concat())
        .context("failed to create client identity from certificate and key")?;

    reqwest::Client::builder()
        .identity(identity)
        .danger_accept_invalid_certs(true)
        .tls_sni(false)
        .build()
        .context("failed to build GraphQL client with mTLS support")
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize rustls crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = Args::parse();
    let mut settings = Settings::load_or_restore(&args.config)?;

    settings.config.validate()?;

    let cfg_path = settings.cfg_path.clone();

    let _guard = init_tracing(args.log_path.as_deref())?;

    if args.repair {
        repair_db(
            &settings.config.visible.data_dir,
            settings.config.visible.max_open_files,
            settings.config.visible.max_mb_of_level_base,
            settings.config.visible.num_of_thread,
            settings.config.visible.max_subcompactions,
            settings.config.compression,
        );
        exit(0);
    }

    let cert_paths = CertPaths {
        cert_path: args.cert.clone(),
        key_path: args.key.clone(),
        ca_certs_paths: args.ca_certs.clone(),
    };
    let loaded = load_tls_material(&cert_paths).context("failed to load initial TLS material")?;
    let cert = loaded.certs.certs.clone();
    let initial_material = Arc::new(TlsMaterial {
        certs: Arc::new(loaded.certs),
        cert_pem: loaded.cert_pem,
        key_pem: loaded.key_pem,
        ca_pem: loaded.ca_pem,
    });
    let (reload_handle, tls_watch) = ReloadHandle::new(cert_paths, Arc::clone(&initial_material));

    let mut is_reboot = false;
    let mut is_power_off = false;
    let mut is_reload_config = false;

    let notify_terminate = Arc::new(Notify::new());

    let notify_tls_reload = Arc::new(Notify::new());

    #[cfg(unix)]
    {
        let mut sigterm_stream =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| anyhow!("failed to install SIGTERM handler: {e}"))?;
        let mut sigint_stream =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|e| anyhow!("failed to install SIGINT handler: {e}"))?;
        let r = notify_terminate.clone();
        task::spawn(async move {
            select! {
                _ = sigterm_stream.recv() => r.notify_one(),
                _ = sigint_stream.recv() => r.notify_one(),
            }
        });

        let mut sighup_stream =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .map_err(|e| anyhow!("failed to install SIGHUP handler: {e}"))?;
        let tls_reload_notify = notify_tls_reload.clone();
        task::spawn(async move {
            loop {
                sighup_stream.recv().await;
                tls_reload_notify.notify_one();
            }
        });
    }

    #[cfg(not(unix))]
    {
        let r = notify_terminate.clone();
        if let Err(ctrlc::Error::System(e)) = ctrlc::set_handler(move || r.notify_one()) {
            return Err(anyhow!("failed to set signal handler: {e}"));
        }
    }

    let tls = tls_reload::get_current_tls_material(&tls_watch);
    let request_client_pool = create_graphql_client(&tls.cert_pem, &tls.key_pem)?;

    loop {
        info!("Data store started");
        let (db_path, db_options) = db_path_and_option(
            &settings.config.visible.data_dir,
            settings.config.visible.max_open_files,
            settings.config.visible.max_mb_of_level_base,
            settings.config.visible.num_of_thread,
            settings.config.visible.max_subcompactions,
            settings.config.compression,
        );

        // Validate compression metadata before migration
        if let Err(e) = validate_compression_metadata(
            &settings.config.visible.data_dir,
            settings.config.compression,
        ) {
            error!("Compression validation failed: {e}");
            bail!("compression validation failed")
        }

        if let Err(e) = migrate_data_dir(&settings.config.visible.data_dir, &db_options) {
            error!("Migration failed: {e}");
            bail!("migration failed")
        }

        let database = storage::Database::open(&db_path, &db_options)?;

        let (reload_tx, mut reload_rx) = mpsc::channel::<ConfigVisible>(1);
        let notify_shutdown = Arc::new(Notify::new());
        let notify_reboot = Arc::new(Notify::new());
        let notify_power_off = Arc::new(Notify::new());
        let mut notify_sensor_change = None;

        let pcap_sensors = new_pcap_sensors();
        let ingest_sensors = new_ingest_sensors(&database);
        let runtime_ingest_sensors = new_runtime_ingest_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let (peers, peer_idents) = new_peers_data(settings.config.peers.clone());
        let ack_transmission_cnt = settings.config.visible.ack_transmission;
        let retain_flag = Arc::new(AtomicBool::new(false));

        let tls = tls_reload::get_current_tls_material(&tls_watch);
        let certs = Arc::clone(&tls.certs);

        let schema = graphql::schema(
            NodeName(host_fqdn_from_cert(&cert)?),
            database.clone(),
            pcap_sensors.clone(),
            ingest_sensors.clone(),
            peers.clone(),
            request_client_pool.clone(),
            settings.config.visible.export_dir.clone(),
            reload_tx,
            notify_reboot.clone(),
            notify_power_off.clone(),
            notify_terminate.clone(),
            settings.clone(),
        );

        let web_addr = settings.config.visible.graphql_srv_addr;
        let mut web_controller: Option<WebController> = match web::serve(
            schema.clone(),
            web_addr,
            tls.cert_pem.clone(),
            tls.key_pem.clone(),
            tls.ca_pem.clone(),
        )
        .await
        {
            Ok(controller) => Some(controller),
            Err(e) => {
                error!("Failed to start GraphQL server: {e}");
                None
            }
        };

        let db = database.clone();
        let notify_shutdown_copy = notify_shutdown.clone();
        let running_flag = retain_flag.clone();
        let retain_task_handle: std::thread::JoinHandle<()> = std::thread::spawn(move || {
            if let Err(e) = runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Cannot create runtime for retain_periodically.")
                .block_on(storage::retain_periodically(
                    ONE_DAY,
                    settings.config.visible.retention,
                    db,
                    notify_shutdown_copy,
                    running_flag,
                ))
            {
                warn!("retain_periodically task terminated unexpectedly: {e}");
            }
        });

        let peer_task_handle: Option<JoinHandle<Result<()>>>;
        if let Some(peer_srv_addr) = settings.config.peer_srv_addr {
            let peer_server = peer::Peer::new(peer_srv_addr, &certs.clone())?;
            let notify_sensor = Arc::new(Notify::new());
            peer_task_handle = Some(task::spawn(peer_server.run(
                ingest_sensors.clone(),
                peers.clone(),
                peer_idents.clone(),
                notify_sensor.clone(),
                notify_shutdown.clone(),
                cfg_path.clone(),
            )));
            notify_sensor_change = Some(notify_sensor);
        } else {
            peer_task_handle = None;
        }

        let publish_server =
            publish::Server::new(settings.config.visible.publish_srv_addr, &certs.clone());
        let publish_task_handle: JoinHandle<()> = task::spawn(publish_server.run(
            database.clone(),
            pcap_sensors.clone(),
            stream_direct_channels.clone(),
            ingest_sensors.clone(),
            peers.clone(),
            peer_idents.clone(),
            tls_watch.clone(),
            notify_shutdown.clone(),
        ));

        let ingest_server =
            ingest::Server::new(settings.config.visible.ingest_srv_addr, &certs.clone());
        let ingest_task_handle: JoinHandle<()> = task::spawn(ingest_server.run(
            database.clone(),
            pcap_sensors,
            ingest_sensors,
            runtime_ingest_sensors,
            stream_direct_channels,
            notify_shutdown.clone(),
            notify_sensor_change,
            ack_transmission_cnt,
            tls_watch.clone(),
        ));

        loop {
            select! {
                Some(new_config) = reload_rx.recv() => {
                    match settings.update_config_file(&new_config) {
                        Ok(()) => {
                            shutdown_web(web_controller.take()).await;
                            notify_shutdown.notify_waiters();
                            wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                            break;
                        }
                        Err(e) => {
                            warn!("Failed to update configuration: {e:#}, run with previous config");
                        }
                    }
                },
                () = notify_terminate.notified() => {
                    info!("Termination signal: daemon exit");
                    shutdown_web(web_controller.take()).await;
                    notify_shutdown.notify_waiters();
                    wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                    sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
                    return Ok(());
                }
                () = notify_reboot.notified() => {
                    info!("Restarting the system...");
                    shutdown_web(web_controller.take()).await;
                    notify_shutdown.notify_waiters();
                    wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                    is_reboot = true;
                    break;
                }
                () = notify_power_off.notified() => {
                    info!("Power off the system...");
                    shutdown_web(web_controller.take()).await;
                    notify_shutdown.notify_waiters();
                    wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                    is_power_off = true;
                    break;
                }
                () = notify_tls_reload.notified() => {
                    reload_https_server(
                        &reload_handle,
                        &tls_watch,
                        &mut web_controller,
                        &schema,
                        web_addr,
                    ).await;
                }
            }
        }

        if is_reboot || is_power_off || is_reload_config {
            loop {
                if !retain_flag.load(Ordering::Relaxed) {
                    break;
                }
                sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
            }
            database.shutdown()?;

            if is_reload_config {
                info!("Before reloading config, wait {SERVER_REBOOT_DELAY} seconds...");
                is_reload_config = false;
            } else {
                info!("Before shut down the system, wait {WAIT_SHUTDOWN} seconds...");
                sleep(tokio::time::Duration::from_secs(WAIT_SHUTDOWN)).await;
                break;
            }
        }
        sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
    }

    if is_reboot || is_power_off {
        if is_reboot {
            roxy::reboot().map_err(|e| anyhow!("cannot restart the system: {e}"))?;
        }
        if is_power_off {
            roxy::power_off().map_err(|e| anyhow!("cannot power off the system: {e}"))?;
        }
    }
    Ok(())
}

/// Initializes the tracing subscriber and returns a `WorkerGuard`.
///
/// Logs will be written to the file specified by `log_path` if provided.
/// If `log_path` is `None`, logs will be printed to stdout.
///
/// # Errors
///
/// Returns an error if the log file cannot be opened in the `log_path` path in the
/// local configuration.
fn init_tracing(log_path: Option<&Path>) -> Result<WorkerGuard> {
    let (layer, guard) = if let Some(log_path) = log_path {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("Failed to open the log file: {}", log_path.display()))?;
        let (file_writer, file_guard) = tracing_appender::non_blocking(file);
        (
            fmt::Layer::default()
                .with_ansi(false)
                .with_target(false)
                .with_writer(file_writer)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
            file_guard,
        )
    } else {
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        (
            fmt::Layer::default()
                .with_ansi(true)
                .with_writer(stdout_writer)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
            stdout_guard,
        )
    };
    tracing_subscriber::Registry::default().with(layer).init();
    Ok(guard)
}

async fn shutdown_web(web_controller: Option<WebController>) {
    if let Some(controller) = web_controller
        && let Err(e) = controller.shutdown().await
    {
        warn!("web task shutdown error: {e}");
    }
}

/// Handles an HTTPS reload trigger: validates the refreshed TLS
/// material, then — if validation produced new material that differs
/// from the current TLS state — shuts down the existing HTTPS GraphQL
/// server and attempts to start a replacement from the validated
/// shared state.
///
/// If validation fails, the previous material is preserved by the
/// common TLS reload plumbing and the existing HTTPS server keeps
/// running. A successful reread that produces identical bytes is
/// treated as a no-op and does not disturb the running server. If the
/// post-stop bind/start fails, the error is logged using the same
/// policy as initial startup failure.
///
/// The new server is built from the already-validated TLS material in
/// the shared watch channel rather than re-reading cert/key/CA files
/// from disk, so the restart does not reopen the TOCTOU window
/// between validation and rebind.
async fn reload_https_server<S>(
    reload_handle: &ReloadHandle,
    tls_watch: &tls_reload::TlsWatch,
    web_controller: &mut Option<WebController>,
    schema: &S,
    web_addr: std::net::SocketAddr,
) where
    S: async_graphql::Executor + Clone,
{
    let previous = tls_reload::get_current_tls_material(tls_watch);
    reload_handle.reload();
    let current = tls_reload::get_current_tls_material(tls_watch);

    if previous.cert_pem == current.cert_pem
        && previous.key_pem == current.key_pem
        && previous.ca_pem == current.ca_pem
    {
        // Either validation failed (common plumbing preserves the
        // previous material) or the refreshed material is byte-for-byte
        // identical to the running state. In both cases the existing
        // HTTPS server should keep serving without interruption.
        info!("HTTPS reload: no TLS material changes detected, keeping current server");
        return;
    }

    info!("HTTPS reload: initiating graceful shutdown of existing GraphQL server");
    if let Some(controller) = web_controller.take()
        && let Err(e) = controller.shutdown().await
    {
        warn!("HTTPS reload: graceful shutdown reported error: {e}");
    }
    info!("HTTPS reload: shutdown complete, starting new GraphQL server");

    match web::serve(
        schema.clone(),
        web_addr,
        current.cert_pem.clone(),
        current.key_pem.clone(),
        current.ca_pem.clone(),
    )
    .await
    {
        Ok(controller) => {
            info!("HTTPS reload: new GraphQL server started");
            *web_controller = Some(controller);
        }
        Err(e) => {
            error!("HTTPS reload: failed to start new GraphQL server: {e:#}");
        }
    }
}

async fn wait_for_task_shutdown(
    ingest_task_handle: JoinHandle<()>,
    publish_task_handle: JoinHandle<()>,
    peer_task_handle: Option<JoinHandle<Result<()>>>,
    retain_task_handle: std::thread::JoinHandle<()>,
) {
    if let Some(handle_peers) = peer_task_handle {
        let _ = tokio::join!(ingest_task_handle, publish_task_handle, handle_peers);
    } else {
        let _ = tokio::join!(ingest_task_handle, publish_task_handle);
    }
    let _ = retain_task_handle.join();
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use regex::Regex;
    use tokio::time::sleep;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    struct CaptureBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for CaptureBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureBuf {
        type Writer = CaptureBuf;

        fn make_writer(&'a self) -> CaptureBuf {
            CaptureBuf(Arc::clone(&self.0))
        }
    }

    #[test]
    fn stdout_fmt_layer_excludes_line_numbers() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = CaptureBuf(Arc::clone(&buf));

        let layer = fmt::Layer::default()
            .with_ansi(false)
            .with_writer(writer)
            .with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            );

        let subscriber = tracing_subscriber::Registry::default().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("test log message");
        });

        let output = String::from_utf8(buf.lock().expect("lock").clone()).expect("utf8 output");
        let re = Regex::new(r"\w+\.rs:\d+").expect("valid regex");
        assert!(
            !re.is_match(&output),
            "stdout should not include file:line numbers, got: {output}"
        );
    }

    #[test]
    fn file_fmt_layer_excludes_line_numbers() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = CaptureBuf(Arc::clone(&buf));

        let layer = fmt::Layer::default()
            .with_ansi(false)
            .with_target(false)
            .with_writer(writer)
            .with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            );

        let subscriber = tracing_subscriber::Registry::default().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("test log message");
        });

        let output = String::from_utf8(buf.lock().expect("lock").clone()).expect("utf8 output");
        let re = Regex::new(r"\w+\.rs:\d+").expect("valid regex");
        assert!(
            !re.is_match(&output),
            "file log should not include file:line numbers, got: {output}"
        );
    }

    #[test]
    fn test_create_graphql_client_with_invalid_cert() {
        let invalid_cert = b"invalid cert";
        let invalid_key = b"invalid key";

        let result = create_graphql_client(invalid_cert, invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_graphql_client_with_valid_cert() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("failed to generate self-signed certificate");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        let result = create_graphql_client(cert_pem.as_bytes(), key_pem.as_bytes());
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wait_for_task_shutdown_joins_all_handles() {
        let ingest_done = Arc::new(AtomicBool::new(false));
        let publish_done = Arc::new(AtomicBool::new(false));
        let peer_done = Arc::new(AtomicBool::new(false));
        let retain_done = Arc::new(AtomicBool::new(false));

        let ingest_task_handle = tokio::spawn({
            let ingest_done = ingest_done.clone();
            async move {
                sleep(Duration::from_millis(25)).await;
                ingest_done.store(true, Ordering::SeqCst);
            }
        });

        let publish_task_handle = tokio::spawn({
            let publish_done = publish_done.clone();
            async move {
                sleep(Duration::from_millis(30)).await;
                publish_done.store(true, Ordering::SeqCst);
            }
        });

        let peer_task_handle = Some(tokio::spawn({
            let peer_done = peer_done.clone();
            async move {
                sleep(Duration::from_millis(35)).await;
                peer_done.store(true, Ordering::SeqCst);
                Ok(())
            }
        }));

        let retain_task_handle = std::thread::spawn({
            let retain_done = retain_done.clone();
            move || {
                std::thread::sleep(Duration::from_millis(20));
                retain_done.store(true, Ordering::SeqCst);
            }
        });

        wait_for_task_shutdown(
            ingest_task_handle,
            publish_task_handle,
            peer_task_handle,
            retain_task_handle,
        )
        .await;

        assert!(ingest_done.load(Ordering::SeqCst));
        assert!(publish_done.load(Ordering::SeqCst));
        assert!(peer_done.load(Ordering::SeqCst));
        assert!(retain_done.load(Ordering::SeqCst));
    }

    mod reload_https_server_tests {
        use std::{
            fs,
            net::{Ipv4Addr, SocketAddr},
            sync::Once,
            time::Duration,
        };

        use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
        use tempfile::tempdir;
        use tokio::time::sleep;

        use super::*;
        use crate::tls_reload::{CertPaths, ReloadHandle, TlsMaterial, load_tls_material};

        static INSTALL_PROVIDER: Once = Once::new();

        fn install_crypto_provider() {
            INSTALL_PROVIDER.call_once(|| {
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            });
        }

        struct Query;

        #[Object]
        impl Query {
            async fn hello(&self) -> &'static str {
                "world"
            }
        }

        fn test_schema() -> Schema<Query, EmptyMutation, EmptySubscription> {
            Schema::build(Query, EmptyMutation, EmptySubscription).finish()
        }

        fn free_addr() -> SocketAddr {
            let listener =
                std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
            listener.local_addr().expect("local addr")
        }

        fn write_pki(dir: &std::path::Path) -> (String, String, String) {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("generate self-signed cert");
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

        fn rewrite_pki(cert_path: &str, key_path: &str, ca_path: &str) {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("generate replacement cert");
            fs::write(cert_path, ck.cert.pem().as_bytes()).expect("write cert");
            fs::write(key_path, ck.signing_key.serialize_pem().as_bytes()).expect("write key");
            fs::write(ca_path, ck.cert.pem().as_bytes()).expect("write ca");
        }

        fn setup(
            dir: &std::path::Path,
        ) -> (ReloadHandle, tls_reload::TlsWatch, String, String, String) {
            install_crypto_provider();
            let (cert_path, key_path, ca_path) = write_pki(dir);
            let paths = CertPaths {
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
                ca_certs_paths: vec![ca_path.clone()],
            };
            let loaded = load_tls_material(&paths).expect("initial load");
            let initial = Arc::new(TlsMaterial {
                certs: Arc::new(loaded.certs),
                cert_pem: loaded.cert_pem,
                key_pem: loaded.key_pem,
                ca_pem: loaded.ca_pem,
            });
            let (handle, watch) = ReloadHandle::new(paths, initial);
            (handle, watch, cert_path, key_path, ca_path)
        }

        /// Builds an mTLS-capable reqwest client that presents the given
        /// client cert/key and trusts only the given CA bytes.
        fn build_mtls_client(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8]) -> reqwest::Client {
            let identity =
                reqwest::Identity::from_pem(&[cert_pem, key_pem].concat()).expect("identity");
            let ca = reqwest::Certificate::from_pem(ca_pem).expect("ca cert");
            reqwest::Client::builder()
                .identity(identity)
                .add_root_certificate(ca)
                .tls_sni(false)
                .danger_accept_invalid_hostnames(true)
                .timeout(Duration::from_secs(5))
                .build()
                .expect("build mTLS client")
        }

        async fn hello_query(
            client: &reqwest::Client,
            addr: SocketAddr,
        ) -> Result<String, reqwest::Error> {
            let url = format!("https://{addr}/graphql");
            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(r#"{"query":"{ hello }"}"#)
                .send()
                .await?;
            resp.error_for_status()?.text().await
        }

        #[tokio::test]
        async fn reload_restarts_server_and_old_trust_is_rejected() {
            // Exercises the full acceptance path: after reload, the
            // restarted HTTPS server must present the new server
            // certificate (verifiable by a client trusting only the new
            // CA) and must reject clients presenting certs signed under
            // the old trust path.
            let dir = tempdir().expect("tempdir");
            let (reload_handle, tls_watch, cert_path, key_path, ca_path) = setup(dir.path());

            let initial = tls_reload::get_current_tls_material(&tls_watch);
            let initial_cert = initial.cert_pem.clone();
            let initial_key = initial.key_pem.clone();
            let initial_ca = initial.ca_pem.clone();

            let addr = free_addr();
            let schema = test_schema();
            let initial_controller = web::serve(
                schema.clone(),
                addr,
                initial.cert_pem.clone(),
                initial.key_pem.clone(),
                initial.ca_pem.clone(),
            )
            .await
            .expect("initial serve");
            let mut web_controller = Some(initial_controller);

            // Sanity check: the initial client can talk to the initial
            // server before any reload.
            sleep(Duration::from_millis(50)).await;
            let old_client = build_mtls_client(&initial_cert, &initial_key, &initial_ca);
            hello_query(&old_client, addr)
                .await
                .expect("pre-reload handshake with old client should succeed");

            // Rotate the on-disk PKI and drive a full reload.
            rewrite_pki(&cert_path, &key_path, &ca_path);
            reload_https_server(
                &reload_handle,
                &tls_watch,
                &mut web_controller,
                &schema,
                addr,
            )
            .await;
            assert!(
                web_controller.is_some(),
                "a new web controller should be installed after reload"
            );

            let updated = tls_reload::get_current_tls_material(&tls_watch);
            assert_ne!(
                initial_cert, updated.cert_pem,
                "reload should have updated the server cert"
            );
            assert_ne!(
                initial_ca, updated.ca_pem,
                "reload should have updated the trusted CA bundle"
            );

            sleep(Duration::from_millis(50)).await;

            // A client that trusts only the NEW CA and presents the NEW
            // client cert must successfully complete mTLS against the
            // restarted server, proving the server presents the new
            // certificate.
            let new_client =
                build_mtls_client(&updated.cert_pem, &updated.key_pem, &updated.ca_pem);
            hello_query(&new_client, addr)
                .await
                .expect("post-reload handshake with new client should succeed");

            // A client presenting the OLD client cert (signed by the
            // old, now-unused CA) must be rejected by the new server
            // because the old trust path is no longer accepted.
            let stale_client = build_mtls_client(&initial_cert, &initial_key, &updated.ca_pem);
            assert!(
                hello_query(&stale_client, addr).await.is_err(),
                "post-reload handshake with old client cert must be rejected"
            );

            shutdown_web(web_controller.take()).await;
        }

        #[tokio::test]
        async fn reload_preserves_controller_on_validation_failure() {
            let dir = tempdir().expect("tempdir");
            let (reload_handle, tls_watch, cert_path, _key_path, _ca_path) = setup(dir.path());

            let addr = free_addr();
            let schema = test_schema();
            let initial = tls_reload::get_current_tls_material(&tls_watch);
            let initial_material_ptr = Arc::as_ptr(&initial);
            let initial_controller = web::serve(
                schema.clone(),
                addr,
                initial.cert_pem.clone(),
                initial.key_pem.clone(),
                initial.ca_pem.clone(),
            )
            .await
            .expect("initial serve");
            let mut web_controller = Some(initial_controller);

            // Corrupt the cert file so validation fails during reload.
            fs::write(&cert_path, b"not a cert").expect("corrupt cert");

            reload_https_server(
                &reload_handle,
                &tls_watch,
                &mut web_controller,
                &schema,
                addr,
            )
            .await;

            let current = tls_reload::get_current_tls_material(&tls_watch);
            assert_eq!(
                initial_material_ptr,
                Arc::as_ptr(&current),
                "pre-stop validation failure must preserve previous TLS material"
            );
            assert!(
                web_controller.is_some(),
                "validation failure must not take the existing web controller"
            );

            shutdown_web(web_controller.take()).await;
        }

        #[tokio::test]
        async fn reload_is_noop_when_material_unchanged() {
            // A successful reread whose bytes are identical to the
            // current TLS state must not restart the HTTPS server. The
            // reload plumbing should swallow the no-op and leave the
            // live controller untouched.
            let dir = tempdir().expect("tempdir");
            let (reload_handle, tls_watch, _cert_path, _key_path, _ca_path) = setup(dir.path());

            let addr = free_addr();
            let schema = test_schema();
            let initial = tls_reload::get_current_tls_material(&tls_watch);
            let initial_material_ptr = Arc::as_ptr(&initial);
            let initial_controller = web::serve(
                schema.clone(),
                addr,
                initial.cert_pem.clone(),
                initial.key_pem.clone(),
                initial.ca_pem.clone(),
            )
            .await
            .expect("initial serve");
            let mut web_controller = Some(initial_controller);

            // Sanity check: the server is serving before reload.
            sleep(Duration::from_millis(50)).await;
            let client = build_mtls_client(&initial.cert_pem, &initial.key_pem, &initial.ca_pem);
            hello_query(&client, addr)
                .await
                .expect("pre-reload handshake should succeed");

            // Drive a reload with no on-disk changes. The watch should
            // keep the same Arc, and the controller must be preserved.
            reload_https_server(
                &reload_handle,
                &tls_watch,
                &mut web_controller,
                &schema,
                addr,
            )
            .await;

            let current = tls_reload::get_current_tls_material(&tls_watch);
            assert_eq!(
                initial_material_ptr,
                Arc::as_ptr(&current),
                "unchanged material must not publish a new TLS state"
            );
            assert!(
                web_controller.is_some(),
                "unchanged material must not restart the HTTPS server"
            );

            // Confirm the same live server is still serving after the
            // no-op reload.
            hello_query(&client, addr)
                .await
                .expect("post-no-op handshake should still succeed");

            shutdown_web(web_controller.take()).await;
        }

        #[tokio::test]
        async fn reload_drops_controller_when_restart_fails() {
            // Exercise the real "stop a live server, then fail to
            // rebind" branch: a live controller is handed to
            // reload_https_server, the reload is driven with
            // successfully validated new material, and the bind step
            // fails because the target address is occupied. The
            // function is expected to still tear down the live
            // controller and surface the failure by leaving the
            // controller slot unset — the same policy as an initial
            // startup failure.
            let dir = tempdir().expect("tempdir");
            let (reload_handle, tls_watch, cert_path, key_path, ca_path) = setup(dir.path());

            let live_addr = free_addr();
            let schema = test_schema();
            let initial = tls_reload::get_current_tls_material(&tls_watch);
            let initial_cert = initial.cert_pem.clone();
            let initial_key = initial.key_pem.clone();
            let initial_ca = initial.ca_pem.clone();

            let live_controller = web::serve(
                schema.clone(),
                live_addr,
                initial.cert_pem.clone(),
                initial.key_pem.clone(),
                initial.ca_pem.clone(),
            )
            .await
            .expect("initial serve");
            let mut web_controller = Some(live_controller);

            // Prove the live server is accepting connections.
            sleep(Duration::from_millis(50)).await;
            let live_client = build_mtls_client(&initial_cert, &initial_key, &initial_ca);
            hello_query(&live_client, live_addr)
                .await
                .expect("pre-reload handshake with live server should succeed");

            // Occupy a separate address so the post-stop bind attempt
            // fails during reload. We point reload at this busy address
            // to force the bind/start step inside reload_https_server
            // to fail after the live controller has already been
            // gracefully shut down.
            let blocker = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("reserve busy port");
            let busy_addr = blocker.local_addr().expect("busy addr");

            // Update on-disk PKI so reload validation succeeds and the
            // only thing that fails is the bind step.
            rewrite_pki(&cert_path, &key_path, &ca_path);

            reload_https_server(
                &reload_handle,
                &tls_watch,
                &mut web_controller,
                &schema,
                busy_addr,
            )
            .await;

            assert!(
                web_controller.is_none(),
                "post-stop bind failure should leave web controller unset"
            );

            // The previously live controller should have been shut down
            // as part of reload. Re-binding on the live address must
            // therefore succeed, confirming the old listener released
            // the port before bind failure was surfaced.
            let probe = tokio::net::TcpListener::bind(live_addr)
                .await
                .expect("live addr should be rebindable after reload shutdown");
            drop(probe);
            drop(blocker);
        }
    }
}
