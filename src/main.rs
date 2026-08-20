pub mod cancellation;
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
use rustls::pki_types::CertificateDer;
use settings::{ConfigVisible, Settings};
use storage::{db_path_and_option, repair_db};
use tokio::{
    select,
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
    cancellation::{DrainOutcome, LockPoisonedError, PendingTaskSnapshot, TaskTracker},
    comm::{
        new_ingest_sensors, new_pcap_sensors, new_peers_data, new_runtime_ingest_sensors,
        new_stream_direct_channels,
    },
    graphql::NodeName,
    server::{SERVER_REBOOT_DELAY, host_fqdn_from_cert},
    settings::Args,
    storage::{migrate_data_dir, validate_compression_metadata},
    tls_reload::{CertPaths, ReloadHandle, load_tls_material},
    web::WebController,
};

const ONE_DAY: Duration = Duration::from_hours(24);
const WAIT_SHUTDOWN: u64 = 15;
/// How often a shutdown drain that is still waiting reports its progress.
///
/// A reporting cadence, not a deadline: the drain is retried until the tracker
/// is empty, and this only decides how often a shutdown that is waiting says
/// so. Making it configurable belongs to the settings work in #1569.
const DRAIN_REPORT_INTERVAL: Duration = Duration::from_secs(5);

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
    let initial_material = Arc::new(loaded);
    let (reload_handle, tls_watch) = ReloadHandle::new(cert_paths, Arc::clone(&initial_material));

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

    let process = ProcessContext {
        cert,
        cfg_path,
        reload_handle,
        tls_watch,
        notify_terminate,
        notify_tls_reload,
        request_client_pool,
    };

    loop {
        match run_generation(&mut settings, &process).await? {
            GenerationEnd::ReloadConfig => {}
            GenerationEnd::Terminate => return Ok(()),
            GenerationEnd::Reboot => {
                roxy::reboot().map_err(|e| anyhow!("cannot restart the system: {e}"))?;
                return Ok(());
            }
            GenerationEnd::PowerOff => {
                roxy::power_off().map_err(|e| anyhow!("cannot power off the system: {e}"))?;
                return Ok(());
            }
        }
    }
}

/// State that outlives every generation.
///
/// `main` builds this once, before the first generation, and lends it to each
/// one. Everything here is either read-only for a generation — the node
/// certificate, the configuration file path, the GraphQL client pool — or a
/// process-wide channel a generation only listens on.
struct ProcessContext {
    /// The node's own certificate chain, which the node name is derived from.
    cert: Vec<CertificateDer<'static>>,
    /// Path to the configuration file, handed to the peer subsystem.
    cfg_path: String,
    /// Trigger that re-reads the TLS material from disk.
    reload_handle: ReloadHandle,
    /// The current TLS material, republished on every successful reload.
    tls_watch: tls_reload::TlsWatch,
    /// Raised by the SIGTERM/SIGINT handler and by the GraphQL shutdown API.
    notify_terminate: Arc<Notify>,
    /// Raised by the SIGHUP handler.
    notify_tls_reload: Arc<Notify>,
    /// mTLS client pool GraphQL uses to reach peer nodes.
    request_client_pool: reqwest::Client,
}

/// Why a generation ended.
///
/// A generation runs until one of these four intents arrives; nothing else
/// takes it down, and each one names a different thing for `main` to do next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationEnd {
    /// The configuration file was rewritten. The next generation starts from
    /// the updated settings.
    ReloadConfig,
    /// The daemon was asked to exit.
    Terminate,
    /// The host was asked to reboot.
    Reboot,
    /// The host was asked to power off.
    PowerOff,
}

/// Runs one generation and reports why it ended.
///
/// A generation is one turn of the process lifecycle: it opens the database,
/// starts the subsystems, serves until a shutdown intent arrives, and shuts
/// everything it built back down. Everything it owns — the database handle,
/// the subsystem tasks, and the top-level [`TaskTracker`] — is dropped before
/// it returns, so the next generation starts from a clean slate. That matters
/// for more than tidiness: RocksDB holds a file lock on the data directory, so
/// a handle surviving into the next generation would fail its `Database::open`.
///
/// `main` keeps only the outer loop and acts on the returned [`GenerationEnd`].
///
/// # Errors
///
/// Returns an error if the data directory fails compression validation or
/// migration, if the database cannot be opened, if the node certificate
/// carries no usable node name, or if the peer subsystem cannot be built.
#[allow(clippy::too_many_lines)]
async fn run_generation(
    settings: &mut Settings,
    process: &ProcessContext,
) -> Result<GenerationEnd> {
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

    // One top-level tracker per generation. It is created here so that it is
    // in scope where the subsystems below are spawned, it is drained on every
    // shutdown arm, and it is dropped with the generation — a `TaskTracker`
    // cannot be reopened once closed, so two generations can never share one
    // registry. Nothing is registered in it yet; the subsystem entry tasks
    // move into it in the issues that follow, and until then every drain
    // below returns on its first round.
    let top_level_tracker = TaskTracker::new();

    let tls = tls_reload::get_current_tls_material(&process.tls_watch);
    let certs = Arc::clone(&tls.certs);

    let schema = graphql::schema(
        NodeName(host_fqdn_from_cert(&process.cert)?),
        database.clone(),
        pcap_sensors.clone(),
        ingest_sensors.clone(),
        peers.clone(),
        process.request_client_pool.clone(),
        settings.config.visible.export_dir.clone(),
        reload_tx,
        notify_reboot.clone(),
        notify_power_off.clone(),
        process.notify_terminate.clone(),
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

    let retention = settings.config.visible.retention;
    let retain_task_handle: JoinHandle<()> = task::spawn({
        let db = database.clone();
        let notify_shutdown_copy = notify_shutdown.clone();
        let running_flag = retain_flag.clone();
        async move {
            if let Err(e) = storage::retain_periodically(
                ONE_DAY,
                retention,
                db,
                notify_shutdown_copy,
                running_flag,
            )
            .await
            {
                warn!("retain_periodically task terminated unexpectedly: {e}");
            }
        }
    });

    let peer_task_handle: Option<JoinHandle<Result<()>>>;
    if let Some(peer_srv_addr) = settings.config.peer_srv_addr {
        let peer_server = peer::Peer::new(peer_srv_addr, &certs.clone(), tls.generation)?;
        let notify_sensor = Arc::new(Notify::new());
        peer_task_handle = Some(task::spawn({
            let ingest_sensors = ingest_sensors.clone();
            let peers = peers.clone();
            let peer_idents = peer_idents.clone();
            let notify_sensor = notify_sensor.clone();
            let notify_shutdown = notify_shutdown.clone();
            let cfg_path = process.cfg_path.clone();
            let tls_watch = process.tls_watch.clone();
            async move {
                let result = peer_server
                    .run(
                        ingest_sensors,
                        peers,
                        peer_idents,
                        notify_sensor,
                        notify_shutdown,
                        cfg_path,
                        tls_watch,
                    )
                    .await;
                if let Err(e) = &result {
                    error!("Peer subsystem terminated unexpectedly: {e:#}");
                }
                result
            }
        }));
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
        process.tls_watch.clone(),
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
        process.tls_watch.clone(),
    ));

    let generation_end = loop {
        select! {
            Some(new_config) = reload_rx.recv() => {
                match settings.update_config_file(&new_config) {
                    Ok(()) => {
                        shutdown_web(web_controller.take()).await;
                        notify_shutdown.notify_waiters();
                        wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                        drain_top_level_tracker_or_log(&top_level_tracker).await;
                        break GenerationEnd::ReloadConfig;
                    }
                    Err(e) => {
                        warn!("Failed to update configuration: {e:#}, run with previous config");
                    }
                }
            },
            () = process.notify_terminate.notified() => {
                info!("Termination signal: daemon exit");
                shutdown_web(web_controller.take()).await;
                notify_shutdown.notify_waiters();
                wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                drain_top_level_tracker_or_log(&top_level_tracker).await;
                break GenerationEnd::Terminate;
            }
            () = notify_reboot.notified() => {
                info!("Restarting the system...");
                shutdown_web(web_controller.take()).await;
                notify_shutdown.notify_waiters();
                wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                drain_top_level_tracker_or_log(&top_level_tracker).await;
                break GenerationEnd::Reboot;
            }
            () = notify_power_off.notified() => {
                info!("Power off the system...");
                shutdown_web(web_controller.take()).await;
                notify_shutdown.notify_waiters();
                wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                drain_top_level_tracker_or_log(&top_level_tracker).await;
                break GenerationEnd::PowerOff;
            }
            () = process.notify_tls_reload.notified() => {
                reload_https_server(
                    &process.reload_handle,
                    &process.tls_watch,
                    &mut web_controller,
                    &schema,
                    web_addr,
                ).await;
            }
        }
    };

    match generation_end {
        // Neither of these closes the database here. On terminate the process
        // is on its way out and the handle goes with it; on a configuration
        // reload the handle is dropped as this function returns, before the
        // next generation reopens it. This is the pre-existing shape of the
        // path, delay included, and the ordering cutover that revisits it is
        // #1569's.
        GenerationEnd::ReloadConfig | GenerationEnd::Terminate => {
            sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
        }
        // The retention sweep runs on a blocking thread holding a database
        // handle, so the database cannot be closed until that flag clears.
        GenerationEnd::Reboot | GenerationEnd::PowerOff => {
            loop {
                if !retain_flag.load(Ordering::Relaxed) {
                    break;
                }
                sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
            }
            database.shutdown()?;

            info!("Before shut down the system, wait {WAIT_SHUTDOWN} seconds...");
            sleep(tokio::time::Duration::from_secs(WAIT_SHUTDOWN)).await;
        }
    }

    Ok(generation_end)
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
/// treated as a no-op *only when a live HTTPS server is already
/// serving*: if the previous startup or restart failed and no
/// controller is active, the reload trigger retries `web::serve`
/// against the current material so a transient bind failure does not
/// permanently suppress HTTPS. If the post-stop bind/start fails, the
/// error is logged using the same policy as initial startup failure.
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
    let outcome = reload_handle.reload();
    let current = tls_reload::get_current_tls_material(tls_watch);

    if outcome != tls_reload::ReloadOutcome::Updated && web_controller.is_some() {
        // A live server is already serving this exact material — either
        // validation failed (common plumbing preserved the previous
        // material) or the reread matched byte-for-byte. Leave the
        // running server untouched.
        info!("HTTPS reload: no TLS material changes detected, keeping current server");
        return;
    }

    if web_controller.is_some() {
        info!("HTTPS reload: initiating graceful shutdown of existing GraphQL server");
        if let Some(controller) = web_controller.take()
            && let Err(e) = controller.shutdown().await
        {
            warn!("HTTPS reload: graceful shutdown reported error: {e}");
        }
        info!("HTTPS reload: shutdown complete, starting new GraphQL server");
    } else {
        // No live server to preserve — a prior startup or restart
        // failed. Retry bind/start against the current material even
        // when the bytes are unchanged so transient failures are
        // recoverable on the next reload trigger.
        info!("HTTPS reload: no live HTTPS server; attempting startup with current TLS material");
    }

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
    retain_task_handle: JoinHandle<()>,
) {
    if let Some(handle_peers) = peer_task_handle {
        let _ = tokio::join!(
            ingest_task_handle,
            publish_task_handle,
            handle_peers,
            retain_task_handle
        );
    } else {
        let _ = tokio::join!(ingest_task_handle, publish_task_handle, retain_task_handle);
    }
}

/// Closes and cancels the per-generation top-level task tracker, then drains it
/// repeatedly until every tracked task has returned.
///
/// `report_interval` is a reporting cadence, not a deadline. Each time it
/// expires with tasks still tracked, the round is reported and the drain is
/// retried. Stragglers are never aborted: `JoinHandle::abort` drops a task
/// future at an arbitrary await point, which voids the cleanup-before-return
/// contract every tracked task is written to. Shutdown therefore ends only when
/// the tasks themselves return, and the repeated report is what narrows down a
/// task that never does.
///
/// The loop is re-callable. `TaskTracker::close` is idempotent and the wait can
/// repeat, so calling it again on an already drained tracker returns as soon as
/// the tracker is observed empty.
///
/// `report_interval` must be non-zero. A zero cadence still drains, because
/// each round polls the tracker before its deadline is checked, but it spins
/// the loop and floods the log with one round per poll. Rejecting an
/// unusable cadence belongs to the settings that supply it.
///
/// # Errors
///
/// Returns [`LockPoisonedError`] if an internal tracker mutex is poisoned. A
/// poisoned lock is the one outcome this policy treats as a real error; pending
/// tasks are not.
async fn drain_top_level_tracker(
    tracker: &TaskTracker,
    report_interval: Duration,
) -> Result<(), LockPoisonedError> {
    tracker.close()?;
    tracker.cancel_children();

    let mut round: u64 = 0;
    let mut reported_snapshot: Option<Vec<(u64, String)>> = None;
    loop {
        match tracker.drain(report_interval).await? {
            DrainOutcome::Drained => {
                if round > 0 {
                    info!("shutdown drain complete after {round} pending round(s)");
                }
                return Ok(());
            }
            DrainOutcome::Pending(pending) => {
                round = round.saturating_add(1);
                report_pending_round(round, &pending, &mut reported_snapshot);
            }
        }
    }
}

/// Drains the per-generation top-level tracker for one shutdown arm, logging a
/// poisoned tracker lock instead of propagating it.
///
/// A poisoned lock says nothing about the rest of the shutdown path, and
/// carrying it out of the generation would skip the work that still has to run
/// after the drain — the retained-handle observation and `database.shutdown()`.
/// So it is reported where it happens and shutdown carries on.
async fn drain_top_level_tracker_or_log(tracker: &TaskTracker) {
    if let Err(e) = drain_top_level_tracker(tracker, DRAIN_REPORT_INTERVAL).await {
        error!("shutdown drain could not read the top-level tracker: {e}");
    }
}

/// Reports one drain round that timed out with tasks still pending.
///
/// Every round emits a single progress line, so a shutdown that is waiting is
/// always visible. The detailed snapshot is one line per task, and the wait is
/// unbounded, so repeating it every round would bury the log while the same
/// tasks hang; it is emitted only when the set of pending tasks differs from
/// the one last reported through `reported_snapshot`. Ages are left out of that
/// comparison because they advance every round and would make every snapshot
/// look changed.
fn report_pending_round(
    round: u64,
    pending: &[PendingTaskSnapshot],
    reported_snapshot: &mut Option<Vec<(u64, String)>>,
) {
    warn!(
        "shutdown drain round {round}: {} task(s) still pending",
        pending.len()
    );

    // The registry is a hash map, so order by id to keep both the comparison
    // and the report stable across rounds.
    let mut pending: Vec<&PendingTaskSnapshot> = pending.iter().collect();
    pending.sort_unstable_by_key(|task| task.id);
    let snapshot: Vec<(u64, String)> = pending
        .iter()
        .map(|task| (task.id, task.name.clone()))
        .collect();

    if reported_snapshot
        .as_ref()
        .is_some_and(|last| *last == snapshot)
    {
        return;
    }

    for task in pending {
        warn!(
            "  pending task id={id} name={:?} age={:?}",
            task.name,
            task.age,
            id = task.id,
        );
    }
    *reported_snapshot = Some(snapshot);
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
    use tokio::{sync::oneshot, time::sleep};
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    /// Reporting cadence used by the drain-loop tests. The tests run on a
    /// paused clock, so this is virtual time only — no test waits on it.
    const REPORT_INTERVAL: Duration = Duration::from_secs(5);
    /// Upper bound on how long a drain loop may take to finish once its tasks
    /// have been released. Also virtual time: a loop that fails to make
    /// progress cannot hang the test, it fails it.
    const DRAIN_LOOP_TIMEOUT: Duration = Duration::from_mins(10);

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

        let retain_task_handle = tokio::spawn({
            let retain_done = retain_done.clone();
            async move {
                sleep(Duration::from_millis(20)).await;
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
        use crate::tls_reload::{CertPaths, ReloadHandle, load_tls_material};

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
            let initial = Arc::new(loaded);
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
            let initial_cert = initial.cert_pem.clone();
            let initial_key = initial.key_pem.clone();
            let initial_ca = initial.ca_pem.clone();
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

            // Sanity check: the live server serves with the old
            // material before the failing reload.
            sleep(Duration::from_millis(50)).await;
            let client = build_mtls_client(&initial_cert, &initial_key, &initial_ca);
            hello_query(&client, addr)
                .await
                .expect("pre-reload handshake with old material should succeed");

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

            // The acceptance guarantee: after a pre-stop validation
            // failure the existing HTTPS server must still serve the
            // old TLS material over a real mTLS handshake.
            hello_query(&client, addr)
                .await
                .expect("post-validation-failure handshake should still succeed on old server");

            shutdown_web(web_controller.take()).await;
        }

        #[tokio::test]
        async fn reload_retries_startup_when_no_live_controller() {
            // If a prior startup failed and no live web controller
            // exists, a follow-up reload trigger must retry `web::serve`
            // against the current TLS material even when the bytes are
            // byte-for-byte unchanged. Otherwise a transient bind
            // failure would be locked in until the cert/key/CA bytes
            // change again.
            let dir = tempdir().expect("tempdir");
            let (reload_handle, tls_watch, _cert_path, _key_path, _ca_path) = setup(dir.path());

            let addr = free_addr();
            let schema = test_schema();

            // Simulate the prior-startup-failed state: no live
            // controller, material unchanged on disk.
            let mut web_controller: Option<WebController> = None;

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
                "reload with no live controller must retry startup even when material is unchanged"
            );

            // Prove the retried server actually serves.
            let tls = tls_reload::get_current_tls_material(&tls_watch);
            sleep(Duration::from_millis(50)).await;
            let client = build_mtls_client(&tls.cert_pem, &tls.key_pem, &tls.ca_pem);
            hello_query(&client, addr)
                .await
                .expect("post-retry handshake should succeed on the newly started server");

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

    /// Installs a log-capturing subscriber for the current thread and returns
    /// the buffer it writes into.
    ///
    /// The drain-loop tests run on a current-thread runtime, so the tasks they
    /// spawn are polled on this same thread and their events land in this
    /// buffer.
    fn capture_logs() -> (Arc<Mutex<Vec<u8>>>, DefaultGuard) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = fmt::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(CaptureBuf(Arc::clone(&buf)))
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (buf, guard)
    }

    fn captured(buf: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().expect("lock").clone()).expect("utf8 log output")
    }

    fn count_lines_containing(output: &str, needle: &str) -> usize {
        output.lines().filter(|line| line.contains(needle)).count()
    }

    /// Spawns a task on `tracker` that stays pending until `release` fires,
    /// deliberately ignoring cancellation so the drain loop has to report
    /// progress across several rounds. The returned flag is set only if the
    /// task runs to the end, so an aborted task leaves it `false`.
    fn spawn_pending_task(
        tracker: &TaskTracker,
        name: &'static str,
        release: oneshot::Receiver<()>,
    ) -> (JoinHandle<()>, Arc<AtomicBool>) {
        let completed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&completed);
        let handle = tracker
            .spawn(name, move |_token| async move {
                let _ = release.await;
                flag.store(true, Ordering::SeqCst);
            })
            .expect("spawn should succeed");
        (handle, completed)
    }

    #[tokio::test(start_paused = true)]
    async fn drain_top_level_tracker_reports_each_round_until_drained() {
        let (logs, _guard) = capture_logs();

        let tracker = TaskTracker::new();
        let (release_tx, release_rx) = oneshot::channel();
        let (task_handle, completed) = spawn_pending_task(&tracker, "synthetic-top", release_rx);

        let drain = tokio::spawn({
            let tracker = tracker.clone();
            async move { drain_top_level_tracker(&tracker, REPORT_INTERVAL).await }
        });

        // Virtual time: the clock only advances while every task is idle, so
        // this lets exactly two drain rounds expire without any wall-clock
        // wait, and releases the task while the third round is in flight.
        sleep(REPORT_INTERVAL * 2 + REPORT_INTERVAL / 2).await;
        assert!(!completed.load(Ordering::SeqCst));
        release_tx
            .send(())
            .expect("drain loop should still be waiting");

        tokio::time::timeout(DRAIN_LOOP_TIMEOUT, drain)
            .await
            .expect("drain loop should finish once the task returns")
            .expect("drain loop task should not panic")
            .expect("drain loop should not report a poisoned lock");

        // The task returned on its own; it was neither aborted nor dropped.
        task_handle
            .await
            .expect("task should not have been aborted");
        assert!(completed.load(Ordering::SeqCst));
        assert!(tracker.is_closed());
        assert_eq!(tracker.pending_count(), 0);

        let output = captured(&logs);
        assert!(
            !output.contains("tracked task did not run to completion"),
            "no task should have been aborted, got: {output}"
        );

        // Every round reports progress ...
        assert!(
            output.contains("shutdown drain round 1: 1 task(s) still pending"),
            "round 1 should be reported, got: {output}"
        );
        assert!(
            output.contains("shutdown drain round 2: 1 task(s) still pending"),
            "round 2 should be reported, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, "shutdown drain round"),
            2,
            "exactly the pending rounds should be reported, got: {output}"
        );
        // ... while the unchanged detailed snapshot is logged only once.
        assert_eq!(
            count_lines_containing(&output, "pending task id="),
            1,
            "the unchanged snapshot should not be repeated, got: {output}"
        );
        assert!(
            output.contains("shutdown drain complete after 2 pending round(s)"),
            "completion should be reported, got: {output}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn drain_top_level_tracker_relogs_snapshot_when_pending_set_changes() {
        let (logs, _guard) = capture_logs();

        let tracker = TaskTracker::new();
        let (first_tx, first_rx) = oneshot::channel();
        let (second_tx, second_rx) = oneshot::channel();
        let (first_handle, first_done) = spawn_pending_task(&tracker, "synthetic-a", first_rx);
        let (second_handle, second_done) = spawn_pending_task(&tracker, "synthetic-b", second_rx);

        let drain = tokio::spawn({
            let tracker = tracker.clone();
            async move { drain_top_level_tracker(&tracker, REPORT_INTERVAL).await }
        });

        // Two rounds see both tasks, then one task returns and the next round
        // sees a changed set.
        sleep(REPORT_INTERVAL * 2 + REPORT_INTERVAL / 2).await;
        first_tx
            .send(())
            .expect("drain loop should still be waiting");
        first_handle
            .await
            .expect("task should not have been aborted");
        sleep(REPORT_INTERVAL * 2).await;
        second_tx
            .send(())
            .expect("drain loop should still be waiting");

        tokio::time::timeout(DRAIN_LOOP_TIMEOUT, drain)
            .await
            .expect("drain loop should finish once the tasks return")
            .expect("drain loop task should not panic")
            .expect("drain loop should not report a poisoned lock");

        second_handle
            .await
            .expect("task should not have been aborted");
        assert!(first_done.load(Ordering::SeqCst));
        assert!(second_done.load(Ordering::SeqCst));

        let output = captured(&logs);
        assert!(
            !output.contains("tracked task did not run to completion"),
            "no task should have been aborted, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, "shutdown drain round"),
            4,
            "each pending round should be reported, got: {output}"
        );
        // Round 1 lists both tasks, round 2 repeats nothing, and the round
        // after the set shrinks lists the one that is left.
        assert_eq!(
            count_lines_containing(&output, "pending task id="),
            3,
            "the snapshot should be relogged only when the set changes, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, "synthetic-a"),
            1,
            "the task that returned should be listed once, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, "synthetic-b"),
            2,
            "the remaining task should be listed in both snapshots, got: {output}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn drain_top_level_tracker_is_re_callable() {
        let tracker = TaskTracker::new();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        let handle = tracker
            .spawn("cooperative", move |token| async move {
                token.cancelled().await;
                flag.store(true, Ordering::SeqCst);
            })
            .expect("spawn should succeed");

        tokio::time::timeout(
            DRAIN_LOOP_TIMEOUT,
            drain_top_level_tracker(&tracker, REPORT_INTERVAL),
        )
        .await
        .expect("a cooperative task should drain on the first round")
        .expect("drain loop should not report a poisoned lock");
        handle.await.expect("task should not have been aborted");
        assert!(cancelled.load(Ordering::SeqCst));

        // `close` is idempotent and the wait can repeat, so the drained
        // tracker can be handed to the loop again.
        tokio::time::timeout(
            DRAIN_LOOP_TIMEOUT,
            drain_top_level_tracker(&tracker, REPORT_INTERVAL),
        )
        .await
        .expect("a second call should return immediately")
        .expect("drain loop should not report a poisoned lock");
    }

    /// A poisoned tracker lock ends the loop instead of being retried. Unlike
    /// a pending task, a poison never clears, so every later round would fail
    /// the same way and the loop would spin.
    ///
    /// The lock is poisoned the way `cancellation`'s own poison test does it:
    /// outside a runtime the inner `tasks.spawn` panics while the admission
    /// lock is held. That has to happen before any runtime is entered, so this
    /// test builds the runtime itself rather than using `#[tokio::test]`.
    #[test]
    fn drain_top_level_tracker_surfaces_a_poisoned_lock() {
        let tracker = TaskTracker::new();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tracker.spawn("no-runtime", |_token| async {});
        }));
        assert!(outcome.is_err(), "spawn outside a runtime should panic");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .expect("current-thread runtime should build");
        let result = runtime.block_on(async {
            tokio::time::timeout(
                DRAIN_LOOP_TIMEOUT,
                drain_top_level_tracker(&tracker, REPORT_INTERVAL),
            )
            .await
            .expect("a poisoned lock should end the loop, not be retried")
        });

        assert_eq!(result, Err(LockPoisonedError));
    }

    #[test]
    fn report_pending_round_skips_unchanged_snapshot_and_relogs_changes() {
        let (logs, _guard) = capture_logs();

        let first = vec![
            PendingTaskSnapshot {
                id: 1,
                name: "task-one".to_string(),
                age: Duration::from_secs(1),
            },
            PendingTaskSnapshot {
                id: 0,
                name: "task-zero".to_string(),
                age: Duration::from_secs(2),
            },
        ];
        // Same tasks, different ages and iteration order: still unchanged.
        let unchanged = vec![
            PendingTaskSnapshot {
                id: 0,
                name: "task-zero".to_string(),
                age: Duration::from_secs(7),
            },
            PendingTaskSnapshot {
                id: 1,
                name: "task-one".to_string(),
                age: Duration::from_secs(7),
            },
        ];
        let changed = vec![PendingTaskSnapshot {
            id: 1,
            name: "task-one".to_string(),
            age: Duration::from_secs(9),
        }];

        let mut reported = None;
        report_pending_round(1, &first, &mut reported);
        report_pending_round(2, &unchanged, &mut reported);
        report_pending_round(3, &changed, &mut reported);

        let output = captured(&logs);
        assert_eq!(count_lines_containing(&output, "shutdown drain round"), 3);
        assert_eq!(count_lines_containing(&output, "pending task id="), 3);

        // The first snapshot is ordered by id regardless of the order the
        // registry handed the tasks over in.
        let detail: Vec<&str> = output
            .lines()
            .filter(|line| line.contains("pending task id="))
            .collect();
        assert!(detail[0].contains("id=0"), "got: {output}");
        assert!(detail[1].contains("id=1"), "got: {output}");
        assert!(detail[2].contains("id=1"), "got: {output}");
    }

    /// A pending round can carry an empty snapshot: the registry may be
    /// emptied between the drain timing out and the snapshot being read. The
    /// round is still reported, and the empty snapshot does not suppress the
    /// next one that has tasks in it.
    #[test]
    fn report_pending_round_handles_an_empty_pending_snapshot() {
        let (logs, _guard) = capture_logs();

        let pending = vec![PendingTaskSnapshot {
            id: 0,
            name: "task-zero".to_string(),
            age: Duration::from_secs(1),
        }];

        let mut reported = None;
        report_pending_round(1, &[], &mut reported);
        report_pending_round(2, &pending, &mut reported);

        let output = captured(&logs);
        assert!(
            output.contains("shutdown drain round 1: 0 task(s) still pending"),
            "an empty round should still be reported, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, "pending task id="),
            1,
            "the empty snapshot should not suppress the next one, got: {output}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn drain_top_level_tracker_or_log_is_silent_for_an_empty_tracker() {
        let (logs, _guard) = capture_logs();
        let tracker = TaskTracker::new();

        tokio::time::timeout(DRAIN_LOOP_TIMEOUT, drain_top_level_tracker_or_log(&tracker))
            .await
            .expect("an empty tracker should drain on the first round");

        assert!(tracker.is_closed());
        assert_eq!(tracker.pending_count(), 0);
        let output = captured(&logs);
        assert!(
            output.is_empty(),
            "draining an empty tracker should log nothing, got: {output}"
        );
    }

    /// The wrapper exists so a poisoned tracker lock does not travel out of the
    /// generation: it is reported where it happens and shutdown carries on. The
    /// lock is poisoned the way the drain-loop poison test does it, which has to
    /// happen before any runtime is entered.
    #[test]
    fn drain_top_level_tracker_or_log_reports_a_poisoned_lock() {
        let tracker = TaskTracker::new();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tracker.spawn("no-runtime", |_token| async {});
        }));
        assert!(outcome.is_err(), "spawn outside a runtime should panic");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .expect("current-thread runtime should build");
        let (logs, _guard) = capture_logs();
        runtime.block_on(async {
            tokio::time::timeout(DRAIN_LOOP_TIMEOUT, drain_top_level_tracker_or_log(&tracker))
                .await
                .expect("a poisoned lock should end the wrapper, not be retried");
        });

        let output = captured(&logs);
        assert!(
            output.contains("task tracker lock was poisoned"),
            "the poisoned lock should be reported, got: {output}"
        );
    }

    /// One whole generation, start to finish.
    ///
    /// The generation loop had no test seam before it became a function: its
    /// body ran only as the process entry point. Now a generation can be built
    /// against a temporary database and ephemeral ports, ended with a terminate
    /// intent, and asked what it returned.
    mod run_generation_tests {
        use std::{
            fs,
            net::{Ipv4Addr, SocketAddr},
            path::Path,
            sync::Once,
        };

        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
        use tempfile::tempdir;

        use super::*;
        use crate::{
            settings::Config,
            tls_reload::{CertPaths, ReloadHandle, load_tls_material},
        };

        static INSTALL_PROVIDER: Once = Once::new();

        /// Upper bound on one generation. The terminate arm waits
        /// `SERVER_REBOOT_DELAY` on its way out, so this is deliberately loose:
        /// it is here so a generation that never ends fails the test instead of
        /// hanging it.
        const GENERATION_TIMEOUT: Duration = Duration::from_mins(2);
        /// Upper bound on the subsystems reporting that they are up. Same
        /// purpose — a bound, not a wait.
        const READY_TIMEOUT: Duration = Duration::from_mins(1);
        /// How often the readiness wait rechecks the captured log.
        const READY_POLL: Duration = Duration::from_millis(5);

        fn install_crypto_provider() {
            INSTALL_PROVIDER.call_once(|| {
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            });
        }

        fn path_string(path: &Path) -> String {
            path.to_str().expect("utf-8 path").to_string()
        }

        /// Writes a self-signed node certificate carrying both identities
        /// giganto knows how to read — the legacy `{service}@{hostname}` CN of
        /// the default build and the four-label SAN DNS name of the `bootroot`
        /// build — so the generation resolves a node name in either build.
        fn write_node_pki(dir: &Path) -> CertPaths {
            let key_pair = KeyPair::generate().expect("generate key pair");
            let mut params =
                CertificateParams::new(vec!["001.giganto.node1.example.test".to_string()])
                    .expect("cert params");
            params.distinguished_name = rcgen::DistinguishedName::new();
            params
                .distinguished_name
                .push(DnType::CommonName, "giganto@node1");
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let cert = params.self_signed(&key_pair).expect("self-signed cert");

            let cert_path = dir.join("cert.pem");
            let key_path = dir.join("key.pem");
            let ca_path = dir.join("ca.pem");
            fs::write(&cert_path, cert.pem()).expect("write cert");
            fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
            fs::write(&ca_path, cert.pem()).expect("write ca");

            CertPaths {
                cert_path: path_string(&cert_path),
                key_path: path_string(&key_path),
                ca_certs_paths: vec![path_string(&ca_path)],
            }
        }

        /// Port 0 on the loopback: the kernel picks a free port at bind time,
        /// so no port has to be reserved and nothing depends on which it picks.
        fn ephemeral_addr() -> SocketAddr {
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
        }

        fn test_settings(dir: &Path) -> Settings {
            let data_dir = dir.join("data");
            let export_dir = dir.join("export");
            fs::create_dir_all(&data_dir).expect("create data dir");
            fs::create_dir_all(&export_dir).expect("create export dir");

            Settings {
                config: Config {
                    // The peer subsystem is not what this test exercises, and
                    // leaving it unconfigured is a shape production supports.
                    peer_srv_addr: None,
                    peers: None,
                    visible: ConfigVisible {
                        graphql_srv_addr: ephemeral_addr(),
                        ingest_srv_addr: ephemeral_addr(),
                        publish_srv_addr: ephemeral_addr(),
                        retention: ONE_DAY * 100,
                        export_dir,
                        data_dir,
                        max_open_files: 500,
                        max_mb_of_level_base: 512,
                        num_of_thread: 2,
                        max_subcompactions: 2,
                        ack_transmission: 1024,
                    },
                    compression: false,
                },
                cfg_path: path_string(&dir.join("config.toml")),
            }
        }

        fn test_process_context(dir: &Path, notify_terminate: Arc<Notify>) -> ProcessContext {
            install_crypto_provider();
            let cert_paths = write_node_pki(dir);
            let loaded = load_tls_material(&cert_paths).expect("load TLS material");
            let cert = loaded.certs.certs.clone();
            let (reload_handle, tls_watch) = ReloadHandle::new(cert_paths, Arc::new(loaded));
            let tls = tls_reload::get_current_tls_material(&tls_watch);
            let request_client_pool =
                create_graphql_client(&tls.cert_pem, &tls.key_pem).expect("graphql client pool");

            ProcessContext {
                cert,
                cfg_path: path_string(&dir.join("config.toml")),
                reload_handle,
                tls_watch,
                notify_terminate,
                notify_tls_reload: Arc::new(Notify::new()),
                request_client_pool,
            }
        }

        /// Waits until every `needle` has appeared in the captured log.
        ///
        /// This is the synchronization the terminate intent needs.
        /// `notify_shutdown` is delivered with `notify_waiters`, which reaches
        /// only the tasks already parked on it, so signalling before the
        /// subsystems are up would notify nobody and the join that follows
        /// would never return. Each subsystem announces itself with no await
        /// between the announcement and the park, and on this test's
        /// current-thread runtime the announcement can only be observed after
        /// that poll has finished — so a subsystem whose line is in the log is
        /// parked.
        async fn wait_for_logs(logs: &Arc<Mutex<Vec<u8>>>, needles: &[&str]) {
            let wait = async {
                while !needles.iter().all(|needle| captured(logs).contains(needle)) {
                    sleep(READY_POLL).await;
                }
            };
            tokio::time::timeout(READY_TIMEOUT, wait)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "the subsystems should report readiness, got: {}",
                        captured(logs)
                    )
                });
        }

        #[tokio::test]
        async fn a_generation_ends_on_a_terminate_intent() {
            let dir = tempdir().expect("tempdir");
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir.path(), Arc::clone(&notify_terminate));
            let mut settings = test_settings(dir.path());

            let (logs, _guard) = capture_logs();
            // `join!` drives both on this task: the generation runs while the
            // other side watches the log for readiness and then sends the
            // intent that ends it.
            let (end, ()) = tokio::join!(
                tokio::time::timeout(GENERATION_TIMEOUT, run_generation(&mut settings, &process)),
                async {
                    wait_for_logs(
                        &logs,
                        &[
                            "Ingest listening on",
                            "Publish listening on",
                            "Database cleanup completed.",
                        ],
                    )
                    .await;
                    notify_terminate.notify_one();
                }
            );

            let end = end
                .expect("the generation should end once the terminate intent arrives")
                .expect("the generation should not fail");
            assert_eq!(end, GenerationEnd::Terminate);

            let output = captured(&logs);
            assert!(
                output.contains("Termination signal: daemon exit"),
                "the terminate arm should have run, got: {output}"
            );
            // Nothing is registered in the top-level tracker yet, so its drain
            // returns on the first round with nothing to report.
            assert!(
                !output.contains("shutdown drain round"),
                "an empty tracker should not report a drain round, got: {output}"
            );
            assert!(
                !output.contains("shutdown drain complete"),
                "an empty tracker should not report drain progress, got: {output}"
            );
        }
    }
}
