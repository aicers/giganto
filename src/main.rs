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

use std::{fs::OpenOptions, path::Path, process::exit, sync::Arc, time::Duration};

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
use tokio_util::sync::CancellationToken;
use tracing::{error, info, metadata::LevelFilter, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, Layer, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

use crate::{
    cancellation::{DRAIN_REPORT_INTERVAL, TaskTracker, drain_with_report},
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
/// Names the per-generation top-level tracker in the drain progress log.
///
/// Every tracker in the process is drained by the same policy, so the label is
/// what tells a shutdown that is waiting on a subsystem apart from one waiting
/// on the top level.
const TOP_LEVEL_DRAIN_LABEL: &str = "shutdown";

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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize rustls crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = Args::parse();
    let mut settings = Settings::load_or_restore(&args.config)?;

    settings.config.validate()?;

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
    let notify_terminate = Arc::new(Notify::new());
    let notify_tls_reload = Arc::new(Notify::new());
    let process = ProcessContext::new(
        cert_paths,
        Arc::clone(&notify_terminate),
        Arc::clone(&notify_tls_reload),
    )?;

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
            // The generation has already drained and closed itself down; what
            // is left is to tell the process manager that this exit was not
            // asked for, so a unit configured to restart on failure does.
            // What failed was reported where it happened.
            GenerationEnd::IngestExited => {
                return Err(anyhow!("the ingest subsystem ended before the daemon did"));
            }
        }
    }
}

/// State that outlives every generation.
///
/// `main` builds this once, before the first generation, and lends it to each
/// one. Everything here is either read-only for a generation — the node
/// certificate, the GraphQL client pool — or a process-wide channel a
/// generation only listens on. The configuration is not here: it is the one
/// piece a generation can rewrite, so it is lent separately as `&mut
/// Settings`.
struct ProcessContext {
    /// The node's own certificate chain, which the node name is derived from.
    cert: Vec<CertificateDer<'static>>,
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

impl ProcessContext {
    /// Builds the state every generation borrows.
    ///
    /// The node certificate, the reload watch, and the GraphQL client pool are
    /// all derived from one load of the TLS material on disk, so they are
    /// built together here rather than assembled by the caller. This load is
    /// also where TLS material the process cannot use is caught, before the
    /// first generation opens the database.
    ///
    /// The two notifiers are passed in because the signal handlers `main`
    /// installs raise them, so `main` needs its own handles on them.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS material cannot be loaded, or if the mTLS
    /// GraphQL client pool cannot be built from it.
    fn new(
        cert_paths: CertPaths,
        notify_terminate: Arc<Notify>,
        notify_tls_reload: Arc<Notify>,
    ) -> Result<Self> {
        let loaded =
            load_tls_material(&cert_paths).context("failed to load initial TLS material")?;
        let cert = loaded.certs.certs.clone();
        let (reload_handle, tls_watch) = ReloadHandle::new(cert_paths, Arc::new(loaded));
        let tls = tls_reload::get_current_tls_material(&tls_watch);
        let request_client_pool = create_graphql_client(&tls.cert_pem, &tls.key_pem)?;

        Ok(Self {
            cert,
            reload_handle,
            tls_watch,
            notify_terminate,
            notify_tls_reload,
            request_client_pool,
        })
    }
}

/// Why a generation ended.
///
/// Four of these are intents that arrive from outside; the fifth is a
/// subsystem entry task ending on its own, which is not an intent but is just
/// as final. Each one names a different thing for `main` to do next.
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
    /// The ingest entry task ended while the generation was still serving.
    ///
    /// Nobody asked for this one. An entry task returns on its own only when
    /// it cannot do its job — a listener whose address is taken — or when it
    /// panics, and a node that keeps serving GraphQL and publish while
    /// ingesting nothing is not a node anyone asked for either. So the early
    /// exit ends the generation through the same shutdown sequence as the
    /// intents, and `main` reports it as a failure rather than exiting
    /// cleanly. Ingest is the only entry task the top-level tracker watches
    /// for now: peer and publish are registered in the tracker but their
    /// handles are not kept, so an early exit of either goes unwatched until
    /// the process-level lifecycle work takes that on.
    IngestExited,
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

    let (reload_tx, reload_rx) = mpsc::channel::<ConfigVisible>(1);
    let notify_shutdown = Arc::new(Notify::new());
    let notify_reboot = Arc::new(Notify::new());
    let notify_power_off = Arc::new(Notify::new());

    let pcap_sensors = new_pcap_sensors();
    let ingest_sensors = new_ingest_sensors(&database);
    let runtime_ingest_sensors = new_runtime_ingest_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let notify_sensor_change = settings
        .config
        .peer_srv_addr
        .is_some()
        .then(|| Arc::new(Notify::new()));
    let (peers, peer_idents) = new_peers_data(settings.config.peers.clone());
    let ack_transmission_cnt = settings.config.visible.ack_transmission;

    // One top-level tracker per generation. It is created here so that it is
    // in scope where the subsystems below are spawned, it is drained on every
    // shutdown arm, and it is dropped with the generation — a `TaskTracker`
    // cannot be reopened once closed, so two generations can never share one
    // registry. Ingest, retention, peer, and publish are all registered in it
    // below.
    let top_level_tracker = TaskTracker::new();

    let tls = tls_reload::get_current_tls_material(&process.tls_watch);
    let certs = Arc::clone(&tls.certs);

    let schema = graphql::schema(
        NodeName(host_fqdn_from_cert(&process.cert)?),
        database.clone(),
        pcap_sensors.clone(),
        ingest_sensors.clone(),
        #[cfg(feature = "bootroot")]
        runtime_ingest_sensors.clone(),
        #[cfg(feature = "bootroot")]
        stream_direct_channels.clone(),
        #[cfg(feature = "bootroot")]
        notify_sensor_change.clone(),
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

    // Retention is tracked, not detached: the tracker's cancellation is what
    // stops it, the tracker's drain is what waits for it, and the handle kept
    // here is what says how it ended. Its child token reaches it through the
    // closure argument, so nothing about its shutdown travels on
    // `notify_shutdown`.
    let retention = settings.config.visible.retention;
    let retain_task_handle: JoinHandle<Result<()>> = top_level_tracker
        .spawn("retention", {
            let db = database.clone();
            move |cancel| run_retention(ONE_DAY, retention, db, cancel)
        })
        .map_err(|e| anyhow!("failed to register the retention task: {e}"))?;

    // Peer is tracked the way retention and ingest are: the tracker hands it
    // the generation's cancellation token and waits for its entry task in the
    // drain below. Unlike theirs, its handle is dropped. Peer reports its own
    // failure where it happens and the tracker's registry guard names a panic
    // or an abort, so the only outcome a retained handle would add is a normal
    // early exit — supervising that, and ordering the read against
    // `database.shutdown()`, is process-level lifecycle work (#1569).
    if let Some(peer_srv_addr) = settings.config.peer_srv_addr {
        let peer_server = peer::Peer::new(peer_srv_addr, &certs.clone(), tls.generation)?;
        let notify_sensor = notify_sensor_change
            .clone()
            .expect("peer notify exists when peer server is configured");
        top_level_tracker
            .spawn("peer", {
                let ingest_sensors = ingest_sensors.clone();
                let peers = peers.clone();
                let peer_idents = peer_idents.clone();
                let cfg_path = settings.cfg_path.clone();
                let tls_watch = process.tls_watch.clone();
                move |token| async move {
                    let result = peer_server
                        .run(
                            ingest_sensors,
                            peers,
                            peer_idents,
                            notify_sensor,
                            cfg_path,
                            tls_watch,
                            token,
                        )
                        .await;
                    if let Err(e) = &result {
                        error!("Peer subsystem terminated unexpectedly: {e:#}");
                    }
                    result
                }
            })
            .context("failed to register the peer entry task")?;
    }

    // Publish is tracked the way peer is: the tracker hands it the
    // generation's cancellation token and waits for its entry task in the
    // drain below, and its handle is dropped. Publish reports its own failure
    // where it happens and the tracker's registry guard names a panic or an
    // abort, so the only outcome a retained handle would add is a normal early
    // exit. Acting on that — a node that keeps serving without publish — is
    // process-level lifecycle work (#1569), which is also why no
    // `GenerationEnd` variant watches this task the way one watches ingest.
    let publish_server =
        publish::Server::new(settings.config.visible.publish_srv_addr, &certs.clone());
    top_level_tracker
        .spawn("publish", {
            let db = database.clone();
            let pcap_sensors = pcap_sensors.clone();
            let stream_direct_channels = stream_direct_channels.clone();
            let ingest_sensors = ingest_sensors.clone();
            let peers = peers.clone();
            let peer_idents = peer_idents.clone();
            let tls_watch = process.tls_watch.clone();
            move |token| async move {
                let result = publish_server
                    .run(
                        db,
                        pcap_sensors,
                        stream_direct_channels,
                        ingest_sensors,
                        peers,
                        peer_idents,
                        tls_watch,
                        token,
                    )
                    .await;
                // Reported here, the way ingest's and peer's are, rather than
                // at a call site that reads the handle back: a listener whose
                // address is taken returns at once, and a node left running
                // without publish must not go unreported until shutdown.
                if let Err(e) = &result {
                    error!("Publish subsystem terminated unexpectedly: {e:#}");
                }
                result
            }
        })
        .context("failed to register the publish entry task")?;

    let ingest_server =
        ingest::Server::new(settings.config.visible.ingest_srv_addr, &certs.clone());
    // Ingest is tracked the way retention is: the tracker hands it the
    // generation's cancellation token, and the drain below waits for the entry
    // task to return before the generation lets go of the database handle. The handle is kept because the tracker cannot stand in
    // for it: the wait below watches it so an entry task that ends on its own
    // takes the generation down with it rather than leaving a node serving
    // everything but ingest, and reading it back after the drain adds the
    // outcome the drain cannot see — a panic as a `JoinError`.
    let mut ingest_task_handle = top_level_tracker
        .spawn("ingest", {
            let db = database.clone();
            let tls_watch = process.tls_watch.clone();
            move |token| async move {
                let result = ingest_server
                    .run(
                        db,
                        pcap_sensors,
                        ingest_sensors,
                        runtime_ingest_sensors,
                        stream_direct_channels,
                        notify_sensor_change,
                        ack_transmission_cnt,
                        tls_watch,
                        token,
                    )
                    .await;
                // Reported here, the way the peer subsystem reports its own,
                // rather than where the handle is read back: this task can end
                // long before the generation does — a listener whose address
                // is taken returns at once — and a node left running without
                // ingest must not go unreported until shutdown.
                if let Err(e) = &result {
                    error!("Ingest subsystem terminated unexpectedly: {e:#}");
                }
                result
            }
        })
        .context("failed to register the ingest entry task")?;

    let mut intents = GenerationIntents {
        reload_rx,
        notify_reboot,
        notify_power_off,
    };
    let generation_end = wait_for_generation_end(
        settings,
        process,
        &mut intents,
        &mut ingest_task_handle,
        &mut web_controller,
        &schema,
        web_addr,
    )
    .await;

    // Every intent that ends a generation is shut down the same way, so the
    // sequence runs once here instead of once per arm. The order is the one
    // each arm had.
    shutdown_web(web_controller.take()).await;
    // Publish was the last subsystem listening on `notify_shutdown`, and it
    // now takes its signal from the token like the rest. The signal is still
    // raised because retiring the `Notify` belongs to the process-level
    // lifecycle work (#1569); nothing subscribes to it today.
    notify_shutdown.notify_waiters();
    // Every subsystem is tracked, so cancelling here is what starts them all
    // draining. `shutdown_generation` cancels again, which is idempotent.
    top_level_tracker.cancel_children();
    shutdown_generation(
        &top_level_tracker,
        retain_task_handle,
        // Handed over only when the wait ended on something else. If the entry
        // task is what ended it, its arm has already read the handle back and
        // reported it, and a `JoinHandle` polled again after it has completed
        // is not a handle that resolves a second time.
        (generation_end != GenerationEnd::IngestExited).then_some(ingest_task_handle),
        generation_end,
        &database,
    )
    .await?;

    Ok(generation_end)
}

/// The three shutdown intents a generation owns.
///
/// Terminate and TLS reload arrive from outside a generation and live in
/// [`ProcessContext`]; these three are created per generation, handed to the
/// GraphQL schema, and listened on only here. Grouping them keeps
/// [`wait_for_generation_end`]'s parameter list readable and gives a test one
/// place to build the intents from.
struct GenerationIntents {
    /// Carries the rewritten configuration a `setConfig` mutation produced.
    reload_rx: mpsc::Receiver<ConfigVisible>,
    /// Raised by the GraphQL reboot mutation.
    notify_reboot: Arc<Notify>,
    /// Raised by the GraphQL power-off mutation.
    notify_power_off: Arc<Notify>,
}

/// Serves until a shutdown intent arrives or a subsystem entry task ends, and
/// reports which it was.
///
/// This is the whole of a generation's steady state. Five of the six arms end
/// the generation; the sixth, a TLS reload, rebinds the HTTPS server in place
/// and keeps serving, which is why the wait is a loop rather than a single
/// `select!`. A configuration reload that cannot be persisted also keeps
/// serving, on the configuration the generation started with.
///
/// The ingest arm is why the entry task's handle is borrowed here rather than
/// only read back after the drain: an entry task that ends on its own is an
/// event the generation has to act on, not one it can discover at shutdown.
/// Borrowing leaves the handle with the caller, so an arm that loses the race
/// has taken nothing from it.
///
/// Shutting the generation's own machinery down is the caller's, not this
/// function's: every arm that ends a generation is torn down the same way, so
/// the sequence runs once at the call site instead of once per arm.
async fn wait_for_generation_end<S>(
    settings: &mut Settings,
    process: &ProcessContext,
    intents: &mut GenerationIntents,
    ingest_task: &mut JoinHandle<Result<()>>,
    web_controller: &mut Option<WebController>,
    schema: &S,
    web_addr: std::net::SocketAddr,
) -> GenerationEnd
where
    S: async_graphql::Executor + Clone,
{
    loop {
        select! {
            Some(new_config) = intents.reload_rx.recv() => {
                match settings.update_config_file(&new_config) {
                    Ok(()) => break GenerationEnd::ReloadConfig,
                    Err(e) => {
                        warn!("Failed to update configuration: {e:#}, run with previous config");
                    }
                }
            },
            () = process.notify_terminate.notified() => {
                info!("Termination signal: daemon exit");
                break GenerationEnd::Terminate;
            }
            () = intents.notify_reboot.notified() => {
                info!("Restarting the system...");
                break GenerationEnd::Reboot;
            }
            () = intents.notify_power_off.notified() => {
                info!("Power off the system...");
                break GenerationEnd::PowerOff;
            }
            outcome = &mut *ingest_task => {
                report_early_ingest_exit(&outcome);
                break GenerationEnd::IngestExited;
            }
            () = process.notify_tls_reload.notified() => {
                reload_https_server(
                    &process.reload_handle,
                    &process.tls_watch,
                    web_controller,
                    schema,
                    web_addr,
                ).await;
            }
        }
    }
}

/// Stops what the generation registered in its top-level tracker, then runs
/// the tail the ending intent asks for.
///
/// The order is the whole of it. The drain cancels the tracker and does not
/// return until every tracked task has returned, so the retention and ingest
/// entry tasks — and with them any cleanup still running on the blocking pool
/// or any handler still writing — have stopped before their handles are read
/// and before [`finish_generation`] is in a position to close the database.
/// Retention holds a database handle on a blocking thread; closing the
/// database while it still ran would pull the store out from under a live
/// RocksDB operation, which is why nothing here is reordered.
///
/// `ingest_task_handle` is `None` when the generation ended because that very
/// task returned: the wait has already read the handle back, and a
/// `JoinHandle` polled again after it has completed is not a handle that
/// resolves a second time.
///
/// # Errors
///
/// Returns an error if the tail cannot flush the database. A retention failure
/// is reported, not returned: the generation is already ending, and the tail
/// still has to run.
async fn shutdown_generation(
    top_level_tracker: &TaskTracker,
    retain_task_handle: JoinHandle<Result<()>>,
    ingest_task_handle: Option<JoinHandle<Result<()>>>,
    generation_end: GenerationEnd,
    database: &storage::Database,
) -> Result<()> {
    drain_top_level_tracker_or_log(top_level_tracker).await;
    report_retention_outcome(retain_task_handle).await;
    if let Some(ingest_task_handle) = ingest_task_handle {
        observe_ingest_shutdown(ingest_task_handle).await;
    }
    finish_generation(generation_end, database).await
}

/// Runs the retention entry task, reporting a failure the moment it happens.
///
/// The handle `main` retains carries whatever this returns to
/// [`report_retention_outcome`], but that accounting runs only when the
/// generation ends — which, for a node that is simply left running, is days or
/// months after a retention pass failed. Retention that stops deleting is the
/// failure an operator has to hear about at once, not at the post-mortem, so
/// it is reported here as well, the way the peer subsystem reports its own.
///
/// # Errors
///
/// Returns whatever [`storage::retain_periodically`] returned, unchanged: the
/// report is in addition to the return value, never in place of it.
async fn run_retention(
    interval: Duration,
    retention_period: Duration,
    db: storage::Database,
    cancel: CancellationToken,
) -> Result<()> {
    let result = storage::retain_periodically(interval, retention_period, db, cancel).await;
    if let Err(e) = &result {
        error!("Retention terminated unexpectedly: {e:#}");
    }
    result
}

/// Reports how the retention entry task ended.
///
/// A drain waits for tracked tasks to exit but says nothing about how they
/// exited, so the handle kept at spawn time is where the generation accounts
/// for its retention task. All four endings are reported: the value it
/// returned, the error it returned, a panic, and an abort it never asked for.
/// Only the first two are anything [`run_retention`] could have reported on
/// its own; a panic and an abort leave no return value behind, so this is the
/// only place they can be seen at all. Awaiting the handle here costs
/// nothing — the drain has already waited for this task — and it is what makes
/// the report the last word on retention before the database is closed.
async fn report_retention_outcome(retain_task_handle: JoinHandle<Result<()>>) {
    match retain_task_handle.await {
        Ok(Ok(())) => info!("Retention stopped"),
        // [`run_retention`] already reported this one when it happened, so
        // this line is the shutdown restating it, not news.
        Ok(Err(e)) => error!("Retention had already terminated unexpectedly: {e:#}"),
        Err(e) if e.is_panic() => error!("Retention panicked: {e}"),
        Err(e) => error!("Retention did not run to completion: {e}"),
    }
}

/// Runs the tail of a generation, the part that differs by intent.
///
/// By the time this runs the subsystems have already been notified and joined
/// and the top-level tracker has drained, so nothing is left holding the
/// database and what remains is what each intent needs of the handle before
/// the generation drops it.
///
/// # Errors
///
/// Returns an error if the database cannot be flushed on the way out.
async fn finish_generation(
    generation_end: GenerationEnd,
    database: &storage::Database,
) -> Result<()> {
    match generation_end {
        // None of these closes the database here. On terminate, and on an
        // entry task that ended early, the process is on its way out and the
        // handle goes with it; on a configuration reload the handle is dropped
        // as the generation returns, before the next one reopens it. This is
        // the pre-existing shape of the path, delay included, and the ordering
        // cutover that revisits it is #1569's.
        GenerationEnd::ReloadConfig | GenerationEnd::Terminate | GenerationEnd::IngestExited => {
            sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
        }
        // The host is about to go down, so the store is flushed and its
        // background work stopped first. The caller has already drained the
        // tracker, so no retention cleanup is running on a blocking thread to
        // be surprised by it.
        GenerationEnd::Reboot | GenerationEnd::PowerOff => {
            database.shutdown()?;

            info!("Before shut down the system, wait {WAIT_SHUTDOWN} seconds...");
            sleep(tokio::time::Duration::from_secs(WAIT_SHUTDOWN)).await;
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

/// Reports how the ingest entry task ended once the generation is shutting
/// down.
///
/// The task reports its own `Err` where it happens, so what is left for the
/// handle to add is the outcome only a `JoinError` carries: a panic, or an
/// abort. The top-level drain waits for the task to return but looks at
/// neither, so this is where it becomes visible. It runs after the drain, so
/// the handle is already resolved and this only reads it back.
async fn observe_ingest_shutdown(handle: JoinHandle<Result<()>>) {
    if let Err(e) = handle.await {
        error!("Ingest task did not join: {e}");
    }
}

/// Reports an ingest entry task that ended while the generation was still
/// serving.
///
/// Nothing here is expected: the task returns on its own only when it cannot
/// keep the listener, and the caller ends the generation on it either way. An
/// `Err` has already been reported by the task itself, where the context that
/// produced it was still at hand, so repeating it here would only say the same
/// thing twice; the other two outcomes have gone unsaid until now.
fn report_early_ingest_exit(outcome: &std::result::Result<Result<()>, task::JoinError>) {
    match outcome {
        Ok(Ok(())) => error!("Ingest subsystem returned before the daemon was asked to stop"),
        Ok(Err(_)) => {}
        Err(e) => error!("Ingest task did not join: {e}"),
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
    if let Err(e) = drain_with_report(tracker, DRAIN_REPORT_INTERVAL, TOP_LEVEL_DRAIN_LABEL).await {
        error!("shutdown drain could not read the top-level tracker: {e}");
    }
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

    /// Every ending the retention handle can carry reaches the log.
    ///
    /// The drain that precedes this report says only that the task exited, so
    /// if the report loses an ending, that ending is lost outright.
    #[tokio::test]
    async fn report_retention_outcome_reports_every_ending() {
        let (logs, guard) = capture_logs();
        report_retention_outcome(tokio::spawn(async { Ok(()) })).await;
        let output = captured(&logs);
        assert!(
            output.contains("Retention stopped"),
            "a clean stop should be reported, got: {output}"
        );
        drop(guard);

        let (logs, guard) = capture_logs();
        report_retention_outcome(tokio::spawn(async {
            Err(anyhow!("retention cleanup failed"))
        }))
        .await;
        let output = captured(&logs);
        assert!(
            output.contains("Retention had already terminated unexpectedly")
                && output.contains("retention cleanup failed"),
            "a returned error should be restated with its cause, got: {output}"
        );
        drop(guard);

        let (logs, guard) = capture_logs();
        report_retention_outcome(tokio::spawn(async {
            panic!("retention panicked");
        }))
        .await;
        let output = captured(&logs);
        assert!(
            output.contains("Retention panicked"),
            "a panic should be reported, got: {output}"
        );
        drop(guard);

        let (logs, _guard) = capture_logs();
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let (block_tx, block_rx) = oneshot::channel::<()>();
        let aborted: JoinHandle<Result<()>> = tokio::spawn(async move {
            let _ = started_tx.send(());
            let _ = block_rx.await;
            Ok(())
        });
        // Aborted while it is parked on `block_rx`, so the handle carries the
        // cancellation of a task that was running — the shape a retention task
        // aborted from outside the lifecycle would arrive in.
        started_rx.await.expect("the task should have started");
        aborted.abort();
        report_retention_outcome(aborted).await;
        drop(block_tx);
        let output = captured(&logs);
        assert!(
            output.contains("Retention did not run to completion"),
            "an abort nobody asked for should be reported, got: {output}"
        );
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

    /// A generation, piece by piece and end to end.
    ///
    /// The generation lifecycle had no test seam before it became a set of
    /// functions: its body ran only as the process entry point. Now the wait
    /// that ends a generation, the tail that runs after it, and a whole
    /// generation over a temporary database and ephemeral ports can each be
    /// driven directly.
    mod generation_tests {
        use std::{
            collections::HashSet,
            fs,
            net::{Ipv4Addr, SocketAddr},
            path::Path,
            sync::Once,
        };

        use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
        use tempfile::tempdir;

        use super::*;
        use crate::settings::Config;

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

        /// A loopback address a test can name in advance.
        ///
        /// The listener is bound only to learn which port the kernel handed
        /// out and is dropped before the address is returned, so the caller
        /// gets an address it can either bind itself or hand to code that
        /// will.
        fn free_addr() -> SocketAddr {
            let listener =
                std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
            listener.local_addr().expect("local addr")
        }

        fn test_settings(dir: &Path) -> Settings {
            let data_dir = dir.join("data");
            let export_dir = dir.join("export");
            fs::create_dir_all(&data_dir).expect("create data dir");
            fs::create_dir_all(&export_dir).expect("create export dir");

            Settings {
                config: Config {
                    // The peer subsystem is not what most of these tests
                    // exercise, and leaving it unconfigured is a shape
                    // production supports.
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

        /// Materializes the configuration file at `cfg_path`.
        ///
        /// Two paths need the file to exist: the peer subsystem reads it on
        /// startup, and a configuration reload backs it up before rewriting
        /// it. Tests that exercise neither leave it absent, which is also how
        /// they reach the reload's failure arm.
        fn write_config_file(settings: &Settings) {
            let toml = toml::to_string(&settings.config).expect("serialize config");
            fs::write(&settings.cfg_path, toml).expect("write config file");
        }

        fn test_process_context(dir: &Path, notify_terminate: Arc<Notify>) -> ProcessContext {
            install_crypto_provider();
            ProcessContext::new(
                write_node_pki(dir),
                notify_terminate,
                Arc::new(Notify::new()),
            )
            .expect("the generated PKI should build a process context")
        }

        fn test_database(data_dir: &Path) -> storage::Database {
            let (db_path, db_options) = db_path_and_option(data_dir, 500, 512, 2, 2, false);
            storage::Database::open(&db_path, &db_options).expect("open database")
        }

        /// Waits until every `needle` has appeared in the captured log.
        ///
        /// This is the synchronization the intent-driven tests need. The
        /// cancellation a subsystem now shuts down on stays raised, so an
        /// intent sent too early is no longer lost — but a generation that
        /// ends before its subsystems are up never produces the startup and
        /// shutdown lines those tests assert on. A subsystem announces itself
        /// with no await between the announcement and the wait that follows,
        /// so a subsystem whose line is in the log is serving.
        async fn wait_for_logs(logs: &Arc<Mutex<Vec<u8>>>, needles: &[&str]) {
            let wait = async {
                while !needles.iter().all(|needle| captured(logs).contains(needle)) {
                    sleep(READY_POLL).await;
                }
            };
            assert!(
                tokio::time::timeout(READY_TIMEOUT, wait).await.is_ok(),
                "expected {needles:?} in the log, got: {}",
                captured(logs)
            );
        }

        struct TestQuery;

        #[Object]
        impl TestQuery {
            async fn hello(&self) -> &'static str {
                "world"
            }
        }

        fn test_schema() -> Schema<TestQuery, EmptyMutation, EmptySubscription> {
            Schema::build(TestQuery, EmptyMutation, EmptySubscription).finish()
        }

        /// Everything [`wait_for_generation_end`] waits on, and the handles a
        /// test drives it with.
        ///
        /// The wait needs no database and no subsystems — it is the select
        /// loop and nothing else — so its arms can be exercised one at a time
        /// without paying for a generation.
        struct WaitFixture {
            settings: Settings,
            process: ProcessContext,
            intents: GenerationIntents,
            /// Stands in for the ingest entry task the wait watches.
            ///
            /// The wait needs a handle to borrow, and the tests that drive the
            /// other arms need that handle to stay pending, so the default is
            /// a task that never returns. A test that wants the ingest arm
            /// replaces it.
            ingest_task: JoinHandle<Result<()>>,
            reload_tx: mpsc::Sender<ConfigVisible>,
            notify_terminate: Arc<Notify>,
            notify_reboot: Arc<Notify>,
            notify_power_off: Arc<Notify>,
            notify_tls_reload: Arc<Notify>,
        }

        fn wait_fixture(dir: &Path) -> WaitFixture {
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir, Arc::clone(&notify_terminate));
            let notify_tls_reload = Arc::clone(&process.notify_tls_reload);
            let (reload_tx, reload_rx) = mpsc::channel::<ConfigVisible>(1);
            let notify_reboot = Arc::new(Notify::new());
            let notify_power_off = Arc::new(Notify::new());

            WaitFixture {
                settings: test_settings(dir),
                process,
                intents: GenerationIntents {
                    reload_rx,
                    notify_reboot: Arc::clone(&notify_reboot),
                    notify_power_off: Arc::clone(&notify_power_off),
                },
                ingest_task: task::spawn(std::future::pending::<Result<()>>()),
                reload_tx,
                notify_terminate,
                notify_reboot,
                notify_power_off,
                notify_tls_reload,
            }
        }

        /// Runs the wait with no HTTPS server and an address nothing binds.
        ///
        /// Every arm but the TLS reload ignores both, and the tests that drive
        /// those arms have no server to keep alive.
        async fn wait_without_web(fixture: &mut WaitFixture) -> GenerationEnd {
            let schema = test_schema();
            let mut web_controller = None;
            wait_for_generation_end(
                &mut fixture.settings,
                &fixture.process,
                &mut fixture.intents,
                &mut fixture.ingest_task,
                &mut web_controller,
                &schema,
                ephemeral_addr(),
            )
            .await
        }

        #[tokio::test]
        async fn a_terminate_intent_ends_the_wait() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());

            // `notify_one` leaves a permit behind when nothing is waiting yet,
            // so the intent is already there when the wait first polls it.
            fixture.notify_terminate.notify_one();

            assert_eq!(
                wait_without_web(&mut fixture).await,
                GenerationEnd::Terminate
            );
        }

        #[tokio::test]
        async fn a_reboot_intent_ends_the_wait() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());

            fixture.notify_reboot.notify_one();

            assert_eq!(wait_without_web(&mut fixture).await, GenerationEnd::Reboot);
        }

        #[tokio::test]
        async fn a_power_off_intent_ends_the_wait() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());

            fixture.notify_power_off.notify_one();

            assert_eq!(
                wait_without_web(&mut fixture).await,
                GenerationEnd::PowerOff
            );
        }

        /// The ingest entry task ending is not an intent, but it ends the
        /// wait all the same.
        ///
        /// Nothing is notified here: the only thing that happens is that the
        /// task the wait borrows returns. A wait that ignored it would leave
        /// the generation serving with nothing behind its ingest port.
        #[tokio::test]
        async fn an_ingest_entry_task_that_ends_ends_the_wait() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            fixture.ingest_task = task::spawn(async { Err(anyhow!("the listener is gone")) });

            let (logs, _guard) = capture_logs();
            assert_eq!(
                wait_without_web(&mut fixture).await,
                GenerationEnd::IngestExited
            );

            // The task reports its own `Err`; a stand-in cannot, so what this
            // asserts is the silence that keeps the real one from being
            // reported twice.
            let output = captured(&logs);
            assert!(
                !output.contains("Ingest subsystem returned before"),
                "an entry task that returned an error is not one that returned cleanly, got: {output}"
            );
        }

        /// A panicking entry task ends the wait too, and says what the task
        /// itself could not.
        #[tokio::test]
        async fn a_panicking_ingest_entry_task_ends_the_wait() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            fixture.ingest_task = task::spawn(async { panic!("the ingest entry task panicked") });

            let (logs, _guard) = capture_logs();
            assert_eq!(
                wait_without_web(&mut fixture).await,
                GenerationEnd::IngestExited
            );

            let output = captured(&logs);
            assert!(
                output.contains("Ingest task did not join"),
                "a panic is the outcome only the handle carries, got: {output}"
            );
        }

        #[tokio::test]
        async fn a_persisted_configuration_reload_ends_the_wait() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            write_config_file(&fixture.settings);

            let mut new_config = fixture.settings.config.visible.clone();
            new_config.ack_transmission = 2048;
            fixture
                .reload_tx
                .send(new_config)
                .await
                .expect("the wait should still hold the receiver");

            assert_eq!(
                wait_without_web(&mut fixture).await,
                GenerationEnd::ReloadConfig
            );
            // The reload is what the next generation starts from, so the wait
            // must leave the persisted settings behind it.
            assert_eq!(fixture.settings.config.visible.ack_transmission, 2048);
        }

        /// A reload that cannot be written down is not a shutdown.
        ///
        /// `cfg_path` names a file that was never created, so the backup that
        /// precedes the rewrite fails and the generation keeps serving the
        /// configuration it started with — until a terminate intent ends it
        /// for real.
        #[tokio::test]
        async fn a_configuration_reload_that_cannot_be_persisted_keeps_serving() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            let notify_terminate = Arc::clone(&fixture.notify_terminate);
            let reload_tx = fixture.reload_tx.clone();
            let mut new_config = fixture.settings.config.visible.clone();
            new_config.ack_transmission = 2048;

            let (logs, _guard) = capture_logs();
            let (end, ()) = tokio::join!(wait_without_web(&mut fixture), async {
                reload_tx
                    .send(new_config)
                    .await
                    .expect("the wait should still hold the receiver");
                wait_for_logs(&logs, &["Failed to update configuration"]).await;
                notify_terminate.notify_one();
            });

            assert_eq!(end, GenerationEnd::Terminate);
            assert_eq!(
                fixture.settings.config.visible.ack_transmission, 1024,
                "a reload that was not persisted must not change the in-memory configuration"
            );
        }

        /// A TLS reload rebinds the HTTPS server and keeps serving.
        ///
        /// It is the one arm that does not end the generation, so the wait has
        /// to come back around and still be able to observe the next intent.
        #[tokio::test]
        async fn a_tls_reload_intent_keeps_serving() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            let notify_terminate = Arc::clone(&fixture.notify_terminate);
            let notify_tls_reload = Arc::clone(&fixture.notify_tls_reload);
            let schema = test_schema();
            let mut web_controller = None;
            let web_addr = free_addr();

            let (logs, _guard) = capture_logs();
            let (end, ()) = tokio::join!(
                wait_for_generation_end(
                    &mut fixture.settings,
                    &fixture.process,
                    &mut fixture.intents,
                    &mut fixture.ingest_task,
                    &mut web_controller,
                    &schema,
                    web_addr,
                ),
                async {
                    notify_tls_reload.notify_one();
                    wait_for_logs(&logs, &["HTTPS reload: new GraphQL server started"]).await;
                    notify_terminate.notify_one();
                }
            );

            assert_eq!(end, GenerationEnd::Terminate);
            assert!(
                web_controller.is_some(),
                "the reload should have left a live server behind"
            );
            shutdown_web(web_controller.take()).await;
        }

        /// The tail of a generation that is not shutting the host down.
        ///
        /// It only waits out `SERVER_REBOOT_DELAY`, and the database handle is
        /// left for the caller to drop. Time is paused, so the delay costs no
        /// wall-clock time.
        #[tokio::test(start_paused = true)]
        async fn a_reload_or_terminate_tail_leaves_the_database_open() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            let (logs, _guard) = capture_logs();
            finish_generation(GenerationEnd::Terminate, &database)
                .await
                .expect("the terminate tail should not fail");

            assert!(
                !captured(&logs).contains("Before shut down the system"),
                "only a reboot or a power-off waits for the host"
            );
        }

        /// The tail of a generation that is handing the host to `roxy`.
        ///
        /// Time is paused, so the `WAIT_SHUTDOWN` pause it takes before the
        /// host goes down costs no wall-clock time.
        #[tokio::test(start_paused = true)]
        async fn a_reboot_tail_flushes_the_database() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            let (logs, _guard) = capture_logs();
            finish_generation(GenerationEnd::Reboot, &database)
                .await
                .expect("the reboot tail should flush the database");

            assert!(
                captured(&logs).contains("Before shut down the system"),
                "the reboot tail should announce the wait it takes before handing over the host"
            );
        }

        /// The database is not closed while retention still holds it.
        ///
        /// The stand-in retention task is written the way the real one is: it
        /// waits for cancellation, and then waits out a cleanup already
        /// running on the blocking pool before returning. The shutdown
        /// sequence must not reach `database.shutdown()` until that blocking
        /// cleanup has finished, so the test releases the blocking work only
        /// after checking that the sequence is still waiting, and reads the
        /// log line that follows the flush as the marker for it.
        #[tokio::test]
        async fn the_database_is_not_closed_until_retention_has_stopped() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);
            let tracker = TaskTracker::new();

            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let cleanup_started = Arc::new(AtomicBool::new(false));
            let cleanup_finished = Arc::new(AtomicBool::new(false));
            let retain_task_handle: JoinHandle<Result<()>> = tracker
                .spawn("retention", {
                    let db = database.clone();
                    let cleanup_started = Arc::clone(&cleanup_started);
                    let cleanup_finished = Arc::clone(&cleanup_finished);
                    move |cancel| async move {
                        cancel.cancelled().await;
                        // The handle is awaited, never aborted: the blocking
                        // cleanup holds a database handle.
                        task::spawn_blocking(move || {
                            cleanup_started.store(true, Ordering::SeqCst);
                            let _ = release_rx.recv();
                            // Touching the store is the point: it is what
                            // would race a database closed too early.
                            db.sensors_store().expect("sensors store");
                            cleanup_finished.store(true, Ordering::SeqCst);
                        })
                        .await?;
                        Ok(())
                    }
                })
                .expect("a fresh tracker admits the retention task");

            let (logs, _guard) = capture_logs();
            let shutdown = task::spawn({
                let tracker = tracker.clone();
                let database = database.clone();
                async move {
                    shutdown_generation(
                        &tracker,
                        retain_task_handle,
                        None,
                        GenerationEnd::Reboot,
                        &database,
                    )
                    .await
                }
            });

            // Cancellation has to reach the stand-in and its blocking cleanup
            // has to be running before the ordering under test means anything.
            let started = async {
                while !cleanup_started.load(Ordering::SeqCst) {
                    sleep(READY_POLL).await;
                }
            };
            assert!(
                tokio::time::timeout(READY_TIMEOUT, started).await.is_ok(),
                "the drain should have cancelled the retention stand-in"
            );

            // A shutdown that did not wait would have flushed by now: the
            // drain is the only thing between it and the tail.
            sleep(Duration::from_millis(100)).await;
            assert!(
                !captured(&logs).contains("Before shut down the system"),
                "the database was closed while a blocking cleanup was still running"
            );

            release_tx
                .send(())
                .expect("the blocking cleanup is waiting");
            wait_for_logs(&logs, &["Before shut down the system"]).await;
            assert!(
                cleanup_finished.load(Ordering::SeqCst),
                "the blocking cleanup should have run to the end before the flush"
            );
            let output = captured(&logs);
            assert!(
                output.contains("Retention stopped"),
                "the retention handle should have been read, got: {output}"
            );

            // What is left of the tail is the pause before the host goes down,
            // and this test is not waiting it out.
            shutdown.abort();
        }

        /// A retention failure is reported when it happens, not at shutdown.
        ///
        /// The generation's accounting for the retention handle runs only when
        /// the generation ends, so on a node that is simply left running an
        /// error reported only there would sit unread for as long as the node
        /// stays up. The retention period used here overflows the nanosecond
        /// arithmetic the entry task does before its first tick, which is the
        /// cheapest failure that reaches the same return path a failed cleanup
        /// pass does.
        #[tokio::test]
        async fn a_retention_failure_is_reported_when_it_happens() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            let (logs, _guard) = capture_logs();
            let result = run_retention(
                ONE_DAY,
                Duration::from_secs(u64::MAX),
                database,
                CancellationToken::new(),
            )
            .await;

            assert!(
                result.is_err(),
                "a retention period that cannot be expressed in nanoseconds should fail"
            );
            let output = captured(&logs);
            assert!(
                output.contains("Retention terminated unexpectedly"),
                "the failure should be reported where it happened, got: {output}"
            );
        }

        /// A data directory whose compression setting no longer matches the
        /// configuration ends the generation before the database is opened.
        #[tokio::test]
        async fn a_generation_refuses_a_changed_compression_setting() {
            let dir = tempdir().expect("tempdir");
            let process = test_process_context(dir.path(), Arc::new(Notify::new()));
            let mut settings = test_settings(dir.path());
            fs::write(
                settings.config.visible.data_dir.join("COMPRESSION"),
                "enabled",
            )
            .expect("write compression metadata");

            let (logs, _guard) = capture_logs();
            let error = run_generation(&mut settings, &process)
                .await
                .expect_err("a compression mismatch should end the generation");

            assert!(error.to_string().contains("compression validation failed"));
            assert!(
                captured(&logs).contains("Compression validation failed"),
                "the mismatch itself should be reported, not just the summary"
            );
        }

        /// A data directory written by a release too old to migrate from ends
        /// the generation before the database is opened.
        #[tokio::test]
        async fn a_generation_stops_when_the_data_directory_cannot_be_migrated() {
            let dir = tempdir().expect("tempdir");
            let process = test_process_context(dir.path(), Arc::new(Notify::new()));
            let mut settings = test_settings(dir.path());
            fs::write(settings.config.visible.data_dir.join("VERSION"), "0.1.0")
                .expect("write version file");

            let (logs, _guard) = capture_logs();
            let error = run_generation(&mut settings, &process)
                .await
                .expect_err("an unsupported data directory should end the generation");

            assert!(error.to_string().contains("migration failed"));
            assert!(
                captured(&logs).contains("Migration failed"),
                "the migration error itself should be reported, not just the summary"
            );
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
                .expect("a terminate intent should end the generation")
                .expect("the generation should not fail");

            assert_eq!(end, GenerationEnd::Terminate);

            let output = captured(&logs);
            assert!(
                output.contains("Termination signal: daemon exit"),
                "the terminate arm should have run, got: {output}"
            );
            // Ingest, publish, and retention are the tasks in the top-level
            // tracker, and all of them stop on the cancellation the drain
            // delivers, so the drain returns on its first round with nothing
            // to report.
            assert!(
                output.contains("Retention stopped"),
                "the retention task should have stopped cleanly, got: {output}"
            );
            // Nothing here joins a publish handle, and publish no longer
            // listens on `notify_shutdown`, so this line can only come from
            // the token the top-level tracker handed its entry task.
            assert!(
                output.contains("Shutting down publish"),
                "the generation's cancellation should reach publish, got: {output}"
            );
            assert!(
                !output.contains("shutdown drain round"),
                "a tracker that drains at once should not report a round, got: {output}"
            );
            assert!(
                !output.contains("shutdown drain complete"),
                "a tracker that drains at once should not report progress, got: {output}"
            );
            assert!(
                !output.contains("tracked task did not run to completion"),
                "the tracked tasks should have returned, not vanished, got: {output}"
            );
        }

        /// A generation with the peer subsystem configured and no HTTPS
        /// server.
        ///
        /// `peer_srv_addr` is set, so the branch that builds and spawns the
        /// peer subsystem runs; the GraphQL address is one this test is
        /// already listening on, so `web::serve` fails and the generation
        /// carries on without a web server — which is what production does
        /// when the port is taken.
        #[tokio::test]
        async fn a_generation_serves_peers_and_survives_a_failed_web_bind() {
            let dir = tempdir().expect("tempdir");
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir.path(), Arc::clone(&notify_terminate));
            let mut settings = test_settings(dir.path());
            settings.config.peer_srv_addr = Some(ephemeral_addr());
            settings.config.peers = Some(HashSet::new());
            write_config_file(&settings);

            let occupied = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("occupy the GraphQL port");
            settings.config.visible.graphql_srv_addr =
                occupied.local_addr().expect("occupied addr");

            let (logs, _guard) = capture_logs();
            let (end, ()) = tokio::join!(
                tokio::time::timeout(GENERATION_TIMEOUT, run_generation(&mut settings, &process)),
                async {
                    wait_for_logs(
                        &logs,
                        &[
                            "Ingest listening on",
                            "Publish listening on",
                            // The peer subsystem logs a bare `listening on`,
                            // so the level that precedes it is what tells it
                            // apart from the two lines above.
                            "INFO listening on",
                            "Database cleanup completed.",
                        ],
                    )
                    .await;
                    notify_terminate.notify_one();
                }
            );
            let end = end
                .expect("a terminate intent should end the generation")
                .expect("the generation should not fail");

            assert_eq!(end, GenerationEnd::Terminate);

            let output = captured(&logs);
            assert!(
                output.contains("Failed to start GraphQL server"),
                "the taken port should have been reported, got: {output}"
            );
            assert!(
                output.contains("Shutting down peer"),
                "the peer subsystem should have been joined, got: {output}"
            );
            // Peer is registered in the top-level tracker, so a peer task
            // still running when the generation moved on would show up as a
            // pending round in one of the two drains.
            assert!(
                !output.contains("shutdown drain round"),
                "the top-level drain should not have reported a pending task, got: {output}"
            );
            assert!(
                !output.contains("peer drain round"),
                "the peer drain should not have reported a pending task, got: {output}"
            );
            assert!(
                !output.contains("tracked task did not run to completion"),
                "every peer task should have returned, not vanished, got: {output}"
            );
        }

        /// A peer subsystem that ends on its own does not take the generation
        /// with it.
        ///
        /// The configuration file is never written, so the peer subsystem
        /// fails the read it performs on startup and returns an error instead
        /// of parking. The generation keeps serving, reports the failure, and
        /// still ends on the intent it is given.
        #[tokio::test]
        async fn a_generation_reports_a_peer_subsystem_that_ended_early() {
            let dir = tempdir().expect("tempdir");
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir.path(), Arc::clone(&notify_terminate));
            let mut settings = test_settings(dir.path());
            settings.config.peer_srv_addr = Some(ephemeral_addr());

            let (logs, _guard) = capture_logs();
            let (end, ()) = tokio::join!(
                tokio::time::timeout(GENERATION_TIMEOUT, run_generation(&mut settings, &process)),
                async {
                    wait_for_logs(
                        &logs,
                        &[
                            "Ingest listening on",
                            "Publish listening on",
                            "Peer subsystem terminated unexpectedly",
                            "Database cleanup completed.",
                        ],
                    )
                    .await;
                    notify_terminate.notify_one();
                }
            );
            let end = end
                .expect("a terminate intent should end the generation")
                .expect("a failed peer subsystem should not fail the generation");

            assert_eq!(end, GenerationEnd::Terminate);
        }

        /// An ingest entry task that ends on its own takes the generation
        /// down with it.
        ///
        /// The address it is told to bind is already held by a UDP socket this
        /// test keeps open, so `Endpoint::server` fails and the entry task
        /// returns before the generation has even reached its steady state.
        /// Nothing is notified here — no terminate intent is ever sent — so
        /// the only thing that can end this generation is the entry task
        /// itself. A node left serving GraphQL and publish while ingesting
        /// nothing would instead sit here until `GENERATION_TIMEOUT`.
        #[tokio::test]
        async fn an_ingest_listener_that_cannot_bind_ends_the_generation() {
            let dir = tempdir().expect("tempdir");
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir.path(), Arc::clone(&notify_terminate));
            let mut settings = test_settings(dir.path());

            // QUIC is UDP, so the port has to be held by a UDP socket for the
            // ingest listener to lose it.
            let occupied = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("occupy the ingest port");
            settings.config.visible.ingest_srv_addr = occupied.local_addr().expect("occupied addr");

            let (logs, _guard) = capture_logs();
            let end =
                tokio::time::timeout(GENERATION_TIMEOUT, run_generation(&mut settings, &process))
                    .await
                    .expect("a failed ingest listener should end the generation on its own")
                    .expect("the generation reports the early exit through its end, not an error");

            assert_eq!(end, GenerationEnd::IngestExited);

            let output = captured(&logs);
            assert!(
                output.contains("failed to bind the ingest listener"),
                "the bind failure itself should be reported, got: {output}"
            );
            assert!(
                output.contains("Ingest subsystem terminated unexpectedly"),
                "the entry task should report its own error, got: {output}"
            );
            assert!(
                !output.contains("Ingest task did not join"),
                "the entry task returned, it did not panic, got: {output}"
            );
            // The generation still went down the common shutdown sequence:
            // the subsystems it did start were notified and the drain ran.
            assert!(
                output.contains("Shutting down publish"),
                "the early exit should run the same shutdown sequence as an intent, got: {output}"
            );
        }

        /// A sensor ingests through a whole generation, and the generation
        /// releases it.
        ///
        /// Everything above drives ingest either as a bare entry task or from
        /// the outside; this is the seam between the two. The sensor connects
        /// to the listener the generation bound, its event is acknowledged by
        /// the generation's own store, and its connection is still open when
        /// the terminate intent arrives. So the generation has to cancel it:
        /// the top-level drain waits for the ingest entry task, which waits in
        /// turn for this connection's handler, and a connection nothing
        /// released would hold the generation until `GENERATION_TIMEOUT`
        /// rather than ending on the intent. That the event is readable from
        /// a reopened data directory afterwards is the other half — the
        /// generation let go of the database only once ingest was done with
        /// it.
        #[tokio::test]
        async fn a_generation_ingests_from_a_sensor_and_releases_it_on_terminate() {
            use giganto_client::{
                RawEventKind,
                connection::client_handshake,
                frame::send_raw,
                ingest::{log::Log, receive_ack_timestamp, send_record_header},
            };

            use crate::server::config_client;

            const TIMESTAMP: i64 = 1_700_000_000_000_000_000;

            let dir = tempdir().expect("tempdir");
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir.path(), Arc::clone(&notify_terminate));
            let mut settings = test_settings(dir.path());
            // The sensor has to name the listener before the generation binds
            // it, and an ephemeral port is only known afterwards.
            let ingest_addr = free_addr();
            settings.config.visible.ingest_srv_addr = ingest_addr;
            // One event per acknowledgement, so a single batch is enough to
            // get a reply back and the test needs no second sync point.
            settings.config.visible.ack_transmission = 1;
            let data_dir = settings.config.visible.data_dir.clone();

            let log = Log {
                kind: String::from("generation ingest test"),
                log: vec![7; 8],
            };
            let expected = bincode::serialize(&log).expect("serialize the log body");

            let (logs, _guard) = capture_logs();
            let (end, conn) = tokio::join!(
                tokio::time::timeout(GENERATION_TIMEOUT, run_generation(&mut settings, &process)),
                async {
                    wait_for_logs(
                        &logs,
                        &["Ingest listening on", "Database cleanup completed."],
                    )
                    .await;

                    // Bound on IPv4 because the listener is: quinn will not
                    // send from a v6 socket to a v4 peer.
                    let mut endpoint =
                        quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                            .expect("create the sensor endpoint");
                    let certs =
                        Arc::clone(&tls_reload::get_current_tls_material(&process.tls_watch).certs);
                    endpoint.set_default_client_config(
                        config_client(&certs).expect("build the sensor client config"),
                    );
                    let conn = endpoint
                        .connect(ingest_addr, "001.giganto.node1.example.test")
                        .expect("the sensor client config should build")
                        .await
                        .expect("the sensor should reach the ingest listener");
                    client_handshake(&conn, env!("CARGO_PKG_VERSION"))
                        .await
                        .expect("the version handshake should succeed");

                    let (mut send, mut recv) =
                        conn.open_bi().await.expect("open the sensor stream");
                    send_record_header(&mut send, RawEventKind::Log)
                        .await
                        .expect("send the record header");
                    let batch = bincode::serialize(&vec![(TIMESTAMP, expected.clone())])
                        .expect("serialize the log batch");
                    send_raw(&mut send, &batch).await.expect("send the log");
                    let acked =
                        tokio::time::timeout(READY_TIMEOUT, receive_ack_timestamp(&mut recv))
                            .await
                            .expect("the generation should acknowledge the event")
                            .expect("the acknowledgement should decode");
                    assert_eq!(acked, TIMESTAMP);

                    // The connection is deliberately left open across the
                    // intent, and `conn` is returned so it stays open: this is
                    // what the generation's drain has to cancel.
                    notify_terminate.notify_one();
                    conn
                }
            );
            let end = end
                .expect("a live sensor connection should not hold the generation open")
                .expect("the generation should not fail");
            assert_eq!(end, GenerationEnd::Terminate);
            drop(conn);

            let output = captured(&logs);
            assert!(
                output.contains("Shutting down ingest"),
                "the ingest listener should have observed cancellation, got: {output}"
            );

            let reopened = test_database(Path::new(&data_dir));
            let stored: Vec<Vec<u8>> = reopened
                .log_store()
                .expect("open the log store")
                .iter_forward()
                .filter_map(|entry| entry.ok().map(|(_, value)| value.to_vec()))
                .collect();
            assert_eq!(
                stored,
                vec![expected],
                "the event the generation acknowledged did not survive its shutdown"
            );
        }
    }
}
