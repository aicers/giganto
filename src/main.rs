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
    fs::OpenOptions, ops::ControlFlow, path::Path, process::exit, sync::Arc, time::Duration,
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

/// Drain label for the web-owned PCAP reaper tracker, distinct from the
/// top-level label so a shutdown waiting on a `tcpdump` reaper is told apart
/// from one waiting on a tracked subsystem.
const WEB_REAPER_DRAIN_LABEL: &str = "web PCAP reaper";

/// Prefix every phase marker of the shutdown sequence carries.
///
/// The sequence is otherwise nearly silent on a clean shutdown, so these are
/// what say which phase a stalled shutdown is stuck in — and what lets a test
/// pull the whole sequence out of a captured log by filtering on one string.
/// It is deliberately not a prefix of the drain's own round reports, which
/// name their tracker instead.
const SHUTDOWN_PHASE: &str = "shutdown phase";

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

    // The seam is built here and lent to the lifecycle rather than
    // constructed inside it: a lifecycle that owned its own production effects
    // could never be driven by a test without a second, test-only entry point,
    // and the two would drift.
    run_lifecycle(&mut settings, &process, &HostEffects).await
}

/// The effects the lifecycle performs on something outside its own control
/// flow.
///
/// Shutting the store down, rebooting the host and powering it off are grouped
/// into one seam because they are the three things a test has to be able to
/// watch happen, watch not happen, and make fail. All three are synchronous;
/// the lifecycle awaits nothing through this trait. It is `Send + Sync`
/// because the teardown holds a reference to it across awaits and the futures
/// that do so have to be spawnable.
trait LifecycleEffects: Send + Sync {
    /// Flushes the store, writes its WAL and cancels its background work.
    ///
    /// This does not close the database and does not release RocksDB's file
    /// `LOCK`: the lock goes when the last [`storage::Database`] clone is
    /// dropped, which happens as the generation returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the store could not be flushed. That is the one
    /// outcome the lifecycle refuses to follow with a host action or a new
    /// generation.
    fn shutdown_database(&self, database: &storage::Database) -> Result<()>;

    /// Reboots the host.
    ///
    /// # Errors
    ///
    /// Returns an error if the host refused the request.
    fn reboot(&self) -> Result<()>;

    /// Powers the host off.
    ///
    /// # Errors
    ///
    /// Returns an error if the host refused the request.
    fn power_off(&self) -> Result<()>;
}

/// The production seam: the real store and the real host.
struct HostEffects;

impl LifecycleEffects for HostEffects {
    fn shutdown_database(&self, database: &storage::Database) -> Result<()> {
        database.shutdown()
    }

    fn reboot(&self) -> Result<()> {
        roxy::reboot()
            .map(|_| ())
            .map_err(|e| anyhow!("cannot restart the system: {e}"))
    }

    fn power_off(&self) -> Result<()> {
        roxy::power_off()
            .map(|_| ())
            .map_err(|e| anyhow!("cannot power off the system: {e}"))
    }
}

/// Runs generations until one of them ends the process.
///
/// This is the whole of the process lifecycle: it starts a generation, takes
/// the action the generation's ending asks for, and either comes back around
/// for another generation or returns. `main` keeps only argument parsing,
/// process-wide setup, and the call into here.
///
/// The order of the two steps is the point. [`run_generation`] returns only
/// after it has dropped every [`storage::Database`] clone it held, and only
/// then does [`act_on_generation_end`] run: a reload's next generation reopens
/// the same path, and `Database::open` fails while a clone of the previous one
/// is alive. Reboot and power-off do not depend on that drop the way a reload
/// does, but they take the same position so that one order holds for every
/// ending.
///
/// # Errors
///
/// Returns an error if a generation failed, if the store could not be shut
/// down, if the host refused a reboot or a power-off, or if the ingest entry
/// task ended on its own.
async fn run_lifecycle(
    settings: &mut Settings,
    process: &ProcessContext,
    effects: &dyn LifecycleEffects,
) -> Result<()> {
    loop {
        let generation_end = run_generation(settings, process, effects).await?;
        match act_on_generation_end(generation_end, effects)? {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(()) => return Ok(()),
        }
    }
}

/// Takes the one action a generation's ending asks for, and says whether the
/// lifecycle carries on.
///
/// This runs immediately after the teardown has returned, so it is the last
/// step of the observable shutdown sequence and the only one that reaches
/// outside the process. Everything before it is identical for every ending.
///
/// # Errors
///
/// Returns an error if the host refused the reboot or the power-off, or if the
/// generation ended because the ingest entry task did: nobody asked for that
/// one, so the process manager is told the exit was not wanted.
fn act_on_generation_end(
    generation_end: GenerationEnd,
    effects: &dyn LifecycleEffects,
) -> Result<ControlFlow<()>> {
    match generation_end {
        GenerationEnd::ReloadConfig => {
            info!(
                "{SHUTDOWN_PHASE}: final action, starting the next generation ({generation_end:?})"
            );
            Ok(ControlFlow::Continue(()))
        }
        GenerationEnd::Terminate => {
            info!(
                "{SHUTDOWN_PHASE}: final action, returning from the lifecycle ({generation_end:?})"
            );
            Ok(ControlFlow::Break(()))
        }
        GenerationEnd::Reboot => {
            info!("{SHUTDOWN_PHASE}: final action, rebooting the host ({generation_end:?})");
            effects.reboot()?;
            Ok(ControlFlow::Break(()))
        }
        GenerationEnd::PowerOff => {
            info!("{SHUTDOWN_PHASE}: final action, powering the host off ({generation_end:?})");
            effects.power_off()?;
            Ok(ControlFlow::Break(()))
        }
        // The generation has already drained and closed itself down; what is
        // left is to tell the process manager that this exit was not asked
        // for, so a unit configured to restart on failure does. What failed
        // was reported where it happened.
        GenerationEnd::IngestExited => {
            info!("{SHUTDOWN_PHASE}: final action, failing the lifecycle ({generation_end:?})");
            Err(anyhow!("the ingest subsystem ended before the daemon did"))
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
/// as final. Each one names a different final action for
/// [`act_on_generation_end`] to take.
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
    /// intents, and the lifecycle reports it as a failure rather than
    /// returning cleanly. Ingest is the only entry task the tracker watches
    /// for now: peer and publish are registered in the tracker but their
    /// handles are not kept, so an early exit of either goes unwatched until
    /// the entry-task supervision issue retains them.
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
/// [`run_lifecycle`] keeps only the loop and acts on the returned
/// [`GenerationEnd`].
///
/// # Errors
///
/// Returns an error if the data directory fails compression validation or
/// migration, if the database cannot be opened, if the node certificate
/// carries no usable node name, if the peer subsystem cannot be built, or if
/// the teardown could not shut the store down.
#[allow(clippy::too_many_lines)]
async fn run_generation(
    settings: &mut Settings,
    process: &ProcessContext,
    effects: &dyn LifecycleEffects,
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

    // A separate, web-owned tracker for the PCAP resolver's `tcpdump`-reaping
    // tasks. It is drained as part of web shutdown (right after `shutdown_web`
    // below), before the top-level tracker is cancelled and drained, so a PCAP
    // request cut off by the web graceful-shutdown timeout has its child killed
    // and reaped before subsystem cancellation begins. Kept out of the top-level
    // tracker precisely because that one is cancelled and drained *after* web
    // shutdown; a reaper registered there would be waited too late.
    let web_reaper_tracker = TaskTracker::new();

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
        top_level_tracker.clone(),
        web_reaper_tracker.clone(),
    );

    let web_addr = settings.config.visible.graphql_srv_addr;
    let web_shutdown_timeout = settings.config.web_shutdown_timeout;
    let mut web_controller: Option<WebController> = match web::serve(
        schema.clone(),
        web_addr,
        tls.cert_pem.clone(),
        tls.key_pem.clone(),
        tls.ca_pem.clone(),
        web_shutdown_timeout,
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
    // closure argument, which is the only thing its shutdown travels on.
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
    // early exit, and supervising that belongs to the issue that retains and
    // reports on every entry task's handle.
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
    // exit. Acting on that — a node that keeps serving without publish —
    // belongs to the entry-task supervision issue, which is also why no
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
        web_shutdown_timeout,
    )
    .await;

    // Every ending is shut down the same way, so the whole sequence is one
    // call rather than a step per arm. Nothing is cancelled here: the only
    // cancellation of the top-level tracker is the close-then-cancel inside
    // the drain, so the tracker is never left cancelled but still admitting.
    shutdown_generation(
        GenerationTeardown {
            web_controller: web_controller.take(),
            web_reaper_tracker,
            top_level_tracker,
            retain_task_handle,
            // Handed over only when the wait ended on something else. If the
            // entry task is what ended it, its arm has already read the handle
            // back and reported it, and a `JoinHandle` polled again after it
            // has completed is not a handle that resolves a second time.
            ingest_task_handle: (generation_end != GenerationEnd::IngestExited)
                .then_some(ingest_task_handle),
        },
        generation_end,
        &database,
        effects,
    )
    .await?;

    // Returning is what releases the store. The teardown flushed it; the file
    // `LOCK` goes only when the last `Database` clone is dropped, and the
    // clones this generation still holds — its own handle, the schema's, the
    // listeners' — go here. That guarantee is exactly as wide as the tracker's
    // registry: work that never entered it, such as the untracked
    // customer-deletion worker, can still hold a clone past this point.
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
#[allow(clippy::too_many_arguments)]
async fn wait_for_generation_end<S>(
    settings: &mut Settings,
    process: &ProcessContext,
    intents: &mut GenerationIntents,
    ingest_task: &mut JoinHandle<Result<()>>,
    web_controller: &mut Option<WebController>,
    schema: &S,
    web_addr: std::net::SocketAddr,
    web_shutdown_timeout: Duration,
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
                    web_shutdown_timeout,
                ).await;
            }
        }
    }
}

/// Everything a generation hands to its teardown.
///
/// The teardown takes ownership of all of it: the web controller it shuts
/// down, the two trackers it drains, and the two handles it reads back. They
/// travel together because the teardown is one unit — grouping them is also
/// what keeps its parameter list within reach of a test that builds one by
/// hand.
struct GenerationTeardown {
    /// The HTTPS GraphQL server, or `None` when the bind failed and the
    /// generation carried on without one.
    web_controller: Option<WebController>,
    /// The web-owned tracker holding the PCAP `tcpdump` reaping.
    web_reaper_tracker: TaskTracker,
    /// The generation's own tracker, holding every subsystem and every
    /// long-running piece of web-origin work.
    top_level_tracker: TaskTracker,
    /// The retention entry task.
    retain_task_handle: JoinHandle<Result<()>>,
    /// The ingest entry task, or `None` when the generation ended because that
    /// very task returned: the wait has already read the handle back, and a
    /// `JoinHandle` polled again after it has completed is not a handle that
    /// resolves a second time.
    ingest_task_handle: Option<JoinHandle<Result<()>>>,
}

/// Runs the whole teardown of a generation, in the one order every ending
/// shares.
///
/// Five phases, and only the tail after the last of them differs by ending:
/// web shutdown, the web reaper drain, the top-level tracker's
/// close-cancel-drain, the retained-handle observation, and the database
/// shutdown. Each phase leaves a marker behind, so a shutdown that stalls says
/// which phase it stalled in and a test can read the sequence back out of one
/// log.
///
/// The order is the whole of it. The drain closes the tracker, cancels it, and
/// does not return until every tracked task has returned, so the retention and
/// ingest entry tasks — and with them any cleanup still running on the
/// blocking pool or any handler still writing — have stopped before their
/// handles are read and before the store is shut down. Retention holds a
/// database handle on a blocking thread; flushing the store while it still ran
/// would pull it out from under a live RocksDB operation, which is why nothing
/// here is reordered.
///
/// What that ordering buys is bounded by the tracker's registry: shutting the
/// database down is not closing it, and the file `LOCK` is released only when
/// the last [`storage::Database`] clone is dropped as the generation returns,
/// so work that never entered the tracker can still hold a clone past this
/// point.
///
/// # Errors
///
/// Returns an error if the database could not be shut down. A retained handle
/// that came back badly is reported, not returned: the drain has already
/// waited for that task, and its failure does not suppress the later database
/// shutdown phase or the ending's requested action. A database-shutdown
/// failure returns before that action.
async fn shutdown_generation(
    teardown: GenerationTeardown,
    generation_end: GenerationEnd,
    database: &storage::Database,
    effects: &dyn LifecycleEffects,
) -> Result<()> {
    let GenerationTeardown {
        web_controller,
        web_reaper_tracker,
        top_level_tracker,
        retain_task_handle,
        ingest_task_handle,
    } = teardown;

    shutdown_web(web_controller).await;
    info!("{SHUTDOWN_PHASE}: web shutdown returned ({generation_end:?})");
    // Web shutdown is not complete until the `tcpdump` children of any PCAP
    // requests the graceful-shutdown timeout cut off have been reaped. Draining
    // the web-owned reaper tracker here waits for them before subsystem
    // cancellation and drain begin, so a timed-out PCAP child is killed and
    // reaped ahead of the drain rather than as detached work that could outlive
    // web shutdown. The placement is cheap only because that tracker holds
    // nothing but the reaping: a long-running job registered there would
    // serialize the whole of subsystem cancellation behind it, which is why
    // long-running web-origin work goes in the top-level tracker instead.
    drain_web_reaper_tracker_or_log(&web_reaper_tracker).await;
    info!("{SHUTDOWN_PHASE}: web reaper drain returned ({generation_end:?})");
    drain_top_level_tracker_or_log(&top_level_tracker).await;
    info!("{SHUTDOWN_PHASE}: top-level drain returned ({generation_end:?})");
    report_retention_outcome(retain_task_handle).await;
    if let Some(ingest_task_handle) = ingest_task_handle {
        observe_ingest_shutdown(ingest_task_handle).await;
    }
    info!("{SHUTDOWN_PHASE}: retained handles read ({generation_end:?})");
    finish_generation(generation_end, database, effects).await
}

/// Runs the retention entry task, reporting a failure the moment it happens.
///
/// The handle the generation retains carries whatever this returns to
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
/// the report the last retention observation before database shutdown.
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

/// Shuts the store down, then runs the tail the ending asks for.
///
/// By the time this runs the subsystems have been cancelled and joined and the
/// top-level tracker has drained, so nothing tracked is left holding the
/// database and the flush cannot be surprised by a retention cleanup on a
/// blocking thread. The shutdown itself runs on every ending, before the tail,
/// so the flush, the WAL write and the cancellation of background work happen
/// once and unconditionally.
///
/// It does not close the database and does not release RocksDB's file `LOCK`:
/// the lock goes when the last [`storage::Database`] clone is dropped, as the
/// generation returns.
///
/// The marker is emitted before the seam is called, not after it returns: it
/// records that the phase was entered, so it is there whether the shutdown
/// succeeds or fails. What says it succeeded is the lifecycle carrying on.
///
/// # Errors
///
/// Returns an error if the store could not be shut down. Its on-disk state is
/// then unknown, so the caller must take no host action and start no further
/// generation on that path.
async fn finish_generation(
    generation_end: GenerationEnd,
    database: &storage::Database,
    effects: &dyn LifecycleEffects,
) -> Result<()> {
    info!("{SHUTDOWN_PHASE}: shutting the database down ({generation_end:?})");
    if let Err(e) = effects.shutdown_database(database) {
        error!("Database shutdown failed: {e:#}");
        return Err(e);
    }

    match generation_end {
        GenerationEnd::ReloadConfig | GenerationEnd::Terminate | GenerationEnd::IngestExited => {
            sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
        }
        // The host is about to go down, so the pause that precedes handing it
        // over is the whole of this tail.
        GenerationEnd::Reboot | GenerationEnd::PowerOff => {
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
    web_shutdown_timeout: Duration,
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
        web_shutdown_timeout,
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

/// Drains the web-owned PCAP reaper tracker as the final step of web shutdown,
/// before the top-level tracker is cancelled and drained.
///
/// Waiting here is what turns the PCAP endpoint's "kill *and* await" contract
/// into an ordering guarantee: a request cut off by the web graceful-shutdown
/// timeout registers its `tcpdump` child's kill-and-reap on this tracker, and
/// draining it now makes that reaping complete before subsystem cancellation
/// begins rather than racing it as detached work. The reaper ignores its
/// cancellation token — `drain_with_report` cancels the tracker's children, but
/// a `SIGKILL` followed by `wait()` must not be abandoned mid-reap — so the
/// drain waits for the reap itself, bounded only by how long the kernel takes to
/// reap a `SIGKILL`ed child. A poisoned lock is logged rather than propagated,
/// the same policy as the top-level drain, so the rest of shutdown still runs.
async fn drain_web_reaper_tracker_or_log(tracker: &TaskTracker) {
    if let Err(e) = drain_with_report(tracker, DRAIN_REPORT_INTERVAL, WEB_REAPER_DRAIN_LABEL).await
    {
        error!("shutdown drain could not read the web PCAP reaper tracker: {e}");
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
        ///
        /// Visible to the sibling test module too: the reload handoff drive
        /// needs the same client identity to reach a generation's own HTTPS
        /// server.
        pub(super) fn build_mtls_client(
            cert_pem: &[u8],
            key_pem: &[u8],
            ca_pem: &[u8],
        ) -> reqwest::Client {
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
                Duration::from_secs(30),
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
                Duration::from_secs(30),
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
                Duration::from_secs(30),
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
                Duration::from_secs(30),
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
                Duration::from_secs(30),
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
                Duration::from_secs(30),
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
                Duration::from_secs(30),
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
                Duration::from_secs(30),
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
                Duration::from_secs(30),
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
        /// How long a transition that must not have happened yet is watched
        /// for.
        ///
        /// A negative is only as good as the window it is observed over, so
        /// this one is a count of chances — twenty [`READY_POLL`]
        /// observations — handed to a teardown that would advance too early,
        /// rather than a settle delay whose end is the only moment anything
        /// is looked at. The first observation that sees the forbidden
        /// transition ends the watch there.
        const FORBIDDEN_WINDOW: Duration = READY_POLL.saturating_mul(20);

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
                    web_shutdown_timeout: Duration::from_secs(30),
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
            assert!(
                poll_until(READY_TIMEOUT, || needles
                    .iter()
                    .all(|needle| captured(logs).contains(needle)))
                .await,
                "expected {needles:?} in the log, got: {}",
                captured(logs)
            );
        }

        /// Polls `condition` at [`READY_POLL`], reporting whether it held
        /// within `limit`.
        ///
        /// None of what these tests synchronize on can be awaited: it is a
        /// flag another task sets, a line in a captured log, or a tracker
        /// closing. One poll covers both directions of that, which is what
        /// keeps a proof that something has not happened from being a sleep.
        /// A `true` under [`READY_TIMEOUT`] is a bounded wait for something
        /// expected; a `false` under [`FORBIDDEN_WINDOW`] is a bounded watch
        /// that saw a forbidden transition at no point in the window. The
        /// result is returned rather than asserted on so that a caller's
        /// diagnostics are read after the wait, not before it.
        async fn poll_until(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
            let wait = async {
                while !condition() {
                    sleep(READY_POLL).await;
                }
            };
            tokio::time::timeout(limit, wait).await.is_ok()
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

        /// Every ending a generation can have, in the order the parameterized
        /// sequence tests walk them.
        const ALL_ENDINGS: [GenerationEnd; 5] = [
            GenerationEnd::Terminate,
            GenerationEnd::ReloadConfig,
            GenerationEnd::Reboot,
            GenerationEnd::PowerOff,
            GenerationEnd::IngestExited,
        ];

        /// The five teardown phases, in the one order every ending shares.
        const TEARDOWN_MARKERS: [&str; 5] = [
            "web shutdown returned",
            "web reaper drain returned",
            "top-level drain returned",
            "retained handles read",
            "shutting the database down",
        ];

        /// The sixth marker, the one that names the ending's final action.
        fn final_action_marker(generation_end: GenerationEnd) -> &'static str {
            match generation_end {
                GenerationEnd::ReloadConfig => "final action, starting the next generation",
                GenerationEnd::Terminate => "final action, returning from the lifecycle",
                GenerationEnd::Reboot => "final action, rebooting the host",
                GenerationEnd::PowerOff => "final action, powering the host off",
                GenerationEnd::IngestExited => "final action, failing the lifecycle",
            }
        }

        /// The whole observable sequence for one ending: the five teardown
        /// phases and the action that follows them.
        fn full_marker_sequence(generation_end: GenerationEnd) -> Vec<&'static str> {
            let mut expected = TEARDOWN_MARKERS.to_vec();
            expected.push(final_action_marker(generation_end));
            expected
        }

        /// Pulls the shutdown sequence out of a captured log.
        ///
        /// One prefix names every phase, so filtering on it is all it takes to
        /// get the sequence — and the drain's own round reports, which name
        /// their tracker instead, are left behind.
        fn phase_markers(logs: &Arc<Mutex<Vec<u8>>>) -> Vec<String> {
            captured(logs)
                .lines()
                .filter(|line| line.contains(SHUTDOWN_PHASE))
                .map(ToString::to_string)
                .collect()
        }

        /// Asserts the captured log carries exactly `expected`, in order.
        ///
        /// One log is one ordered sink, so this is what establishes the order
        /// of the whole sequence. The seam's record is a second, independent
        /// recorder and is never compared against it.
        fn assert_marker_sequence(logs: &Arc<Mutex<Vec<u8>>>, expected: &[&str], ending: &str) {
            let markers = phase_markers(logs);
            assert_eq!(
                markers.len(),
                expected.len(),
                "{ending}: expected {} phase markers, got: {markers:#?}",
                expected.len()
            );
            for (marker, needle) in markers.iter().zip(expected) {
                assert!(
                    marker.contains(needle),
                    "{ending}: expected a marker for {needle:?}, got: {markers:#?}"
                );
            }
        }

        /// One operation of the lifecycle's effects seam.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum EffectCall {
            ShutdownDatabase,
            Reboot,
            PowerOff,
        }

        /// A seam that records what the lifecycle asked of it, and can be told
        /// to fail the database shutdown.
        ///
        /// The record answers only what a log cannot: whether an operation was
        /// invoked at all, and whether it was invoked despite a failure. It is
        /// never compared positionally against a captured log — the two are
        /// independent recorders, and a position in one says nothing about its
        /// order relative to a position in the other.
        #[derive(Clone)]
        struct RecordingEffects {
            calls: Arc<Mutex<Vec<EffectCall>>>,
            shutdown_database_fails: bool,
            host_action_fails: bool,
        }

        impl RecordingEffects {
            fn new() -> Self {
                Self {
                    calls: Arc::new(Mutex::new(Vec::new())),
                    shutdown_database_fails: false,
                    host_action_fails: false,
                }
            }

            /// A seam whose store cannot be flushed.
            fn failing() -> Self {
                Self {
                    shutdown_database_fails: true,
                    ..Self::new()
                }
            }

            /// A seam whose host refuses the command it is given.
            fn refusing_host_actions() -> Self {
                Self {
                    host_action_fails: true,
                    ..Self::new()
                }
            }

            fn calls(&self) -> Vec<EffectCall> {
                self.calls.lock().expect("lock").clone()
            }

            fn record(&self, call: EffectCall) {
                self.calls.lock().expect("lock").push(call);
            }
        }

        /// The message a failing seam's database shutdown carries.
        const SHUTDOWN_FAILURE: &str = "the store could not be flushed";

        /// The message a seam whose host refuses the command carries.
        const HOST_REFUSAL: &str = "the host refused the command";

        impl LifecycleEffects for RecordingEffects {
            fn shutdown_database(&self, _database: &storage::Database) -> Result<()> {
                self.record(EffectCall::ShutdownDatabase);
                if self.shutdown_database_fails {
                    bail!(SHUTDOWN_FAILURE)
                }
                Ok(())
            }

            fn reboot(&self) -> Result<()> {
                self.record(EffectCall::Reboot);
                if self.host_action_fails {
                    bail!(HOST_REFUSAL)
                }
                Ok(())
            }

            fn power_off(&self) -> Result<()> {
                self.record(EffectCall::PowerOff);
                if self.host_action_fails {
                    bail!(HOST_REFUSAL)
                }
                Ok(())
            }
        }

        /// A teardown with nothing left to do but run its phases.
        ///
        /// No web controller, a fresh empty tracker for each of the two
        /// trackers, a retention handle that has already returned and no
        /// ingest handle: what is left is the sequence itself.
        fn teardown_with_retention(
            retain_task_handle: JoinHandle<Result<()>>,
        ) -> GenerationTeardown {
            GenerationTeardown {
                web_controller: None,
                web_reaper_tracker: TaskTracker::new(),
                top_level_tracker: TaskTracker::new(),
                retain_task_handle,
                ingest_task_handle: None,
            }
        }

        fn empty_teardown() -> GenerationTeardown {
            teardown_with_retention(task::spawn(async { Ok(()) }))
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
                Duration::from_secs(30),
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
                    Duration::from_secs(30),
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

        /// Every ending shuts the store down, and only the tail after it
        /// differs.
        ///
        /// This is the rule that replaced the one where a reload, a terminate
        /// and an early exit fell through to their delay with the store never
        /// flushed. Time is paused, so neither tail costs wall-clock time.
        #[tokio::test(start_paused = true)]
        async fn every_ending_shuts_the_database_down_before_its_tail() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            for generation_end in ALL_ENDINGS {
                let ending = format!("{generation_end:?}");
                let effects = RecordingEffects::new();
                let (logs, guard) = capture_logs();
                finish_generation(generation_end, &database, &effects)
                    .await
                    .unwrap_or_else(|e| panic!("{ending}: the tail should not fail: {e:#}"));

                assert_eq!(
                    effects.calls(),
                    vec![EffectCall::ShutdownDatabase],
                    "{ending}: the store should have been shut down exactly once"
                );
                let output = captured(&logs);
                let waits_for_the_host = matches!(
                    generation_end,
                    GenerationEnd::Reboot | GenerationEnd::PowerOff
                );
                assert_eq!(
                    output.contains("Before shut down the system"),
                    waits_for_the_host,
                    "{ending}: only a reboot or a power-off waits for the host, got: {output}"
                );
                drop(guard);
            }
        }

        /// The tail of a generation that is handing the host to `roxy`, taken
        /// through the production seam.
        ///
        /// The parameterized test above covers every ending against a
        /// recording seam; this one is the single case that runs the real
        /// `Database::shutdown` on the way out. Time is paused, so the
        /// `WAIT_SHUTDOWN` pause it takes before the host goes down costs no
        /// wall-clock time.
        #[tokio::test(start_paused = true)]
        async fn a_reboot_tail_flushes_the_database() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            let (logs, _guard) = capture_logs();
            finish_generation(GenerationEnd::Reboot, &database, &HostEffects)
                .await
                .expect("the reboot tail should flush the database");

            assert!(
                captured(&logs).contains("Before shut down the system"),
                "the reboot tail should announce the wait it takes before handing over the host"
            );
        }

        /// The whole sequence, for every ending, at the boundary the lifecycle
        /// calls.
        ///
        /// Both trackers are empty and no drain round can go pending, so this
        /// is also what says the markers do not depend on one: all six appear
        /// with neither of the drain's own report lines anywhere in the log.
        /// Time is paused, so the tails cost nothing.
        #[tokio::test(start_paused = true)]
        async fn the_shutdown_sequence_runs_in_order_for_every_ending() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            for generation_end in ALL_ENDINGS {
                let ending = format!("{generation_end:?}");
                let effects = RecordingEffects::new();
                let (logs, guard) = capture_logs();

                shutdown_generation(empty_teardown(), generation_end, &database, &effects)
                    .await
                    .unwrap_or_else(|e| panic!("{ending}: the teardown should not fail: {e:#}"));
                let flow = act_on_generation_end(generation_end, &effects);

                assert_marker_sequence(&logs, &full_marker_sequence(generation_end), &ending);
                let output = captured(&logs);
                assert!(
                    !output.contains("shutdown drain round")
                        && !output.contains("shutdown drain complete"),
                    "{ending}: two empty trackers should report no drain round, got: {output}"
                );

                // A second recorder, read only for what it alone can say:
                // which operations were invoked. Its order is never used.
                let expected_calls = match generation_end {
                    GenerationEnd::Reboot => {
                        vec![EffectCall::ShutdownDatabase, EffectCall::Reboot]
                    }
                    GenerationEnd::PowerOff => {
                        vec![EffectCall::ShutdownDatabase, EffectCall::PowerOff]
                    }
                    _ => vec![EffectCall::ShutdownDatabase],
                };
                assert_eq!(effects.calls(), expected_calls, "{ending}");

                match generation_end {
                    // The reload ends here, at the boundary: no second
                    // generation is started, and the store was shut down once.
                    GenerationEnd::ReloadConfig => assert_eq!(
                        flow.unwrap_or_else(|e| panic!("{ending}: {e:#}")),
                        ControlFlow::Continue(()),
                        "{ending}: a reload should ask for another generation"
                    ),
                    GenerationEnd::IngestExited => {
                        let error = flow
                            .err()
                            .unwrap_or_else(|| panic!("{ending}: an early exit should fail"));
                        assert!(
                            error.to_string().contains("ingest subsystem ended"),
                            "{ending}: got: {error:#}"
                        );
                    }
                    _ => assert_eq!(
                        flow.unwrap_or_else(|e| panic!("{ending}: {e:#}")),
                        ControlFlow::Break(()),
                        "{ending}: this ending should end the lifecycle"
                    ),
                }
                drop(guard);
            }
        }

        /// A store that cannot be shut down stops the sequence where it is.
        ///
        /// The teardown returns the failure, so `act_on_generation_end` is
        /// never reached: no reboot, no power-off, and — on the reload case —
        /// no next generation. Five markers and no sixth, on every ending.
        #[tokio::test(start_paused = true)]
        async fn a_failed_database_shutdown_takes_no_action_on_any_ending() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            for generation_end in ALL_ENDINGS {
                let ending = format!("{generation_end:?}");
                let effects = RecordingEffects::failing();
                let (logs, guard) = capture_logs();

                let error =
                    shutdown_generation(empty_teardown(), generation_end, &database, &effects)
                        .await
                        .err()
                        .unwrap_or_else(|| {
                            panic!("{ending}: a failed database shutdown should end the teardown")
                        });

                assert!(
                    error.to_string().contains(SHUTDOWN_FAILURE),
                    "{ending}: the seam's failure should be what propagates, got: {error:#}"
                );
                assert_marker_sequence(&logs, &TEARDOWN_MARKERS, &ending);
                assert_eq!(
                    effects.calls(),
                    vec![EffectCall::ShutdownDatabase],
                    "{ending}: no host action may follow a store whose state is unknown"
                );
                assert!(
                    captured(&logs).contains("Database shutdown failed"),
                    "{ending}: the failure should be reported where it happened"
                );
                drop(guard);
            }
        }

        /// A host that refuses the command it is given fails the lifecycle.
        ///
        /// The marker is emitted before the seam is called, so it is there
        /// either way: what says the action succeeded is the lifecycle result,
        /// not the marker.
        #[tokio::test]
        async fn a_refused_host_action_fails_the_lifecycle() {
            for (generation_end, expected_call) in [
                (GenerationEnd::Reboot, EffectCall::Reboot),
                (GenerationEnd::PowerOff, EffectCall::PowerOff),
            ] {
                let ending = format!("{generation_end:?}");
                let effects = RecordingEffects::refusing_host_actions();
                let (logs, guard) = capture_logs();

                let error = act_on_generation_end(generation_end, &effects)
                    .err()
                    .unwrap_or_else(|| panic!("{ending}: a refused command should fail"));

                assert!(
                    error.to_string().contains(HOST_REFUSAL),
                    "{ending}: the host's refusal should be what propagates, got: {error:#}"
                );
                assert_eq!(
                    effects.calls(),
                    vec![expected_call],
                    "{ending}: the command should have been asked for once"
                );
                assert_marker_sequence(&logs, &[final_action_marker(generation_end)], &ending);
                drop(guard);
            }
        }

        /// A retained handle that came back badly is reported and suppresses
        /// nothing.
        ///
        /// The three abnormal completions a handle can carry, against the two
        /// shapes of final action: a host command, and the next generation.
        /// What is asserted is that the failure was reported and that the
        /// action still happened — not that the teardown returned plain
        /// success, which is what the entry-task supervision issue is expected
        /// to turn into a degraded outcome.
        #[tokio::test(start_paused = true)]
        async fn a_failed_retained_handle_is_reported_and_suppresses_no_action() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            for (failure, report) in [
                ("error", "Retention had already terminated unexpectedly"),
                ("panic", "Retention panicked"),
                ("cancelled", "Retention did not run to completion"),
            ] {
                for generation_end in [GenerationEnd::Reboot, GenerationEnd::ReloadConfig] {
                    let case = format!("{failure}/{generation_end:?}");
                    let retain_task_handle: JoinHandle<Result<()>> = match failure {
                        "error" => task::spawn(async { Err(anyhow!("a retention pass failed")) }),
                        "panic" => task::spawn(async { panic!("the retention task panicked") }),
                        _ => {
                            // Aborted before the teardown reads it, so the join
                            // returns a cancellation `JoinError`.
                            let handle = task::spawn(std::future::pending::<Result<()>>());
                            handle.abort();
                            handle
                        }
                    };

                    let effects = RecordingEffects::new();
                    let (logs, guard) = capture_logs();
                    // The return value is deliberately not asserted on: a
                    // handle failure reaching the lifecycle result is the
                    // supervision issue's to add.
                    let _outcome = shutdown_generation(
                        teardown_with_retention(retain_task_handle),
                        generation_end,
                        &database,
                        &effects,
                    )
                    .await;
                    let flow = act_on_generation_end(generation_end, &effects);

                    let output = captured(&logs);
                    assert!(
                        output.contains(report),
                        "{case}: the handle failure should be reported, got: {output}"
                    );
                    assert_marker_sequence(&logs, &full_marker_sequence(generation_end), &case);

                    if generation_end == GenerationEnd::Reboot {
                        assert_eq!(
                            effects.calls(),
                            vec![EffectCall::ShutdownDatabase, EffectCall::Reboot],
                            "{case}: the reboot should still have been asked for"
                        );
                    } else {
                        assert_eq!(
                            flow.unwrap_or_else(|e| panic!("{case}: {e:#}")),
                            ControlFlow::Continue(()),
                            "{case}: the next generation should still start"
                        );
                    }
                    drop(guard);
                }
            }
        }

        /// The store is shut down only after the drain reports the tracker
        /// empty — on every ending, not just on a reboot.
        ///
        /// The stand-in retention task is written the way the real one is: it
        /// waits for cancellation, and then waits out a cleanup already
        /// running on the blocking pool before returning. The sequence must
        /// not reach the database shutdown until that blocking cleanup has
        /// finished, so the test releases the blocking work only after
        /// checking that the sequence is still waiting. The phase marker is
        /// the observable, which is why this holds for a terminate and a
        /// reload as well as for the reboot that used to be the only ending
        /// leaving a line behind.
        #[tokio::test]
        async fn the_database_is_shut_down_only_after_the_drain_reports_the_tracker_empty() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);
            let shutdown_marker = format!("{SHUTDOWN_PHASE}: shutting the database down");

            for generation_end in [
                GenerationEnd::Reboot,
                GenerationEnd::Terminate,
                GenerationEnd::ReloadConfig,
            ] {
                let ending = format!("{generation_end:?}");
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
                            // The handle is awaited, never aborted: the
                            // blocking cleanup holds a database handle.
                            task::spawn_blocking(move || {
                                cleanup_started.store(true, Ordering::SeqCst);
                                let _ = release_rx.recv();
                                // Touching the store is the point: it is what
                                // would race a store flushed too early.
                                db.sensors_store().expect("sensors store");
                                cleanup_finished.store(true, Ordering::SeqCst);
                            })
                            .await?;
                            Ok(())
                        }
                    })
                    .expect("a fresh tracker admits the retention task");

                let effects = RecordingEffects::new();
                let (logs, guard) = capture_logs();
                let shutdown = task::spawn({
                    let database = database.clone();
                    let effects = effects.clone();
                    let top_level_tracker = tracker.clone();
                    async move {
                        shutdown_generation(
                            GenerationTeardown {
                                web_controller: None,
                                web_reaper_tracker: TaskTracker::new(),
                                top_level_tracker,
                                retain_task_handle,
                                ingest_task_handle: None,
                            },
                            generation_end,
                            &database,
                            &effects,
                        )
                        .await
                    }
                });

                // Cancellation has to reach the stand-in and its blocking
                // cleanup has to be running before the ordering under test
                // means anything.
                assert!(
                    poll_until(READY_TIMEOUT, || cleanup_started.load(Ordering::SeqCst)).await,
                    "{ending}: the drain should have cancelled the retention stand-in"
                );

                // The drain is the only thing between the sequence and the
                // tail, so a sequence that did not wait for it would leave the
                // phase it is parked in: by announcing the database shutdown,
                // by reaching the seam, or by emitting any marker beyond the
                // two the phases before the drain already left. The window
                // below is watched rather than slept through — whichever of
                // the three happened first would end it there — so an advance
                // anywhere inside it fails, not only one that is still the
                // state of the world when a single check runs.
                let advanced = || {
                    captured(&logs).contains(&shutdown_marker)
                        || !effects.calls().is_empty()
                        || phase_markers(&logs).len() > 2
                };
                assert!(
                    !poll_until(FORBIDDEN_WINDOW, advanced).await,
                    "{ending}: the sequence advanced past the drain while a blocking cleanup was \
                     still running, markers {:#?}, seam calls {:?}",
                    phase_markers(&logs),
                    effects.calls()
                );
                let markers = phase_markers(&logs);
                assert_eq!(
                    markers.len(),
                    2,
                    "{ending}: the sequence should be waiting on the top-level drain, got: \
                     {markers:#?}"
                );

                release_tx
                    .send(())
                    .expect("the blocking cleanup is waiting");
                wait_for_logs(&logs, &[shutdown_marker.as_str()]).await;
                // The marker says the phase was entered; the seam is what says
                // the store was actually handed over to be shut down.
                assert!(
                    poll_until(READY_TIMEOUT, || effects
                        .calls()
                        .contains(&EffectCall::ShutdownDatabase))
                    .await,
                    "{ending}: the store should have been shut down once the cleanup was released"
                );
                assert!(
                    cleanup_finished.load(Ordering::SeqCst),
                    "{ending}: the blocking cleanup should have run to the end first"
                );
                let output = captured(&logs);
                assert!(
                    output.contains("Retention stopped"),
                    "{ending}: the retention handle should have been read, got: {output}"
                );

                // What is left of the tail is a delay, and this test is not
                // waiting it out.
                shutdown.abort();
                drop(guard);
            }
        }

        /// Each drain phase waits on its own tracker, in the order the
        /// sequence puts them in.
        ///
        /// Both trackers are empty in the sequence test above, so nothing there
        /// would notice a phase draining the wrong one. Here the web reaper
        /// tracker holds a stand-in written the way the real reaper is — it
        /// ignores its cancellation token, because a `SIGKILL` followed by
        /// `wait()` must not be abandoned mid-reap — and the sequence has to
        /// stop at it: the top-level tracker is not even closed to new
        /// admissions until the reaping has finished, which is what says
        /// subsystem cancellation had not begun.
        #[tokio::test]
        async fn the_web_reaper_drain_waits_on_its_own_tracker_before_the_top_level_one() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            let web_reaper_tracker = TaskTracker::new();
            let top_level_tracker = TaskTracker::new();
            let (release_tx, release_rx) = oneshot::channel::<()>();
            let reaping = Arc::new(AtomicBool::new(false));
            web_reaper_tracker
                .spawn("pcap reaper", {
                    let reaping = Arc::clone(&reaping);
                    move |_cancel| async move {
                        reaping.store(true, Ordering::SeqCst);
                        let _ = release_rx.await;
                    }
                })
                .expect("a fresh tracker admits the reaper stand-in");

            let effects = RecordingEffects::new();
            let (logs, _guard) = capture_logs();
            let shutdown = task::spawn({
                let database = database.clone();
                let effects = effects.clone();
                let web_reaper_tracker = web_reaper_tracker.clone();
                let top_level_tracker = top_level_tracker.clone();
                async move {
                    shutdown_generation(
                        GenerationTeardown {
                            web_controller: None,
                            web_reaper_tracker,
                            top_level_tracker,
                            retain_task_handle: task::spawn(async { Ok(()) }),
                            ingest_task_handle: None,
                        },
                        GenerationEnd::Terminate,
                        &database,
                        &effects,
                    )
                    .await
                }
            });

            assert!(
                poll_until(READY_TIMEOUT, || reaping.load(Ordering::SeqCst)).await,
                "the reaper drain should have started its stand-in"
            );
            assert!(
                web_reaper_tracker.is_closed(),
                "the reaper drain should have closed its own tracker to new admissions"
            );

            // Nothing stands between this phase and the rest of the teardown,
            // so a sequence that did not wait would show it in one of two
            // ways: subsystem cancellation closing the top-level tracker, or
            // the next phase marker. Both are watched for the whole window
            // rather than looked at once at the end of a settle delay, so
            // either one, at any point inside it, fails here.
            let advanced = || top_level_tracker.is_closed() || phase_markers(&logs).len() > 1;
            assert!(
                !poll_until(FORBIDDEN_WINDOW, advanced).await,
                "the teardown left the reaper phase while a `tcpdump` child was still being \
                 reaped, markers {:#?}",
                phase_markers(&logs)
            );
            let markers = phase_markers(&logs);
            assert_eq!(
                markers.len(),
                1,
                "the sequence should be waiting on the reaper drain, got: {markers:#?}"
            );

            release_tx.send(()).expect("the reaper stand-in is waiting");
            assert!(
                poll_until(READY_TIMEOUT, || top_level_tracker.is_closed()).await,
                "the top-level drain should have closed its tracker once the reaping was done"
            );
            wait_for_logs(
                &logs,
                &[&format!("{SHUTDOWN_PHASE}: shutting the database down")],
            )
            .await;

            // What is left of the tail is a delay, and this test is not waiting
            // it out.
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
            let error = run_generation(&mut settings, &process, &HostEffects)
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
            let error = run_generation(&mut settings, &process, &HostEffects)
                .await
                .expect_err("an unsupported data directory should end the generation");

            assert!(error.to_string().contains("migration failed"));
            assert!(
                captured(&logs).contains("Migration failed"),
                "the migration error itself should be reported, not just the summary"
            );
        }

        /// A terminate intent taken through the real lifecycle, with the
        /// production seam and real subsystems in the tracker.
        ///
        /// Nothing is asserted about whether a drain round went pending: with
        /// real subsystems that is a race against the reporting cadence, and
        /// the empty-tracker boundary test is what shows the markers do not
        /// depend on it.
        #[tokio::test]
        async fn a_generation_ends_on_a_terminate_intent() {
            let dir = tempdir().expect("tempdir");
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir.path(), Arc::clone(&notify_terminate));
            let mut settings = test_settings(dir.path());

            let (logs, _guard) = capture_logs();
            // `join!` drives both on this task: the lifecycle runs while the
            // other side watches the log for readiness and then sends the
            // intent that ends it.
            let (outcome, ()) = tokio::join!(
                tokio::time::timeout(
                    GENERATION_TIMEOUT,
                    run_lifecycle(&mut settings, &process, &HostEffects)
                ),
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
            outcome
                .expect("a terminate intent should end the lifecycle")
                .expect("the lifecycle should not fail");

            let output = captured(&logs);
            assert!(
                output.contains("Termination signal: daemon exit"),
                "the terminate arm should have run, got: {output}"
            );
            assert!(
                output.contains("Retention stopped"),
                "the retention task should have stopped cleanly, got: {output}"
            );
            // Nothing here joins a publish handle, so this line can only come
            // from the token the top-level tracker handed its entry task.
            assert!(
                output.contains("Shutting down publish"),
                "the generation's cancellation should reach publish, got: {output}"
            );
            assert!(
                !output.contains("tracked task did not run to completion"),
                "the tracked tasks should have returned, not vanished, got: {output}"
            );
            assert_marker_sequence(
                &logs,
                &full_marker_sequence(GenerationEnd::Terminate),
                "Terminate",
            );
        }

        /// A store the lifecycle cannot shut down ends it, and no action is
        /// taken.
        ///
        /// The propagation proof through the real lifecycle: the same drive as
        /// the terminate test above, with a seam whose database shutdown
        /// fails.
        #[tokio::test]
        async fn a_failing_database_shutdown_ends_the_lifecycle_with_no_action() {
            let dir = tempdir().expect("tempdir");
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir.path(), Arc::clone(&notify_terminate));
            let mut settings = test_settings(dir.path());
            let effects = RecordingEffects::failing();

            let (logs, _guard) = capture_logs();
            let (outcome, ()) = tokio::join!(
                tokio::time::timeout(
                    GENERATION_TIMEOUT,
                    run_lifecycle(&mut settings, &process, &effects)
                ),
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
            let error = outcome
                .expect("a terminate intent should end the lifecycle")
                .expect_err("a failed database shutdown should fail the lifecycle");

            assert!(
                error.to_string().contains(SHUTDOWN_FAILURE),
                "the seam's failure should be what propagates, got: {error:#}"
            );
            assert_eq!(
                effects.calls(),
                vec![EffectCall::ShutdownDatabase],
                "no host action may follow a store whose state is unknown"
            );
            assert_marker_sequence(&logs, &TEARDOWN_MARKERS, "Terminate/failing seam");
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
                tokio::time::timeout(
                    GENERATION_TIMEOUT,
                    run_generation(&mut settings, &process, &HostEffects)
                ),
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

        /// Everything both reload drives need.
        ///
        /// All four addresses are pinned with `free_addr()` so the same ports
        /// can be asked of both generations, and the peer subsystem is
        /// configured so the fourth of them is bound at all. The configuration
        /// file has to exist: the peer subsystem reads it on startup, and a
        /// reload backs it up before rewriting it.
        struct ReloadFixture {
            settings: Settings,
            process: ProcessContext,
            notify_terminate: Arc<Notify>,
            graphql_addr: SocketAddr,
        }

        fn reload_fixture(dir: &Path) -> ReloadFixture {
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir, Arc::clone(&notify_terminate));
            let mut settings = test_settings(dir);
            let graphql_addr = free_addr();
            settings.config.visible.graphql_srv_addr = graphql_addr;
            settings.config.visible.ingest_srv_addr = free_addr();
            settings.config.visible.publish_srv_addr = free_addr();
            // `update_config_file` carries these two through the rewrite
            // unchanged, so the second generation is handed the same peer
            // address.
            settings.config.peer_srv_addr = Some(free_addr());
            settings.config.peers = Some(HashSet::new());
            write_config_file(&settings);

            ReloadFixture {
                settings,
                process,
                notify_terminate,
                graphql_addr,
            }
        }

        /// The four readiness lines, one per pinned address.
        const READINESS_LINES: [&str; 4] = [
            "Ingest listening on",
            "Publish listening on",
            // The peer subsystem logs a bare `listening on`, so the level that
            // precedes it is what tells it apart from the two lines above.
            "INFO listening on",
            "GraphQL web server is starting on",
        ];

        fn occurrences(logs: &Arc<Mutex<Vec<u8>>>, needle: &str) -> usize {
            captured(logs).matches(needle).count()
        }

        /// Waits until `needle` has appeared `count` times in the captured log.
        ///
        /// The same bounded poll [`wait_for_logs`] uses, for the assertions
        /// that are about a second occurrence rather than a first.
        async fn wait_for_occurrences(logs: &Arc<Mutex<Vec<u8>>>, needle: &str, count: usize) {
            assert!(
                poll_until(READY_TIMEOUT, || occurrences(logs, needle) >= count).await,
                "expected {needle:?} {count} time(s) in the log, got: {}",
                captured(logs)
            );
        }

        /// The captured log position where the `nth` occurrence of `needle`
        /// starts.
        ///
        /// Meant to be called once a bounded wait — [`wait_for_occurrences`]
        /// with a matching or greater count — has already established that
        /// the occurrence exists; this does no waiting of its own; it is
        /// where a position for two already-confirmed lines is read, so
        /// their relative order in that one log can be asserted.
        fn occurrence_position(logs: &Arc<Mutex<Vec<u8>>>, needle: &str, nth: usize) -> usize {
            captured(logs)
                .match_indices(needle)
                .nth(nth - 1)
                .unwrap_or_else(|| panic!("expected occurrence {nth} of {needle:?} in the log"))
                .0
        }

        /// Sends a configuration reload the only way production sends one: an
        /// mTLS `updateConfig` mutation against the generation's own HTTPS
        /// server.
        ///
        /// The mutation sleeps `GRAPHQL_REBOOT_DELAY` before it hands the new
        /// configuration to the generation, so the response says only that the
        /// mutation was accepted; the reload itself is waited for in the log.
        async fn send_reload_mutation(
            process: &ProcessContext,
            addr: SocketAddr,
            current: &ConfigVisible,
        ) {
            let tls = tls_reload::get_current_tls_material(&process.tls_watch);
            let client = super::reload_https_server_tests::build_mtls_client(
                &tls.cert_pem,
                &tls.key_pem,
                &tls.ca_pem,
            );

            let old = toml::to_string(current).expect("serialize the current config");
            let mut updated = current.clone();
            // One harmless field, so nothing about the next generation changes
            // but the value that proves the rewrite happened.
            updated.ack_transmission = current.ack_transmission + 1;
            let new = toml::to_string(&updated).expect("serialize the new config");

            let body = serde_json::json!({
                "query": "mutation($old: String!, $new: String!) \
                          { updateConfig(old: $old, new: $new) { ackTransmission } }",
                "variables": { "old": old, "new": new },
            });
            let response = client
                .post(format!("https://{addr}/graphql"))
                .json(&body)
                .send()
                .await
                .expect("the reload mutation should reach the generation's web server")
                .text()
                .await
                .expect("the mutation response should decode");
            assert!(
                !response.contains("\"errors\""),
                "the reload mutation should have been accepted, got: {response}"
            );
        }

        /// The lifecycle loops on a reload, and the next generation reopens the
        /// same store and rebinds the same addresses.
        ///
        /// This is the drive that proves the previous generation dropped every
        /// `Database` clone it held: nothing untracked holds one here, so the
        /// second `Database::open` on that path could not have succeeded
        /// otherwise. The four readiness lines are all needed, one per pinned
        /// address, and the GraphQL one is not substitutable — `web::serve`
        /// logs it only after the acceptor has bound, so a second occurrence
        /// is what says this lifecycle released the pinned GraphQL port and
        /// took it again.
        #[tokio::test]
        async fn a_reload_reopens_the_same_store_and_rebinds_the_same_addresses() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = reload_fixture(dir.path());
            let notify_terminate = Arc::clone(&fixture.notify_terminate);
            let graphql_addr = fixture.graphql_addr;
            let first_config = fixture.settings.config.visible.clone();
            let process = fixture.process;
            let reload_marker = final_action_marker(GenerationEnd::ReloadConfig);
            let shutdown_marker = format!("{SHUTDOWN_PHASE}: shutting the database down");

            let (logs, _guard) = capture_logs();
            let (outcome, ()) = tokio::join!(
                tokio::time::timeout(
                    GENERATION_TIMEOUT,
                    run_lifecycle(&mut fixture.settings, &process, &HostEffects)
                ),
                async {
                    wait_for_logs(&logs, &READINESS_LINES).await;
                    send_reload_mutation(&process, graphql_addr, &first_config).await;

                    // The first generation ended on the reload, shut its store
                    // down, and asked for another generation.
                    wait_for_logs(&logs, &[shutdown_marker.as_str(), reload_marker]).await;

                    // The second generation took every pinned address back.
                    for line in READINESS_LINES {
                        wait_for_occurrences(&logs, line, 2).await;
                    }
                    // And reopened the store behind them.
                    wait_for_occurrences(&logs, "Database cleanup completed.", 2).await;

                    notify_terminate.notify_one();
                }
            );
            outcome
                .expect("the lifecycle should end on the terminate intent")
                .expect("the lifecycle should not fail");

            let output = captured(&logs);
            // A bind failure there is non-fatal, so a second generation that
            // came up without a web server would satisfy everything else.
            assert!(
                !output.contains("Failed to start GraphQL server"),
                "both generations should have bound the pinned GraphQL address, got: {output}"
            );
            assert_eq!(
                fixture.settings.config.visible.ack_transmission,
                first_config.ack_transmission + 1,
                "the reload should have left the rewritten configuration behind it"
            );
            // Two endings, two full sequences: the reload and the terminate.
            assert_marker_sequence(
                &logs,
                &[
                    full_marker_sequence(GenerationEnd::ReloadConfig),
                    full_marker_sequence(GenerationEnd::Terminate),
                ]
                .concat(),
                "ReloadConfig then Terminate",
            );
            assert_eq!(
                occurrences(&logs, &shutdown_marker),
                2,
                "each generation shuts its own store down, got: {output}"
            );
            // `run_generation` awaits `web::serve` — which logs the GraphQL
            // readiness line only after its acceptor has bound — before it
            // registers retention, whose own pass is what logs cleanup. That
            // ordering is deterministic, so the second generation's GraphQL
            // readiness line must precede its cleanup line in this one log.
            let second_graphql_ready =
                occurrence_position(&logs, "GraphQL web server is starting on", 2);
            let second_cleanup = occurrence_position(&logs, "Database cleanup completed.", 2);
            assert!(
                second_graphql_ready < second_cleanup,
                "the second generation's GraphQL readiness should precede its cleanup, got: {output}"
            );
        }

        /// A store the first generation could not shut down stops the reload
        /// there: the second generation never starts.
        #[tokio::test]
        async fn a_failed_shutdown_on_a_reload_starts_no_second_generation() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = reload_fixture(dir.path());
            let graphql_addr = fixture.graphql_addr;
            let first_config = fixture.settings.config.visible.clone();
            let process = fixture.process;
            let effects = RecordingEffects::failing();

            let (logs, _guard) = capture_logs();
            let (outcome, ()) = tokio::join!(
                tokio::time::timeout(
                    GENERATION_TIMEOUT,
                    run_lifecycle(&mut fixture.settings, &process, &effects)
                ),
                async {
                    wait_for_logs(&logs, &READINESS_LINES).await;
                    send_reload_mutation(&process, graphql_addr, &first_config).await;
                }
            );
            let error = outcome
                .expect("a failed database shutdown should end the lifecycle")
                .expect_err("a failed database shutdown should fail the lifecycle");

            assert!(
                error.to_string().contains(SHUTDOWN_FAILURE),
                "the seam's failure should be what propagates, got: {error:#}"
            );
            assert_eq!(
                occurrences(&logs, "Ingest listening on"),
                1,
                "no second generation should have started, got: {}",
                captured(&logs)
            );
            assert_marker_sequence(&logs, &TEARDOWN_MARKERS, "ReloadConfig/failing seam");
            assert_eq!(effects.calls(), vec![EffectCall::ShutdownDatabase]);
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
                tokio::time::timeout(
                    GENERATION_TIMEOUT,
                    run_generation(&mut settings, &process, &HostEffects)
                ),
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
            let effects = RecordingEffects::new();
            let error = tokio::time::timeout(
                GENERATION_TIMEOUT,
                run_lifecycle(&mut settings, &process, &effects),
            )
            .await
            .expect("a failed ingest listener should end the generation on its own")
            .expect_err("an entry task that ended on its own is a failure of the lifecycle");

            assert!(
                error
                    .to_string()
                    .contains("the ingest subsystem ended before the daemon did"),
                "the lifecycle should name what ended it, got: {error:#}"
            );
            // The store was shut down like every other ending, and no second
            // generation was started.
            assert_eq!(effects.calls(), vec![EffectCall::ShutdownDatabase]);

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
            assert_marker_sequence(
                &logs,
                &full_marker_sequence(GenerationEnd::IngestExited),
                "IngestExited",
            );
        }

        /// A publish listener that cannot bind is reported where it happens,
        /// and the generation keeps serving.
        ///
        /// This is the other half of the ingest case above. Publish is not
        /// watched by a `GenerationEnd` variant, so nothing outside the entry
        /// task ever reads its result back; if the task did not report the
        /// failure itself, a node serving no publish traffic would run to the
        /// end of the generation without a word about it. The terminate intent
        /// is what ends this one, which is also the proof that the early exit
        /// did not.
        #[tokio::test]
        async fn a_publish_listener_that_cannot_bind_is_reported() {
            let dir = tempdir().expect("tempdir");
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir.path(), Arc::clone(&notify_terminate));
            let mut settings = test_settings(dir.path());

            // QUIC is UDP, so the port has to be held by a UDP socket for the
            // publish listener to lose it.
            let occupied = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("occupy the publish port");
            settings.config.visible.publish_srv_addr =
                occupied.local_addr().expect("occupied addr");

            let (logs, _guard) = capture_logs();
            let (end, ()) = tokio::join!(
                tokio::time::timeout(
                    GENERATION_TIMEOUT,
                    run_generation(&mut settings, &process, &HostEffects)
                ),
                async {
                    wait_for_logs(
                        &logs,
                        &[
                            "Ingest listening on",
                            "Publish subsystem terminated unexpectedly",
                        ],
                    )
                    .await;
                    notify_terminate.notify_one();
                }
            );
            let end = end
                .expect("a terminate intent should end the generation")
                .expect("a failed publish listener should not fail the generation");

            assert_eq!(end, GenerationEnd::Terminate);

            let output = captured(&logs);
            assert!(
                output.contains("failed to bind the publish listener"),
                "the bind failure itself should be reported, got: {output}"
            );
            assert!(
                !output.contains("tracked task did not run to completion"),
                "the entry task returned, it did not vanish, got: {output}"
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
                tokio::time::timeout(
                    GENERATION_TIMEOUT,
                    run_generation(&mut settings, &process, &HostEffects)
                ),
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
            // What follows is read from a store that was shut down, not merely
            // dropped: the flush, the WAL write and the cancellation of
            // background work all ran before the generation let go of it.
            assert!(
                output.contains(&format!("{SHUTDOWN_PHASE}: shutting the database down")),
                "the store should have been shut down before the reopen, got: {output}"
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
