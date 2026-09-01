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
    task,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, metadata::LevelFilter, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, Layer, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

use crate::{
    cancellation::{DRAIN_REPORT_INTERVAL, SupervisedHandle, TaskTracker, drain_with_report},
    comm::{
        new_ingest_sensors, new_pcap_sensors, new_peers_data, new_runtime_ingest_sensors,
        new_stream_direct_channels,
    },
    graphql::NodeName,
    server::{SERVER_REBOOT_DELAY, host_fqdn_from_cert},
    settings::Args,
    storage::{
        deletion_coordination::CustomerDeletionCoordinator, migrate_data_dir,
        validate_compression_metadata,
    },
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
/// down, if the host refused a reboot or a power-off, if an entry task ended
/// on its own, or if a generation ended degraded on an ending other than a
/// configuration reload.
async fn run_lifecycle(
    settings: &mut Settings,
    process: &ProcessContext,
    effects: &dyn LifecycleEffects,
) -> Result<()> {
    loop {
        let outcome = run_generation(settings, process, effects).await?;
        match act_on_generation_end(outcome, effects)? {
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
/// The four steps run in the order written below, and that order is the
/// contract. The action goes first because the drain proved the tracker empty
/// and the store was flushed with its background work stopped, so an operator
/// who asked for a reboot still gets one even though something died on the way
/// out — the opposite of a failed database shutdown, which suppresses the host
/// action entirely because there the store's on-disk state is unknown. The two
/// records that follow are separate lines rather than one, because a returned
/// error is not itself a log record and a degraded generation whose host
/// action also failed has two things to say. The error returned is the host
/// action's: the host did not go down, which is the more actionable of the two.
///
/// # Errors
///
/// Returns an error if the host refused the reboot or the power-off, if the
/// generation ended because an entry task did — nobody asked for that one, so
/// the process manager is told the exit was not wanted — or if the generation
/// ended degraded on any ending but a configuration reload.
fn act_on_generation_end(
    outcome: GenerationOutcome,
    effects: &dyn LifecycleEffects,
) -> Result<ControlFlow<()>> {
    let GenerationOutcome { ending, health } = outcome;

    let action = match ending {
        GenerationEnd::ReloadConfig => {
            info!("{SHUTDOWN_PHASE}: final action, starting the next generation ({ending:?})");
            Ok(())
        }
        GenerationEnd::Terminate => {
            info!("{SHUTDOWN_PHASE}: final action, returning from the lifecycle ({ending:?})");
            Ok(())
        }
        GenerationEnd::Reboot => {
            info!("{SHUTDOWN_PHASE}: final action, rebooting the host ({ending:?})");
            effects.reboot()
        }
        GenerationEnd::PowerOff => {
            info!("{SHUTDOWN_PHASE}: final action, powering the host off ({ending:?})");
            effects.power_off()
        }
        // The generation has already drained and closed itself down; what is
        // left is to tell the process manager that this exit was not asked
        // for, so a unit configured to restart on failure does. What failed
        // was reported at the shutdown coordination boundary.
        GenerationEnd::EntryTaskExited(_) => {
            info!("{SHUTDOWN_PHASE}: final action, failing the lifecycle ({ending:?})");
            Ok(())
        }
    };

    let degraded = health == GenerationHealth::Degraded;
    if degraded {
        error!(ending = ?ending, "generation ended degraded");
    }
    if let Err(e) = &action {
        let cause = format!("{e:#}");
        error!(ending = ?ending, error = %cause, "generation end action failed");
    }
    action?;

    match ending {
        GenerationEnd::EntryTaskExited(subsystem) => Err(anyhow!(
            "the {subsystem} subsystem ended before the daemon did"
        )),
        // The one row a degradation does not fail. A handle that came back
        // badly is a task that ended, and ending is what gives up what the
        // next generation needs: the listeners are unbound, the drain reported
        // the tracker empty, the store was shut down, and the last `Database`
        // clone goes as the generation returns. So the handoff holds, and the
        // failure is logged rather than propagated.
        GenerationEnd::ReloadConfig => Ok(ControlFlow::Continue(())),
        _ if degraded => Err(anyhow!("the generation ended degraded ({ending:?})")),
        _ => Ok(ControlFlow::Break(())),
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

/// The subsystems whose entry tasks a generation supervises.
///
/// One per long-running subsystem registered in the generation's top-level
/// tracker and watched by [`wait_for_generation_end`]. The order the variants
/// are written in is the order that wait polls them and the order the teardown
/// reads back what it was handed, so two subsystems that die together always
/// produce the same choice of which one the generation names as its ending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Subsystem {
    Ingest,
    Publish,
    Peer,
    Retention,
}

impl std::fmt::Display for Subsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Ingest => "ingest",
            Self::Publish => "publish",
            Self::Peer => "peer",
            Self::Retention => "retention",
        };
        f.write_str(name)
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
    /// This subsystem's entry task ended while the generation was still
    /// serving.
    ///
    /// Nobody asked for this one. An entry task returns on its own only when
    /// it cannot do its job — a listener whose address is taken — or when it
    /// panics, and a node that keeps serving everything but the subsystem that
    /// died is not a node anyone asked for either. So the early exit ends the
    /// generation through the same shutdown sequence as the intents, and the
    /// lifecycle reports it as a failure rather than returning cleanly.
    EntryTaskExited(Subsystem),
}

/// Whether a generation reached its end with everything it supervised
/// accounted for.
///
/// Degraded is an internal outcome of one generation, never a lifecycle return
/// value: what it means for the process is decided by
/// [`act_on_generation_end`], from the ending it is paired with. Nothing here
/// names what degraded the generation, so a second producer can raise it on
/// the same mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationHealth {
    /// Everything the generation supervised was accounted for.
    Clean,
    /// Something the generation supervised ended abnormally. The rest of the
    /// teardown ran all the same, and the ending's action still stands.
    Degraded,
}

/// What one generation ended as.
///
/// The ending on its own could not carry a degradation: an `Err` out of
/// [`run_generation`] short-circuits on `?` and is exactly what makes the
/// lifecycle skip the final action, and a degraded generation must still take
/// it. So a degraded outcome is a value, and `Err` keeps its one meaning —
/// the failures that suppress the action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GenerationOutcome {
    /// Why the generation ended.
    ending: GenerationEnd,
    /// Whether it got there with everything accounted for.
    health: GenerationHealth,
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
/// [`GenerationOutcome`].
///
/// # Errors
///
/// Returns an error if the data directory fails compression validation or
/// migration, if the database cannot be opened, if the node certificate
/// carries no usable node name, if the peer subsystem cannot be built, or if
/// the teardown could not shut the store down. A generation that ended
/// degraded is not one of them: that is carried out as a value, because the
/// ending's final action must still be taken.
#[allow(clippy::too_many_lines)]
async fn run_generation(
    settings: &mut Settings,
    process: &ProcessContext,
    effects: &dyn LifecycleEffects,
) -> Result<GenerationOutcome> {
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

    // The one piece of state customer deletion and retention agree on, created
    // here because both sides are built from here: it goes into the GraphQL
    // context for the `deleteCustomerData` resolver and into the retention
    // entry task below. Per generation, like the trackers, and for the same
    // reason — a claim only ever describes work running now, so it must not
    // outlive the store it was claimed over.
    let deletion_coordination = Arc::new(CustomerDeletionCoordinator::new());

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
        Arc::clone(&deletion_coordination),
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
    let retain_task_handle: SupervisedHandle<Result<()>> = top_level_tracker
        .spawn_supervised("retention", {
            let db = database.clone();
            let deletion_coordination = Arc::clone(&deletion_coordination);
            move |cancel| run_retention(ONE_DAY, retention, db, cancel, deletion_coordination)
        })
        .map_err(|e| anyhow!("failed to register the retention task: {e}"))?;

    // Peer is tracked the way retention and ingest are: the tracker hands it
    // the generation's cancellation token and waits for its entry task in the
    // drain below. Its handle is kept so the wait below watches it and the
    // teardown reads back whatever it was not handed — the peer subsystem
    // reports its own `Err` where it happens, but an early return and a panic
    // are outcomes only the handle carries. It is the one entry task that may
    // be absent, because peer runs only when an address is configured for it.
    let peer_task_handle: Option<SupervisedHandle<Result<()>>> =
        if let Some(peer_srv_addr) = settings.config.peer_srv_addr {
            let peer_server = peer::Peer::new(peer_srv_addr, &certs.clone(), tls.generation)?;
            let notify_sensor = notify_sensor_change
                .clone()
                .expect("peer notify exists when peer server is configured");
            let handle = top_level_tracker
                .spawn_supervised("peer", {
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
            Some(handle)
        } else {
            None
        };

    // Publish is tracked the way peer is, and its handle is kept for the same
    // reason: the wait below ends the generation when this task ends, and the
    // teardown reads the handle back when something else ended it first.
    let publish_server =
        publish::Server::new(settings.config.visible.publish_srv_addr, &certs.clone());
    let publish_task_handle = top_level_tracker
        .spawn_supervised("publish", {
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
    // task to return before the generation lets go of the database handle. The
    // handle is kept because the tracker cannot stand in for it: the wait below
    // watches it so an entry task that ends on its own takes the generation
    // down with it rather than leaving a node serving everything but ingest,
    // and reading it back after the drain adds the outcome the drain cannot
    // see — a panic as a `JoinError`.
    let ingest_task_handle = top_level_tracker
        .spawn_supervised("ingest", {
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
    let mut entry_tasks = EntryTasks {
        ingest: Some(ingest_task_handle),
        publish: Some(publish_task_handle),
        peer: peer_task_handle,
        retention: Some(retain_task_handle),
    };
    let generation_end = wait_for_generation_end(
        settings,
        process,
        &mut intents,
        &mut entry_tasks,
        &mut web_controller,
        &schema,
        web_addr,
        web_shutdown_timeout,
    )
    .await;
    // Read here rather than inside the teardown: what an `Ok(())` means
    // depends on whether the handle had already finished at the moment the
    // wait ended, and the drain that runs later is what cancels the rest.
    let retained_entry_tasks = entry_tasks.into_retained();

    // Every ending is shut down the same way, so the whole sequence is one
    // call rather than a step per arm. Nothing is cancelled here: the only
    // cancellation of the top-level tracker is the close-then-cancel inside
    // the drain, so the tracker is never left cancelled but still admitting.
    let health = shutdown_generation(
        GenerationTeardown {
            web_controller: web_controller.take(),
            web_reaper_tracker,
            top_level_tracker,
            entry_tasks: retained_entry_tasks,
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
    // registry, and an accepted customer deletion is inside it: the resolver
    // registers its supervisor on `top_level_tracker`, so the drain above has
    // already waited for it. Work that never entered the registry could still
    // hold a clone past this point.
    Ok(GenerationOutcome {
        ending: generation_end,
        health,
    })
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

/// The four entry tasks a generation supervises, each until something reads
/// its handle back.
///
/// A slot goes to `None` two ways: peer starts there when the subsystem is not
/// configured, and any of the four is taken out by the arm that read it. What
/// is left when the wait returns is exactly what the teardown is handed, so
/// nothing that ended is dropped unobserved and nothing already read is polled
/// twice.
struct EntryTasks {
    ingest: Option<SupervisedHandle<Result<()>>>,
    publish: Option<SupervisedHandle<Result<()>>>,
    peer: Option<SupervisedHandle<Result<()>>>,
    retention: Option<SupervisedHandle<Result<()>>>,
}

impl EntryTasks {
    /// The slot one subsystem's handle lives in.
    fn slot(&mut self, subsystem: Subsystem) -> &mut Option<SupervisedHandle<Result<()>>> {
        match subsystem {
            Subsystem::Ingest => &mut self.ingest,
            Subsystem::Publish => &mut self.publish,
            Subsystem::Peer => &mut self.peer,
            Subsystem::Retention => &mut self.retention,
        }
    }

    /// Everything the wait did not read, in the order the teardown reads it.
    ///
    /// Each handle carries whether it had already finished at this moment —
    /// the moment the wait returned. Cancellation happens inside the drain, so
    /// a handle that was finished already cannot have finished because of it,
    /// and the `Ok(())` it carries is an early exit rather than a clean stop.
    fn into_retained(self) -> Vec<RetainedEntryTask> {
        [self.ingest, self.publish, self.peer, self.retention]
            .into_iter()
            .flatten()
            .map(|handle| RetainedEntryTask {
                already_finished: handle.is_finished(),
                handle,
            })
            .collect()
    }
}

/// One entry task handed to the teardown, and what the wait knew about it.
struct RetainedEntryTask {
    handle: SupervisedHandle<Result<()>>,
    /// Whether the task had already finished when the wait ended.
    already_finished: bool,
}

/// What awaiting an entry task's handle yields.
type EntryTaskOutput = std::result::Result<Result<()>, task::JoinError>;

/// Where in the shutdown an entry task's outcome was observed.
///
/// Two and no others: the generation was still serving, or the handle was read
/// back after the drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationPhase {
    Serving,
    AfterDrain,
}

impl ObservationPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Serving => "serving",
            Self::AfterDrain => "after_drain",
        }
    }
}

/// Awaits an entry task's handle, or never resolves when there is none.
///
/// Peer runs only when an address is configured for it, and the `select!` arm
/// that watches it has to be written either way, so the absent case is a
/// future that stays pending rather than a fabricated handle.
async fn watch_entry_task(handle: Option<&mut SupervisedHandle<Result<()>>>) -> EntryTaskOutput {
    match handle {
        Some(handle) => handle.await,
        None => std::future::pending().await,
    }
}

/// Reports one entry task's outcome, and says whether it was abnormal.
///
/// This is the single report at the shutdown coordination boundary. It does
/// not replace the two others that exist for their own reasons — what a
/// subsystem logs where its own failure happens, and the tracker registration
/// guard's abnormal-completion warning — so an operator sees the same failure
/// from more than one angle, which is intended.
///
/// Both shapes carry all five fields, always: the abnormal one at `error!` and
/// a task that was cancelled and stopped at `info!`. Only a cause is optional,
/// because an early exit and a clean stop have none. `already_finished` is
/// what tells a clean stop from an early exit at
/// [`AfterDrain`](ObservationPhase::AfterDrain): cancellation happens inside
/// the drain, so a handle that was already finished when the wait ended cannot
/// have finished because of it.
///
/// One window is left. A task that finishes on its own between the wait
/// returning and the drain cancelling — the span covering web shutdown, the
/// web reaper drain and the tracker's own `close` — is still read as clean.
/// Closing it would need a completion time stamped inside the task itself.
fn report_entry_task_outcome(
    handle: &SupervisedHandle<Result<()>>,
    phase: ObservationPhase,
    already_finished: bool,
    outcome: &EntryTaskOutput,
) -> bool {
    // Recorded with `?` so a dynamic name and a rendered duration cannot break
    // the line-oriented log format, the way the registration guard records
    // the same two.
    let name = handle.name();
    let id = handle.id();
    let age = handle.age();
    // The one shape an `Ok(())` can be normal in: a handle read back after the
    // drain, from a task that was still running when the wait ended and so can
    // only have stopped because the drain cancelled it.
    let stopped_on_cancellation = phase == ObservationPhase::AfterDrain && !already_finished;
    let phase = phase.as_str();

    match outcome {
        Ok(Ok(())) if stopped_on_cancellation => {
            info!(
                name = ?name,
                id,
                phase,
                outcome = "clean",
                age = ?age,
                "entry task stopped"
            );
            false
        }
        Ok(Ok(())) => {
            error!(
                name = ?name,
                id,
                phase,
                outcome = "early_exit",
                age = ?age,
                "entry task ended abnormally"
            );
            true
        }
        Ok(Err(e)) => {
            let cause = format!("{e:#}");
            error!(
                name = ?name,
                id,
                phase,
                outcome = "error",
                age = ?age,
                error = %cause,
                "entry task ended abnormally"
            );
            true
        }
        Err(e) if e.is_panic() => {
            error!(
                name = ?name,
                id,
                phase,
                outcome = "panic",
                age = ?age,
                error = %e,
                "entry task ended abnormally"
            );
            true
        }
        Err(e) => {
            error!(
                name = ?name,
                id,
                phase,
                outcome = "cancelled",
                age = ?age,
                error = %e,
                "entry task ended abnormally"
            );
            true
        }
    }
}

/// Takes the handle whose arm ended the wait, reports it, and names the
/// ending.
///
/// The handle is taken rather than left behind: it has been read, and a
/// `JoinHandle` polled again after it has completed is not a handle that
/// resolves a second time. Everything still in [`EntryTasks`] goes to the
/// teardown.
fn end_on_entry_task(
    entry_tasks: &mut EntryTasks,
    subsystem: Subsystem,
    outcome: &EntryTaskOutput,
) -> GenerationEnd {
    let handle = entry_tasks
        .slot(subsystem)
        .take()
        .expect("the arm that ended the wait polled a handle that was there");
    // A task read by its own arm ended before anything cancelled it, so an
    // `Ok(())` here is an early exit whatever else is true.
    report_entry_task_outcome(&handle, ObservationPhase::Serving, true, outcome);
    GenerationEnd::EntryTaskExited(subsystem)
}

/// Serves until a shutdown intent arrives or a subsystem entry task ends, and
/// reports which it was.
///
/// This is the whole of a generation's steady state. Every arm but two ends
/// the generation; a TLS reload rebinds the HTTPS server in place and keeps
/// serving, which is why the wait is a loop rather than a single `select!`,
/// and a configuration reload that cannot be persisted also keeps serving, on
/// the configuration the generation started with.
///
/// One selection covers both the wait and the readiness check that follows a
/// configuration write that failed. The check is that same selection with the
/// configuration reload taken out for one round and an immediately ready arm
/// put in below the handles, so the precedence an operator gets is written
/// once rather than restated in a second block that could drift from it.
///
/// The entry-task arms are why the handles are borrowed here rather than only
/// read back after the drain: an entry task that ends on its own is an event
/// the generation has to act on, not one it can discover at shutdown.
/// Borrowing leaves the handles with the caller, so an arm that loses the race
/// has taken nothing from them.
///
/// Shutting the generation's own machinery down is the caller's, not this
/// function's: every arm that ends a generation is torn down the same way, so
/// the sequence runs once at the call site instead of once per arm.
#[allow(clippy::too_many_arguments)]
async fn wait_for_generation_end<S>(
    settings: &mut Settings,
    process: &ProcessContext,
    intents: &mut GenerationIntents,
    entry_tasks: &mut EntryTasks,
    web_controller: &mut Option<WebController>,
    schema: &S,
    web_addr: std::net::SocketAddr,
    web_shutdown_timeout: Duration,
) -> GenerationEnd
where
    S: async_graphql::Executor + Clone,
{
    // `poll_config_reload` is what makes the readiness check below a check.
    //
    // A configuration reload whose write failed does not end the generation
    // and can be ready again at once — several senders parked in `send` refill
    // a channel of capacity 1 as soon as one is taken — so on its own it would
    // keep the entry-task arms beneath it from ever being polled. And the
    // condition that fails a configuration write, a full disk or a path gone
    // read-only, is the same one that kills subsystems, so detection must not
    // depend on an entry-task arm winning. Clearing this flag takes the
    // configuration reload out of the next round, and the last arm — ready on
    // its first poll, and enabled only for that round — is what makes that
    // round a single pass over readiness rather than a second place the wait
    // can park. Only the three terminal intents and a pending TLS reload
    // outrank the handles in it, and when none of those is ready it falls
    // straight back to the full selection.
    let mut poll_config_reload = true;
    loop {
        // `biased`, so the order the arms are written in is the policy.
        //
        // The three terminal intents come first because an explicit request to
        // stop is the strongest thing that can arrive; their order among
        // themselves only has to be fixed, since all three run the same
        // teardown and differ only in the tail.
        //
        // The TLS reload sits directly below them because it is the one arm
        // with a deadline. giganto does not rotate certificates itself: an
        // operator replaces the files and sends SIGHUP, at a cadence that may
        // be as short as an hour, so this arm is a recurring operation rather
        // than a one-off. `Notify` stores at most one permit, so several
        // signals collapse into one reload and the reload rereads whatever
        // files are current when it runs — the collapse costs nothing, and the
        // reload is only ever delayed. But a short-lived certificate delayed
        // far enough expires, an expired certificate under mTLS cuts both
        // directions, and the GraphQL endpoint it takes down is the very path
        // a configuration reload arrives on. Repeated SIGHUP can therefore
        // delay the arms below; at that cadence the frequency does not arise,
        // and the delay is accepted.
        //
        // The configuration reload sits above the entry-task arms because an
        // entry-task exit ends the generation, and a generation that starts
        // from the new configuration also restarts the subsystem that died.
        // `recv` is cancel safe, so losing a poll consumes no message, but the
        // receiver is dropped with the generation, so an update that was never
        // applied is discarded. Taking the entry-task exit first would throw
        // away the recovery the operator asked for.
        //
        // The entry-task arms are next and in a fixed order, so two subsystems
        // dying together always produce the same choice of which one the
        // generation names as its ending. Precedence decides which ending is
        // reported, not which outcomes are: a handle left unpolled because a
        // higher arm won is handed to the teardown and reported there.
        select! {
            biased;
            () = process.notify_terminate.notified() => {
                info!("Termination signal: daemon exit");
                return GenerationEnd::Terminate;
            }
            () = intents.notify_reboot.notified() => {
                info!("Restarting the system...");
                return GenerationEnd::Reboot;
            }
            () = intents.notify_power_off.notified() => {
                info!("Power off the system...");
                return GenerationEnd::PowerOff;
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
                // Back to the full selection, with no readiness check of its
                // own. Checking after a reload would let a configuration
                // update that arrived during its `await` lose to a finished
                // entry handle and be discarded, which is exactly what putting
                // the configuration reload above the entry-task arms is for.
                poll_config_reload = true;
            }
            Some(new_config) = intents.reload_rx.recv(), if poll_config_reload => {
                match settings.update_config_file(&new_config) {
                    Ok(()) => return GenerationEnd::ReloadConfig,
                    Err(e) => {
                        warn!("Failed to update configuration: {e:#}, run with previous config");
                        poll_config_reload = false;
                    }
                }
            }
            outcome = watch_entry_task(entry_tasks.ingest.as_mut()) => {
                return end_on_entry_task(entry_tasks, Subsystem::Ingest, &outcome);
            }
            outcome = watch_entry_task(entry_tasks.publish.as_mut()) => {
                return end_on_entry_task(entry_tasks, Subsystem::Publish, &outcome);
            }
            outcome = watch_entry_task(entry_tasks.peer.as_mut()) => {
                return end_on_entry_task(entry_tasks, Subsystem::Peer, &outcome);
            }
            outcome = watch_entry_task(entry_tasks.retention.as_mut()) => {
                return end_on_entry_task(entry_tasks, Subsystem::Retention, &outcome);
            }
            // Enabled only for the round that follows a configuration write
            // that failed, and ready on its first poll, so that round is a
            // pass over the arms above rather than a wait on them.
            () = std::future::ready(()), if !poll_config_reload => {
                poll_config_reload = true;
            }
        }
    }
}

/// Everything a generation hands to its teardown.
///
/// The teardown takes ownership of all of it: the web controller it shuts
/// down, the two trackers it drains, and the entry-task handles it reads back.
/// They travel together because the teardown is one unit — grouping them is
/// also what keeps its parameter list within reach of a test that builds one
/// by hand.
struct GenerationTeardown {
    /// The HTTPS GraphQL server, or `None` when the bind failed and the
    /// generation carried on without one.
    web_controller: Option<WebController>,
    /// The web-owned tracker holding the PCAP `tcpdump` reaping.
    web_reaper_tracker: TaskTracker,
    /// The generation's own tracker, holding every subsystem and every
    /// long-running piece of web-origin work.
    top_level_tracker: TaskTracker,
    /// The entry tasks the wait did not read back, in the order they are read.
    ///
    /// The one whose arm ended the wait is not here: it has already been read
    /// and reported, and a `JoinHandle` polled again after it has completed is
    /// not a handle that resolves a second time. Everything else is, including
    /// a handle that had finished but lost to a higher arm.
    entry_tasks: Vec<RetainedEntryTask>,
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
/// that came back badly is not one: it is reported, it makes the returned
/// outcome degraded, and it suppresses neither the later database shutdown
/// phase nor the ending's requested action. A database-shutdown failure
/// returns before that action.
async fn shutdown_generation(
    teardown: GenerationTeardown,
    generation_end: GenerationEnd,
    database: &storage::Database,
    effects: &dyn LifecycleEffects,
) -> Result<GenerationHealth> {
    let GenerationTeardown {
        web_controller,
        web_reaper_tracker,
        top_level_tracker,
        entry_tasks,
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
    let mut health = GenerationHealth::Clean;
    for retained in entry_tasks {
        if observe_entry_task(retained).await {
            health = GenerationHealth::Degraded;
        }
    }
    info!("{SHUTDOWN_PHASE}: retained handles read ({generation_end:?})");
    finish_generation(generation_end, database, effects).await?;
    Ok(health)
}

/// Reads one retained entry task back and reports how it ended.
///
/// A drain waits for tracked tasks to exit but says nothing about how they
/// exited, so this is where the generation accounts for a handle it was
/// handed. All four endings reach the log: the value the task returned, the
/// error it returned, a panic, and an abort nobody asked for. Only the first
/// two are anything the task could have reported on its own; a panic and an
/// abort leave no return value behind, so this is the only place they can be
/// seen at all. Awaiting costs nothing — the drain has already waited for this
/// task — and it is what makes the report the last observation before the
/// database shutdown.
///
/// Returns whether the outcome was abnormal, which is what degrades the
/// generation.
async fn observe_entry_task(retained: RetainedEntryTask) -> bool {
    let RetainedEntryTask {
        mut handle,
        already_finished,
    } = retained;
    let outcome = (&mut handle).await;
    report_entry_task_outcome(
        &handle,
        ObservationPhase::AfterDrain,
        already_finished,
        &outcome,
    )
}

/// Runs the retention entry task, reporting a failure the moment it happens.
///
/// The handle the generation retains carries whatever this returns to
/// [`report_entry_task_outcome`], which classes the outcome but says nothing
/// about which pass failed or why. The cause is only here, so it is reported
/// here as well, the way ingest, publish and peer report their own. The
/// duplication is intended: the boundary record is what an operator greps for
/// across the four subsystems, and this line is what says what retention was
/// doing.
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
    deletion_coordination: Arc<CustomerDeletionCoordinator>,
) -> Result<()> {
    let result = storage::retain_periodically(
        interval,
        retention_period,
        db,
        cancel,
        deletion_coordination,
    )
    .await;
    if let Err(e) = &result {
        error!("Retention terminated unexpectedly: {e:#}");
    }
    result
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
        GenerationEnd::ReloadConfig
        | GenerationEnd::Terminate
        | GenerationEnd::EntryTaskExited(_) => {
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
            future::Future,
            net::{Ipv4Addr, SocketAddr},
            path::Path,
            sync::{Once, atomic::AtomicUsize},
        };

        use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
        use tempfile::tempdir;
        use tokio::task::JoinHandle;

        use super::*;
        use crate::{cancellation::DrainOutcome, settings::Config};

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
            GenerationEnd::EntryTaskExited(Subsystem::Ingest),
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
                GenerationEnd::EntryTaskExited(_) => "final action, failing the lifecycle",
            }
        }

        /// The outcome of a generation that ended cleanly.
        fn clean(ending: GenerationEnd) -> GenerationOutcome {
            GenerationOutcome {
                ending,
                health: GenerationHealth::Clean,
            }
        }

        /// The outcome of a generation something abnormal was observed in.
        fn degraded(ending: GenerationEnd) -> GenerationOutcome {
            GenerationOutcome {
                ending,
                health: GenerationHealth::Degraded,
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

        /// The static message every abnormal entry-task record carries.
        const ABNORMAL_RECORD: &str = "entry task ended abnormally";
        /// The static message the record for a task that stopped carries.
        const CLEAN_RECORD: &str = "entry task stopped";
        /// The lifecycle-level record for a generation that ended degraded.
        const DEGRADED_RECORD: &str = "generation ended degraded";
        /// The lifecycle-level record for an ending whose action failed.
        const FAILED_ACTION_RECORD: &str = "generation end action failed";

        /// Every captured line carrying `needle`.
        fn records(logs: &Arc<Mutex<Vec<u8>>>, needle: &str) -> Vec<String> {
            captured(logs)
                .lines()
                .filter(|line| line.contains(needle))
                .map(ToString::to_string)
                .collect()
        }

        /// The one record carrying `needle`, or a failure naming what was
        /// there instead.
        ///
        /// Exactly one is the point: the boundary emits a single record per
        /// abnormal outcome, so a duplicate is as much a failure as a missing
        /// one.
        fn sole_record(logs: &Arc<Mutex<Vec<u8>>>, needle: &str) -> String {
            let found = records(logs, needle);
            assert_eq!(
                found.len(),
                1,
                "expected exactly one {needle:?} record, got: {found:#?}"
            );
            found[0].clone()
        }

        fn abnormal_report(logs: &Arc<Mutex<Vec<u8>>>) -> String {
            sole_record(logs, ABNORMAL_RECORD)
        }

        /// Asserts `first` reached the log before `second`, both of them
        /// having reached it at all.
        ///
        /// The presence check is what makes this an ordering assertion.
        /// `str::find` answers with an `Option`, and `None` sorts below every
        /// `Some`, so comparing the two answers directly would hold for a
        /// `first` that never appeared — which is the very failure an
        /// assertion that the higher-precedence arm ran first is there to
        /// catch.
        fn assert_precedes(logs: &Arc<Mutex<Vec<u8>>>, first: &str, second: &str, case: &str) {
            let output = captured(logs);
            let first_at = output
                .find(first)
                .unwrap_or_else(|| panic!("{case}: expected {first:?} in: {output}"));
            let second_at = output
                .find(second)
                .unwrap_or_else(|| panic!("{case}: expected {second:?} in: {output}"));
            assert!(
                first_at < second_at,
                "{case}: expected {first:?} before {second:?}, got: {output}"
            );
        }

        /// Asserts a per-task record carries the five fields, with these
        /// values.
        ///
        /// The fields are read as fields rather than as substrings of prose,
        /// which is what makes the record greppable for an operator and stable
        /// for a test.
        fn assert_report_fields(
            record: &str,
            subsystem: Subsystem,
            id: u64,
            phase: &str,
            outcome: &str,
        ) {
            for field in [
                format!("name=\"{subsystem}\""),
                format!("id={id} "),
                format!("phase=\"{phase}\""),
                format!("outcome=\"{outcome}\""),
            ] {
                assert!(
                    record.contains(&field),
                    "expected the field {field:?} in: {record}"
                );
            }
            // A `Duration` rendered with `?`: one number and one unit, the way
            // the tracker's own `age` field renders.
            let age = Regex::new(r"age=[0-9]+(\.[0-9]+)?(ns|µs|ms|s)\b").expect("valid regex");
            assert!(
                age.is_match(record),
                "expected a Duration-shaped age in: {record}"
            );
        }

        /// Asserts a lifecycle-level record is told apart from a per-task one
        /// by the fields it carries.
        fn assert_lifecycle_record(record: &str, ending: GenerationEnd) {
            assert!(
                record.contains(&format!("ending={ending:?}")),
                "expected the ending in: {record}"
            );
            assert!(
                !record.contains("name=") && !record.contains("id="),
                "a lifecycle record names no task: {record}"
            );
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

        /// Spawns a stand-in entry task and hands back its supervised handle.
        ///
        /// The metadata the boundary reports — the name, the tracker-assigned
        /// id, the spawn instant — comes from the tracker, so a stand-in has
        /// to be registered in one to be reportable at all. The token is
        /// ignored: a stand-in that has to observe cancellation spawns
        /// through the tracker itself.
        fn stand_in<Fut>(
            tracker: &TaskTracker,
            subsystem: Subsystem,
            fut: Fut,
        ) -> SupervisedHandle<Result<()>>
        where
            Fut: Future<Output = Result<()>> + Send + 'static,
        {
            tracker
                .spawn_supervised(subsystem.to_string(), move |_cancel| fut)
                .expect("a fresh tracker admits a stand-in entry task")
        }

        /// A stand-in that parks until the tracker cancels it, then stops.
        ///
        /// The shape a real entry task has, and the default the wait borrows:
        /// it stays pending for as long as the test needs, and a teardown
        /// driven with the same tracker still gets it back.
        fn parking_stand_in(
            tracker: &TaskTracker,
            subsystem: Subsystem,
        ) -> SupervisedHandle<Result<()>> {
            tracker
                .spawn_supervised(subsystem.to_string(), |cancel| async move {
                    cancel.cancelled().await;
                    Ok(())
                })
                .expect("a fresh tracker admits a stand-in entry task")
        }

        /// A stand-in that has already finished, and is known to have.
        ///
        /// The wait's own readiness check is what a test would otherwise race,
        /// so the task is joined here — through a clone of its abort handle,
        /// which resolves only once the task is done — before the handle is
        /// handed on.
        async fn finished_stand_in<Fut>(
            tracker: &TaskTracker,
            subsystem: Subsystem,
            fut: Fut,
        ) -> SupervisedHandle<Result<()>>
        where
            Fut: Future<Output = Result<()>> + Send + 'static,
        {
            let handle = stand_in(tracker, subsystem, fut);
            assert!(
                poll_until(READY_TIMEOUT, || handle.is_finished()).await,
                "the stand-in for {subsystem} should have finished"
            );
            handle
        }

        /// One entry task the teardown is handed.
        fn retained(
            handle: SupervisedHandle<Result<()>>,
            already_finished: bool,
        ) -> RetainedEntryTask {
            RetainedEntryTask {
                handle,
                already_finished,
            }
        }

        /// A teardown with nothing left to do but run its phases and read the
        /// handles it is given.
        ///
        /// No web controller and a fresh empty tracker for each of the two
        /// trackers: what is left is the sequence itself.
        fn teardown_with_entry_tasks(entry_tasks: Vec<RetainedEntryTask>) -> GenerationTeardown {
            GenerationTeardown {
                web_controller: None,
                web_reaper_tracker: TaskTracker::new(),
                top_level_tracker: TaskTracker::new(),
                entry_tasks,
            }
        }

        fn empty_teardown() -> GenerationTeardown {
            teardown_with_entry_tasks(Vec::new())
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
            /// The tracker the stand-in entry tasks are registered in.
            ///
            /// Nothing drains it: it is here because a supervised handle can
            /// only come from a tracker, and the name, id and spawn instant
            /// the boundary reports are what the tracker stamps.
            tracker: TaskTracker,
            /// Stands in for the four entry tasks the wait watches.
            ///
            /// The wait needs handles to borrow, and the tests that drive the
            /// other arms need those handles to stay pending, so the default
            /// is four tasks that never return. A test that wants one of the
            /// entry-task arms replaces that slot.
            entry_tasks: EntryTasks,
            reload_tx: mpsc::Sender<ConfigVisible>,
            notify_terminate: Arc<Notify>,
            notify_reboot: Arc<Notify>,
            notify_power_off: Arc<Notify>,
            notify_tls_reload: Arc<Notify>,
        }

        impl WaitFixture {
            /// Replaces one entry task with a stand-in of the test's own, and
            /// returns the id the tracker gave it.
            fn replace_entry_task<Fut>(&mut self, subsystem: Subsystem, fut: Fut) -> u64
            where
                Fut: Future<Output = Result<()>> + Send + 'static,
            {
                let handle = stand_in(&self.tracker, subsystem, fut);
                let id = handle.id();
                *self.entry_tasks.slot(subsystem) = Some(handle);
                id
            }

            /// Replaces one entry task with a stand-in already known to have
            /// finished.
            async fn finish_entry_task<Fut>(&mut self, subsystem: Subsystem, fut: Fut) -> u64
            where
                Fut: Future<Output = Result<()>> + Send + 'static,
            {
                let handle = finished_stand_in(&self.tracker, subsystem, fut).await;
                let id = handle.id();
                *self.entry_tasks.slot(subsystem) = Some(handle);
                id
            }

            /// Stops the stand-in entry tasks the test is done with.
            ///
            /// A tracked task the runtime drops without it having returned is
            /// reported by the tracker's registration guard, and by then the
            /// test's log capture is gone. That report is the first thing to
            /// reach its callsite from a thread with no subscriber at all,
            /// which caches the callsite as uninteresting process-wide — and
            /// the tests that assert on that very report then read an empty
            /// log. So a fixture drains its tracker, the way a generation
            /// drains its own.
            async fn settle(&mut self) {
                drop(self.take_retained());
                let outcome = self
                    .tracker
                    .cancel_and_drain(DRAIN_LOOP_TIMEOUT)
                    .await
                    .expect("the fixture tracker should not be poisoned");
                assert_eq!(
                    outcome,
                    DrainOutcome::Drained,
                    "the stand-in entry tasks should have stopped"
                );
            }

            /// Takes the entry tasks the wait left behind, the way the
            /// generation hands them to its teardown.
            fn take_retained(&mut self) -> Vec<RetainedEntryTask> {
                std::mem::replace(
                    &mut self.entry_tasks,
                    EntryTasks {
                        ingest: None,
                        publish: None,
                        peer: None,
                        retention: None,
                    },
                )
                .into_retained()
            }

            /// Replaces one entry task with a stand-in the test aborts, so the
            /// handle carries a cancellation `JoinError`.
            async fn abort_entry_task(&mut self, subsystem: Subsystem) -> u64 {
                let handle = stand_in(&self.tracker, subsystem, std::future::pending());
                handle.abort_handle().abort();
                assert!(
                    poll_until(READY_TIMEOUT, || handle.is_finished()).await,
                    "the aborted stand-in for {subsystem} should have finished"
                );
                let id = handle.id();
                *self.entry_tasks.slot(subsystem) = Some(handle);
                id
            }
        }

        fn wait_fixture(dir: &Path) -> WaitFixture {
            let notify_terminate = Arc::new(Notify::new());
            let process = test_process_context(dir, Arc::clone(&notify_terminate));
            let notify_tls_reload = Arc::clone(&process.notify_tls_reload);
            let (reload_tx, reload_rx) = mpsc::channel::<ConfigVisible>(1);
            let notify_reboot = Arc::new(Notify::new());
            let notify_power_off = Arc::new(Notify::new());
            // Peer is present by default so its arm is exercised alongside the
            // other three; the shape production takes when peer is not
            // configured has a test of its own.
            let tracker = TaskTracker::new();
            let entry_tasks = EntryTasks {
                ingest: Some(parking_stand_in(&tracker, Subsystem::Ingest)),
                publish: Some(parking_stand_in(&tracker, Subsystem::Publish)),
                peer: Some(parking_stand_in(&tracker, Subsystem::Peer)),
                retention: Some(parking_stand_in(&tracker, Subsystem::Retention)),
            };

            WaitFixture {
                settings: test_settings(dir),
                process,
                intents: GenerationIntents {
                    reload_rx,
                    notify_reboot: Arc::clone(&notify_reboot),
                    notify_power_off: Arc::clone(&notify_power_off),
                },
                tracker,
                entry_tasks,
                reload_tx,
                notify_terminate,
                notify_reboot,
                notify_power_off,
                notify_tls_reload,
            }
        }

        /// The teardown a wait fixture hands over, drained on the tracker its
        /// stand-ins are registered in.
        ///
        /// That tracker is what the drain cancels, so the stand-ins that were
        /// still parked when the wait ended return rather than holding the
        /// teardown open.
        fn fixture_teardown(fixture: &mut WaitFixture) -> GenerationTeardown {
            GenerationTeardown {
                web_controller: None,
                web_reaper_tracker: TaskTracker::new(),
                top_level_tracker: fixture.tracker.clone(),
                entry_tasks: fixture.take_retained(),
            }
        }

        /// The record a TLS reload leaves when the material it reread is the
        /// material the live server is already serving.
        const TLS_NOOP_RECORD: &str = "HTTPS reload: no TLS material changes detected";

        /// A live HTTPS server built from the fixture's current TLS material.
        async fn live_web(fixture: &WaitFixture, web_addr: SocketAddr) -> WebController {
            let tls = tls_reload::get_current_tls_material(&fixture.process.tls_watch);
            web::serve(
                test_schema(),
                web_addr,
                tls.cert_pem.clone(),
                tls.key_pem.clone(),
                tls.ca_pem.clone(),
                Duration::from_secs(30),
            )
            .await
            .expect("the test server should start")
        }

        /// Runs the wait against a live HTTPS server the reload has nothing to
        /// rebind for.
        ///
        /// `reload_https_server` returns as soon as it finds unchanged
        /// material behind a live controller, so the arm still runs and still
        /// leaves its completion record — without the bind, serve and
        /// graceful shutdown a restart costs, which a test that repeats the
        /// arm would otherwise pay for on every round.
        async fn wait_with_live_web(
            fixture: &mut WaitFixture,
            web_controller: &mut Option<WebController>,
            web_addr: SocketAddr,
        ) -> GenerationEnd {
            let schema = test_schema();
            wait_for_generation_end(
                &mut fixture.settings,
                &fixture.process,
                &mut fixture.intents,
                &mut fixture.entry_tasks,
                web_controller,
                &schema,
                web_addr,
                Duration::from_secs(30),
            )
            .await
        }

        /// How many times a precedence assertion is repeated in one test.
        ///
        /// Each round is one selection over two simultaneously ready arms, so
        /// an unbiased choice would have to fall the same way every time: at
        /// this count that is about one chance in thirty million.
        const PRECEDENCE_ROUNDS: usize = 25;

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
                &mut fixture.entry_tasks,
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
            fixture.settle().await;
        }

        #[tokio::test]
        async fn a_reboot_intent_ends_the_wait() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());

            fixture.notify_reboot.notify_one();

            assert_eq!(wait_without_web(&mut fixture).await, GenerationEnd::Reboot);
            fixture.settle().await;
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
            fixture.settle().await;
        }

        /// An entry task ending is not an intent, but it ends the wait all the
        /// same — for each of the four, and for each class of outcome.
        ///
        /// Nothing is notified here: the only thing that happens is that one
        /// of the tasks the wait borrows returns. A wait that ignored it would
        /// leave the generation serving with nothing behind that subsystem's
        /// port. The outcome class is varied across the four so the serving
        /// phase covers all four of them.
        #[tokio::test]
        async fn an_entry_task_that_ends_ends_the_wait() {
            for (subsystem, outcome) in [
                (Subsystem::Ingest, "early_exit"),
                (Subsystem::Publish, "error"),
                (Subsystem::Peer, "panic"),
                (Subsystem::Retention, "cancelled"),
            ] {
                let dir = tempdir().expect("tempdir");
                let mut fixture = wait_fixture(dir.path());
                // Installed before the stand-in is built: a panic and an abort
                // are both reported by the registration guard the moment they
                // happen, which is before the wait is even entered.
                let (logs, guard) = capture_logs();
                let id = match outcome {
                    "early_exit" => fixture.replace_entry_task(subsystem, async { Ok(()) }),
                    "error" => fixture.replace_entry_task(subsystem, async {
                        Err(anyhow!("the listener is gone"))
                    }),
                    "panic" => fixture
                        .replace_entry_task(subsystem, async { panic!("the entry task panicked") }),
                    _ => fixture.abort_entry_task(subsystem).await,
                };

                assert_eq!(
                    wait_without_web(&mut fixture).await,
                    GenerationEnd::EntryTaskExited(subsystem),
                    "{subsystem}/{outcome}"
                );

                let report = abnormal_report(&logs);
                assert_report_fields(&report, subsystem, id, "serving", outcome);
                fixture.settle().await;
                drop(guard);
            }
        }

        /// The peer arm is the one that may not be there at all.
        ///
        /// With peer unconfigured its slot is empty, which must leave the
        /// other three arms working rather than fabricate a handle or take
        /// the selection down.
        #[tokio::test]
        async fn an_absent_peer_entry_task_leaves_the_other_arms_watching() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            fixture.entry_tasks.peer = None;
            let id = fixture.replace_entry_task(Subsystem::Publish, async { Ok(()) });

            let (logs, _guard) = capture_logs();
            assert_eq!(
                wait_without_web(&mut fixture).await,
                GenerationEnd::EntryTaskExited(Subsystem::Publish)
            );
            assert_report_fields(
                &abnormal_report(&logs),
                Subsystem::Publish,
                id,
                "serving",
                "early_exit",
            );
            fixture.settle().await;
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
            fixture.settle().await;
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
            fixture.settle().await;
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
                    &mut fixture.entry_tasks,
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
            fixture.settle().await;
        }

        /// A terminal intent decides the ending over a queued configuration
        /// reload, every time.
        ///
        /// The reload is queued once and never consumed: `recv` is cancel
        /// safe, so an arm that is not polled takes no message, which is what
        /// lets the same queued message lose round after round.
        #[tokio::test]
        async fn a_terminal_intent_outranks_a_queued_configuration_reload() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            write_config_file(&fixture.settings);
            let before = fixture.settings.config.visible.ack_transmission;

            let mut new_config = fixture.settings.config.visible.clone();
            new_config.ack_transmission = before + 1;
            fixture
                .reload_tx
                .send(new_config)
                .await
                .expect("the wait should still hold the receiver");

            for round in 0..PRECEDENCE_ROUNDS {
                fixture.notify_terminate.notify_one();
                assert_eq!(
                    wait_without_web(&mut fixture).await,
                    GenerationEnd::Terminate,
                    "round {round}"
                );
            }

            assert_eq!(
                fixture.settings.config.visible.ack_transmission, before,
                "the queued reload should never have been taken"
            );
            fixture.settle().await;
        }

        /// A terminal intent decides the ending over an entry handle that has
        /// already finished, every time — and that handle is still read at the
        /// teardown boundary afterwards.
        ///
        /// Precedence decides which ending the generation reports, not which
        /// outcomes get reported: the handle that lost is handed over, read
        /// after the drain, and reported there as an early exit rather than a
        /// clean stop, which is what degrades the generation.
        #[tokio::test(start_paused = true)]
        async fn a_terminal_intent_outranks_a_finished_entry_handle() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            let id = fixture
                .finish_entry_task(Subsystem::Ingest, async { Ok(()) })
                .await;

            for round in 0..PRECEDENCE_ROUNDS {
                fixture.notify_reboot.notify_one();
                assert_eq!(
                    wait_without_web(&mut fixture).await,
                    GenerationEnd::Reboot,
                    "round {round}"
                );
            }
            assert!(
                fixture.entry_tasks.ingest.is_some(),
                "the arm that lost took nothing from the handle"
            );

            let database = test_database(&fixture.settings.config.visible.data_dir);
            let effects = RecordingEffects::new();
            let (logs, _guard) = capture_logs();
            let health = shutdown_generation(
                fixture_teardown(&mut fixture),
                GenerationEnd::Reboot,
                &database,
                &effects,
            )
            .await
            .expect("the teardown should not fail");

            assert_eq!(health, GenerationHealth::Degraded);
            assert_report_fields(
                &abnormal_report(&logs),
                Subsystem::Ingest,
                id,
                "after_drain",
                "early_exit",
            );
            // The three that were still parked stopped because the drain
            // cancelled them, so they are the clean shape.
            assert_eq!(
                records(&logs, CLEAN_RECORD).len(),
                3,
                "got: {}",
                captured(&logs)
            );
            // The degradation does not cancel the intent's action: the host is
            // still asked to reboot, and the failure is what the lifecycle
            // returns afterwards.
            assert!(
                act_on_generation_end(degraded(GenerationEnd::Reboot), &effects).is_err(),
                "a degraded reboot should fail the lifecycle"
            );
            assert_eq!(
                effects.calls(),
                vec![EffectCall::ShutdownDatabase, EffectCall::Reboot]
            );
            // Four retained handles, and the six markers still in the one
            // order every ending shares.
            assert_marker_sequence(
                &logs,
                &full_marker_sequence(GenerationEnd::Reboot),
                "Reboot with four retained handles",
            );
        }

        /// A queued configuration reload decides the ending over an entry
        /// handle that has already finished, every time.
        ///
        /// The reload is what restarts the subsystem that died, so taking the
        /// entry-task exit first would throw away the recovery the operator
        /// asked for. The handle is still reported after the drain.
        #[tokio::test(start_paused = true)]
        async fn a_configuration_reload_outranks_a_finished_entry_handle() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            write_config_file(&fixture.settings);
            let id = fixture
                .finish_entry_task(Subsystem::Publish, async { Ok(()) })
                .await;

            for round in 0..PRECEDENCE_ROUNDS {
                let new_config = fixture.settings.config.visible.clone();
                fixture
                    .reload_tx
                    .send(new_config)
                    .await
                    .expect("the wait should still hold the receiver");
                assert_eq!(
                    wait_without_web(&mut fixture).await,
                    GenerationEnd::ReloadConfig,
                    "round {round}"
                );
            }
            assert!(fixture.entry_tasks.publish.is_some());

            let database = test_database(&fixture.settings.config.visible.data_dir);
            let effects = RecordingEffects::new();
            let (logs, _guard) = capture_logs();
            let health = shutdown_generation(
                fixture_teardown(&mut fixture),
                GenerationEnd::ReloadConfig,
                &database,
                &effects,
            )
            .await
            .expect("the teardown should not fail");

            assert_eq!(health, GenerationHealth::Degraded);
            assert_report_fields(
                &abnormal_report(&logs),
                Subsystem::Publish,
                id,
                "after_drain",
                "early_exit",
            );
            // The one row a degradation does not fail: the next generation
            // still starts, and the failure is logged rather than propagated.
            assert_eq!(
                act_on_generation_end(degraded(GenerationEnd::ReloadConfig), &effects)
                    .expect("a degraded reload should not fail the lifecycle"),
                ControlFlow::Continue(())
            );
        }

        /// A TLS reload runs before a queued configuration reload, and the
        /// generation still ends as a configuration reload.
        ///
        /// The two are ready together; the reload is the arm with a deadline,
        /// so it goes first, and the configuration reload it delayed is taken
        /// on the next turn of the loop.
        #[tokio::test]
        async fn a_tls_reload_outranks_a_queued_configuration_reload() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            write_config_file(&fixture.settings);
            let web_addr = free_addr();
            let mut web_controller = Some(live_web(&fixture, web_addr).await);

            for round in 0..PRECEDENCE_ROUNDS {
                let new_config = fixture.settings.config.visible.clone();
                fixture
                    .reload_tx
                    .send(new_config)
                    .await
                    .expect("the wait should still hold the receiver");
                fixture.notify_tls_reload.notify_one();

                let (logs, guard) = capture_logs();
                assert_eq!(
                    wait_with_live_web(&mut fixture, &mut web_controller, web_addr).await,
                    GenerationEnd::ReloadConfig,
                    "round {round}"
                );
                assert_eq!(
                    records(&logs, TLS_NOOP_RECORD).len(),
                    1,
                    "round {round}: the TLS reload should have run first, got: {}",
                    captured(&logs)
                );
                drop(guard);
            }
            shutdown_web(web_controller.take()).await;
            fixture.settle().await;
        }

        /// A TLS reload runs before an entry handle that has already finished,
        /// and the generation then ends on that handle.
        #[tokio::test]
        async fn a_tls_reload_outranks_a_finished_entry_handle() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            let web_addr = free_addr();
            let mut web_controller = Some(live_web(&fixture, web_addr).await);

            for round in 0..PRECEDENCE_ROUNDS {
                let id = fixture
                    .finish_entry_task(Subsystem::Retention, async { Ok(()) })
                    .await;
                fixture.notify_tls_reload.notify_one();

                let (logs, guard) = capture_logs();
                assert_eq!(
                    wait_with_live_web(&mut fixture, &mut web_controller, web_addr).await,
                    GenerationEnd::EntryTaskExited(Subsystem::Retention),
                    "round {round}"
                );
                assert_precedes(
                    &logs,
                    TLS_NOOP_RECORD,
                    ABNORMAL_RECORD,
                    &format!("round {round}: the TLS reload should have run first"),
                );
                assert_report_fields(
                    &abnormal_report(&logs),
                    Subsystem::Retention,
                    id,
                    "serving",
                    "early_exit",
                );
                drop(guard);
            }
            shutdown_web(web_controller.take()).await;
            fixture.settle().await;
        }

        /// A terminal intent ready alongside a TLS reload ends the generation
        /// at once, and no reload runs.
        ///
        /// The TLS permit is never consumed, which is what says the arm was
        /// not merely lost but never reached.
        #[tokio::test]
        async fn a_terminal_intent_outranks_a_tls_reload() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());

            let (logs, _guard) = capture_logs();
            for round in 0..PRECEDENCE_ROUNDS {
                fixture.notify_tls_reload.notify_one();
                fixture.notify_power_off.notify_one();
                assert_eq!(
                    wait_without_web(&mut fixture).await,
                    GenerationEnd::PowerOff,
                    "round {round}"
                );
            }

            let output = captured(&logs);
            assert!(
                !output.contains("HTTPS reload"),
                "no TLS reload should have run, got: {output}"
            );
            fixture.settle().await;
        }

        /// A finished entry handle is detected while failing configuration
        /// reloads are still arriving.
        ///
        /// The configuration file is never created, so every write fails on
        /// the backup that precedes it — a failure of the path, not of timing.
        /// That arm does not end the generation and refills at once, so
        /// without the check that follows it the entry-task arms below would
        /// go unpolled for as long as the reloads keep coming.
        #[tokio::test]
        async fn a_finished_handle_is_detected_while_failing_reloads_keep_arriving() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            let id = fixture
                .finish_entry_task(Subsystem::Peer, async { Ok(()) })
                .await;

            let stop = Arc::new(AtomicBool::new(false));
            let sent = Arc::new(AtomicUsize::new(0));
            let sender = task::spawn({
                let reload_tx = fixture.reload_tx.clone();
                let new_config = fixture.settings.config.visible.clone();
                let stop = Arc::clone(&stop);
                let sent = Arc::clone(&sent);
                async move {
                    while !stop.load(Ordering::SeqCst) {
                        if reload_tx.send(new_config.clone()).await.is_err() {
                            break;
                        }
                        sent.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
            assert!(
                poll_until(READY_TIMEOUT, || sent.load(Ordering::SeqCst) > 0).await,
                "the reloads should have started arriving before the wait does"
            );

            let (logs, _guard) = capture_logs();
            let end = tokio::time::timeout(READY_TIMEOUT, wait_without_web(&mut fixture))
                .await
                .expect("the wait should end on the finished handle, not on the reloads stopping");

            assert!(
                !sender.is_finished(),
                "the reloads should still have been arriving when the wait ended"
            );
            stop.store(true, Ordering::SeqCst);
            sender.abort();

            assert_eq!(end, GenerationEnd::EntryTaskExited(Subsystem::Peer));
            assert_report_fields(
                &abnormal_report(&logs),
                Subsystem::Peer,
                id,
                "serving",
                "early_exit",
            );
            assert!(
                captured(&logs).contains("Failed to update configuration"),
                "the failing write is what the check follows"
            );
            fixture.settle().await;
        }

        /// One failed configuration write on its own leaves the generation
        /// serving.
        ///
        /// The check that follows it finds nothing ready, so it returns to the
        /// selection immediately — and the next reload, sent once the
        /// configuration file exists, is applied normally.
        #[tokio::test]
        async fn a_failed_configuration_write_alone_keeps_the_generation_serving() {
            let dir = tempdir().expect("tempdir");
            let mut fixture = wait_fixture(dir.path());
            let reload_tx = fixture.reload_tx.clone();
            let settings = fixture.settings.clone();
            let mut applied = settings.config.visible.clone();
            applied.ack_transmission = settings.config.visible.ack_transmission + 1;

            let (logs, _guard) = capture_logs();
            let (end, ()) = tokio::join!(wait_without_web(&mut fixture), async {
                reload_tx
                    .send(settings.config.visible.clone())
                    .await
                    .expect("the wait should still hold the receiver");
                wait_for_logs(&logs, &["Failed to update configuration"]).await;

                // The path is writable now, so the next reload is persisted.
                write_config_file(&settings);
                reload_tx
                    .send(applied)
                    .await
                    .expect("the wait should still hold the receiver");
            });

            assert_eq!(end, GenerationEnd::ReloadConfig);
            assert_eq!(
                fixture.settings.config.visible.ack_transmission,
                settings.config.visible.ack_transmission + 1,
                "the second reload should have been applied"
            );
            assert!(
                records(&logs, ABNORMAL_RECORD).is_empty(),
                "nothing ended abnormally, got: {}",
                captured(&logs)
            );
            fixture.settle().await;
        }

        /// A resolver that parks until the test releases it.
        ///
        /// `entered` fires the first time the resolver is reached, so a test
        /// can prove a request is genuinely in flight rather than infer it
        /// from a wall-clock sleep; `release` is what lets the request answer.
        /// A request that has not been released is what keeps
        /// [`WebController::shutdown`] from returning, which is how a TLS
        /// reload is held mid-flight without a production seam.
        #[derive(Clone)]
        struct ParkSignal {
            entered: Arc<Notify>,
            release: Arc<Notify>,
        }

        struct ParkQuery;

        #[Object]
        impl ParkQuery {
            async fn hello(&self) -> &'static str {
                "world"
            }

            async fn park(&self, ctx: &async_graphql::Context<'_>) -> &'static str {
                let (entered, release) = {
                    let signal = ctx
                        .data::<ParkSignal>()
                        .expect("the parking schema carries its signal");
                    (Arc::clone(&signal.entered), Arc::clone(&signal.release))
                };
                entered.notify_one();
                release.notified().await;
                "released"
            }
        }

        fn parking_schema(
            signal: &ParkSignal,
        ) -> Schema<ParkQuery, EmptyMutation, EmptySubscription> {
            Schema::build(ParkQuery, EmptyMutation, EmptySubscription)
                .data(signal.clone())
                .finish()
        }

        /// The graceful-shutdown timeout the held reload runs under.
        ///
        /// Long enough that the parked request is never cut off before the
        /// test releases it, which is what makes the hold a hold rather than a
        /// race against a deadline.
        const WEB_HOLD_TIMEOUT: Duration = Duration::from_secs(30);

        /// What the test raises while the TLS reload is held mid-flight.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum MidFlight {
            /// A terminal intent, over a configuration reload queued before
            /// the wait and an entry handle that has already finished.
            Reboot,
            /// A configuration update whose write succeeds, over that same
            /// finished handle.
            PersistedReload,
            /// A configuration update whose write fails, so the check that
            /// follows it is what finds the finished handle.
            FailingReload,
            /// Another SIGHUP alongside a configuration update whose write
            /// fails, so the reload outranks both.
            AnotherTlsReload,
        }

        /// What outranks what at the selection a non-ending arm returns to.
        ///
        /// The TLS reload is held mid-flight by a real request that has not
        /// been answered: `reload_https_server` shuts the live HTTPS server
        /// down gracefully, and `WebController::shutdown` cannot return while
        /// a request is still in its resolver. The graceful-shutdown record is
        /// what confirms the branch was entered, and the request that has not
        /// been released is what keeps it there — nothing here is inferred
        /// from a wall-clock sleep.
        ///
        /// The TLS material has to actually change for that path to run at
        /// all: with a live controller and unchanged material the reload
        /// returns before it touches the server. So a valid but different
        /// certificate set is written to the same paths before the SIGHUP.
        ///
        /// This is the order that applies immediately after the branch
        /// returns, not preemption of the reload that was running.
        // Four rounds of one drive, each with its own live server, parked
        // request and assertions; splitting them would mean four copies of the
        // setup rather than one.
        #[allow(clippy::too_many_lines)]
        #[tokio::test]
        async fn what_outranks_what_when_a_tls_reload_returns() {
            for injection in [
                MidFlight::Reboot,
                MidFlight::PersistedReload,
                MidFlight::FailingReload,
                MidFlight::AnotherTlsReload,
            ] {
                let case = format!("{injection:?}");
                let dir = tempdir().expect("tempdir");
                let mut fixture = wait_fixture(dir.path());
                // The two cases whose reload has to persist need the file the
                // rewrite backs up; the other two reach the failure arm by not
                // having it.
                if matches!(injection, MidFlight::Reboot | MidFlight::PersistedReload) {
                    write_config_file(&fixture.settings);
                }
                let id = fixture
                    .finish_entry_task(Subsystem::Ingest, async { Ok(()) })
                    .await;

                // A live HTTPS server with one request parked inside it.
                let tls = tls_reload::get_current_tls_material(&fixture.process.tls_watch);
                let web_addr = free_addr();
                let signal = ParkSignal {
                    entered: Arc::new(Notify::new()),
                    release: Arc::new(Notify::new()),
                };
                let mut web_controller = Some(
                    web::serve(
                        parking_schema(&signal),
                        web_addr,
                        tls.cert_pem.clone(),
                        tls.key_pem.clone(),
                        tls.ca_pem.clone(),
                        WEB_HOLD_TIMEOUT,
                    )
                    .await
                    .unwrap_or_else(|e| panic!("{case}: the parking server should start: {e:#}")),
                );
                let client = super::reload_https_server_tests::build_mtls_client(
                    &tls.cert_pem,
                    &tls.key_pem,
                    &tls.ca_pem,
                );
                let parked = task::spawn(async move {
                    client
                        .post(format!("https://{web_addr}/graphql"))
                        .header("Content-Type", "application/json")
                        .body(r#"{"query":"{ park }"}"#)
                        .send()
                        .await
                });
                tokio::time::timeout(READY_TIMEOUT, signal.entered.notified())
                    .await
                    .unwrap_or_else(|_| {
                        panic!("{case}: the request should have reached the resolver")
                    });

                // Valid but different material on the same paths, so the
                // reload has something to rebind for.
                write_node_pki(dir.path());
                fixture.notify_tls_reload.notify_one();
                if injection == MidFlight::Reboot {
                    // Queued before the wait, so what the reboot outranks is a
                    // reload that was already there.
                    fixture
                        .reload_tx
                        .send(fixture.settings.config.visible.clone())
                        .await
                        .expect("the wait should still hold the receiver");
                }

                let notify_reboot = Arc::clone(&fixture.notify_reboot);
                let notify_tls_reload = Arc::clone(&fixture.notify_tls_reload);
                let reload_tx = fixture.reload_tx.clone();
                let release = Arc::clone(&signal.release);
                let mut injected = fixture.settings.config.visible.clone();
                injected.ack_transmission += 1;
                let before = fixture.settings.config.visible.ack_transmission;
                let schema = parking_schema(&signal);

                let (logs, guard) = capture_logs();
                let (end, ()) = tokio::time::timeout(GENERATION_TIMEOUT, async {
                    tokio::join!(
                        wait_for_generation_end(
                            &mut fixture.settings,
                            &fixture.process,
                            &mut fixture.intents,
                            &mut fixture.entry_tasks,
                            &mut web_controller,
                            &schema,
                            web_addr,
                            WEB_HOLD_TIMEOUT,
                        ),
                        async {
                            wait_for_logs(&logs, &["HTTPS reload: initiating graceful shutdown"])
                                .await;
                            match injection {
                                MidFlight::Reboot => notify_reboot.notify_one(),
                                MidFlight::AnotherTlsReload => {
                                    notify_tls_reload.notify_one();
                                    reload_tx
                                        .send(injected)
                                        .await
                                        .expect("the wait still holds the receiver");
                                }
                                _ => reload_tx
                                    .send(injected)
                                    .await
                                    .expect("the wait still holds the receiver"),
                            }
                            release.notify_one();
                        }
                    )
                })
                .await
                .unwrap_or_else(|_| panic!("{case}: the wait should have ended"));

                let output = captured(&logs);
                match injection {
                    MidFlight::Reboot => {
                        assert_eq!(end, GenerationEnd::Reboot, "{case}");
                        assert_eq!(
                            fixture.settings.config.visible.ack_transmission, before,
                            "{case}: the queued reload should still be queued"
                        );
                        // The handle the reboot outranked is handed to the
                        // teardown marked as having already finished, which is
                        // what makes it an early exit rather than a clean stop
                        // when it is read back after the drain.
                        let handed_over = fixture.take_retained();
                        assert!(
                            handed_over
                                .iter()
                                .any(|task| task.handle.id() == id && task.already_finished),
                            "{case}: the finished handle should have been handed over"
                        );
                    }
                    MidFlight::PersistedReload => {
                        assert_eq!(end, GenerationEnd::ReloadConfig, "{case}");
                        assert!(
                            fixture.entry_tasks.ingest.is_some(),
                            "{case}: the update outranks the finished handle"
                        );
                        assert_eq!(
                            fixture.settings.config.visible.ack_transmission,
                            before + 1,
                            "{case}: the update should have been applied"
                        );
                    }
                    MidFlight::FailingReload => {
                        assert_eq!(
                            end,
                            GenerationEnd::EntryTaskExited(Subsystem::Ingest),
                            "{case}"
                        );
                        assert!(
                            output.contains("Failed to update configuration"),
                            "{case}: the check follows a write that failed, got: {output}"
                        );
                        assert_report_fields(
                            &abnormal_report(&logs),
                            Subsystem::Ingest,
                            id,
                            "serving",
                            "early_exit",
                        );
                    }
                    MidFlight::AnotherTlsReload => {
                        assert_eq!(
                            end,
                            GenerationEnd::EntryTaskExited(Subsystem::Ingest),
                            "{case}"
                        );
                        // The second reload has nothing to rebind — the files
                        // have not changed since the first one read them — so
                        // it returns at once. That it ran at all, and ran
                        // before the finished handle was taken, is the order
                        // under test.
                        assert_precedes(
                            &logs,
                            TLS_NOOP_RECORD,
                            ABNORMAL_RECORD,
                            &format!("{case}: the pending reload should have gone first"),
                        );
                        assert_report_fields(
                            &abnormal_report(&logs),
                            Subsystem::Ingest,
                            id,
                            "serving",
                            "early_exit",
                        );
                    }
                }
                drop(guard);

                fixture.settle().await;
                shutdown_web(web_controller.take()).await;
                tokio::time::timeout(READY_TIMEOUT, parked)
                    .await
                    .unwrap_or_else(|_| panic!("{case}: the released request should have answered"))
                    .unwrap_or_else(|e| panic!("{case}: the request task should join: {e}"))
                    .unwrap_or_else(|e| panic!("{case}: the request should succeed: {e}"));
            }
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

                let health =
                    shutdown_generation(empty_teardown(), generation_end, &database, &effects)
                        .await
                        .unwrap_or_else(|e| {
                            panic!("{ending}: the teardown should not fail: {e:#}")
                        });
                assert_eq!(
                    health,
                    GenerationHealth::Clean,
                    "{ending}: a teardown with nothing to read back is not degraded"
                );
                let flow = act_on_generation_end(clean(generation_end), &effects);

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
                    GenerationEnd::EntryTaskExited(subsystem) => {
                        let error = flow
                            .err()
                            .unwrap_or_else(|| panic!("{ending}: an early exit should fail"));
                        assert!(
                            error
                                .to_string()
                                .contains(&format!("the {subsystem} subsystem ended")),
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

                let error = act_on_generation_end(clean(generation_end), &effects)
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

        /// A retained handle that came back badly is reported, degrades the
        /// generation, and suppresses nothing.
        ///
        /// The three abnormal completions a handle can carry, against the two
        /// shapes of final action: a host command, and the next generation.
        /// The rest of the teardown and the database shutdown still run, the
        /// action is still taken, and the record names the task at
        /// `phase="after_drain"`.
        #[tokio::test(start_paused = true)]
        async fn a_failed_retained_handle_is_reported_and_suppresses_no_action() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);
            let tracker = TaskTracker::new();

            for outcome in ["error", "panic", "cancelled"] {
                for generation_end in [GenerationEnd::Reboot, GenerationEnd::ReloadConfig] {
                    let case = format!("{outcome}/{generation_end:?}");
                    // Installed before the stand-in is built: a panic and an
                    // abort are reported by the registration guard the moment
                    // they happen, not when the handle is read back.
                    let (logs, guard) = capture_logs();
                    let handle = match outcome {
                        "error" => stand_in(&tracker, Subsystem::Retention, async {
                            Err(anyhow!("a retention pass failed"))
                        }),
                        "panic" => stand_in(&tracker, Subsystem::Retention, async {
                            panic!("the retention task panicked")
                        }),
                        _ => {
                            // Aborted before the teardown reads it, so the
                            // join returns a cancellation `JoinError`.
                            let handle =
                                stand_in(&tracker, Subsystem::Retention, std::future::pending());
                            handle.abort();
                            handle
                        }
                    };
                    let id = handle.id();

                    let effects = RecordingEffects::new();
                    let health = shutdown_generation(
                        teardown_with_entry_tasks(vec![retained(handle, false)]),
                        generation_end,
                        &database,
                        &effects,
                    )
                    .await
                    .unwrap_or_else(|e| panic!("{case}: the teardown should not fail: {e:#}"));
                    assert_eq!(
                        health,
                        GenerationHealth::Degraded,
                        "{case}: an abnormal handle degrades the generation"
                    );
                    let flow = act_on_generation_end(
                        GenerationOutcome {
                            ending: generation_end,
                            health,
                        },
                        &effects,
                    );

                    assert_report_fields(
                        &abnormal_report(&logs),
                        Subsystem::Retention,
                        id,
                        "after_drain",
                        outcome,
                    );
                    assert_marker_sequence(&logs, &full_marker_sequence(generation_end), &case);
                    assert_lifecycle_record(&sole_record(&logs, DEGRADED_RECORD), generation_end);

                    if generation_end == GenerationEnd::Reboot {
                        assert_eq!(
                            effects.calls(),
                            vec![EffectCall::ShutdownDatabase, EffectCall::Reboot],
                            "{case}: the reboot should still have been asked for"
                        );
                        let error = flow.err().unwrap_or_else(|| {
                            panic!("{case}: a degraded reboot should fail the lifecycle")
                        });
                        assert!(
                            error.to_string().contains("degraded"),
                            "{case}: got: {error:#}"
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

        /// A retained handle that stopped because the drain cancelled it is
        /// not a failure.
        ///
        /// It is the one shape reported at `info!`, with `outcome="clean"`,
        /// and it leaves the generation undegraded and the lifecycle result a
        /// success. The stand-in waits for its token, so it returns `Ok(())`
        /// only because the drain cancelled it.
        #[tokio::test(start_paused = true)]
        async fn a_retained_handle_that_stopped_on_cancellation_is_clean() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);

            let top_level_tracker = TaskTracker::new();
            let handle = top_level_tracker
                .spawn_supervised("retention", |cancel| async move {
                    cancel.cancelled().await;
                    Ok(())
                })
                .expect("a fresh tracker admits the retention stand-in");
            let id = handle.id();

            let effects = RecordingEffects::new();
            let (logs, _guard) = capture_logs();
            let health = shutdown_generation(
                GenerationTeardown {
                    web_controller: None,
                    web_reaper_tracker: TaskTracker::new(),
                    top_level_tracker,
                    entry_tasks: vec![retained(handle, false)],
                },
                GenerationEnd::Terminate,
                &database,
                &effects,
            )
            .await
            .expect("the teardown should not fail");

            assert_eq!(health, GenerationHealth::Clean);
            assert_report_fields(
                &sole_record(&logs, CLEAN_RECORD),
                Subsystem::Retention,
                id,
                "after_drain",
                "clean",
            );
            assert!(
                records(&logs, ABNORMAL_RECORD).is_empty(),
                "a cancelled task that stopped is not abnormal, got: {}",
                captured(&logs)
            );
            assert_eq!(
                act_on_generation_end(clean(GenerationEnd::Terminate), &effects)
                    .expect("a clean terminate should not fail"),
                ControlFlow::Break(())
            );
        }

        /// An `Ok(())` from a handle that had already finished when the wait
        /// ended is an early exit, not a clean stop.
        ///
        /// Cancellation happens inside the drain, so a task that was already
        /// finished cannot have finished because of it. The two cases differ
        /// only in that flag, and they are read as different outcomes.
        #[tokio::test(start_paused = true)]
        async fn an_already_finished_handle_reads_as_an_early_exit() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);
            let tracker = TaskTracker::new();
            let handle = finished_stand_in(&tracker, Subsystem::Publish, async { Ok(()) }).await;
            let id = handle.id();

            let effects = RecordingEffects::new();
            let (logs, _guard) = capture_logs();
            let health = shutdown_generation(
                teardown_with_entry_tasks(vec![retained(handle, true)]),
                GenerationEnd::Terminate,
                &database,
                &effects,
            )
            .await
            .expect("the teardown should not fail");

            assert_eq!(health, GenerationHealth::Degraded);
            assert_report_fields(
                &abnormal_report(&logs),
                Subsystem::Publish,
                id,
                "after_drain",
                "early_exit",
            );
        }

        /// What the lifecycle returns for a degraded generation, per ending.
        ///
        /// The final action is taken on every row; only the result differs,
        /// and the configuration reload is the one row a degradation does not
        /// fail. One outcome class is enough here: the ending contract does
        /// not vary by class.
        #[tokio::test(start_paused = true)]
        async fn a_degraded_generation_still_takes_its_action() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);
            let tracker = TaskTracker::new();

            for generation_end in ALL_ENDINGS {
                let ending = format!("{generation_end:?}");
                let handle = stand_in(&tracker, Subsystem::Ingest, async {
                    Err(anyhow!("the listener is gone"))
                });

                let effects = RecordingEffects::new();
                let (logs, guard) = capture_logs();
                let health = shutdown_generation(
                    teardown_with_entry_tasks(vec![retained(handle, false)]),
                    generation_end,
                    &database,
                    &effects,
                )
                .await
                .unwrap_or_else(|e| panic!("{ending}: the teardown should not fail: {e:#}"));
                assert_eq!(health, GenerationHealth::Degraded, "{ending}");

                let flow = act_on_generation_end(degraded(generation_end), &effects);
                let expected_calls = match generation_end {
                    GenerationEnd::Reboot => {
                        vec![EffectCall::ShutdownDatabase, EffectCall::Reboot]
                    }
                    GenerationEnd::PowerOff => {
                        vec![EffectCall::ShutdownDatabase, EffectCall::PowerOff]
                    }
                    _ => vec![EffectCall::ShutdownDatabase],
                };
                assert_eq!(
                    effects.calls(),
                    expected_calls,
                    "{ending}: the ending's action is taken whatever the health"
                );

                if generation_end == GenerationEnd::ReloadConfig {
                    assert_eq!(
                        flow.unwrap_or_else(|e| panic!("{ending}: {e:#}")),
                        ControlFlow::Continue(()),
                        "{ending}: a degraded reload still hands over to the next generation"
                    );
                } else {
                    assert!(
                        flow.is_err(),
                        "{ending}: a degraded generation should fail the lifecycle"
                    );
                }
                assert_lifecycle_record(&sole_record(&logs, DEGRADED_RECORD), generation_end);
                drop(guard);
            }
        }

        /// A store that cannot be shut down still suppresses the action, even
        /// when the generation is also degraded.
        #[tokio::test(start_paused = true)]
        async fn a_failed_database_shutdown_beats_a_degraded_generation() {
            let dir = tempdir().expect("tempdir");
            let settings = test_settings(dir.path());
            let database = test_database(&settings.config.visible.data_dir);
            let tracker = TaskTracker::new();
            let handle = stand_in(&tracker, Subsystem::Ingest, async {
                Err(anyhow!("the listener is gone"))
            });
            let id = handle.id();

            let effects = RecordingEffects::failing();
            let (logs, _guard) = capture_logs();
            let error = shutdown_generation(
                teardown_with_entry_tasks(vec![retained(handle, false)]),
                GenerationEnd::Reboot,
                &database,
                &effects,
            )
            .await
            .expect_err("a failed database shutdown should end the teardown");

            assert!(
                error.to_string().contains(SHUTDOWN_FAILURE),
                "the seam's failure should be what propagates, got: {error:#}"
            );
            assert_eq!(
                effects.calls(),
                vec![EffectCall::ShutdownDatabase],
                "no host action may follow a store whose state is unknown"
            );
            // The handle was still read, before the store was touched.
            assert_report_fields(
                &abnormal_report(&logs),
                Subsystem::Ingest,
                id,
                "after_drain",
                "error",
            );
        }

        /// A degraded generation whose host action also fails returns the
        /// action's error, and both records reach the log in order.
        #[tokio::test]
        async fn a_degraded_generation_whose_host_action_fails_reports_both() {
            let effects = RecordingEffects::refusing_host_actions();
            let (logs, guard) = capture_logs();

            let error = act_on_generation_end(degraded(GenerationEnd::Reboot), &effects)
                .expect_err("a refused command should fail the lifecycle");

            assert!(
                error.to_string().contains(HOST_REFUSAL),
                "the host's refusal is the more actionable of the two, got: {error:#}"
            );
            let degraded_record = sole_record(&logs, DEGRADED_RECORD);
            let failed_action = sole_record(&logs, FAILED_ACTION_RECORD);
            assert_lifecycle_record(&degraded_record, GenerationEnd::Reboot);
            assert_lifecycle_record(&failed_action, GenerationEnd::Reboot);
            assert!(
                failed_action.contains(HOST_REFUSAL),
                "the failed-action record should carry the cause, got: {failed_action}"
            );
            assert_precedes(
                &logs,
                DEGRADED_RECORD,
                FAILED_ACTION_RECORD,
                "the degraded record comes first",
            );
            drop(guard);

            // The companion: a reboot that succeeds leaves the degraded record
            // alone, with no failed-action record beside it.
            let effects = RecordingEffects::new();
            let (logs, _guard) = capture_logs();
            let error = act_on_generation_end(degraded(GenerationEnd::Reboot), &effects)
                .expect_err("a degraded reboot should fail the lifecycle");
            assert!(error.to_string().contains("degraded"), "got: {error:#}");
            assert_lifecycle_record(&sole_record(&logs, DEGRADED_RECORD), GenerationEnd::Reboot);
            assert!(
                records(&logs, FAILED_ACTION_RECORD).is_empty(),
                "an action that succeeded leaves no failure record, got: {}",
                captured(&logs)
            );
        }

        /// A task that has completed and left the registry is still reported
        /// with its name, id and elapsed time.
        ///
        /// The registration guard removes the registry entry as the task
        /// returns, which is the very moment the boundary reads the handle, so
        /// nothing about the task is recoverable from the tracker by then. The
        /// copy the supervised handle carries is what survives that.
        #[tokio::test]
        async fn a_supervised_handle_names_a_task_the_registry_has_forgotten() {
            let tracker = TaskTracker::new();
            let handle = finished_stand_in(&tracker, Subsystem::Peer, async { Ok(()) }).await;
            let id = handle.id();
            assert_eq!(
                tracker.pending_count(),
                0,
                "the task should have left the registry"
            );

            let (logs, _guard) = capture_logs();
            assert!(observe_entry_task(retained(handle, true)).await);
            assert_report_fields(
                &abnormal_report(&logs),
                Subsystem::Peer,
                id,
                "after_drain",
                "early_exit",
            );

            // The other half: `spawn` is untouched, so a caller that wants a
            // bare handle still gets one.
            let plain: JoinHandle<Result<()>> = tracker
                .spawn("plain", |_cancel| async { Ok(()) })
                .expect("the tracker still admits a plain spawn");
            plain
                .await
                .expect("the plain task should join")
                .expect("the plain task should succeed");
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
        #[allow(clippy::too_many_lines)]
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
                let retain_task_handle = tracker
                    .spawn_supervised("retention", {
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
                let retain_task_id = retain_task_handle.id();

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
                                entry_tasks: vec![retained(retain_task_handle, false)],
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
                assert_report_fields(
                    &sole_record(&logs, CLEAN_RECORD),
                    Subsystem::Retention,
                    retain_task_id,
                    "after_drain",
                    "clean",
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
                            entry_tasks: Vec::new(),
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
                Arc::new(CustomerDeletionCoordinator::new()),
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
                records(&logs, CLEAN_RECORD).len() == 3,
                "the three entry tasks should each have stopped cleanly, got: {output}"
            );
            assert!(
                records(&logs, ABNORMAL_RECORD).is_empty(),
                "nothing should have ended abnormally, got: {output}"
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

            assert_eq!(end, clean(GenerationEnd::Terminate));

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

        /// A peer subsystem that ends on its own takes the generation with it.
        ///
        /// The configuration file is never written, so the peer subsystem
        /// fails the read it performs on startup and returns an error instead
        /// of parking. Nothing is notified here: the only thing that can end
        /// this generation is the peer entry task, and a generation that
        /// carried on serving without peer would sit here until
        /// `GENERATION_TIMEOUT`.
        #[tokio::test]
        async fn a_peer_subsystem_that_ends_early_ends_the_generation() {
            let dir = tempdir().expect("tempdir");
            let process = test_process_context(dir.path(), Arc::new(Notify::new()));
            let mut settings = test_settings(dir.path());
            settings.config.peer_srv_addr = Some(ephemeral_addr());

            let (logs, _guard) = capture_logs();
            let end = tokio::time::timeout(
                GENERATION_TIMEOUT,
                run_generation(&mut settings, &process, &HostEffects),
            )
            .await
            .expect("a failed peer subsystem should end the generation on its own")
            .expect("an entry task that ended is not a failure of the generation itself");

            assert_eq!(
                end,
                clean(GenerationEnd::EntryTaskExited(Subsystem::Peer)),
                "the generation should name the subsystem that ended it"
            );

            let output = captured(&logs);
            // The subsystem still reports its own failure where it happens;
            // the boundary record is in addition to it, not in place of it.
            assert!(
                output.contains("Peer subsystem terminated unexpectedly"),
                "the peer subsystem should report its own error, got: {output}"
            );
            let report = abnormal_report(&logs);
            assert!(
                report.contains("name=\"peer\"") && report.contains("phase=\"serving\""),
                "the boundary should name the task it observed, got: {report}"
            );
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
            // One record at the coordination boundary, naming the task and
            // classing the outcome: the task returned an error, it did not
            // panic and it was not cancelled.
            let report = abnormal_report(&logs);
            assert!(
                report.contains("name=\"ingest\"")
                    && report.contains("phase=\"serving\"")
                    && report.contains("outcome=\"error\""),
                "the boundary should class what it observed, got: {report}"
            );
            // The generation still went down the common shutdown sequence:
            // the subsystems it did start were notified and the drain ran.
            assert!(
                output.contains("Shutting down publish"),
                "the early exit should run the same shutdown sequence as an intent, got: {output}"
            );
            assert_marker_sequence(
                &logs,
                &full_marker_sequence(GenerationEnd::EntryTaskExited(Subsystem::Ingest)),
                "EntryTaskExited(Ingest)",
            );
        }

        /// A publish listener that cannot bind ends the generation too.
        ///
        /// The other half of the ingest case above, and the whole point of
        /// watching more than one entry task: a node serving no publish
        /// traffic used to run to the end of the generation with nothing but
        /// the subsystem's own line about it. Nothing is notified here, so the
        /// publish entry task is the only thing that can end this generation.
        #[tokio::test]
        async fn a_publish_listener_that_cannot_bind_ends_the_generation() {
            let dir = tempdir().expect("tempdir");
            let process = test_process_context(dir.path(), Arc::new(Notify::new()));
            let mut settings = test_settings(dir.path());

            // QUIC is UDP, so the port has to be held by a UDP socket for the
            // publish listener to lose it.
            let occupied = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("occupy the publish port");
            settings.config.visible.publish_srv_addr =
                occupied.local_addr().expect("occupied addr");

            let (logs, _guard) = capture_logs();
            let end = tokio::time::timeout(
                GENERATION_TIMEOUT,
                run_generation(&mut settings, &process, &HostEffects),
            )
            .await
            .expect("a failed publish listener should end the generation on its own")
            .expect("an entry task that ended is not a failure of the generation itself");

            assert_eq!(
                end,
                clean(GenerationEnd::EntryTaskExited(Subsystem::Publish))
            );

            let output = captured(&logs);
            assert!(
                output.contains("failed to bind the publish listener"),
                "the bind failure itself should be reported, got: {output}"
            );
            assert!(
                output.contains("Publish subsystem terminated unexpectedly"),
                "the entry task should report its own error, got: {output}"
            );
            assert!(
                !output.contains("tracked task did not run to completion"),
                "the entry task returned, it did not vanish, got: {output}"
            );
            let report = abnormal_report(&logs);
            assert!(
                report.contains("name=\"publish\"") && report.contains("phase=\"serving\""),
                "the boundary should name the task it observed, got: {report}"
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
            assert_eq!(end, clean(GenerationEnd::Terminate));
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

        /// An accepted customer deletion finishes before the generation closes
        /// the database, on every ending an operator can ask for.
        ///
        /// The observable is the deletion job's own status, read at the moment
        /// the teardown shuts the store down: a teardown that reached that
        /// point while the job was still `InProgress` did not wait for the
        /// deletion, whatever the log says. The deletion is held past the
        /// start of the drain by a read guard on the sensor list — the
        /// supervisor takes that lock for writing once the RocksDB deletes are
        /// done — and the drain's own `close` is what the test waits on, so no
        /// step here is timed.
        #[cfg(feature = "bootroot")]
        #[tokio::test]
        async fn an_accepted_deletion_finishes_before_the_generation_closes_the_database() {
            use crate::storage::CustomerDataDeletionStatus;

            const CUSTOMER_ID: u32 = 400;
            let target = "piglet.node1.example.test";

            for generation_end in [
                GenerationEnd::Terminate,
                GenerationEnd::ReloadConfig,
                GenerationEnd::Reboot,
                GenerationEnd::PowerOff,
            ] {
                let ending = format!("{generation_end:?}");
                let schema = crate::graphql::tests::TestSchema::new_with_ingest_sensors(&[target]);
                let hold_sensors = schema.ingest_sensors.read().await;

                let accepted = schema
                    .execute(&format!(
                        r#"mutation {{
                            deleteCustomerData(
                                serviceFqdnList: ["{target}"]
                                customerId: "{CUSTOMER_ID}"
                            )
                        }}"#
                    ))
                    .await;
                assert!(
                    accepted.errors.is_empty(),
                    "{ending}: {:?}",
                    accepted.errors
                );
                assert_eq!(
                    accepted.data.to_string(),
                    "{deleteCustomerData: ACCEPTED}",
                    "{ending}"
                );

                let effects = JobStatusAtShutdown::new(schema.db.clone(), CUSTOMER_ID);
                let shutdown = task::spawn({
                    let database = schema.db.clone();
                    let effects = effects.clone();
                    let top_level_tracker = schema.top_level_tracker.clone();
                    async move {
                        shutdown_generation(
                            GenerationTeardown {
                                web_controller: None,
                                web_reaper_tracker: TaskTracker::new(),
                                top_level_tracker,
                                entry_tasks: Vec::new(),
                            },
                            generation_end,
                            &database,
                            &effects,
                        )
                        .await
                    }
                });

                // The drain closes the tracker on its way in, so this is the
                // teardown having reached the phase that has to wait.
                let closed = async {
                    while !schema.top_level_tracker.is_closed() {
                        sleep(READY_POLL).await;
                    }
                };
                assert!(
                    tokio::time::timeout(READY_TIMEOUT, closed).await.is_ok(),
                    "{ending}: the teardown never reached the drain"
                );
                assert_eq!(
                    job_status(&schema.db, CUSTOMER_ID),
                    Some(CustomerDataDeletionStatus::InProgress),
                    "{ending}: the deletion should still have been running"
                );
                assert!(
                    effects.observed().is_none(),
                    "{ending}: the store was shut down while a deletion was still running"
                );

                drop(hold_sensors);
                let store_shutdown = async {
                    while effects.observed().is_none() {
                        sleep(READY_POLL).await;
                    }
                };
                assert!(
                    tokio::time::timeout(READY_TIMEOUT, store_shutdown)
                        .await
                        .is_ok(),
                    "{ending}: the teardown never shut the store down"
                );
                assert_eq!(
                    effects.observed(),
                    Some(ShutdownObservation::Job(
                        CustomerDataDeletionStatus::Succeeded
                    )),
                    "{ending}: the deletion had not finished when the store was shut down"
                );

                // What is left of the teardown is the pause before the
                // ending's action, and this test is not waiting it out.
                shutdown.abort();
            }
        }

        #[cfg(feature = "bootroot")]
        fn job_status(
            db: &storage::Database,
            customer_id: u32,
        ) -> Option<crate::storage::CustomerDataDeletionStatus> {
            db.customer_deletion_job_store()
                .expect("open the customer deletion job store")
                .get(customer_id)
                .expect("read the customer deletion job")
                .map(|job| job.status)
        }

        /// What the seam below found in the job store when it ran.
        #[cfg(feature = "bootroot")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum ShutdownObservation {
            /// The customer had no deletion job at all.
            NoJob,
            /// The customer's deletion job stood at this status.
            Job(crate::storage::CustomerDataDeletionStatus),
        }

        /// A lifecycle seam that records a customer deletion job's status at
        /// the moment the store is shut down.
        ///
        /// The ordering under test is a fact about the job rather than a line
        /// in a log, and this is where that fact is legible: the seam runs
        /// exactly once, at the top of the last teardown phase.
        #[cfg(feature = "bootroot")]
        #[derive(Clone)]
        struct JobStatusAtShutdown {
            db: storage::Database,
            customer_id: u32,
            /// `None` until the store is shut down; then what the job store
            /// held at that moment.
            observed: Arc<Mutex<Option<ShutdownObservation>>>,
        }

        #[cfg(feature = "bootroot")]
        impl JobStatusAtShutdown {
            fn new(db: storage::Database, customer_id: u32) -> Self {
                Self {
                    db,
                    customer_id,
                    observed: Arc::new(Mutex::new(None)),
                }
            }

            fn observed(&self) -> Option<ShutdownObservation> {
                *self.observed.lock().expect("lock")
            }
        }

        #[cfg(feature = "bootroot")]
        impl LifecycleEffects for JobStatusAtShutdown {
            fn shutdown_database(&self, _database: &storage::Database) -> Result<()> {
                let observation = job_status(&self.db, self.customer_id)
                    .map_or(ShutdownObservation::NoJob, ShutdownObservation::Job);
                *self.observed.lock().expect("lock") = Some(observation);
                Ok(())
            }

            fn reboot(&self) -> Result<()> {
                unreachable!("the teardown itself takes no host action")
            }

            fn power_off(&self) -> Result<()> {
                unreachable!("the teardown itself takes no host action")
            }
        }
    }
}
