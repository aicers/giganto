mod graphql;
mod ingest;
mod peer;
mod publish;
mod server;
mod settings;
mod storage;
mod web;

use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    path::Path,
    process::exit,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use clap::Parser;
use peer::{PeerIdentity, PeerIdents, PeerInfo, Peers};
use quinn::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use settings::{ConfigVisible, Settings};
use storage::{Database, data_dir_to_secondary_path, db_path_and_option, repair_db};
use tokio::{
    runtime, select,
    sync::{
        Notify, RwLock,
        mpsc::{self, UnboundedSender},
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
    graphql::NodeName,
    server::{Certs, SERVER_REBOOT_DELAY, subject_from_cert},
    settings::Args,
    storage::migrate_data_dir,
};

const ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);
const WAIT_SHUTDOWN: u64 = 15;

pub type PcapSensors = Arc<RwLock<HashMap<String, Vec<Connection>>>>;
pub type IngestSensors = Arc<RwLock<HashSet<String>>>;
pub type RunTimeIngestSensors = Arc<RwLock<HashMap<String, DateTime<Utc>>>>;
pub type StreamDirectChannels = Arc<RwLock<HashMap<String, UnboundedSender<Vec<u8>>>>>;

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut settings = Settings::from_file(&args.config).or_else(|e| {
        eprintln!(
            "failed to read configuration file: {}. Error: {e}",
            args.config
        );

        let backup_path = Path::new(&args.config).with_extension("toml.bak");
        if backup_path.exists() {
            println!(
                "attempting to restore backup configuration from: {}",
                backup_path.display()
            );

            fs::copy(&backup_path, &args.config).with_context(|| {
                format!(
                    "failed to restore configuration from backup: {} to {}",
                    backup_path.display(),
                    &args.config
                )
            })?;

            println!("configuration restored from backup.");

            Settings::from_file(&args.config).with_context(|| {
                format!(
                    "failed to read restored configuration file: {}",
                    backup_path.display()
                )
            })
        } else {
            Err(e).context("no valid configuration file available, and no backup found.")
        }
    })?;

    settings.config.validate()?;

    let cfg_path = settings.cfg_path.clone();

    let _guard = init_tracing(args.log_path.as_deref())?;

    if args.repair {
        repair_db(
            &settings.config.visible.data_dir,
            settings.config.visible.max_open_files,
            settings.config.visible.max_mb_of_level_base,
            settings.config.visible.num_of_thread,
            settings.config.visible.max_sub_compactions,
        );
        exit(0);
    }

    let cert_pem = fs::read(&args.cert)
        .with_context(|| format!("failed to read certificate file: {}", args.cert))?;
    let cert = to_cert_chain(&cert_pem).context("cannot read certificate chain")?;
    assert!(!cert.is_empty());
    let key_pem = fs::read(&args.key)
        .with_context(|| format!("failed to read private key file: {}", args.key))?;
    let key = to_private_key(&key_pem).context("cannot read private key")?;
    let root_cert = to_root_cert(&args.ca_certs)?;
    let certs = Arc::new(Certs {
        certs: cert.clone(),
        key: key.clone_key(),
        root: root_cert.clone(),
    });

    let mut is_reboot = false;
    let mut is_power_off = false;
    let mut is_reload_config = false;

    let notify_terminate = Arc::new(Notify::new());
    let r = notify_terminate.clone();
    if let Err(ctrlc::Error::System(e)) = ctrlc::set_handler(move || r.notify_one()) {
        return Err(anyhow!("failed to set signal handler: {}", e));
    }

    let request_client_pool = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_sni(false)
        .build()
        .expect("Failed to build request client pool");

    loop {
        let (db_path, db_options) = db_path_and_option(
            &settings.config.visible.data_dir,
            settings.config.visible.max_open_files,
            settings.config.visible.max_mb_of_level_base,
            settings.config.visible.num_of_thread,
            settings.config.visible.max_sub_compactions,
        );

        if let Err(e) = migrate_data_dir(&settings.config.visible.data_dir, &db_options) {
            error!("migration failed: {e}");
            bail!("migration failed")
        }

        let primary_database = storage::Database::open(&db_path, &db_options)?;
        let secondary_path = data_dir_to_secondary_path(&settings.config.visible.data_dir);
        let secondary_database =
            storage::Database::open_secondary(&db_path, &secondary_path, &db_options)?;
        secondary_database.try_catch_up_with_primary()?;

        let (reload_tx, mut reload_rx) = mpsc::channel::<ConfigVisible>(1);
        let notify_shutdown = Arc::new(Notify::new());
        let notify_reboot = Arc::new(Notify::new());
        let notify_power_off = Arc::new(Notify::new());
        let mut notify_sensor_change = None;

        let pcap_sensors = new_pcap_sensors();
        let ingest_sensors = new_ingest_sensors(&primary_database);
        let runtime_ingest_sensors = new_runtime_ingest_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let (peers, peer_idents) = new_peers_data(settings.config.peers.clone());
        let ack_transmission_cnt = settings.config.visible.ack_transmission;
        let retain_flag = Arc::new(AtomicBool::new(false));

        let schema = graphql::schema(
            NodeName(subject_from_cert(&cert)?.1),
            secondary_database.clone(),
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

        task::spawn(web::serve(
            schema,
            settings.config.visible.graphql_srv_addr,
            cert_pem.clone(),
            key_pem.clone(),
            notify_shutdown.clone(),
        ));

        let db = primary_database.clone();
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
                error!("retain_periodically task terminated unexpectedly: {e}");
            }
        });

        let peer_task_handle: Option<JoinHandle<Result<()>>>;
        if let Some(addr_to_peers) = settings.config.addr_to_peers {
            let peer_server = peer::Peer::new(addr_to_peers, &certs.clone())?;
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
            secondary_database.clone(),
            pcap_sensors.clone(),
            stream_direct_channels.clone(),
            ingest_sensors.clone(),
            peers.clone(),
            peer_idents.clone(),
            certs.clone(),
            notify_shutdown.clone(),
        ));

        let ingest_server =
            ingest::Server::new(settings.config.visible.ingest_srv_addr, &certs.clone());
        let ingest_task_handle: JoinHandle<()> = task::spawn(ingest_server.run(
            primary_database.clone(),
            pcap_sensors,
            ingest_sensors,
            runtime_ingest_sensors,
            stream_direct_channels,
            notify_shutdown.clone(),
            notify_sensor_change,
            ack_transmission_cnt,
        ));

        let secondary_sync_task_handle: Option<JoinHandle<()>> = None;

        loop {
            select! {
                Some(new_config) = reload_rx.recv() => {
                    match settings.update_config_file(&new_config) {
                        Ok(()) => {
                            notify_shutdown.notify_waiters();
                            wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, secondary_sync_task_handle, retain_task_handle).await;
                            break;
                        }
                        Err(e) => {
                            error!("Failed to update configuration: {e:#}");
                            warn!("Run giganto with the previous config");
                        }
                    }
                },
                () = notify_terminate.notified() => {
                    info!("Termination signal: giganto daemon exit");
                    notify_shutdown.notify_waiters();
                    wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, secondary_sync_task_handle, retain_task_handle).await;
                    sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
                    return Ok(());
                }
                () = notify_reboot.notified() => {
                    info!("Restarting the system...");
                    notify_shutdown.notify_waiters();
                    wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, secondary_sync_task_handle, retain_task_handle).await;
                    is_reboot = true;
                    break;
                }
                () = notify_power_off.notified() => {
                    info!("Power off the system...");
                    notify_shutdown.notify_waiters();
                    wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, secondary_sync_task_handle, retain_task_handle).await;
                    is_power_off = true;
                    break;
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
            primary_database.shutdown()?;
            secondary_database.shutdown()?;

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

fn to_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut &*pem)
        .collect::<Result<_, _>>()
        .context("cannot parse certificate chain")?;
    Ok(certs)
}

fn to_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    match rustls_pemfile::read_one(&mut &*pem)
        .context("cannot parse private key")?
        .ok_or_else(|| anyhow!("empty private key"))?
    {
        rustls_pemfile::Item::Pkcs1Key(key) => Ok(key.into()),
        rustls_pemfile::Item::Pkcs8Key(key) => Ok(key.into()),
        _ => Err(anyhow!("unknown private key format")),
    }
}

fn to_root_cert(ca_certs_paths: &[String]) -> Result<rustls::RootCertStore> {
    let mut ca_certs_files = Vec::new();

    for ca_cert in ca_certs_paths {
        let file = fs::read(ca_cert)
            .with_context(|| format!("failed to read root certificate file: {ca_cert}"))?;

        ca_certs_files.push(file);
    }
    let mut root_cert = rustls::RootCertStore::empty();
    for file in ca_certs_files {
        let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*file)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?;
        if let Some(cert) = root_certs.first() {
            root_cert
                .add(cert.to_owned())
                .context("failed to add root cert")?;
        }
    }

    Ok(root_cert)
}

fn to_hms(dur: Duration) -> String {
    let total_sec = dur.as_secs();
    let hours = total_sec / 3600;
    let minutes = (total_sec % 3600) / 60;
    let seconds = total_sec % 60;

    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn new_pcap_sensors() -> PcapSensors {
    Arc::new(RwLock::new(HashMap::<String, Vec<Connection>>::new()))
}

fn new_ingest_sensors(db: &Database) -> IngestSensors {
    let sensor_store = db.sensors_store().expect("Failed to open sensor store");
    Arc::new(RwLock::new(sensor_store.sensor_list()))
}

fn new_runtime_ingest_sensors() -> RunTimeIngestSensors {
    Arc::new(RwLock::new(HashMap::<String, DateTime<Utc>>::new()))
}

fn new_stream_direct_channels() -> StreamDirectChannels {
    Arc::new(RwLock::new(
        HashMap::<String, UnboundedSender<Vec<u8>>>::new(),
    ))
}

fn new_peers_data(peers_list: Option<HashSet<PeerIdentity>>) -> (Peers, PeerIdents) {
    (
        Arc::new(RwLock::new(HashMap::<String, PeerInfo>::new())),
        Arc::new(RwLock::new(peers_list.unwrap_or_default())),
    )
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
                .with_line_number(true)
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

async fn wait_for_task_shutdown(
    ingest_task_handle: JoinHandle<()>,
    publish_task_handle: JoinHandle<()>,
    peer_task_handle: Option<JoinHandle<Result<()>>>,
    secondary_sync_task_handle: Option<JoinHandle<()>>,
    retain_task_handle: std::thread::JoinHandle<()>,
) {
    let _ = ingest_task_handle.await;
    let _ = publish_task_handle.await;
    if let Some(handle_peers) = peer_task_handle {
        let _ = handle_peers.await;
    }
    if let Some(handle_sync) = secondary_sync_task_handle {
        let _ = handle_sync.await;
    }
    let _ = retain_task_handle.join();
}
