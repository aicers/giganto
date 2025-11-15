mod comm;
mod graphql;
mod server;
mod settings;
mod storage;
mod web;

use std::{
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
        new_stream_direct_channels, to_cert_chain, to_private_key, to_root_cert,
    },
    graphql::NodeName,
    server::{Certs, SERVER_REBOOT_DELAY, subject_from_cert},
    settings::Args,
    storage::{migrate_data_dir, validate_compression_metadata},
};

const ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);
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
            settings.config.visible.max_subcompactions,
            settings.config.visible.compression,
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
        return Err(anyhow!("failed to set signal handler: {e}"));
    }

    let request_client_pool =
        create_graphql_client(&cert_pem, &key_pem).expect("Failed to build request client pool");

    loop {
        info!("Data store started");
        let (db_path, db_options) = db_path_and_option(
            &settings.config.visible.data_dir,
            settings.config.visible.max_open_files,
            settings.config.visible.max_mb_of_level_base,
            settings.config.visible.num_of_thread,
            settings.config.visible.max_subcompactions,
            settings.config.visible.compression,
        );

        // Validate compression metadata before migration
        if let Err(e) = validate_compression_metadata(
            &settings.config.visible.data_dir,
            settings.config.visible.compression,
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

        let schema = graphql::schema(
            NodeName(subject_from_cert(&cert)?.1),
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

        let web_cert_pem = cert_pem.clone();
        let web_key_pem = key_pem.clone();
        let web_addr = settings.config.visible.graphql_srv_addr;
        let web_notify_shutdown = notify_shutdown.clone();

        if let Err(e) = web::serve(
            schema,
            web_addr,
            web_cert_pem,
            web_key_pem,
            &args.ca_certs,
            web_notify_shutdown,
        ) {
            error!("Failed to start GraphQL server: {e}");
        }

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
            database.clone(),
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
            database.clone(),
            pcap_sensors,
            ingest_sensors,
            runtime_ingest_sensors,
            stream_direct_channels,
            notify_shutdown.clone(),
            notify_sensor_change,
            ack_transmission_cnt,
        ));

        loop {
            select! {
                Some(new_config) = reload_rx.recv() => {
                    match settings.update_config_file(&new_config) {
                        Ok(()) => {
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
                    notify_shutdown.notify_waiters();
                    wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                    sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
                    return Ok(());
                }
                () = notify_reboot.notified() => {
                    info!("Restarting the system...");
                    notify_shutdown.notify_waiters();
                    wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
                    is_reboot = true;
                    break;
                }
                () = notify_power_off.notified() => {
                    info!("Power off the system...");
                    notify_shutdown.notify_waiters();
                    wait_for_task_shutdown(ingest_task_handle, publish_task_handle, peer_task_handle, retain_task_handle).await;
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
    use super::*;

    #[test]
    fn test_create_graphql_client_with_invalid_cert() {
        let invalid_cert = b"invalid cert";
        let invalid_key = b"invalid key";

        let result = create_graphql_client(invalid_cert, invalid_key);
        assert!(result.is_err());
    }
}
