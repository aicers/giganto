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
    fs,
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use graphql::status::{settings_to_doc, write_toml_file};
use peer::{PeerIdentity, PeerIdents, PeerInfo, Peers};
use quinn::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use settings::{Settings, DEFAULT_GRAPHQL_SRV_ADDR};
use storage::{db_path_and_option, repair_db, Database};
use tokio::{
    runtime, select,
    sync::{
        mpsc::{self, UnboundedSender},
        Notify, RwLock,
    },
    task,
    time::sleep,
};
use tracing::{error, info, metadata::LevelFilter, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

use crate::{
    graphql::NodeName,
    server::{subject_from_cert, Certs, SERVER_REBOOT_DELAY},
    settings::Args,
    storage::migrate_data_dir,
};

const ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);
const WAIT_SHUTDOWN: u64 = 15;
const DEFAULT_TOML: &str = "/opt/clumit/conf/giganto.toml";

pub type PcapSensors = Arc<RwLock<HashMap<String, Vec<Connection>>>>;
pub type IngestSensors = Arc<RwLock<HashSet<String>>>;
pub type RunTimeIngestSensors = Arc<RwLock<HashMap<String, DateTime<Utc>>>>;
pub type StreamDirectChannels = Arc<RwLock<HashMap<String, UnboundedSender<Vec<u8>>>>>;
pub type AckTransmissionCount = Arc<RwLock<u16>>;

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let is_local_config = args.is_local();
    let mut settings = args
        .config
        .as_ref()
        .map(|config_filename| {
            Settings::from_file(config_filename)
                .map_err(|e| anyhow!("Failed to read local config file: {e}"))
        })
        .transpose()?;

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

    // A fix for log handling by local/remote mode will be addressed in the
    // https://github.com/aicers/giganto/issues/878 issue.
    let _guard = init_tracing(settings.as_ref().map(|s| &*s.config.log_dir));

    if args.repair {
        if let Some(ref settings) = settings {
            repair_db(
                &settings.config.data_dir,
                settings.config.max_open_files,
                settings.config.max_mb_of_level_base,
                settings.config.num_of_thread,
                settings.config.max_sub_compactions,
            );
        } else {
            bail!("repair is not allowed on remote config");
        }
    }

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
        // The flag indicates whether the current giganto is in minimal mode or not.
        let is_minimal_mode = settings.is_none();
        let (reload_tx, mut reload_rx) = mpsc::channel::<String>(1);
        let notify_shutdown = Arc::new(Notify::new());
        let notify_reboot = Arc::new(Notify::new());
        let notify_power_off = Arc::new(Notify::new());
        let retain_flag = Arc::new(AtomicBool::new(false));

        let database = if let Some(settings) = settings.clone() {
            let (db_path, db_options) = db_path_and_option(
                &settings.config.data_dir,
                settings.config.max_open_files,
                settings.config.max_mb_of_level_base,
                settings.config.num_of_thread,
                settings.config.max_sub_compactions,
            );

            if let Err(e) = migrate_data_dir(&settings.config.data_dir, &db_options) {
                error!("migration failed: {e}");
                bail!("migration failed")
            }

            let database = storage::Database::open(&db_path, &db_options)?;

            let pcap_sensors = new_pcap_sensors();
            let ingest_sensors = new_ingest_sensors(&database);
            let runtime_ingest_sensors = new_runtime_ingest_sensors();
            let stream_direct_channels = new_stream_direct_channels();
            let (peers, peer_idents) = new_peers_data(settings.config.peers.clone());
            let mut notify_sensor_change = None;
            let ack_transmission_cnt = new_ack_transmission_count(settings.config.ack_transmission);

            let schema = graphql::schema(
                NodeName(subject_from_cert(&cert)?.1),
                database.clone(),
                pcap_sensors.clone(),
                ingest_sensors.clone(),
                peers.clone(),
                request_client_pool.clone(),
                settings.config.export_dir.clone(),
                reload_tx,
                notify_reboot.clone(),
                notify_power_off.clone(),
                notify_terminate.clone(),
                ack_transmission_cnt.clone(),
                is_local_config,
                Some(settings.clone()),
            );

            task::spawn(web::serve(
                schema,
                settings.config.graphql_srv_addr,
                cert_pem.clone(),
                key_pem.clone(),
                notify_shutdown.clone(),
            ));

            let db = database.clone();
            let notify_shutdown_copy = notify_shutdown.clone();
            let running_flag = retain_flag.clone();
            std::thread::spawn(move || {
                if let Err(e) = runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .expect("Cannot create runtime for retain_periodically.")
                    .block_on(storage::retain_periodically(
                        ONE_DAY,
                        settings.config.retention,
                        db,
                        notify_shutdown_copy,
                        running_flag,
                    ))
                {
                    error!("retain_periodically task terminated unexpectedly: {e}");
                }
            });

            if let Some(addr_to_peers) = settings.config.addr_to_peers {
                let peer_server = peer::Peer::new(addr_to_peers, &certs.clone())?;
                let notify_sensor = Arc::new(Notify::new());
                task::spawn(peer_server.run(
                    ingest_sensors.clone(),
                    peers.clone(),
                    peer_idents.clone(),
                    notify_sensor.clone(),
                    notify_shutdown.clone(),
                    settings.clone(),
                ));
                notify_sensor_change = Some(notify_sensor);
            }

            let publish_server =
                publish::Server::new(settings.config.publish_srv_addr, &certs.clone());
            task::spawn(publish_server.run(
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
                ingest::Server::new(settings.config.ingest_srv_addr, &certs.clone());
            task::spawn(ingest_server.run(
                database.clone(),
                pcap_sensors,
                ingest_sensors,
                runtime_ingest_sensors,
                stream_direct_channels,
                notify_shutdown.clone(),
                notify_sensor_change,
                ack_transmission_cnt,
            ));

            Some(database)
        } else {
            // wait for remote configuration
            info!("Running in minimal mode.");
            let schema = graphql::minimal_schema(
                reload_tx,
                notify_reboot.clone(),
                notify_power_off.clone(),
                notify_terminate.clone(),
                is_local_config,
                settings.clone(),
            );

            task::spawn(web::serve(
                schema,
                DEFAULT_GRAPHQL_SRV_ADDR.parse::<SocketAddr>().expect("The value of DEFAULT_GRAPHQL_SRV_ADDR is [::]:8442. Converting that value to SocketAddr is always valid."),
                cert_pem.clone(),
                key_pem.clone(),
                notify_shutdown.clone(),
            ));

            None
        };

        loop {
            select! {
                Some(config_draft) = reload_rx.recv() => {
                    match Settings::from_server(&config_draft) {
                        Ok(mut new_settings) => {
                            // Since the config file can only be reloaded when running without the
                            // "-c" option, cfg_path is always assigned the "DEFAULT_TOML".
                            if let Ok(doc) = settings_to_doc(&new_settings){
                               if write_toml_file(&doc, DEFAULT_TOML).is_ok(){
                                    new_settings.cfg_path.clone_from(&Some(DEFAULT_TOML.to_string()));
                                    settings = Some(new_settings);
                                    notify_and_wait_shutdown(is_minimal_mode, notify_shutdown.clone()).await; // Wait for the shutdown to complete
                                    is_reload_config = true;
                                    break;
                               }
                            }
                            error!("Failed to save the new configuration as {DEFAULT_TOML}");
                            warn!("Run giganto with the previous config");
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to load the new configuration: {e:#}");
                            warn!("Run giganto with the previous config");
                            continue;
                        }
                    }
                },
                () = notify_terminate.notified() => {
                    info!("Termination signal: giganto daemon exit");
                    notify_and_wait_shutdown(is_minimal_mode, notify_shutdown).await;
                    sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
                    return Ok(());
                }
                () = notify_reboot.notified() => {
                    info!("Restarting the system...");
                    notify_and_wait_shutdown(is_minimal_mode, notify_shutdown).await;
                    is_reboot = true;
                    break;
                }
                () = notify_power_off.notified() => {
                    info!("Power off the system...");
                    notify_and_wait_shutdown(is_minimal_mode, notify_shutdown).await;
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

            if let Some(database) = database {
                database.shutdown()?;
            }

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

fn new_ack_transmission_count(count: u16) -> AckTransmissionCount {
    Arc::new(RwLock::new(count))
}

fn new_peers_data(peers_list: Option<HashSet<PeerIdentity>>) -> (Peers, PeerIdents) {
    (
        Arc::new(RwLock::new(HashMap::<String, PeerInfo>::new())),
        Arc::new(RwLock::new(peers_list.unwrap_or_default())),
    )
}

fn init_tracing(log_dir: Option<&Path>) -> WorkerGuard {
    let subscriber = tracing_subscriber::Registry::default();
    let file_name = format!("{}.log", env!("CARGO_PKG_NAME"));

    let is_valid_file =
        matches!(log_dir, Some(path) if std::fs::File::create(path.join(&file_name)).is_ok());

    let (layer, guard) = if !is_valid_file || cfg!(debug_assertions) {
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        (
            fmt::Layer::default()
                .with_ansi(true)
                .with_writer(stdout_writer)
                .with_filter(EnvFilter::from_default_env()),
            stdout_guard,
        )
    } else {
        let file_appender = tracing_appender::rolling::never(
            log_dir.expect("verified by is_valid_file"),
            file_name,
        );
        let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);
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
    };
    subscriber.with(layer).init();
    guard
}

/// Notifies all waiters of `notify_shutdown` and waits for ingest closed notification.
pub async fn notify_and_wait_shutdown(is_minimal_mode: bool, notify_shutdown: Arc<Notify>) {
    notify_shutdown.notify_waiters();
    if !is_minimal_mode {
        notify_shutdown.notified().await;
    }
}
