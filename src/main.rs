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
    env, fs,
    path::Path,
    process::exit,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use peer::{PeerIdentity, PeerIdents, PeerInfo, Peers};
use quinn::Connection;
use rocksdb::DB;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use settings::Settings;
use storage::Database;
use tokio::{
    runtime, select,
    sync::{
        mpsc::{self, UnboundedSender},
        Notify, RwLock,
    },
    task,
    time::{self, sleep},
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

const ONE_DAY: u64 = 60 * 60 * 24;
const WAIT_SHUTDOWN: u64 = 15;

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
    let mut settings = if let Some(config_filename) = args.config {
        Settings::from_file(&config_filename)?
    } else {
        Settings::new()?
    };

    let cfg_path = settings.cfg_path.clone();

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

    let _guard = init_tracing(&settings.config.log_dir)?;

    let db_path = storage::data_dir_to_db_path(&settings.config.data_dir);
    let db_options = crate::storage::DbOptions::new(
        settings.config.max_open_files,
        settings.config.max_mb_of_level_base,
        settings.config.num_of_thread,
        settings.config.max_sub_compactions,
    );

    if args.repair {
        if !is_local_config {
            bail!("repair is not allowed on remote config");
        }
        let start = Instant::now();
        let (db_opts, _) = storage::rocksdb_options(&db_options);
        info!("repair db start.");
        match DB::repair(&db_opts, db_path) {
            Ok(()) => info!("repair ok"),
            Err(e) => error!("repair error: {e}"),
        }
        let dur = start.elapsed();
        info!("{}", to_hms(dur));
        exit(0);
    }

    let mut is_reboot = false;
    let mut is_power_off = false;

    if let Err(e) = migrate_data_dir(&settings.config.data_dir, &db_options) {
        error!("migration failed: {e}");
        bail!("migration failed")
    }

    let database = storage::Database::open(&db_path, &db_options)?;

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
        let pcap_sensors = new_pcap_sensors();
        let ingest_sensors = new_ingest_sensors(&database);
        let runtime_ingest_sensors = new_runtime_ingest_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let (peers, peer_idents) = new_peers_data(settings.config.peers.clone());
        let (reload_tx, mut reload_rx) = mpsc::channel::<String>(1);
        let notify_shutdown = Arc::new(Notify::new());
        let notify_reboot = Arc::new(Notify::new());
        let notify_power_off = Arc::new(Notify::new());
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
            settings.clone(),
        );

        task::spawn(web::serve(
            schema,
            settings.config.graphql_srv_addr,
            cert_pem.clone(),
            key_pem.clone(),
            notify_shutdown.clone(),
        ));

        let retain_flag = Arc::new(Mutex::new(false));
        let db = database.clone();
        let notify_shutdown_copy = notify_shutdown.clone();
        let running_flag = retain_flag.clone();
        std::thread::spawn(move || {
            runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Cannot create runtime for retain_periodically.")
                .block_on(storage::retain_periodically(
                    time::Duration::from_secs(ONE_DAY),
                    settings.config.retention,
                    db,
                    notify_shutdown_copy,
                    running_flag,
                ))
                .unwrap_or_else(|e| {
                    error!("retain_periodically task terminated unexpectedly: {e}");
                });
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

        let publish_server = publish::Server::new(settings.config.publish_srv_addr, &certs.clone());
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

        let ingest_server = ingest::Server::new(settings.config.ingest_srv_addr, &certs.clone());
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

        loop {
            select! {
                Some(config_draft) = reload_rx.recv() => {
                    match Settings::from_server(&config_draft) {
                        Ok(mut new_settings) => {
                            new_settings.cfg_path.clone_from(&cfg_path);
                            settings = new_settings;
                            notify_and_wait_shutdown(notify_shutdown.clone()).await; // Wait for the shutdown to complete
                            break;
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
                    notify_and_wait_shutdown(notify_shutdown).await;
                    sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
                    return Ok(());
                }
                () = notify_reboot.notified() => {
                    info!("Restarting the system...");
                    notify_and_wait_shutdown(notify_shutdown).await;
                    is_reboot = true;
                    break;
                }
                () = notify_power_off.notified() => {
                    info!("Power off the system...");
                    notify_and_wait_shutdown(notify_shutdown).await;
                    is_power_off = true;
                    break;
                }
            }
        }

        if is_reboot || is_power_off {
            loop {
                {
                    let retain_flag = retain_flag.lock().unwrap();
                    if !*retain_flag {
                        break;
                    }
                }
                sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
            }
            database.shutdown()?;
            info!("Before shut down the system, wait {WAIT_SHUTDOWN} seconds...");
            sleep(tokio::time::Duration::from_secs(WAIT_SHUTDOWN)).await;
            break;
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

fn init_tracing(path: &Path) -> Result<WorkerGuard> {
    if !path.exists() {
        bail!("Path not found {path:?}");
    }

    let file_name = format!("{}.log", env!("CARGO_PKG_NAME"));
    if std::fs::File::create(path.join(&file_name)).is_err() {
        bail!("Cannot create file. {}/{file_name}", path.display());
    }

    let file_appender = tracing_appender::rolling::never(path, file_name);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    let layer_file = fmt::Layer::default()
        .with_ansi(false)
        .with_target(false)
        .with_writer(file_writer)
        .with_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        );

    let layered_subscriber = tracing_subscriber::registry().with(layer_file);
    #[cfg(debug_assertions)]
    let layered_subscriber = layered_subscriber.with(
        fmt::Layer::default()
            .with_ansi(true)
            .with_filter(EnvFilter::from_default_env()),
    );
    layered_subscriber.init();

    Ok(guard)
}

/// Notifies all waiters of `notify_shutdown` and waits for ingest closed notification.
pub async fn notify_and_wait_shutdown(notify_shutdown: Arc<Notify>) {
    notify_shutdown.notify_waiters();
    notify_shutdown.notified().await;
}
