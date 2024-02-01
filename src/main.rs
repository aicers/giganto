mod graphql;
mod ingest;
mod peer;
mod publish;
mod server;
mod settings;
mod storage;
mod web;

use crate::{
    graphql::NodeName,
    server::{certificate_info, Certs, SERVER_REBOOT_DELAY},
    storage::migrate_data_dir,
};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use giganto_client::init_tracing;
use peer::{PeerIdentity, PeerIdents, PeerInfo, Peers};
use quinn::Connection;
use rocksdb::DB;
use rustls::{Certificate, PrivateKey};
use settings::Settings;
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::PathBuf,
    process::exit,
    sync::Arc,
    time::{Duration, Instant},
};
use storage::Database;
use tokio::{
    select,
    sync::{mpsc::UnboundedSender, Notify, RwLock},
    task,
    time::{self, sleep},
};
use tracing::{error, info, warn};

const ONE_DAY: u64 = 60 * 60 * 24;
const USAGE: &str = "\
USAGE:
    giganto [CONFIG]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARG:
    <CONFIG>    A TOML config file
";

pub type PcapSources = Arc<RwLock<HashMap<String, Connection>>>;
pub type IngestSources = Arc<RwLock<HashSet<String>>>;
pub type RunTimeIngestSources = Arc<RwLock<HashMap<String, DateTime<Utc>>>>;
pub type StreamDirectChannels = Arc<RwLock<HashMap<String, UnboundedSender<Vec<u8>>>>>;
pub type AckTransmissionCount = Arc<RwLock<u16>>;

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    let (mut settings, repair) = if let Some((config_filename, repair)) = parse() {
        (Settings::from_file(&config_filename)?, repair)
    } else {
        (Settings::new()?, false)
    };

    let cert_pem = fs::read(&settings.cert).with_context(|| {
        format!(
            "failed to read certificate file: {}",
            settings.cert.display()
        )
    })?;
    let cert = to_cert_chain(&cert_pem).context("cannot read certificate chain")?;
    assert!(!cert.is_empty());
    let key_pem = fs::read(&settings.key).with_context(|| {
        format!(
            "failed to read private key file: {}",
            settings.key.display()
        )
    })?;
    let key = to_private_key(&key_pem).context("cannot read private key")?;
    let root_cert = to_root_cert(&settings.roots)?;
    let certs = Arc::new(Certs {
        certs: cert.clone(),
        key: key.clone(),
        ca_certs: root_cert.clone(),
    });

    let _guard = init_tracing(&settings.log_dir, env!("CARGO_PKG_NAME"))?;

    let db_path = settings.data_dir.join("db");
    let db_options =
        crate::storage::DbOptions::new(settings.max_open_files, settings.max_mb_of_level_base);
    if repair {
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
    let database = storage::Database::open(&db_path, &db_options)?;

    if let Err(e) = migrate_data_dir(&settings.data_dir, &database) {
        error!("migration failed: {e}");
        return Ok(());
    }

    let notify_ctrlc = Arc::new(Notify::new());
    let r = notify_ctrlc.clone();
    if let Err(ctrlc::Error::System(e)) = ctrlc::set_handler(move || r.notify_one()) {
        return Err(anyhow!("failed to set signal handler: {}", e));
    }

    let request_client_pool = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_sni(false)
        .build()
        .expect("Failed to build request client pool");

    loop {
        let pcap_sources = new_pcap_sources();
        let ingest_sources = new_ingest_sources(&database);
        let runtime_ingest_sources = new_runtime_ingest_sources();
        let stream_direct_channels = new_stream_direct_channels();
        let (peers, peer_idents) = new_peers_data(settings.peers);
        let notify_config_reload = Arc::new(Notify::new());
        let notify_shutdown = Arc::new(Notify::new());
        let mut notify_source_change = None;
        let ack_transmission_cnt = new_ack_transmission_count(settings.ack_transmission);

        let schema = graphql::schema(
            NodeName(certificate_info(&cert)?.1),
            database.clone(),
            pcap_sources.clone(),
            ingest_sources.clone(),
            peers.clone(),
            request_client_pool.clone(),
            settings.export_dir.clone(),
            notify_config_reload.clone(),
            settings.cfg_path.clone(),
            ack_transmission_cnt.clone(),
        );
        task::spawn(web::serve(
            schema,
            settings.graphql_address,
            cert_pem.clone(),
            key_pem.clone(),
            notify_shutdown.clone(),
        ));

        task::spawn(storage::retain_periodically(
            time::Duration::from_secs(ONE_DAY),
            settings.retention,
            database.clone(),
            notify_shutdown.clone(),
        ));

        if let Some(peer_address) = settings.peer_address {
            let peer_server = peer::Peer::new(peer_address, &certs.clone())?;
            let notify_source = Arc::new(Notify::new());
            task::spawn(peer_server.run(
                ingest_sources.clone(),
                peers.clone(),
                peer_idents.clone(),
                notify_source.clone(),
                notify_shutdown.clone(),
                settings.cfg_path.clone(),
            ));
            notify_source_change = Some(notify_source);
        }

        let publish_server = publish::Server::new(settings.publish_address, &certs.clone());
        task::spawn(publish_server.run(
            database.clone(),
            pcap_sources.clone(),
            stream_direct_channels.clone(),
            ingest_sources.clone(),
            peers.clone(),
            peer_idents.clone(),
            certs.clone(),
            notify_shutdown.clone(),
        ));

        let ingest_server = ingest::Server::new(settings.ingest_address, &certs.clone());
        task::spawn(ingest_server.run(
            database.clone(),
            pcap_sources,
            ingest_sources,
            runtime_ingest_sources,
            stream_direct_channels,
            notify_shutdown.clone(),
            notify_source_change,
            ack_transmission_cnt,
        ));

        loop {
            select! {
                () = notify_config_reload.notified() =>{
                    match Settings::from_file(&settings.cfg_path) {
                        Ok(new_settings) => {
                            settings = new_settings;
                            notify_shutdown.notify_waiters();
                            notify_shutdown.notified().await; // Wait for the shutdown to complete
                            break;
                        }
                        Err(e) => {
                            error!("Failed to load the new configuration: {e:#}");
                            warn!("Run giganto with the previous config");
                            continue;
                        }
                    }
                },
                () = notify_ctrlc.notified() =>{
                    info!("Termination signal: giganto daemon exit");
                    notify_shutdown.notify_waiters();
                    sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
                    return Ok(())
                }

            }
        }
        sleep(Duration::from_millis(SERVER_REBOOT_DELAY)).await;
    }
}

/// Parses the command line arguments and returns the first argument.
#[allow(unused_assignments)]
fn parse() -> Option<(String, bool)> {
    let mut args = env::args();
    let mut repair = false;
    args.next()?;
    let arg = args.next()?;
    let repair_opt = args.next();
    if let Some(str) = repair_opt {
        match str.as_str() {
            "--repair" => repair = true,
            _ => eprintln!("Error: too many arguments"),
        }
    }

    if arg == "--help" || arg == "-h" {
        println!("{}", version());
        println!();
        print!("{USAGE}");
        exit(0);
    }
    if arg == "--version" || arg == "-V" {
        println!("{}", version());
        exit(0);
    }
    if arg.starts_with('-') {
        eprintln!("Error: unknown option: {arg}");
        eprintln!("\n{USAGE}");
        exit(1);
    }

    Some((arg, repair))
}

fn version() -> String {
    format!("giganto {}", env!("CARGO_PKG_VERSION"))
}

fn to_cert_chain(pem: &[u8]) -> Result<Vec<Certificate>> {
    let certs = rustls_pemfile::certs(&mut &*pem).context("cannot parse certificate chain")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate found"));
    }
    Ok(certs.into_iter().map(Certificate).collect())
}

fn to_private_key(pem: &[u8]) -> Result<PrivateKey> {
    match rustls_pemfile::read_one(&mut &*pem)
        .context("cannot parse private key")?
        .ok_or_else(|| anyhow!("empty private key"))?
    {
        rustls_pemfile::Item::PKCS8Key(key) | rustls_pemfile::Item::RSAKey(key) => {
            Ok(PrivateKey(key))
        }
        _ => Err(anyhow!("unknown private key format")),
    }
}

fn to_root_cert(root_cert_paths: &Vec<PathBuf>) -> Result<rustls::RootCertStore> {
    let mut root_files: Vec<Vec<u8>> = Vec::new();
    for root in root_cert_paths {
        let file = fs::read(root).expect("Failed to read file");
        root_files.push(file);
    }

    let mut root_cert = rustls::RootCertStore::empty();
    for file in root_files {
        let root_certs: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*file)
            .context("invalid PEM-encoded certificate")?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        if let Some(cert) = root_certs.first() {
            root_cert.add(cert).context("failed to add root cert")?;
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

fn new_pcap_sources() -> PcapSources {
    Arc::new(RwLock::new(HashMap::<String, Connection>::new()))
}

fn new_ingest_sources(db: &Database) -> IngestSources {
    let source_store = db.sources_store().expect("Failed to open source store");
    Arc::new(RwLock::new(source_store.source_list()))
}

fn new_runtime_ingest_sources() -> RunTimeIngestSources {
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
