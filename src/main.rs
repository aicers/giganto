mod graphql;
mod ingest;
mod peer;
mod publish;
mod server;
mod settings;
mod storage;
mod web;

use crate::{server::SERVER_REBOOT_DELAY, storage::migrate_data_dir};
use anyhow::{anyhow, Context, Result};
use giganto_client::{ingest::RecordType, init_tracing};
use rustls::{Certificate, PrivateKey};
use settings::Settings;
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    process::exit,
    sync::Arc,
    time::Duration,
};
use tokio::{
    select,
    sync::{mpsc::unbounded_channel, Notify, RwLock},
    task,
    time::{self, sleep},
};
use tracing::{error, info, warn};

pub type IndexInfo = (String, RecordType, Vec<u8>, i64); // raw event source, type, data, timestamp

const ONE_DAY: u64 = 60 * 60 * 24;
const ONE_MIN: u64 = 60;
const USAGE: &str = "\
USAGE:
    giganto [CONFIG]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARG:
    <CONFIG>    A TOML config file
";

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    let mut settings = if let Some(config_filename) = parse() {
        Settings::from_file(&config_filename)?
    } else {
        Settings::new()?
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

    let db_path = settings.data_dir.join("db");
    let db_options =
        crate::storage::DbOptions::new(settings.max_open_files, settings.max_mb_of_level_base);
    let database = storage::Database::open(&db_path, &db_options)?;

    let _guard = init_tracing(&settings.log_dir, env!("CARGO_PKG_NAME"))?;

    let mut files: Vec<Vec<u8>> = Vec::new();
    for root in &settings.roots {
        let file = fs::read(root).expect("Failed to read file");
        files.push(file);
    }

    if let Err(e) = migrate_data_dir(&settings.data_dir, &database) {
        error!("migration failed: {e}");
        return Ok(());
    }

    let notify_ctrlc = Arc::new(Notify::new());
    let r = notify_ctrlc.clone();
    if let Err(ctrlc::Error::System(e)) = ctrlc::set_handler(move || r.notify_one()) {
        return Err(anyhow!("failed to set signal handler: {}", e));
    }

    loop {
        let packet_sources = Arc::new(RwLock::new(HashMap::new()));
        let sources = Arc::new(RwLock::new(HashMap::new()));
        let stream_direct_channel = Arc::new(RwLock::new(HashMap::new()));
        let config_reload = Arc::new(Notify::new());
        let notify_shutdown = Arc::new(Notify::new());
        let mut notify_change_source = None;

        let schema = graphql::schema(
            database.clone(),
            packet_sources.clone(),
            settings.export_dir.clone(),
            config_reload.clone(),
            settings.cfg_path.clone(),
            settings.index_creation_period,
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

        let index_creation_send =
            if let Some(index_creation_period) = settings.index_creation_period {
                let (send, recv) = unbounded_channel::<IndexInfo>();
                task::spawn(storage::index_periodically(
                    time::Duration::from_secs(ONE_MIN),
                    index_creation_period,
                    database.clone(),
                    notify_shutdown.clone(),
                    recv,
                ));
                Some(send)
            } else {
                None
            };

        if let Some(peer_address) = settings.peer_address {
            let peer_server =
                peer::Peer::new(peer_address, cert.clone(), key.clone(), files.clone())?;
            let peer_sources = Arc::new(RwLock::new(HashMap::new()));
            let notify_source = Arc::new(Notify::new());
            let peers = if let Some(peers) = settings.peers {
                peers
            } else {
                HashSet::new()
            };
            task::spawn(peer_server.run(
                peers,
                sources.clone(),
                peer_sources,
                notify_source.clone(),
                notify_shutdown.clone(),
                settings.cfg_path.clone(),
            ));
            notify_change_source = Some(notify_source);
        }

        let publish_server = publish::Server::new(
            settings.publish_address,
            cert.clone(),
            key.clone(),
            files.clone(),
        );
        task::spawn(publish_server.run(
            database.clone(),
            packet_sources.clone(),
            stream_direct_channel.clone(),
            notify_shutdown.clone(),
        ));

        let ingest_server = ingest::Server::new(
            settings.ingest_address,
            cert.clone(),
            key.clone(),
            files.clone(),
        );
        task::spawn(ingest_server.run(
            database.clone(),
            packet_sources,
            sources,
            stream_direct_channel,
            notify_shutdown.clone(),
            notify_change_source,
            index_creation_send,
        ));

        loop {
            select! {
                () = config_reload.notified() =>{
                    match Settings::from_file(&settings.cfg_path) {
                        Ok(new_settings) => {
                            settings = new_settings;
                            notify_shutdown.notify_waiters();
                            notify_shutdown.notified().await; // Wait for the shutdown to complete
                            break;
                        }
                        Err(e) => {
                            error!("Failed to load the new configuration: {:#}", e);
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
fn parse() -> Option<String> {
    let mut args = env::args();
    args.next()?;
    let arg = args.next()?;
    if args.next().is_some() {
        eprintln!("Error: too many arguments");
        exit(1);
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

    Some(arg)
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
