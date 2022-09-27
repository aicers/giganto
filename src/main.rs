mod graphql;
mod ingestion;
mod publish;
mod settings;
mod storage;
mod web;

use anyhow::{anyhow, Context, Result};
use rustls::{Certificate, PrivateKey};
use settings::Settings;
use std::{env, fs, process::exit};
use tokio::{task, time};

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

#[tokio::main]
async fn main() -> Result<()> {
    let settings = if let Some(config_filename) = parse() {
        Settings::from_file(&config_filename)?
    } else {
        Settings::new()?
    };

    let pem = fs::read(&settings.cert).with_context(|| {
        format!(
            "failed to read certificate file: {}",
            settings.cert.display()
        )
    })?;
    let cert = to_cert_chain(&pem).context("cannot read certificate chain")?;
    assert!(!cert.is_empty());
    let pem = fs::read(&settings.key).with_context(|| {
        format!(
            "failed to read private key file: {}",
            settings.key.display()
        )
    })?;
    let key = to_private_key(&pem).context("cannot read private key")?;

    let db_path = settings.data_dir.join("db");
    let database = storage::Database::open(&db_path)?;

    tracing_subscriber::fmt::init();

    let mut files: Vec<Vec<u8>> = Vec::new();
    for root in &settings.roots {
        let file = fs::read(root).expect("Failed to read file");
        files.push(file);
    }

    let schema = graphql::schema(database.clone());
    task::spawn(web::serve(
        schema,
        settings.graphql_address,
        cert.first().expect("non-empty").clone(),
        pem,
    ));

    task::spawn(storage::retain_periodically(
        time::Duration::from_secs(ONE_DAY),
        settings.retention,
        database.clone(),
    ));

    let publish_server = publish::Server::new(
        settings.publish_address,
        cert.clone(),
        key.clone(),
        files.clone(),
    );
    task::spawn(publish_server.run(database.clone()));

    let ingestion_server = ingestion::Server::new(
        settings.ingestion_address,
        cert.clone(),
        key.clone(),
        files.clone(),
    );
    ingestion_server.run(database).await;

    Ok(())
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
        print!("{}", USAGE);
        exit(0);
    }
    if arg == "--version" || arg == "-V" {
        println!("{}", version());
        exit(0);
    }
    if arg.starts_with('-') {
        eprintln!("Error: unknown option: {}", arg);
        eprintln!("\n{}", USAGE);
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
