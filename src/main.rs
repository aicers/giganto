mod graphql;
mod ingestion;
mod publish;
mod settings;
mod storage;
mod web;

use anyhow::{bail, Context, Result};
use settings::Settings;
use std::path::Path;
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
    let s = settings.clone();

    let db_path = Path::new(&settings.data_dir).join("db");
    let database = storage::Database::open(&db_path)?;

    tracing_subscriber::fmt::init();

    let (cert, key) = match fs::read(&s.cert).and_then(|x| Ok((x, fs::read(&s.key)?))) {
        Ok(x) => x,
        Err(_) => {
            bail!(
                "failed to read (cert, key) file, {}, {} read file error. Check the location of cert or key and try again.",
                &s.cert,
                &s.key,
            );
        }
    };

    let mut files: Vec<Vec<u8>> = Vec::new();
    for root in &s.roots {
        let file = fs::read(root).expect("Failed to read file");
        files.push(file);
    }

    let db = database.clone();
    let (c, k) = (cert.clone(), key.clone());
    task::spawn(async move {
        let schema = graphql::schema(db);
        web::serve(schema, &s, &c, &k).await;
    });

    let db = database.clone();
    let retention_period = humantime::parse_duration(&settings.retention)
        .with_context(|| format!("invalid retention period: {}", settings.retention))?;
    task::spawn(storage::retain_periodically(
        time::Duration::from_secs(ONE_DAY),
        retention_period,
        db.clone(),
    ));

    let publish_server = publish::Server::new(&settings, cert.clone(), key.clone(), files.clone());
    task::spawn(publish_server.run(db.clone()));

    let ingestion_server =
        ingestion::Server::new(&settings, cert.clone(), key.clone(), files.clone());
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
