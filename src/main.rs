mod graphql;
mod ingestion;
mod settings;
mod storage;
mod web;

use settings::Settings;
use std::path::Path;
use std::{env, process::exit};
use tokio::task;

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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = if let Some(config_filename) = parse() {
        Settings::from_file(&config_filename)?
    } else {
        Settings::from_file("config.toml")?
    };
    let s = settings.clone();

    let db_path = Path::new(&settings.data_dir).join("db");
    let database = storage::Database::open(&db_path)?;

    let db = database.clone();
    task::spawn(async move {
        let schema = graphql::schema(db);
        web::serve(schema, &s).await;
    });

    let ingestion_server = ingestion::Server::new(&settings);
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
