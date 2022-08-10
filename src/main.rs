use std::{env, path::PathBuf, process::exit};

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
async fn main() {
    let _config_filename = parse();
}

/// Parses the command line arguments and returns the first argument.
fn parse() -> Option<PathBuf> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() <= 1 {
        return None;
    }
    if args.len() > 2 {
        eprintln!("Error: too many arguments");
        exit(1);
    }

    if args[1] == "--help" || args[1] == "-h" {
        println!("{}", version());
        println!();
        print!("{}", USAGE);
        exit(0);
    }
    if args[1] == "--version" || args[1] == "-V" {
        println!("{}", version());
        exit(0);
    }
    if args[1].starts_with('-') {
        eprintln!("Error: unknown option: {}", args[1]);
        eprintln!("\n{}", USAGE);
        exit(1);
    }

    Some(PathBuf::from(&args[1]))
}

fn version() -> String {
    format!("giganto {}", env!("CARGO_PKG_VERSION"))
}
