use std::{env, fs, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let major = env::var("CARGO_PKG_VERSION_MAJOR")?;
    let minor = env::var("CARGO_PKG_VERSION_MINOR")?.parse::<u64>()?;
    let next_minor = minor
        .checked_add(1)
        .ok_or("crate minor version cannot be incremented")?;
    println!("cargo:rustc-env=GIGANTO_NEXT_MINOR_VERSION={major}.{next_minor}.0");
    println!("cargo:rerun-if-changed=Cargo.toml");

    if env::var("CARGO_CFG_FEATURE")
        .unwrap_or_default()
        .contains("cluster")
        && !env::var("CI")
            .unwrap_or_default()
            .parse::<bool>()
            .unwrap_or(false)
    {
        let status = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "gen_schema",
                "--no-default-features",
                "--target-dir",
                "target/gen_schema",
            ])
            .status()?;
        assert!(status.success(), "Failed to generate GraphQL schema");
    }

    println!("cargo:rerun-if-changed=src/graphql.rs");
    // Re-run if non-client files in `src/graphql` change
    for entry in fs::read_dir("src/graphql")? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "client" || name == "client.rs" {
            continue;
        }
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }
    Ok(())
}
