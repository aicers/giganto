use std::{env, fs, process::Command};

fn main() {
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
                "target_gen_schema",
            ])
            .status()
            .expect("Failed to execute `cargo run` for schema generation");
        assert!(status.success(), "Failed to generate GraphQL schema");
    }

    println!("cargo:rerun-if-changed=src/graphql.rs");
    // Re-run if non-client files in `src/graphql` change
    for entry in fs::read_dir("src/graphql")
        .expect("src/graphql directory must exist as it's part of the source tree")
    {
        let entry = entry.expect("directory entries from fs::read_dir should always be readable");
        let name = entry.file_name();
        if name == "client" || name == "client.rs" {
            continue;
        }
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }
}
