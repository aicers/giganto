use config::{Config, ConfigError, File};
use serde::Deserialize;
use std::fs;

const DEFAULT_INGESTION_ADDRESS: &str = "[::]:38370";

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub cert: String,              // Path to the certificate file
    pub key: String,               // Path to the private key file
    pub ingestion_address: String, // IP address & port to ingest data
}

impl Settings {
    pub fn from_file(cfg_path: &str) -> Result<Self, ConfigError> {
        let dirs = directories::ProjectDirs::from("com", "einsis", "giganto").expect("unreachable");
        let path = dirs.config_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        fs::create_dir_all(&path).expect("failed to create cert dir");

        let s = Config::builder()
            .set_default("cert", cert_path.to_str().expect("read cert path"))
            .expect("failed to read cert dir")
            .set_default("key", key_path.to_str().expect("read key path"))
            .expect("failed to read key dir")
            .set_default("ingestion_address", DEFAULT_INGESTION_ADDRESS)
            .expect("valid address")
            .add_source(File::with_name(cfg_path))
            .build()?;

        s.try_deserialize()
    }
}
