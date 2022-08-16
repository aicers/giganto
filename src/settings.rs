use config::{Config, ConfigError, File};
use serde::Deserialize;

const DEFAULT_INGESTION_ADDRESS: &str = "[::]:38370";

#[derive(Deserialize)]
pub struct Settings {
    pub cert: String,              // Path to the certificate file
    pub key: String,               // Path to the private key file
    pub ingestion_address: String, // IP address & port to ingest data
}

impl Settings {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let s = Config::builder()
            .set_default("ingestion_address", DEFAULT_INGESTION_ADDRESS)
            .expect("valid address")
            .add_source(File::with_name(path))
            .build()?;

        s.try_deserialize()
    }
}
