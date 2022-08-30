use config::{Config, ConfigError, File};
use serde::Deserialize;

const DEFAULT_INGESTION_ADDRESS: &str = "[::]:38370";
const DEFAULT_GRAPHQL_ADDRESS: &str = "127.0.0.1:8443";

#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub cert: String,              // Path to the certificate file
    pub key: String,               // Path to the private key file
    pub roots: Vec<String>,        // Path to the rootCA file
    pub ingestion_address: String, // IP address & port to ingest data
    pub graphql_address: String,   // IP address & port to graphql
}

impl Settings {
    pub fn from_file(cfg_path: &str) -> Result<Self, ConfigError> {
        let dirs = directories::ProjectDirs::from("com", "einsis", "giganto").expect("unreachable");
        let path = dirs.config_dir();
        let cert_path = path.join("cert.pem");
        let key_path = path.join("key.pem");

        let s = Config::builder()
            .set_default("cert", cert_path.to_str().expect("path to string"))
            .expect("default cert dir")
            .set_default("key", key_path.to_str().expect("path to string"))
            .expect("default key dir")
            .set_default("ingestion_address", DEFAULT_INGESTION_ADDRESS)
            .expect("valid address")
            .set_default("graphql_address", DEFAULT_GRAPHQL_ADDRESS)
            .expect("local address")
            .add_source(File::with_name(cfg_path))
            .build()?;

        s.try_deserialize()
    }
}
