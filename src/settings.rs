//! Configurations for the application.
use config::{builder::DefaultState, Config, ConfigBuilder, ConfigError, File};
use serde::Deserialize;
use std::path::PathBuf;

const DEFAULT_INGESTION_ADDRESS: &str = "[::]:38370";
const DEFAULT_GRAPHQL_ADDRESS: &str = "127.0.0.1:8443";

/// The application settings.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub cert: String,              // Path to the certificate file
    pub key: String,               // Path to the private key file
    pub roots: Vec<String>,        // Path to the rootCA file
    pub ingestion_address: String, // IP address & port to ingest data
    pub data_dir: String,          // DB storage path
    pub retention: String,         // Data retention period
    pub graphql_address: String,   // IP address & port to graphql
}

impl Settings {
    /// Creates a new `Settings` instance, populated from the default
    /// configuration file if it exists.
    pub fn new() -> Result<Self, ConfigError> {
        let dirs = directories::ProjectDirs::from("com", "einsis", "giganto").expect("unreachable");
        let config_path = dirs.config_dir().join("config.toml");
        if config_path.exists() {
            // `config::File` requires a `&str` path, so we can't use `config_path` directly.
            if let Some(path) = config_path.to_str() {
                Self::from_file(path)
            } else {
                Err(ConfigError::Message(
                    "config path must be a valid UTF-8 string".to_string(),
                ))
            }
        } else {
            default_config_builder().build()?.try_deserialize()
        }
    }

    /// Creates a new `Settings` instance, populated from the given
    /// configuration file.
    pub fn from_file(cfg_path: &str) -> Result<Self, ConfigError> {
        let s = default_config_builder()
            .add_source(File::with_name(cfg_path))
            .build()?;

        s.try_deserialize()
    }
}

/// Creates a new `ConfigBuilder` instance with the default configuration.
fn default_config_builder() -> ConfigBuilder<DefaultState> {
    let dirs = directories::ProjectDirs::from("com", "einsis", "giganto").expect("unreachable");
    let db_dir =
        directories::ProjectDirs::from_path(PathBuf::from("db")).expect("unreachable db dir");
    let db_path = db_dir.data_dir().to_str().unwrap();
    let config_dir = dirs.config_dir();
    let cert_path = config_dir.join("cert.pem");
    let key_path = config_dir.join("key.pem");

    Config::builder()
        .set_default("cert", cert_path.to_str().expect("path to string"))
        .expect("default cert dir")
        .set_default("key", key_path.to_str().expect("path to string"))
        .expect("default key dir")
        .set_default("ingestion_address", DEFAULT_INGESTION_ADDRESS)
        .expect("valid address")
        .set_default("graphql_address", DEFAULT_GRAPHQL_ADDRESS)
        .expect("local address")
        .set_default("data_dir", db_path)
        .expect("data dir")
        .set_default("retention", "100d")
        .expect("retention")
}
