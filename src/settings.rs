//! Configurations for the application.
use config::{builder::DefaultState, Config, ConfigBuilder, ConfigError, File};
use serde::{de::Error, Deserialize, Deserializer};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

const DEFAULT_INGESTION_ADDRESS: &str = "[::]:38370";
const DEFAULT_PUBLISH_ADDRESS: &str = "[::]:38371";
const DEFAULT_GRAPHQL_ADDRESS: &str = "[::]:8443";

/// The application settings.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub cert: PathBuf,       // Path to the certificate file
    pub key: PathBuf,        // Path to the private key file
    pub roots: Vec<PathBuf>, // Path to the rootCA file
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub ingestion_address: SocketAddr, // IP address & port to ingest data
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub publish_address: SocketAddr, // IP address & port to publish data
    pub data_dir: PathBuf,   // DB storage path
    #[serde(with = "humantime_serde")]
    pub retention: Duration, // Data retention period
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub graphql_address: SocketAddr, // IP address & port to graphql
    pub log_dir: PathBuf,    //giganto's syslog path
    pub export_dir: PathBuf, //giganto's export file path
    #[serde(with = "humantime_serde")]
    pub statistics_period: Duration, // statistics generate period
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
    let log_dir = directories::ProjectDirs::from_path(PathBuf::from("logs/apps"))
        .expect("unreachable logs dir");
    let export_dir = directories::ProjectDirs::from_path(PathBuf::from("export"))
        .expect("unreachable export dir");
    let db_path = db_dir.data_dir().to_str().expect("unreachable db path");
    let log_path = log_dir.data_dir().to_str().expect("unreachable log path");
    let export_path = export_dir
        .data_dir()
        .to_str()
        .expect("unreachable export path");
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
        .set_default("publish_address", DEFAULT_PUBLISH_ADDRESS)
        .expect("valid address")
        .set_default("graphql_address", DEFAULT_GRAPHQL_ADDRESS)
        .expect("local address")
        .set_default("data_dir", db_path)
        .expect("data dir")
        .set_default("retention", "100d")
        .expect("retention")
        .set_default("log_path", log_path)
        .expect("log dir")
        .set_default("export_path", export_path)
        .expect("export_dir")
        .set_default("statistics_period", "10m")
        .expect("statistics period")
}

/// Deserializes a socket address.
///
/// # Errors
///
/// Returns an error if the address is not in the form of 'IP:PORT'.
fn deserialize_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: Deserializer<'de>,
{
    let addr = String::deserialize(deserializer)?;
    addr.parse()
        .map_err(|e| D::Error::custom(format!("invalid address \"{addr}\": {e}")))
}
