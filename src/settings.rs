//! Configurations for the application.
use std::{collections::HashSet, net::SocketAddr, path::PathBuf, time::Duration};

use clap::Parser;
use config::{builder::DefaultState, Config, ConfigBuilder, ConfigError, File};
use serde::{de::Error, Deserialize, Deserializer};

use crate::peer::PeerIdentity;

const DEFAULT_INGEST_SRV_ADDR: &str = "[::]:38370";
const DEFAULT_PUBLISH_SRV_ADDR: &str = "[::]:38371";
const DEFAULT_GRAPHQL_SRV_ADDR: &str = "[::]:8442";
const DEFAULT_INVALID_ADDR_TO_PEERS: &str = "254.254.254.254:38383";
const DEFAULT_ACK_TRANSMISSION: u16 = 1024;
const DEFAULT_RETENTION: &str = "100d";
const DEFAULT_MAX_OPEN_FILES: i32 = 8000;
const DEFAULT_MAX_MB_OF_LEVEL_BASE: u64 = 512;
const DEFAULT_NUM_OF_THREAD: i32 = 8;
const DEFAULT_MAX_SUBCOMPACTIONS: u32 = 2;

#[derive(Parser, Debug)]
pub struct Args {
    /// Path to the local configuration TOML file
    #[arg(short, value_name = "CONFIG_PATH")]
    pub config: Option<String>,
    /// Path to the certificate file
    #[arg(long, value_name = "CERT_PATH")]
    pub cert: String,
    /// Path to the key file
    #[arg(long, value_name = "KEY_PATH")]
    pub key: String,
    /// Path to the root CA file
    #[arg(long, value_name = "ROOT_PATH")]
    pub root: String,
    /// Central management server "hostname@address"
    pub central_server: String,
    /// Enable the repair mode
    #[arg(long)]
    pub repair: bool,
}

/// The application settings.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub ingest_srv_addr: SocketAddr, // IP address & port to ingest data
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub publish_srv_addr: SocketAddr, // IP address & port to publish data
    pub data_dir: PathBuf, // DB storage path
    #[serde(with = "humantime_serde")]
    pub retention: Duration, // Data retention period
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub graphql_srv_addr: SocketAddr, // IP address & port to graphql
    pub log_dir: PathBuf,  //giganto's syslog path
    pub export_dir: PathBuf, //giganto's export file path

    // db options
    pub max_open_files: i32,
    pub max_mb_of_level_base: u64,
    pub num_of_thread: i32,
    pub max_sub_compactions: u32,

    // config file path
    pub cfg_path: String,

    // peers
    #[serde(deserialize_with = "deserialize_peer_addr")]
    pub addr_to_peers: Option<SocketAddr>, // IP address & port for peer connection
    pub peers: Option<HashSet<PeerIdentity>>,

    // ack transmission interval
    pub ack_transmission: u16,
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
        let mut setting: Settings = s.try_deserialize()?;
        setting.cfg_path = cfg_path.to_string();
        Ok(setting)
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
    let config_path = config_dir.join("config.toml");

    Config::builder()
        .set_default("ingest_srv_addr", DEFAULT_INGEST_SRV_ADDR)
        .expect("valid address")
        .set_default("publish_srv_addr", DEFAULT_PUBLISH_SRV_ADDR)
        .expect("valid address")
        .set_default("graphql_srv_addr", DEFAULT_GRAPHQL_SRV_ADDR)
        .expect("local address")
        .set_default("data_dir", db_path)
        .expect("data dir")
        .set_default("retention", DEFAULT_RETENTION)
        .expect("retention")
        .set_default("log_path", log_path)
        .expect("log dir")
        .set_default("export_path", export_path)
        .expect("export_dir")
        .set_default("max_open_files", DEFAULT_MAX_OPEN_FILES)
        .expect("default max open files")
        .set_default("max_mb_of_level_base", DEFAULT_MAX_MB_OF_LEVEL_BASE)
        .expect("default max mb of level base")
        .set_default("num_of_thread", DEFAULT_NUM_OF_THREAD)
        .expect("default number of thread")
        .set_default("max_sub_compactions", DEFAULT_MAX_SUBCOMPACTIONS)
        .expect("default max subcompactions")
        .set_default("cfg_path", config_path.to_str().expect("path to string"))
        .expect("default config dir")
        .set_default("addr_to_peers", DEFAULT_INVALID_ADDR_TO_PEERS)
        .expect("default ack transmission")
        .set_default("ack_transmission", DEFAULT_ACK_TRANSMISSION)
        .expect("ack_transmission")
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

/// Deserializes a giganto's peer socket address.
///
/// `Ok(None)` is returned if the address is an empty string or there is no `addr_to_peers`
///  option in the configuration file.
///
/// # Errors
///
/// Returns an error if the address is invalid.
fn deserialize_peer_addr<'de, D>(deserializer: D) -> Result<Option<SocketAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    (Option::<String>::deserialize(deserializer)?).map_or(Ok(None), |addr| {
        // Cluster mode is only available if there is a value for 'Peer Address' in the configuration file.
        if addr == DEFAULT_INVALID_ADDR_TO_PEERS || addr.is_empty() {
            Ok(None)
        } else {
            Ok(Some(addr.parse::<SocketAddr>().map_err(|e| {
                D::Error::custom(format!("invalid address \"{addr}\": {e}"))
            })?))
        }
    })
}
