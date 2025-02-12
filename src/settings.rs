//! Configurations for the application.
use std::{
    collections::HashSet,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};

use anyhow::bail;
use clap::Parser;
use config::{builder::DefaultState, Config as ConfConfig, ConfigBuilder, ConfigError, File};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use toml_edit::DocumentMut;

use crate::{graphql::status::write_toml_file, peer::PeerIdentity};

const DEFAULT_INGEST_SRV_ADDR: &str = "[::]:38370";
const DEFAULT_PUBLISH_SRV_ADDR: &str = "[::]:38371";
pub const DEFAULT_GRAPHQL_SRV_ADDR: &str = "[::]:8442";
const DEFAULT_INVALID_ADDR_TO_PEERS: &str = "254.254.254.254:38383";
const DEFAULT_ACK_TRANSMISSION: u16 = 1024;
const DEFAULT_RETENTION: &str = "100d";
const DEFAULT_MAX_OPEN_FILES: i32 = 8000;
const DEFAULT_MAX_MB_OF_LEVEL_BASE: u64 = 512;
const DEFAULT_NUM_OF_THREAD: i32 = 8;
const DEFAULT_MAX_SUB_COMPACTIONS: u32 = 2;

#[derive(Parser, Debug)]
#[command(version)]
pub struct Args {
    /// Path to the local configuration TOML file.
    #[arg(short, value_name = "CONFIG_PATH")]
    pub config: String,

    /// Path to the certificate file.
    #[arg(long, value_name = "CERT_PATH")]
    pub cert: String,

    /// Path to the key file.
    #[arg(long, value_name = "KEY_PATH")]
    pub key: String,

    /// Paths to the CA certificate files.
    #[arg(
        long,
        value_name = "CA_CERTS_PATHS",
        required = true,
        value_delimiter = ','
    )]
    pub ca_certs: Vec<String>,

    /// Path to the log directory.
    #[arg(long, value_name = "LOG_DIR")]
    pub log_dir: Option<PathBuf>,

    /// Enable the repair mode.
    #[arg(long)]
    pub repair: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub config: Config,

    // config file path
    pub cfg_path: String,
}
/// The application settings.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default, deserialize_with = "deserialize_peer_addr")]
    pub addr_to_peers: Option<SocketAddr>, // IP address & port for peer connection
    pub peers: Option<HashSet<PeerIdentity>>,

    #[serde(flatten)]
    pub visible: ConfigVisible,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigVisible {
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub graphql_srv_addr: SocketAddr, // IP address & port to graphql
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub ingest_srv_addr: SocketAddr, // IP address & port to ingest data
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub publish_srv_addr: SocketAddr, // IP address & port to publish data
    #[serde(with = "humantime_serde")]
    pub retention: Duration, // Data retention period
    pub export_dir: PathBuf, // giganto's export file path

    // DB and DB options
    pub data_dir: PathBuf, // DB storage path
    pub max_open_files: i32,
    pub max_mb_of_level_base: u64,
    pub num_of_thread: i32,
    pub max_sub_compactions: u32,

    // ack transmission interval
    pub ack_transmission: u16,
}

impl Settings {
    /// Creates a new `Settings` instance, populated from the given
    /// configuration file.
    pub fn from_file(cfg_path: &str) -> Result<Self, ConfigError> {
        let s = default_config_builder()
            .add_source(File::with_name(cfg_path))
            .build()?;
        let config: Config = s.try_deserialize()?;

        Ok(Self {
            config,
            cfg_path: cfg_path.to_string(),
        })
    }

    pub fn update_config_file(&mut self, new_config: &ConfigVisible) -> anyhow::Result<()> {
        self.config.visible = new_config.clone();

        let toml_str = toml::to_string(&self.config)?;
        let doc = toml_str.parse::<DocumentMut>()?;
        write_toml_file(&doc, &self.cfg_path)?;

        Ok(())
    }
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.visible.validate()?;
        Ok(())
    }
}

impl ConfigVisible {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_open_files < 0 {
            bail!("max open files must be greater than or equal to 0");
        }

        if self.num_of_thread < 0 {
            bail!("num of thread must be greater than or equal to 0");
        }

        if !self.data_dir.exists() || !self.data_dir.is_dir() {
            bail!("data directory is invalid");
        }

        if !self.export_dir.exists() || !self.export_dir.is_dir() {
            bail!("export directory is invalid");
        }
        if !is_writable(&self.export_dir) {
            bail!("no write permission to the export directory");
        }

        Ok(())
    }
}

fn is_writable(path: &PathBuf) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };

    let permissions = metadata.permissions();
    let mode = permissions.mode();

    let uid = nix::unistd::Uid::current().as_raw();
    let gid = nix::unistd::Gid::current().as_raw();

    metadata.uid() == uid && mode & 0o200 != 0
        || metadata.gid() == gid && mode & 0o020 != 0
        || mode & 0o002 != 0
}

/// Creates a new `ConfigBuilder` instance with the default configuration.
fn default_config_builder() -> ConfigBuilder<DefaultState> {
    ConfConfig::builder()
        .set_default("ingest_srv_addr", DEFAULT_INGEST_SRV_ADDR)
        .expect("valid address")
        .set_default("publish_srv_addr", DEFAULT_PUBLISH_SRV_ADDR)
        .expect("valid address")
        .set_default("graphql_srv_addr", DEFAULT_GRAPHQL_SRV_ADDR)
        .expect("local address")
        .set_default("retention", DEFAULT_RETENTION)
        .expect("retention")
        .set_default("max_open_files", DEFAULT_MAX_OPEN_FILES)
        .expect("default max open files")
        .set_default("max_mb_of_level_base", DEFAULT_MAX_MB_OF_LEVEL_BASE)
        .expect("default max mb of level base")
        .set_default("num_of_thread", DEFAULT_NUM_OF_THREAD)
        .expect("default number of thread")
        .set_default("max_sub_compactions", DEFAULT_MAX_SUB_COMPACTIONS)
        .expect("default max subcompactions")
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
