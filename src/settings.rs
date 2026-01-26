//! Configurations for the application.
use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, bail};
use clap::Parser;
use config::{Config as ConfConfig, ConfigBuilder, ConfigError, File, builder::DefaultState};
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use toml_edit::DocumentMut;
use tracing::info;

use crate::{comm::peer::PeerIdentity, graphql::status::write_toml_file};

const DEFAULT_INGEST_SRV_ADDR: &str = "[::]:38370";
const DEFAULT_PUBLISH_SRV_ADDR: &str = "[::]:38371";
pub const DEFAULT_GRAPHQL_SRV_ADDR: &str = "[::]:8443";
const DEFAULT_INVALID_ADDR_TO_PEERS: &str = "254.254.254.254:38383";
const DEFAULT_ACK_TRANSMISSION: u16 = 1024;
const DEFAULT_RETENTION: &str = "100d";
const DEFAULT_MAX_OPEN_FILES: i32 = 8000;
const DEFAULT_MAX_MB_OF_LEVEL_BASE: u64 = 512;
const DEFAULT_NUM_OF_THREAD: i32 = 8;
const DEFAULT_MAX_SUBCOMPACTIONS: u32 = 2;

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

    /// Path to the log file.
    #[arg(long, value_name = "LOG_PATH")]
    pub log_path: Option<PathBuf>,

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

    // RocksDB compression
    #[serde(default)]
    pub compression: bool,
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
    pub max_subcompactions: u32,

    // ack transmission interval
    pub ack_transmission: u16,
}

impl Settings {
    /// Creates a new `Settings` instance, populated from the given
    /// configuration file.
    pub fn load(cfg_path: &str) -> Result<Self, ConfigError> {
        let s = default_config_builder()
            .add_source(File::with_name(cfg_path))
            .build()?;
        let config: Config = s.try_deserialize()?;

        Ok(Self {
            config,
            cfg_path: cfg_path.to_string(),
        })
    }

    /// Loads the configuration, restoring from a backup if needed.
    pub fn load_or_restore(cfg_path: &str) -> anyhow::Result<Self> {
        Self::load(cfg_path).or_else(|e| {
            eprintln!("failed to read configuration file: {cfg_path}. Error: {e}");

            let backup_path = Path::new(cfg_path).with_extension("toml.bak");

            if !backup_path.exists() {
                return Err(e)
                    .context("no valid configuration file available, and no backup found.");
            }

            println!(
                "attempting to restore backup configuration from: {}",
                backup_path.display()
            );

            fs::copy(&backup_path, cfg_path).with_context(|| {
                format!(
                    "failed to restore configuration from backup: {} to {}",
                    backup_path.display(),
                    cfg_path
                )
            })?;

            println!("configuration restored from backup.");

            Self::load(cfg_path).with_context(|| {
                format!(
                    "failed to read restored configuration file: {}",
                    backup_path.display()
                )
            })
        })
    }

    pub fn update_config_file(&mut self, new_config: &ConfigVisible) -> anyhow::Result<()> {
        // Create a temporary config with the new visible settings to serialize
        let temp_config = Config {
            addr_to_peers: self.config.addr_to_peers,
            peers: self.config.peers.clone(),
            visible: new_config.clone(),
            compression: self.config.compression,
        };

        let toml_str = toml::to_string(&temp_config)?;
        let doc = toml_str.parse::<DocumentMut>()?;

        // Perform persistence operations first; only update in-memory state if both succeed
        backup_toml_file(&self.cfg_path)?;
        write_toml_file(&doc, &self.cfg_path)?;

        // Only update in-memory config after successful persistence
        self.config.visible = temp_config.visible;

        Ok(())
    }
}

fn backup_toml_file(path: &str) -> anyhow::Result<()> {
    let original_path = Path::new(path);
    let backup_path = original_path.with_extension("toml.bak");

    std::fs::copy(original_path, &backup_path)
        .with_context(|| format!("Failed to create backup: {}", backup_path.display()))?;

    info!(
        "Settings backup files is created at: {}",
        backup_path.display()
    );

    Ok(())
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.visible.validate()?;
        Ok(())
    }
}

impl ConfigVisible {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.data_dir.exists() || !self.data_dir.is_dir() {
            bail!("data directory is invalid");
        }
        Ok(())
    }
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
        .set_default("max_subcompactions", DEFAULT_MAX_SUBCOMPACTIONS)
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

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    use pretty_assertions::assert_eq;
    use tempfile::tempdir;

    use super::*;

    /// Helper function to create a temporary test config file
    fn create_test_config(
        compression: bool,
    ) -> (
        tempfile::NamedTempFile,
        tempfile::TempDir,
        tempfile::TempDir,
        ConfigVisible,
    ) {
        let mut temp_file = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("Failed to create temp file");

        let data_dir = tempfile::tempdir().expect("Failed to create test_data dir");
        let export_dir = tempfile::tempdir().expect("Failed to create test_export dir");

        let config_content = format!(
            r#"
graphql_srv_addr = "[::]:8443"
ingest_srv_addr = "[::]:38370"
publish_srv_addr = "[::]:38371"
retention = "100d"
data_dir = "{}"
export_dir = "{}"
max_open_files = 8000
max_mb_of_level_base = 512
num_of_thread = 8
max_subcompactions = 2
ack_transmission = 1024
compression = {}
"#,
            data_dir.path().display(),
            export_dir.path().display(),
            compression
        );

        temp_file
            .write_all(config_content.as_bytes())
            .expect("Failed to write config");
        temp_file.flush().expect("Failed to flush");

        let config_visible = ConfigVisible {
            graphql_srv_addr: "[::]:8443".parse().unwrap(),
            ingest_srv_addr: "[::]:38370".parse().unwrap(),
            publish_srv_addr: "[::]:38371".parse().unwrap(),
            retention: Duration::from_secs(100 * 24 * 60 * 60),
            data_dir: data_dir.path().to_path_buf(),
            export_dir: export_dir.path().to_path_buf(),
            max_open_files: 8000,
            max_mb_of_level_base: 512,
            num_of_thread: 8,
            max_subcompactions: 2,
            ack_transmission: 1024,
        };

        (temp_file, data_dir, export_dir, config_visible)
    }

    #[test]
    fn test_update_config_file_readonly_failure_preserves_state() {
        let (temp_file, _data_dir, _export_dir, original_config) = create_test_config(false);
        let config_path = temp_file.path().to_str().unwrap();

        // Load settings from the temporary config file
        let mut settings = Settings::load(config_path).expect("Failed to load settings");

        // Store the original config for comparison
        let original_visible = settings.config.visible.clone();

        // Create a new config with different values
        let new_config = ConfigVisible {
            graphql_srv_addr: "[::]:9999".parse().unwrap(),
            ingest_srv_addr: original_config.ingest_srv_addr,
            publish_srv_addr: original_config.publish_srv_addr,
            retention: original_config.retention,
            data_dir: original_config.data_dir.clone(),
            export_dir: original_config.export_dir.clone(),
            max_open_files: original_config.max_open_files,
            max_mb_of_level_base: original_config.max_mb_of_level_base,
            num_of_thread: original_config.num_of_thread,
            max_subcompactions: original_config.max_subcompactions,
            ack_transmission: original_config.ack_transmission,
        };

        // Make the file read-only to force a write failure
        let mut permissions = fs::metadata(config_path)
            .expect("Failed to get metadata")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(config_path, permissions).expect("Failed to set read-only");

        // Attempt to update the config file, which should fail
        let result = settings.update_config_file(&new_config);

        // Verify that the update failed
        assert!(
            result.is_err(),
            "Expected update_config_file to fail on read-only file"
        );

        // Verify that the in-memory config was NOT changed
        assert_eq!(
            settings.config.visible, original_visible,
            "In-memory config should remain unchanged after failed update"
        );

        // Remove any backup file created during the failed update attempt
        let backup_path = PathBuf::from(config_path).with_extension("toml.bak");
        fs::remove_file(backup_path).expect("Failed to remove backup file");
    }

    #[test]
    fn test_update_config_file_success_updates_both_memory_and_disk() {
        let (temp_file, _data_dir, _export_dir, original_config) = create_test_config(false);
        let config_path = temp_file.path().to_str().unwrap();

        // Load settings from the temporary config file
        let mut settings = Settings::load(config_path).expect("Failed to load settings");

        // Create a new config with different values
        let new_config = ConfigVisible {
            graphql_srv_addr: "[::]:9999".parse().unwrap(),
            ingest_srv_addr: "[::]:12345".parse().unwrap(),
            publish_srv_addr: original_config.publish_srv_addr,
            retention: Duration::from_secs(200 * 24 * 60 * 60), // 200 days
            data_dir: original_config.data_dir.clone(),
            export_dir: original_config.export_dir.clone(),
            max_open_files: 9000,
            max_mb_of_level_base: original_config.max_mb_of_level_base,
            num_of_thread: original_config.num_of_thread,
            max_subcompactions: original_config.max_subcompactions,
            ack_transmission: original_config.ack_transmission,
        };

        // Update the config file, which should succeed
        let result = settings.update_config_file(&new_config);
        assert!(result.is_ok(), "Expected update_config_file to succeed");

        // Verify that the in-memory config was updated
        assert_eq!(
            settings.config.visible.graphql_srv_addr, new_config.graphql_srv_addr,
            "In-memory graphql_srv_addr should be updated"
        );
        assert_eq!(
            settings.config.visible.ingest_srv_addr, new_config.ingest_srv_addr,
            "In-memory ingest_srv_addr should be updated"
        );
        assert_eq!(
            settings.config.visible.max_open_files, new_config.max_open_files,
            "In-memory max_open_files should be updated"
        );

        // Reload settings from disk to verify persistence
        let reloaded_settings =
            Settings::load(config_path).expect("Failed to reload settings from disk");

        // Verify that the persisted config matches the new config
        assert_eq!(
            reloaded_settings.config.visible.graphql_srv_addr, new_config.graphql_srv_addr,
            "Persisted graphql_srv_addr should match new config"
        );
        assert_eq!(
            reloaded_settings.config.visible.ingest_srv_addr, new_config.ingest_srv_addr,
            "Persisted ingest_srv_addr should match new config"
        );
        assert_eq!(
            reloaded_settings.config.visible.max_open_files, new_config.max_open_files,
            "Persisted max_open_files should match new config"
        );

        // Verify that a backup file was created
        let backup_path = PathBuf::from(config_path).with_extension("toml.bak");
        assert!(
            backup_path.exists(),
            "Backup file should be created at {}",
            backup_path.display()
        );

        // Clean up the backup file created during the test
        fs::remove_file(backup_path).expect("Failed to remove backup file");
    }

    #[test]
    fn test_update_config_file_preserves_compression_setting() {
        let (temp_file, _data_dir, _export_dir, original_config) = create_test_config(true);
        let config_path = temp_file.path().to_str().unwrap();

        let mut settings = Settings::load(config_path).expect("Failed to load settings");
        assert!(
            settings.config.compression,
            "Compression should be loaded from the config file"
        );

        // Update a visible field and ensure compression stays intact
        let new_config = ConfigVisible {
            graphql_srv_addr: original_config.graphql_srv_addr,
            ingest_srv_addr: "[::]:12345".parse().unwrap(),
            publish_srv_addr: original_config.publish_srv_addr,
            retention: original_config.retention,
            data_dir: original_config.data_dir.clone(),
            export_dir: original_config.export_dir.clone(),
            max_open_files: original_config.max_open_files + 1,
            max_mb_of_level_base: original_config.max_mb_of_level_base,
            num_of_thread: original_config.num_of_thread,
            max_subcompactions: original_config.max_subcompactions,
            ack_transmission: original_config.ack_transmission,
        };

        settings
            .update_config_file(&new_config)
            .expect("Expected update_config_file to succeed");

        assert!(
            settings.config.compression,
            "In-memory compression should be preserved after update"
        );

        let reloaded_settings =
            Settings::load(config_path).expect("Failed to reload settings from disk");
        assert!(
            reloaded_settings.config.compression,
            "Persisted compression should be preserved after update"
        );

        // Clean up the backup file created during the test
        let backup_path = PathBuf::from(config_path).with_extension("toml.bak");
        fs::remove_file(backup_path).expect("Failed to remove backup file");
    }

    const TEST_CONFIG_CONTENT: &str = r#"
        ingest_srv_addr = "0.0.0.0:38370"
        publish_srv_addr = "0.0.0.0:38371"
        graphql_srv_addr = "0.0.0.0:38372"
        data_dir = "data"
        retention = "100d"
        max_open_files = 800
        max_mb_of_level_base = 512
        num_of_thread = 8
        max_subcompactions = 2
        ack_transmission = 1024
        export_dir = "export"
    "#;

    #[test]
    fn test_load_config_success() {
        let dir = tempdir().expect("failed to create temp dir");
        let config_path = dir.path().join("config.toml");
        let mut file = fs::File::create(&config_path).expect("failed to create config file");
        writeln!(file, "{TEST_CONFIG_CONTENT}").expect("failed to write config content");

        let settings = Settings::load_or_restore(config_path.to_str().unwrap());
        let settings = settings.unwrap();
        assert_eq!(
            settings.config.visible.ingest_srv_addr.to_string(),
            "0.0.0.0:38370"
        );
        assert_eq!(
            settings.config.visible.publish_srv_addr.to_string(),
            "0.0.0.0:38371"
        );
        assert_eq!(
            settings.config.visible.graphql_srv_addr.to_string(),
            "0.0.0.0:38372"
        );
        assert_eq!(settings.config.visible.data_dir, PathBuf::from("data"));
        assert_eq!(
            settings.config.visible.retention,
            Duration::from_secs(100 * 24 * 60 * 60)
        );
        assert_eq!(settings.config.visible.max_open_files, 800);
        assert_eq!(settings.config.visible.max_mb_of_level_base, 512);
        assert_eq!(settings.config.visible.num_of_thread, 8);
        assert_eq!(settings.config.visible.max_subcompactions, 2);
        assert_eq!(settings.config.visible.ack_transmission, 1024);
        assert_eq!(settings.config.visible.export_dir, PathBuf::from("export"));
    }

    #[test]
    fn test_load_config_msg_fail_no_backup() {
        let dir = tempdir().expect("failed to create temp dir");
        let config_path = dir.path().join("non_existent.toml");
        let settings = Settings::load_or_restore(config_path.to_str().unwrap());
        assert!(settings.is_err());
    }

    #[test]
    fn test_load_config_backup_restore() {
        let dir = tempdir().expect("failed to create temp dir");
        let config_path = dir.path().join("config.toml");
        let backup_path = dir.path().join("config.toml.bak");

        let mut file = fs::File::create(&backup_path).expect("failed to create backup file");
        writeln!(file, "{TEST_CONFIG_CONTENT}").expect("failed to write backup content");

        let settings = Settings::load_or_restore(config_path.to_str().unwrap());
        assert!(settings.is_ok());
        assert!(config_path.exists());
    }

    #[test]
    fn test_load_config_backup_restore_copy_failure() {
        let dir = tempdir().expect("failed to create temp dir");
        let config_path = dir.path().join("config.toml");
        let backup_path = dir.path().join("config.toml.bak");

        fs::File::create(&backup_path).expect("failed to create backup file");
        fs::create_dir(&config_path).expect("failed to create directory at config path");

        let result = Settings::load_or_restore(config_path.to_str().unwrap());
        let err = result.expect_err("Operation should have failed");
        assert!(
            err.to_string()
                .contains("failed to restore configuration from backup"),
            "Unexpected error message received: '{err:?}'",
        );
    }

    #[test]
    fn test_load_config_backup_restore_read_failure() {
        let dir = tempdir().expect("failed to create temp dir");
        let config_path = dir.path().join("config.toml");
        let backup_path = dir.path().join("config.toml.bak");

        let mut file = fs::File::create(&backup_path).expect("failed to create backup file");
        writeln!(file, "invalid_toml_content").expect("failed to write invalid content");

        let result = Settings::load_or_restore(config_path.to_str().unwrap());
        let err = result.expect_err("Operation should have failed");
        assert!(
            err.to_string()
                .contains("failed to read restored configuration file"),
            "Unexpected error message received: '{err:?}'",
        );
    }

    #[test]
    fn test_load_config_both_invalid() {
        let dir = tempdir().expect("failed to create temp dir");
        let config_path = dir.path().join("config.toml");
        let backup_path = dir.path().join("config.toml.bak");

        // Create invalid config file
        let mut config_file = fs::File::create(&config_path).expect("failed to create config file");
        writeln!(config_file, "invalid_toml_content")
            .expect("failed to write invalid config content");

        // Create invalid backup file
        let mut backup_file = fs::File::create(&backup_path).expect("failed to create backup file");
        writeln!(backup_file, "invalid_backup_content")
            .expect("failed to write invalid backup content");

        let result = Settings::load_or_restore(config_path.to_str().unwrap());
        let err = result.expect_err("Operation should have failed");
        assert!(
            err.to_string()
                .contains("failed to read restored configuration file"),
            "Unexpected error message: {err:?}"
        );
    }

    #[test]
    fn test_validate_config() {
        let (_temp_file, data_dir, _export_dir, config_visible) = create_test_config(false);
        let config = Config {
            addr_to_peers: None,
            peers: None,
            visible: config_visible,
            compression: false,
        };

        // Case 1: Valid data directory
        assert!(config.validate().is_ok());

        // Case 2: Non-existent data directory
        let mut invalid_config = config.clone();
        invalid_config.visible.data_dir = PathBuf::from("non_existent_dir");
        let err = invalid_config
            .validate()
            .expect_err("Operation should have failed");
        assert!(
            err.to_string().contains("data directory is invalid"),
            "Unexpected error message: {err:?}"
        );

        // Case 3: Data directory is a file
        let file_path = data_dir.path().join("file");
        fs::File::create(&file_path).expect("Failed to create file");
        invalid_config.visible.data_dir = file_path;
        let err = invalid_config
            .validate()
            .expect_err("Operation should have failed");
        assert!(
            err.to_string().contains("data directory is invalid"),
            "Unexpected error message: {err:?}"
        );
    }
}
