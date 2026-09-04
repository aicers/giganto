use std::{io::Write, path::Path};

use anyhow::{Context as AnyhowContext, anyhow};
#[cfg(feature = "storage_diagnostics")]
use async_graphql::InputObject;
use async_graphql::{Context, Object, Result, SimpleObject};
use tokio::sync::mpsc::{Sender, error::TrySendError};
use toml_edit::{DocumentMut, InlineTable};
use tracing::info;

use super::{PowerOffNotify, RebootNotify, TerminateNotify};
use crate::graphql::{StringNumberU32, StringNumberU64};
use crate::settings::ConfigVisible;
#[cfg(feature = "storage_diagnostics")]
use crate::storage::Database;
use crate::{comm::peer::PeerIdentity, settings::Settings};

pub const CONFIG_PUBLISH_SRV_ADDR: &str = "publish_srv_addr";
pub const CONFIG_GRAPHQL_SRV_ADDR: &str = "graphql_srv_addr";

pub trait TomlPeers {
    fn get_hostname(&self) -> String;
    fn get_addr(&self) -> String;
}

#[derive(SimpleObject, Debug)]
struct Status {
    name: String,
    cpu_usage: f32,
    total_memory: u64,
    used_memory: u64,
    disk_used_bytes: u64,
    disk_available_bytes: u64,
}

#[cfg(feature = "storage_diagnostics")]
#[derive(InputObject)]
struct PropertyFilter {
    record_type: String,
}

#[cfg(feature = "storage_diagnostics")]
#[derive(SimpleObject, Debug)]
struct Properties {
    estimate_live_data_size: u64,
    estimate_num_keys: u64,
    stats: String,
}

#[Object(name = "Config")]
impl ConfigVisible {
    async fn ingest_srv_addr(&self) -> String {
        self.ingest_srv_addr.to_string()
    }

    async fn publish_srv_addr(&self) -> String {
        self.publish_srv_addr.to_string()
    }

    async fn graphql_srv_addr(&self) -> String {
        self.graphql_srv_addr.to_string()
    }

    async fn retention(&self) -> String {
        let retention_secs = self.retention.as_secs();
        let days = retention_secs / 86400;
        let days = if retention_secs.is_multiple_of(86400) {
            days
        } else {
            days + 1
        };
        format!("{days}d")
    }

    async fn data_dir(&self) -> String {
        self.data_dir.to_string_lossy().to_string()
    }

    async fn export_dir(&self) -> String {
        self.export_dir.to_string_lossy().to_string()
    }

    async fn max_open_files(&self) -> i32 {
        self.max_open_files
    }

    async fn max_mb_of_level_base(&self) -> StringNumberU64 {
        self.max_mb_of_level_base.into()
    }

    async fn num_of_thread(&self) -> i32 {
        self.num_of_thread
    }

    async fn max_subcompactions(&self) -> StringNumberU32 {
        self.max_subcompactions.into()
    }

    async fn ack_transmission(&self) -> u16 {
        self.ack_transmission
    }
}

#[Object]
impl PeerIdentity {
    async fn addr(&self) -> String {
        self.addr.to_string()
    }

    async fn hostname(&self) -> String {
        self.hostname.clone()
    }
}

#[derive(Default)]
pub(super) struct StatusQuery;

#[derive(Default)]
pub(super) struct ConfigMutation;

#[Object]
impl StatusQuery {
    /// Returns the current node status, including CPU, memory, and disk usage.
    async fn status(&self) -> Result<Status> {
        let usg = roxy::resource_usage().await;
        let hostname = roxy::hostname();
        let usg = Status {
            name: hostname,
            cpu_usage: usg.cpu_usage,
            total_memory: usg.total_memory,
            used_memory: usg.used_memory,
            disk_used_bytes: usg.disk_used_bytes,
            disk_available_bytes: usg.disk_available_bytes,
        };
        Ok(usg)
    }

    #[cfg(feature = "storage_diagnostics")]
    async fn properties_cf(&self, ctx: &Context<'_>, filter: PropertyFilter) -> Result<Properties> {
        let cfname = filter.record_type;
        let db = ctx.data::<Database>()?;

        let props = db.properties_cf(&cfname)?;

        crate::graphql::ready(Ok(Properties {
            estimate_live_data_size: props.estimate_live_data_size,
            estimate_num_keys: props.estimate_num_keys,
            stats: props.stats,
        }))
        .await
    }

    /// Returns the current visible Giganto configuration.
    async fn config(&self, ctx: &Context<'_>) -> Result<ConfigVisible> {
        let s = ctx.data::<Settings>()?;
        crate::graphql::ready(Ok(s.config.visible.clone())).await
    }

    /// Returns `true` when the GraphQL service is reachable.
    async fn ping(&self) -> Result<bool> {
        crate::graphql::ready(Ok(true)).await
    }
}

#[Object]
impl ConfigMutation {
    /// Updates the config with the given `new` config. It involves reloading the module with the
    /// new config.
    ///
    /// # Errors
    ///
    /// Returns an error if `new` is empty, unchanged, stale relative to the current configuration,
    /// malformed, or invalid. Validation rejects negative `max_open_files` or `num_of_thread`,
    /// missing or non-directory `data_dir` and `export_dir` paths, and an unwritable `export_dir`.
    /// Admission also fails with a retryable error when the reload queue is full, or with a closed
    /// error when the generation is ending and no longer accepts reloads.
    async fn update_config(
        &self,
        ctx: &Context<'_>,
        old: String,
        new: String,
    ) -> Result<ConfigVisible> {
        if new.is_empty() {
            return Err("Cannot update data store's config with an empty new config"
                .to_string()
                .into());
        }

        if old == new {
            return Err(
                "Cannot update data store's config with the same old and new configs"
                    .to_string()
                    .into(),
            );
        }

        let s = ctx.data::<Settings>()?;
        let old_config: ConfigVisible = toml::from_str(&old)?;
        if s.config.visible != old_config {
            info!("Old config does not match the current config.");
            return Err("Old config does not match the current config."
                .to_string()
                .into());
        }

        let new_config: ConfigVisible = toml::from_str(&new)?;
        new_config.validate()?;

        if s.config.visible == new_config {
            info!("No changes");
            return Err("No changes".to_string().into());
        }

        let reload_tx = ctx.data::<Sender<ConfigVisible>>()?;
        match reload_tx.try_send(new_config.clone()) {
            Ok(()) => {
                info!("Configuration reload accepted");
                crate::graphql::ready(Ok(new_config)).await
            }
            Err(TrySendError::Full(_)) => Err("Reload queue is full; please retry later"
                .to_string()
                .into()),
            Err(TrySendError::Closed(_)) => Err("Reload admission closed: generation is ending"
                .to_string()
                .into()),
        }
    }

    async fn stop(&self, ctx: &Context<'_>) -> Result<bool> {
        info!("Received request to stop service");
        let terminate_notify = ctx.data::<TerminateNotify>()?;
        terminate_notify.0.notify_one();

        crate::graphql::ready(Ok(true)).await
    }

    async fn reboot(&self, ctx: &Context<'_>) -> Result<bool> {
        info!("Received request to reboot system");
        let reboot_notify = ctx.data::<RebootNotify>()?;
        reboot_notify.0.notify_one();

        crate::graphql::ready(Ok(true)).await
    }

    async fn shutdown(&self, ctx: &Context<'_>) -> Result<bool> {
        info!("Received request to shutdown system");
        let power_off_notify = ctx.data::<PowerOffNotify>()?;
        power_off_notify.0.notify_one();

        crate::graphql::ready(Ok(true)).await
    }
}

pub fn read_toml_file(path: &str) -> anyhow::Result<DocumentMut> {
    let toml = std::fs::read_to_string(path).context("toml not found")?;
    let doc = toml.parse::<DocumentMut>()?;
    Ok(doc)
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

pub fn write_toml_file(doc: &DocumentMut, path: &str) -> anyhow::Result<()> {
    let output = doc.to_string();
    let path = Path::new(path);
    let parent = parent_directory(path);
    let mut config_file = tempfile::Builder::new()
        .prefix(".giganto-config-")
        .tempfile_in(parent)
        .context("failed to create temporary config file")?;
    if let Ok(metadata) = path.metadata() {
        config_file
            .as_file()
            .set_permissions(metadata.permissions())
            .context("failed to preserve config file permissions")?;
    }
    config_file
        .write_all(output.as_bytes())
        .context("failed to write temporary config file")?;
    if !output.ends_with('\n') {
        writeln!(config_file).context("failed to finish temporary config file")?;
    }
    config_file
        .as_file()
        .sync_all()
        .context("failed to sync temporary config file")?;
    config_file
        .persist(path)
        .map_err(|error| error.error)
        .context("failed to atomically replace config file")?;
    std::fs::File::open(parent)
        .context("failed to open config directory")?
        .sync_all()
        .context("failed to sync config directory")?;
    Ok(())
}

pub fn parse_toml_element_to_string(key: &str, doc: &DocumentMut) -> Result<String> {
    let Some(item) = doc.get(key) else {
        return Err(anyhow!("{key} not found.").into());
    };
    let Some(value) = item.as_str() else {
        return Err(anyhow!("parse failed: {key}'s item format is not available.").into());
    };
    Ok(value.to_string())
}

pub fn insert_toml_peers<T>(doc: &mut DocumentMut, input: Option<Vec<T>>) -> Result<()>
where
    T: TomlPeers,
{
    if let Some(peer_list) = input {
        let Some(array) = doc["peers"].as_array_mut() else {
            return Err(anyhow!("insert failed: peers option not found").into());
        };
        array.clear();
        for peer in peer_list {
            let mut table = InlineTable::new();
            table.insert("addr", peer.get_addr().into());
            table.insert("hostname", peer.get_hostname().into());
            array.push(table);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::Path, str::FromStr};

    use toml_edit::DocumentMut;

    use super::{
        insert_toml_peers, parent_directory, parse_toml_element_to_string, read_toml_file,
        write_toml_file,
    };
    use crate::{comm::peer::PeerIdentity, graphql::tests::TestSchema};

    #[tokio::test]
    async fn test_ping() {
        let schema = TestSchema::new();

        let query = "{ ping }";

        let res = schema.execute(query).await;

        assert_eq!(res.data.to_string(), "{ping: true}");
    }

    #[tokio::test]
    async fn test_status() {
        let schema = TestSchema::new();

        let query = r"
        {
            status {
                name
                cpuUsage
                totalMemory
                usedMemory
                diskUsedBytes
                diskAvailableBytes
            }
        }
        ";

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty());
    }

    #[tokio::test]
    async fn test_update_config_with_empty_string() {
        let schema = TestSchema::new();

        let old_config = old_config();

        // set_config
        let query = format!(
            r#"
            mutation {{
                updateConfig(old: {old_config:?} new: "") {{
                    ingestSrvAddr
                }}
            }}
            "#
        );

        let res = schema.execute(&query).await;
        assert!(
            res.errors
                .first()
                .is_some_and(|error| error.message.contains("empty new config"))
        );
    }

    #[tokio::test]
    async fn test_update_config_with_same_old_and_new() {
        let schema = TestSchema::new();

        let old_config = old_config();
        let query = format!(
            r"
            mutation {{
                updateConfig(old: {old_config:?} new: {old_config:?}) {{
                    ingestSrvAddr
                }}
            }}
            "
        );

        let res = schema.execute(&query).await;
        assert!(
            res.errors
                .first()
                .is_some_and(|error| error.message.contains("same old and new configs"))
        );
    }

    #[tokio::test]
    async fn test_config() {
        let mut schema = TestSchema::new();

        // config
        let query = r"
            {
                config {
                    ingestSrvAddr
                    publishSrvAddr
                    graphqlSrvAddr
                    dataDir
                    retention
                    exportDir
                    ackTransmission
                    maxOpenFiles
                    maxMbOfLevelBase
                    numOfThread
                    maxSubcompactions
                }
            }
        ";

        let res = schema.execute(query).await;

        let data = res.data.to_string();
        assert!(
            data.contains("ackTransmission: 1024, maxOpenFiles: 8000, maxMbOfLevelBase: \"512\", numOfThread: 8, maxSubcompactions: \"2\"")
        );

        let old_config = old_config();
        let new_config = changed_config();
        let expected_config: crate::settings::ConfigVisible = toml::from_str(&new_config).unwrap();

        // set_config
        let query = format!(
            r"
            mutation {{
                updateConfig(old: {old_config:?} new: {new_config:?}) {{
                    ingestSrvAddr
                    publishSrvAddr
                    graphqlSrvAddr
                    dataDir
                    retention
                    exportDir
                    ackTransmission
                    maxOpenFiles
                    maxMbOfLevelBase
                    numOfThread
                    maxSubcompactions
                }}
            }}
            "
        );

        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            "{updateConfig: {ingestSrvAddr: \"0.0.0.0:48370\", publishSrvAddr: \"0.0.0.0:48371\", graphqlSrvAddr: \"127.0.0.1:8443\", dataDir: \"tests\", retention: \"100d\", exportDir: \"tests\", ackTransmission: 1024, maxOpenFiles: 8000, maxMbOfLevelBase: \"512\", numOfThread: 10, maxSubcompactions: \"2\"}}"
        );
        assert_eq!(
            schema.reload_rx.recv().await,
            Some(expected_config.clone()),
            "a successful response must correspond to the same admitted configuration"
        );

        let res = schema.execute(&query).await;
        assert!(
            res.errors.is_empty(),
            "draining the queue should admit a subsequent reload: {:?}",
            res.errors
        );
        assert_eq!(schema.reload_rx.recv().await, Some(expected_config));
    }

    #[tokio::test]
    async fn test_update_config_reports_full_reload_queue() {
        let mut schema = TestSchema::new();
        let queued: crate::settings::ConfigVisible = toml::from_str(&old_config()).unwrap();
        schema
            .reload_tx
            .try_send(queued.clone())
            .expect("the empty capacity-one queue should accept its first item");

        let query = update_config_query(&old_config(), &changed_config());
        let res = schema.execute(&query).await;

        assert_eq!(
            res.errors.first().map(|error| error.message.as_str()),
            Some("Reload queue is full; please retry later")
        );
        assert_eq!(
            schema.reload_rx.try_recv(),
            Ok(queued),
            "a refused reload must not replace the request already queued"
        );
    }

    #[tokio::test]
    async fn test_update_config_reports_closed_reload_admission() {
        let mut schema = TestSchema::new();
        schema.reload_rx.close();

        let query = update_config_query(&old_config(), &changed_config());
        let res = schema.execute(&query).await;

        assert_eq!(
            res.errors.first().map(|error| error.message.as_str()),
            Some("Reload admission closed: generation is ending")
        );
        assert!(schema.reload_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn config_retention_format_stability() {
        let schema = TestSchema::new();
        let query = r"
        {
            config {
                retention
            }
        }";

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let config = data["config"].as_object().unwrap();
        assert_eq!(config["retention"].as_str().unwrap(), "100d");
    }

    #[cfg(all(test, feature = "storage_diagnostics"))]
    #[tokio::test]
    async fn test_properties_cf() {
        let schema = TestSchema::new();
        let query = r#"
        {
            propertiesCf(filter: { recordType: "conn" }) {
                estimateLiveDataSize
                estimateNumKeys
                stats
            }
        }
        "#;

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let props = data["propertiesCf"].as_object().unwrap();
        assert!(props.contains_key("estimateLiveDataSize"));
        assert!(props.contains_key("estimateNumKeys"));
        assert!(props.contains_key("stats"));
    }

    #[tokio::test]
    async fn test_update_config_with_old_mismatch() {
        let schema = TestSchema::new();

        let mismatched_old_config = toml::toml!(
            ingest_srv_addr = "0.0.0.0:38370"
            publish_srv_addr = "0.0.0.0:38371"
            graphql_srv_addr = "127.0.0.1:8443"
            data_dir = "tests"
            retention = "101d"
            export_dir = "tests"
            ack_transmission = 1024
            max_open_files = 8000
            max_mb_of_level_base = 512
            num_of_thread = 8
            max_subcompactions = 2
        )
        .to_string();
        let new_config = old_config();

        let query = format!(
            r"
            mutation {{
                updateConfig(old: {mismatched_old_config:?} new: {new_config:?}) {{
                    ingestSrvAddr
                }}
            }}
            "
        );

        let res = schema.execute(&query).await;
        assert!(
            res.errors
                .first()
                .is_some_and(|error| error.message.contains("Old config does not match"))
        );
    }

    #[tokio::test]
    async fn test_update_config_with_no_changes() {
        let schema = TestSchema::new();

        let old_config = old_config();
        let new_config = format!("{old_config}\n");
        let query = format!(
            r"
            mutation {{
                updateConfig(old: {old_config:?} new: {new_config:?}) {{
                    ingestSrvAddr
                }}
            }}
            "
        );

        let res = schema.execute(&query).await;
        assert!(
            res.errors
                .first()
                .is_some_and(|error| error.message.contains("No changes"))
        );
    }

    #[tokio::test]
    async fn test_stop() {
        let schema = TestSchema::new();
        let query = "mutation { stop }";
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{stop: true}");
    }

    #[tokio::test]
    async fn test_reboot() {
        let schema = TestSchema::new();
        let query = "mutation { reboot }";
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{reboot: true}");
    }

    #[tokio::test]
    async fn test_shutdown() {
        let schema = TestSchema::new();
        let query = "mutation { shutdown }";
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{shutdown: true}");
    }

    #[test]
    fn parse_toml_element_to_string_handles_errors_and_success() {
        let doc = "title = \"ok\"\ncount = 3\n"
            .parse::<DocumentMut>()
            .unwrap();

        let ok = parse_toml_element_to_string("title", &doc).unwrap();
        assert_eq!(ok, "ok");

        let missing = parse_toml_element_to_string("missing", &doc).unwrap_err();
        assert!(
            missing.message.contains("missing not found"),
            "unexpected error: {missing:?}"
        );

        let non_string = parse_toml_element_to_string("count", &doc).unwrap_err();
        assert!(
            non_string
                .message
                .contains("parse failed: count's item format is not available"),
            "unexpected error: {non_string:?}"
        );
    }

    #[test]
    fn test_insert_toml_peers() {
        let mut doc = "peers = []\n".parse::<DocumentMut>().unwrap();
        let peers = vec![PeerIdentity {
            addr: SocketAddr::from_str("127.0.0.1:38384").unwrap(),
            hostname: "node1".to_string(),
        }];

        insert_toml_peers(&mut doc, Some(peers)).unwrap();
        let out = doc.to_string();
        assert!(out.contains("127.0.0.1:38384"));
        assert!(out.contains("node1"));

        insert_toml_peers::<PeerIdentity>(&mut doc, None).unwrap();

        let mut missing = "title = \"ok\"\n".parse::<DocumentMut>().unwrap();
        let peers = vec![PeerIdentity {
            addr: SocketAddr::from_str("127.0.0.1:38384").unwrap(),
            hostname: "node1".to_string(),
        }];
        let err = insert_toml_peers(&mut missing, Some(peers)).unwrap_err();
        assert!(
            err.message
                .contains("insert failed: peers option not found"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn write_toml_file_allows_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let doc = r#"
            ingest_srv_addr = "0.0.0.0:38370"
            publish_srv_addr = "0.0.0.0:38371"
            graphql_srv_addr = "127.0.0.1:8443"
        "#
        .trim()
        .parse::<DocumentMut>()
        .unwrap();

        write_toml_file(&doc, path.to_str().unwrap()).unwrap();
        let read_doc = read_toml_file(path.to_str().unwrap()).unwrap();

        assert_eq!(read_doc.to_string().trim_end(), doc.to_string().trim_end());
    }

    #[test]
    fn parent_directory_uses_current_directory_for_bare_filename() {
        assert_eq!(parent_directory(Path::new("config.toml")), Path::new("."));
    }

    #[test]
    fn read_toml_file_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.toml");

        let err = read_toml_file(path.to_str().unwrap()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("toml not found"));
    }

    fn old_config() -> String {
        toml::toml!(
            ingest_srv_addr = "0.0.0.0:38370"
            publish_srv_addr = "0.0.0.0:38371"
            graphql_srv_addr = "127.0.0.1:8443"
            data_dir = "tests"
            retention = "100d"
            log_dir = "/data/logs/apps"
            export_dir = "tests"
            ack_transmission = 1024
            max_open_files = 8000
            max_mb_of_level_base = 512
            num_of_thread = 8
            max_subcompactions = 2
        )
        .to_string()
    }

    fn changed_config() -> String {
        toml::toml!(
            ingest_srv_addr = "0.0.0.0:48370"
            publish_srv_addr = "0.0.0.0:48371"
            graphql_srv_addr = "127.0.0.1:8443"
            data_dir = "tests"
            retention = "100d"
            export_dir = "tests"
            ack_transmission = 1024
            max_open_files = 8000
            max_mb_of_level_base = 512
            num_of_thread = 10
            max_subcompactions = 2
        )
        .to_string()
    }

    fn update_config_query(old: &str, new: &str) -> String {
        format!(
            r"
            mutation {{
                updateConfig(old: {old:?} new: {new:?}) {{
                    ingestSrvAddr
                }}
            }}
            "
        )
    }
}
