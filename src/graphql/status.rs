use std::{fs::OpenOptions, io::Write, time::Duration};

use anyhow::{anyhow, Context as AnyhowContext};
use async_graphql::{Context, InputObject, Object, Result, SimpleObject};
use tokio::sync::mpsc::Sender;
use toml_edit::{DocumentMut, InlineTable};
use tracing::{error, info};

use super::{
    client::derives::{StringNumberU32, StringNumberU64},
    PowerOffNotify, RebootNotify, TerminateNotify,
};
use crate::settings::ConfigVisible;
#[cfg(debug_assertions)]
use crate::storage::Database;
use crate::{peer::PeerIdentity, settings::Settings};

const GRAPHQL_REBOOT_DELAY: u64 = 100;
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
    total_disk_space: u64,
    used_disk_space: u64,
}

#[derive(InputObject)]
struct PropertyFilter {
    record_type: String,
}

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
        let days = if retention_secs % 86400 > 0 {
            days + 1
        } else {
            days
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

    async fn max_sub_compactions(&self) -> StringNumberU32 {
        self.max_sub_compactions.into()
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
    async fn status(&self) -> Result<Status> {
        let usg = roxy::resource_usage().await;
        let hostname = roxy::hostname();
        let usg = Status {
            name: hostname,
            cpu_usage: usg.cpu_usage,
            total_memory: usg.total_memory,
            used_memory: usg.used_memory,
            total_disk_space: usg.total_disk_space,
            used_disk_space: usg.used_disk_space,
        };
        Ok(usg)
    }

    #[allow(clippy::unused_async)]
    #[cfg(debug_assertions)]
    async fn properties_cf(&self, ctx: &Context<'_>, filter: PropertyFilter) -> Result<Properties> {
        let cfname = filter.record_type;
        let db = ctx.data::<Database>()?;

        let props = db.properties_cf(&cfname)?;

        Ok(Properties {
            estimate_live_data_size: props.estimate_live_data_size,
            estimate_num_keys: props.estimate_num_keys,
            stats: props.stats,
        })
    }

    #[allow(clippy::unused_async)]
    async fn config(&self, ctx: &Context<'_>) -> Result<ConfigVisible> {
        let s = ctx.data::<Settings>()?;
        Ok(s.config.visible.clone())
    }

    #[allow(clippy::unused_async)]
    async fn ping(&self) -> Result<bool> {
        Ok(true)
    }
}

#[Object]
impl ConfigMutation {
    /// Updates the config with the given `new` config. It involves realoding the module with the new
    /// config.
    ///
    /// # Errors
    ///
    /// Returns an error if the `new` is empty. In addition, it returns an error if the `new` is
    /// invalid. The `new` config is invalid if it contains a negative value for `max_open_files` or
    /// `num_of_thread`, or if the `data_dir` or `export_dir` does not exist or is not a directory.
    /// It also returns an error if the `export_dir` is not writable. If the `new` is the same as
    /// the current config, it returns an error.
    #[allow(clippy::unused_async)]
    async fn update_config(
        &self,
        ctx: &Context<'_>,
        old: String,
        new: String,
    ) -> Result<ConfigVisible> {
        if new.is_empty() {
            return Err("Cannot update datalake config with an empty new config"
                .to_string()
                .into());
        }

        if old == new {
            return Err(
                "Cannot update datalake config with the same old and new configs"
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
            info!("No changes.");
            return Err("No changes".to_string().into());
        }

        let reload_tx = ctx.data::<Sender<ConfigVisible>>()?;
        let tx_clone = reload_tx.clone();

        let new_config_clone = new_config.clone();
        tokio::spawn(async move {
            // Used to complete the response of a GraphQL Mutation.
            tokio::time::sleep(Duration::from_millis(GRAPHQL_REBOOT_DELAY)).await;
            tx_clone.send(new_config_clone).await.map_err(|e| {
                error!("Failed to send config: {e:?}");
                "Failed to send config".to_string()
            })
        });
        info!("New config is applied.");

        Ok(new_config)
    }

    #[allow(clippy::unused_async)]
    async fn stop(&self, ctx: &Context<'_>) -> Result<bool> {
        let terminate_notify = ctx.data::<TerminateNotify>()?;
        terminate_notify.0.notify_one();

        Ok(true)
    }

    #[allow(clippy::unused_async)]
    async fn reboot(&self, ctx: &Context<'_>) -> Result<bool> {
        let reboot_notify = ctx.data::<RebootNotify>()?;
        reboot_notify.0.notify_one();

        Ok(true)
    }

    #[allow(clippy::unused_async)]
    async fn shutdown(&self, ctx: &Context<'_>) -> Result<bool> {
        let power_off_notify = ctx.data::<PowerOffNotify>()?;
        power_off_notify.0.notify_one();

        Ok(true)
    }
}

pub fn read_toml_file(path: &str) -> anyhow::Result<DocumentMut> {
    let toml = std::fs::read_to_string(path).context("toml not found")?;
    let doc = toml.parse::<DocumentMut>()?;
    Ok(doc)
}

pub fn write_toml_file(doc: &DocumentMut, path: &str) -> anyhow::Result<()> {
    let output = doc.to_string();
    let mut config_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)?;
    writeln!(config_file, "{output}")?;
    Ok(())
}

pub fn parse_toml_element_to_string(key: &str, doc: &DocumentMut) -> Result<String> {
    let Some(item) = doc.get(key) else {
        return Err(anyhow!("{} not found.", key).into());
    };
    let Some(value) = item.as_str() else {
        return Err(anyhow!("parse failed: {}'s item format is not available.", key).into());
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
    use crate::graphql::tests::TestSchema;

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
                totalDiskSpace
                usedDiskSpace
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
                updateConfig(old: {old_config:?} new: "")
            }}
            "#
        );

        let res = schema.execute(&query).await;

        assert!(!res.errors.is_empty());
    }

    #[tokio::test]
    async fn test_config() {
        let schema = TestSchema::new();

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
                    maxSubCompactions
                }
            }
        ";

        let res = schema.execute(query).await;

        let data = res.data.to_string();
        assert!(
            data.contains("ackTransmission: 1024, maxOpenFiles: 8000, maxMbOfLevelBase: \"512\", numOfThread: 8, maxSubCompactions: \"2\"")
        );

        let old_config = old_config();
        let new_config = toml::toml!(
            ingest_srv_addr = "0.0.0.0:48370"
            publish_srv_addr = "0.0.0.0:48371"
            graphql_srv_addr = "127.0.0.1:8442"
            data_dir = "tests"
            retention = "100d"
            export_dir = "tests"
            ack_transmission = 1024
            max_open_files = 8000
            max_mb_of_level_base = 512
            num_of_thread = 10
            max_sub_compactions = 2
        )
        .to_string();

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
                    maxSubCompactions
                }}
            }}
            "
        );

        let res = schema.execute(&query).await;
        assert_eq!(res.data.to_string(), "{updateConfig: {ingestSrvAddr: \"0.0.0.0:48370\", publishSrvAddr: \"0.0.0.0:48371\", graphqlSrvAddr: \"127.0.0.1:8442\", dataDir: \"tests\", retention: \"100d\", exportDir: \"tests\", ackTransmission: 1024, maxOpenFiles: 8000, maxMbOfLevelBase: \"512\", numOfThread: 10, maxSubCompactions: \"2\"}}");
    }

    fn old_config() -> String {
        toml::toml!(
            ingest_srv_addr = "0.0.0.0:38370"
            publish_srv_addr = "0.0.0.0:38371"
            graphql_srv_addr = "127.0.0.1:8442"
            data_dir = "tests"
            retention = "100d"
            log_dir = "/data/logs/apps"
            export_dir = "tests"
            ack_transmission = 1024
            max_open_files = 8000
            max_mb_of_level_base = 512
            num_of_thread = 8
            max_sub_compactions = 2
        )
        .to_string()
    }
}
