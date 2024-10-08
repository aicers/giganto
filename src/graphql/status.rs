use std::{
    fs::{self, OpenOptions},
    io::Write,
    time::Duration,
};

use anyhow::{anyhow, Context as ct};
use async_graphql::{Context, InputObject, Object, Result, SimpleObject, StringNumber};
use toml_edit::{value, DocumentMut, InlineTable};
use tracing::info;

use super::{PowerOffNotify, RebootNotify, ReloadNotify, TerminateNotify};
use crate::peer::PeerIdentity;
use crate::settings::Config;
#[cfg(debug_assertions)]
use crate::storage::Database;
use crate::AckTransmissionCount;

const GRAPHQL_REBOOT_DELAY: u64 = 100;
pub const CONFIG_PUBLISH_SRV_ADDR: &str = "publish_srv_addr";
pub const CONFIG_GRAPHQL_SRV_ADDR: &str = "graphql_srv_addr";
const CONFIG_ACK_TRANSMISSION: &str = "ack_transmission";
pub const TEMP_TOML_POST_FIX: &str = ".temp.toml";

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

#[Object]
impl Config {
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
        humantime::format_duration(self.retention).to_string()
    }

    async fn data_dir(&self) -> String {
        self.data_dir.to_string_lossy().to_string()
    }

    async fn log_dir(&self) -> String {
        self.log_dir.to_string_lossy().to_string()
    }

    async fn export_dir(&self) -> String {
        self.export_dir.to_string_lossy().to_string()
    }

    async fn max_open_files(&self) -> i32 {
        self.max_open_files
    }

    async fn max_mb_of_level_base(&self) -> StringNumber<u64> {
        StringNumber(self.max_mb_of_level_base)
    }

    async fn num_of_thread(&self) -> i32 {
        self.num_of_thread
    }

    async fn max_sub_compactions(&self) -> StringNumber<u32> {
        StringNumber(self.max_sub_compactions)
    }

    async fn addr_to_peers(&self) -> Option<String> {
        self.addr_to_peers.map(|addr| addr.to_string())
    }

    async fn peers(&self) -> Option<Vec<PeerIdentity>> {
        self.peers.clone().map(|peers| peers.into_iter().collect())
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
    async fn properties_cf<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: PropertyFilter,
    ) -> Result<Properties> {
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
    async fn config<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Config> {
        let cfg_path = ctx.data::<String>()?;
        let toml = fs::read_to_string(cfg_path).context("toml not found")?;

        let config: Config = toml::from_str(&toml)?;

        Ok(config)
    }

    #[allow(clippy::unused_async)]
    async fn ping(&self) -> Result<bool> {
        Ok(true)
    }
}

#[Object]
impl ConfigMutation {
    #[allow(clippy::unused_async)]
    async fn set_config<'ctx>(&self, ctx: &Context<'ctx>, draft: String) -> Result<bool> {
        let config_draft: Config = toml::from_str(&draft)?;

        let cfg_path = ctx.data::<String>()?;

        let config_toml = fs::read_to_string(cfg_path).context("toml not found")?;
        let config: Config = toml::from_str(&config_toml)?;

        if config == config_draft {
            info!("No changes.");
            return Err("No changes".to_string().into());
        }

        let new_path = copy_toml_file(cfg_path)?;

        fs::write(new_path, draft)?;

        let reload_notify = ctx.data::<ReloadNotify>()?;
        let config_reload = reload_notify.0.clone();

        tokio::spawn(async move {
            // Used to complete the response of a graphql Mutation.
            tokio::time::sleep(Duration::from_millis(GRAPHQL_REBOOT_DELAY)).await;
            config_reload.notify_one();
        });
        info!("Draft applied.");

        Ok(true)
    }

    async fn set_ack_transmission_count<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        count: u16,
    ) -> Result<String> {
        let cfg_path = ctx.data::<String>()?;
        let mut doc = read_toml_file(cfg_path)?;
        let convert_ack_trans_cnt = Some(i64::from(count));
        insert_toml_element(CONFIG_ACK_TRANSMISSION, &mut doc, convert_ack_trans_cnt);
        write_toml_file(&doc, cfg_path)?;

        let ack_cnt = ctx.data::<AckTransmissionCount>()?;
        *ack_cnt.write().await = count;

        Ok("Done".to_string())
    }

    #[allow(clippy::unused_async)]
    async fn stop<'ctx>(&self, ctx: &Context<'ctx>) -> Result<bool> {
        let terminate_notify = ctx.data::<TerminateNotify>()?;
        let notify_terminate = terminate_notify.0.clone();
        notify_terminate.notify_one();

        Ok(true)
    }

    #[allow(clippy::unused_async)]
    async fn reboot<'ctx>(&self, ctx: &Context<'ctx>) -> Result<bool> {
        let reboot_notify = ctx.data::<RebootNotify>()?;
        let notify_reboot = reboot_notify.0.clone();
        notify_reboot.notify_one();

        Ok(true)
    }

    #[allow(clippy::unused_async)]
    async fn shutdown<'ctx>(&self, ctx: &Context<'ctx>) -> Result<bool> {
        let power_off_notify = ctx.data::<PowerOffNotify>()?;
        let notify_power_off = power_off_notify.0.clone();
        notify_power_off.notify_one();

        Ok(true)
    }
}

fn copy_toml_file(path: &str) -> Result<String> {
    let new_path = format!("{path}{TEMP_TOML_POST_FIX}");
    fs::copy(path, &new_path)?;
    Ok(new_path)
}

pub fn read_toml_file(path: &str) -> Result<DocumentMut> {
    let toml = fs::read_to_string(path).context("toml not found")?;
    let doc = toml.parse::<DocumentMut>()?;
    Ok(doc)
}

pub fn write_toml_file(doc: &DocumentMut, path: &str) -> Result<()> {
    let output = doc.to_string();
    let mut config_file = OpenOptions::new().write(true).truncate(true).open(path)?;
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

fn insert_toml_element<T>(key: &str, doc: &mut DocumentMut, input: Option<T>)
where
    T: std::convert::Into<toml_edit::Value>,
{
    if let Some(element) = input {
        doc[key] = value(element);
    };
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
            if let (Some(addr), Some(hostname)) = (
                value(peer.get_addr()).as_value(),
                value(peer.get_hostname()).as_value(),
            ) {
                table.insert("addr", addr.clone());
                table.insert("hostname", hostname.clone());
            } else {
                return Err(
                    anyhow!("insert failed: peer's `addr`, `hostname` option not found.").into(),
                );
            }
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

        let query = r#"
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
        "#;

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty());
    }

    #[tokio::test]
    async fn test_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        let toml_content = test_toml_content();

        std::fs::write(&config_path, toml_content).unwrap();

        let schema =
            TestSchema::new_with_config_file_path(config_path.to_string_lossy().to_string());

        let query = r#"
            {
                config {
                    ingestSrvAddr
                    publishSrvAddr
                    graphqlSrvAddr
                    dataDir
                    retention
                    logDir
                    exportDir
                    ackTransmission
                    maxOpenFiles
                    maxMbOfLevelBase
                    numOfThread
                    maxSubCompactions
                    addrToPeers
                    peers {
                        addr
                        hostname
                    }
                }
            }
        "#;

        let res = schema.execute(query).await;

        let data = res.data.to_string();
        assert_eq!(
            data,
            "{config: {ingestSrvAddr: \"0.0.0.0:38370\", publishSrvAddr: \"0.0.0.0:38371\", \
            graphqlSrvAddr: \"127.0.0.1:8442\", dataDir: \"tests/data\", retention: \"3months 8days 16h 19m 12s\", logDir: \"/data/logs/apps\", exportDir: \"tests/export\", ackTransmission: 1024, maxOpenFiles: 8000, maxMbOfLevelBase: \"512\", numOfThread: 8, maxSubCompactions: \"2\", addrToPeers: \"127.0.0.1:48383\", peers: [{addr: \"127.0.0.1:60192\", hostname: \"node2\"}]}}".to_string()
        );
    }

    #[tokio::test]
    async fn test_set_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        let toml_content = test_toml_content();

        std::fs::write(&config_path, &toml_content).unwrap();

        let schema =
            TestSchema::new_with_config_file_path(config_path.to_string_lossy().to_string());

        // No changes
        let query = format!(
            r#"
                mutation {{
                    setConfig(draft: {toml_content:?})
                }}
                "#
        );

        let res = schema.execute(&query).await;

        assert_eq!(
            res.errors.first().unwrap().message,
            "No changes".to_string()
        );

        // Change publish port
        let new_draft = r#"
            ingest_srv_addr = "0.0.0.0:38370"
            publish_srv_addr = "0.0.0.0:38372"
            graphql_srv_addr = "127.0.0.1:8442"
            data_dir = "tests/data"
            retention = "100d"
            log_dir = "/data/logs/apps"
            export_dir = "tests/export"
            ack_transmission = 1024
            max_open_files = 8000
            max_mb_of_level_base = 512
            num_of_thread = 8
            max_sub_compactions = 2
            addr_to_peers = "127.0.0.1:48383"
            peers = [{ addr = "127.0.0.1:60192", hostname = "node2" }]
            "#;

        let query = format!(
            r#"
            mutation {{
                setConfig(draft: {new_draft:?})
            }}
            "#
        );

        let res = schema.execute(&query).await;

        assert_eq!(res.data.to_string(), "{setConfig: true}");

        // check config temp file changes
        let config_temp_file =
            std::fs::read_to_string(&config_path.with_extension("toml.temp.toml")).unwrap();

        assert!(
            config_temp_file.contains(r#"publish_srv_addr = "0.0.0.0:38372""#),
            "Config update was not applied correctly: {}",
            config_temp_file
        );
    }

    fn test_toml_content() -> String {
        r#"
            ingest_srv_addr = "0.0.0.0:38370"
            publish_srv_addr = "0.0.0.0:38371"
            graphql_srv_addr = "127.0.0.1:8442"
            data_dir = "tests/data"
            retention = "100d"
            log_dir = "/data/logs/apps"
            export_dir = "tests/export"
            ack_transmission = 1024
            max_open_files = 8000
            max_mb_of_level_base = 512
            num_of_thread = 8
            max_sub_compactions = 2
            addr_to_peers = "127.0.0.1:48383"
            peers = [{ addr = "127.0.0.1:60192", hostname = "node2" }]
            "#
        .to_string()
    }
}
