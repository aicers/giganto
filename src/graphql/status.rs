use std::{
    fs::{self, OpenOptions},
    io::Write,
    time::Duration,
};

use anyhow::{anyhow, Context as ct};
use async_graphql::{Context, InputObject, Object, Result, SimpleObject};
use toml_edit::{value, DocumentMut, InlineTable};

use super::{PowerOffNotify, RebootNotify, ReloadNotify, TerminateNotify};
#[cfg(debug_assertions)]
use crate::storage::Database;
use crate::AckTransmissionCount;

const GRAPHQL_REBOOT_DELAY: u64 = 100;
const CONFIG_INGEST_SRV_ADDR: &str = "ingest_srv_addr";
pub const CONFIG_PUBLISH_SRV_ADDR: &str = "publish_srv_addr";
pub const CONFIG_GRAPHQL_SRV_ADDR: &str = "graphql_srv_addr";
const CONFIG_RETENTION: &str = "retention";
const CONFIG_MAX_OPEN_FILES: &str = "max_open_files";
const CONFIG_MAX_MB_OF_LEVEL_BASE: &str = "max_mb_of_level_base";
const CONFIG_PEER_ADDRESS: &str = "peer_address";
const CONFIG_PEER_LIST: &str = "peers";
const CONFIG_ACK_TRANSMISSION: &str = "ack_transmission";
pub const TEMP_TOML_POST_FIX: &str = ".temp.toml";

pub trait TomlPeers {
    fn get_host_name(&self) -> String;
    fn get_address(&self) -> String;
}

#[derive(SimpleObject, Debug)]
struct GigantoStatus {
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

#[derive(InputObject, SimpleObject, Debug)]
#[graphql(input_name = "InputPeerList")]
pub struct PeerList {
    pub address: String,
    pub host_name: String,
}

impl TomlPeers for PeerList {
    fn get_host_name(&self) -> String {
        self.host_name.clone()
    }
    fn get_address(&self) -> String {
        self.address.clone()
    }
}

#[derive(SimpleObject, Debug)]
struct GigantoConfig {
    ingest_srv_addr: String,
    publish_srv_addr: String,
    graphql_srv_addr: String,
    retention: String,
    max_open_files: i32,
    max_mb_of_level_base: u64,
    peer_address: String,
    peer_list: Vec<PeerList>,
    ack_transmission_cnt: u16,
}

#[derive(InputObject)]
struct UserConfig {
    ingest_srv_addr: Option<String>,
    publish_srv_addr: Option<String>,
    graphql_srv_addr: Option<String>,
    retention: Option<String>,
    max_open_files: Option<i32>,
    max_mb_of_level_base: Option<u64>,
    peer_address: Option<String>,
    peer_list: Option<Vec<PeerList>>,
    ack_transmission_cnt: Option<u16>,
}

#[derive(Default)]
pub(super) struct GigantoStatusQuery;

#[derive(Default)]
pub(super) struct GigantoConfigMutation;

#[Object]
impl GigantoStatusQuery {
    async fn giganto_status(&self) -> Result<GigantoStatus> {
        let usg = roxy::resource_usage().await;
        let host_name = roxy::hostname();
        let usg = GigantoStatus {
            name: host_name,
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
    async fn giganto_config<'ctx>(&self, ctx: &Context<'ctx>) -> Result<GigantoConfig> {
        let cfg_path = ctx.data::<String>()?;
        let doc = read_toml_file(cfg_path)?;
        let ingest_srv_addr = parse_toml_element_to_string(CONFIG_INGEST_SRV_ADDR, &doc)?;
        let publish_srv_addr = parse_toml_element_to_string(CONFIG_PUBLISH_SRV_ADDR, &doc)?;
        let graphql_srv_addr = parse_toml_element_to_string(CONFIG_GRAPHQL_SRV_ADDR, &doc)?;
        let retention = parse_toml_element_to_string(CONFIG_RETENTION, &doc)?;
        let max_open_files = parse_toml_element_to_integer(CONFIG_MAX_OPEN_FILES, &doc)?;
        let max_mb_of_level_base =
            parse_toml_element_to_integer(CONFIG_MAX_MB_OF_LEVEL_BASE, &doc)?;
        let ack_transmission_cnt = parse_toml_element_to_integer(CONFIG_ACK_TRANSMISSION, &doc)?;
        let mut peer_list = Vec::new();
        let peer_address = if doc.get(CONFIG_PEER_ADDRESS).is_some() {
            let peers_value = doc
                .get(CONFIG_PEER_LIST)
                .context("peers not found")?
                .as_array()
                .context("invalid peers format")?;
            for peer in peers_value {
                if let Some(peer_data) = peer.as_inline_table() {
                    let (Some(address_val), Some(host_name_val)) =
                        (peer_data.get("address"), peer_data.get("host_name"))
                    else {
                        return Err(anyhow!("Invalid address/hostname Value format").into());
                    };
                    let (Some(address), Some(host_name)) =
                        (address_val.as_str(), host_name_val.as_str())
                    else {
                        return Err(anyhow!("Invalid address/hostname String format").into());
                    };
                    peer_list.push(PeerList {
                        address: address.to_string(),
                        host_name: host_name.to_string(),
                    });
                }
            }
            parse_toml_element_to_string(CONFIG_PEER_ADDRESS, &doc)?
        } else {
            String::new()
        };

        Ok(GigantoConfig {
            ingest_srv_addr,
            publish_srv_addr,
            graphql_srv_addr,
            retention,
            max_open_files,
            max_mb_of_level_base,
            peer_address,
            peer_list,
            ack_transmission_cnt,
        })
    }

    #[allow(clippy::unused_async)]
    async fn ping(&self) -> Result<bool> {
        Ok(true)
    }
}

#[Object]
impl GigantoConfigMutation {
    #[allow(clippy::unused_async)]
    async fn set_giganto_config<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        field: UserConfig,
    ) -> Result<String> {
        let cfg_path = ctx.data::<String>()?;
        let new_path = copy_toml_file(cfg_path)?;
        let mut doc = read_toml_file(&new_path)?;
        insert_toml_element(CONFIG_INGEST_SRV_ADDR, &mut doc, field.ingest_srv_addr);
        insert_toml_element(CONFIG_PUBLISH_SRV_ADDR, &mut doc, field.publish_srv_addr);
        insert_toml_element(CONFIG_GRAPHQL_SRV_ADDR, &mut doc, field.graphql_srv_addr);
        insert_toml_element(CONFIG_RETENTION, &mut doc, field.retention);
        let convert_open_file = field.max_open_files.map(i64::from);
        insert_toml_element(CONFIG_MAX_OPEN_FILES, &mut doc, convert_open_file);
        let convert_level_base = field
            .max_mb_of_level_base
            .and_then(|x| i64::try_from(x).ok());
        insert_toml_element(CONFIG_MAX_MB_OF_LEVEL_BASE, &mut doc, convert_level_base);
        let convert_ack_trans_cnt = field.ack_transmission_cnt.map(i64::from);
        insert_toml_element(CONFIG_ACK_TRANSMISSION, &mut doc, convert_ack_trans_cnt);
        insert_toml_element(CONFIG_PEER_ADDRESS, &mut doc, field.peer_address);
        insert_toml_peers(&mut doc, field.peer_list)?;
        write_toml_file(&doc, &new_path)?;

        let reload_notify = ctx.data::<ReloadNotify>()?;
        let config_reload = reload_notify.0.clone();

        tokio::spawn(async move {
            // Used to complete the response of a graphql Mutation.
            tokio::time::sleep(Duration::from_millis(GRAPHQL_REBOOT_DELAY)).await;
            config_reload.notify_one();
        });

        Ok("Done".to_string())
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

fn parse_toml_element_to_integer<T>(key: &str, doc: &DocumentMut) -> Result<T>
where
    T: std::convert::TryFrom<i64>,
{
    let Some(item) = doc.get(key) else {
        return Err(anyhow!("{} not found.", key).into());
    };
    let Some(value) = item.as_integer() else {
        return Err(anyhow!("parse failed: {}'s item format is not available.", key).into());
    };
    let Ok(value) = T::try_from(value) else {
        return Err(anyhow!("parse failed: {}'s value format is not available.", key).into());
    };
    Ok(value)
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
            if let (Some(address), Some(host_name)) = (
                value(peer.get_address()).as_value(),
                value(peer.get_host_name()).as_value(),
            ) {
                table.insert("address", address.clone());
                table.insert("host_name", host_name.clone());
            } else {
                return Err(
                    anyhow!("insert failed: peer's address/hostname option not found.").into(),
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
}
