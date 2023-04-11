#[cfg(debug_assertions)]
use crate::storage::Database;
use anyhow::{anyhow, Context as ct};
use async_graphql::Context;
use async_graphql::{InputObject, Object, Result, SimpleObject};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Notify;
use toml_edit::{value, Document, InlineTable};

const GRAPHQL_REBOOT_DELAY: u64 = 100;
const CONFIG_INGEST_ADDRESS: &str = "ingest_address";
const CONFIG_PUBLISH_ADDRESS: &str = "publish_address";
const CONFIG_GRAPHQL_ADDRESS: &str = "graphql_address";
const CONFIG_RETENTION: &str = "retention";
const CONFIG_MAX_OPEN_FILES: &str = "max_open_files";
const CONFIG_MAX_MB_OF_LEVEL_BASE: &str = "max_mb_of_level_base";
const CONFIG_PEER_ADDRESS: &str = "peer_address";

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
    ingest_address: String,
    publish_address: String,
    graphql_address: String,
    retention: String,
    max_open_files: String,
    max_mb_of_level_base: String,
    peer_address: String,
    peer_list: Vec<PeerList>,
}

#[derive(InputObject)]
struct UserConfig {
    ingest_address: Option<String>,
    publish_address: Option<String>,
    graphql_address: Option<String>,
    retention: Option<String>,
    max_open_files: Option<String>,
    max_mb_of_level_base: Option<String>,
    peer_address: Option<String>,
    peer_list: Option<Vec<PeerList>>,
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
    async fn giganto_config<'ctx>(
        &self,
        ctx: &async_graphql::Context<'ctx>,
    ) -> Result<GigantoConfig> {
        let cfg_path = ctx.data::<String>()?;
        let doc = read_toml_file(cfg_path)?;
        let ingest_address = parse_toml_element(CONFIG_INGEST_ADDRESS, &doc)?;
        let publish_address = parse_toml_element(CONFIG_PUBLISH_ADDRESS, &doc)?;
        let graphql_address = parse_toml_element(CONFIG_GRAPHQL_ADDRESS, &doc)?;
        let retention = parse_toml_element(CONFIG_RETENTION, &doc)?;
        let max_open_files = parse_toml_element(CONFIG_MAX_OPEN_FILES, &doc)?;
        let max_mb_of_level_base = parse_toml_element(CONFIG_MAX_MB_OF_LEVEL_BASE, &doc)?;
        let peer_address = parse_toml_element(CONFIG_PEER_ADDRESS, &doc)?;
        let peers_value = doc
            .get("peers")
            .context("peers not found")?
            .as_array()
            .context("invaild peers format")?;
        let mut peer_list = Vec::new();
        for peer in peers_value.iter() {
            if let Some(peer_data) = peer.as_inline_table() {
                let (Some(address_val),Some(host_name_val)) = (peer_data.get("address"),peer_data.get("host_name")) else{
                    return Err(anyhow!("Invalid address/hostname Value format").into());
                };
                let (Some(address),Some(host_name)) = (address_val.as_str(),host_name_val.as_str()) else{
                    return Err(anyhow!("Invalid address/hostname String format").into());
                };
                peer_list.push(PeerList {
                    address: address.to_string(),
                    host_name: host_name.to_string(),
                });
            }
        }
        Ok(GigantoConfig {
            ingest_address,
            publish_address,
            graphql_address,
            retention,
            max_open_files,
            max_mb_of_level_base,
            peer_address,
            peer_list,
        })
    }
}

#[Object]
impl GigantoConfigMutation {
    #[allow(clippy::unused_async)]
    async fn set_giganto_config<'ctx>(
        &self,
        ctx: &async_graphql::Context<'ctx>,
        field: UserConfig,
    ) -> Result<String> {
        let cfg_path = ctx.data::<String>()?;
        let mut doc = read_toml_file(cfg_path)?;
        insert_toml_element(CONFIG_INGEST_ADDRESS, &mut doc, field.ingest_address);
        insert_toml_element(CONFIG_PUBLISH_ADDRESS, &mut doc, field.publish_address);
        insert_toml_element(CONFIG_GRAPHQL_ADDRESS, &mut doc, field.graphql_address);
        insert_toml_element(CONFIG_RETENTION, &mut doc, field.retention);
        insert_toml_element(CONFIG_MAX_OPEN_FILES, &mut doc, field.max_open_files);
        insert_toml_element(
            CONFIG_MAX_MB_OF_LEVEL_BASE,
            &mut doc,
            field.max_mb_of_level_base,
        );
        insert_toml_element(CONFIG_PEER_ADDRESS, &mut doc, field.peer_address);
        insert_toml_peers(&mut doc, field.peer_list)?;
        write_toml_file(&doc, cfg_path)?;

        let config_reload = ctx.data::<Arc<Notify>>()?.clone();
        tokio::spawn(async move {
            // Used to complete the response of a graphql Mutation.
            tokio::time::sleep(Duration::from_millis(GRAPHQL_REBOOT_DELAY)).await;
            config_reload.notify_one();
        });

        Ok("Done".to_string())
    }
}

pub fn read_toml_file(path: &str) -> Result<Document> {
    let toml = fs::read_to_string(path).context("toml not found")?;
    let doc = toml.parse::<Document>()?;
    Ok(doc)
}

pub fn write_toml_file(doc: &Document, path: &str) -> Result<()> {
    let output = doc.to_string();
    let mut config_file = OpenOptions::new().write(true).truncate(true).open(path)?;
    writeln!(config_file, "{output}")?;
    Ok(())
}

fn parse_toml_element(key: &str, doc: &Document) -> Result<String> {
    let Some(item) = doc.get(key) else {
        return Err(anyhow!("{} not found.",key).into());
    };
    let Some(value) = item.as_str() else {
        return Err(anyhow!("parse failed: {}'s format is not available.",key).into());
    };
    Ok(value.to_string())
}

fn insert_toml_element(key: &str, doc: &mut Document, input: Option<String>) {
    if let Some(element) = input {
        doc[key] = value(element);
    };
}

pub fn insert_toml_peers<T>(doc: &mut Document, input: Option<Vec<T>>) -> Result<()>
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
