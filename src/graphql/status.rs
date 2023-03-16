#[cfg(debug_assertions)]
use crate::storage::Database;
use anyhow::Context as ct;
#[cfg(debug_assertions)]
use async_graphql::Context;
use async_graphql::{InputObject, Object, Result, SimpleObject};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Notify;
use toml_edit::{value, Document};

pub const DEFAULT_TOML: &str = "/usr/local/aice/conf/giganto.toml";
const GRAPHQL_REBOOT_DELAY: u64 = 100;

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

#[derive(SimpleObject, Debug)]
struct GigantoConfig {
    ingest_address: String,
    publish_address: String,
    graphql_address: String,
    retention: String,
    max_open_files: String,
    max_mb_of_level_base: String,
}

#[derive(InputObject)]
struct UserConfig {
    ingest_address: Option<String>,
    publish_address: Option<String>,
    graphql_address: Option<String>,
    retention: Option<String>,
    max_open_files: Option<String>,
    max_mb_of_level_base: Option<String>,
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
    async fn giganto_config(&self) -> Result<GigantoConfig> {
        let toml = fs::read_to_string(DEFAULT_TOML).context("toml not found")?;
        let doc = toml.parse::<Document>()?;

        let ingest_address = doc
            .get("ingest_address")
            .context("\"ingest_address\" not found")?
            .to_string();
        let publish_address = doc
            .get("publish_address")
            .context("\"publish_address\" not found")?
            .to_string();
        let graphql_address = doc
            .get("graphql_address")
            .context("\"graphql_address\" not found")?
            .to_string();
        let retention = doc
            .get("retention")
            .context("\"retention\" not found")?
            .to_string();
        let max_open_files = doc
            .get("max_open_files")
            .context("\"max_open_files\" not found")?
            .to_string();
        let max_mb_of_level_base = doc
            .get("max_mb_of_level_base")
            .context("\"max_mb_of_level_base\" not found")?
            .to_string();

        Ok(GigantoConfig {
            ingest_address,
            publish_address,
            graphql_address,
            retention,
            max_open_files,
            max_mb_of_level_base,
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
        let toml = fs::read_to_string(DEFAULT_TOML).context("toml not found")?;
        let mut doc = toml.parse::<Document>()?;

        if let Some(ingest_address) = field.ingest_address {
            doc["ingest_address"] = value(ingest_address);
        }
        if let Some(publish_address) = field.publish_address {
            doc["publish_address"] = value(publish_address);
        }
        if let Some(graphql_address) = field.graphql_address {
            doc["graphql_address"] = value(graphql_address);
        }
        if let Some(retention) = field.retention {
            doc["retention"] = value(retention);
        }
        if let Some(max_open_files) = field.max_open_files {
            doc["max_open_files"] = value(max_open_files);
        }
        if let Some(max_mb_of_level_base) = field.max_mb_of_level_base {
            doc["max_mb_of_level_base"] = value(max_mb_of_level_base);
        }

        let output = doc.to_string();
        let mut toml_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(DEFAULT_TOML)?;
        writeln!(toml_file, "{output}")?;

        let config_reload = ctx.data::<Arc<Notify>>()?.clone();
        tokio::spawn(async move {
            // Used to complete the response of a graphql Mutation.
            tokio::time::sleep(Duration::from_millis(GRAPHQL_REBOOT_DELAY)).await;
            config_reload.notify_one();
        });

        Ok("Done".to_string())
    }
}
