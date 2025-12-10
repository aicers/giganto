use std::{fs::OpenOptions, io::Write, time::Duration};

use anyhow::{Context as AnyhowContext, anyhow};
use async_graphql::{Context, Enum, InputObject, Object, Result, SimpleObject};
use tokio::sync::mpsc::Sender;
use toml_edit::{DocumentMut, InlineTable};
use tracing::{error, info};

use super::{PowerOffNotify, RebootNotify, TerminateNotify};
use crate::graphql::{StringNumberU32, StringNumberU64};
use crate::settings::ConfigVisible;
use crate::storage::Database;
use crate::{comm::peer::PeerIdentity, settings::Settings};

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
    disk_used_bytes: u64,
    disk_available_bytes: u64,
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

/// Input type for the `deleteSamplingPolicy` mutation.
#[derive(InputObject)]
pub struct DeleteSamplingPolicyInput {
    /// The unique identifier of the sampling policy to delete.
    pub policy_id: String,
}

/// Status of the sampling policy deletion operation.
#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug)]
pub enum DeletionStatus {
    /// Deletion completed successfully.
    Ok,
    /// Policy was not found.
    NotFound,
    /// Deletion failed due to an error.
    Failed,
}

/// Response payload for the `deleteSamplingPolicy` mutation.
#[derive(SimpleObject, Debug)]
pub struct DeleteSamplingPolicyPayload {
    /// Whether the deletion was successful.
    pub success: bool,
    /// The status of the deletion operation.
    pub status: DeletionStatus,
    /// The number of time series records deleted.
    pub deleted_count: u64,
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

#[derive(Default)]
pub(super) struct SamplingPolicyMutation;

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
            disk_used_bytes: usg.disk_used_bytes,
            disk_available_bytes: usg.disk_available_bytes,
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
    /// Updates the config with the given `new` config. It involves reloading the module with the
    /// new config.
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
        info!("New config applied");

        Ok(new_config)
    }

    #[allow(clippy::unused_async)]
    async fn stop(&self, ctx: &Context<'_>) -> Result<bool> {
        info!("Received request to stop service");
        let terminate_notify = ctx.data::<TerminateNotify>()?;
        terminate_notify.0.notify_one();

        Ok(true)
    }

    #[allow(clippy::unused_async)]
    async fn reboot(&self, ctx: &Context<'_>) -> Result<bool> {
        info!("Received request to reboot system");
        let reboot_notify = ctx.data::<RebootNotify>()?;
        reboot_notify.0.notify_one();

        Ok(true)
    }

    #[allow(clippy::unused_async)]
    async fn shutdown(&self, ctx: &Context<'_>) -> Result<bool> {
        info!("Received request to shutdown system");
        let power_off_notify = ctx.data::<PowerOffNotify>()?;
        power_off_notify.0.notify_one();

        Ok(true)
    }
}

#[Object]
impl SamplingPolicyMutation {
    /// Deletes a sampling policy and its associated time series data.
    ///
    /// This mutation removes all periodic time series data associated with the given policy ID
    /// from the database. The deletion is performed synchronously.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails. If no data exists for the given policy
    /// ID, the mutation succeeds with `deleted_count` of 0 and `status` of `NOT_FOUND`.
    #[allow(clippy::unused_async)]
    async fn delete_sampling_policy(
        &self,
        ctx: &Context<'_>,
        input: DeleteSamplingPolicyInput,
    ) -> Result<DeleteSamplingPolicyPayload> {
        info!(
            "Received request to delete sampling policy: {}",
            input.policy_id
        );

        if input.policy_id.is_empty() {
            return Err("Policy ID cannot be empty".into());
        }

        let db = ctx.data::<Database>()?;

        match db.delete_time_series_by_policy_id(&input.policy_id) {
            Ok(deleted_count) => {
                if deleted_count == 0 {
                    info!(
                        "No time series data found for policy ID: {}",
                        input.policy_id
                    );
                    Ok(DeleteSamplingPolicyPayload {
                        success: true,
                        status: DeletionStatus::NotFound,
                        deleted_count: 0,
                    })
                } else {
                    info!(
                        "Successfully deleted {} time series records for policy ID: {}",
                        deleted_count, input.policy_id
                    );
                    Ok(DeleteSamplingPolicyPayload {
                        success: true,
                        status: DeletionStatus::Ok,
                        deleted_count,
                    })
                }
            }
            Err(e) => {
                error!(
                    "Failed to delete time series for policy ID {}: {}",
                    input.policy_id, e
                );
                Ok(DeleteSamplingPolicyPayload {
                    success: false,
                    status: DeletionStatus::Failed,
                    deleted_count: 0,
                })
            }
        }
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
        let new_config = toml::toml!(
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
    }

    #[tokio::test]
    async fn config_retention_fomat_stability() {
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

    #[tokio::test]
    async fn test_delete_sampling_policy_not_found() {
        let schema = TestSchema::new();

        let query = r#"
            mutation {
                deleteSamplingPolicy(input: { policyId: "non_existent_policy" }) {
                    success
                    status
                    deletedCount
                }
            }
        "#;

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);

        let data = res.data.into_json().unwrap();
        let payload = &data["deleteSamplingPolicy"];
        assert!(payload["success"].as_bool().unwrap());
        assert_eq!(payload["status"].as_str().unwrap(), "NOT_FOUND");
        assert_eq!(payload["deletedCount"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_delete_sampling_policy_empty_id() {
        let schema = TestSchema::new();

        let query = r#"
            mutation {
                deleteSamplingPolicy(input: { policyId: "" }) {
                    success
                    status
                    deletedCount
                }
            }
        "#;

        let res = schema.execute(query).await;
        assert!(!res.errors.is_empty(), "Expected error for empty policy ID");
    }

    #[tokio::test]
    async fn test_delete_sampling_policy_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.periodic_time_series_store().unwrap();

        // Insert test time series data
        let policy_id = "test_policy_123";
        for i in 1..=5 {
            insert_time_series(&store, policy_id, i, vec![1.0, 2.0, 3.0]);
        }

        // Verify data was inserted
        let query = format!(
            r#"
            {{
                periodicTimeSeries(filter: {{ id: "{policy_id}" }}, first: 10) {{
                    edges {{
                        node {{
                            id
                        }}
                    }}
                }}
            }}
        "#
        );
        let res = schema.execute(&query).await;
        assert!(res.errors.is_empty());
        let data = res.data.into_json().unwrap();
        assert_eq!(
            data["periodicTimeSeries"]["edges"]
                .as_array()
                .unwrap()
                .len(),
            5
        );

        // Delete the policy
        let delete_query = format!(
            r#"
            mutation {{
                deleteSamplingPolicy(input: {{ policyId: "{policy_id}" }}) {{
                    success
                    status
                    deletedCount
                }}
            }}
        "#
        );

        let res = schema.execute(&delete_query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);

        let data = res.data.into_json().unwrap();
        let payload = &data["deleteSamplingPolicy"];
        assert!(payload["success"].as_bool().unwrap());
        assert_eq!(payload["status"].as_str().unwrap(), "OK");
        assert_eq!(payload["deletedCount"].as_u64().unwrap(), 5);

        // Verify data was deleted
        let query = format!(
            r#"
            {{
                periodicTimeSeries(filter: {{ id: "{policy_id}" }}, first: 10) {{
                    edges {{
                        node {{
                            id
                        }}
                    }}
                }}
            }}
        "#
        );
        let res = schema.execute(&query).await;
        assert!(res.errors.is_empty());
        let data = res.data.into_json().unwrap();
        assert_eq!(
            data["periodicTimeSeries"]["edges"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn test_delete_sampling_policy_does_not_affect_other_policies() {
        let schema = TestSchema::new();
        let store = schema.db.periodic_time_series_store().unwrap();

        // Insert data for two different policies
        let policy_a = "policy_a";
        let policy_b = "policy_b";

        for i in 1..=3 {
            insert_time_series(&store, policy_a, i, vec![1.0]);
        }
        for i in 1..=2 {
            insert_time_series(&store, policy_b, i, vec![2.0]);
        }

        // Delete policy_a
        let delete_query = format!(
            r#"
            mutation {{
                deleteSamplingPolicy(input: {{ policyId: "{policy_a}" }}) {{
                    success
                    status
                    deletedCount
                }}
            }}
        "#
        );

        let res = schema.execute(&delete_query).await;
        assert!(res.errors.is_empty());

        let data = res.data.into_json().unwrap();
        let payload = &data["deleteSamplingPolicy"];
        assert!(payload["success"].as_bool().unwrap());
        assert_eq!(payload["deletedCount"].as_u64().unwrap(), 3);

        // Verify policy_b data still exists
        let query = format!(
            r#"
            {{
                periodicTimeSeries(filter: {{ id: "{policy_b}" }}, first: 10) {{
                    edges {{
                        node {{
                            id
                        }}
                    }}
                }}
            }}
        "#
        );
        let res = schema.execute(&query).await;
        assert!(res.errors.is_empty());
        let data = res.data.into_json().unwrap();
        assert_eq!(
            data["periodicTimeSeries"]["edges"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    fn insert_time_series(
        store: &crate::storage::RawEventStore<
            giganto_client::ingest::timeseries::PeriodicTimeSeries,
        >,
        id: &str,
        start: i64,
        data: Vec<f64>,
    ) {
        let mut key: Vec<u8> = Vec::new();
        key.extend_from_slice(id.as_bytes());
        key.push(0);
        key.extend_from_slice(&start.to_be_bytes());
        let time_series_data = giganto_client::ingest::timeseries::PeriodicTimeSeries {
            id: id.to_string(),
            data,
        };
        let value = bincode::serialize(&time_series_data).unwrap();
        store.append(&key, &value).unwrap();
    }
}
