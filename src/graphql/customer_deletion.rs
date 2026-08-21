use std::{borrow::Cow, collections::HashSet, future, sync::Arc};

use anyhow::{Context as AnyhowContext, Result as AnyhowResult, anyhow};
use async_graphql::{
    Context, ContextSelectionSet, Object, OutputType, Positioned, Result, ServerResult, Value,
    indexmap::IndexMap,
    parser::types::Field,
    registry::{Deprecation, MetaEnumValue, MetaType, MetaTypeId, Registry},
    resolver_utils::{EnumItem, EnumType},
};
use tokio::sync::Mutex;
use tracing::{error, info};

use super::StringNumberU32;
use crate::{
    comm::IngestSensors,
    datetime::DateTime,
    storage::{CustomerDataDeletion, CustomerDataDeletionStatus, Database},
};

const PIGLET_COLUMN_FAMILIES: [&str; 21] = [
    "conn",
    "dns",
    "malformed_dns",
    "http",
    "rdp",
    "smtp",
    "ntlm",
    "kerberos",
    "ssh",
    "dce rpc",
    "ftp",
    "mqtt",
    "ldap",
    "tls",
    "smb",
    "nfs",
    "bootp",
    "dhcp",
    "radius",
    "icmp",
    "packet",
];

const REPRODUCE_COLUMN_FAMILIES: [&str; 18] = [
    "process create",
    "file create time",
    "network connect",
    "process terminate",
    "image load",
    "file create",
    "registry value set",
    "registry key rename",
    "file create stream hash",
    "pipe event",
    "dns query",
    "file delete",
    "process tamper",
    "file delete detected",
    "log",
    "seculog",
    "netflow5",
    "netflow9",
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CustomerDataDeletionRequestStatus {
    /// Terminal mutation response: this node accepted the request and started the deletion job.
    Accepted,
    /// Terminal mutation response: an earlier deletion job for this customer already succeeded.
    AlreadyCompleted,
    /// Wait for the existing job: this customer's previously accepted deletion is still running.
    DeletionInProgress,
    /// Retry later: another customer's deletion blocks this request, which was not accepted.
    BlockedByAnotherDeletion,
    /// Retry later: retention cleanup blocks this request, which was not accepted.
    BlockedByRetention,
    /// Retry after restart or on another node: shutdown blocks this request, which was not accepted.
    BlockedByShutdown,
    /// Node-local no-op: none of the requested targets are stored on this node.
    ///
    /// This response remains node-local until cluster aggregation is implemented in #1727.
    NoLocalTargetOnThisNode,
}

impl EnumType for CustomerDataDeletionRequestStatus {
    fn items() -> &'static [EnumItem<Self>] {
        &[
            EnumItem {
                name: "ACCEPTED",
                value: Self::Accepted,
            },
            EnumItem {
                name: "ALREADY_COMPLETED",
                value: Self::AlreadyCompleted,
            },
            EnumItem {
                name: "DELETION_IN_PROGRESS",
                value: Self::DeletionInProgress,
            },
            EnumItem {
                name: "BLOCKED_BY_ANOTHER_DELETION",
                value: Self::BlockedByAnotherDeletion,
            },
            EnumItem {
                name: "BLOCKED_BY_RETENTION",
                value: Self::BlockedByRetention,
            },
            EnumItem {
                name: "BLOCKED_BY_SHUTDOWN",
                value: Self::BlockedByShutdown,
            },
            EnumItem {
                name: "NO_LOCAL_TARGET_ON_THIS_NODE",
                value: Self::NoLocalTargetOnThisNode,
            },
        ]
    }
}

// Keep this output-only enum explicit because async-graphql's Enum derive emits an
// async OutputType::resolve implementation without awaits.
impl OutputType for CustomerDataDeletionRequestStatus {
    fn type_name() -> Cow<'static, str> {
        Cow::Borrowed("CustomerDataDeletionRequestStatus")
    }

    fn create_type_info(registry: &mut Registry) -> String {
        registry.create_output_type::<Self, _>(MetaTypeId::Enum, |_| MetaType::Enum {
            name: Self::type_name().into_owned(),
            description: None,
            enum_values: [
                (
                    "ACCEPTED",
                    "Terminal mutation response: this node accepted the request and started the deletion job.",
                ),
                (
                    "ALREADY_COMPLETED",
                    "Terminal mutation response: an earlier deletion job for this customer already succeeded.",
                ),
                (
                    "DELETION_IN_PROGRESS",
                    "Wait for the existing job: this customer's previously accepted deletion is still running.",
                ),
                (
                    "BLOCKED_BY_ANOTHER_DELETION",
                    "Retry later: another customer's deletion blocks this request, which was not accepted.",
                ),
                (
                    "BLOCKED_BY_RETENTION",
                    "Retry later: retention cleanup blocks this request, which was not accepted.",
                ),
                (
                    "BLOCKED_BY_SHUTDOWN",
                    "Retry after restart or on another node: shutdown blocks this request, which was not accepted.",
                ),
                (
                    "NO_LOCAL_TARGET_ON_THIS_NODE",
                    "Node-local no-op: none of the requested targets are stored on this node.\n\nThis response remains node-local until cluster aggregation is implemented in #1727.",
                ),
            ]
            .into_iter()
            .map(|(name, description)| {
                (
                    name.to_owned(),
                    MetaEnumValue {
                        name: name.to_owned(),
                        description: Some(description.to_owned()),
                        deprecation: Deprecation::NoDeprecated,
                        visible: None,
                        inaccessible: false,
                        tags: Vec::new(),
                        directive_invocations: Vec::new(),
                    },
                )
            })
            .collect::<IndexMap<_, _>>(),
            visible: None,
            inaccessible: false,
            tags: Vec::new(),
            rust_typename: Some(std::any::type_name::<Self>()),
            directive_invocations: Vec::new(),
            requires_scopes: Vec::new(),
        })
    }

    fn resolve(
        &self,
        _: &ContextSelectionSet<'_>,
        _: &Positioned<Field>,
    ) -> impl Future<Output = ServerResult<Value>> + Send {
        future::ready(Ok(async_graphql::resolver_utils::enum_value(*self)))
    }
}

#[derive(Default)]
pub struct CustomerDeletionRequestManager {
    request_lock: Mutex<()>,
}

#[derive(Default)]
pub(super) struct CustomerDeletionMutation;

#[Object]
impl CustomerDeletionMutation {
    /// Starts asynchronous deletion of customer-owned data stored on this Giganto node.
    async fn delete_customer_data(
        &self,
        ctx: &Context<'_>,
        service_fqdn_list: Vec<String>,
        customer_id: StringNumberU32,
    ) -> Result<CustomerDataDeletionRequestStatus> {
        let provided_targets = validate_service_fqdn_list(service_fqdn_list)?;
        let db = ctx.data::<Database>()?.clone();
        let ingest_sensors = ctx.data::<IngestSensors>()?;
        let manager = ctx.data::<Arc<CustomerDeletionRequestManager>>()?;
        let _request_guard = manager.request_lock.lock().await;

        let store = db.customer_deletion_job_store()?;
        let existing_job = store.get(customer_id.0)?;
        let is_retry = existing_job.is_some();
        let local_targets = if let Some(job) = existing_job {
            match job.status {
                CustomerDataDeletionStatus::InProgress => {
                    return Ok(CustomerDataDeletionRequestStatus::DeletionInProgress);
                }
                CustomerDataDeletionStatus::Succeeded => {
                    return Ok(CustomerDataDeletionRequestStatus::AlreadyCompleted);
                }
                CustomerDataDeletionStatus::Failed => {
                    let provided: HashSet<&str> =
                        provided_targets.iter().map(String::as_str).collect();
                    if !job
                        .service_fqdn_list
                        .iter()
                        .all(|target| provided.contains(target.as_str()))
                    {
                        return Err(
                            "Retry request must include every service FQDN from the failed job"
                                .into(),
                        );
                    }
                    job.service_fqdn_list
                }
            }
        } else {
            let local_sensors = ingest_sensors.read().await;
            let targets = provided_targets
                .into_iter()
                .filter(|target| local_sensors.contains(target))
                .collect::<Vec<_>>();
            if targets.is_empty() {
                return Ok(CustomerDataDeletionRequestStatus::NoLocalTargetOnThisNode);
            }
            targets
        };

        let in_progress = CustomerDataDeletion {
            service_fqdn_list: local_targets,
            requested_at: now_nanos(),
            status: CustomerDataDeletionStatus::InProgress,
            completed_at: None,
            error: None,
        };
        if is_retry {
            store.update(customer_id.0, &in_progress)?;
        } else {
            store.create(customer_id.0, &in_progress)?;
        }

        start_customer_deletion_worker(db, customer_id.0, in_progress.service_fqdn_list);
        Ok(CustomerDataDeletionRequestStatus::Accepted)
    }
}

fn validate_service_fqdn_list(service_fqdn_list: Vec<String>) -> Result<Vec<String>> {
    if service_fqdn_list.is_empty() {
        return Err("serviceFqdnList must not be empty".into());
    }

    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(service_fqdn_list.len());
    for service_fqdn in service_fqdn_list {
        if service_fqdn.is_empty() {
            return Err("serviceFqdnList entries must not be empty".into());
        }
        if service_fqdn.chars().any(char::is_whitespace) {
            return Err("serviceFqdnList entries must not contain whitespace".into());
        }
        let labels = service_fqdn.split('.').collect::<Vec<_>>();
        if labels.len() < 3 || labels.iter().any(|label| label.is_empty()) {
            return Err(format!("Invalid service FQDN: {service_fqdn}").into());
        }
        if !matches!(labels[0], "piglet" | "reproduce") {
            return Err(format!("Unsupported service FQDN: {service_fqdn}").into());
        }
        if seen.insert(service_fqdn.clone()) {
            validated.push(service_fqdn);
        }
    }
    if validated.is_empty() {
        return Err("serviceFqdnList must contain at least one service FQDN".into());
    }
    Ok(validated)
}

fn delete_customer_data_from_db(db: &Database, service_fqdn_list: &[String]) -> AnyhowResult<()> {
    delete_customer_data_with(
        service_fqdn_list,
        |service_fqdn, cf_names| db.delete_customer_event_ranges(service_fqdn, cf_names),
        |service_fqdn| db.sensors_store()?.delete(service_fqdn),
    )
}

fn delete_customer_data_with(
    service_fqdn_list: &[String],
    mut delete_event_ranges: impl FnMut(&str, &[&str]) -> AnyhowResult<()>,
    mut delete_sensor: impl FnMut(&str) -> AnyhowResult<()>,
) -> AnyhowResult<()> {
    for service_fqdn in service_fqdn_list {
        let column_families = if service_fqdn.starts_with("piglet.") {
            PIGLET_COLUMN_FAMILIES.as_slice()
        } else {
            REPRODUCE_COLUMN_FAMILIES.as_slice()
        };
        delete_event_ranges(service_fqdn, column_families)
            .with_context(|| format!("cannot delete customer event ranges for {service_fqdn}"))?;
    }

    for service_fqdn in service_fqdn_list {
        delete_sensor(service_fqdn)
            .with_context(|| format!("cannot delete exact sensors key for {service_fqdn}"))?;
    }
    Ok(())
}

fn start_customer_deletion_worker(db: Database, customer_id: u32, service_fqdn_list: Vec<String>) {
    let worker_db = db.clone();
    let worker = tokio::task::spawn_blocking(move || {
        delete_customer_data_from_db(&worker_db, &service_fqdn_list)
    });

    tokio::spawn(supervise_worker(worker, db, customer_id));
}

#[derive(Debug)]
enum DeletionOutcome {
    Succeeded,
    Failed(String),
}

const TERMINAL_STATUS_UPDATE_ATTEMPTS: usize = 2;

/// Owns the single transition from `InProgress` to a durable terminal state.
///
/// The blocking worker only performs deletion and returns its outcome. Keeping
/// persistence here ensures a failed status write can be retried without
/// repeating deletion work.
///
/// TODO(#1724): Register and drain this supervisor at the application lifecycle
/// level before RocksDB shutdown. Until that coordination is implemented, the
/// supervisor remains detached.
async fn supervise_worker(
    worker: tokio::task::JoinHandle<AnyhowResult<()>>,
    db: Database,
    customer_id: u32,
) {
    let outcome = match worker.await {
        Ok(Ok(())) => {
            info!(customer_id, "Customer data deletion succeeded");
            DeletionOutcome::Succeeded
        }
        Ok(Err(err)) => {
            let message = format!("{err:#}");
            error!(customer_id, "Customer data deletion failed: {message}");
            DeletionOutcome::Failed(message)
        }
        Err(join_error) => {
            let message = format!("Customer data deletion task join failure: {join_error}");
            error!(customer_id, "{message}");
            DeletionOutcome::Failed(message)
        }
    };

    for attempt in 1..=TERMINAL_STATUS_UPDATE_ATTEMPTS {
        let update = match &outcome {
            DeletionOutcome::Succeeded => mark_job_succeeded(&db, customer_id),
            DeletionOutcome::Failed(message) => mark_job_failed(&db, customer_id, message.clone()),
        };
        match update {
            Ok(()) => return,
            Err(err) => error!(
                customer_id,
                attempt,
                max_attempts = TERMINAL_STATUS_UPDATE_ATTEMPTS,
                "Failed to persist terminal customer data deletion status: {err:#}"
            ),
        }
    }
}

fn mark_job_succeeded(db: &Database, customer_id: u32) -> AnyhowResult<()> {
    let store = db.customer_deletion_job_store()?;
    let mut job = store
        .get(customer_id)?
        .ok_or_else(|| anyhow!("customer deletion job disappeared"))?;
    job.status = CustomerDataDeletionStatus::Succeeded;
    job.completed_at = Some(now_nanos());
    job.error = None;
    store.update(customer_id, &job)
}

fn mark_job_failed(db: &Database, customer_id: u32, error: String) -> AnyhowResult<()> {
    let store = db.customer_deletion_job_store()?;
    let mut job = store
        .get(customer_id)?
        .ok_or_else(|| anyhow!("customer deletion job disappeared"))?;
    job.status = CustomerDataDeletionStatus::Failed;
    job.completed_at = Some(now_nanos());
    job.error = Some(error);
    store.update(customer_id, &job)
}

fn now_nanos() -> i64 {
    DateTime::now().timestamp_nanos_opt().unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use super::{
        PIGLET_COLUMN_FAMILIES, REPRODUCE_COLUMN_FAMILIES, delete_customer_data_from_db,
        delete_customer_data_with, supervise_worker, validate_service_fqdn_list,
    };
    use crate::{
        datetime::DateTime,
        graphql::tests::TestSchema,
        storage::{CustomerDataDeletion, CustomerDataDeletionStatus, Database, DbOptions},
    };

    fn event_key(service_fqdn: &str, suffix: &[u8]) -> Vec<u8> {
        let mut key = service_fqdn.as_bytes().to_vec();
        key.push(0);
        key.extend_from_slice(suffix);
        key
    }

    async fn wait_for_terminal_job(db: &Database, customer_id: u32) -> CustomerDataDeletion {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let job = db
                .customer_deletion_job_store()
                .unwrap()
                .get(customer_id)
                .unwrap()
                .unwrap();
            if job.status != CustomerDataDeletionStatus::InProgress {
                return job;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "customer deletion job did not finish"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn validates_and_deduplicates_service_fqdns() {
        let result = validate_service_fqdn_list(vec![
            "piglet.node1.example.test".to_string(),
            "reproduce.node2.example.test".to_string(),
            "piglet.node1.example.test".to_string(),
        ])
        .unwrap();
        assert_eq!(
            result,
            ["piglet.node1.example.test", "reproduce.node2.example.test"]
        );
    }

    #[test]
    fn rejects_invalid_service_fqdns() {
        let invalid_lists = [
            vec![],
            vec![""],
            vec!["piglet.node1"],
            vec!["piglet..example.test"],
            vec!["piglet.node 1.example.test"],
            vec!["Piglet.node1.example.test"],
            vec!["manager.node1.example.test"],
        ];
        for invalid in invalid_lists {
            assert!(
                validate_service_fqdn_list(invalid.into_iter().map(str::to_string).collect())
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn mutation_accepts_first_request_and_observes_existing_states() {
        let target = "piglet.node1.example.test";
        let schema = TestSchema::new_with_ingest_sensors(&[target]);
        let before = DateTime::now().timestamp_nanos_opt().unwrap();
        let response = schema
            .execute(&format!(
                r#"mutation {{
                    deleteCustomerData(
                        serviceFqdnList: ["{target}", "{target}"]
                        customerId: "42"
                    )
                }}"#
            ))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(response.data.to_string(), "{deleteCustomerData: ACCEPTED}");

        let completed = wait_for_terminal_job(&schema.db, 42).await;
        assert_eq!(completed.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(completed.service_fqdn_list, [target]);
        assert!(completed.requested_at >= before);
        assert!(completed.completed_at.is_some());
        assert!(completed.error.is_none());

        let response = schema
            .execute(&format!(
                r#"mutation {{
                    deleteCustomerData(serviceFqdnList: ["{target}"] customerId: "42")
                }}"#
            ))
            .await;
        assert_eq!(
            response.data.to_string(),
            "{deleteCustomerData: ALREADY_COMPLETED}"
        );

        let in_progress = CustomerDataDeletion {
            service_fqdn_list: vec![target.to_string()],
            requested_at: 1,
            status: CustomerDataDeletionStatus::InProgress,
            completed_at: None,
            error: None,
        };
        schema
            .db
            .customer_deletion_job_store()
            .unwrap()
            .create(43, &in_progress)
            .unwrap();
        let response = schema
            .execute(&format!(
                r#"mutation {{
                    deleteCustomerData(serviceFqdnList: ["{target}"] customerId: "43")
                }}"#
            ))
            .await;
        assert_eq!(
            response.data.to_string(),
            "{deleteCustomerData: DELETION_IN_PROGRESS}"
        );
    }

    #[tokio::test]
    async fn failed_retry_regenerates_requested_at_and_uses_stored_targets() {
        let stored_target = "reproduce.node1.example.test";
        let extra_target = "piglet.node2.example.test";
        let schema = TestSchema::new_with_ingest_sensors(&[]);
        let failed = CustomerDataDeletion {
            service_fqdn_list: vec![stored_target.to_string()],
            requested_at: 1,
            status: CustomerDataDeletionStatus::Failed,
            completed_at: Some(2),
            error: Some("old failure".to_string()),
        };
        schema
            .db
            .customer_deletion_job_store()
            .unwrap()
            .create(77, &failed)
            .unwrap();

        let inconsistent = schema
            .execute(&format!(
                r#"mutation {{
                    deleteCustomerData(serviceFqdnList: ["{extra_target}"] customerId: "77")
                }}"#
            ))
            .await;
        assert!(!inconsistent.errors.is_empty());
        assert_eq!(
            schema
                .db
                .customer_deletion_job_store()
                .unwrap()
                .get(77)
                .unwrap(),
            Some(failed)
        );

        let response = schema
            .execute(&format!(
                r#"mutation {{
                    deleteCustomerData(
                        serviceFqdnList: ["{extra_target}", "{stored_target}"]
                        customerId: "77"
                    )
                }}"#
            ))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(response.data.to_string(), "{deleteCustomerData: ACCEPTED}");
        let completed = wait_for_terminal_job(&schema.db, 77).await;
        assert!(completed.requested_at > 1);
        assert_eq!(completed.service_fqdn_list, [stored_target]);
        assert_eq!(completed.status, CustomerDataDeletionStatus::Succeeded);
    }

    #[tokio::test]
    async fn mutation_returns_no_local_target_without_creating_job() {
        let schema = TestSchema::new_with_ingest_sensors(&[]);
        let response = schema
            .execute(
                r#"mutation {
                    deleteCustomerData(
                        serviceFqdnList: ["piglet.node1.example.test"]
                        customerId: "5"
                    )
                }"#,
            )
            .await;
        assert_eq!(
            response.data.to_string(),
            "{deleteCustomerData: NO_LOCAL_TARGET_ON_THIS_NODE}"
        );
        assert!(
            schema
                .db
                .customer_deletion_job_store()
                .unwrap()
                .get(5)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn deletes_owned_ranges_and_preserves_other_data() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        let piglet = "piglet.node1.example.test";
        let reproduce = "reproduce.node1.example.test";
        let similar = "piglet.node1.example.test2";
        let other = "piglet.other.example.test";
        let piglet_key = event_key(piglet, &[1]);
        let reproduce_key = event_key(reproduce, &[1]);
        let similar_key = event_key(similar, &[1]);
        let other_key = event_key(other, &[1]);

        for cf in PIGLET_COLUMN_FAMILIES {
            db.put_cf_for_test(cf, &piglet_key, b"target").unwrap();
            db.put_cf_for_test(cf, &similar_key, b"similar").unwrap();
            db.put_cf_for_test(cf, &other_key, b"other").unwrap();
        }
        for cf in REPRODUCE_COLUMN_FAMILIES {
            db.put_cf_for_test(cf, &reproduce_key, b"target").unwrap();
            db.put_cf_for_test(cf, &other_key, b"other").unwrap();
        }
        for cf in ["periodic time series", "statistics", "oplog"] {
            db.put_cf_for_test(cf, &piglet_key, b"excluded").unwrap();
            db.put_cf_for_test(cf, &reproduce_key, b"excluded").unwrap();
        }
        let sensors = db.sensors_store().unwrap();
        let now = DateTime::now();
        for sensor in [piglet, reproduce, similar, other] {
            sensors.insert(sensor, now).unwrap();
        }

        delete_customer_data_from_db(&db, &[piglet.to_string(), reproduce.to_string()]).unwrap();

        for cf in PIGLET_COLUMN_FAMILIES {
            assert!(db.get_cf_for_test(cf, &piglet_key).unwrap().is_none());
            assert!(db.get_cf_for_test(cf, &similar_key).unwrap().is_some());
            assert!(db.get_cf_for_test(cf, &other_key).unwrap().is_some());
        }
        for cf in REPRODUCE_COLUMN_FAMILIES {
            assert!(db.get_cf_for_test(cf, &reproduce_key).unwrap().is_none());
            assert!(db.get_cf_for_test(cf, &other_key).unwrap().is_some());
        }
        for cf in ["periodic time series", "statistics", "oplog"] {
            assert!(db.get_cf_for_test(cf, &piglet_key).unwrap().is_some());
            assert!(db.get_cf_for_test(cf, &reproduce_key).unwrap().is_some());
        }
        let remaining_sensors = db.sensors_store().unwrap().sensor_list();
        assert!(!remaining_sensors.contains(piglet));
        assert!(!remaining_sensors.contains(reproduce));
        assert!(remaining_sensors.contains(similar));
        assert!(remaining_sensors.contains(other));
    }

    #[test]
    fn missing_target_data_is_a_successful_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        delete_customer_data_from_db(
            &db,
            &[
                "piglet.missing.example.test".to_string(),
                "reproduce.missing.example.test".to_string(),
            ],
        )
        .unwrap();
    }

    #[test]
    fn sensor_deletion_only_runs_after_all_event_deletions_succeed() {
        let sensor_delete_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&sensor_delete_count);
        let result = delete_customer_data_with(
            &["piglet.node1.example.test".to_string()],
            |service_fqdn, cf_names| {
                assert_eq!(service_fqdn, "piglet.node1.example.test");
                assert_eq!(cf_names, PIGLET_COLUMN_FAMILIES);
                anyhow::bail!("injected event deletion failure");
            },
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(sensor_delete_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unexpected_task_failure_is_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        let make_job = || CustomerDataDeletion {
            service_fqdn_list: vec!["piglet.node1.example.test".to_string()],
            requested_at: 1,
            status: CustomerDataDeletionStatus::InProgress,
            completed_at: None,
            error: None,
        };
        let store = db.customer_deletion_job_store().unwrap();
        store.create(1, &make_job()).unwrap();
        let panicking_worker = tokio::task::spawn_blocking(|| {
            panic!("injected worker panic");
        });
        supervise_worker(panicking_worker, db.clone(), 1).await;
        let failed = store.get(1).unwrap().unwrap();
        assert_eq!(failed.status, CustomerDataDeletionStatus::Failed);
        assert!(failed.completed_at.is_some());
        assert!(
            failed
                .error
                .as_deref()
                .is_some_and(|message| message.contains("join failure"))
        );
    }

    #[tokio::test]
    async fn supervisor_owns_terminal_job_updates() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        let make_job = || CustomerDataDeletion {
            service_fqdn_list: vec!["piglet.node1.example.test".to_string()],
            requested_at: 1,
            status: CustomerDataDeletionStatus::InProgress,
            completed_at: None,
            error: None,
        };
        let store = db.customer_deletion_job_store().unwrap();

        store.create(1, &make_job()).unwrap();
        let succeeded_worker = tokio::task::spawn_blocking(|| Ok(()));
        supervise_worker(succeeded_worker, db.clone(), 1).await;
        let succeeded = store.get(1).unwrap().unwrap();
        assert_eq!(succeeded.status, CustomerDataDeletionStatus::Succeeded);
        assert!(succeeded.completed_at.is_some());
        assert!(succeeded.error.is_none());

        store.create(2, &make_job()).unwrap();
        let deletion_error = "injected deletion failure".to_string();
        let failed_worker = tokio::task::spawn_blocking({
            let deletion_error = deletion_error.clone();
            move || anyhow::bail!(deletion_error)
        });
        supervise_worker(failed_worker, db.clone(), 2).await;
        let failed = store.get(2).unwrap().unwrap();
        assert_eq!(failed.status, CustomerDataDeletionStatus::Failed);
        assert!(failed.completed_at.is_some());
        assert_eq!(failed.error.as_deref(), Some(deletion_error.as_str()));
    }
}
