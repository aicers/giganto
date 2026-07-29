use std::{collections::HashSet, sync::Arc};

use anyhow::{Context as AnyhowContext, Result as AnyhowResult, anyhow};
use async_graphql::{Context, Enum, Object, Result};
use tokio::sync::Mutex;
use tracing::{error, info};

use super::StringNumberU32;
use crate::{
    cancellation::TaskTracker,
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

#[derive(Enum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum CustomerDataDeletionRequestStatus {
    Accepted,
    AlreadyCompleted,
    DeletionInProgress,
    Busy,
    RetentionInProgress,
    ShuttingDown,
    NoLocalTarget,
}

pub struct CustomerDeletionTaskManager {
    tracker: Arc<TaskTracker>,
    request_lock: Mutex<()>,
}

impl Default for CustomerDeletionTaskManager {
    fn default() -> Self {
        Self {
            tracker: Arc::new(TaskTracker::new()),
            request_lock: Mutex::new(()),
        }
    }
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
        let manager = ctx.data::<Arc<CustomerDeletionTaskManager>>()?;
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
                return Ok(CustomerDataDeletionRequestStatus::NoLocalTarget);
            }
            targets
        };

        let in_progress = CustomerDataDeletion {
            service_fqdn_list: local_targets.clone(),
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

        start_customer_deletion_worker(&manager.tracker, db, customer_id.0, local_targets)?;
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
        |cf_name, service_fqdn| db.delete_customer_event_range(cf_name, service_fqdn),
        |service_fqdn| db.sensors_store()?.delete(service_fqdn),
    )
}

fn delete_customer_data_with(
    service_fqdn_list: &[String],
    mut delete_event_range: impl FnMut(&str, &str) -> AnyhowResult<()>,
    mut delete_sensor: impl FnMut(&str) -> AnyhowResult<()>,
) -> AnyhowResult<()> {
    for service_fqdn in service_fqdn_list {
        let column_families = if service_fqdn.starts_with("piglet.") {
            PIGLET_COLUMN_FAMILIES.as_slice()
        } else {
            REPRODUCE_COLUMN_FAMILIES.as_slice()
        };
        for cf_name in column_families {
            delete_event_range(cf_name, service_fqdn).with_context(|| {
                format!("cannot delete customer data range for {service_fqdn} from {cf_name}")
            })?;
        }
    }

    for service_fqdn in service_fqdn_list {
        delete_sensor(service_fqdn)
            .with_context(|| format!("cannot delete exact sensors key for {service_fqdn}"))?;
    }
    Ok(())
}

fn start_customer_deletion_worker(
    tracker: &TaskTracker,
    db: Database,
    customer_id: u32,
    service_fqdn_list: Vec<String>,
) -> AnyhowResult<()> {
    let worker_db = db.clone();
    let worker = tracker.spawn(
        format!("customer-data-deletion-{customer_id}"),
        move |_token| async move {
            match delete_customer_data_from_db(&worker_db, &service_fqdn_list) {
                Ok(()) => {
                    if let Err(err) = mark_job_succeeded(&worker_db, customer_id) {
                        error!(
                            customer_id,
                            "Failed to persist successful customer data deletion: {err:#}"
                        );
                    } else {
                        info!(customer_id, "Customer data deletion completed");
                    }
                }
                Err(err) => {
                    let message = format!("{err:#}");
                    if let Err(update_err) =
                        mark_job_failed(&worker_db, customer_id, message.clone())
                    {
                        error!(
                            customer_id,
                            "Failed to persist customer data deletion failure: {update_err:#}"
                        );
                    }
                    error!(customer_id, "Customer data deletion failed: {message}");
                }
            }
            Ok(())
        },
    );

    let worker = match worker {
        Ok(worker) => worker,
        Err(err) => {
            let message = format!("Failed to start customer data deletion task: {err}");
            mark_job_failed(&db, customer_id, message.clone())?;
            return Err(anyhow!(message));
        }
    };

    tokio::spawn(supervise_worker(worker, db, customer_id));
    Ok(())
}

async fn supervise_worker(
    worker: tokio::task::JoinHandle<std::result::Result<(), crate::cancellation::CancelledError>>,
    db: Database,
    customer_id: u32,
) {
    match worker.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            let message = format!("Customer data deletion task terminated unexpectedly: {err}");
            if let Err(update_err) = mark_job_failed(&db, customer_id, message) {
                error!(
                    customer_id,
                    "Failed to record unexpected customer deletion termination: {update_err:#}"
                );
            }
        }
        Err(err) => {
            let message = format!("Customer data deletion task join failure: {err}");
            if let Err(update_err) = mark_job_failed(&db, customer_id, message) {
                error!(
                    customer_id,
                    "Failed to record customer deletion task join failure: {update_err:#}"
                );
            }
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
        delete_customer_data_with, start_customer_deletion_worker, supervise_worker,
        validate_service_fqdn_list,
    };
    use crate::{
        cancellation::{CancelledError, TaskTracker},
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
        for _ in 0..100 {
            let job = db
                .customer_deletion_job_store()
                .unwrap()
                .get(customer_id)
                .unwrap()
                .unwrap();
            if job.status != CustomerDataDeletionStatus::InProgress {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("customer deletion job did not finish");
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
            "{deleteCustomerData: NO_LOCAL_TARGET}"
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
            |cf, _| {
                if cf == "http" {
                    anyhow::bail!("injected event deletion failure");
                }
                Ok(())
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
    async fn startup_and_unexpected_task_failures_are_persisted() {
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
        let tracker = TaskTracker::new();
        tracker.close().unwrap();
        let error = start_customer_deletion_worker(
            &tracker,
            db.clone(),
            1,
            vec!["piglet.node1.example.test".to_string()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("Failed to start"));
        let failed = store.get(1).unwrap().unwrap();
        assert_eq!(failed.status, CustomerDataDeletionStatus::Failed);
        assert!(failed.completed_at.is_some());
        assert!(
            failed
                .error
                .as_deref()
                .is_some_and(|message| message.contains("Failed to start"))
        );

        store.create(2, &make_job()).unwrap();
        let panicking_worker = tokio::spawn(async {
            panic!("injected worker panic");
            #[allow(unreachable_code)]
            Ok::<(), CancelledError>(())
        });
        supervise_worker(panicking_worker, db.clone(), 2).await;
        let failed = store.get(2).unwrap().unwrap();
        assert_eq!(failed.status, CustomerDataDeletionStatus::Failed);
        assert!(failed.completed_at.is_some());
        assert!(
            failed
                .error
                .as_deref()
                .is_some_and(|message| message.contains("join failure"))
        );
    }
}
