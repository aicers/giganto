#[cfg(feature = "bootroot")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "bootroot")]
use anyhow::{Result as AnyhowResult, anyhow};
use async_graphql::{Context, Enum, Object, Result, SimpleObject};
#[cfg(feature = "bootroot")]
use tokio::task::JoinHandle;
#[cfg(feature = "bootroot")]
use tracing::error;

use super::{StringNumberI64, StringNumberU64};
use crate::storage::CustomerDeletionJobStatus;
#[cfg(feature = "bootroot")]
use crate::{
    datetime::DateTime,
    storage::{CustomerDeletionJob, Database},
};

#[cfg(feature = "bootroot")]
static LAST_JOB_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(name = "CustomerDataDeletionJobStatus")]
enum CustomerDataDeletionJobStatusOutput {
    InProgress,
    Succeeded,
    Failed,
}

impl From<CustomerDeletionJobStatus> for CustomerDataDeletionJobStatusOutput {
    fn from(status: CustomerDeletionJobStatus) -> Self {
        match status {
            CustomerDeletionJobStatus::InProgress => Self::InProgress,
            CustomerDeletionJobStatus::Succeeded => Self::Succeeded,
            CustomerDeletionJobStatus::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct CustomerDataDeletionRequestStatus {
    job_id: StringNumberU64,
    status: CustomerDataDeletionJobStatusOutput,
}

#[derive(Default)]
pub(super) struct CustomerDeletionMutation;

#[Object]
impl CustomerDeletionMutation {
    /// Accepts an asynchronous request to delete one customer's Piglet and
    /// Reproduce data. This operation is available only in bootroot builds.
    #[allow(clippy::unused_async)]
    async fn delete_customer_data(
        &self,
        ctx: &Context<'_>,
        host_fqdn: String,
        requested_at: StringNumberI64,
    ) -> Result<CustomerDataDeletionRequestStatus> {
        validate_request(&host_fqdn, requested_at.0)?;

        #[cfg(not(feature = "bootroot"))]
        {
            let _ = ctx;
            Err("deleteCustomerData is available only in bootroot builds".into())
        }

        #[cfg(feature = "bootroot")]
        {
            let db = ctx.data::<Database>()?.clone();
            let job_id = next_job_id(&db)?;
            let job =
                CustomerDeletionJob::in_progress(job_id, host_fqdn, requested_at.0, now_nanos());

            // The durable InProgress record must exist before any worker can
            // begin deleting data.
            db.customer_deletion_jobs()?.create(&job)?;
            spawn_customer_deletion_worker(db, job_id);

            Ok(CustomerDataDeletionRequestStatus {
                job_id: StringNumberU64(job_id),
                status: CustomerDataDeletionJobStatusOutput::InProgress,
            })
        }
    }
}

fn validate_request(host_fqdn: &str, requested_at: i64) -> Result<()> {
    if host_fqdn.trim().is_empty() {
        return Err("hostFqdn must not be empty or whitespace-only".into());
    }
    let labels: Vec<_> = host_fqdn.split('.').collect();
    if labels.len() < 2 {
        return Err("hostFqdn must contain at least two labels".into());
    }
    if labels.contains(&"") {
        return Err("hostFqdn must not contain empty labels".into());
    }
    if requested_at < 0 {
        return Err("requestedAt must not be negative".into());
    }
    Ok(())
}

#[cfg(feature = "bootroot")]
fn next_job_id(db: &Database) -> AnyhowResult<u64> {
    loop {
        let clock = u64::try_from(now_nanos()).unwrap_or_default();
        let previous = LAST_JOB_ID.load(Ordering::Relaxed);
        let candidate = clock.max(previous.saturating_add(1));
        if LAST_JOB_ID
            .compare_exchange(previous, candidate, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        if db.customer_deletion_jobs()?.get(candidate)?.is_none() {
            return Ok(candidate);
        }
    }
}

#[cfg(feature = "bootroot")]
fn now_nanos() -> i64 {
    DateTime::now().timestamp_nanos_opt().unwrap_or(i64::MAX)
}

#[cfg(feature = "bootroot")]
fn spawn_customer_deletion_worker(db: Database, job_id: u64) {
    let worker_db = db.clone();
    let worker = tokio::task::spawn_blocking(move || {
        finish_customer_deletion_job(&worker_db, job_id, |database| {
            database.delete_customer_data(
                &database
                    .customer_deletion_jobs()?
                    .get(job_id)?
                    .ok_or_else(|| anyhow!("customer deletion job {job_id} does not exist"))?
                    .host_fqdn,
            )
        })
    });
    spawn_supervisor(db, job_id, worker);
}

#[cfg(feature = "bootroot")]
fn finish_customer_deletion_job<F>(db: &Database, job_id: u64, delete: F) -> AnyhowResult<()>
where
    F: FnOnce(&Database) -> AnyhowResult<()>,
{
    match delete(db) {
        Ok(()) => {
            db.customer_deletion_jobs()?
                .mark_succeeded(job_id, now_nanos())?;
        }
        Err(deletion_error) => {
            db.customer_deletion_jobs()?.mark_failed(
                job_id,
                now_nanos(),
                format!("customer data deletion failed: {deletion_error:#}"),
            )?;
        }
    }
    Ok(())
}

#[cfg(feature = "bootroot")]
fn spawn_supervisor(
    db: Database,
    job_id: u64,
    worker: JoinHandle<AnyhowResult<()>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let unexpected_error = match worker.await {
            Ok(Ok(())) => return,
            Ok(Err(worker_error)) => format!("worker terminated unexpectedly: {worker_error:#}"),
            Err(join_error) => format!("worker terminated unexpectedly: {join_error}"),
        };

        error!("Customer data deletion job {job_id}: {unexpected_error}");
        let store = match db.customer_deletion_jobs() {
            Ok(store) => store,
            Err(store_error) => {
                error!("Failed to access customer deletion job {job_id}: {store_error:#}");
                return;
            }
        };
        if store.get(job_id).is_ok_and(|job| {
            job.is_some_and(|job| job.status == CustomerDeletionJobStatus::InProgress)
        }) && let Err(update_error) = store.mark_failed(job_id, now_nanos(), unexpected_error)
        {
            error!("Failed to mark customer deletion job {job_id} as failed: {update_error:#}");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::validate_request;
    #[cfg(feature = "bootroot")]
    use super::{finish_customer_deletion_job, spawn_supervisor};
    use crate::graphql::tests::TestSchema;
    #[cfg(feature = "bootroot")]
    use crate::storage::{CustomerDeletionJob, CustomerDeletionJobStatus, Database, DbOptions};

    #[test]
    fn validates_host_fqdn_and_requested_at_without_normalizing() {
        for invalid in [
            "",
            "   ",
            "localhost",
            ".example.com",
            "host..com",
            "host.com.",
        ] {
            assert!(validate_request(invalid, 0).is_err(), "{invalid:?}");
        }
        assert!(validate_request("Host.Example", 0).is_ok());
        assert!(validate_request(" host.example ", 0).is_ok());
        assert!(validate_request("host.example", -1).is_err());
    }

    #[tokio::test]
    async fn graphql_mutation_rejects_invalid_inputs() {
        let schema = TestSchema::new();
        for (host_fqdn, requested_at) in [
            ("", "0"),
            ("   ", "0"),
            ("localhost", "0"),
            (".example.com", "0"),
            ("host..com", "0"),
            ("host.com.", "0"),
            ("host.example", "-1"),
        ] {
            let response = schema
                .schema
                .execute(format!(
                    r"
                    mutation {{
                        deleteCustomerData(
                            hostFqdn: {host_fqdn:?}
                            requestedAt: {requested_at:?}
                        ) {{
                            jobId
                        }}
                    }}
                    "
                ))
                .await;
            assert!(!response.errors.is_empty(), "{host_fqdn:?}, {requested_at}");
        }
    }

    #[cfg(feature = "bootroot")]
    #[test]
    fn deletion_failure_marks_job_failed_with_completion_information() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        db.customer_deletion_jobs()
            .unwrap()
            .create(&CustomerDeletionJob::in_progress(
                1,
                "failure.example".to_string(),
                10,
                20,
            ))
            .unwrap();

        finish_customer_deletion_job(&db, 1, |_| anyhow::bail!("injected failure")).unwrap();
        let job = db
            .customer_deletion_jobs()
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap();
        assert_eq!(job.status, CustomerDeletionJobStatus::Failed);
        assert!(job.completed_at.is_some());
        assert!(
            job.error_message
                .as_deref()
                .is_some_and(|message| message.contains("injected failure"))
        );
    }

    #[cfg(feature = "bootroot")]
    #[tokio::test]
    async fn unexpected_worker_termination_marks_job_failed() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        db.customer_deletion_jobs()
            .unwrap()
            .create(&CustomerDeletionJob::in_progress(
                2,
                "panic.example".to_string(),
                10,
                20,
            ))
            .unwrap();

        let worker = tokio::spawn(async {
            panic!("injected panic");
            #[allow(unreachable_code)]
            Ok(())
        });
        spawn_supervisor(db.clone(), 2, worker).await.unwrap();

        let job = db
            .customer_deletion_jobs()
            .unwrap()
            .get(2)
            .unwrap()
            .unwrap();
        assert_eq!(job.status, CustomerDeletionJobStatus::Failed);
        assert!(job.completed_at.is_some());
        assert!(
            job.error_message
                .as_deref()
                .is_some_and(|message| message.contains("worker terminated unexpectedly"))
        );
    }

    #[cfg(feature = "bootroot")]
    #[tokio::test]
    async fn graphql_mutation_persists_job_before_accepting_request() {
        let schema = TestSchema::new();
        let response = schema
            .schema
            .execute(
                r#"
                mutation {
                    deleteCustomerData(
                        hostFqdn: "CaseSensitive.Example"
                        requestedAt: "123"
                    ) {
                        jobId
                        status
                    }
                }
                "#,
            )
            .await;
        assert!(
            response.errors.is_empty(),
            "GraphQL errors: {:?}",
            response.errors
        );
        let data = response.data.into_json().unwrap();
        assert_eq!(
            data["deleteCustomerData"]["status"].as_str(),
            Some("IN_PROGRESS")
        );
        let job_id = data["deleteCustomerData"]["jobId"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let mut job = schema
            .db
            .customer_deletion_jobs()
            .unwrap()
            .get(job_id)
            .unwrap()
            .unwrap();
        for _ in 0..100 {
            if job.status != CustomerDeletionJobStatus::InProgress {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            job = schema
                .db
                .customer_deletion_jobs()
                .unwrap()
                .get(job_id)
                .unwrap()
                .unwrap();
        }
        assert_eq!(job.host_fqdn, "CaseSensitive.Example");
        assert_eq!(job.requested_at, 123);
        assert_eq!(job.status, CustomerDeletionJobStatus::Succeeded);
        assert!(job.completed_at.is_some());
        assert!(job.error_message.is_none());
    }
}
