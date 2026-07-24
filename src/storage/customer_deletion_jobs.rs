//! Versioned metadata records for customer-data deletion jobs.
//!
//! Keys are unsigned job IDs encoded as eight-byte big-endian integers.
//! Values use bincode 1 over [`CustomerDeletionJob`]. The leading
//! `encoding_version` field must be retained when the record evolves.

use anyhow::{Context, Result, bail};
use rocksdb::{ColumnFamily, DB, IteratorMode};
use serde::{Deserialize, Serialize};

const ENCODING_VERSION: u8 = 1;
const STARTUP_RECOVERY_ERROR: &str =
    "Giganto restarted while the customer data deletion job was in progress";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CustomerDeletionJobStatus {
    InProgress,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustomerDeletionJob {
    encoding_version: u8,
    pub job_id: u64,
    pub host_fqdn: String,
    pub requested_at: i64,
    pub status: CustomerDeletionJobStatus,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub error_message: Option<String>,
}

impl CustomerDeletionJob {
    #[must_use]
    #[cfg(any(test, feature = "bootroot"))]
    pub fn in_progress(job_id: u64, host_fqdn: String, requested_at: i64, started_at: i64) -> Self {
        Self {
            encoding_version: ENCODING_VERSION,
            job_id,
            host_fqdn,
            requested_at,
            status: CustomerDeletionJobStatus::InProgress,
            started_at: Some(started_at),
            completed_at: None,
            error_message: None,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.encoding_version != ENCODING_VERSION {
            bail!(
                "unsupported customer deletion job encoding version {}",
                self.encoding_version
            );
        }
        match self.status {
            CustomerDeletionJobStatus::InProgress => {
                if self.completed_at.is_some() || self.error_message.is_some() {
                    bail!("an in-progress job cannot have completion information");
                }
            }
            CustomerDeletionJobStatus::Succeeded => {
                if self.completed_at.is_none() || self.error_message.is_some() {
                    bail!("a succeeded job requires completed_at and no error");
                }
            }
            CustomerDeletionJobStatus::Failed => {
                if self.completed_at.is_none()
                    || self.error_message.as_ref().is_none_or(String::is_empty)
                {
                    bail!("a failed job requires completed_at and a non-empty error");
                }
            }
        }
        Ok(())
    }
}

pub struct CustomerDeletionJobStore<'db> {
    db: &'db DB,
    cf: &'db ColumnFamily,
}

impl<'db> CustomerDeletionJobStore<'db> {
    pub(super) fn new(db: &'db DB, cf: &'db ColumnFamily) -> Self {
        Self { db, cf }
    }

    #[cfg(any(test, feature = "bootroot"))]
    pub fn create(&self, job: &CustomerDeletionJob) -> Result<()> {
        job.validate()?;
        let key = encode_job_key(job.job_id);
        if self.db.get_cf(self.cf, key)?.is_some() {
            bail!("customer deletion job {} already exists", job.job_id);
        }
        self.put(job)
    }

    pub fn get(&self, job_id: u64) -> Result<Option<CustomerDeletionJob>> {
        self.db
            .get_cf(self.cf, encode_job_key(job_id))?
            .map(|value| decode_job(&value))
            .transpose()
    }

    #[cfg(any(test, feature = "bootroot"))]
    pub fn mark_succeeded(&self, job_id: u64, completed_at: i64) -> Result<CustomerDeletionJob> {
        self.transition(job_id, completed_at, None)
    }

    pub fn mark_failed(
        &self,
        job_id: u64,
        completed_at: i64,
        error_message: String,
    ) -> Result<CustomerDeletionJob> {
        if error_message.is_empty() {
            bail!("failure error message cannot be empty");
        }
        self.transition(job_id, completed_at, Some(error_message))
    }

    pub fn fail_in_progress_jobs(&self, completed_at: i64) -> Result<usize> {
        let mut jobs = Vec::new();
        for item in self.db.iterator_cf(self.cf, IteratorMode::Start) {
            let (_key, value) = item.context("failed to scan customer deletion jobs")?;
            let job = decode_job(&value)?;
            if job.status == CustomerDeletionJobStatus::InProgress {
                jobs.push(job.job_id);
            }
        }

        for job_id in &jobs {
            self.mark_failed(*job_id, completed_at, STARTUP_RECOVERY_ERROR.to_string())?;
        }
        Ok(jobs.len())
    }

    fn transition(
        &self,
        job_id: u64,
        completed_at: i64,
        error_message: Option<String>,
    ) -> Result<CustomerDeletionJob> {
        let mut job = self
            .get(job_id)?
            .with_context(|| format!("customer deletion job {job_id} does not exist"))?;
        if job.status != CustomerDeletionJobStatus::InProgress {
            bail!("customer deletion job {job_id} is already complete");
        }

        job.status = if error_message.is_some() {
            CustomerDeletionJobStatus::Failed
        } else {
            CustomerDeletionJobStatus::Succeeded
        };
        job.completed_at = Some(completed_at);
        job.error_message = error_message;
        self.put(&job)?;
        Ok(job)
    }

    fn put(&self, job: &CustomerDeletionJob) -> Result<()> {
        job.validate()?;
        let value = bincode::serialize(job).context("failed to serialize customer deletion job")?;
        self.db.put_cf(self.cf, encode_job_key(job.job_id), value)?;
        self.db.flush_wal(true)?;
        Ok(())
    }
}

fn encode_job_key(job_id: u64) -> [u8; 8] {
    job_id.to_be_bytes()
}

fn decode_job(value: &[u8]) -> Result<CustomerDeletionJob> {
    let job: CustomerDeletionJob =
        bincode::deserialize(value).context("failed to deserialize customer deletion job")?;
    job.validate()?;
    Ok(job)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_key_encoding_round_trip_is_stable_and_ordered() {
        for job_id in [0, 1, u64::from(u32::MAX), u64::MAX] {
            assert_eq!(u64::from_be_bytes(encode_job_key(job_id)), job_id);
        }
        assert!(encode_job_key(1) < encode_job_key(2));
    }

    #[test]
    fn job_value_serialization_round_trip() {
        let job = CustomerDeletionJob::in_progress(42, "Host.Example".to_string(), 123, 456);
        let encoded = bincode::serialize(&job).unwrap();
        assert_eq!(decode_job(&encoded).unwrap(), job);
    }
}
