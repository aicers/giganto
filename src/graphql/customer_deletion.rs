use std::{borrow::Cow, collections::HashSet, future, sync::Arc};

use anyhow::{Context as AnyhowContext, Result as AnyhowResult, anyhow};
use async_graphql::{
    Context, ContextSelectionSet, Object, OutputType, Positioned, Result, ServerResult, Value,
    indexmap::IndexMap,
    parser::types::Field,
    registry::{Deprecation, MetaEnumValue, MetaType, MetaTypeId, Registry},
    resolver_utils::{EnumItem, EnumType},
};
use tokio::sync::Notify;
use tracing::{error, info, warn};

use super::StringNumberU32;
use crate::{
    cancellation::{SpawnError, TaskTracker},
    comm::{
        IngestSensors, PcapSensors, RunTimeIngestSensors, StreamDirectChannels,
        stream_channel_key::StreamChannelKey,
    },
    datetime::DateTime,
    storage::{
        CustomerDataDeletion, CustomerDataDeletionStatus, CustomerDeletionJobStore, Database,
        deletion_coordination::{CustomerDeletionCoordinator, DeletionBlocked, DeletionGuard},
    },
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
pub(super) struct CustomerDeletionMutation;

#[Object]
impl CustomerDeletionMutation {
    /// Starts asynchronous deletion of customer-owned data stored on this Giganto node.
    // Kept to one line above, because async-graphql publishes a resolver's doc
    // comment as the field's GraphQL description; the rest belongs here.
    //
    // Three of the seven responses are refusals this node decides on before it
    // writes anything, and all three are read off state rather than guessed at:
    // the generation's `TaskTracker` says whether shutdown has begun, and the
    // `CustomerDeletionCoordinator` says whether retention or another
    // customer's deletion owns the store. A refused request leaves the job
    // store exactly as it found it.
    //
    // None of the three is reached by a node that holds neither a job for this
    // customer nor a sensor named in the request. Such a node would have
    // nothing to do even with the store to itself, so #1675 has it answer
    // `NO_LOCAL_TARGET_ON_THIS_NODE` ahead of the maintenance state: telling a
    // caller to retry after shutdown or after retention would send it back for
    // an answer that can never change.
    async fn delete_customer_data(
        &self,
        ctx: &Context<'_>,
        service_fqdn_list: Vec<String>,
        customer_id: StringNumberU32,
    ) -> Result<CustomerDataDeletionRequestStatus> {
        let provided_targets = validate_service_fqdn_list(service_fqdn_list)?;
        let db = ctx.data::<Database>()?.clone();
        let ingest_sensors = ctx.data::<IngestSensors>()?.clone();
        let runtime_ingest_sensors = ctx.data::<RunTimeIngestSensors>()?.clone();
        let pcap_sensors = ctx.data::<PcapSensors>()?.clone();
        let stream_direct_channels = ctx.data::<StreamDirectChannels>()?.clone();
        let peer_notify = ctx.data_opt::<Arc<Notify>>().cloned();
        let tracker = ctx.data::<TaskTracker>()?.clone();
        let coordination = ctx.data::<Arc<CustomerDeletionCoordinator>>()?;

        let store = db.customer_deletion_job_store()?;
        // Asked first, and asked without claiming anything: a node with no
        // stake in the request answers it instead of refusing it, and a
        // refusal it never needed must not make a retention cycle give way or
        // turn another customer away.
        if store.get(customer_id.0)?.is_none()
            && local_targets(&provided_targets, &ingest_sensors)
                .await
                .is_empty()
        {
            return Ok(CustomerDataDeletionRequestStatus::NoLocalTargetOnThisNode);
        }

        // Asked before anything is written. The tracker is closed for the
        // whole of shutdown, so a request that arrives after it began can
        // never be finished here, and accepting one would leave an
        // `InProgress` job behind that nothing in this generation will ever
        // resolve.
        if tracker.is_closed() {
            return Ok(CustomerDataDeletionRequestStatus::BlockedByShutdown);
        }

        // The claim on the store, and the only serialization this resolver
        // needs: it is taken without awaiting, two concurrent requests cannot
        // both hold it, and dropping the guard on any path below — including
        // every early return between here and the registration — releases it.
        let deletion_guard = match coordination.begin_deletion(customer_id.0) {
            Ok(guard) => guard,
            Err(DeletionBlocked::SameCustomer) => {
                return Ok(CustomerDataDeletionRequestStatus::DeletionInProgress);
            }
            Err(DeletionBlocked::AnotherDeletion) => {
                return Ok(CustomerDataDeletionRequestStatus::BlockedByAnotherDeletion);
            }
            Err(DeletionBlocked::Retention) => {
                return Ok(CustomerDataDeletionRequestStatus::BlockedByRetention);
            }
        };

        // Read again rather than reused from the check above: that read
        // answered a question no claim was needed for, and the job store can
        // have moved on between the two. This one is taken under the claim,
        // which is what makes it the state the request acts on — without it a
        // request that saw no job before waiting for the sensor list could
        // overwrite a deletion that succeeded while it waited.
        //
        // Kept whole rather than consumed: it is both what this request reads
        // its decision off and what the job store is put back to if the
        // registration below loses a race with shutdown.
        let previous_job = store.get(customer_id.0)?;
        let local_targets = if let Some(job) = &previous_job {
            match job.status {
                // Not the coordinator's answer but the store's: a job left
                // `InProgress` by a generation that ended mid-deletion outlives
                // the claim that was taken for it. Recovering from that is
                // #1725; until then it is reported as still running.
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
                    job.service_fqdn_list.clone()
                }
            }
        } else {
            let targets = local_targets(&provided_targets, &ingest_sensors).await;
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
        if previous_job.is_some() {
            store.update(customer_id.0, &in_progress)?;
        } else {
            store.create(customer_id.0, &in_progress)?;
        }

        if let Err(e) = start_customer_deletion_worker(
            &tracker,
            deletion_guard,
            db.clone(),
            customer_id.0,
            in_progress.service_fqdn_list,
            ingest_sensors,
            runtime_ingest_sensors,
            pcap_sensors,
            stream_direct_channels,
            peer_notify,
        ) {
            return refuse_registration(&e, customer_id.0, || {
                restore_previous_job(&store, customer_id.0, previous_job.as_ref())
            });
        }
        Ok(CustomerDataDeletionRequestStatus::Accepted)
    }
}

/// The service FQDNs of `provided` this node ingests, in the order given.
///
/// Only a first request resolves its targets this way. A `Failed` retry uses
/// the list stored with the job instead, because an earlier attempt that
/// partly succeeded may already have removed the sensors it deleted.
async fn local_targets(provided: &[String], ingest_sensors: &IngestSensors) -> Vec<String> {
    let local_sensors = ingest_sensors.read().await;
    provided
        .iter()
        .filter(|target| local_sensors.contains(*target))
        .cloned()
        .collect()
}

/// Answers a request whose registration the shutdown tracker refused.
///
/// Reported rather than answered silently, because this is the one refusal the
/// request had already been written into the job store for, and because the
/// reason carries more than the response does: `Closed` is the shutdown this
/// node expected to lose the race to, while `LockPoisoned` is a tracker that
/// will admit nothing again for the rest of the generation.
///
/// `undo` puts the job store back the way the request found it, and only a
/// request that leaves it that way is a refusal. When the undo fails the job
/// just written stays `InProgress` with no worker registered to finish it —
/// the very thing the refusal exists to prevent, and, until #1725 recovers
/// such a job at startup, the answer to every later request for this customer.
/// That is a failure of the mutation, not a `BLOCKED_BY_SHUTDOWN` the caller
/// could act on, so it is raised as an error.
///
/// # Errors
///
/// Returns an error if `undo` fails.
fn refuse_registration(
    spawn_error: &SpawnError,
    customer_id: u32,
    undo: impl FnOnce() -> AnyhowResult<()>,
) -> Result<CustomerDataDeletionRequestStatus> {
    warn!(
        customer_id,
        "Refusing an accepted customer data deletion: the shutdown tracker would not admit it: {spawn_error}"
    );
    if let Err(e) = undo() {
        error!(
            customer_id,
            "Failed to undo the customer deletion job a shutdown refused: {e:#}"
        );
        return Err(format!(
            "Shutdown refused the deletion for customer {customer_id}, and the job record written \
             for it could not be undone: {e:#}. The job is left in progress with nothing running \
             it, and requests for this customer will report DELETION_IN_PROGRESS until it is \
             recovered."
        )
        .into());
    }
    Ok(CustomerDataDeletionRequestStatus::BlockedByShutdown)
}

/// Puts the job store back the way a refused request found it.
///
/// A first request wrote a job where there was none, so the job goes; a retry
/// overwrote the `Failed` job it was retrying, so that job comes back
/// unchanged — error text, completion time and all. Either way the customer is
/// left able to ask again, on this node once it restarts or on another one now.
///
/// # Errors
///
/// Returns an error if the job store cannot be written.
fn restore_previous_job(
    store: &CustomerDeletionJobStore<'_>,
    customer_id: u32,
    previous_job: Option<&CustomerDataDeletion>,
) -> AnyhowResult<()> {
    match previous_job {
        Some(job) => store.update(customer_id, job),
        None => store.delete(customer_id),
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

/// Registers an accepted deletion on the generation's tracker and starts it.
///
/// Registration is what ties the deletion to shutdown. The supervisor awaits
/// the blocking worker, so a drain that waits for the supervisor waits for the
/// RocksDB range deletes too, and the generation cannot reach
/// `database.shutdown()` with a deletion still running. That is the only gate:
/// there is no deletion-specific close path.
///
/// The cancellation token is ignored on purpose. An accepted deletion is a
/// commitment recorded in the job store, and abandoning it halfway would leave
/// a customer's data partly deleted with nothing to say so — the opposite of
/// what the drain is for.
///
/// # Errors
///
/// Returns [`SpawnError`] when the tracker refuses the registration, which is
/// what a request racing the start of shutdown gets. `deletion_guard` and
/// every clone this takes then travel into a future that is dropped without
/// ever being polled, so nothing was started and the store claim is released.
/// That is also why the blocking worker is spawned inside the future rather
/// than built here: a worker built in this factory would outlive the
/// registration that was refused.
#[allow(clippy::too_many_arguments)]
fn start_customer_deletion_worker(
    tracker: &TaskTracker,
    deletion_guard: DeletionGuard,
    db: Database,
    customer_id: u32,
    service_fqdn_list: Vec<String>,
    ingest_sensors: IngestSensors,
    runtime_ingest_sensors: RunTimeIngestSensors,
    pcap_sensors: PcapSensors,
    stream_direct_channels: StreamDirectChannels,
    peer_notify: Option<Arc<Notify>>,
) -> Result<(), SpawnError> {
    let _handle = tracker.spawn("customer-deletion", move |_cancel| async move {
        // Held for the whole deletion and dropped with this future, so every
        // way it can end — success, failure, a panic in the supervisor, or a
        // registration that was refused — releases the store.
        let _deletion_guard = deletion_guard;
        let worker = tokio::task::spawn_blocking({
            let db = db.clone();
            let targets = service_fqdn_list.clone();
            move || delete_customer_data_from_db(&db, &targets)
        });

        supervise_worker(
            worker,
            db,
            customer_id,
            service_fqdn_list,
            ingest_sensors,
            runtime_ingest_sensors,
            pcap_sensors,
            stream_direct_channels,
            peer_notify,
        )
        .await;
    })?;
    Ok(())
}

async fn cleanup_runtime_for_targets(
    targets: &[String],
    ingest_sensors: &IngestSensors,
    runtime_ingest_sensors: &RunTimeIngestSensors,
    pcap_sensors: &PcapSensors,
    stream_direct_channels: &StreamDirectChannels,
    peer_notify: Option<&Arc<Notify>>,
) {
    info!(
        target_count = targets.len(),
        "Cleaning customer runtime state"
    );

    {
        let mut ingest_sensors = ingest_sensors.write().await;
        for target in targets {
            ingest_sensors.remove(target);
        }
    }

    {
        let mut runtime_ingest_sensors = runtime_ingest_sensors.write().await;
        for target in targets {
            runtime_ingest_sensors.remove(target);
        }
    }

    {
        let mut pcap_sensors = pcap_sensors.write().await;
        for target in targets {
            pcap_sensors.remove(target);
        }
    }

    let targets = targets.iter().map(String::as_str).collect::<HashSet<_>>();
    stream_direct_channels.write().await.retain(|key, _| {
        let target_sensor = match key {
            StreamChannelKey::SemiSupervised { target_sensor, .. }
            | StreamChannelKey::TimeSeriesGenerator { target_sensor, .. } => target_sensor,
        };
        !targets.contains(target_sensor.as_str())
    });

    if let Some(notify) = peer_notify {
        notify.notify_one();
    }

    info!(
        target_count = targets.len(),
        "Customer runtime state cleaned"
    );
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
/// This runs inside the task [`start_customer_deletion_worker`] registered on
/// the generation's tracker, so the shutdown drain waits for it — and, through
/// the `worker.await` below, for the blocking deletion it supervises.
#[allow(clippy::too_many_arguments)]
async fn supervise_worker(
    worker: tokio::task::JoinHandle<AnyhowResult<()>>,
    db: Database,
    customer_id: u32,
    service_fqdn_list: Vec<String>,
    ingest_sensors: IngestSensors,
    runtime_ingest_sensors: RunTimeIngestSensors,
    pcap_sensors: PcapSensors,
    stream_direct_channels: StreamDirectChannels,
    peer_notify: Option<Arc<Notify>>,
) {
    let outcome = match worker.await {
        Ok(Ok(())) => {
            info!(customer_id, "Customer database deletion succeeded");
            cleanup_runtime_for_targets(
                &service_fqdn_list,
                &ingest_sensors,
                &runtime_ingest_sensors,
                &pcap_sensors,
                &stream_direct_channels,
                peer_notify.as_ref(),
            )
            .await;
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
    use std::collections::HashSet;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use giganto_client::publish::stream::{RequestStreamRecord, STREAM_REQUEST_ALL_SENSOR};
    use tokio::sync::Notify;

    use anyhow::anyhow;

    use super::{
        CustomerDataDeletionRequestStatus, PIGLET_COLUMN_FAMILIES, REPRODUCE_COLUMN_FAMILIES,
        cleanup_runtime_for_targets, delete_customer_data_from_db, delete_customer_data_with,
        refuse_registration, restore_previous_job, start_customer_deletion_worker,
        supervise_worker, validate_service_fqdn_list,
    };
    use crate::{
        cancellation::{SpawnError, TaskTracker},
        comm::{
            IngestSensors, PcapSensors, RunTimeIngestSensors, StreamDirectChannels,
            new_ingest_sensors, new_pcap_sensors, new_runtime_ingest_sensors,
            new_stream_direct_channels, peer::tests::fixtures::SensorListPeerHarness,
            stream_channel_key::StreamChannelKey,
        },
        datetime::DateTime,
        graphql::tests::TestSchema,
        storage::{
            CustomerDataDeletion, CustomerDataDeletionStatus, Database, DbOptions,
            deletion_coordination::CustomerDeletionCoordinator,
        },
    };

    fn delete_customer_data_mutation(targets: &[&str], customer_id: u32) -> String {
        let targets = targets
            .iter()
            .map(|target| format!("\"{target}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"mutation {{
                deleteCustomerData(serviceFqdnList: [{targets}] customerId: "{customer_id}")
            }}"#
        )
    }

    fn job_status(db: &Database, customer_id: u32) -> Option<CustomerDataDeletionStatus> {
        db.customer_deletion_job_store()
            .unwrap()
            .get(customer_id)
            .unwrap()
            .map(|job| job.status)
    }

    type RuntimeState = (
        IngestSensors,
        RunTimeIngestSensors,
        PcapSensors,
        StreamDirectChannels,
    );

    fn runtime_state(db: &Database) -> RuntimeState {
        (
            new_ingest_sensors(db),
            new_runtime_ingest_sensors(),
            new_pcap_sensors(),
            new_stream_direct_channels(),
        )
    }

    async fn supervise_test_worker(
        worker: tokio::task::JoinHandle<anyhow::Result<()>>,
        db: Database,
        customer_id: u32,
        service_fqdn_list: Vec<String>,
        runtime_state: &RuntimeState,
        peer_notify: Option<Arc<Notify>>,
    ) {
        supervise_worker(
            worker,
            db,
            customer_id,
            service_fqdn_list,
            runtime_state.0.clone(),
            runtime_state.1.clone(),
            runtime_state.2.clone(),
            runtime_state.3.clone(),
            peer_notify,
        )
        .await;
    }

    async fn seed_runtime_target(runtime_state: &RuntimeState, target: &str) -> StreamChannelKey {
        runtime_state.0.write().await.insert(target.to_string());
        runtime_state
            .1
            .write()
            .await
            .insert(target.to_string(), DateTime::now());
        runtime_state
            .2
            .write()
            .await
            .insert(target.to_string(), Vec::new());
        let key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "publisher".to_string(),
            target_sensor: target.to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
        runtime_state.3.write().await.insert(key.clone(), sender);
        key
    }

    async fn assert_runtime_target_present(
        runtime_state: &RuntimeState,
        target: &str,
        channel_key: &StreamChannelKey,
    ) {
        assert!(runtime_state.0.read().await.contains(target));
        assert!(runtime_state.1.read().await.contains_key(target));
        assert!(runtime_state.2.read().await.contains_key(target));
        assert!(runtime_state.3.read().await.contains_key(channel_key));
    }

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

    /// A node with neither a job for the customer nor a sensor named in the
    /// request answers `NO_LOCAL_TARGET_ON_THIS_NODE` whatever its store is
    /// busy with.
    ///
    /// The three refusals all mean "ask again later", and later never helps
    /// here: no cycle of retention, no other customer's deletion and no
    /// restart gives this node data it never held. It also claims nothing on
    /// the way to that answer, so a request it has no part in cannot make a
    /// retention cycle give way or turn another customer away.
    #[tokio::test]
    async fn no_local_target_outranks_every_refusal() {
        const REQUESTING: u32 = 800;
        const OTHER: u32 = 801;
        let schema = TestSchema::new_with_ingest_sensors(&[]);
        let query = delete_customer_data_mutation(&["piglet.node1.example.test"], REQUESTING);
        let no_local_target = "{deleteCustomerData: NO_LOCAL_TARGET_ON_THIS_NODE}";

        let retention = schema
            .deletion_coordination
            .begin_retention()
            .expect("nothing has claimed the store yet");
        assert_eq!(schema.execute(&query).await.data.to_string(), no_local_target);
        drop(retention);

        let other_customer = schema
            .deletion_coordination
            .begin_deletion(OTHER)
            .expect("the retention cycle released the store");
        assert_eq!(schema.execute(&query).await.data.to_string(), no_local_target);
        drop(other_customer);

        schema
            .top_level_tracker
            .close()
            .expect("a fresh tracker closes");
        assert_eq!(schema.execute(&query).await.data.to_string(), no_local_target);

        assert_eq!(
            job_status(&schema.db, REQUESTING),
            None,
            "a node with no local target must write no job"
        );
        drop(
            schema
                .deletion_coordination
                .begin_retention()
                .expect("a request answered this way claims nothing"),
        );
    }

    #[tokio::test]
    async fn multiple_runtime_targets_are_cleaned_without_affecting_other_state() {
        let piglet = "piglet.node1.example.test";
        let reproduce = "reproduce.node2.example.test";
        let similar = "piglet.node1.example.test2";
        let unrelated = "piglet.other.example.test";
        let schema = TestSchema::new_with_ingest_sensors(&[piglet, reproduce, similar, unrelated]);

        schema.runtime_ingest_sensors.write().await.extend([
            (piglet.to_string(), DateTime::now()),
            (reproduce.to_string(), DateTime::now()),
            (similar.to_string(), DateTime::now()),
            (unrelated.to_string(), DateTime::now()),
        ]);
        schema.pcap_sensors.write().await.extend([
            (piglet.to_string(), Vec::new()),
            (reproduce.to_string(), Vec::new()),
            (similar.to_string(), Vec::new()),
            (unrelated.to_string(), Vec::new()),
        ]);

        let piglet_key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "publisher".to_string(),
            target_sensor: piglet.to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        let reproduce_key = StreamChannelKey::TimeSeriesGenerator {
            id: "reproduce-generator".to_string(),
            target_sensor: reproduce.to_string(),
            record_type: RequestStreamRecord::Dns,
        };
        let similar_key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "publisher".to_string(),
            target_sensor: similar.to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        let wildcard_key = StreamChannelKey::TimeSeriesGenerator {
            id: "wildcard-generator".to_string(),
            target_sensor: STREAM_REQUEST_ALL_SENSOR.to_string(),
            record_type: RequestStreamRecord::Dns,
        };
        let unrelated_key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "publisher".to_string(),
            target_sensor: unrelated.to_string(),
            record_type: RequestStreamRecord::Conn,
        };
        let mut receivers = Vec::new();
        {
            let mut channels = schema.stream_direct_channels.write().await;
            for key in [
                piglet_key.clone(),
                reproduce_key.clone(),
                similar_key.clone(),
                wildcard_key.clone(),
                unrelated_key.clone(),
            ] {
                let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
                channels.insert(key, sender);
                receivers.push(receiver);
            }
        }

        let response = schema
            .execute(&format!(
                r#"mutation {{
                    deleteCustomerData(
                        serviceFqdnList: ["{piglet}", "{reproduce}"]
                        customerId: "101"
                    )
                }}"#
            ))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let completed = wait_for_terminal_job(&schema.db, 101).await;
        assert_eq!(completed.status, CustomerDataDeletionStatus::Succeeded);

        let ingest_sensors = schema.ingest_sensors.read().await;
        assert!(!ingest_sensors.contains(piglet));
        assert!(!ingest_sensors.contains(reproduce));
        assert!(ingest_sensors.contains(similar));
        assert!(ingest_sensors.contains(unrelated));
        drop(ingest_sensors);

        let runtime_ingest_sensors = schema.runtime_ingest_sensors.read().await;
        assert!(!runtime_ingest_sensors.contains_key(piglet));
        assert!(!runtime_ingest_sensors.contains_key(reproduce));
        assert!(runtime_ingest_sensors.contains_key(similar));
        assert!(runtime_ingest_sensors.contains_key(unrelated));
        drop(runtime_ingest_sensors);

        let pcap_sensors = schema.pcap_sensors.read().await;
        assert!(!pcap_sensors.contains_key(piglet));
        assert!(!pcap_sensors.contains_key(reproduce));
        assert!(pcap_sensors.contains_key(similar));
        assert!(pcap_sensors.contains_key(unrelated));
        drop(pcap_sensors);

        let channels = schema.stream_direct_channels.read().await;
        assert!(!channels.contains_key(&piglet_key));
        assert!(!channels.contains_key(&reproduce_key));
        assert!(channels.contains_key(&similar_key));
        assert!(channels.contains_key(&wildcard_key));
        assert!(channels.contains_key(&unrelated_key));
    }

    #[tokio::test]
    async fn peer_propagation_happens_when_configured_and_is_optional() {
        let target = "piglet.node1.example.test";
        let peer_notify = Arc::new(Notify::new());
        let schema = TestSchema::new_with_ingest_sensors_and_peer_notify(
            &[target],
            Some(peer_notify.clone()),
        );

        let response = schema
            .execute(&format!(
                r#"mutation {{
                    deleteCustomerData(serviceFqdnList: ["{target}"] customerId: "102")
                }}"#
            ))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let completed = wait_for_terminal_job(&schema.db, 102).await;
        assert_eq!(completed.status, CustomerDataDeletionStatus::Succeeded);
        tokio::time::timeout(Duration::from_secs(1), peer_notify.notified())
            .await
            .expect("peer sensor-list notification was not sent");
        drop(schema);

        let without_peers = TestSchema::new_with_ingest_sensors(&[target]);
        let response = without_peers
            .execute(&format!(
                r#"mutation {{
                    deleteCustomerData(serviceFqdnList: ["{target}"] customerId: "103")
                }}"#
            ))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let completed = wait_for_terminal_job(&without_peers.db, 103).await;
        assert_eq!(completed.status, CustomerDataDeletionStatus::Succeeded);
    }

    #[tokio::test]
    async fn peer_receives_sensor_list_after_customer_target_is_removed() {
        let target = "piglet.node1.example.test";
        let unrelated = "reproduce.other.example.test";
        let ingest_sensors = Arc::new(tokio::sync::RwLock::new(HashSet::from([
            target.to_string(),
            unrelated.to_string(),
        ])));
        let peer_notify = Arc::new(Notify::new());
        let schema = TestSchema::new_with_shared_ingest_sensors_and_peer_notify(
            ingest_sensors.clone(),
            Some(peer_notify.clone()),
        );
        let (peer, initial_sensor_list) =
            SensorListPeerHarness::start(ingest_sensors, peer_notify).await;
        assert_eq!(
            initial_sensor_list,
            HashSet::from([target.to_string(), unrelated.to_string()])
        );

        let response = schema
            .execute(&format!(
                r#"mutation {{
                    deleteCustomerData(serviceFqdnList: ["{target}"] customerId: "104")
                }}"#
            ))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let completed = wait_for_terminal_job(&schema.db, 104).await;
        assert_eq!(completed.status, CustomerDataDeletionStatus::Succeeded);

        assert_eq!(
            peer.receive_sensor_list().await,
            HashSet::from([unrelated.to_string()])
        );
        peer.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_cleanup_is_idempotent() {
        let target = "piglet.node1.example.test".to_string();
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        let (ingest_sensors, runtime_ingest_sensors, pcap_sensors, stream_direct_channels) =
            runtime_state(&db);
        ingest_sensors.write().await.insert(target.clone());
        runtime_ingest_sensors
            .write()
            .await
            .insert(target.clone(), DateTime::now());
        pcap_sensors
            .write()
            .await
            .insert(target.clone(), Vec::new());
        let exact_key = StreamChannelKey::SemiSupervised {
            publisher_sensor: "publisher".to_string(),
            target_sensor: target.clone(),
            record_type: RequestStreamRecord::Conn,
        };
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
        stream_direct_channels
            .write()
            .await
            .insert(exact_key.clone(), sender);

        for _ in 0..2 {
            cleanup_runtime_for_targets(
                std::slice::from_ref(&target),
                &ingest_sensors,
                &runtime_ingest_sensors,
                &pcap_sensors,
                &stream_direct_channels,
                None,
            )
            .await;
        }

        assert!(!ingest_sensors.read().await.contains(&target));
        assert!(!runtime_ingest_sensors.read().await.contains_key(&target));
        assert!(!pcap_sensors.read().await.contains_key(&target));
        assert!(!stream_direct_channels.read().await.contains_key(&exact_key));
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
    async fn worker_panic_preserves_runtime_state_and_skips_peer_notification() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        let target = "piglet.node1.example.test";
        let make_job = || CustomerDataDeletion {
            service_fqdn_list: vec![target.to_string()],
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
        let runtime_state = runtime_state(&db);
        let channel_key = seed_runtime_target(&runtime_state, target).await;
        let peer_notify = Arc::new(Notify::new());
        supervise_test_worker(
            panicking_worker,
            db.clone(),
            1,
            vec![target.to_string()],
            &runtime_state,
            Some(peer_notify.clone()),
        )
        .await;
        let failed = store.get(1).unwrap().unwrap();
        assert_eq!(failed.status, CustomerDataDeletionStatus::Failed);
        assert!(failed.completed_at.is_some());
        assert!(
            failed
                .error
                .as_deref()
                .is_some_and(|message| message.contains("join failure"))
        );
        assert_runtime_target_present(&runtime_state, target, &channel_key).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), peer_notify.notified())
                .await
                .is_err(),
            "peer notification must not fire after a worker panic"
        );
    }

    #[tokio::test]
    async fn database_deletion_failure_preserves_runtime_state_and_skips_peer_notification() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        let target = "reproduce.node1.example.test";
        let job = CustomerDataDeletion {
            service_fqdn_list: vec![target.to_string()],
            requested_at: 1,
            status: CustomerDataDeletionStatus::InProgress,
            completed_at: None,
            error: None,
        };
        let store = db.customer_deletion_job_store().unwrap();
        store.create(2, &job).unwrap();
        let runtime_state = runtime_state(&db);
        let channel_key = seed_runtime_target(&runtime_state, target).await;
        let peer_notify = Arc::new(Notify::new());
        let worker =
            tokio::task::spawn_blocking(|| anyhow::bail!("injected RocksDB deletion failure"));

        supervise_test_worker(
            worker,
            db.clone(),
            2,
            vec![target.to_string()],
            &runtime_state,
            Some(peer_notify.clone()),
        )
        .await;

        let failed = store.get(2).unwrap().unwrap();
        assert_eq!(failed.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(
            failed.error.as_deref(),
            Some("injected RocksDB deletion failure")
        );
        assert_runtime_target_present(&runtime_state, target, &channel_key).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), peer_notify.notified())
                .await
                .is_err(),
            "peer notification must not fire after database deletion fails"
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
        let runtime_state = runtime_state(&db);
        supervise_test_worker(
            succeeded_worker,
            db.clone(),
            1,
            vec!["piglet.node1.example.test".to_string()],
            &runtime_state,
            None,
        )
        .await;
        let succeeded = store.get(1).unwrap().unwrap();
        assert_eq!(succeeded.status, CustomerDataDeletionStatus::Succeeded);
        assert!(succeeded.completed_at.is_some());
        assert!(succeeded.error.is_none());
    }

    /// A request that arrives after shutdown has begun is refused, and the job
    /// store is left exactly as it was.
    ///
    /// Both shapes of request are covered because the two write differently: a
    /// first request would create a job where there was none, and a retry
    /// would overwrite the `Failed` job it is retrying. Neither may leave an
    /// `InProgress` job behind for a generation that is on its way out.
    #[tokio::test]
    async fn a_request_after_shutdown_has_begun_is_refused_and_writes_nothing() {
        let target = "piglet.node1.example.test";
        let schema = TestSchema::new_with_ingest_sensors(&[target]);
        let failed = CustomerDataDeletion {
            service_fqdn_list: vec![target.to_string()],
            requested_at: 1,
            status: CustomerDataDeletionStatus::Failed,
            completed_at: Some(2),
            error: Some("old failure".to_string()),
        };
        let store = schema.db.customer_deletion_job_store().unwrap();
        store.create(201, &failed).unwrap();

        // Exactly what the generation's teardown does on its way into the
        // drain, and the only thing this node needs to know to refuse.
        schema
            .top_level_tracker
            .close()
            .expect("a fresh tracker closes");

        for customer_id in [200, 201] {
            let response = schema
                .execute(&delete_customer_data_mutation(&[target], customer_id))
                .await;
            assert!(response.errors.is_empty(), "{:?}", response.errors);
            assert_eq!(
                response.data.to_string(),
                "{deleteCustomerData: BLOCKED_BY_SHUTDOWN}"
            );
        }

        assert_eq!(
            job_status(&schema.db, 200),
            None,
            "a refused first request must leave no job behind"
        );
        assert_eq!(
            store.get(201).unwrap(),
            Some(failed),
            "a refused retry must leave the failed job it would have replaced untouched"
        );
    }

    /// A request that arrives while a retention cycle owns the store is
    /// refused, writes nothing, and is taken once that cycle ends.
    #[tokio::test]
    async fn a_request_while_retention_runs_is_refused_and_writes_nothing() {
        let target = "piglet.node1.example.test";
        let schema = TestSchema::new_with_ingest_sensors(&[target]);

        // The claim a retention cycle holds for as long as it is deleting.
        let retention = schema
            .deletion_coordination
            .begin_retention()
            .expect("nothing has claimed the store yet");

        let response = schema
            .execute(&delete_customer_data_mutation(&[target], 202))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(
            response.data.to_string(),
            "{deleteCustomerData: BLOCKED_BY_RETENTION}"
        );
        assert_eq!(
            job_status(&schema.db, 202),
            None,
            "a refused request must leave no job behind"
        );

        // The refusal was the cycle's, not the node's: releasing the claim is
        // the only thing that changes between these two requests.
        drop(retention);
        let response = schema
            .execute(&delete_customer_data_mutation(&[target], 202))
            .await;
        assert_eq!(response.data.to_string(), "{deleteCustomerData: ACCEPTED}");
        assert_eq!(
            wait_for_terminal_job(&schema.db, 202).await.status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    /// While one customer's deletion is in flight, another customer's request
    /// is refused and a repeat of the in-flight one is told to wait.
    ///
    /// Nothing here is timed. The claim is taken inside the resolver, so it is
    /// already held when `ACCEPTED` comes back, and the deletion is kept from
    /// finishing by a write guard on the runtime sensor list — the second of
    /// the four runtime maps the supervisor clears once the RocksDB deletes
    /// are done. The resolver never reads that map, so the requests below run
    /// while the deletion is parked on it.
    #[tokio::test]
    async fn a_deletion_in_flight_refuses_other_customers_and_repeats_itself() {
        let first = "piglet.node1.example.test";
        let second = "reproduce.node2.example.test";
        let schema = TestSchema::new_with_ingest_sensors(&[first, second]);

        let hold_runtime_sensors = schema.runtime_ingest_sensors.write().await;
        let accepted = schema
            .execute(&delete_customer_data_mutation(&[first], 300))
            .await;
        assert!(accepted.errors.is_empty(), "{:?}", accepted.errors);
        assert_eq!(accepted.data.to_string(), "{deleteCustomerData: ACCEPTED}");

        let other_customer = schema
            .execute(&delete_customer_data_mutation(&[second], 301))
            .await;
        assert_eq!(
            other_customer.data.to_string(),
            "{deleteCustomerData: BLOCKED_BY_ANOTHER_DELETION}"
        );
        assert_eq!(
            job_status(&schema.db, 301),
            None,
            "a customer that was turned away must have no job of its own"
        );

        let repeat = schema
            .execute(&delete_customer_data_mutation(&[first], 300))
            .await;
        assert_eq!(
            repeat.data.to_string(),
            "{deleteCustomerData: DELETION_IN_PROGRESS}",
            "the customer already deleting is told to wait, not that it is blocked"
        );

        drop(hold_runtime_sensors);
        assert_eq!(
            wait_for_terminal_job(&schema.db, 300).await.status,
            CustomerDataDeletionStatus::Succeeded
        );

        // The store goes back to whoever asks next, so the customer that was
        // turned away is taken now.
        let retry = schema
            .execute(&delete_customer_data_mutation(&[second], 301))
            .await;
        assert_eq!(retry.data.to_string(), "{deleteCustomerData: ACCEPTED}");
        assert_eq!(
            wait_for_terminal_job(&schema.db, 301).await.status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    /// A registration the tracker refuses starts nothing and releases the
    /// store.
    ///
    /// This is the window the resolver's early `is_closed` check cannot close:
    /// shutdown can begin between that check and the registration. The future
    /// the tracker built is dropped without ever being polled, which is why
    /// the blocking deletion is created inside it — and why the claim it
    /// carries is released rather than stranded.
    #[tokio::test]
    async fn a_refused_registration_starts_nothing_and_releases_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        let target = "piglet.node1.example.test";
        db.sensors_store()
            .unwrap()
            .insert(target, DateTime::now())
            .unwrap();

        let coordination = Arc::new(CustomerDeletionCoordinator::new());
        let deletion_guard = coordination
            .begin_deletion(500)
            .expect("nothing has claimed the store yet");
        let tracker = TaskTracker::new();
        tracker.close().expect("a fresh tracker closes");
        let runtime_state = runtime_state(&db);

        let refused = start_customer_deletion_worker(
            &tracker,
            deletion_guard,
            db.clone(),
            500,
            vec![target.to_string()],
            runtime_state.0.clone(),
            runtime_state.1.clone(),
            runtime_state.2.clone(),
            runtime_state.3.clone(),
            None,
        );

        assert!(refused.is_err(), "a closed tracker admits nothing");
        assert!(
            db.sensors_store().unwrap().sensor_list().contains(target),
            "a refused registration must not have started deleting"
        );
        drop(
            coordination
                .begin_retention()
                .expect("the refused registration released the store"),
        );
    }

    /// A deletion that ends in failure releases the store exactly as one that
    /// succeeds does.
    ///
    /// The failure is the one the supervisor already models: the job row is
    /// not there, so every attempt at the terminal status write has nothing to
    /// update and the task ends without ever reaching a terminal status. Which
    /// branch the supervisor took is beside the point — the claim is a field of
    /// the future the tracker holds, so the drain that ends the future is what
    /// ends the claim, and the drain is also this test's synchronization.
    #[tokio::test]
    async fn a_deletion_that_ends_in_failure_releases_the_store() {
        use crate::cancellation::DrainOutcome;

        const FAILING: u32 = 900;
        const NEXT: u32 = 901;
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        let target = "piglet.node1.example.test";
        db.sensors_store()
            .unwrap()
            .insert(target, DateTime::now())
            .unwrap();

        let coordination = Arc::new(CustomerDeletionCoordinator::new());
        let deletion_guard = coordination
            .begin_deletion(FAILING)
            .expect("nothing has claimed the store yet");
        let tracker = TaskTracker::new();
        let runtime_state = runtime_state(&db);

        start_customer_deletion_worker(
            &tracker,
            deletion_guard,
            db.clone(),
            FAILING,
            vec![target.to_string()],
            runtime_state.0.clone(),
            runtime_state.1.clone(),
            runtime_state.2.clone(),
            runtime_state.3.clone(),
            None,
        )
        .expect("an open tracker admits the deletion");

        assert_eq!(
            tracker.drain(Duration::from_secs(5)).await.unwrap(),
            DrainOutcome::Drained,
            "the drain must not leave the deletion behind"
        );
        assert_eq!(
            db.customer_deletion_job_store()
                .unwrap()
                .get(FAILING)
                .unwrap(),
            None,
            "the supervisor must not write a job it was never given one for"
        );
        drop(
            coordination
                .begin_deletion(NEXT)
                .expect("the deletion that failed released the store"),
        );
        drop(
            coordination
                .begin_retention()
                .expect("the deletion that failed released the store"),
        );
    }

    /// A request already in flight when shutdown begins is refused and leaves
    /// the job store alone.
    ///
    /// The request is parked at the sensor list it reads to work out its local
    /// targets — the resolver's first `.await`, and, on a current-thread
    /// runtime, where a single yield is enough to put it — and held there
    /// until the tracker has been closed. What it does next is the whole of
    /// the resolver's shutdown handling: the `is_closed` check it now fails,
    /// and the claim and the job write it therefore never reaches.
    #[tokio::test]
    async fn a_request_in_flight_when_shutdown_begins_is_refused_and_writes_nothing() {
        const REQUESTING: u32 = 700;
        let target = "piglet.node1.example.test";
        let schema = TestSchema::new_with_ingest_sensors(&[target]);

        let hold_sensors = schema.ingest_sensors.write().await;
        let request = tokio::spawn({
            let schema = schema.schema.clone();
            let query = delete_customer_data_mutation(&[target], REQUESTING);
            async move { schema.execute(query).await }
        });
        // Polls the request up to its first park, which is the sensor list
        // this test is holding: everything before it is synchronous.
        tokio::task::yield_now().await;

        schema
            .top_level_tracker
            .close()
            .expect("a fresh tracker closes");
        drop(hold_sensors);

        let refused = request.await.unwrap();
        assert!(refused.errors.is_empty(), "{:?}", refused.errors);
        assert_eq!(
            refused.data.to_string(),
            "{deleteCustomerData: BLOCKED_BY_SHUTDOWN}"
        );
        assert_eq!(
            job_status(&schema.db, REQUESTING),
            None,
            "a refused request must leave no job behind"
        );
        assert!(
            schema.ingest_sensors.read().await.contains(target),
            "a refused request must not have started the runtime cleanup"
        );
        drop(
            schema
                .deletion_coordination
                .begin_retention()
                .expect("the refused request claimed nothing"),
        );
    }

    /// A registration the tracker refuses undoes the job the request had
    /// already written, for both shapes of request.
    ///
    /// This is the window the two tests above cannot be driven through:
    /// nothing in the resolver awaits between the `is_closed` check and the
    /// registration, so a request only reaches it when shutdown begins in the
    /// middle of a synchronous run. What stands in for that here is the other
    /// way the tracker refuses work — a poisoned admission lock, which
    /// `is_closed` does not report and `spawn` does. The resolver takes the
    /// same path either way: the job is written, the registration comes back
    /// refused, and the write is undone before the refusal is reported.
    #[tokio::test]
    async fn a_registration_the_tracker_refuses_undoes_the_job_it_wrote() {
        const REQUESTING: u32 = 700;
        const RETRYING: u32 = 701;
        let target = "piglet.node1.example.test";
        let schema = TestSchema::new_with_ingest_sensors(&[target]);
        let failed = CustomerDataDeletion {
            service_fqdn_list: vec![target.to_string()],
            requested_at: 1,
            status: CustomerDataDeletionStatus::Failed,
            completed_at: Some(2),
            error: Some("old failure".to_string()),
        };
        schema
            .db
            .customer_deletion_job_store()
            .unwrap()
            .create(RETRYING, &failed)
            .unwrap();

        // Poisons the admission lock the way `cancellation` already tests:
        // the inner spawn panics off a runtime, and it panics while the lock
        // is held. Done on a thread of its own because this test has a
        // runtime, and left uncaught nowhere because a panicking test thread
        // would take the assertions with it.
        std::thread::spawn({
            let tracker = schema.top_level_tracker.clone();
            move || {
                let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = tracker.spawn("off-runtime", |_token| async {});
                }));
                assert!(panicked.is_err(), "spawning off a runtime should panic");
            }
        })
        .join()
        .expect("the poisoning thread caught its own panic");
        assert!(
            !schema.top_level_tracker.is_closed(),
            "the request must pass the check the registration then fails"
        );

        for customer_id in [REQUESTING, RETRYING] {
            let refused = schema
                .execute(&delete_customer_data_mutation(&[target], customer_id))
                .await;
            assert!(refused.errors.is_empty(), "{:?}", refused.errors);
            assert_eq!(
                refused.data.to_string(),
                "{deleteCustomerData: BLOCKED_BY_SHUTDOWN}"
            );
        }

        assert_eq!(
            job_status(&schema.db, REQUESTING),
            None,
            "the job the refused first request wrote must be undone"
        );
        assert_eq!(
            schema
                .db
                .customer_deletion_job_store()
                .unwrap()
                .get(RETRYING)
                .unwrap(),
            Some(failed),
            "a refused retry must leave the failed job it overwrote as it was"
        );
        assert!(
            schema.ingest_sensors.read().await.contains(target),
            "a refused registration must not have started deleting"
        );
        drop(
            schema
                .deletion_coordination
                .begin_retention()
                .expect("both refused requests released the store"),
        );
    }

    /// An undo that fails is raised as an error rather than answered as a
    /// refusal.
    ///
    /// Nothing ran the job the request wrote and nothing has removed it, so
    /// reporting `BLOCKED_BY_SHUTDOWN` would tell the caller to retry
    /// elsewhere while leaving this node answering `DELETION_IN_PROGRESS` for
    /// the customer until #1725 recovers the job at startup.
    #[test]
    fn an_undo_that_fails_is_an_error_not_a_refusal() {
        const CUSTOMER: u32 = 702;
        let undone = std::cell::Cell::new(false);
        let refusal = refuse_registration(&SpawnError::Closed, CUSTOMER, || {
            undone.set(true);
            Ok(())
        })
        .expect("an undone request is a refusal, not a failure");
        assert_eq!(
            refusal,
            CustomerDataDeletionRequestStatus::BlockedByShutdown
        );
        assert!(undone.get(), "the job written for the request must be undone");

        let failure = refuse_registration(&SpawnError::LockPoisoned, CUSTOMER, || {
            Err(anyhow!("the job store is gone"))
        })
        .expect_err("an undo that failed is not a refusal the caller can act on");
        let message = failure.message;
        assert!(message.contains("the job store is gone"), "{message}");
        assert!(message.contains("DELETION_IN_PROGRESS"), "{message}");
    }

    /// Undoing the job a refused request wrote leaves the store as the request
    /// found it, for both shapes of request.
    #[test]
    fn undoing_a_refused_request_restores_the_job_store() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        let store = db.customer_deletion_job_store().unwrap();
        let in_progress = CustomerDataDeletion {
            service_fqdn_list: vec!["piglet.node1.example.test".to_string()],
            requested_at: 3,
            status: CustomerDataDeletionStatus::InProgress,
            completed_at: None,
            error: None,
        };

        store.create(600, &in_progress).unwrap();
        restore_previous_job(&store, 600, None).unwrap();
        assert_eq!(
            store.get(600).unwrap(),
            None,
            "a first request that was refused leaves no job"
        );

        let failed = CustomerDataDeletion {
            service_fqdn_list: vec!["piglet.node1.example.test".to_string()],
            requested_at: 1,
            status: CustomerDataDeletionStatus::Failed,
            completed_at: Some(2),
            error: Some("old failure".to_string()),
        };
        store.create(601, &failed).unwrap();
        store.update(601, &in_progress).unwrap();
        restore_previous_job(&store, 601, Some(&failed)).unwrap();
        assert_eq!(
            store.get(601).unwrap(),
            Some(failed),
            "a retry that was refused leaves the failed job it would have replaced"
        );
    }
}
