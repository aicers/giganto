//! The endpoint entry's telemetry streams: one senta-protocol
//! [`ReceiverStream`] per generation, over a [`ReceiverStore`] in the
//! generation's database, behind one lock.
//!
//! The stream rules — which records a batch stores, acknowledgements, gaps,
//! dropped and lost ranges, closed streams — are the crate's. What is here is
//! the store: each change set the crate writes becomes one synced RocksDB
//! write, its records converted into the Giganto structs of their kinds,
//! together with the streams' states and loss records, so that what is
//! acknowledged and what is stored never disagree.

use std::{
    cell::Cell,
    sync::{Mutex, MutexGuard},
};

use anyhow::{Context, Result, anyhow};
use jiff::Timestamp;
use senta_protocol::telemetry::{
    LastStored, ReceiverChange, ReceiverConnection, ReceiverEntryState, ReceiverFlowKey,
    ReceiverFlowState, ReceiverLossReason, ReceiverOutput, ReceiverRecord, ReceiverStore,
    ReceiverStream, Record, SeqRange, TelemetryMessage,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::convert;
use crate::storage::{
    Database,
    endpoint::{
        EndpointBatch, EndpointChange, EndpointRecordRow, EndpointWriteError, LossReason,
        StoredStream,
    },
};

/// The telemetry streams of the generation's entry: the `ReceiverStream`
/// lock.
///
/// It holds the stream of the `entry_id` stored, or none while no `entry_id`
/// is stored or its state could not be read. Every call that takes the lock
/// blocks — a batch write and its sync happen under it — so it is taken only
/// on blocking threads. It is taken before the active list's lock, never
/// while that is held.
pub(crate) struct EndpointFlows {
    database: Database,
    stream: Mutex<Option<ReceiverStream<EndpointStore>>>,
    #[cfg(test)]
    controls: std::sync::Arc<tests::Controls>,
}

/// The `ReceiverStream` lock, held.
pub(crate) struct FlowsGuard<'a> {
    flows: &'a EndpointFlows,
    stream: MutexGuard<'a, Option<ReceiverStream<EndpointStore>>>,
}

/// What a connection delivered, decoded.
#[derive(Debug)]
pub(super) enum Delivered {
    /// A telemetry message.
    Message(TelemetryMessage),
    /// A `record_batch` of this stream past a size limit.
    BatchTooLarge(Uuid),
}

/// What became of a delivered message.
#[derive(Debug)]
pub(super) enum Handled {
    /// The connection was stopped before its message was handled; nothing
    /// was done.
    Stopped,
    /// The message was handled.
    Done {
        /// What to send, or to close the connection.
        output: ReceiverOutput,
        /// The received time of the write that handled the message, when
        /// that write stored at least one record.
        stored_at: Option<Timestamp>,
    },
}

impl EndpointFlows {
    /// Creates the streams of a generation over `database`, holding no
    /// stream yet: the first call that takes the lock builds the stream of
    /// the `entry_id` stored, if one is.
    pub(crate) fn new(database: Database) -> Self {
        Self {
            database,
            stream: Mutex::new(None),
            #[cfg(test)]
            controls: std::sync::Arc::default(),
        }
    }

    /// Builds the stream of the `entry_id` stored, if one is and none is held
    /// yet; a failure is logged.
    ///
    /// It blocks, so it must not be called on an async worker thread.
    pub(crate) fn load(&self) {
        drop(self.lock());
    }

    /// Takes the `ReceiverStream` lock. Without a stream, it tries to build
    /// one from the `entry_id` stored, if any.
    ///
    /// It blocks, so it must not be called on an async worker thread.
    pub(crate) fn lock(&self) -> FlowsGuard<'_> {
        #[cfg(test)]
        let _waiting = self.controls.waiting();
        let stream = self.stream.lock().unwrap_or_else(|poisoned| {
            // A call that panicked under the lock may have left the stream's
            // copy of the state behind the store: it is read again.
            warn!("Endpoint entry: a call on the telemetry streams panicked; reading them again");
            let mut stream = poisoned.into_inner();
            *stream = None;
            self.stream.clear_poison();
            stream
        });
        let mut guard = FlowsGuard {
            flows: self,
            stream,
        };
        if guard.stream.is_none() {
            *guard.stream = self.restore();
        }
        guard
    }

    /// Builds the stream of the `entry_id` stored, or returns `None`, with
    /// the reason logged, when none is stored or it cannot be read.
    fn restore(&self) -> Option<ReceiverStream<EndpointStore>> {
        let entry_id = match self.database.endpoint_entry_id() {
            Ok(entry_id) => entry_id?,
            Err(e) => {
                error!("Endpoint entry: {e:#}; no telemetry stream is served");
                return None;
            }
        };
        match ReceiverStream::restore(entry_id, self.store()) {
            Ok(stream) => Some(stream),
            Err(e) => {
                error!(
                    "Endpoint entry: cannot read the stream state of entry_id {entry_id}: {e:#}; \
                     no telemetry stream is served until it can be"
                );
                None
            }
        }
    }

    /// Returns a store over the generation's database.
    fn store(&self) -> EndpointStore {
        EndpointStore {
            database: self.database.clone(),
            stored_at: Cell::new(None),
            #[cfg(test)]
            controls: std::sync::Arc::clone(&self.controls),
        }
    }

    /// Handles a message delivered on `connection`, unless the connection's
    /// `stop` token is cancelled by the time the lock is taken.
    ///
    /// It blocks, so it must not be called on an async worker thread.
    pub(super) fn handle(
        &self,
        stop: &CancellationToken,
        connection: &mut ReceiverConnection,
        delivered: Delivered,
    ) -> Handled {
        let mut guard = self.lock();
        if stop.is_cancelled() {
            return Handled::Stopped;
        }
        let Some(stream) = guard.stream.as_mut() else {
            warn!(
                "Endpoint {}: no telemetry stream is served; closing the connection",
                connection.endpoint_id()
            );
            return Handled::Done {
                output: ReceiverOutput::Disconnect,
                stored_at: None,
            };
        };
        stream.store().stored_at.set(None);
        let now = Timestamp::now();
        let output = match delivered {
            Delivered::Message(message) => stream.receive(connection, message, now),
            Delivered::BatchTooLarge(id) => stream.receive_batch_too_large(connection, id, now),
        };
        Handled::Done {
            output,
            stored_at: stream.store().stored_at.take(),
        }
    }

    /// Forgets the streams closed at least
    /// [`RECEIVER_CLOSED_RETENTION`](senta_protocol::telemetry::RECEIVER_CLOSED_RETENTION)
    /// before `now`; their records and loss records stay. A failure is
    /// logged.
    ///
    /// It blocks, so it must not be called on an async worker thread.
    pub(super) fn prune(&self, now: Timestamp) {
        let mut guard = self.lock();
        let Some(stream) = guard.stream.as_mut() else {
            return;
        };
        match stream.prune(now) {
            Ok(forgotten) if forgotten.is_empty() => {}
            Ok(forgotten) => info!(
                "Endpoint entry: forgot {} telemetry stream(s) closed 30 days ago or more",
                forgotten.len()
            ),
            Err(e) => error!("Endpoint entry: closed telemetry streams were not forgotten: {e:#}"),
        }
    }

    /// Returns the switches tests set.
    #[cfg(test)]
    pub(crate) fn controls(&self) -> &tests::Controls {
        &self.controls
    }

    /// Returns the `entry_id` of the stream held, if any; the lock is taken.
    #[cfg(test)]
    pub(crate) fn entry_id(&self) -> Option<Uuid> {
        self.lock().stream.as_ref().map(ReceiverStream::entry_id)
    }
}

impl FlowsGuard<'_> {
    /// Makes `entry_id` the node's, replacing `previous`: builds the new
    /// `entry_id`'s stream, then, in one synced write, stores the `entry_id`
    /// and forgets the stream states of `previous`, and only then holds the
    /// new stream. The loss records of `previous` stay.
    ///
    /// # Errors
    ///
    /// Returns an error if the new stream's state cannot be read or the write
    /// fails; then nothing has changed.
    pub(crate) fn change_entry_id(&mut self, entry_id: Uuid, previous: Option<Uuid>) -> Result<()> {
        #[cfg(test)]
        self.flows.controls.check_failure()?;
        let stream = ReceiverStream::restore(entry_id, self.flows.store())
            .context("cannot read the telemetry stream state of the new entry_id")?;
        self.flows
            .database
            .replace_endpoint_entry_id(entry_id, previous)?;
        *self.stream = Some(stream);
        Ok(())
    }
}

/// The [`ReceiverStore`] of the endpoint entry, over the generation's
/// database.
pub(crate) struct EndpointStore {
    database: Database,
    /// The received time of the last write that stored a record, taken by
    /// [`EndpointFlows::handle`].
    stored_at: Cell<Option<Timestamp>>,
    #[cfg(test)]
    controls: std::sync::Arc<tests::Controls>,
}

impl ReceiverStore for EndpointStore {
    type Error = anyhow::Error;

    fn load(&self, entry_id: Uuid) -> Result<ReceiverEntryState> {
        let mut state = ReceiverEntryState::default();
        for ((endpoint_id, stream), stored) in self.database.endpoint_streams(entry_id)? {
            state.flows.insert(
                ReceiverFlowKey {
                    endpoint_id,
                    stream,
                },
                flow_state(stored)?,
            );
        }
        Ok(state)
    }

    fn has_lost_on_reset(
        &self,
        entry_id: Uuid,
        endpoint_id: Uuid,
        stream: Uuid,
        range: SeqRange,
    ) -> Result<bool> {
        self.database.has_endpoint_lost_on_reset(
            entry_id,
            endpoint_id,
            stream,
            range.from,
            range.to,
        )
    }

    fn write(&mut self, entry_id: Uuid, changes: Vec<ReceiverChange>) -> Result<()> {
        let subject = changes.first().map(change_subject);
        let written = self.write_changes(entry_id, changes);
        if let Err(e) = &written {
            if let Some((endpoint_id, stream)) = subject {
                error!("Endpoint {endpoint_id}, stream {stream}: the batch was not written: {e:#}");
            } else {
                error!("Endpoint entry: an empty batch was not written: {e:#}");
            }
        }
        written
    }
}

impl EndpointStore {
    /// Writes `changes` of `entry_id` as one batch, converting the records.
    fn write_changes(&mut self, entry_id: Uuid, changes: Vec<ReceiverChange>) -> Result<()> {
        #[cfg(test)]
        self.controls.before_write(&changes)?;
        let received = Timestamp::now();
        let received_ns = nanos(received)?;
        let mut batch = EndpointBatch {
            entry_id,
            received_ns,
            changes: Vec::with_capacity(changes.len()),
            received_from: Vec::new(),
        };
        for change in changes {
            let change = match change {
                ReceiverChange::SetFlow { key, state } => EndpointChange::SetStream {
                    endpoint_id: key.endpoint_id,
                    stream: key.stream,
                    state: stored_stream(state)?,
                },
                ReceiverChange::RemoveFlow(key) => EndpointChange::RemoveStream {
                    endpoint_id: key.endpoint_id,
                    stream: key.stream,
                },
                ReceiverChange::AppendLoss(loss) => {
                    let (reason, detail) = match &loss.reason {
                        ReceiverLossReason::Dropped(reason) => {
                            (LossReason::Dropped, convert::wire_tag(reason))
                        }
                        ReceiverLossReason::LostOnReset => (LossReason::LostOnReset, String::new()),
                    };
                    EndpointChange::Loss {
                        endpoint_id: loss.endpoint_id,
                        stream: loss.stream,
                        from: loss.range.from,
                        to: loss.range.to,
                        reason,
                        detail,
                    }
                }
                ReceiverChange::AppendRecord(record) => {
                    if !batch.received_from.contains(&record.endpoint_id) {
                        batch.received_from.push(record.endpoint_id);
                    }
                    match record_row(&record) {
                        Ok(row) => EndpointChange::Record(row),
                        Err(reason) => {
                            warn!(
                                "Endpoint {}, stream {}: record {} is not stored: {reason}",
                                record.endpoint_id, record.stream, record.seq
                            );
                            EndpointChange::Loss {
                                endpoint_id: record.endpoint_id,
                                stream: record.stream,
                                from: record.seq,
                                to: record.seq,
                                reason: LossReason::ConversionFailure,
                                detail: reason,
                            }
                        }
                    }
                }
            };
            batch.changes.push(change);
        }
        let stored = self
            .database
            .write_endpoint_batch(batch)
            .map_err(|e| match e {
                EndpointWriteError::Storage(e) => e,
                e => anyhow!(e),
            })?;
        if stored > 0 {
            self.stored_at.set(Some(received));
        }
        Ok(())
    }
}

/// Returns the endpoint and stream a change is about.
fn change_subject(change: &ReceiverChange) -> (Uuid, Uuid) {
    match change {
        ReceiverChange::SetFlow { key, .. } | ReceiverChange::RemoveFlow(key) => {
            (key.endpoint_id, key.stream)
        }
        ReceiverChange::AppendRecord(record) => (record.endpoint_id, record.stream),
        ReceiverChange::AppendLoss(loss) => (loss.endpoint_id, loss.stream),
    }
}

/// Converts a record into the row it is stored as, or returns why it cannot
/// be.
fn record_row(record: &ReceiverRecord) -> Result<EndpointRecordRow, String> {
    let decoded = Record::from_bytes(&record.bytes)
        .map_err(|e| format!("the record does not decode: {e}"))?;
    let converted = convert::convert(decoded).map_err(|e| e.to_string())?;
    let value = converted
        .event
        .to_bincode()
        .map_err(|e| format!("the converted record does not serialize: {e}"))?;
    Ok(EndpointRecordRow {
        column_family: converted.event.column_family(),
        // The connection's endpoint id, which the crate has checked the
        // header's against: lowercase hyphenated, as `converted.sensor`.
        sensor: record.endpoint_id.to_string(),
        timestamp: converted.timestamp,
        value,
    })
}

/// Returns `time` in nanoseconds since the Unix epoch.
fn nanos(time: Timestamp) -> Result<i64> {
    i64::try_from(time.as_nanosecond())
        .with_context(|| format!("{time} does not fit i64 nanoseconds since the Unix epoch"))
}

/// Returns a stream state as it is stored.
fn stored_stream(state: ReceiverFlowState) -> Result<StoredStream> {
    Ok(StoredStream {
        a: state.a,
        last_stored: state.last_stored.map(|last| (last.seq, last.hash)),
        closed_at_ns: state.closed_at.map(nanos).transpose()?,
    })
}

/// Returns a stream state as it was stored.
fn flow_state(stored: StoredStream) -> Result<ReceiverFlowState> {
    let closed_at = stored
        .closed_at_ns
        .map(|ns| {
            Timestamp::from_nanosecond(i128::from(ns))
                .with_context(|| format!("a stream closed at {ns} ns is out of range"))
        })
        .transpose()?;
    Ok(ReceiverFlowState {
        a: stored.a,
        last_stored: stored
            .last_stored
            .map(|(seq, hash)| LastStored { seq, hash }),
        closed_at,
    })
}

#[cfg(test)]
pub(super) mod tests;
