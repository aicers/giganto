//! What the endpoint entry keeps in the store about itself and about the
//! endpoints that connect to it: the `entry_id` REview assigned the node, the
//! events the entry records, such as a key held by two hosts, the state of
//! every telemetry stream, the records an endpoint reported lost or the entry
//! could not convert, when each endpoint last sent records, the endpoints
//! customer data deletion has blocked for good, and the endpoint ids of each
//! customer data deletion job.
//!
//! None of these column families is a raw-data one: retention there deletes
//! by sensor prefix, which none of their keys has. The records themselves go
//! into the raw-data column family of their kind, under the endpoint id as
//! the sensor.

use std::{collections::HashSet, net::IpAddr, sync::Mutex};

use anyhow::{Context, Result, anyhow, bail};
use rocksdb::{ColumnFamily, Direction, IteratorMode, WriteBatch, WriteOptions};
use serde::{Deserialize, Serialize};
use tracing::error;
use uuid::Uuid;

use super::{APPEND_UNIQUE_LOCKS, Database, SENSORS_CF, StorageKey, append_unique_lock_index};

/// The column family holding the node's `entry_id`.
pub(crate) const ENDPOINT_ENTRY_CF: &str = "endpoint_entry";

/// The column family holding the events the endpoint entry records.
pub(crate) const ENDPOINT_EVENTS_CF: &str = "endpoint_events";

/// The column family holding the state of every telemetry stream, `A` and
/// `(L, H)` and when it was closed, under the `entry_id`, the endpoint id and
/// the stream id.
pub(crate) const ENDPOINT_STREAMS_CF: &str = "endpoint_streams";

/// The column family holding the loss records: ranges an endpoint dropped or
/// lost on a reset, and records the entry could not convert.
pub(crate) const ENDPOINT_LOSSES_CF: &str = "endpoint_losses";

/// The column family holding, per endpoint id, the received time of the
/// endpoint's last write carrying records.
pub(crate) const ENDPOINT_LAST_RECEIVED_CF: &str = "endpoint_last_received";

/// The column family holding, per endpoint id, when customer data deletion
/// blocked the endpoint, in nanoseconds since the Unix epoch. A block is
/// never lifted.
pub(crate) const ENDPOINT_BLOCKED_CF: &str = "endpoint_blocked";

/// The column family holding, per customer id, the endpoint ids of that
/// customer's data deletion job: the ids' 16 bytes, one after another.
pub(crate) const ENDPOINT_DELETION_JOBS_CF: &str = "endpoint_deletion_jobs";

/// How long loss records and endpoint events are kept after they were
/// received: 30 days, in nanoseconds.
pub(crate) const ENDPOINT_HISTORY_RETENTION_NS: i64 = 30 * 24 * 60 * 60 * 1_000_000_000;

/// The one key of [`ENDPOINT_ENTRY_CF`].
const ENTRY_ID_KEY: &[u8] = b"entry_id";

/// How many deletions [`Database::expire_endpoint_history`] puts in one write.
const EXPIRY_BATCH_LEN: usize = 10_000;

/// The length of an [`ENDPOINT_EVENTS_CF`] key: the received time, the
/// endpoint id and the sequence number.
const EVENT_KEY_LEN: usize = 8 + 16 + 4;

/// The length of an [`ENDPOINT_STREAMS_CF`] key: the `entry_id`, the endpoint
/// id and the stream id.
const STREAM_KEY_LEN: usize = 16 + 16 + 16;

/// The length of an [`ENDPOINT_LOSSES_CF`] key: a stream's key, then `from`,
/// `to`, the reason code and the received time.
const LOSS_KEY_LEN: usize = STREAM_KEY_LEN + 8 + 8 + 1 + 8;

/// Serializes the sequence number lookup and the write that follows it, so
/// that two events of one endpoint in the same nanosecond never take the same
/// sequence number. It also serializes each append, which reads the block of
/// its endpoint under it, with [`Database::block_endpoints`], which holds it
/// while it stores the blocks: an append either ends before a block is
/// stored or reads it, so none is stored after the block.
static EVENT_APPEND: Mutex<()> = Mutex::new(());

/// Serializes the lookup of a block and the write that follows it, so that
/// an endpoint blocked twice at once keeps the first blocked time.
static BLOCK_WRITE: Mutex<()> = Mutex::new(());

/// One key's connections replaced each other too often, from more than one
/// address: two hosts may hold the same key.
///
/// Stored in [`ENDPOINT_EVENTS_CF`] under the received time and the endpoint
/// id, serialized with bincode 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DuplicateKeyEvent {
    /// The SHA-256 of the key's `SubjectPublicKeyInfo`.
    pub(crate) spki_sha256: [u8; 32],
    /// The distinct source addresses of the connections counted.
    pub(crate) addresses: Vec<IpAddr>,
    /// How many replacements were counted.
    pub(crate) replacements: u64,
}

/// A telemetry stream's state, as [`ENDPOINT_STREAMS_CF`] holds it: bincode 1
/// of the tuple of its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredStream {
    /// `A`, the highest sequence number acknowledged.
    pub(crate) a: u64,
    /// `(L, H)`, the sequence number and hash of the last record stored, if
    /// any was.
    pub(crate) last_stored: Option<(u64, [u8; 16])>,
    /// When the stream was closed, in nanoseconds since the Unix epoch, or
    /// `None` while it is open.
    pub(crate) closed_at_ns: Option<i64>,
}

/// Why records were lost, as the reason code of an [`ENDPOINT_LOSSES_CF`] key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LossReason {
    /// The endpoint dropped the range; the detail is the drop reason's tag.
    Dropped,
    /// The endpoint lost the range when its state was reset; no detail.
    LostOnReset,
    /// The entry could not decode or convert the record; the detail is why.
    ConversionFailure,
}

impl LossReason {
    /// Returns the reason code a key carries.
    #[must_use]
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Dropped => 0,
            Self::LostOnReset => 1,
            Self::ConversionFailure => 2,
        }
    }

    /// Returns the reason a key's reason code stands for, or `None` for a
    /// code no reason has.
    #[must_use]
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Dropped),
            1 => Some(Self::LostOnReset),
            2 => Some(Self::ConversionFailure),
            _ => None,
        }
    }
}

/// A loss record, read back from its [`ENDPOINT_LOSSES_CF`] key and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredLoss {
    /// The `entry_id` the record was written under.
    pub(crate) entry_id: Uuid,
    /// The endpoint whose records were lost.
    pub(crate) endpoint_id: Uuid,
    /// The stream the records were lost from.
    pub(crate) stream: Uuid,
    /// The first sequence number of the range lost.
    pub(crate) from: u64,
    /// The last sequence number of the range lost.
    pub(crate) to: u64,
    /// Why the records were lost.
    pub(crate) reason: LossReason,
    /// The reason's detail, empty for [`LossReason::LostOnReset`].
    pub(crate) detail: String,
    /// When the record was written, in nanoseconds since the Unix epoch.
    pub(crate) received_ns: i64,
}

/// A duplicate-key event, read back from its [`ENDPOINT_EVENTS_CF`] key and
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredEndpointEvent {
    /// When the event was recorded, in nanoseconds since the Unix epoch.
    pub(crate) received_ns: i64,
    /// The endpoint the event is about.
    pub(crate) endpoint_id: Uuid,
    /// The event's sequence number among those of the same received time and
    /// endpoint.
    pub(crate) sequence: u32,
    /// The event.
    pub(crate) event: DuplicateKeyEvent,
}

/// How many entries [`Database::expire_endpoint_history`] deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ExpiredEndpointHistory {
    /// The loss records deleted.
    pub(crate) losses: usize,
    /// The endpoint events deleted.
    pub(crate) events: usize,
}

/// A record converted for storage: its value goes into `column_family` under
/// the standard key of `sensor` and `timestamp`, or the first free key after
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointRecordRow {
    /// The raw-data column family of the record's kind.
    pub(crate) column_family: &'static str,
    /// The endpoint id, lowercase hyphenated.
    pub(crate) sensor: String,
    /// The record's event time, in nanoseconds since the Unix epoch.
    pub(crate) timestamp: i64,
    /// The bincode 1 serialization of the record's struct.
    pub(crate) value: Vec<u8>,
}

/// One change of an [`EndpointBatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EndpointChange {
    /// Sets a stream's state.
    SetStream {
        endpoint_id: Uuid,
        stream: Uuid,
        state: StoredStream,
    },
    /// Forgets a stream's state.
    RemoveStream { endpoint_id: Uuid, stream: Uuid },
    /// Adds a loss record of `from..=to`.
    Loss {
        endpoint_id: Uuid,
        stream: Uuid,
        from: u64,
        to: u64,
        reason: LossReason,
        detail: String,
    },
    /// Adds a record.
    Record(EndpointRecordRow),
}

/// What [`Database::write_endpoint_batch`] writes as one batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointBatch {
    /// The `entry_id` the stream states and loss records belong to.
    pub(crate) entry_id: Uuid,
    /// The node's wall clock when the write began, in nanoseconds since the
    /// Unix epoch: the received time of every loss record, of the last
    /// received time and of the `sensors` rows.
    pub(crate) received_ns: i64,
    /// The changes, in order.
    pub(crate) changes: Vec<EndpointChange>,
    /// The endpoints whose records the write carries, whether or not they
    /// converted: their last received time is set.
    pub(crate) received_from: Vec<Uuid>,
}

/// Why an endpoint batch was not written. Nothing of it was.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EndpointWriteError {
    /// Every key the probe limit allows for a record is taken.
    #[error(
        "the {limit} timestamps from {timestamp} on of sensor {sensor} in {column_family} are \
         all taken"
    )]
    ProbeLimit {
        column_family: &'static str,
        sensor: String,
        timestamp: i64,
        limit: i64,
    },
    /// Every key from a record's time up to `i64::MAX` is taken.
    #[error(
        "every timestamp from {timestamp} up to i64::MAX of sensor {sensor} in {column_family} \
         is taken"
    )]
    Overflow {
        column_family: &'static str,
        sensor: String,
        timestamp: i64,
    },
    /// The store could not be read or written.
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
}

/// Returns the [`ENDPOINT_EVENTS_CF`] key of an event received at
/// `received_ns` about `endpoint_id`, with sequence number `sequence`.
///
/// The parts are big-endian, so keys sort by time first.
pub(crate) fn endpoint_event_key(
    received_ns: i64,
    endpoint_id: Uuid,
    sequence: u32,
) -> [u8; EVENT_KEY_LEN] {
    let mut key = [0_u8; EVENT_KEY_LEN];
    let (time, rest) = key.split_at_mut(8);
    let (id, seq) = rest.split_at_mut(16);
    time.copy_from_slice(&received_ns.to_be_bytes());
    id.copy_from_slice(endpoint_id.as_bytes());
    seq.copy_from_slice(&sequence.to_be_bytes());
    key
}

/// Returns the [`ENDPOINT_STREAMS_CF`] key of `stream` of `endpoint_id` at
/// `entry_id`.
pub(crate) fn endpoint_stream_key(
    entry_id: Uuid,
    endpoint_id: Uuid,
    stream: Uuid,
) -> [u8; STREAM_KEY_LEN] {
    let mut key = [0_u8; STREAM_KEY_LEN];
    let (entry, rest) = key.split_at_mut(16);
    let (endpoint, stream_id) = rest.split_at_mut(16);
    entry.copy_from_slice(entry_id.as_bytes());
    endpoint.copy_from_slice(endpoint_id.as_bytes());
    stream_id.copy_from_slice(stream.as_bytes());
    key
}

/// Returns the [`ENDPOINT_LOSSES_CF`] key of a loss of `from..=to` in
/// `stream` of `endpoint_id` at `entry_id`, for `reason`, received at
/// `received_ns`.
pub(crate) fn endpoint_loss_key(
    entry_id: Uuid,
    endpoint_id: Uuid,
    stream: Uuid,
    from: u64,
    to: u64,
    reason: LossReason,
    received_ns: i64,
) -> [u8; LOSS_KEY_LEN] {
    let mut key = [0_u8; LOSS_KEY_LEN];
    let (prefix, received) = key.split_at_mut(LOSS_KEY_LEN - 8);
    prefix.copy_from_slice(&loss_prefix(
        entry_id,
        endpoint_id,
        stream,
        from,
        to,
        reason,
    ));
    received.copy_from_slice(&received_ns.to_be_bytes());
    key
}

/// Returns the [`ENDPOINT_LOSSES_CF`] key of a loss without its received
/// time: every loss of the same range and reason starts with it.
fn loss_prefix(
    entry_id: Uuid,
    endpoint_id: Uuid,
    stream: Uuid,
    from: u64,
    to: u64,
    reason: LossReason,
) -> [u8; LOSS_KEY_LEN - 8] {
    let mut key = [0_u8; LOSS_KEY_LEN - 8];
    let (stream_key, rest) = key.split_at_mut(STREAM_KEY_LEN);
    let (from_part, rest) = rest.split_at_mut(8);
    let (to_part, code) = rest.split_at_mut(8);
    stream_key.copy_from_slice(&endpoint_stream_key(entry_id, endpoint_id, stream));
    from_part.copy_from_slice(&from.to_be_bytes());
    to_part.copy_from_slice(&to.to_be_bytes());
    code.copy_from_slice(&[reason.code()]);
    key
}

/// Returns the standard key of `sensor` at `timestamp`.
fn record_key(sensor: &str, timestamp: i64) -> Vec<u8> {
    StorageKey::builder()
        .start_key(sensor)
        .end_key(timestamp)
        .build()
        .key()
}

/// Returns the standard key prefix of `sensor`, the part every key of it
/// shares before the timestamp.
fn record_prefix(sensor: &str) -> Vec<u8> {
    StorageKey::builder().start_key(sensor).build().key()
}

/// Returns the options of a write that is on disk once it returns.
fn synced() -> WriteOptions {
    let mut options = WriteOptions::default();
    options.set_sync(true);
    options
}

/// Returns the big-endian `i64` at the start of `bytes`, if it is that long.
fn be_i64(bytes: &[u8]) -> Option<i64> {
    bytes.first_chunk::<8>().copied().map(i64::from_be_bytes)
}

/// Decodes an [`ENDPOINT_LOSSES_CF`] entry.
fn decode_loss(key: &[u8], value: &[u8]) -> Result<StoredLoss> {
    let key: &[u8; LOSS_KEY_LEN] = key.try_into().map_err(|_| {
        anyhow!(
            "an endpoint loss key is {} bytes long, not {LOSS_KEY_LEN}",
            key.len()
        )
    })?;
    let (entry_id, rest) = key.split_first_chunk::<16>().context("an entry_id")?;
    let (endpoint_id, rest) = rest.split_first_chunk::<16>().context("an endpoint id")?;
    let (stream, rest) = rest.split_first_chunk::<16>().context("a stream id")?;
    let (from, rest) = rest.split_first_chunk::<8>().context("a range start")?;
    let (to, rest) = rest.split_first_chunk::<8>().context("a range end")?;
    let (code, received) = rest.split_first().context("a reason code")?;
    let received: &[u8; 8] = received.try_into().context("a received time")?;
    let reason = LossReason::from_code(*code)
        .ok_or_else(|| anyhow!("an endpoint loss key carries the unknown reason code {code}"))?;
    let detail = String::from_utf8(value.to_vec())
        .map_err(|_| anyhow!("an endpoint loss detail is not UTF-8"))?;
    Ok(StoredLoss {
        entry_id: Uuid::from_bytes(*entry_id),
        endpoint_id: Uuid::from_bytes(*endpoint_id),
        stream: Uuid::from_bytes(*stream),
        from: u64::from_be_bytes(*from),
        to: u64::from_be_bytes(*to),
        reason,
        detail,
        received_ns: i64::from_be_bytes(*received),
    })
}

/// Decodes an [`ENDPOINT_EVENTS_CF`] entry.
fn decode_event(key: &[u8], value: &[u8]) -> Result<StoredEndpointEvent> {
    let key: &[u8; EVENT_KEY_LEN] = key.try_into().map_err(|_| {
        anyhow!(
            "an endpoint event key is {} bytes long, not {EVENT_KEY_LEN}",
            key.len()
        )
    })?;
    let (received, rest) = key.split_first_chunk::<8>().context("a received time")?;
    let (endpoint_id, sequence) = rest.split_first_chunk::<16>().context("an endpoint id")?;
    let sequence: &[u8; 4] = sequence.try_into().context("a sequence number")?;
    let endpoint_id = Uuid::from_bytes(*endpoint_id);
    let received_ns = i64::from_be_bytes(*received);
    let event: DuplicateKeyEvent = bincode::deserialize(value).with_context(|| {
        format!("cannot decode the endpoint event of {endpoint_id} received at {received_ns}")
    })?;
    Ok(StoredEndpointEvent {
        received_ns,
        endpoint_id,
        sequence: u32::from_be_bytes(*sequence),
        event,
    })
}

impl Database {
    /// Returns the `entry_id` stored, or `None` when none is.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read or the value
    /// stored is not 16 bytes long.
    pub(crate) fn endpoint_entry_id(&self) -> Result<Option<Uuid>> {
        let cf = self.get_cf_handle(ENDPOINT_ENTRY_CF)?;
        let Some(value) = self
            .db
            .get_pinned_cf(cf, ENTRY_ID_KEY)
            .context("cannot read the stored endpoint entry_id")?
        else {
            return Ok(None);
        };
        let bytes: [u8; 16] = value.as_ref().try_into().map_err(|_| {
            anyhow!(
                "the stored endpoint entry_id is {} bytes long, not 16",
                value.len()
            )
        })?;
        Ok(Some(Uuid::from_bytes(bytes)))
    }

    /// Stores `entry_id` as the node's `entry_id`, replacing any stored, and
    /// forgets the stream states of `previous`, the `entry_id` it replaces,
    /// in one write; returns once the write is on disk. The loss records of
    /// `previous` stay.
    ///
    /// # Errors
    ///
    /// Returns an error if a column family cannot be read or written; then
    /// nothing was written.
    pub(crate) fn replace_endpoint_entry_id(
        &self,
        entry_id: Uuid,
        previous: Option<Uuid>,
    ) -> Result<()> {
        let entry_cf = self.get_cf_handle(ENDPOINT_ENTRY_CF)?;
        let streams_cf = self.get_cf_handle(ENDPOINT_STREAMS_CF)?;
        let mut batch = WriteBatch::default();
        batch.put_cf(entry_cf, ENTRY_ID_KEY, entry_id.as_bytes());
        if let Some(previous) = previous.filter(|previous| *previous != entry_id) {
            for key in self.keys_with_prefix(streams_cf, previous.as_bytes()) {
                batch.delete_cf(streams_cf, key.context("cannot read the endpoint streams")?);
            }
        }
        #[cfg(test)]
        if self
            .entry_id_write_fault
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            bail!("injected failure writing the endpoint entry_id");
        }
        // REview is told the update is applied once this returns, and every
        // `hello_ack` carries the value from then on, so a crash must not
        // bring back the one it replaced. The database flushes its WAL only
        // when asked (`manual_wal_flush`); a synced write writes the WAL out
        // and syncs it before returning. The cost is one disk round trip on a
        // write REview makes only when it assigns the node a new `entry_id`.
        self.db
            .write_opt(batch, &synced())
            .context("cannot write the endpoint entry_id")
    }

    /// Makes every later [`replace_endpoint_entry_id`] on this database or a
    /// clone of it fail, after it has read what it deletes and before it
    /// writes anything, while `fail` is `true`.
    ///
    /// [`replace_endpoint_entry_id`]: Self::replace_endpoint_entry_id
    #[cfg(test)]
    pub(crate) fn fail_entry_id_writes_for_test(&self, fail: bool) {
        self.entry_id_write_fault
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Returns the state of every stream stored under `entry_id`, by endpoint
    /// id and stream id.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read, or a key or
    /// value in it is malformed.
    pub(crate) fn endpoint_streams(
        &self,
        entry_id: Uuid,
    ) -> Result<Vec<((Uuid, Uuid), StoredStream)>> {
        let cf = self.get_cf_handle(ENDPOINT_STREAMS_CF)?;
        let mut streams = Vec::new();
        for item in self.db.iterator_cf(
            cf,
            IteratorMode::From(entry_id.as_bytes(), Direction::Forward),
        ) {
            let (key, value) = item.context("cannot read the endpoint streams")?;
            if !key.starts_with(entry_id.as_bytes()) {
                break;
            }
            let ids: [u8; STREAM_KEY_LEN] = key.as_ref().try_into().map_err(|_| {
                anyhow!(
                    "an endpoint stream key is {} bytes long, not {STREAM_KEY_LEN}",
                    key.len()
                )
            })?;
            let (_, ids) = ids.split_at(16);
            let (endpoint, stream) = ids.split_at(16);
            let endpoint = Uuid::from_slice(endpoint).context("an endpoint id")?;
            let stream = Uuid::from_slice(stream).context("a stream id")?;
            let state: StoredStream = bincode::deserialize(&value).with_context(|| {
                format!("cannot decode the state of stream {stream} of endpoint {endpoint}")
            })?;
            streams.push(((endpoint, stream), state));
        }
        Ok(streams)
    }

    /// Returns whether `entry_id` holds a lost-on-reset loss record of
    /// `from..=to` in `stream` of `endpoint_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read.
    pub(crate) fn has_endpoint_lost_on_reset(
        &self,
        entry_id: Uuid,
        endpoint_id: Uuid,
        stream: Uuid,
        from: u64,
        to: u64,
    ) -> Result<bool> {
        let cf = self.get_cf_handle(ENDPOINT_LOSSES_CF)?;
        let prefix = loss_prefix(
            entry_id,
            endpoint_id,
            stream,
            from,
            to,
            LossReason::LostOnReset,
        );
        match self.keys_with_prefix(cf, &prefix).next() {
            Some(key) => key.map(|_| true).context("cannot read the endpoint losses"),
            None => Ok(false),
        }
    }

    /// Writes `batch` as one synced write, and returns how many records it
    /// stored.
    ///
    /// Each record takes the first key, from its own time on, that neither
    /// the store nor an earlier record of the batch holds; a byte-identical
    /// record stored before is no exception. The `append_unique` locks of
    /// the records' sensors are held, each taken once and in index order,
    /// from before the first lookup until the batch is written, so module
    /// ingest cannot take a key between the lookup and the write. Every
    /// endpoint the batch received records from has its last received time
    /// set, and every sensor it stores records of has its `sensors` row put,
    /// in the same batch.
    ///
    /// It blocks on the locks, so it must not run on an async worker thread.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointWriteError::ProbeLimit`] or
    /// [`EndpointWriteError::Overflow`] when a record finds no free key, and
    /// [`EndpointWriteError::Storage`] when the store cannot be read or
    /// written. Nothing of the batch is written then.
    pub(crate) fn write_endpoint_batch(
        &self,
        batch: EndpointBatch,
    ) -> Result<usize, EndpointWriteError> {
        let EndpointBatch {
            entry_id,
            received_ns,
            changes,
            received_from,
        } = batch;
        let streams_cf = self.get_cf_handle(ENDPOINT_STREAMS_CF)?;
        let losses_cf = self.get_cf_handle(ENDPOINT_LOSSES_CF)?;
        let last_received_cf = self.get_cf_handle(ENDPOINT_LAST_RECEIVED_CF)?;
        let sensors_cf = self.get_cf_handle(SENSORS_CF)?;

        let mut slots = Vec::new();
        for change in &changes {
            if let EndpointChange::Record(row) = change {
                let cf = self.get_cf_handle(row.column_family)?;
                slots.push(append_unique_lock_index(cf, &record_prefix(&row.sensor)));
            }
        }
        slots.sort_unstable();
        slots.dedup();
        // Module ingest holds one of these at a time and takes nothing else
        // while it does, so taking several in index order cannot deadlock
        // with it or with another batch.
        let _guards: Vec<_> = slots
            .into_iter()
            .filter_map(|slot| APPEND_UNIQUE_LOCKS.get(slot))
            .map(tokio::sync::Mutex::blocking_lock)
            .collect();

        let mut write = WriteBatch::default();
        let mut taken: HashSet<(&'static str, Vec<u8>)> = HashSet::new();
        let mut sensors: Vec<String> = Vec::new();
        let mut stored = 0_usize;
        for change in changes {
            match change {
                EndpointChange::SetStream {
                    endpoint_id,
                    stream,
                    state,
                } => {
                    let value = bincode::serialize(&state)
                        .context("cannot serialize an endpoint stream state")?;
                    write.put_cf(
                        streams_cf,
                        endpoint_stream_key(entry_id, endpoint_id, stream),
                        value,
                    );
                }
                EndpointChange::RemoveStream {
                    endpoint_id,
                    stream,
                } => write.delete_cf(
                    streams_cf,
                    endpoint_stream_key(entry_id, endpoint_id, stream),
                ),
                EndpointChange::Loss {
                    endpoint_id,
                    stream,
                    from,
                    to,
                    reason,
                    detail,
                } => write.put_cf(
                    losses_cf,
                    endpoint_loss_key(entry_id, endpoint_id, stream, from, to, reason, received_ns),
                    detail.as_bytes(),
                ),
                EndpointChange::Record(row) => {
                    let cf = self.get_cf_handle(row.column_family)?;
                    let key = self.free_record_key(cf, &row, &taken)?;
                    write.put_cf(cf, &key, &row.value);
                    taken.insert((row.column_family, key));
                    if !sensors.contains(&row.sensor) {
                        sensors.push(row.sensor);
                    }
                    stored += 1;
                }
            }
        }
        for endpoint_id in received_from {
            write.put_cf(
                last_received_cf,
                endpoint_id.as_bytes(),
                received_ns.to_be_bytes(),
            );
        }
        // Retention walks the `sensors` names, so a record stored without its
        // sensor's row, as a crash between two writes would leave it, would
        // never be deleted. The value is as `SensorStore::insert` writes it.
        for sensor in sensors {
            write.put_cf(sensors_cf, sensor, received_ns.to_be_bytes());
        }
        // The endpoint is told the records are stored once this returns. The
        // database flushes its WAL only when asked (`manual_wal_flush`), so
        // only a synced write is on disk by then.
        self.db
            .write_opt(write, &synced())
            .context("cannot write an endpoint batch")?;
        Ok(stored)
    }

    /// Returns the first key of `row`, from its own time on, that neither the
    /// store nor `taken` holds.
    fn free_record_key(
        &self,
        cf: &ColumnFamily,
        row: &EndpointRecordRow,
        taken: &HashSet<(&'static str, Vec<u8>)>,
    ) -> Result<Vec<u8>, EndpointWriteError> {
        for offset in 0..self.append_unique_max_probes {
            let Some(timestamp) = row.timestamp.checked_add(offset) else {
                return Err(EndpointWriteError::Overflow {
                    column_family: row.column_family,
                    sensor: row.sensor.clone(),
                    timestamp: row.timestamp,
                });
            };
            let key = record_key(&row.sensor, timestamp);
            if taken.contains(&(row.column_family, key.clone())) {
                continue;
            }
            let stored = self
                .db
                .get_pinned_cf(cf, &key)
                .with_context(|| format!("cannot read {}", row.column_family))?;
            if stored.is_none() {
                return Ok(key);
            }
        }
        Err(EndpointWriteError::ProbeLimit {
            column_family: row.column_family,
            sensor: row.sensor.clone(),
            timestamp: row.timestamp,
            limit: self.append_unique_max_probes,
        })
    }

    /// Returns the keys of `cf` that start with `prefix`, in order.
    fn keys_with_prefix<'a>(
        &'a self,
        cf: &'a ColumnFamily,
        prefix: &'a [u8],
    ) -> impl Iterator<Item = Result<Box<[u8]>, rocksdb::Error>> + 'a {
        self.db
            .iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward))
            .map(|item| item.map(|(key, _)| key))
            .take_while(move |key| key.as_ref().map_or(true, |key| key.starts_with(prefix)))
    }

    /// Stores `event` about `endpoint_id`, received at `received_ns`
    /// nanoseconds since the Unix epoch, under the lowest sequence number
    /// not yet used for that time and endpoint, and returns that number; or
    /// stores nothing and returns `None` when `endpoint_id` is blocked, or
    /// its block cannot be read.
    ///
    /// The block is read under the same lock [`Self::block_endpoints`]
    /// stores blocks under, so once a block is stored, no event of its
    /// endpoint is stored after it: customer data deletion, which deletes
    /// the events once the block is stored, never leaves one behind.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read or written, the
    /// event cannot be serialized, or every sequence number is taken.
    pub(crate) fn append_endpoint_duplicate_key(
        &self,
        received_ns: i64,
        endpoint_id: Uuid,
        event: &DuplicateKeyEvent,
    ) -> Result<Option<u32>> {
        let cf = self.get_cf_handle(ENDPOINT_EVENTS_CF)?;
        let value = bincode::serialize(event).context("cannot serialize an endpoint event")?;
        let _append = EVENT_APPEND
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Refused rather than stored when the block cannot be read: an event
        // stored after the deletion it should have stopped stays.
        if self.is_endpoint_blocked_or_unreadable(endpoint_id, "not storing its event") {
            return Ok(None);
        }
        let mut sequence = 0_u32;
        loop {
            let key = endpoint_event_key(received_ns, endpoint_id, sequence);
            let taken = self
                .db
                .get_pinned_cf(cf, key)
                .context("cannot read the endpoint events")?
                .is_some();
            if !taken {
                self.db
                    .put_cf(cf, key, &value)
                    .context("cannot write an endpoint event")?;
                return Ok(Some(sequence));
            }
            let Some(next) = sequence.checked_add(1) else {
                bail!("every sequence number of an endpoint event time is taken");
            };
            sequence = next;
        }
    }

    /// Returns every loss record received at or after `since` nanoseconds
    /// since the Unix epoch, under every `entry_id`, in key order.
    ///
    /// The keys start with the `entry_id`, not the received time, so every
    /// record is read; retention bounds how many there are. Received times are
    /// never negative, so a negative `since` returns every record.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read, or an entry in it
    /// is malformed.
    pub(crate) fn endpoint_losses_since(&self, since: i64) -> Result<Vec<StoredLoss>> {
        let cf = self.get_cf_handle(ENDPOINT_LOSSES_CF)?;
        let mut losses = Vec::new();
        for item in self.db.iterator_cf(cf, IteratorMode::Start) {
            let (key, value) = item.context("cannot read the endpoint losses")?;
            let loss = decode_loss(&key, &value)?;
            if loss.received_ns >= since {
                losses.push(loss);
            }
        }
        Ok(losses)
    }

    /// Returns every endpoint event received at or after `since` nanoseconds
    /// since the Unix epoch, in key order: by received time, then endpoint id,
    /// then sequence number.
    ///
    /// Received times are never negative, and a negative one would sort after
    /// every other in a big-endian key, so a negative `since` is read as 0 and
    /// returns every event.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read, or an entry in it
    /// is malformed.
    pub(crate) fn endpoint_events_since(&self, since: i64) -> Result<Vec<StoredEndpointEvent>> {
        let cf = self.get_cf_handle(ENDPOINT_EVENTS_CF)?;
        let start = since.max(0).to_be_bytes();
        let mut events = Vec::new();
        for item in self
            .db
            .iterator_cf(cf, IteratorMode::From(&start, Direction::Forward))
        {
            let (key, value) = item.context("cannot read the endpoint events")?;
            let event = decode_event(&key, &value)?;
            if event.received_ns < 0 {
                break;
            }
            events.push(event);
        }
        Ok(events)
    }

    /// Returns, in endpoint id order, the last received time of up to `limit`
    /// endpoints whose id comes strictly after `after`, or from the first
    /// when `after` is `None`, and whether more endpoints follow them.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read, or an entry in it
    /// is malformed.
    pub(crate) fn endpoint_last_received(
        &self,
        after: Option<Uuid>,
        limit: usize,
    ) -> Result<(Vec<(Uuid, i64)>, bool)> {
        let cf = self.get_cf_handle(ENDPOINT_LAST_RECEIVED_CF)?;
        let mode = match &after {
            Some(after) => IteratorMode::From(after.as_bytes(), Direction::Forward),
            None => IteratorMode::Start,
        };
        let mut page = Vec::new();
        for item in self.db.iterator_cf(cf, mode) {
            let (key, value) = item.context("cannot read the endpoint last received times")?;
            if after.is_some_and(|after| key.as_ref() == after.as_bytes()) {
                continue;
            }
            if page.len() == limit {
                return Ok((page, true));
            }
            let endpoint_id = Uuid::from_slice(&key).map_err(|_| {
                anyhow!(
                    "an endpoint last received key is {} bytes long, not 16",
                    key.len()
                )
            })?;
            let received: [u8; 8] = value.as_ref().try_into().map_err(|_| {
                anyhow!(
                    "the last received time of endpoint {endpoint_id} is {} bytes long, not 8",
                    value.len()
                )
            })?;
            page.push((endpoint_id, i64::from_be_bytes(received)));
        }
        Ok((page, false))
    }

    /// Deletes every loss record and endpoint event received
    /// [`ENDPOINT_HISTORY_RETENTION_NS`] or more before `now_ns`, nanoseconds
    /// since the Unix epoch, and returns how many of each it deleted. The last
    /// received times are left alone.
    ///
    /// A key too short to carry a received time is left alone too. The
    /// deletions are written in batches of [`EXPIRY_BATCH_LEN`]; a failure
    /// leaves the earlier batches deleted, which the next run does not mind.
    ///
    /// # Errors
    ///
    /// Returns an error if a column family cannot be read or written.
    pub(crate) fn expire_endpoint_history(&self, now_ns: i64) -> Result<ExpiredEndpointHistory> {
        let cutoff = now_ns.saturating_sub(ENDPOINT_HISTORY_RETENTION_NS);
        let losses_cf = self.get_cf_handle(ENDPOINT_LOSSES_CF)?;
        let events_cf = self.get_cf_handle(ENDPOINT_EVENTS_CF)?;
        let mut expired = ExpiredEndpointHistory::default();
        let mut batch = WriteBatch::default();
        let write = |batch: &mut WriteBatch, at_least: usize| -> Result<()> {
            if batch.len() >= at_least.max(1) {
                self.db
                    .write(std::mem::take(batch))
                    .context("cannot delete expired endpoint losses and events")?;
            }
            Ok(())
        };

        for item in self.db.iterator_cf(losses_cf, IteratorMode::Start) {
            let (key, _) = item.context("cannot read the endpoint losses")?;
            let received = (key.len() == LOSS_KEY_LEN)
                .then(|| key.get(LOSS_KEY_LEN - 8..).and_then(be_i64))
                .flatten();
            if received.is_some_and(|received| received <= cutoff) {
                batch.delete_cf(losses_cf, &key);
                expired.losses += 1;
                write(&mut batch, EXPIRY_BATCH_LEN)?;
            }
        }

        // Keys start with the received time, so the expired ones come first.
        // A negative time would sort after every other; none is stored.
        for item in self.db.iterator_cf(events_cf, IteratorMode::Start) {
            let (key, _) = item.context("cannot read the endpoint events")?;
            let Some(received) = be_i64(&key) else {
                continue;
            };
            if !(0..=cutoff).contains(&received) {
                break;
            }
            batch.delete_cf(events_cf, &key);
            expired.events += 1;
            write(&mut batch, EXPIRY_BATCH_LEN)?;
        }
        write(&mut batch, 1)?;
        Ok(expired)
    }

    /// Blocks every endpoint of `endpoint_ids` at `now_ns`, nanoseconds since
    /// the Unix epoch, in one synced write; returns once the write is on disk.
    /// An endpoint already blocked keeps the time it was first blocked at.
    ///
    /// It waits for an event append in progress, and holds off new ones,
    /// until the blocks are stored: once it returns, every event of those
    /// endpoints stored before is on disk, and none is stored after.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read or written; then
    /// nothing was written.
    pub(crate) fn block_endpoints(&self, endpoint_ids: &[Uuid], now_ns: i64) -> Result<()> {
        let cf = self.get_cf_handle(ENDPOINT_BLOCKED_CF)?;
        let _write = BLOCK_WRITE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Taken after `BLOCK_WRITE`, which an append never takes.
        let _appends = EVENT_APPEND
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut batch = WriteBatch::default();
        for endpoint_id in endpoint_ids {
            if self.endpoint_blocked_at(*endpoint_id)?.is_none() {
                batch.put_cf(cf, endpoint_id.as_bytes(), now_ns.to_be_bytes());
            }
        }
        if batch.is_empty() {
            return Ok(());
        }
        // The deletion that follows the block, and REview's removal of the
        // endpoint from its own tables, rely on it holding after a crash. The
        // database flushes its WAL only when asked (`manual_wal_flush`), so
        // only a synced write is on disk by the time the request is answered.
        // The cost is one disk round trip per customer data deletion request
        // naming endpoints.
        self.db
            .write_opt(batch, &synced())
            .context("cannot write the endpoint blocks")
    }

    /// Returns when `endpoint_id` was blocked, in nanoseconds since the Unix
    /// epoch, or `None` when it is not blocked.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read or the value
    /// stored is not 8 bytes long.
    pub(crate) fn endpoint_blocked_at(&self, endpoint_id: Uuid) -> Result<Option<i64>> {
        let cf = self.get_cf_handle(ENDPOINT_BLOCKED_CF)?;
        let Some(value) = self
            .db
            .get_pinned_cf(cf, endpoint_id.as_bytes())
            .context("cannot read the endpoint blocks")?
        else {
            return Ok(None);
        };
        let bytes: [u8; 8] = value.as_ref().try_into().map_err(|_| {
            anyhow!(
                "the blocked time of endpoint {endpoint_id} is {} bytes long, not 8",
                value.len()
            )
        })?;
        Ok(Some(i64::from_be_bytes(bytes)))
    }

    /// Returns whether `endpoint_id` is blocked.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read. A value of the
    /// wrong length still means blocked.
    pub(crate) fn is_endpoint_blocked(&self, endpoint_id: Uuid) -> Result<bool> {
        let cf = self.get_cf_handle(ENDPOINT_BLOCKED_CF)?;
        Ok(self
            .db
            .get_pinned_cf(cf, endpoint_id.as_bytes())
            .context("cannot read the endpoint blocks")?
            .is_some())
    }

    /// Returns whether `endpoint_id` is blocked, taking it as blocked when
    /// that cannot be read: a block cannot be lifted, and one that cannot be
    /// read may be there. `refusal` says, for the log, what is refused then.
    pub(crate) fn is_endpoint_blocked_or_unreadable(
        &self,
        endpoint_id: Uuid,
        refusal: &str,
    ) -> bool {
        blocked_unless_read(endpoint_id, self.is_endpoint_blocked(endpoint_id), refusal)
    }

    /// Returns whether the endpoint entry's own column families hold anything
    /// of any endpoint of `endpoint_ids`: its last received time, a stream
    /// state, a loss record under any `entry_id`, or an event.
    ///
    /// Neither the stream, the loss nor the event keys start with the
    /// endpoint id, so those column families are read whole, once each for
    /// all of `endpoint_ids`.
    ///
    /// # Errors
    ///
    /// Returns an error if a column family cannot be read, or a loss or event
    /// entry in it is malformed.
    pub(crate) fn holds_endpoint_data(&self, endpoint_ids: &[Uuid]) -> Result<bool> {
        if endpoint_ids.is_empty() {
            return Ok(false);
        }
        let last_received_cf = self.get_cf_handle(ENDPOINT_LAST_RECEIVED_CF)?;
        for endpoint_id in endpoint_ids {
            if self
                .db
                .get_pinned_cf(last_received_cf, endpoint_id.as_bytes())
                .context("cannot read the endpoint last received times")?
                .is_some()
            {
                return Ok(true);
            }
        }
        let endpoint_ids: HashSet<Uuid> = endpoint_ids.iter().copied().collect();
        Ok(!self
            .endpoint_stream_keys_of(&endpoint_ids, Some(1))?
            .is_empty()
            || !self
                .endpoint_loss_keys_of(&endpoint_ids, Some(1))?
                .is_empty()
            || !self
                .endpoint_event_keys_of(&endpoint_ids, Some(1))?
                .is_empty())
    }

    /// Deletes every loss record of every endpoint of `endpoint_ids` under
    /// every `entry_id`, every event about them and their last received
    /// times, in one write. Deleting what is already gone succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if a column family cannot be read or written, or a
    /// loss or event entry in it is malformed; then nothing was deleted.
    pub(crate) fn delete_endpoint_history(&self, endpoint_ids: &[Uuid]) -> Result<()> {
        if endpoint_ids.is_empty() {
            return Ok(());
        }
        let losses_cf = self.get_cf_handle(ENDPOINT_LOSSES_CF)?;
        let events_cf = self.get_cf_handle(ENDPOINT_EVENTS_CF)?;
        let last_received_cf = self.get_cf_handle(ENDPOINT_LAST_RECEIVED_CF)?;
        let ids: HashSet<Uuid> = endpoint_ids.iter().copied().collect();
        let mut batch = WriteBatch::default();
        for key in self.endpoint_loss_keys_of(&ids, None)? {
            batch.delete_cf(losses_cf, key);
        }
        for key in self.endpoint_event_keys_of(&ids, None)? {
            batch.delete_cf(events_cf, key);
        }
        for endpoint_id in endpoint_ids {
            batch.delete_cf(last_received_cf, endpoint_id.as_bytes());
        }
        self.db
            .write(batch)
            .context("cannot delete the endpoint losses, events and last received times")
    }

    /// Deletes the state of every stream of every endpoint of `endpoint_ids`,
    /// under every `entry_id`, in one write. Deleting what is already gone
    /// succeeds.
    ///
    /// It must be called holding the `ReceiverStream` lock, so that no batch
    /// write interleaves with it.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read or written; then
    /// nothing was deleted.
    pub(crate) fn delete_endpoint_streams(&self, endpoint_ids: &[Uuid]) -> Result<()> {
        if endpoint_ids.is_empty() {
            return Ok(());
        }
        let cf = self.get_cf_handle(ENDPOINT_STREAMS_CF)?;
        let ids: HashSet<Uuid> = endpoint_ids.iter().copied().collect();
        let mut batch = WriteBatch::default();
        for key in self.endpoint_stream_keys_of(&ids, None)? {
            batch.delete_cf(cf, key);
        }
        self.db
            .write(batch)
            .context("cannot delete the endpoint stream states")
    }

    /// Returns the keys of the stream states of the endpoints of
    /// `endpoint_ids` under every `entry_id`, at most `limit` of them when
    /// one is given. A key of another length is no stream state.
    fn endpoint_stream_keys_of(
        &self,
        endpoint_ids: &HashSet<Uuid>,
        limit: Option<usize>,
    ) -> Result<Vec<Box<[u8]>>> {
        let cf = self.get_cf_handle(ENDPOINT_STREAMS_CF)?;
        let mut keys = Vec::new();
        for item in self.db.iterator_cf(cf, IteratorMode::Start) {
            if limit.is_some_and(|limit| keys.len() >= limit) {
                break;
            }
            let (key, _) = item.context("cannot read the endpoint streams")?;
            let endpoint_id = (key.len() == STREAM_KEY_LEN)
                .then(|| key.get(16..32))
                .flatten()
                .and_then(|bytes| Uuid::from_slice(bytes).ok());
            if endpoint_id.is_some_and(|id| endpoint_ids.contains(&id)) {
                keys.push(key);
            }
        }
        Ok(keys)
    }

    /// Returns the keys of the loss records of the endpoints of
    /// `endpoint_ids` under every `entry_id`, at most `limit` of them when
    /// one is given.
    fn endpoint_loss_keys_of(
        &self,
        endpoint_ids: &HashSet<Uuid>,
        limit: Option<usize>,
    ) -> Result<Vec<Box<[u8]>>> {
        let cf = self.get_cf_handle(ENDPOINT_LOSSES_CF)?;
        let mut keys = Vec::new();
        for item in self.db.iterator_cf(cf, IteratorMode::Start) {
            if limit.is_some_and(|limit| keys.len() >= limit) {
                break;
            }
            let (key, value) = item.context("cannot read the endpoint losses")?;
            if endpoint_ids.contains(&decode_loss(&key, &value)?.endpoint_id) {
                keys.push(key);
            }
        }
        Ok(keys)
    }

    /// Returns the keys of the events about the endpoints of `endpoint_ids`,
    /// at most `limit` of them when one is given.
    fn endpoint_event_keys_of(
        &self,
        endpoint_ids: &HashSet<Uuid>,
        limit: Option<usize>,
    ) -> Result<Vec<Box<[u8]>>> {
        let cf = self.get_cf_handle(ENDPOINT_EVENTS_CF)?;
        let mut keys = Vec::new();
        for item in self.db.iterator_cf(cf, IteratorMode::Start) {
            if limit.is_some_and(|limit| keys.len() >= limit) {
                break;
            }
            let (key, value) = item.context("cannot read the endpoint events")?;
            if endpoint_ids.contains(&decode_event(&key, &value)?.endpoint_id) {
                keys.push(key);
            }
        }
        Ok(keys)
    }

    /// Returns the endpoint ids stored with customer `customer_id`'s data
    /// deletion job, or `None` when none are stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be read or the value is
    /// not a whole number of endpoint ids.
    pub(crate) fn endpoint_deletion_job(&self, customer_id: u32) -> Result<Option<Vec<Uuid>>> {
        let cf = self.get_cf_handle(ENDPOINT_DELETION_JOBS_CF)?;
        let Some(value) = self
            .db
            .get_pinned_cf(cf, customer_id.to_be_bytes())
            .context("cannot read the endpoint ids of the customer deletion jobs")?
        else {
            return Ok(None);
        };
        let (ids, rest) = value.as_chunks::<16>();
        if !rest.is_empty() {
            bail!(
                "the endpoint ids of customer {customer_id}'s deletion job are {} bytes long, \
                 not a multiple of 16",
                value.len()
            );
        }
        Ok(Some(ids.iter().copied().map(Uuid::from_bytes).collect()))
    }

    /// Stores `endpoint_ids` as the endpoint ids of customer `customer_id`'s
    /// data deletion job, replacing any stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be written.
    pub(crate) fn put_endpoint_deletion_job(
        &self,
        customer_id: u32,
        endpoint_ids: &[Uuid],
    ) -> Result<()> {
        let cf = self.get_cf_handle(ENDPOINT_DELETION_JOBS_CF)?;
        let value: Vec<u8> = endpoint_ids
            .iter()
            .flat_map(|id| id.as_bytes().iter().copied())
            .collect();
        self.db
            .put_cf(cf, customer_id.to_be_bytes(), value)
            .context("cannot write the endpoint ids of a customer deletion job")
    }

    /// Forgets the endpoint ids of customer `customer_id`'s data deletion job.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be written.
    pub(crate) fn delete_endpoint_deletion_job(&self, customer_id: u32) -> Result<()> {
        let cf = self.get_cf_handle(ENDPOINT_DELETION_JOBS_CF)?;
        self.db
            .delete_cf(cf, customer_id.to_be_bytes())
            .context("cannot delete the endpoint ids of a customer deletion job")
    }
}

/// Returns what `read` says of whether `endpoint_id` is blocked, or `true`
/// when it could not be read, logging why and that `refusal` follows.
fn blocked_unless_read(endpoint_id: Uuid, read: Result<bool>, refusal: &str) -> bool {
    read.unwrap_or_else(|e| {
        error!("Endpoint {endpoint_id}: {e:#}; {refusal}");
        true
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::DbOptions;

    #[test]
    fn the_entry_id_is_stored_and_survives_reopening() {
        let dir = tempfile::tempdir().expect("tempdir");
        let entry_id = Uuid::from_u128(0x1234);
        {
            let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
            assert_eq!(db.endpoint_entry_id().expect("read"), None);
            db.replace_endpoint_entry_id(entry_id, None).expect("write");
            assert_eq!(db.endpoint_entry_id().expect("read"), Some(entry_id));
            assert_eq!(
                db.get_cf_for_test(ENDPOINT_ENTRY_CF, b"entry_id")
                    .expect("raw read")
                    .as_deref(),
                Some(entry_id.as_bytes().as_slice()),
                "the value is the UUID's 16 bytes"
            );
            db.shutdown().expect("shut down");
        }
        let db = Database::open(dir.path(), &DbOptions::default()).expect("reopen");
        assert_eq!(db.endpoint_entry_id().expect("read"), Some(entry_id));
    }

    /// What a crash leaves is what is in the files: the copy is taken while
    /// the database is open, with nothing flushed or shut down, and holds the
    /// `entry_id` the write acknowledged.
    #[test]
    fn the_entry_id_is_on_disk_once_its_write_returns() {
        let dir = tempfile::tempdir().expect("tempdir");
        let crashed = tempfile::tempdir().expect("tempdir");
        let entry_id = Uuid::from_u128(0x5678);
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        db.replace_endpoint_entry_id(entry_id, None).expect("write");
        for file in std::fs::read_dir(dir.path()).expect("list the database files") {
            let file = file.expect("a database file");
            if file.file_type().expect("its type").is_file() {
                std::fs::copy(file.path(), crashed.path().join(file.file_name()))
                    .expect("copy a database file");
            }
        }
        let recovered = Database::open(crashed.path(), &DbOptions::default()).expect("recover");
        assert_eq!(recovered.endpoint_entry_id().expect("read"), Some(entry_id));
        drop(db);
    }

    #[test]
    fn a_malformed_entry_id_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        db.put_cf_for_test(ENDPOINT_ENTRY_CF, b"entry_id", b"short")
            .expect("raw write");
        assert!(db.endpoint_entry_id().is_err());
    }

    #[test]
    fn a_stream_key_of_another_length_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let entry_id = Uuid::from_u128(0x1234);
        let mut key = entry_id.as_bytes().to_vec();
        key.extend_from_slice(&[0; 16]);
        db.put_cf_for_test(ENDPOINT_STREAMS_CF, &key, b"state")
            .expect("raw write");
        let error = db
            .endpoint_streams(entry_id)
            .expect_err("a 32-byte stream key");
        assert!(
            error.to_string().contains("32 bytes long"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn duplicate_keys_in_one_nanosecond_take_successive_sequence_numbers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let endpoint_id = Uuid::from_u128(0xabcd);
        let other = Uuid::from_u128(0xabce);
        let event = DuplicateKeyEvent {
            spki_sha256: [9; 32],
            addresses: vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
            replacements: 3,
        };
        let at = 1_700_000_000_000_000_000_i64;
        assert_eq!(
            db.append_endpoint_duplicate_key(at, endpoint_id, &event)
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            db.append_endpoint_duplicate_key(at, endpoint_id, &event)
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            db.append_endpoint_duplicate_key(at, other, &event).unwrap(),
            Some(0)
        );
        assert_eq!(
            db.append_endpoint_duplicate_key(at + 1, endpoint_id, &event)
                .unwrap(),
            Some(0)
        );

        let mut expected_key = Vec::new();
        expected_key.extend_from_slice(&at.to_be_bytes());
        expected_key.extend_from_slice(endpoint_id.as_bytes());
        expected_key.extend_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            endpoint_event_key(at, endpoint_id, 1).as_slice(),
            expected_key
        );
        let stored = db
            .get_cf_for_test(ENDPOINT_EVENTS_CF, &expected_key)
            .unwrap()
            .expect("the second event is stored under sequence 1");
        let decoded: DuplicateKeyEvent = bincode::deserialize(&stored).unwrap();
        assert_eq!(decoded, event);
    }

    const DAY_NS: i64 = 24 * 60 * 60 * 1_000_000_000;

    /// Writes a loss record of `from..=to` in `stream` of `endpoint_id` under
    /// `entry_id`, received at `received_ns`.
    fn write_loss(
        db: &Database,
        entry_id: Uuid,
        (endpoint_id, stream): (Uuid, Uuid),
        (from, to): (u64, u64),
        (reason, detail): (LossReason, &str),
        received_ns: i64,
    ) {
        db.write_endpoint_batch(EndpointBatch {
            entry_id,
            received_ns,
            changes: vec![EndpointChange::Loss {
                endpoint_id,
                stream,
                from,
                to,
                reason,
                detail: detail.to_owned(),
            }],
            received_from: Vec::new(),
        })
        .expect("write a loss");
    }

    fn duplicate_key(replacements: u64) -> DuplicateKeyEvent {
        DuplicateKeyEvent {
            spki_sha256: [7; 32],
            addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            replacements,
        }
    }

    #[test]
    fn reason_codes_round_trip() {
        for reason in [
            LossReason::Dropped,
            LossReason::LostOnReset,
            LossReason::ConversionFailure,
        ] {
            assert_eq!(LossReason::from_code(reason.code()), Some(reason));
        }
        assert_eq!(LossReason::from_code(3), None);
    }

    #[test]
    fn losses_since_are_read_back_under_every_entry_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let (old_entry, entry) = (Uuid::from_u128(0x10), Uuid::from_u128(0x20));
        let ids = (Uuid::from_u128(0x1), Uuid::from_u128(0x2));
        let since = 1_000_i64;
        write_loss(
            &db,
            entry,
            ids,
            (1, 4),
            (LossReason::Dropped, "queue_full"),
            since - 1,
        );
        write_loss(
            &db,
            entry,
            ids,
            (5, 9),
            (LossReason::Dropped, "queue_full"),
            since,
        );
        write_loss(
            &db,
            entry,
            ids,
            (10, 10),
            (LossReason::LostOnReset, ""),
            since + 1,
        );
        write_loss(
            &db,
            old_entry,
            ids,
            (11, 11),
            (LossReason::ConversionFailure, "bad image path"),
            since + 2,
        );

        let mut losses = db.endpoint_losses_since(since).expect("read");
        losses.sort_unstable_by_key(|loss| loss.received_ns);
        let expected = |entry_id, from, to, reason, detail: &str, received_ns| StoredLoss {
            entry_id,
            endpoint_id: ids.0,
            stream: ids.1,
            from,
            to,
            reason,
            detail: detail.to_owned(),
            received_ns,
        };
        assert_eq!(
            losses,
            vec![
                expected(entry, 5, 9, LossReason::Dropped, "queue_full", since),
                expected(entry, 10, 10, LossReason::LostOnReset, "", since + 1),
                expected(
                    old_entry,
                    11,
                    11,
                    LossReason::ConversionFailure,
                    "bad image path",
                    since + 2
                ),
            ]
        );
        assert_eq!(db.endpoint_losses_since(-1).expect("read").len(), 4);
        assert_eq!(db.endpoint_losses_since(i64::MIN).expect("read").len(), 4);
        assert_eq!(
            db.endpoint_losses_since(since + 3).expect("read"),
            Vec::new()
        );
    }

    #[test]
    fn a_loss_with_an_unknown_reason_code_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let mut key = endpoint_loss_key(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            1,
            2,
            LossReason::Dropped,
            5,
        );
        key[LOSS_KEY_LEN - 9] = 9;
        db.put_cf_for_test(ENDPOINT_LOSSES_CF, &key, b"")
            .expect("raw write");
        let error = db.endpoint_losses_since(0).expect_err("reason code 9");
        assert!(error.to_string().contains("code 9"), "{error}");
    }

    /// Each reader reports a malformed entry as an error naming what is wrong
    /// with it, rather than skipping it or returning a partial list.
    #[test]
    fn malformed_entries_are_errors() {
        type Read = fn(&Database) -> Result<()>;
        /// A column family, a raw key and value, the reader, and what its
        /// error must say.
        type Case<'a> = (&'a str, &'a [u8], &'a [u8], Read, &'a str);

        let loss_key = endpoint_loss_key(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            1,
            2,
            LossReason::ConversionFailure,
            5,
        );
        let event_key = endpoint_event_key(5, Uuid::from_u128(1), 0);
        let endpoint_id = Uuid::from_u128(1);
        let read_losses: Read = |db| db.endpoint_losses_since(0).map(drop);
        let read_events: Read = |db| db.endpoint_events_since(0).map(drop);
        let read_last: Read = |db| db.endpoint_last_received(None, 10).map(drop);
        let cases: [Case<'_>; 6] = [
            (ENDPOINT_LOSSES_CF, b"short", b"", read_losses, "bytes long"),
            (ENDPOINT_LOSSES_CF, &loss_key, &[0xff], read_losses, "UTF-8"),
            (ENDPOINT_EVENTS_CF, &[0; 9], b"", read_events, "bytes long"),
            (ENDPOINT_EVENTS_CF, &event_key, &[1], read_events, "decode"),
            (
                ENDPOINT_LAST_RECEIVED_CF,
                b"abc",
                &[0; 8],
                read_last,
                "not 16",
            ),
            (
                ENDPOINT_LAST_RECEIVED_CF,
                endpoint_id.as_bytes(),
                &[0; 3],
                read_last,
                "not 8",
            ),
        ];
        for (cf, key, value, read, expected) in cases {
            let dir = tempfile::tempdir().expect("tempdir");
            let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
            db.put_cf_for_test(cf, key, value).expect("raw write");
            let error = read(&db).expect_err(expected);
            assert!(format!("{error:#}").contains(expected), "{cf}: {error:#}");
        }
    }

    /// An event key with a negative received time, which sorts after every
    /// other, is neither returned nor expired, and a key too short to carry a
    /// received time is left alone by the expiry.
    #[test]
    fn events_outside_the_received_time_range_are_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let endpoint_id = Uuid::from_u128(1);
        let value = bincode::serialize(&duplicate_key(1)).expect("serialize");
        let negative = endpoint_event_key(-1, endpoint_id, 0);
        let short = [0_u8; 3];
        db.put_cf_for_test(ENDPOINT_EVENTS_CF, &negative, &value)
            .expect("raw write");
        db.put_cf_for_test(ENDPOINT_EVENTS_CF, &short, b"")
            .expect("raw write");
        db.append_endpoint_duplicate_key(5, endpoint_id, &duplicate_key(2))
            .unwrap();

        let events = db.endpoint_events_since(0).expect("read");
        assert_eq!(
            events.iter().map(|e| e.received_ns).collect::<Vec<_>>(),
            vec![5]
        );

        let expired = db
            .expire_endpoint_history(1_800_000_000_000_000_000)
            .expect("expire");
        assert_eq!(expired.events, 1);
        for key in [&negative[..], &short[..]] {
            assert!(
                db.get_cf_for_test(ENDPOINT_EVENTS_CF, key)
                    .expect("read")
                    .is_some(),
                "{key:?} is kept"
            );
        }
    }

    #[test]
    fn events_since_are_read_back_in_key_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let (first, second) = (Uuid::from_u128(0xa), Uuid::from_u128(0xb));
        let since = 5_000_i64;
        db.append_endpoint_duplicate_key(since - 1, first, &duplicate_key(1))
            .unwrap();
        db.append_endpoint_duplicate_key(since, second, &duplicate_key(2))
            .unwrap();
        db.append_endpoint_duplicate_key(since, first, &duplicate_key(3))
            .unwrap();
        db.append_endpoint_duplicate_key(since, first, &duplicate_key(4))
            .unwrap();
        db.append_endpoint_duplicate_key(since + 1, first, &duplicate_key(5))
            .unwrap();

        let events = db.endpoint_events_since(since).expect("read");
        let keys: Vec<_> = events
            .iter()
            .map(|event| {
                (
                    event.received_ns,
                    event.endpoint_id,
                    event.sequence,
                    event.event.replacements,
                )
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                (since, first, 0, 3),
                (since, first, 1, 4),
                (since, second, 0, 2),
                (since + 1, first, 0, 5),
            ]
        );
        assert_eq!(events.first().map(|e| &e.event), Some(&duplicate_key(3)));
        assert_eq!(db.endpoint_events_since(-5).expect("read").len(), 5);
        assert_eq!(db.endpoint_events_since(i64::MIN).expect("read").len(), 5);
        assert_eq!(
            db.endpoint_events_since(since + 2).expect("read"),
            Vec::new()
        );
    }

    #[test]
    fn last_received_times_are_paged_in_endpoint_id_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        for (n, at) in [(3_u128, 30_i64), (1, 10), (2, 20)] {
            db.write_endpoint_batch(EndpointBatch {
                entry_id: Uuid::from_u128(0x99),
                received_ns: at,
                changes: Vec::new(),
                received_from: vec![Uuid::from_u128(n)],
            })
            .expect("write");
        }
        let (page, more) = db.endpoint_last_received(None, 2).expect("read");
        assert_eq!(
            page,
            vec![(Uuid::from_u128(1), 10), (Uuid::from_u128(2), 20)]
        );
        assert!(more);
        let (page, more) = db
            .endpoint_last_received(Some(Uuid::from_u128(2)), 2)
            .expect("read");
        assert_eq!(page, vec![(Uuid::from_u128(3), 30)]);
        assert!(!more);
        let (page, more) = db
            .endpoint_last_received(Some(Uuid::from_u128(3)), 2)
            .expect("read");
        assert_eq!(page, Vec::new());
        assert!(!more);
        // An `after` that is not stored starts at the next id.
        let (page, _) = db
            .endpoint_last_received(Some(Uuid::from_u128(0)), 1)
            .expect("read");
        assert_eq!(page, vec![(Uuid::from_u128(1), 10)]);
    }

    #[test]
    fn expiry_deletes_losses_and_events_thirty_days_old_and_keeps_the_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let now = 1_800_000_000_000_000_000_i64;
        let line = now - 30 * DAY_NS;
        let ids = (Uuid::from_u128(0x1), Uuid::from_u128(0x2));
        let entry = Uuid::from_u128(0x10);
        for (n, at) in [(1_u64, line - 1), (2, line), (3, line + 1), (4, now)] {
            write_loss(&db, entry, ids, (n, n), (LossReason::LostOnReset, ""), at);
            db.append_endpoint_duplicate_key(at, ids.0, &duplicate_key(n))
                .unwrap();
        }
        db.write_endpoint_batch(EndpointBatch {
            entry_id: entry,
            received_ns: line - DAY_NS,
            changes: Vec::new(),
            received_from: vec![ids.0],
        })
        .expect("write a last received time");

        let expired = db.expire_endpoint_history(now).expect("expire");
        assert_eq!(
            expired,
            ExpiredEndpointHistory {
                losses: 2,
                events: 2
            }
        );
        let mut losses: Vec<_> = db
            .endpoint_losses_since(0)
            .unwrap()
            .into_iter()
            .map(|loss| loss.received_ns)
            .collect();
        losses.sort_unstable();
        assert_eq!(losses, vec![line + 1, now]);
        let events: Vec<_> = db
            .endpoint_events_since(0)
            .unwrap()
            .into_iter()
            .map(|event| event.received_ns)
            .collect();
        assert_eq!(events, vec![line + 1, now]);
        assert_eq!(
            db.endpoint_last_received(None, 10).unwrap(),
            (vec![(ids.0, line - DAY_NS)], false),
            "the last received times are not expired"
        );

        assert_eq!(
            db.expire_endpoint_history(now).expect("expire again"),
            ExpiredEndpointHistory::default()
        );
    }

    #[test]
    fn the_endpoint_families_are_not_raw_data_families() {
        for cf in [
            ENDPOINT_ENTRY_CF,
            ENDPOINT_EVENTS_CF,
            ENDPOINT_STREAMS_CF,
            ENDPOINT_LOSSES_CF,
            ENDPOINT_LAST_RECEIVED_CF,
            ENDPOINT_BLOCKED_CF,
            ENDPOINT_DELETION_JOBS_CF,
        ] {
            assert!(
                !crate::storage::RAW_DATA_COLUMN_FAMILY_NAMES.contains(&cf),
                "{cf}"
            );
        }
    }

    #[test]
    fn a_block_keeps_its_first_time_and_survives_reopening() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blocked = Uuid::from_u128(0xb1);
        let other = Uuid::from_u128(0xb2);
        {
            let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
            assert!(!db.is_endpoint_blocked(blocked).unwrap());
            db.block_endpoints(&[blocked], 10).expect("block");
            db.block_endpoints(&[blocked, other], 20)
                .expect("block again");
            assert_eq!(db.endpoint_blocked_at(blocked).unwrap(), Some(10));
            assert_eq!(db.endpoint_blocked_at(other).unwrap(), Some(20));
            db.block_endpoints(&[], 30).expect("block nothing");
            db.shutdown().expect("shut down");
        }
        let db = Database::open(dir.path(), &DbOptions::default()).expect("reopen");
        assert!(db.is_endpoint_blocked(blocked).unwrap());
        assert_eq!(db.endpoint_blocked_at(blocked).unwrap(), Some(10));
        assert!(!db.is_endpoint_blocked(Uuid::from_u128(0xb3)).unwrap());
    }

    /// An event of a blocked endpoint, or of one whose block cannot be read,
    /// is not stored; another endpoint's still is.
    #[test]
    fn an_event_of_a_blocked_endpoint_is_not_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let (blocked, unreadable, other) = (
            Uuid::from_u128(0xe1),
            Uuid::from_u128(0xe2),
            Uuid::from_u128(0xe3),
        );
        let event = DuplicateKeyEvent {
            spki_sha256: [7; 32],
            addresses: vec!["192.0.2.1".parse().unwrap()],
            replacements: 3,
        };
        db.block_endpoints(&[blocked], 10).expect("block");
        db.put_cf_for_test(ENDPOINT_BLOCKED_CF, unreadable.as_bytes(), &[0; 3])
            .expect("raw write");
        let at = 1_700_000_000_000_000_000_i64;
        for endpoint_id in [blocked, unreadable] {
            assert_eq!(
                db.append_endpoint_duplicate_key(at, endpoint_id, &event)
                    .unwrap(),
                None
            );
        }
        assert_eq!(
            db.append_endpoint_duplicate_key(at, other, &event).unwrap(),
            Some(0)
        );
        let events = db.endpoint_events_since(-1).expect("read");
        assert_eq!(
            events.iter().map(|e| e.endpoint_id).collect::<Vec<_>>(),
            [other]
        );
    }

    #[test]
    fn a_block_of_the_wrong_length_is_an_error_and_still_blocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let blocked = Uuid::from_u128(0xb5);
        db.put_cf_for_test(ENDPOINT_BLOCKED_CF, blocked.as_bytes(), &[0; 3])
            .expect("raw write");
        assert!(db.endpoint_blocked_at(blocked).is_err());
        assert!(db.is_endpoint_blocked(blocked).unwrap());
        assert!(db.is_endpoint_blocked_or_unreadable(blocked, "refusing"));
        assert!(!db.is_endpoint_blocked_or_unreadable(Uuid::from_u128(0xb6), "refusing"));
    }

    #[test]
    fn a_block_that_cannot_be_read_is_taken_as_a_block() {
        let endpoint_id = Uuid::from_u128(0xb7);
        assert!(blocked_unless_read(
            endpoint_id,
            Err(anyhow!("injected read failure")),
            "refusing"
        ));
        assert!(blocked_unless_read(endpoint_id, Ok(true), "refusing"));
        assert!(!blocked_unless_read(endpoint_id, Ok(false), "refusing"));
    }

    /// What a crash leaves is what is in the files: a block is on disk once
    /// its write returns.
    #[test]
    fn a_block_is_on_disk_once_its_write_returns() {
        let dir = tempfile::tempdir().expect("tempdir");
        let crashed = tempfile::tempdir().expect("tempdir");
        let blocked = Uuid::from_u128(0xb4);
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        db.block_endpoints(&[blocked], 1).expect("block");
        for file in std::fs::read_dir(dir.path()).expect("list the database files") {
            let file = file.expect("a database file");
            if file.file_type().expect("its type").is_file() {
                std::fs::copy(file.path(), crashed.path().join(file.file_name()))
                    .expect("copy a database file");
            }
        }
        let recovered = Database::open(crashed.path(), &DbOptions::default()).expect("recover");
        assert!(recovered.is_endpoint_blocked(blocked).unwrap());
        drop(db);
    }

    /// Writes one entry of each endpoint family of `endpoint_id`: a stream
    /// state and a loss under `entry_id`, an event and its last received
    /// time.
    fn write_history(db: &Database, entry_id: Uuid, endpoint_id: Uuid, at: i64) {
        let stream = Uuid::from_u128(0x5);
        db.write_endpoint_batch(EndpointBatch {
            entry_id,
            received_ns: at,
            changes: vec![
                EndpointChange::SetStream {
                    endpoint_id,
                    stream,
                    state: StoredStream {
                        a: 1,
                        last_stored: None,
                        closed_at_ns: None,
                    },
                },
                EndpointChange::Loss {
                    endpoint_id,
                    stream,
                    from: 1,
                    to: 1,
                    reason: LossReason::Dropped,
                    detail: "full".to_owned(),
                },
            ],
            received_from: vec![endpoint_id],
        })
        .expect("write a batch");
        db.append_endpoint_duplicate_key(at, endpoint_id, &duplicate_key(4))
            .expect("write an event");
    }

    #[test]
    fn an_endpoints_history_and_streams_are_deleted_under_every_entry_id_and_no_other() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let (deleted, kept) = (Uuid::from_u128(0xd1), Uuid::from_u128(0xd2));
        let (old_entry, entry) = (Uuid::from_u128(0xe1), Uuid::from_u128(0xe2));
        assert!(!db.holds_endpoint_data(&[deleted]).unwrap());
        write_history(&db, old_entry, deleted, 1);
        write_history(&db, entry, deleted, 2);
        write_history(&db, entry, kept, 3);
        assert!(db.holds_endpoint_data(&[deleted]).unwrap());

        for _ in 0..2 {
            db.delete_endpoint_history(&[deleted])
                .expect("delete the history");
            db.delete_endpoint_streams(&[deleted])
                .expect("delete the streams");
            assert!(!db.holds_endpoint_data(&[deleted]).unwrap());
            let losses = db.endpoint_losses_since(-1).unwrap();
            assert_eq!(losses.len(), 1);
            assert!(losses.iter().all(|loss| loss.endpoint_id == kept));
            let events = db.endpoint_events_since(-1).unwrap();
            assert_eq!(events.len(), 1);
            assert!(events.iter().all(|event| event.endpoint_id == kept));
            assert_eq!(db.endpoint_last_received(None, 10).unwrap().0, [(kept, 3)]);
            assert!(
                db.endpoint_streams(old_entry).unwrap().is_empty(),
                "under the earlier entry_id too"
            );
            let streams = db.endpoint_streams(entry).unwrap();
            assert_eq!(streams.len(), 1);
            assert_eq!(streams[0].0.0, kept);
            assert!(db.holds_endpoint_data(&[kept]).unwrap());
        }
    }

    #[test]
    fn each_endpoint_family_alone_is_data_of_the_endpoint() {
        let endpoint_id = Uuid::from_u128(0xf1);
        let entry_id = Uuid::from_u128(0xe1);
        let stream = Uuid::from_u128(0x5);
        let writes: [(&str, Vec<u8>, Vec<u8>); 4] = [
            (
                ENDPOINT_LAST_RECEIVED_CF,
                endpoint_id.as_bytes().to_vec(),
                1_i64.to_be_bytes().to_vec(),
            ),
            (
                ENDPOINT_STREAMS_CF,
                endpoint_stream_key(entry_id, endpoint_id, stream).to_vec(),
                b"state".to_vec(),
            ),
            (
                ENDPOINT_LOSSES_CF,
                endpoint_loss_key(entry_id, endpoint_id, stream, 1, 1, LossReason::Dropped, 1)
                    .to_vec(),
                Vec::new(),
            ),
            (
                ENDPOINT_EVENTS_CF,
                endpoint_event_key(1, endpoint_id, 0).to_vec(),
                bincode::serialize(&duplicate_key(4)).unwrap(),
            ),
        ];
        for (cf, key, value) in writes {
            let dir = tempfile::tempdir().expect("tempdir");
            let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
            db.put_cf_for_test(cf, &key, &value).expect("raw write");
            assert!(db.holds_endpoint_data(&[endpoint_id]).unwrap(), "{cf}");
            assert!(
                !db.holds_endpoint_data(&[Uuid::from_u128(0xf2)]).unwrap(),
                "{cf}"
            );
        }
    }

    /// A column family holding more than one entry of the endpoint is data
    /// of it as well, and nothing is data of no endpoint.
    #[test]
    fn several_entries_of_one_family_are_data_of_the_endpoint() {
        type TwoEntries = [(Vec<u8>, Vec<u8>); 2];
        let endpoint_id = Uuid::from_u128(0xf3);
        let (entry_id, stream) = (Uuid::from_u128(0xe1), Uuid::from_u128(0x5));
        let event = bincode::serialize(&duplicate_key(4)).unwrap();
        let writes: [(&str, TwoEntries); 3] = [
            (
                ENDPOINT_STREAMS_CF,
                [
                    (
                        endpoint_stream_key(entry_id, endpoint_id, stream).to_vec(),
                        b"state".to_vec(),
                    ),
                    (
                        endpoint_stream_key(Uuid::from_u128(0xe2), endpoint_id, stream).to_vec(),
                        b"state".to_vec(),
                    ),
                ],
            ),
            (
                ENDPOINT_LOSSES_CF,
                [1, 2].map(|from| {
                    let key = endpoint_loss_key(
                        entry_id,
                        endpoint_id,
                        stream,
                        from,
                        from,
                        LossReason::Dropped,
                        1,
                    );
                    (key.to_vec(), Vec::new())
                }),
            ),
            (
                ENDPOINT_EVENTS_CF,
                [1, 2].map(|at| {
                    (
                        endpoint_event_key(at, endpoint_id, 0).to_vec(),
                        event.clone(),
                    )
                }),
            ),
        ];
        for (cf, entries) in writes {
            let dir = tempfile::tempdir().expect("tempdir");
            let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
            for (key, value) in entries {
                db.put_cf_for_test(cf, &key, &value).expect("raw write");
            }
            assert!(db.holds_endpoint_data(&[endpoint_id]).unwrap(), "{cf}");
            assert!(!db.holds_endpoint_data(&[]).unwrap(), "{cf}");
            db.delete_endpoint_history(&[]).expect("delete no history");
            db.delete_endpoint_streams(&[]).expect("delete no streams");
            assert!(db.holds_endpoint_data(&[endpoint_id]).unwrap(), "{cf}");
        }
    }

    #[test]
    fn a_jobs_endpoint_ids_are_stored_replaced_and_forgotten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let ids = [Uuid::from_u128(1), Uuid::from_u128(2)];
        assert_eq!(db.endpoint_deletion_job(7).unwrap(), None);
        db.put_endpoint_deletion_job(7, &ids).expect("store");
        assert_eq!(db.endpoint_deletion_job(7).unwrap(), Some(ids.to_vec()));
        assert_eq!(db.endpoint_deletion_job(8).unwrap(), None);
        db.put_endpoint_deletion_job(7, &ids[1..]).expect("replace");
        assert_eq!(
            db.endpoint_deletion_job(7).unwrap(),
            Some(ids[1..].to_vec())
        );
        db.delete_endpoint_deletion_job(7).expect("forget");
        assert_eq!(db.endpoint_deletion_job(7).unwrap(), None);

        db.put_cf_for_test(ENDPOINT_DELETION_JOBS_CF, &9_u32.to_be_bytes(), &[0; 17])
            .expect("raw write");
        assert!(db.endpoint_deletion_job(9).is_err());
    }
}
