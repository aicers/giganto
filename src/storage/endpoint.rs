//! What the endpoint entry keeps in the store about itself and about the
//! endpoints that connect to it: the `entry_id` REview assigned the node, the
//! events the entry records, such as a key held by two hosts, the state of
//! every telemetry stream, the records an endpoint reported lost or the entry
//! could not convert, and when each endpoint last sent records.
//!
//! None of these column families is a raw-data one: retention there deletes
//! by sensor prefix, which none of their keys has. The records themselves go
//! into the raw-data column family of their kind, under the endpoint id as
//! the sensor.

use std::{collections::HashSet, net::IpAddr, sync::Mutex};

use anyhow::{Context, Result, anyhow, bail};
use rocksdb::{ColumnFamily, Direction, IteratorMode, WriteBatch, WriteOptions};
use serde::{Deserialize, Serialize};
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

/// The one key of [`ENDPOINT_ENTRY_CF`].
const ENTRY_ID_KEY: &[u8] = b"entry_id";

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
/// sequence number.
static EVENT_APPEND: Mutex<()> = Mutex::new(());

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
    /// not yet used for that time and endpoint, and returns that number.
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
    ) -> Result<u32> {
        let cf = self.get_cf_handle(ENDPOINT_EVENTS_CF)?;
        let value = bincode::serialize(event).context("cannot serialize an endpoint event")?;
        let _append = EVENT_APPEND
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                return Ok(sequence);
            }
            let Some(next) = sequence.checked_add(1) else {
                bail!("every sequence number of an endpoint event time is taken");
            };
            sequence = next;
        }
    }
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
            0
        );
        assert_eq!(
            db.append_endpoint_duplicate_key(at, endpoint_id, &event)
                .unwrap(),
            1
        );
        assert_eq!(
            db.append_endpoint_duplicate_key(at, other, &event).unwrap(),
            0
        );
        assert_eq!(
            db.append_endpoint_duplicate_key(at + 1, endpoint_id, &event)
                .unwrap(),
            0
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

    #[test]
    fn the_endpoint_families_are_not_raw_data_families() {
        assert!(!crate::storage::RAW_DATA_COLUMN_FAMILY_NAMES.contains(&ENDPOINT_ENTRY_CF));
        assert!(!crate::storage::RAW_DATA_COLUMN_FAMILY_NAMES.contains(&ENDPOINT_EVENTS_CF));
    }
}
