//! What the endpoint entry keeps in the store about itself and about the
//! endpoints that connect to it: the `entry_id` REview assigned the node, and
//! the events the entry records, such as a key held by two hosts.
//!
//! Neither column family is a raw-data one: retention there deletes by sensor
//! prefix, which neither key has.

use std::{net::IpAddr, sync::Mutex};

use anyhow::{Context, Result, anyhow, bail};
use rocksdb::WriteOptions;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::Database;

/// The column family holding the node's `entry_id`.
pub(crate) const ENDPOINT_ENTRY_CF: &str = "endpoint_entry";

/// The column family holding the events the endpoint entry records.
pub(crate) const ENDPOINT_EVENTS_CF: &str = "endpoint_events";

/// The one key of [`ENDPOINT_ENTRY_CF`].
const ENTRY_ID_KEY: &[u8] = b"entry_id";

/// The length of an [`ENDPOINT_EVENTS_CF`] key: the received time, the
/// endpoint id and the sequence number.
const EVENT_KEY_LEN: usize = 8 + 16 + 4;

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
    /// returns once it is on disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be written.
    pub(crate) fn put_endpoint_entry_id(&self, entry_id: Uuid) -> Result<()> {
        let cf = self.get_cf_handle(ENDPOINT_ENTRY_CF)?;
        // REview is told the update is applied once this returns, and every
        // `hello_ack` carries the value from then on, so a crash must not
        // bring back the one it replaced. The database flushes its WAL only
        // when asked (`manual_wal_flush`); a synced write writes the WAL out
        // and syncs it before returning. The cost is one disk round trip on a
        // write REview makes only when it assigns the node a new `entry_id`.
        let mut options = WriteOptions::default();
        options.set_sync(true);
        self.db
            .put_cf_opt(cf, ENTRY_ID_KEY, entry_id.as_bytes(), &options)
            .context("cannot write the endpoint entry_id")
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
            db.put_endpoint_entry_id(entry_id).expect("write");
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
        db.put_endpoint_entry_id(entry_id).expect("write");
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
