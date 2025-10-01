//! Raw event storage based on RocksDB.

mod migration;

use std::{
    collections::HashSet,
    marker::PhantomData,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(feature = "count_events")]
use anyhow::anyhow;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
pub use giganto_client::ingest::network::{Conn, Http, Ntlm, Smtp, Ssh, Tls};
use giganto_client::ingest::{
    Packet,
    log::{Log, OpLog, SecuLog},
    netflow::{Netflow5, Netflow9},
    network::{
        Bootp, DceRpc, Dhcp, Dns, Ftp, Kerberos, Ldap, MalformedDns, Mqtt, Nfs, Radius, Rdp, Smb,
    },
    statistics::Statistics,
    sysmon::{
        DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
        FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
        ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
    },
    timeseries::PeriodicTimeSeries,
};
pub use migration::migrate_data_dir;
pub use rocksdb::Direction;
#[cfg(debug_assertions)]
use rocksdb::properties;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, DBIteratorWithThreadMode, Options, ReadOptions,
};
use serde::de::DeserializeOwned;
use tokio::{select, sync::Notify, time};
use tracing::{debug, error, info, warn};

use crate::bincode_utils::decode_legacy;
use crate::{
    comm::ingest::implement::EventFilter,
    graphql::{NetworkFilter, RawEventFilter, TIMESTAMP_SIZE},
};

const RAW_DATA_COLUMN_FAMILY_NAMES: [&str; 41] = [
    "conn",
    "dns",
    "log",
    "http",
    "rdp",
    "periodic time series",
    "smtp",
    "ntlm",
    "kerberos",
    "ssh",
    "dce rpc",
    "statistics",
    "oplog",
    "packet",
    "ftp",
    "mqtt",
    "ldap",
    "tls",
    "smb",
    "nfs",
    "bootp",
    "dhcp",
    "radius",
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
    "netflow5",
    "netflow9",
    "seculog",
    "malformed_dns",
];
const META_DATA_COLUMN_FAMILY_NAMES: [&str; 1] = ["sensors"];

// Not a `sensor`+`time` event.
const NON_STANDARD_CFS: [&str; 6] = [
    "log",
    // "periodic time series", // Temporarily excluded until the retention logic for time series is clearly defined.
    "statistics",
    "packet",
    "seculog",
    "netflow5", // netflow5 + timestamp
    "netflow9", // netflow9 + timestamp
];
const USAGE_THRESHOLD: u64 = 95;
const USAGE_LOW: u64 = 85;

pub struct RetentionStores<'db, T> {
    pub standard_cfs: Vec<RawEventStore<'db, T>>,
    pub non_standard_cfs: Vec<RawEventStore<'db, T>>,
    pub op_log_cf: RawEventStore<'db, OpLog>,
}

impl<'db, T> RetentionStores<'db, T> {
    fn new(db: &'db Database) -> Result<Self> {
        Ok(RetentionStores {
            standard_cfs: Vec::new(),
            non_standard_cfs: Vec::new(),
            op_log_cf: db.op_log_store()?,
        })
    }
}

#[cfg(debug_assertions)]
pub struct CfProperties {
    pub estimate_live_data_size: u64,
    pub estimate_num_keys: u64,
    pub stats: String,
}

pub struct DbOptions {
    max_open_files: i32,
    max_mb_of_level_base: u64,
    num_of_thread: i32,
    max_subcompactions: u32,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self {
            max_open_files: 8000,
            max_mb_of_level_base: 512,
            num_of_thread: 8,
            max_subcompactions: 2,
        }
    }
}

impl DbOptions {
    pub fn new(
        max_open_files: i32,
        max_mb_of_level_base: u64,
        num_of_thread: i32,
        max_subcompactions: u32,
    ) -> Self {
        DbOptions {
            max_open_files,
            max_mb_of_level_base,
            num_of_thread,
            max_subcompactions,
        }
    }
}

#[derive(Clone)]
pub struct Database {
    db: Arc<DB>,
}

impl Database {
    /// Opens the database at the given path.
    pub fn open(path: &Path, db_options: &DbOptions) -> Result<Database> {
        let (db_opts, cf_opts) = rocksdb_options(db_options);
        let mut cfs_name: Vec<&str> = Vec::with_capacity(
            RAW_DATA_COLUMN_FAMILY_NAMES.len() + META_DATA_COLUMN_FAMILY_NAMES.len(),
        );
        cfs_name.extend(RAW_DATA_COLUMN_FAMILY_NAMES);
        cfs_name.extend(META_DATA_COLUMN_FAMILY_NAMES);

        let cfs = cfs_name
            .into_iter()
            .map(|name| ColumnFamilyDescriptor::new(name, cf_opts.clone()));

        let db = DB::open_cf_descriptors(&db_opts, path, cfs).context("cannot open database")?;
        Ok(Database { db: Arc::new(db) })
    }

    /// Shuts down the database, ensuring data integrity and consistency before exiting.
    ///
    /// This method flushes all in-memory changes to disk, writes all pending Write Ahead Log (WAL) entries to disk,
    /// and cancels all background work to safely shut down the database.
    pub fn shutdown(&self) -> Result<()> {
        self.db.flush()?;
        self.db.flush_wal(true)?;
        self.db.cancel_all_background_work(true);

        Ok(())
    }

    #[cfg(debug_assertions)]
    pub fn properties_cf(&self, cf_name: &str) -> Result<CfProperties> {
        let stats = if let Some(s) = self
            .db
            .property_value_cf(&self.get_cf_handle(cf_name)?, properties::STATS)?
        {
            s
        } else {
            "invalid".to_string()
        };
        let size = self
            .db
            .property_int_value_cf(
                &self.get_cf_handle(cf_name)?,
                properties::ESTIMATE_LIVE_DATA_SIZE,
            )?
            .unwrap_or_default();
        let num_keys = self
            .db
            .property_int_value_cf(&self.get_cf_handle(cf_name)?, properties::ESTIMATE_NUM_KEYS)?
            .unwrap_or_default();

        Ok(CfProperties {
            estimate_live_data_size: size,
            estimate_num_keys: num_keys,
            stats,
        })
    }

    /// Returns the raw event store for all types.
    pub fn retain_period_store(&self) -> Result<RetentionStores<'_, ()>> {
        let mut stores = RetentionStores::new(self)?;

        for store in RAW_DATA_COLUMN_FAMILY_NAMES {
            if NON_STANDARD_CFS.contains(&store) {
                let cf = self.get_cf_handle(store)?;
                stores
                    .non_standard_cfs
                    .push(RawEventStore::new(&self.db, cf));
            } else {
                let cf = self.get_cf_handle(store)?;
                stores.standard_cfs.push(RawEventStore::new(&self.db, cf));
            }
        }
        Ok(stores)
    }

    fn get_cf_handle(&self, cf_name: &str) -> Result<&ColumnFamily> {
        self.db
            .cf_handle(cf_name)
            .context("cannot access {cf_name} column family")
    }

    /// Creates a snapshot-based iterator for counting entries in a column family.
    /// This is intended for precise counting operations that require consistency.
    #[cfg(feature = "count_events")]
    pub fn count_cf_entries(&self, cf_name: &str) -> Result<i32> {
        let cf = self.get_cf_handle(cf_name)?;
        let snap = self.db.snapshot();

        let mut ro = rocksdb::ReadOptions::default();
        ro.set_total_order_seek(true);
        let iter = snap.iterator_cf_opt(cf, ro, rocksdb::IteratorMode::Start);

        let mut count = 0i32;
        for item in iter {
            item.context("failed to read from database")?;
            count = count
                .checked_add(1)
                .ok_or_else(|| anyhow!("count overflow"))?;
        }

        Ok(count)
    }

    /// Returns the raw event store for connections.
    pub fn conn_store(&self) -> Result<RawEventStore<'_, Conn>> {
        let cf = self.get_cf_handle("conn")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for dns.
    pub fn dns_store(&self) -> Result<RawEventStore<'_, Dns>> {
        let cf = self.get_cf_handle("dns")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for log.
    pub fn log_store(&self) -> Result<RawEventStore<'_, Log>> {
        let cf = self.get_cf_handle("log")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for http.
    pub fn http_store(&self) -> Result<RawEventStore<'_, Http>> {
        let cf = self.get_cf_handle("http")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for rdp.
    pub fn rdp_store(&self) -> Result<RawEventStore<'_, Rdp>> {
        let cf = self.get_cf_handle("rdp")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for periodic time series.
    pub fn periodic_time_series_store(&self) -> Result<RawEventStore<'_, PeriodicTimeSeries>> {
        let cf = self.get_cf_handle("periodic time series")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for smtp.
    pub fn smtp_store(&self) -> Result<RawEventStore<'_, Smtp>> {
        let cf = self.get_cf_handle("smtp")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for ntlm.
    pub fn ntlm_store(&self) -> Result<RawEventStore<'_, Ntlm>> {
        let cf = self.get_cf_handle("ntlm")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for kerberos.
    pub fn kerberos_store(&self) -> Result<RawEventStore<'_, Kerberos>> {
        let cf = self.get_cf_handle("kerberos")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for ssh.
    pub fn ssh_store(&self) -> Result<RawEventStore<'_, Ssh>> {
        let cf = self.get_cf_handle("ssh")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for dce rpc.
    pub fn dce_rpc_store(&self) -> Result<RawEventStore<'_, DceRpc>> {
        let cf = self.get_cf_handle("dce rpc")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for statistics
    pub fn statistics_store(&self) -> Result<RawEventStore<'_, Statistics>> {
        let cf = self.get_cf_handle("statistics")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for operation log
    pub fn op_log_store(&self) -> Result<RawEventStore<'_, OpLog>> {
        let cf = self.get_cf_handle("oplog")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for packet
    pub fn packet_store(&self) -> Result<RawEventStore<'_, Packet>> {
        let cf = self.get_cf_handle("packet")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for connection sensors
    pub fn sensors_store(&self) -> Result<SensorStore<'_>> {
        let cf = self.get_cf_handle("sensors")?;
        Ok(SensorStore { db: &self.db, cf })
    }

    /// Returns the store for Ftp
    pub fn ftp_store(&self) -> Result<RawEventStore<'_, Ftp>> {
        let cf = self.get_cf_handle("ftp")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for Mqtt
    pub fn mqtt_store(&self) -> Result<RawEventStore<'_, Mqtt>> {
        let cf = self.get_cf_handle("mqtt")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for ldap
    pub fn ldap_store(&self) -> Result<RawEventStore<'_, Ldap>> {
        let cf = self.get_cf_handle("ldap")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for tls
    pub fn tls_store(&self) -> Result<RawEventStore<'_, Tls>> {
        let cf = self.get_cf_handle("tls")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for smb
    pub fn smb_store(&self) -> Result<RawEventStore<'_, Smb>> {
        let cf = self.get_cf_handle("smb")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for nfs
    pub fn nfs_store(&self) -> Result<RawEventStore<'_, Nfs>> {
        let cf = self.get_cf_handle("nfs")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for bootp
    pub fn bootp_store(&self) -> Result<RawEventStore<'_, Bootp>> {
        let cf = self.get_cf_handle("bootp")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for dhcp
    pub fn dhcp_store(&self) -> Result<RawEventStore<'_, Dhcp>> {
        let cf = self.get_cf_handle("dhcp")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for radius
    pub fn radius_store(&self) -> Result<RawEventStore<'_, Radius>> {
        let cf = self.get_cf_handle("radius")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `ProcessCreate` (#1).
    pub fn process_create_store(&self) -> Result<RawEventStore<'_, ProcessCreate>> {
        let cf = self.get_cf_handle("process create")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileCreateTime` (#2).
    pub fn file_create_time_store(&self) -> Result<RawEventStore<'_, FileCreationTimeChanged>> {
        let cf = self.get_cf_handle("file create time")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `NetworkConnect` (#3).
    pub fn network_connect_store(&self) -> Result<RawEventStore<'_, NetworkConnection>> {
        let cf = self.get_cf_handle("network connect")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `ProcessTerminate` (#5).
    pub fn process_terminate_store(&self) -> Result<RawEventStore<'_, ProcessTerminated>> {
        let cf = self.get_cf_handle("process terminate")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `ImageLoad` (#7).
    pub fn image_load_store(&self) -> Result<RawEventStore<'_, ImageLoaded>> {
        let cf = self.get_cf_handle("image load")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileCreate` (#11).
    pub fn file_create_store(&self) -> Result<RawEventStore<'_, FileCreate>> {
        let cf = self.get_cf_handle("file create")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `RegistryValueSet` (#13).
    pub fn registry_value_set_store(&self) -> Result<RawEventStore<'_, RegistryValueSet>> {
        let cf = self.get_cf_handle("registry value set")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `RegistryKeyRename` (#14).
    pub fn registry_key_rename_store(&self) -> Result<RawEventStore<'_, RegistryKeyValueRename>> {
        let cf = self.get_cf_handle("registry key rename")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileCreateStreamHash` (#15).
    pub fn file_create_stream_hash_store(&self) -> Result<RawEventStore<'_, FileCreateStreamHash>> {
        let cf = self.get_cf_handle("file create stream hash")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `PipeEvent` (#17).
    pub fn pipe_event_store(&self) -> Result<RawEventStore<'_, PipeEvent>> {
        let cf = self.get_cf_handle("pipe event")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `DnsQuery` (#22).
    pub fn dns_query_store(&self) -> Result<RawEventStore<'_, DnsEvent>> {
        let cf = self.get_cf_handle("dns query")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileDelete` (#23).
    pub fn file_delete_store(&self) -> Result<RawEventStore<'_, FileDelete>> {
        let cf = self.get_cf_handle("file delete")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `ProcessTamper` (#25).
    pub fn process_tamper_store(&self) -> Result<RawEventStore<'_, ProcessTampering>> {
        let cf = self.get_cf_handle("process tamper")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileDeleteDetected` (#26).
    pub fn file_delete_detected_store(&self) -> Result<RawEventStore<'_, FileDeleteDetected>> {
        let cf = self.get_cf_handle("file delete detected")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for event `netflow5`.
    pub fn netflow5_store(&self) -> Result<RawEventStore<'_, Netflow5>> {
        let cf = self.get_cf_handle("netflow5")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for event `netflow9`.
    pub fn netflow9_store(&self) -> Result<RawEventStore<'_, Netflow9>> {
        let cf = self.get_cf_handle("netflow9")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for security log.
    pub fn secu_log_store(&self) -> Result<RawEventStore<'_, SecuLog>> {
        let cf = self.get_cf_handle("seculog")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for malformed dns.
    pub fn malformed_dns_store(&self) -> Result<RawEventStore<'_, MalformedDns>> {
        let cf = self.get_cf_handle("malformed dns")?;
        Ok(RawEventStore::new(&self.db, cf))
    }
}

pub struct RawEventStore<'db, T> {
    db: &'db DB,
    cf: &'db ColumnFamily,
    phantom: PhantomData<T>,
}

// RocksDB must manage thread safety for `ColumnFamily`.
// See rust-rocksdb/rust-rocksdb#407.
unsafe impl<T> Send for RawEventStore<'_, T> {}

impl<'db, T> RawEventStore<'db, T> {
    fn new(db: &'db DB, cf: &'db ColumnFamily) -> RawEventStore<'db, T> {
        RawEventStore {
            db,
            cf,
            phantom: PhantomData,
        }
    }

    pub fn append(&self, key: &[u8], raw_event: &[u8]) -> Result<()> {
        self.db.put_cf(self.cf, key, raw_event)?;
        Ok(())
    }

    pub fn delete(&self, key: &[u8]) -> Result<()> {
        self.db.delete_cf(self.cf, key)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.db.flush_wal(true)?;
        Ok(())
    }

    pub fn batched_multi_get_from_ts(
        &self,
        sensor: &str,
        times: &[DateTime<Utc>],
    ) -> Vec<(DateTime<Utc>, Vec<u8>)> {
        let mut times = times.to_vec();
        times.sort_unstable();
        let keys = times
            .iter()
            .map(|time| {
                StorageKey::builder()
                    .start_key(sensor)
                    .end_key(time.timestamp_nanos_opt().unwrap_or(i64::MAX))
                    .build()
                    .key()
            })
            .collect::<Vec<Vec<u8>>>();
        let keys = keys.iter().map(std::vec::Vec::as_slice);

        let result_vector: Vec<(DateTime<Utc>, Vec<u8>)> = times
            .iter()
            .zip(self.db.batched_multi_get_cf(&self.cf, keys, true))
            .filter_map(|(time, result_value)| {
                result_value
                    .ok()
                    .and_then(|val| val.map(|inner_val| (*time, inner_val.deref().to_vec())))
            })
            .collect();
        result_vector
    }

    pub fn batched_multi_get_with_sensor(
        &self,
        sensor: &str,
        timestamps: &[i64],
    ) -> Vec<(i64, String, Vec<u8>)> {
        let mut timestamps = timestamps.to_vec();
        timestamps.sort_unstable();
        let keys = timestamps
            .iter()
            .map(|timestamp| {
                StorageKey::builder()
                    .start_key(sensor)
                    .end_key(*timestamp)
                    .build()
                    .key()
            })
            .collect::<Vec<Vec<u8>>>();
        let keys = keys.iter().map(std::vec::Vec::as_slice);

        let result_vector: Vec<(i64, String, Vec<u8>)> = timestamps
            .iter()
            .zip(self.db.batched_multi_get_cf(&self.cf, keys, true))
            .filter_map(|(timestamp, result_value)| {
                result_value.ok().and_then(|val| {
                    val.map(|inner_val| {
                        (*timestamp, sensor.to_string(), inner_val.deref().to_vec())
                    })
                })
            })
            .collect();
        result_vector
    }
}

impl<'db, T: DeserializeOwned> RawEventStore<'db, T> {
    pub fn boundary_iter(
        &self,
        from: &[u8],
        to: &[u8],
        direction: Direction,
    ) -> BoundaryIter<'db, T> {
        let mut read_options = ReadOptions::default();
        match direction {
            Direction::Forward => {
                read_options.set_iterate_upper_bound(to);
            }
            Direction::Reverse => {
                read_options.set_iterate_lower_bound(to);
            }
        }
        BoundaryIter::new(self.db.iterator_cf_opt(
            self.cf,
            read_options,
            rocksdb::IteratorMode::From(from, direction),
        ))
    }

    pub fn iter_forward(&self) -> Iter<'db> {
        Iter::new(self.db.iterator_cf(self.cf, rocksdb::IteratorMode::Start))
    }
}

pub struct SensorStore<'db> {
    db: &'db DB,
    cf: &'db ColumnFamily,
}

impl SensorStore<'_> {
    /// Inserts a sensor name and its last active time.
    ///
    /// If the sensor already exists, its last active time is updated.
    pub fn insert(&self, name: &str, last_active: DateTime<Utc>) -> Result<()> {
        self.db.put_cf(
            self.cf,
            name,
            last_active
                .timestamp_nanos_opt()
                .unwrap_or(i64::MAX)
                .to_be_bytes(),
        )?;
        Ok(())
    }

    /// Returns the names of all sensors.
    pub fn names(&self) -> Vec<Vec<u8>> {
        self.db
            .iterator_cf(self.cf, rocksdb::IteratorMode::Start)
            .flatten()
            .map(|(key, _value)| key.to_vec())
            .collect()
    }

    /// Returns the sensor list that sent the data to ingest.
    pub fn sensor_list(&self) -> HashSet<String> {
        self.db
            .iterator_cf(self.cf, rocksdb::IteratorMode::Start)
            .flatten()
            .map(|(key, _)| String::from_utf8(key.to_vec()).expect("from utf8"))
            .collect()
    }
}

// RocksDB must manage thread safety for `ColumnFamily`.
// See rust-rocksdb/rust-rocksdb#407.
unsafe impl Send for SensorStore<'_> {}

#[allow(clippy::module_name_repetitions)]
#[derive(Default, Debug, Clone)]
pub struct StorageKey(Vec<u8>);

impl StorageKey {
    #[must_use]
    pub fn builder() -> StorageKeyBuilder {
        StorageKeyBuilder::default()
    }

    pub fn timestamp_builder() -> StorageTimestampKeyBuilder {
        StorageTimestampKeyBuilder::default()
    }

    pub fn key(self) -> Vec<u8> {
        self.0
    }
}

pub trait KeyExtractor {
    fn get_start_key(&self) -> &str;
    fn get_mid_key(&self) -> Option<Vec<u8>>;
    fn get_range_end_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>);
}

pub trait TimestampKeyExtractor {
    fn get_range_start_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>);
}

#[allow(clippy::module_name_repetitions)]
#[derive(Default, Debug, Clone)]
pub struct StorageKeyBuilder {
    pre_key: Vec<u8>,
}

impl StorageKeyBuilder {
    pub fn start_key(mut self, key: &str) -> Self {
        let start_key = key.as_bytes();
        self.pre_key.reserve(start_key.len() + 1);
        self.pre_key.extend_from_slice(start_key);
        self.pre_key.push(0);
        self
    }

    pub fn mid_key(mut self, key: Option<Vec<u8>>) -> Self {
        if let Some(mid_key) = key {
            self.pre_key.reserve(mid_key.len() + 1);
            self.pre_key.extend_from_slice(&mid_key);
            self.pre_key.push(0);
        }
        self
    }

    pub fn end_key(mut self, key: i64) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        self.pre_key.extend_from_slice(&key.to_be_bytes());
        self
    }

    pub fn lower_closed_bound_end_key(mut self, time: Option<DateTime<Utc>>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        let ns = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            0
        };
        self.pre_key.extend_from_slice(&ns.to_be_bytes());
        self
    }

    pub fn upper_open_bound_end_key(mut self, time: Option<DateTime<Utc>>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        let ns = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            i64::MAX
        };
        self.pre_key.extend_from_slice(&ns.to_be_bytes());
        self
    }

    pub fn upper_closed_bound_end_key(mut self, time: Option<DateTime<Utc>>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        if let Some(time) = time {
            let ns = time.timestamp_nanos_opt().unwrap_or(i64::MAX);
            if let Some(ns) = ns.checked_sub(1)
                && ns >= 0
            {
                self.pre_key.extend_from_slice(&ns.to_be_bytes());
                return self;
            }
        }
        self.pre_key.extend_from_slice(&i64::MAX.to_be_bytes());
        self
    }

    pub fn build(self) -> StorageKey {
        StorageKey(self.pre_key)
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Default, Debug, Clone)]
pub struct StorageTimestampKeyBuilder {
    pre_key: Vec<u8>,
}

impl StorageTimestampKeyBuilder {
    pub fn start_key(mut self, key: i64) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        self.pre_key.extend_from_slice(&key.to_be_bytes());
        self
    }

    pub fn mid_key(mut self, key: usize) -> Self {
        let mid_key = key.to_be_bytes();
        self.pre_key.reserve(mid_key.len());
        self.pre_key.extend_from_slice(&mid_key);
        self
    }

    pub fn lower_closed_bound_start_key(mut self, time: Option<DateTime<Utc>>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        let ns = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            0
        };
        self.pre_key.extend_from_slice(&ns.to_be_bytes());
        self
    }

    pub fn upper_open_bound_start_key(mut self, time: Option<DateTime<Utc>>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        let ns = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            i64::MAX
        };
        self.pre_key.extend_from_slice(&ns.to_be_bytes());
        self
    }

    pub fn upper_closed_bound_start_key(mut self, time: Option<DateTime<Utc>>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        if let Some(time) = time {
            let ns = time.timestamp_nanos_opt().unwrap_or(i64::MAX);
            if let Some(ns) = ns.checked_sub(1)
                && ns >= 0
            {
                self.pre_key.extend_from_slice(&ns.to_be_bytes());
                return self;
            }
        }
        self.pre_key.extend_from_slice(&i64::MAX.to_be_bytes());
        self
    }

    pub fn build(self) -> StorageKey {
        StorageKey(self.pre_key)
    }
}

pub type KeyValue<T> = (Box<[u8]>, T);
pub type RawValue = (Box<[u8]>, Box<[u8]>);

pub struct StatisticsIter<'d, T> {
    inner: BoundaryIter<'d, T>,
}

impl<'d, T> StatisticsIter<'d, T> {
    pub fn new(inner: BoundaryIter<'d, T>) -> Self {
        Self { inner }
    }
}

impl<T> Iterator for StatisticsIter<'_, T>
where
    T: DeserializeOwned,
{
    type Item = KeyValue<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(Ok(elem)) = self.inner.next() {
            return Some(elem);
        }
        None
    }
}

pub struct FilteredIter<'d, T> {
    inner: BoundaryIter<'d, T>,
    filter: &'d NetworkFilter,
}

impl<'d, T> FilteredIter<'d, T> {
    pub fn new(inner: BoundaryIter<'d, T>, filter: &'d NetworkFilter) -> Self {
        Self { inner, filter }
    }
}

impl<T> Iterator for FilteredIter<'_, T>
where
    T: DeserializeOwned + EventFilter,
{
    type Item = KeyValue<T>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(Ok(elem)) = self.inner.next() {
            if let Ok(true) = self.filter.check(
                elem.1.orig_addr(),
                elem.1.resp_addr(),
                elem.1.orig_port(),
                elem.1.resp_port(),
                elem.1.log_level(),
                elem.1.log_contents(),
                elem.1.text(),
                elem.1.sensor(),
                elem.1.agent_id(),
            ) {
                return Some(elem);
            }
        }
        None
    }
}

pub struct BoundaryIter<'d, T> {
    inner: DBIteratorWithThreadMode<'d, DB>,
    phantom: PhantomData<T>,
}

impl<'d, T> BoundaryIter<'d, T> {
    pub fn new(inner: DBIteratorWithThreadMode<'d, DB>) -> Self {
        Self {
            inner,
            phantom: PhantomData,
        }
    }
}

impl<T> Iterator for BoundaryIter<'_, T>
where
    T: DeserializeOwned,
{
    type Item = anyhow::Result<KeyValue<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| match item {
            Ok((key, value)) => decode_legacy::<T>(&value)
                .map(|value| (key, value))
                .map_err(Into::into),

            Err(e) => Err(e.into()),
        })
    }
}

pub struct Iter<'d> {
    inner: DBIteratorWithThreadMode<'d, DB>,
}

impl<'d> Iter<'d> {
    #[allow(dead_code)]
    pub fn new(inner: DBIteratorWithThreadMode<'d, DB>) -> Self {
        Self { inner }
    }
}

impl Iterator for Iter<'_> {
    type Item = anyhow::Result<RawValue>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| match item {
            Ok((key, value)) => Ok((key, value)),
            Err(e) => Err(e.into()),
        })
    }
}

#[allow(clippy::too_many_lines)]
pub async fn retain_periodically(
    interval: Duration,
    retention_period: Duration,
    db: Database,
    notify_shutdown: Arc<Notify>,
    running_flag: Arc<AtomicBool>,
) -> Result<()> {
    const DEFAULT_FROM_TIMESTAMP_NANOS: i64 = 61_000_000_000;
    const ONE_DAY_TIMESTAMP_NANOS: i64 = 86_400_000_000_000;

    let mut itv = time::interval(interval);
    let retention_duration = i64::try_from(retention_period.as_nanos())?;
    let from_timestamp = DEFAULT_FROM_TIMESTAMP_NANOS.to_be_bytes();
    loop {
        select! {
            _ = itv.tick() => {
                info!("Begin to cleanup the database based on retention period.");
                running_flag.store(true, Ordering::Relaxed);

                let now = Utc::now();
                let mut retention_timestamp = now
                    .timestamp_nanos_opt()
                    .unwrap_or(retention_duration)
                    - retention_duration;
                let mut usage_flag = false;

                if check_db_usage().await.0 {
                    info!(
                        "Disk usage is over {USAGE_THRESHOLD}%. \
                        Retention period is temporarily reduced."
                    );
                    retention_timestamp += ONE_DAY_TIMESTAMP_NANOS;
                    usage_flag = true;
                }

                loop {
                    let retention_timestamp_vec = retention_timestamp.to_be_bytes();
                    let sensors = db.sensors_store()?.names();
                    let all_store = db.retain_period_store()?;

                    for sensor in sensors {
                        let mut from: Vec<u8> = sensor.clone();
                        from.push(0x00);
                        from.extend_from_slice(&from_timestamp);

                        let mut to: Vec<u8> = sensor.clone();
                        to.push(0x00);
                        to.extend_from_slice(&retention_timestamp_vec);

                        for store in &all_store.standard_cfs {
                            store.flush()?;
                            if store
                                .db
                                .delete_file_in_range_cf(store.cf, &from, &to)
                                .is_ok()
                            {
                                store.flush()?;
                                if store.db.delete_range_cf(store.cf, &from, &to).is_ok() {
                                    store.db.compact_range_cf(store.cf, Some(&from), Some(&to));
                                }
                            } else {
                                warn!("Failed to delete file in range");
                            }
                        }

                        for store in &all_store.non_standard_cfs {
                            let iterator = store
                                .db
                                .prefix_iterator_cf(store.cf, sensor.clone())
                                .flatten();

                            for (key, _) in iterator {
                                let data_timestamp =
                                    i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);

                                if retention_timestamp > data_timestamp {
                                    if store.delete(&key).is_err() {
                                        warn!("Failed to delete data");
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            store.flush()?;
                        }
                    }

                    // Handle oplog deletion with timestamp-based range deletion
                    let mut from: Vec<u8> = from_timestamp.to_vec();
                    from.push(0x00);
                    from.extend_from_slice(&1_usize.to_be_bytes());

                    let mut to: Vec<u8> = retention_timestamp_vec.to_vec();
                    to.push(0x00);
                    to.extend_from_slice(&usize::MAX.to_be_bytes());

                    let store = &all_store.op_log_cf;
                    if store
                        .db
                        .delete_file_in_range_cf(store.cf, &from, &to)
                        .is_ok()
                    {
                        store.flush()?;
                        if store.db.delete_range_cf(store.cf, &from, &to).is_ok() {
                            store.db.compact_range_cf(store.cf, Some(&from), Some(&to));
                        }
                    } else {
                        warn!("Failed to delete file in range for operation log");
                    }
                    if check_db_usage().await.1 && usage_flag {
                        retention_timestamp += ONE_DAY_TIMESTAMP_NANOS;
                        if retention_timestamp > now.timestamp_nanos_opt().unwrap_or(0) {
                            warn!("cannot delete data to usage under {USAGE_LOW}");
                            break;
                        }
                    } else if usage_flag {
                        info!("Disk usage is under {USAGE_LOW}%");
                        break;
                    } else {
                        break;
                    }
                }
                info!("Database cleanup completed.");
                running_flag.store(false, Ordering::Relaxed);
            },
            () = notify_shutdown.notified() => {
                return Ok(());
            },
        }
    }
}

/// Returns the boolean of the disk usages over `USAGE_THRESHOLD` and `USAGE_LOW`.
async fn check_db_usage() -> (bool, bool) {
    let resource_usage = roxy::resource_usage().await;
    let total_disk_space = resource_usage
        .disk_used_bytes
        .saturating_add(resource_usage.disk_available_bytes);
    let usage = if total_disk_space == 0 {
        0
    } else {
        resource_usage.disk_used_bytes.saturating_mul(100) / total_disk_space
    };
    debug!("Disk usage: {usage}%");
    (usage > USAGE_THRESHOLD, usage > USAGE_LOW)
}

pub(crate) fn rocksdb_options(db_options: &DbOptions) -> (Options, Options) {
    let max_bytes = db_options.max_mb_of_level_base * 1024 * 1024;
    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    db_opts.set_max_open_files(db_options.max_open_files);
    db_opts.set_keep_log_file_num(10);
    db_opts.set_stats_dump_period_sec(3600);
    db_opts.set_max_total_wal_size(max_bytes);
    db_opts.set_manual_wal_flush(true);
    db_opts.increase_parallelism(db_options.num_of_thread);
    db_opts.set_max_subcompactions(db_options.max_subcompactions);

    let mut cf_opts = Options::default();
    cf_opts.set_write_buffer_size((max_bytes / 4).try_into().expect("u64 to usize"));
    cf_opts.set_max_bytes_for_level_base(max_bytes);
    cf_opts.set_target_file_size_base(max_bytes / 10);
    cf_opts.set_target_file_size_multiplier(10);
    cf_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
    cf_opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
    cf_opts.set_bottommost_zstd_max_train_bytes(0, true);

    (db_opts, cf_opts)
}

pub(crate) fn data_dir_to_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("db")
}

pub fn db_path_and_option(
    data_dir: &Path,
    max_open_files: i32,
    max_mb_of_level_base: u64,
    num_of_thread: i32,
    max_subcompactions: u32,
) -> (PathBuf, DbOptions) {
    let db_path = data_dir_to_db_path(data_dir);
    let db_options = DbOptions::new(
        max_open_files,
        max_mb_of_level_base,
        num_of_thread,
        max_subcompactions,
    );
    (db_path, db_options)
}

fn to_hms(dur: Duration) -> String {
    let total_sec = dur.as_secs();
    let hours = total_sec / 3600;
    let minutes = (total_sec % 3600) / 60;
    let seconds = total_sec % 60;

    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

pub fn repair_db(
    data_dir: &Path,
    max_open_files: i32,
    max_mb_of_level_base: u64,
    num_of_thread: i32,
    max_subcompactions: u32,
) {
    let (db_path, db_options) = db_path_and_option(
        data_dir,
        max_open_files,
        max_mb_of_level_base,
        num_of_thread,
        max_subcompactions,
    );
    let start = Instant::now();
    let (db_opts, _) = rocksdb_options(&db_options);
    info!("Starting DB repair");
    match DB::repair(&db_opts, db_path) {
        Ok(()) => info!("DB repair completed successfully"),
        Err(e) => error!("DB repair failed: {e}"),
    }
    let dur = start.elapsed();
    info!("DB repair duration: {}", to_hms(dur));
}
