//! Raw event storage based on RocksDB.

mod migration;

use std::{
    collections::HashSet,
    fs,
    marker::PhantomData,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
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

use crate::{
    comm::ingest::implement::EventFilter,
    graphql::{NetworkFilter, RawEventFilter, TIMESTAMP_SIZE},
};

const RAW_DATA_COLUMN_FAMILY_NAMES: [&str; 41] = [
    "conn",
    "dns",
    "malformed_dns",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseMode {
    Primary,
    Secondary,
}

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
            op_log_cf: db.raw_store_for("oplog")?,
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
    compression: bool,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self {
            max_open_files: 8000,
            max_mb_of_level_base: 512,
            num_of_thread: 8,
            max_subcompactions: 2,
            compression: true,
        }
    }
}

impl DbOptions {
    pub fn new(
        max_open_files: i32,
        max_mb_of_level_base: u64,
        num_of_thread: i32,
        max_subcompactions: u32,
        compression: bool,
    ) -> Self {
        DbOptions {
            max_open_files,
            max_mb_of_level_base,
            num_of_thread,
            max_subcompactions,
            compression,
        }
    }
}

#[derive(Clone)]
pub struct Database {
    db: Arc<DB>,
    mode: DatabaseMode,
}

macro_rules! impl_store {
    ($read_fn:ident, $write_fn:ident, $cf:literal, $ty:ty) => {
        pub fn $read_fn(&self) -> Result<ReadableRawEventStoreHandle<'_, $ty>> {
            self.readable_store_for($cf)
        }

        pub fn $write_fn(&self) -> Result<WritableRawEventStoreHandle<'_, $ty>> {
            self.writable_store_for($cf)
        }
    };
}

impl Database {
    /// Opens the database at the given path.
    pub fn open(path: &Path, db_options: &DbOptions) -> Result<Database> {
        Self::open_primary(path, db_options)
    }

    /// Opens the database at the given path with write access.
    pub fn open_primary(path: &Path, db_options: &DbOptions) -> Result<Database> {
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
        Ok(Database {
            db: Arc::new(db),
            mode: DatabaseMode::Primary,
        })
    }

    /// Opens the database as a secondary for read operations.
    pub fn open_secondary(
        primary_path: &Path,
        secondary_path: &Path,
        db_options: &DbOptions,
    ) -> Result<Database> {
        let (mut db_opts, cf_opts) = rocksdb_options(db_options);
        db_opts.set_max_open_files(-1);
        let mut cfs_name: Vec<&str> = Vec::with_capacity(
            RAW_DATA_COLUMN_FAMILY_NAMES.len() + META_DATA_COLUMN_FAMILY_NAMES.len(),
        );
        cfs_name.extend(RAW_DATA_COLUMN_FAMILY_NAMES);
        cfs_name.extend(META_DATA_COLUMN_FAMILY_NAMES);

        let cfs = cfs_name
            .into_iter()
            .map(|name| ColumnFamilyDescriptor::new(name, cf_opts.clone()));

        if let Some(parent) = secondary_path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        fs::create_dir_all(secondary_path)
            .with_context(|| format!("failed to create directory {}", secondary_path.display()))?;

        let db = DB::open_cf_descriptors_as_secondary(&db_opts, primary_path, secondary_path, cfs)
            .context("cannot open secondary database")?;
        Ok(Database {
            db: Arc::new(db),
            mode: DatabaseMode::Secondary,
        })
    }

    /// Shuts down the database, ensuring data integrity and consistency before exiting.
    ///
    /// This method flushes all in-memory changes to disk, writes all pending Write Ahead Log (WAL) entries to disk,
    /// and cancels all background work to safely shut down the database.
    pub fn shutdown(&self) -> Result<()> {
        if self.mode == DatabaseMode::Primary {
            self.db.flush()?;
            self.db.flush_wal(true)?;
        }
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
            let cf = self.get_cf_handle(store)?;
            let raw_store = RawEventStore::new(&self.db, cf);
            if NON_STANDARD_CFS.contains(&store) {
                stores.non_standard_cfs.push(raw_store);
            } else {
                stores.standard_cfs.push(raw_store);
            }
        }
        Ok(stores)
    }

    fn raw_store_for<T>(&self, cf_name: &str) -> Result<RawEventStore<'_, T>> {
        let cf = self.get_cf_handle(cf_name)?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    fn readable_store_for<'a, T: 'a + Sync>(
        &'a self,
        cf_name: &str,
    ) -> Result<ReadableRawEventStoreHandle<'a, T>> {
        let store = self.raw_store_for(cf_name)?;
        let handle: Box<dyn ReadableRawEventStore<'_, T> + '_> = match self.mode {
            DatabaseMode::Primary => Box::new(store),
            DatabaseMode::Secondary => Box::new(ReadOnlyRawEventStore::new(store)),
        };
        Ok(ReadableRawEventStoreHandle::new(handle))
    }

    fn writable_store_for<'a, T: 'a + Sync>(
        &'a self,
        cf_name: &str,
    ) -> Result<WritableRawEventStoreHandle<'a, T>> {
        if self.mode != DatabaseMode::Primary {
            bail!("write operations are not supported on secondary databases");
        }
        let store = self.raw_store_for(cf_name)?;
        Ok(WritableRawEventStoreHandle::new(Box::new(store)))
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

    impl_store!(conn_store, conn_store_writable, "conn", Conn);
    impl_store!(dns_store, dns_store_writable, "dns", Dns);
    impl_store!(
        malformed_dns_store,
        malformed_dns_store_writable,
        "malformed_dns",
        MalformedDns
    );
    impl_store!(log_store, log_store_writable, "log", Log);
    impl_store!(http_store, http_store_writable, "http", Http);
    impl_store!(rdp_store, rdp_store_writable, "rdp", Rdp);
    impl_store!(
        periodic_time_series_store,
        periodic_time_series_store_writable,
        "periodic time series",
        PeriodicTimeSeries
    );
    impl_store!(smtp_store, smtp_store_writable, "smtp", Smtp);
    impl_store!(ntlm_store, ntlm_store_writable, "ntlm", Ntlm);
    impl_store!(
        kerberos_store,
        kerberos_store_writable,
        "kerberos",
        Kerberos
    );
    impl_store!(ssh_store, ssh_store_writable, "ssh", Ssh);
    impl_store!(dce_rpc_store, dce_rpc_store_writable, "dce rpc", DceRpc);
    impl_store!(
        statistics_store,
        statistics_store_writable,
        "statistics",
        Statistics
    );
    impl_store!(op_log_store, op_log_store_writable, "oplog", OpLog);
    impl_store!(packet_store, packet_store_writable, "packet", Packet);
    impl_store!(ftp_store, ftp_store_writable, "ftp", Ftp);
    impl_store!(mqtt_store, mqtt_store_writable, "mqtt", Mqtt);
    impl_store!(ldap_store, ldap_store_writable, "ldap", Ldap);
    impl_store!(tls_store, tls_store_writable, "tls", Tls);
    impl_store!(smb_store, smb_store_writable, "smb", Smb);
    impl_store!(nfs_store, nfs_store_writable, "nfs", Nfs);
    impl_store!(bootp_store, bootp_store_writable, "bootp", Bootp);
    impl_store!(dhcp_store, dhcp_store_writable, "dhcp", Dhcp);
    impl_store!(radius_store, radius_store_writable, "radius", Radius);
    impl_store!(
        process_create_store,
        process_create_store_writable,
        "process create",
        ProcessCreate
    );
    impl_store!(
        file_create_time_store,
        file_create_time_store_writable,
        "file create time",
        FileCreationTimeChanged
    );
    impl_store!(
        network_connect_store,
        network_connect_store_writable,
        "network connect",
        NetworkConnection
    );
    impl_store!(
        process_terminate_store,
        process_terminate_store_writable,
        "process terminate",
        ProcessTerminated
    );
    impl_store!(
        image_load_store,
        image_load_store_writable,
        "image load",
        ImageLoaded
    );
    impl_store!(
        file_create_store,
        file_create_store_writable,
        "file create",
        FileCreate
    );
    impl_store!(
        registry_value_set_store,
        registry_value_set_store_writable,
        "registry value set",
        RegistryValueSet
    );
    impl_store!(
        registry_key_rename_store,
        registry_key_rename_store_writable,
        "registry key rename",
        RegistryKeyValueRename
    );
    impl_store!(
        file_create_stream_hash_store,
        file_create_stream_hash_store_writable,
        "file create stream hash",
        FileCreateStreamHash
    );
    impl_store!(
        pipe_event_store,
        pipe_event_store_writable,
        "pipe event",
        PipeEvent
    );
    impl_store!(
        dns_query_store,
        dns_query_store_writable,
        "dns query",
        DnsEvent
    );
    impl_store!(
        file_delete_store,
        file_delete_store_writable,
        "file delete",
        FileDelete
    );
    impl_store!(
        process_tamper_store,
        process_tamper_store_writable,
        "process tamper",
        ProcessTampering
    );
    impl_store!(
        file_delete_detected_store,
        file_delete_detected_store_writable,
        "file delete detected",
        FileDeleteDetected
    );
    impl_store!(
        netflow5_store,
        netflow5_store_writable,
        "netflow5",
        Netflow5
    );
    impl_store!(
        netflow9_store,
        netflow9_store_writable,
        "netflow9",
        Netflow9
    );
    impl_store!(secu_log_store, secu_log_store_writable, "seculog", SecuLog);

    /// Returns the store for connection sensors
    pub fn sensors_store(&self) -> Result<SensorStore<'_>> {
        if self.mode != DatabaseMode::Primary {
            bail!("write operations are not supported on secondary databases");
        }
        let cf = self.get_cf_handle("sensors")?;
        Ok(SensorStore { db: &self.db, cf })
    }

    fn catch_up_if_secondary(&self) -> Result<()> {
        if self.mode == DatabaseMode::Secondary {
            self.db
                .try_catch_up_with_primary()
                .context("failed to synchronize secondary database with primary")?;
        }
        Ok(())
    }

    /// Forces the secondary database to catch up with the primary.
    pub fn try_catch_up_with_primary(&self) -> Result<()> {
        self.catch_up_if_secondary()
    }
}

pub trait ReadableRawEventStore<'db, T>: Send + Sync {
    fn batched_multi_get_from_ts(
        &self,
        sensor: &str,
        times: &[DateTime<Utc>],
    ) -> Vec<(DateTime<Utc>, Vec<u8>)>;

    fn batched_multi_get_with_sensor(
        &self,
        sensor: &str,
        timestamps: &[i64],
    ) -> Vec<(i64, String, Vec<u8>)>;

    fn boundary_iter(&self, from: &[u8], to: &[u8], direction: Direction) -> BoundaryIter<'db, T>
    where
        T: DeserializeOwned;

    fn iter_forward(&self) -> Iter<'db>;
}

pub trait WritableRawEventStore<'db, T>: ReadableRawEventStore<'db, T> {
    fn append(&self, key: &[u8], raw_event: &[u8]) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<()>;
    fn flush(&self) -> Result<()>;
}

pub struct ReadableRawEventStoreHandle<'db, T>(Box<dyn ReadableRawEventStore<'db, T> + 'db>);

impl<'db, T> ReadableRawEventStoreHandle<'db, T> {
    fn new(inner: Box<dyn ReadableRawEventStore<'db, T> + 'db>) -> Self {
        Self(inner)
    }

    pub fn as_ref(&self) -> &(dyn ReadableRawEventStore<'db, T> + 'db) {
        &*self.0
    }
}

impl<'db, T> Deref for ReadableRawEventStoreHandle<'db, T> {
    type Target = dyn ReadableRawEventStore<'db, T> + 'db;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

pub struct WritableRawEventStoreHandle<'db, T>(Box<dyn WritableRawEventStore<'db, T> + 'db>);

impl<'db, T> WritableRawEventStoreHandle<'db, T> {
    fn new(inner: Box<dyn WritableRawEventStore<'db, T> + 'db>) -> Self {
        Self(inner)
    }

    pub fn as_ref(&self) -> &(dyn WritableRawEventStore<'db, T> + 'db) {
        &*self.0
    }
}

impl<'db, T> Deref for WritableRawEventStoreHandle<'db, T> {
    type Target = dyn WritableRawEventStore<'db, T> + 'db;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<'db, T> ReadableRawEventStore<'db, T> for ReadableRawEventStoreHandle<'db, T> {
    fn batched_multi_get_from_ts(
        &self,
        sensor: &str,
        times: &[DateTime<Utc>],
    ) -> Vec<(DateTime<Utc>, Vec<u8>)> {
        self.0.batched_multi_get_from_ts(sensor, times)
    }

    fn batched_multi_get_with_sensor(
        &self,
        sensor: &str,
        timestamps: &[i64],
    ) -> Vec<(i64, String, Vec<u8>)> {
        self.0.batched_multi_get_with_sensor(sensor, timestamps)
    }

    fn boundary_iter(&self, from: &[u8], to: &[u8], direction: Direction) -> BoundaryIter<'db, T>
    where
        T: DeserializeOwned,
    {
        self.0.boundary_iter(from, to, direction)
    }

    fn iter_forward(&self) -> Iter<'db> {
        self.0.iter_forward()
    }
}

impl<'db, T> ReadableRawEventStore<'db, T> for WritableRawEventStoreHandle<'db, T> {
    fn batched_multi_get_from_ts(
        &self,
        sensor: &str,
        times: &[DateTime<Utc>],
    ) -> Vec<(DateTime<Utc>, Vec<u8>)> {
        self.0.batched_multi_get_from_ts(sensor, times)
    }

    fn batched_multi_get_with_sensor(
        &self,
        sensor: &str,
        timestamps: &[i64],
    ) -> Vec<(i64, String, Vec<u8>)> {
        self.0.batched_multi_get_with_sensor(sensor, timestamps)
    }

    fn boundary_iter(&self, from: &[u8], to: &[u8], direction: Direction) -> BoundaryIter<'db, T>
    where
        T: DeserializeOwned,
    {
        self.0.boundary_iter(from, to, direction)
    }

    fn iter_forward(&self) -> Iter<'db> {
        self.0.iter_forward()
    }
}

impl<'db, T> WritableRawEventStore<'db, T> for WritableRawEventStoreHandle<'db, T> {
    fn append(&self, key: &[u8], raw_event: &[u8]) -> Result<()> {
        self.0.append(key, raw_event)
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.0.delete(key)
    }

    fn flush(&self) -> Result<()> {
        self.0.flush()
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

    fn append_impl(&self, key: &[u8], raw_event: &[u8]) -> Result<()> {
        self.db.put_cf(self.cf, key, raw_event)?;
        Ok(())
    }

    fn delete_impl(&self, key: &[u8]) -> Result<()> {
        self.db.delete_cf(self.cf, key)?;
        Ok(())
    }

    fn flush_impl(&self) -> Result<()> {
        self.db.flush_wal(true)?;
        Ok(())
    }

    fn batched_multi_get_from_ts_impl(
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

    fn batched_multi_get_with_sensor_impl(
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

    fn iter_forward_impl(&self) -> Iter<'db> {
        Iter::new(self.db.iterator_cf(self.cf, rocksdb::IteratorMode::Start))
    }
}

impl<'db, T: DeserializeOwned> RawEventStore<'db, T> {
    fn boundary_iter_impl(
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
}

pub struct ReadOnlyRawEventStore<'db, T>(RawEventStore<'db, T>);

impl<'db, T> ReadOnlyRawEventStore<'db, T> {
    fn new(inner: RawEventStore<'db, T>) -> Self {
        Self(inner)
    }
}

impl<'db, T: Sync> ReadableRawEventStore<'db, T> for RawEventStore<'db, T> {
    fn batched_multi_get_from_ts(
        &self,
        sensor: &str,
        times: &[DateTime<Utc>],
    ) -> Vec<(DateTime<Utc>, Vec<u8>)> {
        self.batched_multi_get_from_ts_impl(sensor, times)
    }

    fn batched_multi_get_with_sensor(
        &self,
        sensor: &str,
        timestamps: &[i64],
    ) -> Vec<(i64, String, Vec<u8>)> {
        self.batched_multi_get_with_sensor_impl(sensor, timestamps)
    }

    fn boundary_iter(&self, from: &[u8], to: &[u8], direction: Direction) -> BoundaryIter<'db, T>
    where
        T: DeserializeOwned,
    {
        self.boundary_iter_impl(from, to, direction)
    }

    fn iter_forward(&self) -> Iter<'db> {
        self.iter_forward_impl()
    }
}

impl<'db, T: Sync> WritableRawEventStore<'db, T> for RawEventStore<'db, T> {
    fn append(&self, key: &[u8], raw_event: &[u8]) -> Result<()> {
        self.append_impl(key, raw_event)
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.delete_impl(key)
    }

    fn flush(&self) -> Result<()> {
        self.flush_impl()
    }
}

impl<'db, T: Sync> ReadableRawEventStore<'db, T> for ReadOnlyRawEventStore<'db, T> {
    fn batched_multi_get_from_ts(
        &self,
        sensor: &str,
        times: &[DateTime<Utc>],
    ) -> Vec<(DateTime<Utc>, Vec<u8>)> {
        self.0.batched_multi_get_from_ts_impl(sensor, times)
    }

    fn batched_multi_get_with_sensor(
        &self,
        sensor: &str,
        timestamps: &[i64],
    ) -> Vec<(i64, String, Vec<u8>)> {
        self.0
            .batched_multi_get_with_sensor_impl(sensor, timestamps)
    }

    fn boundary_iter(&self, from: &[u8], to: &[u8], direction: Direction) -> BoundaryIter<'db, T>
    where
        T: DeserializeOwned,
    {
        self.0.boundary_iter_impl(from, to, direction)
    }

    fn iter_forward(&self) -> Iter<'db> {
        self.0.iter_forward_impl()
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
            Ok((key, value)) => bincode::deserialize::<T>(&value)
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

    if db_options.compression {
        cf_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        cf_opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        cf_opts.set_bottommost_zstd_max_train_bytes(0, true);
    } else {
        cf_opts.set_compression_type(rocksdb::DBCompressionType::None);
        cf_opts.set_bottommost_compression_type(rocksdb::DBCompressionType::None);
    }

    (db_opts, cf_opts)
}

pub(crate) fn data_dir_to_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("db")
}

pub(crate) fn data_dir_to_secondary_path(data_dir: &Path) -> PathBuf {
    data_dir.join("db-secondary")
}

/// Stores the compression setting to a metadata file.
///
/// # Errors
///
/// Returns an error if the file cannot be created or written to.
fn store_compression_metadata(data_dir: &Path, compression: bool) -> Result<()> {
    let metadata_path = data_dir.join("COMPRESSION");
    let content = if compression { "enabled" } else { "disabled" };
    std::fs::write(metadata_path, content).context("failed to write compression metadata")?;
    Ok(())
}

/// Reads the compression setting from the metadata file.
///
/// Returns `None` if the file doesn't exist (first run).
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or contains invalid data.
fn read_compression_metadata(data_dir: &Path) -> Result<Option<bool>> {
    let metadata_path = data_dir.join("COMPRESSION");
    if !metadata_path.exists() {
        return Ok(None);
    }

    let content =
        std::fs::read_to_string(&metadata_path).context("failed to read compression metadata")?;
    match content.trim() {
        "enabled" => Ok(Some(true)),
        "disabled" => Ok(Some(false)),
        other => Err(anyhow!("invalid compression metadata: {other}")),
    }
}

/// Validates that the compression setting matches the stored metadata.
///
/// If this is the first run (no metadata file), the setting is stored.
///
/// # Errors
///
/// Returns an error if:
/// - The metadata file cannot be read
/// - The compression setting doesn't match the stored metadata
pub fn validate_compression_metadata(data_dir: &Path, compression: bool) -> Result<()> {
    if let Some(stored_compression) = read_compression_metadata(data_dir)? {
        if stored_compression != compression {
            let stored_str = if stored_compression {
                "enabled"
            } else {
                "disabled"
            };
            let current_str = if compression { "enabled" } else { "disabled" };
            bail!(
                "Compression scheme mismatch: database was created with compression {stored_str}, \
                 but current configuration has compression {current_str}. \
                 Changing compression settings is not supported for existing databases. \
                 Please restore the original compression setting or create a new database."
            );
        }
        Ok(())
    } else {
        info!(
            "First run: storing compression metadata (compression: {})",
            compression
        );
        store_compression_metadata(data_dir, compression)
    }
}

pub fn db_path_and_option(
    data_dir: &Path,
    max_open_files: i32,
    max_mb_of_level_base: u64,
    num_of_thread: i32,
    max_subcompactions: u32,
    compression: bool,
) -> (PathBuf, DbOptions) {
    let db_path = data_dir_to_db_path(data_dir);
    let db_options = DbOptions::new(
        max_open_files,
        max_mb_of_level_base,
        num_of_thread,
        max_subcompactions,
        compression,
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
    compression: bool,
) {
    let (db_path, db_options) = db_path_and_option(
        data_dir,
        max_open_files,
        max_mb_of_level_base,
        num_of_thread,
        max_subcompactions,
        compression,
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
