//! Raw event storage based on RocksDB.

mod migration;

use crate::{
    graphql::{
        get_timestamp,
        network::{key_prefix, NetworkFilter},
        RawEventFilter,
    },
    ingest::implement::EventFilter,
};
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use giganto_client::ingest::{
    log::{Log, Oplog},
    network::{Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Ntlm, Rdp, Smtp, Ssh},
    statistics::Statistics,
    timeseries::PeriodicTimeSeries,
    Packet,
};
pub use migration::migrate_data_dir;
#[cfg(debug_assertions)]
use rocksdb::properties;
pub use rocksdb::Direction;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DBIteratorWithThreadMode, Options, DB};
use serde::de::DeserializeOwned;
use std::{cmp, marker::PhantomData, mem, path::Path, sync::Arc, time::Duration};
use tokio::{select, sync::Notify, time};
use tracing::error;

const RAW_DATA_COLUMN_FAMILY_NAMES: [&str; 17] = [
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
];
const META_DATA_COLUMN_FAMILY_NAMES: [&str; 1] = ["sources"];
const TIMESTAMP_SIZE: usize = 8;

#[cfg(debug_assertions)]
pub struct CfProperties {
    pub estimate_live_data_size: u64,
    pub estimate_num_keys: u64,
    pub stats: String,
}

pub struct DbOptions {
    max_open_files: i32,
    max_mb_of_level_base: u64,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self {
            max_open_files: 8000,
            max_mb_of_level_base: 512,
        }
    }
}

impl DbOptions {
    pub fn new(max_open_files: i32, max_mb_of_level_base: u64) -> Self {
        DbOptions {
            max_open_files,
            max_mb_of_level_base,
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

    #[cfg(debug_assertions)]
    pub fn properties_cf(&self, cfname: &str) -> Result<CfProperties> {
        let stats = if let Some(s) = self.db.property_value_cf(
            &self
                .db
                .cf_handle(cfname)
                .context("invalid record type name")?,
            properties::STATS,
        )? {
            s
        } else {
            "invalid".to_string()
        };
        let size = if let Some(u) = self.db.property_int_value_cf(
            &self
                .db
                .cf_handle(cfname)
                .context("invalid record type name")?,
            properties::ESTIMATE_LIVE_DATA_SIZE,
        )? {
            u
        } else {
            0
        };
        let num_keys = if let Some(n) = self.db.property_int_value_cf(
            &self
                .db
                .cf_handle(cfname)
                .context("invalid record type name")?,
            properties::ESTIMATE_NUM_KEYS,
        )? {
            n
        } else {
            0
        };

        Ok(CfProperties {
            estimate_live_data_size: size,
            estimate_num_keys: num_keys,
            stats,
        })
    }

    /// Returns the raw event store for all type. (exclude log type)
    pub fn retain_period_store(&self) -> Result<Vec<RawEventStore<()>>> {
        let mut stores: Vec<RawEventStore<()>> = Vec::new();
        for store in RAW_DATA_COLUMN_FAMILY_NAMES {
            if !store.eq("log") {
                let cf = self
                    .db
                    .cf_handle(store)
                    .context("cannot access column family")?;
                stores.push(RawEventStore::new(&self.db, cf));
            }
        }
        Ok(stores)
    }

    /// Returns the raw event store for connections.
    pub fn conn_store(&self) -> Result<RawEventStore<Conn>> {
        let cf = self
            .db
            .cf_handle("conn")
            .context("cannot access conn column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for dns.
    pub fn dns_store(&self) -> Result<RawEventStore<Dns>> {
        let cf = self
            .db
            .cf_handle("dns")
            .context("cannot access dns column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for log.
    pub fn log_store(&self) -> Result<RawEventStore<Log>> {
        let cf = self
            .db
            .cf_handle("log")
            .context("cannot access log column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for http.
    pub fn http_store(&self) -> Result<RawEventStore<Http>> {
        let cf = self
            .db
            .cf_handle("http")
            .context("cannot access http column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for rdp.
    pub fn rdp_store(&self) -> Result<RawEventStore<Rdp>> {
        let cf = self
            .db
            .cf_handle("rdp")
            .context("cannot access rdp column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for periodic time series.
    pub fn periodic_time_series_store(&self) -> Result<RawEventStore<PeriodicTimeSeries>> {
        let cf = self
            .db
            .cf_handle("periodic time series")
            .context("cannot access periodic time series column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for smtp.
    pub fn smtp_store(&self) -> Result<RawEventStore<Smtp>> {
        let cf = self
            .db
            .cf_handle("smtp")
            .context("cannot access smtp column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for ntlm.
    pub fn ntlm_store(&self) -> Result<RawEventStore<Ntlm>> {
        let cf = self
            .db
            .cf_handle("ntlm")
            .context("cannot access ntlm column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for kerberos.
    pub fn kerberos_store(&self) -> Result<RawEventStore<Kerberos>> {
        let cf = self
            .db
            .cf_handle("kerberos")
            .context("cannot access kerberos column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for ssh.
    pub fn ssh_store(&self) -> Result<RawEventStore<Ssh>> {
        let cf = self
            .db
            .cf_handle("ssh")
            .context("cannot access ssh column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the raw event store for dce rpc.
    pub fn dce_rpc_store(&self) -> Result<RawEventStore<DceRpc>> {
        let cf = self
            .db
            .cf_handle("dce rpc")
            .context("cannot access dce rpc column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for statistics
    pub fn statistics_store(&self) -> Result<RawEventStore<Statistics>> {
        let cf = self
            .db
            .cf_handle("statistics")
            .context("cannot access statistics column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for oplog
    pub fn oplog_store(&self) -> Result<RawEventStore<Oplog>> {
        let cf = self
            .db
            .cf_handle("oplog")
            .context("cannot access operation log column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for packet
    pub fn packet_store(&self) -> Result<RawEventStore<Packet>> {
        let cf = self
            .db
            .cf_handle("packet")
            .context("cannot access packet column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for connection sources
    pub fn sources_store(&self) -> Result<SourceStore> {
        let cf = self
            .db
            .cf_handle("sources")
            .context("cannot access sources column family")?;
        Ok(SourceStore { db: &self.db, cf })
    }

    /// Returns the store for Ftp
    pub fn ftp_store(&self) -> Result<RawEventStore<Ftp>> {
        let cf = self
            .db
            .cf_handle("ftp")
            .context("cannot access ftp column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for Mqtt
    pub fn mqtt_store(&self) -> Result<RawEventStore<Mqtt>> {
        let cf = self
            .db
            .cf_handle("mqtt")
            .context("cannot access mqtt column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for Mqtt
    pub fn ldap_store(&self) -> Result<RawEventStore<Ldap>> {
        let cf = self
            .db
            .cf_handle("ldap")
            .context("cannot access ldap column family")?;
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
unsafe impl<'db, T> Send for RawEventStore<'db, T> {}

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

    pub fn multi_get_from_ts(
        &self,
        source: &str,
        timestamps: &[DateTime<Utc>],
    ) -> Vec<(DateTime<Utc>, Vec<u8>)> {
        let key_prefix = key_prefix(source);
        timestamps
            .iter()
            .filter_map(|timestamp| {
                let mut key = key_prefix.clone();
                key.extend_from_slice(&timestamp.timestamp_nanos().to_be_bytes());
                self.db
                    .get_cf(&self.cf, &key)
                    .ok()
                    .and_then(|val| get_timestamp(&key).ok().zip(val))
            })
            .collect::<Vec<_>>()
    }

    pub fn multi_get_with_source(
        &self,
        source: &str,
        timestamps: &[i64],
    ) -> Vec<(String, Vec<u8>)> {
        let key_prefix = key_prefix(source);

        let multi_keys: Vec<(&ColumnFamily, Vec<u8>)> = timestamps
            .iter()
            .map(|timestamp| {
                let mut key: Vec<u8> = key_prefix.clone();
                key.extend_from_slice(&timestamp.to_be_bytes());
                (self.cf, key)
            })
            .collect();

        let values = self.db.multi_get_cf(multi_keys);

        let values_with_source: Vec<(String, Vec<u8>)> = values
            .into_iter()
            .flatten()
            .flatten()
            .map(|value| (source.to_string(), value))
            .collect();

        values_with_source
    }
}

impl<'db, T: DeserializeOwned> RawEventStore<'db, T> {
    pub fn boundary_iter(
        &self,
        from: &[u8],
        to: &[u8],
        direction: Direction,
    ) -> BoundaryIter<'db, T> {
        BoundaryIter::new(
            self.db
                .iterator_cf(self.cf, rocksdb::IteratorMode::From(from, direction)),
            to.to_vec(),
            direction,
        )
    }
    pub fn _iter(&self, from: &[u8]) -> Iter<'db> {
        Iter::new(self.db.iterator_cf(
            self.cf,
            rocksdb::IteratorMode::From(from, Direction::Forward),
        ))
    }
}

pub struct SourceStore<'db> {
    db: &'db DB,
    cf: &'db ColumnFamily,
}

impl<'db> SourceStore<'db> {
    /// Inserts a source name and its last active time.
    ///
    /// If the source already exists, its last active time is updated.
    pub fn insert(&self, name: &str, last_active: DateTime<Utc>) -> Result<()> {
        self.db
            .put_cf(self.cf, name, last_active.timestamp_nanos().to_be_bytes())?;
        Ok(())
    }

    /// Returns the names of all sources.
    pub fn names(&self) -> Vec<Vec<u8>> {
        self.db
            .iterator_cf(self.cf, rocksdb::IteratorMode::Start)
            .flatten()
            .map(|(key, _value)| key.to_vec())
            .collect()
    }
}

// RocksDB must manage thread safety for `ColumnFamily`.
// See rust-rocksdb/rust-rocksdb#407.
unsafe impl<'db> Send for SourceStore<'db> {}

/// Creates a key corresponding to the given `prefix` and `time`.
pub fn lower_closed_bound_key(prefix: &[u8], time: Option<DateTime<Utc>>) -> Vec<u8> {
    let mut bound = Vec::with_capacity(prefix.len() + mem::size_of::<i64>());
    bound.extend(prefix);
    if let Some(time) = time {
        bound.extend(time.timestamp_nanos().to_be_bytes());
    }
    bound
}

/// Creates a key corresponding to the given `prefix` and `time`.
pub fn upper_closed_bound_key(prefix: &[u8], time: Option<DateTime<Utc>>) -> Vec<u8> {
    let mut bound = Vec::with_capacity(prefix.len() + mem::size_of::<i64>());
    bound.extend(prefix);
    if let Some(time) = time {
        bound.extend(time.timestamp_nanos().to_be_bytes());
    } else {
        bound.extend(i64::MAX.to_be_bytes());
    }
    bound
}

/// Creates a key that follows the key calculated from the given `prefix` and
/// `time`.
pub fn upper_open_bound_key(prefix: &[u8], time: Option<DateTime<Utc>>) -> Vec<u8> {
    let mut bound = Vec::with_capacity(prefix.len() + mem::size_of::<i64>() + 1);
    bound.extend(prefix);
    if let Some(time) = time {
        let ns = time.timestamp_nanos();
        if let Some(ns) = ns.checked_sub(1) {
            if ns >= 0 {
                bound.extend(ns.to_be_bytes());
                return bound;
            }
        }
    }
    bound.extend(i64::MAX.to_be_bytes());
    bound.push(0);
    bound
}

pub type KeyValue<T> = (Box<[u8]>, T);
pub type RawValue = (Box<[u8]>, Box<[u8]>);

pub struct FilteredIter<'d, T> {
    inner: BoundaryIter<'d, T>,
    filter: &'d NetworkFilter,
}

impl<'d, T> FilteredIter<'d, T> {
    pub fn new(inner: BoundaryIter<'d, T>, filter: &'d NetworkFilter) -> Self {
        Self { inner, filter }
    }
}

impl<'d, T> Iterator for FilteredIter<'d, T>
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
            ) {
                return Some(elem);
            }
        }
        None
    }
}

pub struct BoundaryIter<'d, T> {
    inner: DBIteratorWithThreadMode<'d, DB>,
    boundary: Vec<u8>,
    cond: cmp::Ordering,
    phantom: PhantomData<T>,
}

impl<'d, T> BoundaryIter<'d, T> {
    pub fn new(
        inner: DBIteratorWithThreadMode<'d, DB>,
        boundary: Vec<u8>,
        direction: Direction,
    ) -> Self {
        let cond = match direction {
            Direction::Forward => cmp::Ordering::Greater,
            Direction::Reverse => cmp::Ordering::Less,
        };

        Self {
            inner,
            boundary,
            cond,
            phantom: PhantomData,
        }
    }
}

impl<'d, T> Iterator for BoundaryIter<'d, T>
where
    T: DeserializeOwned,
{
    type Item = anyhow::Result<KeyValue<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().and_then(|item| match item {
            Ok((key, value)) => {
                if key.as_ref().cmp(&self.boundary) == self.cond {
                    None
                } else {
                    Some(
                        bincode::deserialize::<T>(&value)
                            .map(|value| (key, value))
                            .map_err(Into::into),
                    )
                }
            }
            Err(e) => Some(Err(e.into())),
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

impl<'d> Iterator for Iter<'d> {
    type Item = anyhow::Result<RawValue>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| match item {
            Ok((key, value)) => Ok((key, value)),
            Err(e) => Err(e.into()),
        })
    }
}

pub async fn retain_periodically(
    duration: Duration,
    retention_period: Duration,
    db: Database,
    wait_shutdown: Arc<Notify>,
) -> Result<()> {
    let mut itv = time::interval(duration);
    let retention_duration = i64::try_from(retention_period.as_nanos())?;
    let from_timestamp = DateTime::<Utc>::from_utc(
        NaiveDateTime::from_timestamp_opt(61, 0).expect("valid time"),
        Utc,
    )
    .timestamp_nanos()
    .to_be_bytes();
    loop {
        select! {
            _ = itv.tick() => {
                let standard_duration = Utc::now().timestamp_nanos() - retention_duration;
                let standard_duration_vec = standard_duration.to_be_bytes().to_vec();
                let sources = db.sources_store()?.names();
                let all_store = db.retain_period_store()?;
                let log_store = db.log_store()?;

                for source in sources {
                    let mut from: Vec<u8> = source.clone();
                    from.push(0x00);
                    from.extend_from_slice(&from_timestamp);

                    let mut to: Vec<u8> = source.clone();
                    to.push(0x00);
                    to.extend_from_slice(&standard_duration_vec);

                    for store in &all_store {
                        if store.db.delete_range_cf(store.cf, &from, &to).is_err() {
                            error!("Failed to delete range data");
                        }
                    }

                    for (key, _) in log_store
                        .db
                        .prefix_iterator_cf(log_store.cf, source.clone())
                        .flatten()
                        .filter(|(key, _)| {
                            let store_duration = i64::from_be_bytes(
                                key[(key.len() - TIMESTAMP_SIZE)..]
                                    .try_into()
                                    .expect("valid key"),
                            );
                            standard_duration > store_duration
                        })
                    {
                        if log_store.delete(&key).is_err() {
                            error!("Failed to delete log data");
                        }
                    }
                }
            }
            _ = wait_shutdown.notified() => {
                return Ok(());
            },
        }
    }
}

fn rocksdb_options(db_options: &DbOptions) -> (Options, Options) {
    let max_bytes = db_options.max_mb_of_level_base * 1024 * 1024;
    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    db_opts.set_max_open_files(db_options.max_open_files);
    db_opts.set_keep_log_file_num(10);
    db_opts.set_stats_dump_period_sec(3600);
    db_opts.set_max_total_wal_size(max_bytes);
    db_opts.set_manual_wal_flush(true);

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
