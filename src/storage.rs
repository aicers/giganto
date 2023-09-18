//! Raw event storage based on RocksDB.

mod migration;

use crate::{
    graphql::{network::NetworkFilter, RawEventFilter, TIMESTAMP_SIZE},
    ingest::implement::EventFilter,
    IndexInfo,
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, NaiveDateTime, TimeZone, Timelike, Utc};
use giganto_client::ingest::{
    log::{Log, Oplog},
    network::{
        Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
    },
    statistics::Statistics,
    sysmon::{
        DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
        FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
        ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
    },
    timeseries::PeriodicTimeSeries,
    Packet, RecordType,
};
pub use migration::migrate_data_dir;
#[cfg(debug_assertions)]
use rocksdb::properties;
pub use rocksdb::Direction;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DBIteratorWithThreadMode, Options, DB};
use serde::de::DeserializeOwned;
use std::{
    cmp, collections::HashMap, marker::PhantomData, net::IpAddr, path::Path, sync::Arc,
    time::Duration,
};
use tokio::{
    select,
    sync::{mpsc::UnboundedReceiver, Notify},
    time,
};
use tracing::error;

const RAW_DATA_COLUMN_FAMILY_NAMES: [&str; 34] = [
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
];
const META_DATA_COLUMN_FAMILY_NAMES: [&str; 1] = ["sources"];
const RAW_DATA_IDX_COLUMN_FAMILY_NAMES: [&str; 4] = [
    "src addr index",
    "src port index",
    "dst addr index",
    "dst port index",
];
const INDEX_PERIOD_OFFSET: i64 = 5; // 5sec
const LAST_INDEX_THRESHOLD: u8 = 2;

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
            RAW_DATA_COLUMN_FAMILY_NAMES.len()
                + META_DATA_COLUMN_FAMILY_NAMES.len()
                + RAW_DATA_IDX_COLUMN_FAMILY_NAMES.len(),
        );
        cfs_name.extend(RAW_DATA_COLUMN_FAMILY_NAMES);
        cfs_name.extend(META_DATA_COLUMN_FAMILY_NAMES);
        cfs_name.extend(RAW_DATA_IDX_COLUMN_FAMILY_NAMES);

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

    /// Returns the store for ldap
    pub fn ldap_store(&self) -> Result<RawEventStore<Ldap>> {
        let cf = self
            .db
            .cf_handle("ldap")
            .context("cannot access ldap column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for tls
    pub fn tls_store(&self) -> Result<RawEventStore<Tls>> {
        let cf = self
            .db
            .cf_handle("tls")
            .context("cannot access tls column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for smb
    pub fn smb_store(&self) -> Result<RawEventStore<Smb>> {
        let cf = self
            .db
            .cf_handle("smb")
            .context("cannot access smb column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for nfs
    pub fn nfs_store(&self) -> Result<RawEventStore<Nfs>> {
        let cf = self
            .db
            .cf_handle("nfs")
            .context("cannot access nfs column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `ProcessCreate` (#1).
    pub fn process_create_store(&self) -> Result<RawEventStore<ProcessCreate>> {
        let cf = self
            .db
            .cf_handle("process create")
            .context("cannot access sysmon #1 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileCreateTime` (#2).
    pub fn file_create_time_store(&self) -> Result<RawEventStore<FileCreationTimeChanged>> {
        let cf = self
            .db
            .cf_handle("file create time")
            .context("cannot access sysmon #2 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `NetworkConnect` (#3).
    pub fn network_connect_store(&self) -> Result<RawEventStore<NetworkConnection>> {
        let cf = self
            .db
            .cf_handle("network connect")
            .context("cannot access sysmon #3 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `ProcessTerminate` (#5).
    pub fn process_terminate_store(&self) -> Result<RawEventStore<ProcessTerminated>> {
        let cf = self
            .db
            .cf_handle("process terminate")
            .context("cannot access sysmon #5 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `ImageLoad` (#7).
    pub fn image_load_store(&self) -> Result<RawEventStore<ImageLoaded>> {
        let cf = self
            .db
            .cf_handle("image load")
            .context("cannot access sysmon #7 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileCreate` (#11).
    pub fn file_create_store(&self) -> Result<RawEventStore<FileCreate>> {
        let cf = self
            .db
            .cf_handle("file create")
            .context("cannot access sysmon #11 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `RegistryValueSet` (#13).
    pub fn registry_value_set_store(&self) -> Result<RawEventStore<RegistryValueSet>> {
        let cf = self
            .db
            .cf_handle("registry value set")
            .context("cannot access sysmon #13 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `RegistryKeyRename` (#14).
    pub fn registry_key_rename_store(&self) -> Result<RawEventStore<RegistryKeyValueRename>> {
        let cf = self
            .db
            .cf_handle("registry key rename")
            .context("cannot access sysmon #14 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileCreateStreamHash` (#15).
    pub fn file_create_stream_hash_store(&self) -> Result<RawEventStore<FileCreateStreamHash>> {
        let cf = self
            .db
            .cf_handle("file create stream hash")
            .context("cannot access sysmon #15 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `PipeEvent` (#17).
    pub fn pipe_event_store(&self) -> Result<RawEventStore<PipeEvent>> {
        let cf = self
            .db
            .cf_handle("pipe event")
            .context("cannot access sysmon #17 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `DnsQuery` (#22).
    pub fn dns_query_store(&self) -> Result<RawEventStore<DnsEvent>> {
        let cf = self
            .db
            .cf_handle("dns query")
            .context("cannot access sysmon #22 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileDelete` (#23).
    pub fn file_delete_store(&self) -> Result<RawEventStore<FileDelete>> {
        let cf = self
            .db
            .cf_handle("file delete")
            .context("cannot access sysmon #23 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `ProcessTamper` (#25).
    pub fn process_tamper_store(&self) -> Result<RawEventStore<ProcessTampering>> {
        let cf = self
            .db
            .cf_handle("process tamper")
            .context("cannot access sysmon #25 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for sysmon event `FileDeleteDetected` (#26).
    pub fn file_delete_detected_store(&self) -> Result<RawEventStore<FileDeleteDetected>> {
        let cf = self
            .db
            .cf_handle("file delete detected")
            .context("cannot access sysmon #26 column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for `network_raw_event`'s `src_addr` index
    pub fn src_addr_index(&self) -> Result<RawEventStore<Vec<i64>>> {
        let cf = self
            .db
            .cf_handle("src addr index")
            .context("cannot access src_addr_index column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for `network_raw_event`'s `src_port` index
    pub fn src_port_index(&self) -> Result<RawEventStore<Vec<i64>>> {
        let cf = self
            .db
            .cf_handle("src port index")
            .context("cannot access src_port_index column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for `network_raw_event`'s `dst_addr` index
    pub fn dst_addr_index(&self) -> Result<RawEventStore<Vec<i64>>> {
        let cf = self
            .db
            .cf_handle("dst addr index")
            .context("cannot access dst_addr_index column family")?;
        Ok(RawEventStore::new(&self.db, cf))
    }

    /// Returns the store for `network_raw_event`'s `dst_port` index
    pub fn dst_port_index(&self) -> Result<RawEventStore<Vec<i64>>> {
        let cf = self
            .db
            .cf_handle("dst port index")
            .context("cannot access dst_port_index column family")?;
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

    pub fn get_key_value(&self, source: &str, timestamp: i64) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = StorageKey::builder()
            .start_key(source)
            .end_key(timestamp)
            .build()
            .key();
        if let Some(value) = self.db.get_cf(&self.cf, &key)? {
            Ok((key, value))
        } else {
            bail!("Failed to get rocksdb's value");
        }
    }

    pub fn multi_get_from_ts(
        &self,
        source: &str,
        timestamps: &[DateTime<Utc>],
    ) -> Vec<(DateTime<Utc>, Vec<u8>)> {
        let key_builder = StorageKey::builder().start_key(source);
        timestamps
            .iter()
            .filter_map(|timestamp| {
                let key = key_builder
                    .clone()
                    .end_key(timestamp.timestamp_nanos_opt().unwrap_or(i64::MAX))
                    .build();
                self.db
                    .get_cf(&self.cf, key.key())
                    .ok()
                    .and_then(|val| Some(*timestamp).zip(val))
            })
            .collect::<Vec<_>>()
    }

    pub fn multi_get_with_source(
        &self,
        source: &str,
        timestamps: &[i64],
    ) -> Vec<(i64, String, Vec<u8>)> {
        let key_builder = StorageKey::builder().start_key(source);
        let values_with_source: Vec<(i64, String, Vec<u8>)> = timestamps
            .iter()
            .filter_map(|timestamp| {
                let key = key_builder.clone().end_key(*timestamp).build();
                self.db
                    .get_cf(&self.cf, key.key())
                    .ok()
                    .and_then(|value| value.map(|val| (*timestamp, source.to_string(), val)))
            })
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

    pub fn iter_forward(&self) -> Iter<'db> {
        Iter::new(self.db.iterator_cf(self.cf, rocksdb::IteratorMode::Start))
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

#[allow(clippy::module_name_repetitions)]
#[derive(Default, Debug, Clone)]
pub struct StorageKey(Vec<u8>);

impl StorageKey {
    #[must_use]
    pub fn builder() -> StorageKeyBuilder {
        StorageKeyBuilder::default()
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
        let end_key = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            0
        };
        self.pre_key.extend_from_slice(&end_key.to_be_bytes());
        self
    }

    pub fn upper_closed_bound_end_key(mut self, time: Option<DateTime<Utc>>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        let end_key = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            i64::MAX
        };
        self.pre_key.extend_from_slice(&end_key.to_be_bytes());
        self
    }

    pub fn upper_open_bound_end_key(mut self, time: Option<DateTime<Utc>>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        if let Some(time) = time {
            let ns = time.timestamp_nanos_opt().unwrap_or(i64::MAX);
            if let Some(ns) = ns.checked_sub(1) {
                if ns >= 0 {
                    self.pre_key.extend_from_slice(&ns.to_be_bytes());
                    return self;
                }
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

impl<'d, T> Iterator for StatisticsIter<'d, T>
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
    let from_timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDateTime::from_timestamp_opt(61, 0).expect("valid time"),
        Utc,
    )
    .timestamp_nanos_opt()
    .unwrap_or(i64::MAX)
    .to_be_bytes();
    loop {
        select! {
            _ = itv.tick() => {
                let standard_duration = Utc::now().timestamp_nanos_opt().unwrap_or(i64::MAX) - retention_duration;
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
            () = wait_shutdown.notified() => {
                return Ok(());
            },
        }
    }
}

#[allow(clippy::too_many_lines)]
pub async fn index_periodically(
    duration: Duration,
    index_period: Duration,
    db: Database,
    wait_shutdown: Arc<Notify>,
    mut recv_idx_channel: UnboundedReceiver<IndexInfo>,
) -> Result<()> {
    let mut itv = time::interval(duration);
    let index_timestamp = i64::try_from(index_period.as_nanos())?;
    let mut src_addr_idx_hash: HashMap<i64, HashMap<Vec<u8>, Vec<i64>>> = HashMap::new();
    let mut src_port_idx_hash: HashMap<i64, HashMap<Vec<u8>, Vec<i64>>> = HashMap::new();
    let mut dst_addr_idx_hash: HashMap<i64, HashMap<Vec<u8>, Vec<i64>>> = HashMap::new();
    let mut dst_port_idx_hash: HashMap<i64, HashMap<Vec<u8>, Vec<i64>>> = HashMap::new();
    let mut last_src_addr_idx_target: (i64, u8) = (0, 0);
    let mut last_src_port_idx_target: (i64, u8) = (0, 0);
    let mut last_dst_addr_idx_target: (i64, u8) = (0, 0);
    let mut last_dst_port_idx_target: (i64, u8) = (0, 0);

    itv.tick().await;
    loop {
        select! {
            Some((source, record, raw_event, timestamp)) = recv_idx_channel.recv() => {
                let mut idx_key: Vec<u8> = Vec::new();

                let (src_addr, src_port, dst_addr, dst_port):(IpAddr, u16, IpAddr, u16) = bincode::deserialize(&raw_event)?;
                let date_time = truncate_datetime(Utc.timestamp_nanos(timestamp), index_period)?;
                let date_time_hash_key = date_time.timestamp_nanos_opt().unwrap(); // truncate_datetime's result is always valid.

                start_idx_key(&mut idx_key, &source, record);
                mid_idx_key(&mut idx_key, &date_time);
                let mut src_addr_key = idx_key.clone();
                src_addr_key.extend_from_slice(&addr_to_index_key(src_addr,false));
                let mut src_port_key = idx_key.clone();
                src_port_key.extend_from_slice(&src_port.to_be_bytes());
                let mut dst_addr_key = idx_key.clone();
                dst_addr_key.extend_from_slice(&addr_to_index_key(dst_addr,false));
                let mut dst_port_key = idx_key;
                dst_port_key.extend_from_slice(&dst_port.to_be_bytes());

                upsert_index_hashmap(&mut src_addr_idx_hash, date_time_hash_key, src_addr_key, timestamp);
                upsert_index_hashmap(&mut src_port_idx_hash, date_time_hash_key, src_port_key, timestamp);
                upsert_index_hashmap(&mut dst_addr_idx_hash, date_time_hash_key, dst_addr_key, timestamp);
                upsert_index_hashmap(&mut dst_port_idx_hash ,date_time_hash_key, dst_port_key, timestamp);
            }
            _ = itv.tick() => {
                // configure the index by applying an offset to the piglet transfer time.
                let current_idx_target = truncate_datetime(Utc::now() - chrono::Duration::seconds(INDEX_PERIOD_OFFSET), index_period)?.timestamp_nanos_opt().unwrap() - index_timestamp; // truncate_datetime's result is always valid.

                let src_addr_idx_db = db.src_addr_index()?;
                if let Err(e) = append_target_indexes(&src_addr_idx_db, &mut src_addr_idx_hash, &mut last_src_addr_idx_target, current_idx_target){
                    error!("Failed to append src_addr's index: {e}");
                }

                let src_port_idx_db = db.src_port_index()?;
                if let Err(e) = append_target_indexes(&src_port_idx_db, &mut src_port_idx_hash, &mut last_src_port_idx_target, current_idx_target){
                    error!("Failed to append src_port's index: {e}");
                }

                let dst_addr_idx_db = db.dst_addr_index()?;
                if let Err(e) = append_target_indexes(&dst_addr_idx_db, &mut dst_addr_idx_hash, &mut last_dst_addr_idx_target, current_idx_target){
                    error!("Failed to append dst_addr's index: {e}");
                }

                let dst_port_idx_db = db.dst_port_index()?;
                if let Err(e) = append_target_indexes(&dst_port_idx_db, &mut dst_port_idx_hash, &mut last_dst_port_idx_target, current_idx_target){
                    error!("Failed to append dst_port's index: {e}");
                }
            }
            () = wait_shutdown.notified() => {
                // Insert the remaining index data into index db.
                let src_addr_idx_db = db.src_addr_index()?;
                if let Err(e) = append_remaining_indexes(&src_addr_idx_db, &mut src_addr_idx_hash){
                    error!("Failed to append src_addr's index: {e}");
                }

                let src_port_idx_db = db.src_port_index()?;
                if let Err(e) = append_remaining_indexes(&src_port_idx_db, &mut src_port_idx_hash){
                    error!("Failed to append src_port's index: {e}");
                }

                let dst_addr_idx_db = db.dst_addr_index()?;
                if let Err(e) = append_remaining_indexes(&dst_addr_idx_db, &mut dst_addr_idx_hash){
                    error!("Failed to append dst_addr's index: {e}");
                }

                let dst_port_idx_db = db.dst_port_index()?;
                if let Err(e) = append_remaining_indexes(&dst_port_idx_db, &mut dst_port_idx_hash){
                    error!("Failed to append dst_port's index: {e}");
                }
                return Ok(());
            },
        }
    }
}

fn append_remaining_indexes(
    index_cf: &RawEventStore<Vec<i64>>,
    index_hash: &mut HashMap<i64, HashMap<Vec<u8>, Vec<i64>>>,
) -> Result<()> {
    for db_hash in index_hash.values_mut() {
        for (cf_key, cf_value) in db_hash {
            index_cf.append(cf_key, &bincode::serialize(&cf_value)?)?;
        }
    }
    Ok(())
}

fn append_target_indexes(
    index_cf: &RawEventStore<Vec<i64>>,
    index_hash: &mut HashMap<i64, HashMap<Vec<u8>, Vec<i64>>>,
    last_idx_target: &mut (i64, u8),
    current_idx_target: i64,
) -> Result<()> {
    let mut old_raw_data: Vec<i64> = index_hash
        .keys()
        .copied()
        .filter(|x| *x < current_idx_target)
        .collect();
    old_raw_data.sort_unstable();

    // Check the last data sent by reproduce.
    if let Some(last) = old_raw_data.pop() {
        if last_idx_target.0 == last {
            last_idx_target.1 += 1;
        } else {
            *last_idx_target = (last, 1);
        }
        if last_idx_target.1 >= LAST_INDEX_THRESHOLD {
            if let Some(db_hash) = index_hash.remove(&last_idx_target.0) {
                for (cf_key, cf_value) in db_hash {
                    index_cf.append(&cf_key, &bincode::serialize(&cf_value)?)?;
                }
            }
            *last_idx_target = (0, 0);
        }
    }

    // Insert an index on an old raw event. (from reproduce)
    for key in &old_raw_data {
        if let Some(db_hash) = index_hash.remove(key) {
            for (cf_key, cf_value) in db_hash {
                index_cf.append(&cf_key, &bincode::serialize(&cf_value)?)?;
            }
        }
    }

    // Insert an index on an latest raw event. (from piglet)
    if let Some(db_hash) = index_hash.remove(&current_idx_target) {
        for (cf_key, cf_value) in db_hash {
            index_cf.append(&cf_key, &bincode::serialize(&cf_value)?)?;
        }
    }
    Ok(())
}

fn upsert_index_hashmap(
    idx_hash: &mut HashMap<i64, HashMap<Vec<u8>, Vec<i64>>>,
    hash_key: i64,
    key: Vec<u8>,
    value: i64,
) {
    idx_hash
        .entry(hash_key)
        .and_modify(|db_entry| {
            db_entry
                .entry(key.clone())
                .and_modify(|db_value| db_value.push(value))
                .or_insert(vec![value]);
        })
        .or_insert_with(|| {
            let mut db_hash = HashMap::new();
            db_hash.insert(key, vec![value]);
            db_hash
        });
}

pub fn addr_to_index_key(ip_addr: IpAddr, is_to_search_key: bool) -> Vec<u8> {
    match ip_addr {
        IpAddr::V4(ipv4) => {
            let ipv4_u32: u32 = ipv4.into();
            if is_to_search_key && ipv4_u32 > 0 {
                (ipv4_u32 - 1).to_be_bytes().to_vec()
            } else {
                ipv4_u32.to_be_bytes().to_vec()
            }
        }
        IpAddr::V6(ipv6) => {
            let ipv6_u128: u128 = ipv6.into();
            if is_to_search_key && ipv6_u128 > 0 {
                (ipv6_u128 - 1).to_be_bytes().to_vec()
            } else {
                ipv6_u128.to_be_bytes().to_vec()
            }
        }
    }
}

pub fn start_idx_key(idx_key: &mut Vec<u8>, source: &str, proto: RecordType) {
    idx_key.extend_from_slice(source.as_bytes());
    idx_key.push(0);

    idx_key.extend_from_slice(format!("{proto:?}").as_bytes());
    idx_key.push(0);
}

pub fn mid_idx_key(idx_key: &mut Vec<u8>, date_time: &DateTime<Utc>) {
    idx_key.extend_from_slice(date_time.format("%Y%m%d%H%M").to_string().as_bytes());
    idx_key.push(0);
}

pub fn truncate_datetime(datetime: DateTime<Utc>, duration: Duration) -> Result<DateTime<Utc>> {
    let seconds = u32::try_from(duration.as_secs())?;
    let mut trunc_time = datetime
        .with_second(0)
        .expect("Failed to truncate DateTime to second")
        .with_nanosecond(0)
        .expect("Failed to truncate DateTime to nanos");
    let period = seconds / 60;
    trunc_time = if period >= 60 {
        // if period is 1hour
        let hour_period = period / 60;
        trunc_time
            .with_hour(datetime.hour() / hour_period * hour_period)
            .expect("Failed to truncate DateTime to hour")
            .with_minute(0)
            .expect("Failed to truncate DateTime to minute")
    } else {
        // if period is 1min/10min
        trunc_time
            .with_minute(datetime.minute() / period * period)
            .expect("Failed to truncate DateTime to minute")
    };
    Ok(trunc_time)
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
