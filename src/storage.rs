//! Raw event storage based on RocksDB.

mod migration;

use std::{
    collections::HashSet,
    marker::PhantomData,
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
pub use giganto_client::ingest::network::{Conn, Http, Ntlm, Smtp, Ssh, Tls};
use giganto_client::ingest::{
    Packet,
    log::{Log, OpLog, SecuLog},
    netflow::{Netflow5, Netflow9},
    network::{
        Bootp, DceRpc, Dhcp, Dns, Ftp, Icmp, Kerberos, Ldap, MalformedDns as ClientMalformedDns,
        Mqtt, Nfs, Radius, Rdp, Smb,
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
#[cfg(feature = "bootroot")]
use rocksdb::WriteBatch;
#[cfg(feature = "storage_diagnostics")]
use rocksdb::properties;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, DBIteratorWithThreadMode, Options, ReadOptions,
};
use serde::de::DeserializeOwned;
#[cfg(feature = "bootroot")]
use serde::{Deserialize, Serialize};
use tokio::{select, task::JoinHandle, time};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::datetime::DateTime;
use crate::{
    comm::ingest::implement::EventFilter,
    graphql::{RawEventFilter, TIMESTAMP_SIZE},
};

pub(crate) const RAW_DATA_COLUMN_FAMILY_NAMES: [&str; 42] = [
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
    "icmp",
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
#[cfg(feature = "bootroot")]
const CUSTOMER_DELETION_JOBS_CF: &str = "customer deletion jobs";

#[cfg(feature = "bootroot")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustomerDataDeletionStatus {
    InProgress,
    Succeeded,
    Failed,
}

#[cfg(feature = "bootroot")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerDataDeletion {
    pub service_fqdn_list: Vec<String>,
    pub requested_at: i64,
    pub status: CustomerDataDeletionStatus,
    pub completed_at: Option<i64>,
    pub error: Option<String>,
}

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

#[cfg(feature = "storage_diagnostics")]
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
        #[cfg(feature = "bootroot")]
        cfs_name.push(CUSTOMER_DELETION_JOBS_CF);

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

    #[cfg(feature = "storage_diagnostics")]
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
    #[cfg(feature = "storage_diagnostics")]
    pub fn count_cf_entries(&self, cf_name: &str) -> Result<u64> {
        let cf = self.get_cf_handle(cf_name)?;
        let snap = self.db.snapshot();

        let mut ro = rocksdb::ReadOptions::default();
        ro.set_total_order_seek(true);
        let iter = snap.iterator_cf_opt(cf, ro, rocksdb::IteratorMode::Start);

        let mut count = 0u64;
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

    /// Returns the raw event store for `malformed_dns`.
    pub fn malformed_dns_store(&self) -> Result<RawEventStore<'_, ClientMalformedDns>> {
        let cf = self.get_cf_handle("malformed_dns")?;
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

    #[cfg(feature = "bootroot")]
    pub fn customer_deletion_job_store(&self) -> Result<CustomerDeletionJobStore<'_>> {
        let cf = self.get_cf_handle(CUSTOMER_DELETION_JOBS_CF)?;
        Ok(CustomerDeletionJobStore { db: &self.db, cf })
    }

    #[cfg(feature = "bootroot")]
    pub(crate) fn delete_customer_event_ranges(
        &self,
        service_fqdn: &str,
        cf_names: &[&str],
    ) -> Result<()> {
        let mut from = Vec::with_capacity(service_fqdn.len() + 1);
        from.extend_from_slice(service_fqdn.as_bytes());
        from.push(0x00);
        let mut to = Vec::with_capacity(service_fqdn.len() + 1);
        to.extend_from_slice(service_fqdn.as_bytes());
        to.push(0x01);

        let mut batch = WriteBatch::default();
        for cf_name in cf_names {
            let cf = self.get_cf_handle(cf_name)?;
            batch.delete_range_cf(cf, &from, &to);
        }
        self.db.write(batch)?;
        Ok(())
    }

    #[cfg(all(test, feature = "bootroot"))]
    pub(crate) fn put_cf_for_test(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.get_cf_handle(cf_name)?;
        self.db.put_cf(cf, key, value)?;
        Ok(())
    }

    #[cfg(all(test, feature = "bootroot"))]
    pub(crate) fn get_cf_for_test(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.get_cf_handle(cf_name)?;
        Ok(self.db.get_cf(cf, key)?)
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

    /// Returns the store for icmp
    pub fn icmp_store(&self) -> Result<RawEventStore<'_, Icmp>> {
        let cf = self.get_cf_handle("icmp")?;
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
        times: &[DateTime],
    ) -> Vec<(DateTime, Vec<u8>)> {
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

        let result_vector: Vec<(DateTime, Vec<u8>)> = times
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
    pub fn insert(&self, name: &str, last_active: DateTime) -> Result<()> {
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

    #[cfg(feature = "bootroot")]
    pub fn delete(&self, name: &str) -> Result<()> {
        self.db.delete_cf(self.cf, name)?;
        Ok(())
    }
}

// RocksDB must manage thread safety for `ColumnFamily`.
// See rust-rocksdb/rust-rocksdb#407.
unsafe impl Send for SensorStore<'_> {}

#[cfg(feature = "bootroot")]
pub struct CustomerDeletionJobStore<'db> {
    db: &'db DB,
    cf: &'db ColumnFamily,
}

#[cfg(feature = "bootroot")]
impl CustomerDeletionJobStore<'_> {
    pub fn create(&self, customer_id: u32, job: &CustomerDataDeletion) -> Result<()> {
        if self
            .db
            .get_cf(self.cf, customer_id.to_be_bytes())?
            .is_some()
        {
            bail!("customer deletion job already exists for customer {customer_id}");
        }
        self.put(customer_id, job)
    }

    pub fn get(&self, customer_id: u32) -> Result<Option<CustomerDataDeletion>> {
        self.db
            .get_cf(self.cf, customer_id.to_be_bytes())?
            .map(|value| bincode::deserialize(&value).context("invalid customer deletion job"))
            .transpose()
    }

    pub fn update(&self, customer_id: u32, job: &CustomerDataDeletion) -> Result<()> {
        if self
            .db
            .get_cf(self.cf, customer_id.to_be_bytes())?
            .is_none()
        {
            bail!("customer deletion job does not exist for customer {customer_id}");
        }
        self.put(customer_id, job)
    }

    #[allow(dead_code)]
    pub fn delete(&self, customer_id: u32) -> Result<()> {
        self.db.delete_cf(self.cf, customer_id.to_be_bytes())?;
        Ok(())
    }

    fn put(&self, customer_id: u32, job: &CustomerDataDeletion) -> Result<()> {
        let value = bincode::serialize(job).context("cannot serialize customer deletion job")?;
        self.db
            .put_cf(self.cf, customer_id.to_be_bytes(), value)
            .context("cannot persist customer deletion job")
    }
}

#[cfg(feature = "bootroot")]
// RocksDB must manage thread safety for `ColumnFamily`.
// See rust-rocksdb/rust-rocksdb#407.
unsafe impl Send for CustomerDeletionJobStore<'_> {}

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
    fn get_range_end_key(&self) -> (Option<DateTime>, Option<DateTime>);
}

pub trait TimestampKeyExtractor {
    fn get_range_start_key(&self) -> (Option<DateTime>, Option<DateTime>);
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

    pub fn lower_closed_bound_end_key(mut self, time: Option<DateTime>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        let ns = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            0
        };
        self.pre_key.extend_from_slice(&ns.to_be_bytes());
        self
    }

    pub fn upper_open_bound_end_key(mut self, time: Option<DateTime>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        let ns = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            i64::MAX
        };
        self.pre_key.extend_from_slice(&ns.to_be_bytes());
        self
    }

    pub fn upper_closed_bound_end_key(mut self, time: Option<DateTime>) -> Self {
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

    pub fn mid_key(mut self, key: u64) -> Self {
        let mid_key = key.to_be_bytes();
        self.pre_key.reserve(mid_key.len());
        self.pre_key.extend_from_slice(&mid_key);
        self
    }

    pub fn lower_closed_bound_start_key(mut self, time: Option<DateTime>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        let ns = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            0
        };
        self.pre_key.extend_from_slice(&ns.to_be_bytes());
        self
    }

    pub fn upper_open_bound_start_key(mut self, time: Option<DateTime>) -> Self {
        self.pre_key.reserve(TIMESTAMP_SIZE);
        let ns = if let Some(time) = time {
            time.timestamp_nanos_opt().unwrap_or(i64::MAX)
        } else {
            i64::MAX
        };
        self.pre_key.extend_from_slice(&ns.to_be_bytes());
        self
    }

    pub fn upper_closed_bound_start_key(mut self, time: Option<DateTime>) -> Self {
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

pub struct FilteredIter<'d, T, F: RawEventFilter = crate::graphql::NetworkFilter> {
    inner: BoundaryIter<'d, T>,
    filter: &'d F,
}

impl<'d, T, F: RawEventFilter> FilteredIter<'d, T, F> {
    pub fn new(inner: BoundaryIter<'d, T>, filter: &'d F) -> Self {
        Self { inner, filter }
    }
}

impl<T, F: RawEventFilter> Iterator for FilteredIter<'_, T, F>
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
                elem.1.service_name(),
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

/// Performs one iteration of synchronous RocksDB retention cleanup.
fn retain_cleanup_iteration(
    db: &Database,
    retention_timestamp: i64,
    from_timestamp: [u8; 8],
) -> Result<()> {
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

    Ok(())
}

/// How long a cleanup pass waits before retrying an iteration whose blocking
/// task failed to join.
const BLOCKING_JOIN_BACKOFF: Duration = Duration::from_secs(1);

/// One day, in nanoseconds.
///
/// The step by which a pass relaxes its retention timestamp when disk usage
/// stays above `USAGE_LOW` after an iteration.
const ONE_DAY_TIMESTAMP_NANOS: i64 = 86_400_000_000_000;

/// How a cleanup pass ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PassOutcome {
    /// The pass ran every iteration it wanted to run.
    Completed,
    /// The pass observed cancellation and stopped early.
    Cancelled,
}

/// Runs the blocking cleanup iterations of one retention pass.
///
/// A pass is normally a single iteration. It repeats only while disk usage
/// stays above `USAGE_LOW`, each repeat relaxing `retention_timestamp` by a
/// further day until the pass either brings usage down or reaches
/// `now_timestamp` with nothing left to give.
///
/// `spawn_iteration` is what the pass calls to put one iteration on the
/// blocking pool; taking it as an argument is what lets a test drive the
/// cancellation and failure branches below without a database behind them.
///
/// # Cancellation
///
/// The pass never abandons an iteration it has already started: a blocking
/// task holds a database handle, and returning while it still runs would let
/// the lifecycle owner close the database underneath it. It stops between
/// iterations instead, so the permitted loss is the cleanup that was not
/// started yet. Nothing is lost by that: retention only deletes data that has
/// aged out, and data that has aged out stays aged out, so the next pass —
/// in this generation or the next — deletes exactly what this one skipped.
///
/// # Errors
///
/// Returns an error if an iteration reports one, or if an iteration's blocking
/// task cannot be joined while cancellation is in progress. A join failure
/// outside shutdown is retried after [`BLOCKING_JOIN_BACKOFF`] instead.
async fn retain_cleanup_pass<F>(
    cancel: &CancellationToken,
    mut retention_timestamp: i64,
    now_timestamp: i64,
    usage_flag: bool,
    mut spawn_iteration: F,
) -> Result<PassOutcome>
where
    F: FnMut(i64) -> JoinHandle<Result<()>>,
{
    loop {
        // Nothing is in flight here, so this is the cheap place to stop: the
        // iteration that is not scheduled is the one the next pass picks up.
        if cancel.is_cancelled() {
            return Ok(PassOutcome::Cancelled);
        }

        // Awaited, never aborted. `JoinHandle::abort` cannot stop a blocking
        // task that has already begun anyway, so aborting would only detach a
        // live RocksDB operation from the task that is supposed to be waiting
        // for it.
        match spawn_iteration(retention_timestamp).await {
            Ok(Ok(())) => {}
            // A cleanup error is the pass's own failure and is surfaced
            // whether or not shutdown is under way.
            Ok(Err(e)) => return Err(e),
            // The blocking task panicked or was aborted. During shutdown there
            // is no next pass to retry it, so it leaves through the return
            // value rather than a log line nobody is watching for.
            Err(e) if cancel.is_cancelled() => return Err(e.into()),
            Err(e) => {
                warn!(
                    "retention cleanup blocking task failed: {e}; \
                    retrying after backoff"
                );
                if cancel
                    .run_until_cancelled(time::sleep(BLOCKING_JOIN_BACKOFF))
                    .await
                    .is_none()
                {
                    return Ok(PassOutcome::Cancelled);
                }
                continue;
            }
        }

        // The iteration that was in flight has finished. Report the stop here
        // rather than falling through to the disk-usage decision, which would
        // announce a pass that shutdown cut short as a completed one.
        if cancel.is_cancelled() {
            return Ok(PassOutcome::Cancelled);
        }

        // Only a pass that started because the disk was over `USAGE_THRESHOLD`
        // has a reason to look at usage again, so the check is behind
        // `usage_flag` rather than beside it: a pass on a healthy disk asks
        // `roxy` nothing.
        if !usage_flag {
            return Ok(PassOutcome::Completed);
        }
        if !cfg!(test) && check_db_usage().await.1 {
            retention_timestamp += ONE_DAY_TIMESTAMP_NANOS;
            if retention_timestamp > now_timestamp {
                warn!("cannot delete data to usage under {USAGE_LOW}");
                return Ok(PassOutcome::Completed);
            }
        } else {
            info!("Disk usage is under {USAGE_LOW}%");
            return Ok(PassOutcome::Completed);
        }
    }
}

/// Deletes data that has aged out of the retention window, once per
/// `interval`, until `cancel` is cancelled.
///
/// This is the retention subsystem's entry task. It is registered in the
/// generation's top-level tracker, which is where `cancel` comes from and what
/// waits for this function to return; the lifecycle owner keeps the
/// [`JoinHandle`] so the value returned here — and a panic in place of one —
/// stays observable.
///
/// # Cancellation
///
/// Once cancellation begins no further pass is scheduled, and a pass that is
/// under way stops between iterations. The cleanup that shutdown defers this
/// way is not lost work: expired data stays expired, so the next pass deletes
/// it. What this function will not do is return while an iteration is still
/// running on the blocking pool, because the caller closes the database as
/// soon as this returns.
///
/// # Errors
///
/// Returns an error if the retention period cannot be expressed in
/// nanoseconds, or if a cleanup pass fails.
pub async fn retain_periodically(
    interval: Duration,
    retention_period: Duration,
    db: Database,
    cancel: CancellationToken,
) -> Result<()> {
    const DEFAULT_FROM_TIMESTAMP_NANOS: i64 = 61_000_000_000;

    let mut itv = time::interval(interval);
    let retention_duration = i64::try_from(retention_period.as_nanos())?;
    let from_timestamp = DEFAULT_FROM_TIMESTAMP_NANOS.to_be_bytes();
    loop {
        select! {
            // Biased so that a tick that came due in the same poll as the
            // cancellation cannot win the race and open one more pass.
            biased;
            () = cancel.cancelled() => return Ok(()),
            _ = itv.tick() => {}
        }

        info!("Begin to cleanup the database based on retention period.");
        let now = DateTime::now();
        let mut retention_timestamp =
            now.timestamp_nanos_opt().unwrap_or(retention_duration) - retention_duration;
        let mut usage_flag = false;

        if !cfg!(test) && check_db_usage().await.0 {
            info!(
                "Disk usage is over {USAGE_THRESHOLD}%. \
                Retention period is temporarily reduced."
            );
            retention_timestamp += ONE_DAY_TIMESTAMP_NANOS;
            usage_flag = true;
        }

        let now_timestamp = now.timestamp_nanos_opt().unwrap_or(0);
        let outcome = retain_cleanup_pass(
            &cancel,
            retention_timestamp,
            now_timestamp,
            usage_flag,
            |retention_timestamp| {
                let db = db.clone();
                tokio::task::spawn_blocking(move || {
                    retain_cleanup_iteration(&db, retention_timestamp, from_timestamp)
                })
            },
        )
        .await?;

        if outcome == PassOutcome::Cancelled {
            return Ok(());
        }
        info!("Database cleanup completed.");
    }
}

/// Returns the boolean of the disk usages over `USAGE_THRESHOLD` and `USAGE_LOW`.
async fn check_db_usage() -> (bool, bool) {
    let resource_usage = roxy::resource_usage().await;
    let total_disk_space = resource_usage
        .disk_used_bytes
        .saturating_add(resource_usage.disk_available_bytes);
    let usage = resource_usage
        .disk_used_bytes
        .saturating_mul(100)
        .checked_div(total_disk_space)
        .unwrap_or(0);
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use anyhow::anyhow;
    use giganto_client::ingest::network::Conn;
    use giganto_client::ingest::statistics::Statistics;
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;

    use super::{
        BoundaryIter, Database, DbOptions, RAW_DATA_COLUMN_FAMILY_NAMES, RawEventStore,
        StatisticsIter, StorageKey, read_compression_metadata, store_compression_metadata,
    };
    #[cfg(feature = "bootroot")]
    use super::{CUSTOMER_DELETION_JOBS_CF, CustomerDataDeletion, CustomerDataDeletionStatus};
    use crate::datetime::DateTime;

    fn setup_db() -> (TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
        (dir, db)
    }

    fn conn_key(sensor: &str, timestamp: i64) -> Vec<u8> {
        StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key()
    }

    fn register_sensor(db: &Database, sensor: &str) {
        let sensor_store = db.sensors_store().unwrap();
        sensor_store.insert(sensor, DateTime::now()).unwrap();
    }

    #[cfg(feature = "bootroot")]
    #[test]
    fn customer_deletion_job_uses_customer_id_key_and_roundtrips_value() {
        let (_dir, db) = setup_db();
        let store = db.customer_deletion_job_store().unwrap();
        let customer_id = 0x0102_0304;
        let requested_at = DateTime::now().timestamp_nanos_opt().unwrap();
        let job = CustomerDataDeletion {
            service_fqdn_list: vec![
                "piglet.node1.example.test".to_string(),
                "reproduce.node1.example.test".to_string(),
            ],
            requested_at,
            status: CustomerDataDeletionStatus::InProgress,
            completed_at: None,
            error: None,
        };

        store.create(customer_id, &job).unwrap();

        assert_eq!(store.get(customer_id).unwrap(), Some(job.clone()));
        let duplicate = CustomerDataDeletion {
            status: CustomerDataDeletionStatus::Failed,
            completed_at: Some(requested_at),
            error: Some("must not replace the existing job".to_string()),
            ..job.clone()
        };
        assert!(store.create(customer_id, &duplicate).is_err());
        assert_eq!(store.get(customer_id).unwrap(), Some(job.clone()));

        let missing_customer_id = customer_id + 1;
        assert!(store.update(missing_customer_id, &duplicate).is_err());
        assert!(store.get(missing_customer_id).unwrap().is_none());

        let cf = db.get_cf_handle(CUSTOMER_DELETION_JOBS_CF).unwrap();
        let entries = db
            .db
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(&*entries[0].0, customer_id.to_be_bytes());
        let stored: CustomerDataDeletion = bincode::deserialize(&entries[0].1).unwrap();
        assert_eq!(stored.service_fqdn_list, job.service_fqdn_list);
        assert_eq!(stored.requested_at, requested_at);

        let completed_at = DateTime::now().timestamp_nanos_opt().unwrap();
        let failed = CustomerDataDeletion {
            status: CustomerDataDeletionStatus::Failed,
            completed_at: Some(completed_at),
            error: Some("failure".to_string()),
            ..job
        };
        store.update(customer_id, &failed).unwrap();
        assert_eq!(store.get(customer_id).unwrap(), Some(failed));

        store.delete(customer_id).unwrap();
        assert!(store.get(customer_id).unwrap().is_none());
    }

    fn insert_conn(store: &RawEventStore<Conn>, sensor: &str, timestamp: i64, value: &[u8]) {
        let key = conn_key(sensor, timestamp);
        store.append(&key, value).unwrap();
    }

    fn assert_conn_key_exists(db: &Database, key: &[u8]) {
        let cf = db.get_cf_handle("conn").unwrap();
        assert!(db.db.get_cf(cf, key).unwrap().is_some());
    }

    fn append_and_assert_first_conn(db: &Database, key: &[u8], value: &[u8]) {
        let conn_store = db.conn_store().unwrap();
        conn_store.append(key, value).unwrap();
        let mut iter = conn_store.iter_forward();
        let (k, v) = iter.next().unwrap().unwrap();
        assert_eq!(&*k, key);
        assert_eq!(&*v, value);
    }

    #[test]
    fn test_compression_metadata_enabled() {
        let dir = tempfile::tempdir().unwrap();

        store_compression_metadata(dir.path(), true).unwrap();
        let value = read_compression_metadata(dir.path()).unwrap();

        assert_eq!(value, Some(true));
    }

    #[test]
    fn test_compression_metadata_disabled() {
        let dir = tempfile::tempdir().unwrap();

        store_compression_metadata(dir.path(), false).unwrap();
        let value = read_compression_metadata(dir.path()).unwrap();

        assert_eq!(value, Some(false));
    }

    #[test]
    fn test_compression_metadata_missing_file() {
        let dir = tempfile::tempdir().unwrap();

        let value = read_compression_metadata(dir.path()).unwrap();

        assert_eq!(value, None);
    }

    #[test]
    fn test_compression_metadata_invalid_data() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::write(dir.path().join("COMPRESSION"), "invalid").unwrap();

        let result = read_compression_metadata(dir.path());
        let err = result.expect_err("Operation should have failed");
        assert!(err.to_string().contains("invalid compression metadata:"));
    }

    #[test]
    fn test_database_open_fails_with_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not_a_dir");
        std::fs::write(&file_path, "not a directory").unwrap();

        let result = Database::open(&file_path, &DbOptions::default());
        let Err(err) = result else {
            panic!("expected open to fail for file path")
        };
        let has_rocksdb = err
            .chain()
            .any(|cause| cause.downcast_ref::<rocksdb::Error>().is_some());
        let has_not_a_directory = err.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotADirectory)
        });
        assert!(
            has_rocksdb || has_not_a_directory,
            "unexpected error chain: {err:?}"
        );
    }

    /// Test `SensorStore` insert with `DateTime` conversion
    #[test]
    fn test_sensor_store_datetime_to_timestamp() {
        let (_dir, db) = setup_db();
        let sensor_store = db.sensors_store().unwrap();

        // Test with current time
        let now = DateTime::now();
        let result = sensor_store.insert("test_sensor", now);
        assert!(result.is_ok());

        // Test with specific timestamp
        let specific_time = DateTime::from_timestamp_nanos(1_700_000_000_000_000_000);
        let result = sensor_store.insert("test_sensor_2", specific_time);
        assert!(result.is_ok());

        // Test with boundary values
        let min_time = DateTime::min_utc();
        let result = sensor_store.insert("test_sensor_min", min_time);
        assert!(result.is_ok());

        let max_time = DateTime::max_utc();
        let result = sensor_store.insert("test_sensor_max", max_time);
        assert!(result.is_ok());

        // Verify inserted values
        let list = sensor_store.sensor_list();
        assert_eq!(list.len(), 4);
        assert!(list.contains("test_sensor"));
        assert!(list.contains("test_sensor_2"));
        assert!(list.contains("test_sensor_min"));
        assert!(list.contains("test_sensor_max"));

        let cf = db.get_cf_handle("sensors").unwrap();
        let val = db.db.get_cf(cf, "test_sensor").unwrap().unwrap();
        assert_eq!(
            val,
            now.timestamp_nanos_opt().unwrap().to_be_bytes().to_vec()
        );

        let val = db.db.get_cf(cf, "test_sensor_2").unwrap().unwrap();
        assert_eq!(
            val,
            specific_time
                .timestamp_nanos_opt()
                .unwrap()
                .to_be_bytes()
                .to_vec()
        );

        let val = db.db.get_cf(cf, "test_sensor_min").unwrap().unwrap();
        assert_eq!(
            val,
            min_time
                .timestamp_nanos_opt()
                .unwrap_or(i64::MAX)
                .to_be_bytes()
                .to_vec()
        );

        let val = db.db.get_cf(cf, "test_sensor_max").unwrap().unwrap();
        assert_eq!(
            val,
            max_time
                .timestamp_nanos_opt()
                .unwrap_or(i64::MAX)
                .to_be_bytes()
                .to_vec()
        );
    }

    #[test]
    fn test_sensor_store_names_and_list() {
        let (_dir, db) = setup_db();
        let sensor_store = db.sensors_store().unwrap();

        let now = DateTime::now();
        sensor_store.insert("sensor1", now).unwrap();
        sensor_store.insert("sensor2", now).unwrap();

        let names = sensor_store.names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"sensor1".to_vec()));
        assert!(names.contains(&b"sensor2".to_vec()));

        let list = sensor_store.sensor_list();
        assert_eq!(list.len(), 2);
        assert!(list.contains("sensor1"));
        assert!(list.contains("sensor2"));
    }

    #[test]
    fn test_batched_multi_get_from_ts_returns_sorted_values() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();
        let sensor = "batch-sensor";
        let other_sensor = "ignored-sensor";

        let ts_early_nanos = 1_700_000_000_000_000_000_i64;
        let ts_late_nanos = ts_early_nanos + 2_000_000_000;
        let ts_missing_nanos = ts_late_nanos + 2_000_000_000;
        let ts_early = DateTime::from_timestamp_nanos(ts_early_nanos);
        let ts_late = DateTime::from_timestamp_nanos(ts_late_nanos);
        let ts_missing = DateTime::from_timestamp_nanos(ts_missing_nanos);

        let key_early = StorageKey::builder()
            .start_key(sensor)
            .end_key(ts_early_nanos)
            .build()
            .key();
        store.append(&key_early, b"alpha").unwrap();

        let key_late = StorageKey::builder()
            .start_key(sensor)
            .end_key(ts_late_nanos)
            .build()
            .key();
        store.append(&key_late, b"omega").unwrap();

        // Insert an entry for another sensor to ensure filtering by sensor id.
        let other_key = StorageKey::builder()
            .start_key(other_sensor)
            .end_key(ts_early_nanos)
            .build()
            .key();
        store.append(&other_key, b"other").unwrap();

        let query_times = [ts_late, ts_missing, ts_early];
        let results = store.batched_multi_get_from_ts(sensor, &query_times);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, ts_early);
        assert_eq!(results[0].1, b"alpha");
        assert_eq!(results[1].0, ts_late);
        assert_eq!(results[1].1, b"omega");
    }

    #[test]
    fn test_raw_event_store_delete() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();
        let key = b"test_key";
        let value = b"test_value";

        store.append(key, value).unwrap();
        store.delete(key).unwrap();

        let deleted = store.db.get_cf(store.cf, key).unwrap();
        assert!(deleted.is_none());
    }

    #[test]
    fn test_raw_event_store_batched_multi_get_with_sensor() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();
        let sensor = "sensor1";

        let ts1 = 1_000_000_000;
        let ts2 = 2_000_000_000;

        let key1 = StorageKey::builder()
            .start_key(sensor)
            .end_key(ts1)
            .build()
            .key();
        let key2 = StorageKey::builder()
            .start_key(sensor)
            .end_key(ts2)
            .build()
            .key();

        store.append(&key1, b"val1").unwrap();
        store.append(&key2, b"val2").unwrap();

        let timestamps = [ts1, ts2, 3_000_000_000];
        let results = store.batched_multi_get_with_sensor(sensor, &timestamps);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, ts1);
        assert_eq!(results[0].1, sensor);
        assert_eq!(results[0].2, b"val1");
        assert_eq!(results[1].0, ts2);
        assert_eq!(results[1].1, sensor);
        assert_eq!(results[1].2, b"val2");
    }

    #[test]
    fn test_raw_event_store_batched_multi_get_with_sensor_sorts_input() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();
        let sensor = "sensor-sort";

        let ts1 = 1_000_000_000;
        let ts2 = 2_000_000_000;

        let key1 = conn_key(sensor, ts1);
        let key2 = conn_key(sensor, ts2);

        store.append(&key1, b"val1").unwrap();
        store.append(&key2, b"val2").unwrap();

        let timestamps = [ts2, ts1];
        let results = store.batched_multi_get_with_sensor(sensor, &timestamps);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, ts1);
        assert_eq!(results[0].1, sensor);
        assert_eq!(results[0].2, b"val1");
        assert_eq!(results[1].0, ts2);
        assert_eq!(results[1].1, sensor);
        assert_eq!(results[1].2, b"val2");
    }

    #[test]
    fn test_raw_event_store_iter_forward() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();

        store.append(b"key1", b"val1").unwrap();
        store.append(b"key2", b"val2").unwrap();

        let mut iter = store.iter_forward();
        let item1 = iter.next().unwrap().unwrap();
        assert_eq!(item1.0.as_ref(), b"key1");
        assert_eq!(item1.1.as_ref(), b"val1");

        let item2 = iter.next().unwrap().unwrap();
        assert_eq!(item2.0.as_ref(), b"key2");
        assert_eq!(item2.1.as_ref(), b"val2");

        assert!(iter.next().is_none());
    }

    fn create_test_conn(orig_addr: &str) -> Conn {
        Conn {
            orig_addr: orig_addr.parse().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: "sf".to_string(),
            start_time: DateTime::now().timestamp_nanos_opt().unwrap(),
            duration: 1000,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 21515,
            resp_l2_bytes: 27889,
        }
    }

    fn create_test_statistics() -> Statistics {
        Statistics {
            core: 0,
            period: 600,
            stats: vec![],
        }
    }

    fn assert_conn_fields(actual: &Conn, expected: &Conn) {
        assert_eq!(actual.orig_addr, expected.orig_addr);
        assert_eq!(actual.orig_port, expected.orig_port);
        assert_eq!(actual.resp_addr, expected.resp_addr);
        assert_eq!(actual.resp_port, expected.resp_port);
        assert_eq!(actual.proto, expected.proto);
        assert_eq!(actual.conn_state, expected.conn_state);
        assert_eq!(actual.start_time, expected.start_time);
        assert_eq!(actual.duration, expected.duration);
        assert_eq!(actual.service, expected.service);
        assert_eq!(actual.orig_bytes, expected.orig_bytes);
        assert_eq!(actual.resp_bytes, expected.resp_bytes);
        assert_eq!(actual.orig_pkts, expected.orig_pkts);
        assert_eq!(actual.resp_pkts, expected.resp_pkts);
        assert_eq!(actual.orig_l2_bytes, expected.orig_l2_bytes);
        assert_eq!(actual.resp_l2_bytes, expected.resp_l2_bytes);
    }

    fn insert_conn_keys(store: &RawEventStore<Conn>, conn: &Conn, keys: &[&[u8]]) {
        let value = bincode::serialize(conn).unwrap();
        for key in keys {
            store.append(key, &value).unwrap();
        }
    }

    fn assert_next_conn(
        iter: &mut BoundaryIter<'_, Conn>,
        expected_key: &[u8],
        expected_conn: &Conn,
    ) {
        let item = iter.next().unwrap().unwrap();
        assert_eq!(item.0.as_ref(), expected_key);
        assert_conn_fields(&item.1, expected_conn);
    }

    #[test]
    fn test_boundary_iter() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();

        let conn = create_test_conn("192.168.4.76");
        insert_conn_keys(&store, &conn, &[b"key0", b"key1", b"key2"]);

        let mut boundary_iter = store.boundary_iter(b"key1", b"key2", super::Direction::Forward);

        assert_next_conn(&mut boundary_iter, b"key1", &conn);
        assert!(boundary_iter.next().is_none());
    }

    #[test]
    fn test_boundary_iter_reverse() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();

        let conn = create_test_conn("192.168.4.76");
        insert_conn_keys(&store, &conn, &[b"key0", b"key1", b"key2"]);

        let mut boundary_iter = store.boundary_iter(b"key2", b"key1", super::Direction::Reverse);

        assert_next_conn(&mut boundary_iter, b"key2", &conn);
        assert_next_conn(&mut boundary_iter, b"key1", &conn);
        assert!(boundary_iter.next().is_none());
    }

    #[test]
    fn test_boundary_iter_reverse_from_equals_to() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();

        let conn = create_test_conn("192.168.4.76");
        insert_conn_keys(&store, &conn, &[b"key1", b"key2"]);

        let mut same_iter = store.boundary_iter(b"key1", b"key1", super::Direction::Reverse);
        assert_next_conn(&mut same_iter, b"key1", &conn);
        assert!(same_iter.next().is_none());
    }

    #[test]
    fn test_boundary_iter_reverse_empty_range() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();

        let conn = create_test_conn("192.168.4.76");
        insert_conn_keys(&store, &conn, &[b"key1", b"key2"]);

        let mut empty_iter = store.boundary_iter(b"key0", b"key2", super::Direction::Reverse);
        assert!(empty_iter.next().is_none());
    }

    #[test]
    fn test_boundary_iter_reverse_missing_bounds() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();

        let conn = create_test_conn("192.168.4.76");
        insert_conn_keys(&store, &conn, &[b"key1", b"key2"]);

        let mut high_from_iter = store.boundary_iter(b"key3", b"key1", super::Direction::Reverse);
        assert_next_conn(&mut high_from_iter, b"key2", &conn);
        assert_next_conn(&mut high_from_iter, b"key1", &conn);
        assert!(high_from_iter.next().is_none());

        let mut missing_range_iter =
            store.boundary_iter(b"key4", b"key3", super::Direction::Reverse);
        assert!(missing_range_iter.next().is_none());
    }

    #[test]
    fn test_statistics_iter() {
        let (_dir, db) = setup_db();
        let store = db.statistics_store().unwrap();

        let stats = create_test_statistics();
        let value = bincode::serialize(&stats).unwrap();
        store.append(b"key1", &value).unwrap();

        let boundary_iter = store.boundary_iter(b"key1", b"key2", super::Direction::Forward);
        let mut stats_iter = StatisticsIter::new(boundary_iter);

        let item = stats_iter.next().unwrap();
        assert_eq!(item.0.as_ref(), b"key1");
        assert_eq!(item.1.core, stats.core);
        assert_eq!(item.1.period, stats.period);
        assert!(item.1.stats.is_empty());
    }

    /// Test `StorageKeyBuilder` with timestamp boundaries
    #[test]
    fn test_storage_key_builder_lower_bound() {
        // Test with None (should use 0)
        let key_none = StorageKey::builder()
            .start_key("test_source")
            .lower_closed_bound_end_key(None)
            .build();
        let expected_none = {
            let mut k = b"test_source\0".to_vec();
            k.extend_from_slice(&0_i64.to_be_bytes());
            k
        };
        assert_eq!(*key_none.key(), expected_none);

        // Test with Some(DateTime)
        let some_time = DateTime::from_timestamp_nanos(1_000_000_000);
        let key_some = StorageKey::builder()
            .start_key("test_source")
            .lower_closed_bound_end_key(Some(some_time))
            .build();
        let expected_some = {
            let mut k = b"test_source\0".to_vec();
            k.extend_from_slice(&1_000_000_000_i64.to_be_bytes());
            k
        };
        assert_eq!(*key_some.key(), expected_some);

        // Test with MIN timestamp
        let min_time = DateTime::from_timestamp_nanos(i64::MIN);
        let key_min = StorageKey::builder()
            .start_key("test_source")
            .lower_closed_bound_end_key(Some(min_time))
            .build();
        let expected_min = {
            let mut k = b"test_source\0".to_vec();
            k.extend_from_slice(&i64::MIN.to_be_bytes());
            k
        };
        assert_eq!(*key_min.key(), expected_min);
    }

    /// Test `StorageKeyBuilder` with upper bound edge cases
    #[test]
    fn test_storage_key_builder_upper_bound() {
        // Test upper_closed_bound with None (should use i64::MAX)
        let key_none = StorageKey::builder()
            .start_key("test_source")
            .upper_closed_bound_end_key(None)
            .build();
        let expected_none = {
            let mut k = b"test_source\0".to_vec();
            k.extend_from_slice(&i64::MAX.to_be_bytes());
            k
        };
        assert_eq!(*key_none.key(), expected_none);

        // Test upper_closed_bound with Some(DateTime)
        // Should subtract 1 if possible
        let some_time = DateTime::from_timestamp_nanos(2_000_000_000);
        let key_some = StorageKey::builder()
            .start_key("test_source")
            .upper_closed_bound_end_key(Some(some_time))
            .build();
        let expected_some = {
            let mut k = b"test_source\0".to_vec();
            k.extend_from_slice(&1_999_999_999_i64.to_be_bytes());
            k
        };
        assert_eq!(*key_some.key(), expected_some);

        // Test upper_closed_bound with 0 (edge case)
        // When timestamp is 0, subtracting 1 gives -1, which fails >= 0 check
        // So it falls through to i64::MAX
        let zero_time = DateTime::from_timestamp_nanos(0);
        let key_zero = StorageKey::builder()
            .start_key("test_source")
            .upper_closed_bound_end_key(Some(zero_time))
            .build();
        let expected_zero = {
            let mut k = b"test_source\0".to_vec();
            k.extend_from_slice(&i64::MAX.to_be_bytes());
            k
        };
        assert_eq!(*key_zero.key(), expected_zero);

        // Test upper_open_bound with None (should use i64::MAX)
        let key_open_none = StorageKey::builder()
            .start_key("test_source")
            .upper_open_bound_end_key(None)
            .build();
        let expected_open_none = {
            let mut k = b"test_source\0".to_vec();
            k.extend_from_slice(&i64::MAX.to_be_bytes());
            k
        };
        assert_eq!(*key_open_none.key(), expected_open_none);

        // Test upper_open_bound with Some(DateTime)
        let some_time_open = DateTime::from_timestamp_nanos(3_000_000_000);
        let key_open_some = StorageKey::builder()
            .start_key("test_source")
            .upper_open_bound_end_key(Some(some_time_open))
            .build();
        let expected_open_some = {
            let mut k = b"test_source\0".to_vec();
            k.extend_from_slice(&3_000_000_000_i64.to_be_bytes());
            k
        };
        assert_eq!(*key_open_some.key(), expected_open_some);
    }

    #[test]
    fn test_storage_timestamp_key_builder_lower_bound() {
        // None uses zero epoch nanos
        let key_none = StorageKey::timestamp_builder()
            .start_key(42)
            .lower_closed_bound_start_key(None)
            .build()
            .key();
        let mut expected_none = 42_i64.to_be_bytes().to_vec();
        expected_none.extend_from_slice(&0_i64.to_be_bytes());
        assert_eq!(key_none, expected_none);

        // Specific DateTime should be preserved exactly
        let some_time = DateTime::from_timestamp_nanos(4_200_000_000);
        let key_some = StorageKey::timestamp_builder()
            .start_key(42)
            .lower_closed_bound_start_key(Some(some_time))
            .build()
            .key();
        let mut expected_some = 42_i64.to_be_bytes().to_vec();
        expected_some.extend_from_slice(&4_200_000_000_i64.to_be_bytes());
        assert_eq!(key_some, expected_some);

        // MIN timestamp preserves i64::MIN nanoseconds
        let min_time = DateTime::min_utc();
        let key_min = StorageKey::timestamp_builder()
            .start_key(42)
            .lower_closed_bound_start_key(Some(min_time))
            .build()
            .key();
        let mut expected_min = 42_i64.to_be_bytes().to_vec();
        expected_min.extend_from_slice(&i64::MIN.to_be_bytes());
        assert_eq!(key_min, expected_min);

        // Out-of-range timestamps still fall back to i64::MAX
        let overflow_time =
            DateTime::from("3000-01-01T00:00:00Z".parse::<jiff::Timestamp>().unwrap());
        let key_overflow = StorageKey::timestamp_builder()
            .start_key(42)
            .lower_closed_bound_start_key(Some(overflow_time))
            .build()
            .key();
        let mut expected_overflow = 42_i64.to_be_bytes().to_vec();
        expected_overflow.extend_from_slice(&i64::MAX.to_be_bytes());
        assert_eq!(key_overflow, expected_overflow);
    }

    #[test]
    fn test_storage_timestamp_key_builder_upper_bound() {
        // upper_open_bound_start_key with None falls back to i64::MAX
        let key_open_none = StorageKey::timestamp_builder()
            .start_key(7)
            .upper_open_bound_start_key(None)
            .build()
            .key();
        let mut expected_open_none = 7_i64.to_be_bytes().to_vec();
        expected_open_none.extend_from_slice(&i64::MAX.to_be_bytes());
        assert_eq!(key_open_none, expected_open_none);

        // upper_open_bound_start_key with Some(DateTime) preserves the timestamp
        let open_time = DateTime::from_timestamp_nanos(8_000_000_000);
        let key_open_some = StorageKey::timestamp_builder()
            .start_key(7)
            .upper_open_bound_start_key(Some(open_time))
            .build()
            .key();
        let mut expected_open_some = 7_i64.to_be_bytes().to_vec();
        expected_open_some.extend_from_slice(&8_000_000_000_i64.to_be_bytes());
        assert_eq!(key_open_some, expected_open_some);

        // upper_closed_bound_start_key subtracts one nanosecond when possible
        let closed_time = DateTime::from_timestamp_nanos(9_000_000_000);
        let key_closed_some = StorageKey::timestamp_builder()
            .start_key(7)
            .upper_closed_bound_start_key(Some(closed_time))
            .build()
            .key();
        let mut expected_closed_some = 7_i64.to_be_bytes().to_vec();
        expected_closed_some.extend_from_slice(&8_999_999_999_i64.to_be_bytes());
        assert_eq!(key_closed_some, expected_closed_some);

        // When subtraction would underflow, it should fall back to i64::MAX
        let zero_time = DateTime::from_timestamp_nanos(0);
        let key_zero = StorageKey::timestamp_builder()
            .start_key(7)
            .upper_closed_bound_start_key(Some(zero_time))
            .build()
            .key();
        let mut expected_zero = 7_i64.to_be_bytes().to_vec();
        expected_zero.extend_from_slice(&i64::MAX.to_be_bytes());
        assert_eq!(key_zero, expected_zero);
    }

    #[test]
    fn test_storage_key_builder_mid_key() {
        let key = StorageKey::builder()
            .start_key("source")
            .mid_key(Some(b"mid".to_vec()))
            .end_key(12345)
            .build()
            .key();

        let mut expected = b"source\0".to_vec();
        expected.extend_from_slice(b"mid\0");
        expected.extend_from_slice(&12345_i64.to_be_bytes());
        assert_eq!(key, expected);

        let key_none = StorageKey::builder()
            .start_key("source")
            .mid_key(None)
            .end_key(12345)
            .build()
            .key();

        let mut expected_none = b"source\0".to_vec();
        expected_none.extend_from_slice(&12345_i64.to_be_bytes());
        assert_eq!(key_none, expected_none);
    }

    #[test]
    fn test_to_hms() {
        assert_eq!(super::to_hms(std::time::Duration::from_secs(0)), "00:00:00");
        assert_eq!(
            super::to_hms(std::time::Duration::from_secs(61)),
            "00:01:01"
        );
        assert_eq!(
            super::to_hms(std::time::Duration::from_secs(3661)),
            "01:01:01"
        );
    }

    #[test]
    fn test_data_dir_to_db_path() {
        let path = std::path::Path::new("/tmp/data");
        let db_path = super::data_dir_to_db_path(path);
        assert_eq!(db_path, path.join("db"));
    }

    #[test]
    fn test_validate_compression_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        // First run: should create metadata
        super::validate_compression_metadata(data_dir, true).unwrap();
        let metadata_path = data_dir.join("COMPRESSION");
        assert!(metadata_path.exists());
        assert_eq!(std::fs::read_to_string(metadata_path).unwrap(), "enabled");

        // Second run: should match
        super::validate_compression_metadata(data_dir, true).unwrap();

        // Third run: should mismatch
        let result = super::validate_compression_metadata(data_dir, false);
        let err = result.expect_err("Operation should have failed");
        assert!(err.to_string().contains("Compression scheme mismatch"));
    }

    #[test]
    fn test_database_shutdown() {
        let (_dir, db) = setup_db();
        let result = db.shutdown();
        assert!(result.is_ok());
    }

    #[cfg(all(test, feature = "storage_diagnostics"))]
    #[test]
    fn test_properties_cf() {
        let (_dir, db) = setup_db();
        let conn = db.conn_store().unwrap();
        conn.append(b"key", b"value").unwrap();
        let props = db
            .properties_cf("conn")
            .expect("properties_cf should succeed");
        assert!(props.estimate_num_keys > 0);
        assert!(!props.stats.is_empty());
    }

    #[test]
    fn test_retain_period_store() {
        let (_dir, db) = setup_db();
        let stores = db
            .retain_period_store()
            .expect("Failed to get retain stores");

        let total_count = stores.standard_cfs.len() + stores.non_standard_cfs.len();
        assert_eq!(total_count, RAW_DATA_COLUMN_FAMILY_NAMES.len());
    }

    #[tokio::test]
    async fn test_retain_periodically_shutdown() {
        let (_dir, db) = setup_db();
        let cancel = CancellationToken::new();

        let task = tokio::spawn(super::retain_periodically(
            std::time::Duration::from_millis(10),
            std::time::Duration::from_hours(1),
            db,
            cancel.clone(),
        ));

        cancel.cancel();
        let result = task.await.unwrap();
        assert!(result.is_ok());
    }

    /// A token cancelled before the entry task is ever polled opens no pass.
    ///
    /// The interval fires its first tick immediately, so this is the race the
    /// biased `select!` decides: cancellation wins, and the expired data is
    /// left for the next generation to delete.
    #[tokio::test]
    async fn cancellation_before_the_first_tick_opens_no_pass() {
        let (_dir, db) = setup_db();
        let sensor = "cancelled_before_start";
        register_sensor(&db, sensor);

        let now_nanos = DateTime::now().timestamp_nanos_opt().unwrap();
        let expired_key = conn_key(sensor, now_nanos - 10_000_000_000);
        insert_conn(
            &db.conn_store().unwrap(),
            sensor,
            now_nanos - 10_000_000_000,
            b"old",
        );
        assert_conn_key_exists(&db, &expired_key);

        let cancel = CancellationToken::new();
        cancel.cancel();

        let result = super::retain_periodically(
            std::time::Duration::from_millis(10),
            std::time::Duration::from_secs(2),
            db.clone(),
            cancel,
        )
        .await;

        assert!(result.is_ok());
        // The permitted loss, stated as a test: cleanup that never started is
        // deferred, not performed.
        assert_conn_key_exists(&db, &expired_key);
    }

    /// A pass that is cancelled does not schedule another iteration.
    #[tokio::test]
    async fn a_cancelled_pass_schedules_no_iteration() {
        let cancel = CancellationToken::new();
        cancel.cancel();

        let outcome = super::retain_cleanup_pass(&cancel, 0, 0, true, |_retention_timestamp| {
            panic!("a cancelled pass must not schedule an iteration");
        })
        .await
        .expect("a cancelled pass is not a failure");

        assert_eq!(outcome, super::PassOutcome::Cancelled);
    }

    /// A pass opened by disk pressure still runs one iteration and completes.
    ///
    /// Under `cfg!(test)` the pass asks `roxy` nothing, so the repeat that
    /// disk pressure would drive never triggers here; what this pins down is
    /// that raising `usage_flag` neither skips the iteration nor turns a
    /// finished pass into a repeating one.
    #[tokio::test]
    async fn a_disk_pressure_pass_completes_after_one_iteration() {
        let cancel = CancellationToken::new();
        let iterations = Arc::new(AtomicUsize::new(0));

        let outcome = super::retain_cleanup_pass(&cancel, 0, i64::MAX, true, {
            let iterations = Arc::clone(&iterations);
            move |_retention_timestamp| {
                iterations.fetch_add(1, Ordering::SeqCst);
                tokio::task::spawn_blocking(|| Ok(()))
            }
        })
        .await
        .expect("a pass with no failing iteration should complete");

        assert_eq!(outcome, super::PassOutcome::Completed);
        assert_eq!(iterations.load(Ordering::SeqCst), 1);
    }

    /// Cancellation waits out the blocking iteration that is already running.
    ///
    /// The stand-in iteration blocks until the test releases it, which is what
    /// lets the test assert the thing that matters: the pass is still waiting
    /// while the iteration runs, and the iteration ran to its end rather than
    /// being abandoned.
    #[tokio::test]
    async fn cancellation_awaits_the_running_blocking_iteration() {
        let cancel = CancellationToken::new();
        let started = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let pass = tokio::spawn({
            let cancel = cancel.clone();
            let started = Arc::clone(&started);
            let finished = Arc::clone(&finished);
            let mut release_rx = Some(release_rx);
            async move {
                super::retain_cleanup_pass(&cancel, 0, 0, false, move |_retention_timestamp| {
                    let release_rx = release_rx.take().expect("one iteration only");
                    let started = Arc::clone(&started);
                    let finished = Arc::clone(&finished);
                    tokio::task::spawn_blocking(move || {
                        started.store(true, Ordering::SeqCst);
                        release_rx.recv().expect("the test releases the iteration");
                        finished.store(true, Ordering::SeqCst);
                        Ok(())
                    })
                })
                .await
            }
        });

        while !started.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(
            !pass.is_finished(),
            "the pass returned while its blocking iteration was still running"
        );
        assert!(!finished.load(Ordering::SeqCst));

        release_tx.send(()).expect("the iteration is waiting");
        let outcome = pass
            .await
            .expect("the pass task should not panic")
            .expect("a cancelled pass is not a failure");

        assert_eq!(outcome, super::PassOutcome::Cancelled);
        assert!(
            finished.load(Ordering::SeqCst),
            "the blocking iteration should have run to its end"
        );
    }

    /// A cleanup error leaves through the return value, cancelled or not.
    #[tokio::test]
    async fn a_failed_iteration_is_reported_to_the_caller() {
        let cancel = CancellationToken::new();

        let error = super::retain_cleanup_pass(&cancel, 0, 0, false, |_retention_timestamp| {
            tokio::task::spawn_blocking(|| Err(anyhow!("cleanup failed")))
        })
        .await
        .expect_err("a failed iteration should fail the pass");

        assert!(error.to_string().contains("cleanup failed"));
    }

    /// A blocking iteration that panics during shutdown is not swallowed.
    ///
    /// Outside shutdown the pass retries, so there is a next iteration to
    /// report the trouble. During shutdown there is not, and the lifecycle
    /// owner reads the return value.
    #[tokio::test]
    async fn a_panic_during_cancellation_is_reported_to_the_caller() {
        let cancel = CancellationToken::new();

        let error = super::retain_cleanup_pass(&cancel, 0, 0, false, {
            let cancel = cancel.clone();
            move |_retention_timestamp| {
                let cancel = cancel.clone();
                tokio::task::spawn_blocking(move || {
                    cancel.cancel();
                    panic!("cleanup panicked");
                })
            }
        })
        .await
        .expect_err("a panicking iteration should fail the pass during shutdown");

        assert!(error.to_string().contains("panic"));
    }

    /// A blocking iteration that panics outside shutdown is retried.
    ///
    /// Time is paused, so the backoff between the two iterations costs no
    /// wall-clock time.
    #[tokio::test(start_paused = true)]
    async fn a_panicking_iteration_is_retried_outside_shutdown() {
        let cancel = CancellationToken::new();
        let iterations = Arc::new(AtomicUsize::new(0));

        let outcome = super::retain_cleanup_pass(&cancel, 0, 0, false, {
            let iterations = Arc::clone(&iterations);
            move |_retention_timestamp| {
                let attempt = iterations.fetch_add(1, Ordering::SeqCst);
                tokio::task::spawn_blocking(move || {
                    assert!(attempt > 0, "cleanup panicked");
                    Ok(())
                })
            }
        })
        .await
        .expect("the retry should carry the pass to completion");

        assert_eq!(outcome, super::PassOutcome::Completed);
        assert_eq!(iterations.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_retain_periodically_deletes_expired_data() {
        let (_dir, db) = setup_db();
        let sensor = "retain_sensor";
        register_sensor(&db, sensor);

        let store = db.conn_store().unwrap();
        let now_nanos = DateTime::now().timestamp_nanos_opt().unwrap();
        let retention_period = std::time::Duration::from_secs(2);
        let old_ts_nanos = now_nanos - 10_000_000_000;
        let new_ts_nanos = now_nanos - 1_000_000_000;

        let old_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(old_ts_nanos)
            .build()
            .key();
        let new_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(new_ts_nanos)
            .build()
            .key();

        insert_conn(&store, sensor, old_ts_nanos, b"old");
        insert_conn(&store, sensor, new_ts_nanos, b"new");

        assert_conn_key_exists(&db, &old_key);
        assert_conn_key_exists(&db, &new_key);

        let cancel = CancellationToken::new();
        let task = tokio::spawn(super::retain_periodically(
            std::time::Duration::from_millis(10),
            retention_period,
            db.clone(),
            cancel.clone(),
        ));

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if db
                .db
                .get_cf(db.get_cf_handle("conn").unwrap(), &old_key)
                .unwrap()
                .is_none()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "cleanup did not delete old data"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert_conn_key_exists(&db, &new_key);

        cancel.cancel();
        let result = task.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_retain_periodically_keeps_within_retention_window() {
        let (_dir, db) = setup_db();
        let sensor = "retain_boundary_sensor";
        register_sensor(&db, sensor);

        let store = db.conn_store().unwrap();
        let now_nanos = DateTime::now().timestamp_nanos_opt().unwrap();
        let retention_period = std::time::Duration::from_secs(2);
        // Keep the timestamp safely within the retention window to avoid timing flakiness.
        let retention_ts_nanos = now_nanos - 1_000_000_000;

        let boundary_key = conn_key(sensor, retention_ts_nanos);

        store.append(&boundary_key, b"boundary").unwrap();

        assert_conn_key_exists(&db, &boundary_key);

        let cancel = CancellationToken::new();
        let task = tokio::spawn(super::retain_periodically(
            std::time::Duration::from_millis(10),
            retention_period,
            db.clone(),
            cancel.clone(),
        ));

        // Give retain loop a chance to run.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_conn_key_exists(&db, &boundary_key);

        cancel.cancel();
        let result = task.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_retain_periodically_skips_unregistered_sensor() {
        let (_dir, db) = setup_db();
        let store = db.conn_store().unwrap();
        let sensor = "orphan_sensor";
        let now_nanos = DateTime::now().timestamp_nanos_opt().unwrap();
        let retention_period = std::time::Duration::from_secs(2);
        let old_ts_nanos = now_nanos - 10_000_000_000;

        let orphan_key = conn_key(sensor, old_ts_nanos);
        store.append(&orphan_key, b"orphan").unwrap();

        assert_conn_key_exists(&db, &orphan_key);

        let cancel = CancellationToken::new();
        let task = tokio::spawn(super::retain_periodically(
            std::time::Duration::from_millis(10),
            retention_period,
            db.clone(),
            cancel.clone(),
        ));

        // Wait briefly to give retain loop a chance to run.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_conn_key_exists(&db, &orphan_key);

        cancel.cancel();
        let result = task.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_retain_periodically_does_not_block_runtime() {
        let (_dir, db) = setup_db();
        let sensor = "block_test_sensor";
        register_sensor(&db, sensor);

        let store = db.conn_store().unwrap();
        let now_nanos = DateTime::now().timestamp_nanos_opt().unwrap();
        let retention_period = std::time::Duration::from_secs(2);
        let old_ts_nanos = now_nanos - 10_000_000_000;

        for offset in 0..100 {
            insert_conn(&store, sensor, old_ts_nanos + offset, b"old");
        }

        let cancel = CancellationToken::new();
        let progress = Arc::new(AtomicUsize::new(0));

        let progress_clone = progress.clone();
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(1));
            loop {
                interval.tick().await;
                progress_clone.fetch_add(1, Ordering::Relaxed);
            }
        });

        let task = tokio::spawn(super::retain_periodically(
            std::time::Duration::from_millis(10),
            retention_period,
            db.clone(),
            cancel.clone(),
        ));

        // The interval's first tick is immediate and a pass repeats every
        // 10ms, so cleanup is running for most of this window. Cleanup that
        // ran on the runtime instead of the blocking pool would stall the
        // ticker for it.
        let progress_before = progress.load(Ordering::Relaxed);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let progress_after = progress.load(Ordering::Relaxed);

        cancel.cancel();
        let result = task.await.unwrap();
        assert!(result.is_ok());
        ticker.abort();

        assert!(
            progress_after > progress_before + 5,
            "runtime was blocked during retention cleanup"
        );
    }

    #[tokio::test]
    async fn test_check_db_usage() {
        let (over_threshold, over_low) = super::check_db_usage().await;
        if over_threshold {
            assert!(over_low);
        }
    }

    #[test]
    fn test_repair_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = super::data_dir_to_db_path(dir.path());

        let db_opts = DbOptions::default();
        let db = Database::open(&db_path, &db_opts).unwrap();
        let key = b"test_key";
        let value = b"test_value";
        append_and_assert_first_conn(&db, key, value);
        db.shutdown().unwrap();
        drop(db);

        super::repair_db(dir.path(), 8000, 512, 8, 2, true);

        let db = Database::open(&db_path, &db_opts).unwrap();
        assert!(db.conn_store().is_ok());
        append_and_assert_first_conn(&db, key, value);
        db.shutdown().unwrap();
        drop(db);
    }
}
