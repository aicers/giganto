//! Raw event storage based on RocksDB.
use crate::{
    graphql::{network::NetworkFilter, RawEventFilter},
    ingest::implement::EventFilter,
};
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use giganto_client::ingest::{
    log::{Log, Oplog},
    network::{Conn, DceRpc, Dns, Http, Kerberos, Ntlm, Rdp, Smtp, Ssh},
    statistics::Statistics,
    timeseries::PeriodicTimeSeries,
    Packet,
};
pub use rocksdb::Direction;
use rocksdb::{ColumnFamily, DBIteratorWithThreadMode, Options, DB};
use serde::de::DeserializeOwned;
use std::{cmp, marker::PhantomData, mem, path::Path, sync::Arc, time::Duration};
use tokio::time;
use tracing::error;

const RAW_DATA_COLUMN_FAMILY_NAMES: [&str; 14] = [
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
];
const META_DATA_COLUMN_FAMILY_NAMES: [&str; 1] = ["sources"];
const TIMESTAMP_SIZE: usize = 8;

#[derive(Clone)]
pub struct Database {
    db: Arc<DB>,
}

impl Database {
    /// Opens the database at the given path.
    pub fn open(path: &Path) -> Result<Database> {
        let mut opts = Options::default();
        let mut cfs: Vec<&str> = Vec::with_capacity(
            RAW_DATA_COLUMN_FAMILY_NAMES.len() + META_DATA_COLUMN_FAMILY_NAMES.len(),
        );
        cfs.extend(RAW_DATA_COLUMN_FAMILY_NAMES);
        cfs.extend(META_DATA_COLUMN_FAMILY_NAMES);

        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(8000);
        let db = DB::open_cf(&opts, path, cfs).context("cannot open database")?;

        Ok(Database { db: Arc::new(db) })
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
    fn names(&self) -> Vec<Vec<u8>> {
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
        itv.tick().await;
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
}
