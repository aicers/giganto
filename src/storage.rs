//! Raw event storage based on RocksDB.
use anyhow::{Context, Result};
use chrono::Utc;
use rocksdb::{ColumnFamily, Options, DB};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::time;

use crate::ingestion;

const COLUMN_FAMILY_NAMES: [&str; 5] = ["conn", "dns", "log", "http", "rdp"];
const TIMESTAMP_SIZE: usize = 8;

#[derive(Clone)]
pub struct Database {
    db: Arc<DB>,
}

impl Database {
    /// Opens the database at the given path.
    pub fn open(path: &Path) -> Result<Database> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open_cf(&opts, path, COLUMN_FAMILY_NAMES).context("cannot open database")?;
        Ok(Database { db: Arc::new(db) })
    }

    /// Returns the raw event store for all type.
    pub fn all_store(&self) -> Result<Vec<RawEventStore>> {
        let mut stores: Vec<RawEventStore> = Vec::new();
        for store in COLUMN_FAMILY_NAMES {
            let cf = self
                .db
                .cf_handle(store)
                .context("cannot access column family")?;
            stores.push(RawEventStore { db: &self.db, cf });
        }
        Ok(stores)
    }

    /// Returns the raw event store for connections.
    pub fn conn_store(&self) -> Result<RawEventStore> {
        let cf = self
            .db
            .cf_handle("conn")
            .context("cannot access conn column family")?;
        Ok(RawEventStore { db: &self.db, cf })
    }

    /// Returns the raw event store for dns.
    pub fn dns_store(&self) -> Result<RawEventStore> {
        let cf = self
            .db
            .cf_handle("dns")
            .context("cannot access dns column family")?;
        Ok(RawEventStore { db: &self.db, cf })
    }

    /// Returns the raw event store for log.
    pub fn log_store(&self) -> Result<RawEventStore> {
        let cf = self
            .db
            .cf_handle("log")
            .context("cannot access log column family")?;
        Ok(RawEventStore { db: &self.db, cf })
    }
    /// Returns the raw event store for http.
    pub fn http_store(&self) -> Result<RawEventStore> {
        let cf = self
            .db
            .cf_handle("http")
            .context("cannot access http column family")?;
        Ok(RawEventStore { db: &self.db, cf })
    }
    /// Returns the raw event store for rdp.
    pub fn rdp_store(&self) -> Result<RawEventStore> {
        let cf = self
            .db
            .cf_handle("rdp")
            .context("cannot access rdp column family")?;
        Ok(RawEventStore { db: &self.db, cf })
    }
}

pub struct RawEventStore<'db> {
    db: &'db DB,
    cf: &'db ColumnFamily,
}

unsafe impl<'db> Send for RawEventStore<'db> {}

impl<'db> RawEventStore<'db> {
    pub fn append(&self, source: &str, timestamp: i64, raw_event: &[u8]) -> Result<()> {
        let mut key: Vec<u8> = Vec::new();
        key.append(&mut source.as_bytes().to_vec());
        key.append(&mut timestamp.to_be_bytes().to_vec());
        self.db.put_cf(self.cf, key, raw_event)?;
        Ok(())
    }

    pub fn append_log(&self, source: &str, timestamp: i64, raw_event: &[u8]) -> Result<()> {
        let mut key: Vec<u8> = Vec::new();
        let de_log = bincode::deserialize::<ingestion::Log>(raw_event)?;
        let (kind, _) = de_log.log;
        key.append(&mut source.as_bytes().to_vec());
        key.push(0);
        key.append(&mut kind.as_bytes().to_vec());
        key.append(&mut timestamp.to_be_bytes().to_vec());
        self.db.put_cf(self.cf, key, raw_event)?;
        Ok(())
    }

    pub fn delete(&self, key: &[u8]) -> Result<()> {
        self.db.delete_cf(self.cf, key)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.db.flush_cf(self.cf)?;
        Ok(())
    }

    /// Returns the all raw event.
    #[allow(unused)]
    pub fn all_raw_event(&self) -> Vec<Vec<u8>> {
        let mut raw = Vec::new();
        let iter = self
            .db
            .iterator_cf(self.cf, rocksdb::IteratorMode::Start)
            .flatten();
        for (_key, val) in iter {
            raw.push(val.to_vec());
        }
        raw
    }

    /// Returns all raw events given source
    pub fn src_raw_events(&self, source: &str) -> Vec<Vec<u8>> {
        let mut raw = Vec::new();
        let iter = self
            .db
            .iterator_cf(
                self.cf,
                rocksdb::IteratorMode::From(source.as_bytes(), rocksdb::Direction::Forward),
            )
            .flatten();
        for (key, val) in iter {
            let (src, _ts) = key.split_at(key.len() - TIMESTAMP_SIZE);
            if source == std::str::from_utf8(src).expect("src to string") {
                raw.push(val.to_vec());
            }
        }
        raw
    }

    pub fn log_events(&self, source: &str, kind: &str) -> Vec<Vec<u8>> {
        let mut logs = Vec::new();
        let mut source_kind: Vec<u8> = Vec::new();
        source_kind.append(&mut source.as_bytes().to_vec());
        source_kind.push(0);
        source_kind.append(&mut kind.as_bytes().to_vec());
        let iter = self
            .db
            .iterator_cf(
                self.cf,
                rocksdb::IteratorMode::From(&source_kind, rocksdb::Direction::Forward),
            )
            .flatten();
        for (key, val) in iter {
            let (src_kind, _ts) = key.split_at(key.len() - TIMESTAMP_SIZE);
            if source_kind == src_kind {
                logs.push(val.to_vec());
            }
        }
        logs
    }

    /// Returns the all key values ​​of column family.
    pub fn all_keys(&self) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        let iter = self
            .db
            .iterator_cf(self.cf, rocksdb::IteratorMode::Start)
            .flatten();
        for (key, _val) in iter {
            keys.push(key.to_vec());
        }
        keys
    }
}

pub async fn retain_periodically(
    duration: Duration,
    retention_period: Duration,
    db: Database,
) -> Result<()> {
    let mut itv = time::interval(duration);
    let stores = db.all_store()?;
    let retention_duration = i64::try_from(retention_period.as_nanos())?;
    loop {
        itv.tick().await;
        let standard_duration = Utc::now().timestamp_nanos() - retention_duration;
        for store in &stores {
            for key in store.all_keys() {
                let store_duration =
                    i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into()?);
                if standard_duration > store_duration {
                    store.delete(&key)?;
                }
            }
        }
    }
}
