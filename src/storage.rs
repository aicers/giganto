//! Raw event storage based on RocksDB.
use anyhow::{Context, Result};
use rocksdb::{ColumnFamily, Options, DB};
use std::{path::Path, sync::Arc};

const COLUMN_FAMILY_NAMES: [&str; 5] = ["conn", "dns", "log", "http", "rdp"];

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

    #[allow(unused)]
    /// Returns the all raw event.
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
}
