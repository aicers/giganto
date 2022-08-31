//! Raw event storage based on RocksDB.
use anyhow::{Context, Result};
use rocksdb::{ColumnFamily, Options, DB};
use std::path::Path;

const COLUMN_FAMILY_NAMES: [&str; 3] = ["conn", "dns", "log"];
const TIMESTAMP_SIZE: usize = 8;

pub struct Database {
    db: DB,
}

impl Database {
    /// Opens the database at the given path.
    pub fn open(path: &Path) -> Result<Database> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open_cf(&opts, path, COLUMN_FAMILY_NAMES).context("cannot open database")?;
        Ok(Database { db })
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
    pub fn all_raw_event(&self) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let val = self.db.iterator_cf(self.cf, rocksdb::IteratorMode::Start);
        let mut events: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
        for (key, val) in val.flatten() {
            let (source, timestamp) = key.split_at(key.len() - TIMESTAMP_SIZE);
            events.push((source.to_vec(), timestamp.to_vec(), val.to_vec()));
        }
        events
    }
}
