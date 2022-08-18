//! Raw event storage based on RocksDB.
#![allow(unused)] // not implemented yet

use std::path::Path;

use anyhow::{Context, Result};
use rocksdb::{ColumnFamily, Options, DB};

const COLUMN_FAMILY_NAMES: [&str; 1] = ["conn"];

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
}

pub struct RawEventStore<'db> {
    db: &'db DB,
    cf: &'db ColumnFamily,
}

impl<'db> RawEventStore<'db> {
    pub fn append(source: &str, timestamp: i64, raw_event: &[u8]) {
        unimplemented!()
    }
}
