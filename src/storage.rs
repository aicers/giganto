//! Raw event storage based on RocksDB.
use crate::graphql::PagingType;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use rocksdb::{ColumnFamily, Options, DB};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::time;
use tracing::error;

const RAW_DATA_COLUMN_FAMILY_NAMES: [&str; 5] = ["conn", "dns", "log", "http", "rdp"];
const META_DATA_COLUMN_FAMILY_NAMES: [&str; 1] = ["sources"];
const TIMESTAMP_SIZE: usize = 8;
const TIMESTAMP_WITH_DIV_SIZE: usize = TIMESTAMP_SIZE + 1;

type Pages = (Vec<(Vec<u8>, Vec<u8>)>, bool, bool);

#[derive(Clone)]
pub struct Database {
    db: Arc<DB>,
}

impl Database {
    /// Opens the database at the given path.
    pub fn open(path: &Path) -> Result<Database> {
        let mut opts = Options::default();
        let mut cfs: Vec<&str> = Vec::new();
        cfs.append(&mut RAW_DATA_COLUMN_FAMILY_NAMES.to_vec());
        cfs.append(&mut META_DATA_COLUMN_FAMILY_NAMES.to_vec());

        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open_cf(&opts, path, cfs).context("cannot open database")?;

        Ok(Database { db: Arc::new(db) })
    }

    /// Returns the raw event store for all type. (exclude log type)
    pub fn retain_period_store(&self) -> Result<Vec<RawEventStore>> {
        let mut stores: Vec<RawEventStore> = Vec::new();
        for store in RAW_DATA_COLUMN_FAMILY_NAMES {
            if !store.eq("log") {
                let cf = self
                    .db
                    .cf_handle(store)
                    .context("cannot access column family")?;
                stores.push(RawEventStore { db: &self.db, cf });
            }
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

    /// Returns the raw event store for connection sources
    pub fn sources_store(&self) -> Result<RawEventStore> {
        let cf = self
            .db
            .cf_handle("sources")
            .context("cannot access sources column family")?;
        Ok(RawEventStore { db: &self.db, cf })
    }
}

pub struct RawEventStore<'db> {
    db: &'db DB,
    cf: &'db ColumnFamily,
}

unsafe impl<'db> Send for RawEventStore<'db> {}

impl<'db> RawEventStore<'db> {
    pub fn append(&self, key: &[u8], raw_event: &[u8]) -> Result<()> {
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

    pub fn conn_events(&self, source: &str, paging_type: PagingType) -> Pages {
        let mut conn = Vec::new();
        let source = source.as_bytes().to_vec();

        let (iter, next_idx, mut prev, mut next) = match paging_type {
            PagingType::First(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&source, rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::Last(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&source, rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
            PagingType::AfterFirst(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::BeforeLast(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
        };

        for (idx, (key, val)) in iter.enumerate() {
            if idx == next_idx {
                (prev, next) = (true, true);
                break;
            }
            let (src, _ts) = key.split_at(key.len() - TIMESTAMP_WITH_DIV_SIZE);
            if source == src {
                conn.push((key.to_vec(), val.to_vec()));
            }
        }
        (conn, prev, next)
    }

    pub fn log_events(&self, source_kind: &str, paging_type: PagingType) -> Pages {
        let mut logs = Vec::new();
        let source_kind = source_kind.as_bytes().to_vec();

        let (iter, next_idx, mut prev, mut next) = match paging_type {
            PagingType::First(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&source_kind, rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::Last(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&source_kind, rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
            PagingType::AfterFirst(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::BeforeLast(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
        };

        for (idx, (key, val)) in iter.enumerate() {
            if idx == next_idx {
                (prev, next) = (true, true);
                break;
            }
            let (src_kind, _ts) = key.split_at(key.len() - TIMESTAMP_WITH_DIV_SIZE);
            if source_kind == src_kind {
                logs.push((key.to_vec(), val.to_vec()));
            }
        }
        (logs, prev, next)
    }

    pub fn dns_time_events(
        &self,
        source: &str,
        start: &DateTime<Utc>,
        end: &DateTime<Utc>,
        paging_type: PagingType,
    ) -> Pages {
        let mut dns_time = Vec::new();
        let mut dns_key = Vec::new();
        let start_vec = start.timestamp_nanos().to_be_bytes();
        dns_key.append(&mut source.as_bytes().to_vec());
        dns_key.push(00);
        dns_key.append(&mut start_vec.to_vec());

        let (iter, next_idx, mut prev, mut next) = match paging_type {
            PagingType::First(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&dns_key, rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::Last(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&dns_key, rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
            PagingType::AfterFirst(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::BeforeLast(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
        };

        let end_vec = end.timestamp_nanos().to_be_bytes().to_vec();
        let end_time = i64::from_be_bytes(end_vec.try_into().unwrap());

        for (idx, (key, val)) in iter.enumerate() {
            let (src, ts) = key.split_at(key.len() - TIMESTAMP_SIZE);
            let src = &src[0..src.len() - 1];
            let ts_nano = i64::from_be_bytes(ts.to_vec().try_into().unwrap());

            if idx == next_idx {
                (prev, next) = (true, true);
                break;
            }
            if src == source.as_bytes() {
                if ts_nano <= end_time {
                    dns_time.push((key.to_vec(), val.to_vec()));
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        (dns_time, prev, next)
    }

    pub fn http_events(&self, source: &str, paging_type: PagingType) -> Pages {
        let mut http = Vec::new();
        let source = source.as_bytes().to_vec();

        let (iter, next_idx, mut prev, mut next) = match paging_type {
            PagingType::First(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&source, rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::Last(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&source, rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
            PagingType::AfterFirst(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::BeforeLast(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
        };

        for (idx, (key, val)) in iter.enumerate() {
            if idx == next_idx {
                (prev, next) = (true, true);
                break;
            }
            let (src, _ts) = key.split_at(key.len() - TIMESTAMP_WITH_DIV_SIZE);
            if source == src {
                http.push((key.to_vec(), val.to_vec()));
            }
        }
        (http, prev, next)
    }

    pub fn rdp_events(&self, source: &str, paging_type: PagingType) -> Pages {
        let mut rdp = Vec::new();
        let source = source.as_bytes().to_vec();

        let (iter, next_idx, mut prev, mut next) = match paging_type {
            PagingType::First(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&source, rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::Last(val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(&source, rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
            PagingType::AfterFirst(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Forward),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                true,
                false,
            ),
            PagingType::BeforeLast(cursor, val) => (
                self.db
                    .iterator_cf(
                        self.cf,
                        rocksdb::IteratorMode::From(cursor.as_bytes(), rocksdb::Direction::Reverse),
                    )
                    .take(val + 1)
                    .flatten(),
                val,
                false,
                true,
            ),
        };

        for (idx, (key, val)) in iter.enumerate() {
            if idx == next_idx {
                (prev, next) = (true, true);
                break;
            }
            let (src, _ts) = key.split_at(key.len() - TIMESTAMP_WITH_DIV_SIZE);
            if source == src {
                rdp.push((key.to_vec(), val.to_vec()));
            }
        }
        (rdp, prev, next)
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

pub fn gen_key(args: Vec<Vec<u8>>) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::new();
    for arg in args {
        key.extend_from_slice(&arg);
        key.push(0x00);
    }
    key.pop();
    key
}

pub async fn retain_periodically(
    duration: Duration,
    retention_period: Duration,
    db: Database,
) -> Result<()> {
    let mut itv = time::interval(duration);
    let retention_duration = i64::try_from(retention_period.as_nanos())?;
    let from_timestamp = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(61, 0), Utc)
        .timestamp_nanos()
        .to_be_bytes()
        .to_vec();
    loop {
        itv.tick().await;
        let standard_duration = Utc::now().timestamp_nanos() - retention_duration;
        let standard_duration_vec = standard_duration.to_be_bytes().to_vec();
        let sources = db.sources_store()?.all_keys();
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
                    let store_duration =
                        i64::from_be_bytes(key[(key.len() - TIMESTAMP_SIZE)..].try_into().unwrap());
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
