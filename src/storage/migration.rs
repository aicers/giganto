//! Routines to check the database format version and migrate it if necessary.
mod migration_structures;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fs::{File, create_dir_all},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, anyhow};
use rocksdb::{ColumnFamilyDescriptor, DB, WriteBatch};
use semver::{Version, VersionReq};
use serde::de::DeserializeOwned;
use tracing::info;

use self::migration_structures::{
    ConnBeforeV21, HttpFromV12BeforeV21, Netflow5BeforeV23, Netflow9BeforeV23, NtlmBeforeV21,
    SecuLogBeforeV23, SmtpBeforeV21, SshBeforeV21, TlsBeforeV21,
};
use super::{Database, RAW_DATA_COLUMN_FAMILY_NAMES, data_dir_to_db_path};
use crate::storage::migration::migration_structures::OpLogBeforeV24;
use crate::{
    comm::ingest::implement::EventFilter,
    graphql::TIMESTAMP_SIZE,
    storage::{
        Conn as ConnFromV21, DbOptions, Http as HttpFromV21, Netflow5 as Netflow5FromV23,
        Netflow9 as Netflow9FromV23, Ntlm as NtlmFromV21, OpLog as OpLogFromV24, RawEventStore,
        SecuLog as SecuLogFromV23, Smtp as SmtpFromV21, Ssh as SshFromV21, StorageKey,
        Tls as TlsFromV21, rocksdb_options,
    },
};

const COMPATIBLE_VERSION_REQ: &str = ">=0.24.0,<0.26.0";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format too old to be upgraded.
pub fn migrate_data_dir(data_dir: &Path, db_opts: &DbOptions) -> Result<()> {
    let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid version requirement");
    let mut version: Version = retrieve_or_create_version(data_dir)?;
    if compatible.matches(&version) {
        return Ok(());
    }

    let db_path = data_dir_to_db_path(data_dir);
    let migration: Vec<(_, _, fn(_, _) -> Result<_, _>)> = vec![
        (
            VersionReq::parse(">=0.13.0,<0.19.0").expect("valid version requirement"),
            Version::parse("0.19.0").expect("valid version"),
            migrate_0_13_to_0_19_0,
        ),
        (
            VersionReq::parse(">=0.19.0,<0.21.0").expect("valid version requirement"),
            Version::parse("0.21.0").expect("valid version"),
            migrate_0_19_to_0_21_0,
        ),
        (
            VersionReq::parse(">=0.21.0,<0.23.0").expect("valid version requirement"),
            Version::parse("0.23.0").expect("valid version"),
            migrate_0_21_to_0_23,
        ),
        (
            VersionReq::parse(">=0.23.0,<0.24.0").expect("valid version requirement"),
            Version::parse("0.24.0").expect("valid version"),
            migrate_0_23_to_0_24,
        ),
    ];

    while let Some((_req, to, m)) = migration
        .iter()
        .find(|(req, _to, _m)| req.matches(&version))
    {
        info!("Migrating database to {to}");
        m(&db_path, db_opts)?;
        version = to.clone();
        if compatible.matches(&version) {
            return create_version_file(&data_dir.join("VERSION"))
                .context("failed to update VERSION");
        }
    }
    Err(anyhow!("migration from {version} is not supported",))
}

fn retrieve_or_create_version(path: &Path) -> Result<Version> {
    let file = path.join("VERSION");
    if !path.exists() {
        create_dir_all(path)?;
    }
    if !path
        .read_dir()
        .context("cannot read data dir")?
        .any(|dir_info| {
            if let Ok(name) = dir_info {
                name.file_name() == "VERSION"
            } else {
                false
            }
        })
    {
        create_version_file(&file)?;
    }
    let version = read_version_file(&file)?;
    Ok(version)
}

fn create_version_file(path: &Path) -> Result<()> {
    let mut f = File::create(path).context("cannot create VERSION")?;
    f.write_all(env!("CARGO_PKG_VERSION").as_bytes())
        .context("cannot write VERSION")?;
    Ok(())
}

fn read_version_file(path: &Path) -> Result<Version> {
    let mut ver = String::new();
    File::open(path)
        .context("cannot open VERSION")?
        .read_to_string(&mut ver)
        .context("cannot read VERSION")?;
    Version::parse(&ver).context("cannot parse VERSION")
}

const OLD_META_DATA_COLUMN_FAMILY_NAMES: [&str; 1] = ["sources"];
impl Database {
    fn open_with_old_cfs(db_path: &Path, db_opts: &DbOptions) -> Result<Self> {
        let (db_opts, cf_opts) = rocksdb_options(db_opts);
        let mut cfs_name: Vec<&str> = Vec::with_capacity(
            RAW_DATA_COLUMN_FAMILY_NAMES.len() + OLD_META_DATA_COLUMN_FAMILY_NAMES.len(),
        );
        cfs_name.extend(RAW_DATA_COLUMN_FAMILY_NAMES);
        cfs_name.extend(OLD_META_DATA_COLUMN_FAMILY_NAMES);

        let cfs = cfs_name
            .into_iter()
            .map(|name| ColumnFamilyDescriptor::new(name, cf_opts.clone()));

        let db = DB::open_cf_descriptors(&db_opts, db_path, cfs).context("cannot open database")?;
        Ok(Database {
            db: std::sync::Arc::new(db),
        })
    }
}

// Delete the netflow5/netflow5/secuLog data in the old key and insert it with the new key.
fn migrate_0_13_to_0_19_0(db_path: &Path, db_opts: &DbOptions) -> Result<()> {
    let db = Database::open_with_old_cfs(db_path, db_opts)?;

    let netflow5_store: RawEventStore<'_, Netflow5FromV23> = db.netflow5_store()?;
    migrate_netflow_from_0_13_to_0_19_0::<Netflow5FromV23, Netflow5BeforeV23>(&netflow5_store)?;

    let netflow9_store = db.netflow9_store()?;
    migrate_netflow_from_0_13_to_0_19_0::<Netflow9FromV23, Netflow9BeforeV23>(&netflow9_store)?;

    let secu_log_store = db.secu_log_store()?;
    for raw_event in secu_log_store.iter_forward() {
        let Ok((key, value)) = raw_event else {
            continue;
        };
        secu_log_store.delete(&key)?;

        let (Ok(timestamp), Ok(secu_log_raw_event)) = (
            get_timestamp_from_key(&key),
            bincode::deserialize::<SecuLogBeforeV23>(&value),
        ) else {
            continue;
        };
        let new_key = StorageKey::builder()
            .start_key(&secu_log_raw_event.source)
            .mid_key(Some(secu_log_raw_event.kind.as_bytes().to_vec()))
            .end_key(timestamp)
            .build();
        secu_log_store.append(&new_key.key(), &value)?;
    }

    Ok(())
}

fn migrate_netflow_from_0_13_to_0_19_0<S, T>(store: &RawEventStore<'_, S>) -> Result<()>
where
    T: DeserializeOwned + EventFilter,
    S: DeserializeOwned,
{
    for raw_event in store.iter_forward() {
        let Ok((key, value)) = raw_event else {
            continue;
        };
        store.delete(&key)?;

        let (Ok(timestamp), Ok(netflow_raw_event)) = (
            get_timestamp_from_key(&key),
            bincode::deserialize::<T>(&value),
        ) else {
            continue;
        };
        let new_key = StorageKey::builder()
            .start_key(&netflow_raw_event.sensor().expect("Netflow source field is always populated during processing, ensuring sensor value exists."))
            .end_key(timestamp)
            .build();
        store.append(&new_key.key(), &value)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn migrate_0_19_to_0_21_0(db_path: &Path, db_opts: &DbOptions) -> Result<()> {
    let db = Database::open_with_old_cfs(db_path, db_opts)?;

    // migration ntlm raw event
    info!("start migration for ntlm");
    let store = db.ntlm_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<NtlmBeforeV21>(&val)?;
        let convert_new: NtlmFromV21 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("ntlm migration complete");

    // migration http raw event
    info!("start migration for http");
    let store = db.http_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<HttpFromV12BeforeV21>(&val)?;
        let convert_new: HttpFromV21 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("http migration complete");

    // migration ssh raw event
    info!("start migration for ssh");
    let store = db.ssh_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<SshBeforeV21>(&val)?;
        let convert_new: SshFromV21 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("ssh migration complete");

    // migration tls raw event
    info!("start migration for tls");
    let store = db.tls_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<TlsBeforeV21>(&val)?;
        let convert_new: TlsFromV21 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("tls migration complete");

    // migration smtp raw event
    info!("start migration for smtp");
    let store = db.smtp_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<SmtpBeforeV21>(&val)?;
        let convert_new: SmtpFromV21 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("smtp migration complete");

    // migration conn raw event
    info!("start migration for conn");
    let store = db.conn_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<ConnBeforeV21>(&val)?;
        let convert_new: ConnFromV21 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("conn migration complete");

    Ok(())
}

fn migrate_0_21_to_0_23(db_path: &Path, db_opts: &DbOptions) -> Result<()> {
    rename_sources_to_sensors(db_path, db_opts)?;

    let db = Database::open(db_path, db_opts)?;
    migrate_0_21_to_0_23_netflow5(&db)?;
    migrate_0_21_to_0_23_netflow9(&db)?;
    migrate_0_21_to_0_23_secu_log(&db)?;
    Ok(())
}

fn migrate_0_23_to_0_24(db_path: &Path, db_opts: &DbOptions) -> Result<()> {
    let db = Database::open(db_path, db_opts)?;
    migrate_0_23_0_to_0_24_0_op_log(&db)?;
    Ok(())
}

fn migrate_0_21_to_0_23_netflow5(db: &Database) -> Result<()> {
    let store = db.netflow5_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<Netflow5BeforeV23>(&val)?;
        let convert_new: Netflow5FromV23 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("netflow5 migration complete");
    Ok(())
}

fn migrate_0_21_to_0_23_netflow9(db: &Database) -> Result<()> {
    let store = db.netflow9_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<Netflow9BeforeV23>(&val)?;
        let convert_new: Netflow9FromV23 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("netflow9 migration complete");
    Ok(())
}

fn migrate_0_21_to_0_23_secu_log(db: &Database) -> Result<()> {
    let store = db.secu_log_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<SecuLogBeforeV23>(&val)?;
        let convert_new: SecuLogFromV23 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("secu log migration complete");
    Ok(())
}

fn migrate_0_23_0_to_0_24_0_op_log(db: &Database) -> Result<()> {
    info!("start migration for oplog");
    let store = db.op_log_store()?;
    let counter = AtomicUsize::new(0);

    for raw_event in store.iter_forward() {
        let Ok((key, value)) = raw_event else {
            continue;
        };

        let (Ok(timestamp), Ok(old)) = (
            get_timestamp_from_key(&key),
            bincode::deserialize::<OpLogBeforeV24>(&value),
        ) else {
            continue;
        };

        if key.len() > TIMESTAMP_SIZE + 1 {
            let old_start_key = String::from_utf8_lossy(&key[..(key.len() - (TIMESTAMP_SIZE + 1))]);
            let split_start_key: Vec<_> = old_start_key.split('@').collect();
            let mut convert_new: OpLogFromV24 = old.into();
            let Some(sensor) = split_start_key.get(1) else {
                continue;
            };
            convert_new.sensor.clone_from(&(*sensor).to_string());
            let new = bincode::serialize(&convert_new)?;

            let storage_key = StorageKey::timestamp_builder()
                .start_key(timestamp)
                .mid_key(counter.fetch_add(1, Ordering::Relaxed))
                .build();

            store.append(&storage_key.key(), &new)?;
            store.delete(&key)?;
        }
    }
    info!("oplog migration complete");
    Ok(())
}

// Since rocksdb does not provide column familiy renaming interface, we need to copy the data from
// the old column family to the new one, and then drop the old column family.
fn rename_sources_to_sensors(db_path: &Path, db_opts: &DbOptions) -> Result<()> {
    const OLD_CF: &str = "sources";
    const NEW_CF: &str = "sensors";

    let (db_opts, _) = rocksdb_options(db_opts);

    let mut cfs = DB::list_cf(&db_opts, db_path).unwrap_or_default();

    if cfs.iter().all(|cf| cf.as_str() != OLD_CF) {
        info!("Ignore column family renaming: column family {OLD_CF} does not exist.");
        return Ok(());
    }

    info!("Renaming column family from {} to {}", OLD_CF, NEW_CF);
    cfs.push(NEW_CF.to_string());

    let mut db = DB::open_cf(&db_opts, db_path, cfs).context("cannot open database")?;

    let mut batch = WriteBatch::default();
    let old_cf = db
        .cf_handle(OLD_CF)
        .context(format!("{OLD_CF} column family does not exist"))?;
    let new_cf = db
        .cf_handle(NEW_CF)
        .context(format!("{NEW_CF} column family does not exist"))?;

    let iter = db.iterator_cf(old_cf, rocksdb::IteratorMode::Start);
    for (key, value) in iter.flatten() {
        batch.put_cf(&new_cf, key, value);
    }

    if db.write(batch).is_ok() {
        db.drop_cf(OLD_CF)
            .context("Failed to drop old column family")?;
    }

    info!("Column family renaming from {OLD_CF} to {NEW_CF} is complete",);

    Ok(())
}

fn get_timestamp_from_key(key: &[u8]) -> Result<i64, anyhow::Error> {
    if key.len() > TIMESTAMP_SIZE {
        return Ok(i64::from_be_bytes(
            key[(key.len() - TIMESTAMP_SIZE)..].try_into()?,
        ));
    }
    Err(anyhow!("invalid database key length"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::net::IpAddr;
    use std::path::PathBuf;

    use chrono::Utc;
    use giganto_client::ingest::log::OpLogLevel;
    use rocksdb::{DB, Options, WriteBatch};
    use semver::{Version, VersionReq};
    use tempfile::TempDir;

    use super::COMPATIBLE_VERSION_REQ;
    use crate::storage::migration::migration_structures::OpLogBeforeV24;
    use crate::storage::{
        Conn as ConnFromV21, Database, DbOptions, Http as HttpFromV21, Netflow5 as Netflow5FromV23,
        Netflow9 as Netflow9FromV23, Ntlm as NtlmFromV21, OpLog as OpLogFromV24,
        SecuLog as SecuLogFromV23, Smtp as SmtpFromV21, Ssh as SshFromV21, StorageKey,
        Tls as TlsFromV21, data_dir_to_db_path, migrate_data_dir,
        migration::migration_structures::{
            ConnBeforeV21, HttpFromV12BeforeV21, Netflow5BeforeV23, Netflow9BeforeV23,
            NtlmBeforeV21, SecuLogBeforeV23, SmtpBeforeV21, SshBeforeV21, TlsBeforeV21,
        },
    };

    fn mock_version_file(dir: &TempDir, version_content: &str) -> PathBuf {
        let version_path = dir.path().join("VERSION");
        let mut file = File::create(&version_path).expect("Failed to create VERSION file");
        file.write_all(version_content.as_bytes())
            .expect("Failed to write version");
        version_path
    }

    #[test]
    fn version() {
        let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid semver");
        let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");

        // The current version must match the compatible version requirement.
        assert!(compatible.matches(&current));

        // Older versions are not compatible.
        let breaking = {
            let mut breaking = current.clone();
            if breaking.major == 0 {
                breaking.minor -= 6;
            } else {
                breaking.major -= 1;
            }
            breaking
        };

        assert!(!compatible.matches(&breaking));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn migrate_0_13_to_0_19() {
        const OLD_NETFLOW5_PREFIX_KEY: &str = "netflow5";
        const OLD_NETFLOW9_PREFIX_KEY: &str = "netflow9";
        const TEST_SENSOR: &str = "src1";
        const TEST_KIND: &str = "kind1"; //Used as prefix key in seculog's old key.
        const TEST_TIMESTAMP: i64 = 1000;

        // open temp db
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir_to_db_path(db_dir.path());

        let netflow5_old_key = StorageKey::builder()
            .start_key(OLD_NETFLOW5_PREFIX_KEY)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();
        let netflow5_body = Netflow5BeforeV23 {
            source: TEST_SENSOR.to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            next_hop: "192.168.4.78".parse::<IpAddr>().unwrap(),
            input: 65535,
            output: 1,
            d_pkts: 1,
            d_octets: 464,
            first: 3_477_280_180,
            last: 3_477_280_180,
            src_port: 9,
            dst_port: 771,
            tcp_flags: 0,
            prot: 1,
            tos: 192,
            src_as: 0,
            dst_as: 0,
            src_mask: 0,
            dst_mask: 0,
            sequence: 64,
            engine_type: 0,
            engine_id: 0,
            sampling_mode: 0,
            sampling_rate: 0,
        };
        let serialized_netflow5 = bincode::serialize(&netflow5_body).unwrap();

        let netflow9_old_key = StorageKey::builder()
            .start_key(OLD_NETFLOW9_PREFIX_KEY)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();
        let netflow9_body = Netflow9BeforeV23 {
            source: TEST_SENSOR.to_string(),
            sequence: 3_282_250_832,
            source_id: 17,
            template_id: 260,
            orig_addr: "192.168.4.75".parse::<IpAddr>().unwrap(),
            orig_port: 5000,
            resp_addr: "192.168.4.80".parse::<IpAddr>().unwrap(),
            resp_port: 6000,
            proto: 6,
            contents: format!("netflow5_contents {TEST_TIMESTAMP}").to_string(),
        };
        let serialized_netflow9 = bincode::serialize(&netflow9_body).unwrap();

        let secu_log_old_key = StorageKey::builder()
            .start_key(TEST_KIND)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();
        let secu_log_body = SecuLogBeforeV23 {
            source: TEST_SENSOR.to_string(),
            kind: TEST_KIND.to_string(),
            log_type: TEST_KIND.to_string(),
            version: "V3".to_string(),
            orig_addr: None,
            orig_port: None,
            resp_addr: None,
            resp_port: None,
            proto: None,
            contents: format!("secu_log_contents {TEST_TIMESTAMP}").to_string(),
        };
        let serialized_secu_log = bincode::serialize(&secu_log_body).unwrap();

        {
            let db = Database::open_with_old_cfs(&db_path, &DbOptions::default()).unwrap();

            // insert netflow5 data using the old key.
            let netflow5_store = db.netflow5_store().unwrap();
            netflow5_store
                .append(&netflow5_old_key, &serialized_netflow5)
                .unwrap();

            // insert netflow9 data using the old key.
            let netflow9_store = db.netflow9_store().unwrap();
            netflow9_store
                .append(&netflow9_old_key, &serialized_netflow9)
                .unwrap();

            // insert secuLog data using the old key.
            let secu_log_store = db.secu_log_store().unwrap();

            secu_log_store
                .append(&secu_log_old_key, &serialized_secu_log)
                .unwrap();
        }

        // migration 0.13.0 to 0.19.0
        super::migrate_0_13_to_0_19_0(&db_path, &DbOptions::default()).unwrap();

        // check netflow5/9 migration

        let db = Database::open_with_old_cfs(&db_path, &DbOptions::default()).unwrap();

        let netflow_new_key = StorageKey::builder()
            .start_key(TEST_SENSOR)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();

        let netflow5_store = db.netflow5_store().unwrap();
        let mut result_iter = netflow5_store.iter_forward();
        let (result_key, result_value) = result_iter.next().unwrap().unwrap();

        assert_ne!(netflow5_old_key, result_key.to_vec());
        assert_eq!(netflow_new_key, result_key.to_vec());
        assert_eq!(serialized_netflow5, result_value.to_vec());

        let netflow9_store = db.netflow9_store().unwrap();

        let mut result_iter = netflow9_store.iter_forward();
        let (result_key, result_value) = result_iter.next().unwrap().unwrap();

        assert_ne!(netflow9_old_key, result_key.to_vec());
        assert_eq!(netflow_new_key, result_key.to_vec());
        assert_eq!(serialized_netflow9, result_value.to_vec());

        //check secuLog migration
        let secu_log_new_key = StorageKey::builder()
            .start_key(TEST_SENSOR)
            .mid_key(Some(TEST_KIND.as_bytes().to_vec()))
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();

        let secu_log_store = db.secu_log_store().unwrap();

        let mut result_iter = secu_log_store.iter_forward();
        let (result_key, result_value) = result_iter.next().unwrap().unwrap();

        assert_ne!(secu_log_old_key, result_key.to_vec());
        assert_eq!(secu_log_new_key, result_key.to_vec());
        assert_eq!(serialized_secu_log, result_value.to_vec());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn migrate_0_19_to_0_21_0() {
        // open temp db & store
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir_to_db_path(db_dir.path());

        // generate key
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        let sensor = "src1";
        let mut key = Vec::with_capacity(sensor.len() + 1 + std::mem::size_of::<i64>());
        key.extend_from_slice(sensor.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        // prepare old conn raw data
        let old_conn = ConnBeforeV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            duration: 1,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
        };
        let ser_old_conn = bincode::serialize(&old_conn).unwrap();

        // prepare old http raw data
        let old_http = HttpFromV12BeforeV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            method: "POST".to_string(),
            host: "cluml".to_string(),
            uri: "/cluml.gif".to_string(),
            referer: "cluml.com".to_string(),
            version: String::new(),
            user_agent: "giganto".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: String::new(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: String::new(),
            cache_control: String::new(),
            orig_filenames: vec!["-".to_string()],
            orig_mime_types: vec!["-".to_string()],
            resp_filenames: vec!["-".to_string()],
            resp_mime_types: vec!["-".to_string()],
        };
        let ser_old_http = bincode::serialize(&old_http).unwrap();

        // prepare old smtp raw data
        let old_smtp = SmtpBeforeV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            mailfrom: "mailfrom".to_string(),
            date: "date".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            subject: "subject".to_string(),
            agent: "agent".to_string(),
        };
        let ser_old_smtp = bincode::serialize(&old_smtp).unwrap();

        // prepare old ntlm raw data
        let old_ntlm = NtlmBeforeV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            username: "bly".to_string(),
            hostname: "host".to_string(),
            domainname: "domain".to_string(),
            server_nb_computer_name: "NB".to_string(),
            server_dns_computer_name: "dns".to_string(),
            server_tree_name: "tree".to_string(),
            success: "tf".to_string(),
        };
        let ser_old_ntlm = bincode::serialize(&old_ntlm).unwrap();

        // prepare old ssh raw data
        let old_ssh = SshBeforeV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            version: 1,
            auth_success: "auth_success".to_string(),
            auth_attempts: 3,
            direction: "direction".to_string(),
            client: "client".to_string(),
            server: "server".to_string(),
            cipher_alg: "cipher_alg".to_string(),
            mac_alg: "mac_alg".to_string(),
            compression_alg: "compression_alg".to_string(),
            kex_alg: "kex_alg".to_string(),
            host_key_alg: "host_key_alg".to_string(),
            host_key: "host_key".to_string(),
        };
        let ser_old_ssh = bincode::serialize(&old_ssh).unwrap();

        // prepare old tls raw data
        let old_tls = TlsBeforeV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            server_name: "server_name".to_string(),
            alpn_protocol: "alpn_protocol".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            cipher: 10,
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "sub_country".to_string(),
            subject_org_name: "sub_org".to_string(),
            subject_common_name: "sub_comm".to_string(),
            validity_not_before: 11,
            validity_not_after: 12,
            subject_alt_name: "sub_alt".to_string(),
            issuer_country: "issuer_country".to_string(),
            issuer_org_name: "issuer_org".to_string(),
            issuer_org_unit_name: "issuer_org_unit".to_string(),
            issuer_common_name: "issuer_comm".to_string(),
            last_alert: 13,
        };
        let ser_old_tls = bincode::serialize(&old_tls).unwrap();

        {
            let db = Database::open_with_old_cfs(&db_path, &DbOptions::default()).unwrap();

            let conn_store = db.conn_store().unwrap();
            conn_store.append(&key, &ser_old_conn).unwrap();

            let http_store = db.http_store().unwrap();
            http_store.append(&key, &ser_old_http).unwrap();

            let smtp_store = db.smtp_store().unwrap();
            smtp_store.append(&key, &ser_old_smtp).unwrap();

            let ntlm_store = db.ntlm_store().unwrap();
            ntlm_store.append(&key, &ser_old_ntlm).unwrap();

            let ssh_store = db.ssh_store().unwrap();
            ssh_store.append(&key, &ser_old_ssh).unwrap();

            let tls_store = db.tls_store().unwrap();
            tls_store.append(&key, &ser_old_tls).unwrap();
        }

        // migration 0.19.0 to 0.21.0
        super::migrate_0_19_to_0_21_0(&db_path, &DbOptions::default()).unwrap();

        let db = Database::open_with_old_cfs(&db_path, &DbOptions::default()).unwrap();

        // check conn migration
        let conn_store = db.conn_store().unwrap();
        let raw_event = conn_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_conn = bincode::deserialize::<ConnFromV21>(&val).unwrap();
        let new_conn = ConnFromV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: String::new(),
            duration: 1,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
        };
        assert_eq!(new_conn, store_conn);

        // check http migration
        let http_store = db.http_store().unwrap();
        let raw_event = http_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_http = bincode::deserialize::<HttpFromV21>(&val).unwrap();
        let new_http = HttpFromV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            method: "POST".to_string(),
            host: "cluml".to_string(),
            uri: "/cluml.gif".to_string(),
            referer: "cluml.com".to_string(),
            version: String::new(),
            user_agent: "giganto".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: String::new(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: String::new(),
            cache_control: String::new(),
            orig_filenames: vec!["-".to_string()],
            orig_mime_types: vec!["-".to_string()],
            resp_filenames: vec!["-".to_string()],
            resp_mime_types: vec!["-".to_string()],
            post_body: Vec::new(),
            state: String::new(),
        };
        assert_eq!(new_http, store_http);

        // check smtp migration
        let smtp_store = db.smtp_store().unwrap();
        let raw_event = smtp_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_smtp = bincode::deserialize::<SmtpFromV21>(&val).unwrap();
        let new_smtp = SmtpFromV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            mailfrom: "mailfrom".to_string(),
            date: "date".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            subject: "subject".to_string(),
            agent: "agent".to_string(),
            state: String::new(),
        };
        assert_eq!(new_smtp, store_smtp);

        // check ntlm migration
        let ntlm_store = db.ntlm_store().unwrap();
        let raw_event = ntlm_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_ntlm = bincode::deserialize::<NtlmFromV21>(&val).unwrap();
        let new_ntlm = NtlmFromV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            protocol: String::new(),
            username: "bly".to_string(),
            hostname: "host".to_string(),
            domainname: "domain".to_string(),
            success: "tf".to_string(),
        };
        assert_eq!(new_ntlm, store_ntlm);

        // check ssh migration
        let ssh_store = db.ssh_store().unwrap();
        let raw_event = ssh_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_ssh = bincode::deserialize::<SshFromV21>(&val).unwrap();
        let new_ssh = SshFromV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            client: "client".to_string(),
            server: "server".to_string(),
            cipher_alg: "cipher_alg".to_string(),
            mac_alg: "mac_alg".to_string(),
            compression_alg: "compression_alg".to_string(),
            kex_alg: "kex_alg".to_string(),
            host_key_alg: "host_key_alg".to_string(),
            hassh_algorithms: String::new(),
            hassh: String::new(),
            hassh_server_algorithms: String::new(),
            hassh_server: String::new(),
            client_shka: String::new(),
            server_shka: String::new(),
        };
        assert_eq!(new_ssh, store_ssh);

        // check tls migration
        let tls_store = db.tls_store().unwrap();
        let raw_event = tls_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_tls = bincode::deserialize::<TlsFromV21>(&val).unwrap();
        let new_tls = TlsFromV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            server_name: "server_name".to_string(),
            alpn_protocol: "alpn_protocol".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            client_cipher_suites: Vec::new(),
            client_extensions: Vec::new(),
            cipher: 10,
            extensions: Vec::new(),
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "sub_country".to_string(),
            subject_org_name: "sub_org".to_string(),
            subject_common_name: "sub_comm".to_string(),
            validity_not_before: 11,
            validity_not_after: 12,
            subject_alt_name: "sub_alt".to_string(),
            issuer_country: "issuer_country".to_string(),
            issuer_org_name: "issuer_org".to_string(),
            issuer_org_unit_name: "issuer_org_unit".to_string(),
            issuer_common_name: "issuer_comm".to_string(),
            last_alert: 13,
        };
        assert_eq!(new_tls, store_tls);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn migrate_0_21_to_0_23() {
        const TEST_SENSOR: &str = "src1";
        const TEST_KIND: &str = "kind1"; //Used as prefix key in seculog's old key.
        const TEST_TIMESTAMP: i64 = 1000;

        // open temp db
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir_to_db_path(db_dir.path());

        let netflow5_key = StorageKey::builder()
            .start_key(TEST_SENSOR)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();
        let netflow5_old = Netflow5BeforeV23 {
            source: String::new(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            next_hop: "192.168.4.78".parse::<IpAddr>().unwrap(),
            input: 65535,
            output: 1,
            d_pkts: 1,
            d_octets: 464,
            first: 3_477_280_180,
            last: 3_477_280_180,
            src_port: 9,
            dst_port: 771,
            tcp_flags: 0,
            prot: 1,
            tos: 192,
            src_as: 0,
            dst_as: 0,
            src_mask: 0,
            dst_mask: 0,
            sequence: 64,
            engine_type: 0,
            engine_id: 0,
            sampling_mode: 0,
            sampling_rate: 0,
        };
        let serialized_netflow5_old = bincode::serialize(&netflow5_old).unwrap();

        let netflow9_key = StorageKey::builder()
            .start_key(TEST_SENSOR)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();
        let netflow9_old = Netflow9BeforeV23 {
            source: String::new(),
            sequence: 3_282_250_832,
            source_id: 17,
            template_id: 260,
            orig_addr: "192.168.4.75".parse::<IpAddr>().unwrap(),
            orig_port: 5000,
            resp_addr: "192.168.4.80".parse::<IpAddr>().unwrap(),
            resp_port: 6000,
            proto: 6,
            contents: format!("netflow5_contents {TEST_TIMESTAMP}").to_string(),
        };
        let serialized_netflow9_old = bincode::serialize(&netflow9_old).unwrap();

        let secu_log_key = StorageKey::builder()
            .start_key(TEST_SENSOR)
            .mid_key(Some(TEST_KIND.as_bytes().to_vec()))
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();
        let secu_log_old = SecuLogBeforeV23 {
            source: String::new(),
            kind: TEST_KIND.to_string(),
            log_type: TEST_KIND.to_string(),
            version: "V3".to_string(),
            orig_addr: None,
            orig_port: None,
            resp_addr: None,
            resp_port: None,
            proto: None,
            contents: format!("secu_log_contents {TEST_TIMESTAMP}").to_string(),
        };

        let serialized_secu_log_old = bincode::serialize(&secu_log_old).unwrap();

        {
            let db = Database::open_with_old_cfs(&db_path, &DbOptions::default()).unwrap();

            // insert netflow5 data using the old key.
            let netflow5_store = db.netflow5_store().unwrap();
            netflow5_store
                .append(&netflow5_key, &serialized_netflow5_old)
                .unwrap();

            // insert netflow9 data using the old key.
            let netflow9_store = db.netflow9_store().unwrap();
            netflow9_store
                .append(&netflow9_key, &serialized_netflow9_old)
                .unwrap();

            // insert secuLog data using the old key.
            let secu_log_store = db.secu_log_store().unwrap();
            secu_log_store
                .append(&secu_log_key, &serialized_secu_log_old)
                .unwrap();
        }

        // run migration
        super::migrate_0_21_to_0_23(&db_path, &DbOptions::default()).unwrap();

        let db = Database::open(&db_path, &DbOptions::default()).unwrap();

        // check netflow5
        let netflow5_store = db.netflow5_store().unwrap();
        let mut result_iter = netflow5_store.iter_forward();
        let (result_key, result_value) = result_iter.next().unwrap().unwrap();

        assert_eq!(netflow5_key, result_key.to_vec());
        let netflow5_new: Netflow5FromV23 = netflow5_old.into();
        assert_eq!(
            bincode::serialize(&netflow5_new).unwrap(),
            result_value.to_vec()
        );

        // check netflow9
        let netflow9_store = db.netflow9_store().unwrap();
        let mut result_iter = netflow9_store.iter_forward();
        let (result_key, result_value) = result_iter.next().unwrap().unwrap();

        assert_eq!(netflow9_key, result_key.to_vec());
        let netflow9_new: Netflow9FromV23 = netflow9_old.into();
        assert_eq!(
            bincode::serialize(&netflow9_new).unwrap(),
            result_value.to_vec()
        );

        // check secuLog
        let secu_log_store = db.secu_log_store().unwrap();
        let mut result_iter = secu_log_store.iter_forward();
        let (result_key, result_value) = result_iter.next().unwrap().unwrap();

        assert_eq!(secu_log_key, result_key.to_vec());
        let secu_log_new: SecuLogFromV23 = secu_log_old.into();
        assert_eq!(
            bincode::serialize(&secu_log_new).unwrap(),
            result_value.to_vec()
        );
    }

    #[test]
    fn migrate_0_21_to_0_23_with_renaming_cf_sources_to_sensors() {
        const OLD_CF: &str = "sources";
        const NEW_CF: &str = "sensors";

        let db_dir = tempfile::tempdir().unwrap();
        let db_path = &data_dir_to_db_path(db_dir.path());
        let (db_opts, _cf_opts) = crate::storage::rocksdb_options(&DbOptions::default());

        // create old cf and insert data
        {
            let db = DB::open_cf(&db_opts, db_path, [OLD_CF]).unwrap();

            let old_cf = db.cf_handle(OLD_CF).unwrap();
            let mut batch = WriteBatch::default();
            batch.put_cf(&old_cf, b"test_key_1", b"test_value_1");
            batch.put_cf(&old_cf, b"test_key_2", b"test_value_2");
            db.write(batch).unwrap();
        }

        let old_cfs: Vec<String> = DB::list_cf(&db_opts, db_path).unwrap_or_default();
        assert!(old_cfs.iter().any(|cf| cf == OLD_CF));
        assert!(!old_cfs.iter().any(|cf| cf == NEW_CF));

        // run migration
        super::migrate_0_21_to_0_23(db_path, &DbOptions::default()).unwrap();

        let new_cfs: Vec<String> = DB::list_cf(&db_opts, db_path).unwrap_or_default();
        assert!(!new_cfs.iter().any(|cf| cf == OLD_CF));
        assert!(new_cfs.iter().any(|cf| cf == NEW_CF));

        let db_after_renaming =
            DB::open_cf_for_read_only(&Options::default(), db_path, [NEW_CF], false).unwrap();

        assert!(db_after_renaming.cf_handle(NEW_CF).is_some());

        let new_cf = db_after_renaming.cf_handle(NEW_CF).unwrap();

        let result_value_1 = db_after_renaming
            .get_cf(&new_cf, b"test_key_1")
            .unwrap()
            .unwrap();

        let result_value_2 = db_after_renaming
            .get_cf(&new_cf, b"test_key_2")
            .unwrap()
            .unwrap();

        assert_eq!(result_value_1, b"test_value_1");
        assert_eq!(result_value_2, b"test_value_2");
    }

    #[test]
    fn migrate_0_23_to_0_24_0_oplog() {
        const TEST_TIMESTAMP: i64 = 1000;

        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let op_log_store = db.op_log_store().unwrap();

        let old_op_log = OpLogBeforeV24 {
            agent_name: "local".to_string(),
            log_level: OpLogLevel::Info,
            contents: "test".to_string(),
        };

        let serialized_old_op_log = bincode::serialize(&old_op_log).unwrap();
        let op_log_old_key = StorageKey::builder()
            .start_key("local@sr1")
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();

        op_log_store
            .append(&op_log_old_key, &serialized_old_op_log)
            .unwrap();

        super::migrate_0_23_0_to_0_24_0_op_log(&db).unwrap();

        let count = op_log_store.iter_forward().count();
        assert_eq!(count, 1);

        for log in op_log_store.iter_forward() {
            let Ok((_key, value)) = log else {
                continue;
            };

            let Ok(oplog) = bincode::deserialize::<OpLogFromV24>(&value) else {
                continue;
            };

            assert_eq!(oplog.sensor, "sr1".to_string());
            assert_eq!(oplog.agent_name, "local".to_string());
        }
    }

    #[test]
    fn migrate_data_dir_version_test() {
        let version_dir = tempfile::tempdir().unwrap();

        mock_version_file(&version_dir, "0.13.0");

        let db_options = DbOptions::new(8000, 512, 8, 2);

        let result = migrate_data_dir(version_dir.path(), &db_options);
        assert!(result.is_ok());

        if let Ok(updated_version) = fs::read_to_string(version_dir.path().join("VERSION")) {
            let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");
            let diff = Version::parse(&updated_version).expect("valid semver");
            assert_eq!(current, diff);
        }
    }
}
