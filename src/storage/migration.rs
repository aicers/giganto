//! Routines to check the database format version and migrate it if necessary.
mod migration_structures;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fs::{File, create_dir_all},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, anyhow};
use rocksdb::{DB, WriteBatch};
use semver::{Version, VersionReq};
use serde::{Serialize, de::DeserializeOwned};
use tracing::info;

use super::{Database, data_dir_to_db_path};
use crate::storage::migration::migration_structures::{
    BootpBeforeV26, ConnFromV21BeforeV26, DceRpcBeforeV26, DhcpBeforeV26, DnsBeforeV26,
    FtpBeforeV26, HttpFromV21BeforeV26, KerberosBeforeV26, LdapBeforeV26, MigrationNew,
    MqttBeforeV26, Netflow5BeforeV23, Netflow9BeforeV23, NfsBeforeV26, NtlmBeforeV26,
    OpLogBeforeV24, RdpBeforeV26, SecuLogBeforeV23, SmbBeforeV26, SmtpBeforeV26, SshBeforeV26,
    TlsBeforeV26,
};
use crate::{
    graphql::TIMESTAMP_SIZE,
    storage::{
        Bootp as BootpFromV26, Conn as ConnFromV26, DbOptions, DceRpc as DceRpcFromV26,
        Dhcp as DhcpFromV26, Dns as DnsFromV26, Ftp as FtpFromV26, Http as HttpFromV26,
        Kerberos as KerberosFromV26, Ldap as LdapFromV26, Mqtt as MqttFromV26,
        Netflow5 as Netflow5FromV23, Netflow9 as Netflow9FromV23, Nfs as NfsFromV26,
        Ntlm as NtlmFromV26, OpLog as OpLogFromV24, Rdp as RdpFromV26, SecuLog as SecuLogFromV23,
        Smb as SmbFromV26, Smtp as SmtpFromV26, Ssh as SshFromV26, StorageKey, Tls as TlsFromV26,
        rocksdb_options,
    },
};

const COMPATIBLE_VERSION_REQ: &str = ">=0.26.0,<0.27.0";

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
            VersionReq::parse(">=0.21.0,<0.23.0").expect("valid version requirement"),
            Version::parse("0.23.0").expect("valid version"),
            migrate_0_21_to_0_23,
        ),
        (
            VersionReq::parse(">=0.23.0,<0.24.0").expect("valid version requirement"),
            Version::parse("0.24.0").expect("valid version"),
            migrate_0_23_to_0_24,
        ),
        (
            VersionReq::parse(">=0.24.0,<0.26.0").expect("valid version requirement"),
            Version::parse("0.26.0").expect("valid version"),
            migrate_0_24_to_0_26,
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
    Err(anyhow!(
        "migration from {version} is not supported. Only versions 0.21.0 and above are supported",
    ))
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

fn migrate_0_24_to_0_26(db_path: &Path, db_opts: &DbOptions) -> Result<()> {
    let db = Database::open(db_path, db_opts)?;
    migrate_0_24_to_0_26_conn(&db)?;
    migrate_0_24_to_0_26_http(&db)?;
    migration_0_24_to_0_26_other_protocols(&db)?;
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
    info!("Completed migration for netflow5");
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
    info!("Completed migration for netflow9");
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
    info!("Completed migration for secu log");
    Ok(())
}

fn migrate_0_23_0_to_0_24_0_op_log(db: &Database) -> Result<()> {
    info!("Starting migration for oplog");
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
    info!("Completed migration for oplog");
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
        info!("Ignore column family renaming: column family {OLD_CF} does not exist");
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

fn migration_0_24_to_0_26_other_protocols(db: &Database) -> Result<()> {
    info!("Starting migration for other raw event");
    migrate_raw_event_0_24_to_0_26::<DnsBeforeV26, DnsFromV26>(&db.dns_store()?)?;
    migrate_raw_event_0_24_to_0_26::<RdpBeforeV26, RdpFromV26>(&db.rdp_store()?)?;
    migrate_raw_event_0_24_to_0_26::<SmtpBeforeV26, SmtpFromV26>(&db.smtp_store()?)?;
    migrate_raw_event_0_24_to_0_26::<NtlmBeforeV26, NtlmFromV26>(&db.ntlm_store()?)?;
    migrate_raw_event_0_24_to_0_26::<KerberosBeforeV26, KerberosFromV26>(&db.kerberos_store()?)?;
    migrate_raw_event_0_24_to_0_26::<SshBeforeV26, SshFromV26>(&db.ssh_store()?)?;
    migrate_raw_event_0_24_to_0_26::<DceRpcBeforeV26, DceRpcFromV26>(&db.dce_rpc_store()?)?;
    migrate_raw_event_0_24_to_0_26::<FtpBeforeV26, FtpFromV26>(&db.ftp_store()?)?;
    migrate_raw_event_0_24_to_0_26::<MqttBeforeV26, MqttFromV26>(&db.mqtt_store()?)?;
    migrate_raw_event_0_24_to_0_26::<LdapBeforeV26, LdapFromV26>(&db.ldap_store()?)?;
    migrate_raw_event_0_24_to_0_26::<TlsBeforeV26, TlsFromV26>(&db.tls_store()?)?;
    migrate_raw_event_0_24_to_0_26::<SmbBeforeV26, SmbFromV26>(&db.smb_store()?)?;
    migrate_raw_event_0_24_to_0_26::<NfsBeforeV26, NfsFromV26>(&db.nfs_store()?)?;
    migrate_raw_event_0_24_to_0_26::<BootpBeforeV26, BootpFromV26>(&db.bootp_store()?)?;
    migrate_raw_event_0_24_to_0_26::<DhcpBeforeV26, DhcpFromV26>(&db.dhcp_store()?)?;
    info!("Completed migration for other raw event");
    Ok(())
}

fn migrate_raw_event_0_24_to_0_26<OldT, NewT>(
    store: &crate::storage::RawEventStore<'_, NewT>,
) -> Result<()>
where
    OldT: DeserializeOwned + Sized,
    NewT: Serialize + DeserializeOwned + MigrationNew<OldT>,
{
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;

        let old = bincode::deserialize::<OldT>(&val)?;

        let session_start_time = get_timestamp_from_key(&key)?;

        let new_data = NewT::new(old, session_start_time);

        let new = bincode::serialize(&new_data)?;
        store.append(&key, &new)?;
    }
    Ok(())
}

fn migrate_0_24_to_0_26_conn(db: &Database) -> Result<()> {
    info!("Starting migration for conn");
    let store = db.conn_store()?;

    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;

        // Deserialize the old conn structure that has duration field
        let old = bincode::deserialize::<ConnFromV21BeforeV26>(&val)?;

        // Extract session start time from the key
        let session_start_time = get_timestamp_from_key(&key)?;

        // Create new conn structure with new `start_time` field
        let new_conn = ConnFromV26 {
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            proto: old.proto,
            conn_state: old.conn_state,
            start_time: session_start_time,
            duration: old.duration,
            service: old.service,
            orig_bytes: old.orig_bytes,
            resp_bytes: old.resp_bytes,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
        };

        let new = bincode::serialize(&new_conn)?;
        store.append(&key, &new)?;
    }

    info!("Completed migration for conn");
    Ok(())
}

fn migrate_0_24_to_0_26_http(db: &Database) -> Result<()> {
    info!("Starting migration for http field consolidation");
    let store = db.http_store()?;

    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<HttpFromV21BeforeV26>(&val)?;

        let mut filenames = old.orig_filenames;
        filenames.extend(old.resp_filenames);

        let mut mime_types = old.orig_mime_types;
        mime_types.extend(old.resp_mime_types);

        // Extract session start time from the key
        let start_time = get_timestamp_from_key(&key)?;

        let new_http = HttpFromV26 {
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            proto: old.proto,
            start_time,
            duration: old.end_time - start_time,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            method: old.method,
            host: old.host,
            uri: old.uri,
            referer: old.referer,
            version: old.version,
            user_agent: old.user_agent,
            request_len: old.request_len,
            response_len: old.response_len,
            status_code: old.status_code,
            status_msg: old.status_msg,
            username: old.username,
            password: old.password,
            cookie: old.cookie,
            content_encoding: old.content_encoding,
            content_type: old.content_type,
            cache_control: old.cache_control,
            filenames,
            mime_types,
            body: old.post_body,
            state: old.state,
        };
        let new = bincode::serialize(&new_http)?;
        store.append(&key, &new)?;
    }

    info!("Completed migration for http field consolidation");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fmt::Debug, fs, fs::File, io::Write, net::IpAddr, path::Path, path::PathBuf};

    use chrono::Utc;
    use giganto_client::ingest::{log::OpLogLevel, network::FtpCommand};
    use rocksdb::{ColumnFamilyDescriptor, DB, Options, WriteBatch};
    use semver::{Version, VersionReq};
    use serde::{Serialize, de::DeserializeOwned};
    use tempfile::TempDir;

    use super::COMPATIBLE_VERSION_REQ;
    use crate::storage::{
        Bootp as BootpFromV26, Conn as ConnFromV26, Database, DbOptions, DceRpc as DceRpcFromV26,
        Dhcp as DhcpFromV26, Dns as DnsFromV26, Ftp as FtpFromV26, Http as HttpFromV26,
        Kerberos as KerberosFromV26, Ldap as LdapFromV26, Mqtt as MqttFromV26,
        Netflow5 as Netflow5FromV23, Netflow9 as Netflow9FromV23, Nfs as NfsFromV26,
        Ntlm as NtlmFromV26, OpLog as OpLogFromV24, RAW_DATA_COLUMN_FAMILY_NAMES, RawEventStore,
        Rdp as RdpFromV26, SecuLog as SecuLogFromV23, Smb as SmbFromV26, Smtp as SmtpFromV26,
        Ssh as SshFromV26, StorageKey, Tls as TlsFromV26, data_dir_to_db_path, migrate_data_dir,
        migration::migration_structures::{
            BootpBeforeV26, ConnFromV21BeforeV26, DceRpcBeforeV26, DhcpBeforeV26, DnsBeforeV26,
            FtpBeforeV26, HttpFromV21BeforeV26, KerberosBeforeV26, LdapBeforeV26, MigrationNew,
            MqttBeforeV26, Netflow5BeforeV23, Netflow9BeforeV23, NfsBeforeV26, NtlmBeforeV26,
            OpLogBeforeV24, RdpBeforeV26, SecuLogBeforeV23, SmbBeforeV26, SmtpBeforeV26,
            SshBeforeV26, TlsBeforeV26,
        },
        rocksdb_options,
    };

    fn open_with_old_cfs(db_path: &Path, db_opts: &DbOptions) -> Database {
        const OLD_META_DATA_COLUMN_FAMILY_NAMES: [&str; 1] = ["sources"];

        let (db_opts, cf_opts) = rocksdb_options(db_opts);
        let mut cfs_name: Vec<&str> = Vec::with_capacity(
            RAW_DATA_COLUMN_FAMILY_NAMES.len() + OLD_META_DATA_COLUMN_FAMILY_NAMES.len(),
        );
        cfs_name.extend(RAW_DATA_COLUMN_FAMILY_NAMES);
        cfs_name.extend(OLD_META_DATA_COLUMN_FAMILY_NAMES);

        let cfs = cfs_name
            .into_iter()
            .map(|name| ColumnFamilyDescriptor::new(name, cf_opts.clone()));

        let db = DB::open_cf_descriptors(&db_opts, db_path, cfs).unwrap();
        Database {
            db: std::sync::Arc::new(db),
        }
    }

    fn mock_version_file(dir: &TempDir, version_content: &str) -> PathBuf {
        let version_path = dir.path().join("VERSION");
        let mut file = File::create(&version_path).expect("Failed to create VERSION file");
        file.write_all(version_content.as_bytes())
            .expect("Failed to write version");
        version_path
    }

    fn setup_mock_netflow5_v21() -> Netflow5BeforeV23 {
        Netflow5BeforeV23 {
            source: "legacy".to_string(),
            src_addr: "192.168.0.1".parse().unwrap(),
            dst_addr: "192.168.0.2".parse().unwrap(),
            next_hop: "192.168.0.3".parse().unwrap(),
            input: 1,
            output: 2,
            d_pkts: 10,
            d_octets: 20,
            first: 100,
            last: 200,
            src_port: 1234,
            dst_port: 80,
            tcp_flags: 0,
            prot: 6,
            tos: 0,
            src_as: 0,
            dst_as: 0,
            src_mask: 0,
            dst_mask: 0,
            sequence: 42,
            engine_type: 0,
            engine_id: 0,
            sampling_mode: 0,
            sampling_rate: 0,
        }
    }

    fn setup_mock_http_v21() -> HttpFromV21BeforeV26 {
        HttpFromV21BeforeV26 {
            orig_addr: "10.1.1.1".parse().unwrap(),
            orig_port: 80,
            resp_addr: "10.1.1.2".parse().unwrap(),
            resp_port: 8080,
            proto: 6,
            end_time: 3005,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/path".to_string(),
            referer: "http://ref".to_string(),
            version: "1.1".to_string(),
            user_agent: "agent".to_string(),
            request_len: 10,
            response_len: 20,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "gzip".to_string(),
            content_type: "text/html".to_string(),
            cache_control: "no-cache".to_string(),
            orig_filenames: vec!["a.txt".to_string()],
            orig_mime_types: vec!["text/plain".to_string()],
            resp_filenames: vec!["b.txt".to_string()],
            resp_mime_types: vec!["text/html".to_string()],
            post_body: vec![1, 2, 3],
            state: "state".to_string(),
        }
    }

    fn setup_mock_conn_v21() -> ConnFromV21BeforeV26 {
        ConnFromV21BeforeV26 {
            orig_addr: "10.0.0.1".parse().unwrap(),
            orig_port: 1111,
            resp_addr: "10.0.0.2".parse().unwrap(),
            resp_port: 2222,
            proto: 6,
            conn_state: "SF".to_string(),
            duration: 500,
            service: "http".to_string(),
            orig_bytes: 100,
            resp_bytes: 200,
            orig_pkts: 3,
            resp_pkts: 4,
            orig_l2_bytes: 10,
            resp_l2_bytes: 20,
        }
    }

    fn build_storage_key(sensor: &str, timestamp: i64) -> Vec<u8> {
        StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn migrate_and_assert_raw_event<Old, New>(
        store: &RawEventStore<'_, New>,
        sensor: &str,
        timestamp: i64,
        old: &Old,
        expected: New,
    ) where
        Old: Serialize + DeserializeOwned,
        New: Serialize + DeserializeOwned + MigrationNew<Old> + PartialEq + Debug,
    {
        let key = build_storage_key(sensor, timestamp);
        let serialized_old = bincode::serialize(old).unwrap();
        store.append(&key, &serialized_old).unwrap();

        super::migrate_raw_event_0_24_to_0_26::<Old, New>(store).unwrap();

        let (_, val) = store.iter_forward().next().unwrap().unwrap();
        let migrated: New = bincode::deserialize(&val).unwrap();
        assert_eq!(expected, migrated);
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
        let netflow5_old = setup_mock_netflow5_v21();
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
            let db = open_with_old_cfs(&db_path, &DbOptions::default());

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
    #[allow(clippy::too_many_lines)]
    fn migrate_0_24_to_0_26_0_raw_event() {
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        let sensor = "src1";

        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();

        let conn_store = db.conn_store().unwrap();
        let old_conn = setup_mock_conn_v21();
        let conn_old_key = build_storage_key(sensor, timestamp);
        conn_store
            .append(&conn_old_key, &bincode::serialize(&old_conn).unwrap())
            .unwrap();

        super::migrate_0_24_to_0_26_conn(&db).unwrap();

        let raw_event = conn_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_conn = bincode::deserialize::<ConnFromV26>(&val).unwrap();
        let new_conn = ConnFromV26 {
            orig_addr: old_conn.orig_addr,
            orig_port: old_conn.orig_port,
            resp_addr: old_conn.resp_addr,
            resp_port: old_conn.resp_port,
            proto: old_conn.proto,
            conn_state: old_conn.conn_state,
            start_time: timestamp,
            duration: old_conn.duration,
            service: old_conn.service,
            orig_bytes: old_conn.orig_bytes,
            resp_bytes: old_conn.resp_bytes,
            orig_pkts: old_conn.orig_pkts,
            resp_pkts: old_conn.resp_pkts,
            orig_l2_bytes: old_conn.orig_l2_bytes,
            resp_l2_bytes: old_conn.resp_l2_bytes,
        };
        assert_eq!(new_conn, store_conn);

        let old_http = setup_mock_http_v21();
        let http_store = db.http_store().unwrap();
        let http_old_key = build_storage_key(sensor, timestamp);
        http_store
            .append(&http_old_key, &bincode::serialize(&old_http).unwrap())
            .unwrap();

        super::migrate_0_24_to_0_26_http(&db).unwrap();

        let raw_event = http_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_http = bincode::deserialize::<HttpFromV26>(&val).unwrap();
        let new_http = HttpFromV26 {
            orig_addr: old_http.orig_addr,
            orig_port: old_http.orig_port,
            resp_addr: old_http.resp_addr,
            resp_port: old_http.resp_port,
            proto: old_http.proto,
            start_time: timestamp,
            duration: old_http.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            method: old_http.method.clone(),
            host: old_http.host.clone(),
            uri: old_http.uri.clone(),
            referer: old_http.referer.clone(),
            version: old_http.version.clone(),
            user_agent: old_http.user_agent.clone(),
            request_len: old_http.request_len,
            response_len: old_http.response_len,
            status_code: old_http.status_code,
            status_msg: old_http.status_msg.clone(),
            username: old_http.username.clone(),
            password: old_http.password.clone(),
            cookie: old_http.cookie.clone(),
            content_encoding: old_http.content_encoding.clone(),
            content_type: old_http.content_type.clone(),
            cache_control: old_http.cache_control.clone(),
            filenames: [
                old_http.orig_filenames.clone(),
                old_http.resp_filenames.clone(),
            ]
            .concat(),
            mime_types: [
                old_http.orig_mime_types.clone(),
                old_http.resp_mime_types.clone(),
            ]
            .concat(),
            body: old_http.post_body.clone(),
            state: old_http.state.clone(),
        };
        assert_eq!(new_http, store_http);

        let dns_old = DnsBeforeV26 {
            orig_addr: "192.168.4.76".parse().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            query: "Hello Server".to_string(),
            answer: vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            trans_id: 1,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1; 5],
        };
        let dns_store = db.dns_store().unwrap();
        let new_dns = DnsFromV26 {
            orig_addr: dns_old.orig_addr,
            orig_port: dns_old.orig_port,
            resp_addr: dns_old.resp_addr,
            resp_port: dns_old.resp_port,
            proto: dns_old.proto,
            start_time: timestamp,
            duration: dns_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: dns_old.query.clone(),
            answer: dns_old.answer.clone(),
            trans_id: dns_old.trans_id,
            rtt: dns_old.rtt,
            qclass: dns_old.qclass,
            qtype: dns_old.qtype,
            rcode: dns_old.rcode,
            aa_flag: dns_old.aa_flag,
            tc_flag: dns_old.tc_flag,
            rd_flag: dns_old.rd_flag,
            ra_flag: dns_old.ra_flag,
            ttl: dns_old.ttl.clone(),
        };
        migrate_and_assert_raw_event::<DnsBeforeV26, DnsFromV26>(
            &dns_store, sensor, timestamp, &dns_old, new_dns,
        );

        let rdp_old = RdpBeforeV26 {
            orig_addr: "10.0.0.1".parse().unwrap(),
            orig_port: 3389,
            resp_addr: "10.0.0.2".parse().unwrap(),
            resp_port: 3390,
            proto: 6,
            end_time: 123,
            cookie: "cookie_val".to_string(),
        };
        let rdp_store = db.rdp_store().unwrap();
        let new_rdp = RdpFromV26 {
            orig_addr: rdp_old.orig_addr,
            orig_port: rdp_old.orig_port,
            resp_addr: rdp_old.resp_addr,
            resp_port: rdp_old.resp_port,
            proto: rdp_old.proto,
            start_time: timestamp,
            duration: rdp_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            cookie: rdp_old.cookie.clone(),
        };
        migrate_and_assert_raw_event::<RdpBeforeV26, RdpFromV26>(
            &rdp_store, sensor, timestamp, &rdp_old, new_rdp,
        );

        let smtp_old = SmtpBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            mailfrom: "mailfrom".to_string(),
            date: "date".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            subject: "subject".to_string(),
            agent: "agent".to_string(),
            state: String::new(),
        };
        let smtp_store = db.smtp_store().unwrap();
        let new_smtp = SmtpFromV26 {
            orig_addr: smtp_old.orig_addr,
            orig_port: smtp_old.orig_port,
            resp_addr: smtp_old.resp_addr,
            resp_port: smtp_old.resp_port,
            proto: smtp_old.proto,
            start_time: timestamp,
            duration: smtp_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            mailfrom: smtp_old.mailfrom.clone(),
            date: smtp_old.date.clone(),
            from: smtp_old.from.clone(),
            to: smtp_old.to.clone(),
            subject: smtp_old.subject.clone(),
            agent: smtp_old.agent.clone(),
            state: smtp_old.state.clone(),
        };
        migrate_and_assert_raw_event::<SmtpBeforeV26, SmtpFromV26>(
            &smtp_store,
            sensor,
            timestamp,
            &smtp_old,
            new_smtp,
        );

        let ntlm_old = NtlmBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            username: "bly".to_string(),
            hostname: "host".to_string(),
            domainname: "domain".to_string(),
            success: "tf".to_string(),
            protocol: "protocol".to_string(),
        };
        let ntlm_store = db.ntlm_store().unwrap();
        let new_ntlm = NtlmFromV26 {
            orig_addr: ntlm_old.orig_addr,
            orig_port: ntlm_old.orig_port,
            resp_addr: ntlm_old.resp_addr,
            resp_port: ntlm_old.resp_port,
            proto: ntlm_old.proto,
            start_time: timestamp,
            duration: ntlm_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            username: ntlm_old.username.clone(),
            hostname: ntlm_old.hostname.clone(),
            domainname: ntlm_old.domainname.clone(),
            success: ntlm_old.success.clone(),
            protocol: ntlm_old.protocol.clone(),
        };
        migrate_and_assert_raw_event::<NtlmBeforeV26, NtlmFromV26>(
            &ntlm_store,
            sensor,
            timestamp,
            &ntlm_old,
            new_ntlm,
        );

        let kerberos_old = KerberosBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            client_time: 1,
            server_time: 1,
            error_code: 1,
            client_realm: "client_realm".to_string(),
            cname_type: 1,
            client_name: vec!["client_name".to_string()],
            realm: "realm".to_string(),
            sname_type: 1,
            service_name: vec!["service_name".to_string()],
        };
        let kerberos_store = db.kerberos_store().unwrap();
        let new_kerberos = KerberosFromV26 {
            orig_addr: kerberos_old.orig_addr,
            orig_port: kerberos_old.orig_port,
            resp_addr: kerberos_old.resp_addr,
            resp_port: kerberos_old.resp_port,
            proto: kerberos_old.proto,
            start_time: timestamp,
            duration: kerberos_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            client_time: kerberos_old.client_time,
            server_time: kerberos_old.server_time,
            error_code: kerberos_old.error_code,
            client_realm: kerberos_old.client_realm.clone(),
            cname_type: kerberos_old.cname_type,
            client_name: kerberos_old.client_name.clone(),
            realm: kerberos_old.realm.clone(),
            sname_type: kerberos_old.sname_type,
            service_name: kerberos_old.service_name.clone(),
        };
        migrate_and_assert_raw_event::<KerberosBeforeV26, KerberosFromV26>(
            &kerberos_store,
            sensor,
            timestamp,
            &kerberos_old,
            new_kerberos,
        );

        let ssh_old = SshBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            client: "client".to_string(),
            server: "server".to_string(),
            cipher_alg: "cipher_alg".to_string(),
            mac_alg: "mac_alg".to_string(),
            compression_alg: "compression_alg".to_string(),
            kex_alg: "kex_alg".to_string(),
            host_key_alg: "host_key_alg".to_string(),
            hassh_algorithms: "hassh_algorithms".to_string(),
            hassh: "hassh".to_string(),
            hassh_server_algorithms: "hassh_server_algorithms".to_string(),
            hassh_server: "hassh_server".to_string(),
            client_shka: "client_shka".to_string(),
            server_shka: "server_shka".to_string(),
        };
        let ssh_store = db.ssh_store().unwrap();
        let new_ssh = SshFromV26 {
            orig_addr: ssh_old.orig_addr,
            orig_port: ssh_old.orig_port,
            resp_addr: ssh_old.resp_addr,
            resp_port: ssh_old.resp_port,
            proto: ssh_old.proto,
            start_time: timestamp,
            duration: ssh_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            client: ssh_old.client.clone(),
            server: ssh_old.server.clone(),
            cipher_alg: ssh_old.cipher_alg.clone(),
            mac_alg: ssh_old.mac_alg.clone(),
            compression_alg: ssh_old.compression_alg.clone(),
            kex_alg: ssh_old.kex_alg.clone(),
            host_key_alg: ssh_old.host_key_alg.clone(),
            hassh_algorithms: ssh_old.hassh_algorithms.clone(),
            hassh: ssh_old.hassh.clone(),
            hassh_server_algorithms: ssh_old.hassh_server_algorithms.clone(),
            hassh_server: ssh_old.hassh_server.clone(),
            client_shka: ssh_old.client_shka.clone(),
            server_shka: ssh_old.server_shka.clone(),
        };
        migrate_and_assert_raw_event::<SshBeforeV26, SshFromV26>(
            &ssh_store, sensor, timestamp, &ssh_old, new_ssh,
        );

        let dcerpc_old = DceRpcBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            rtt: 3,
            named_pipe: "named_pipe".to_string(),
            endpoint: "endpoint".to_string(),
            operation: "operation".to_string(),
        };
        let dcerpc_store = db.dce_rpc_store().unwrap();
        let new_dcerpc = DceRpcFromV26 {
            orig_addr: dcerpc_old.orig_addr,
            orig_port: dcerpc_old.orig_port,
            resp_addr: dcerpc_old.resp_addr,
            resp_port: dcerpc_old.resp_port,
            proto: dcerpc_old.proto,
            start_time: timestamp,
            duration: dcerpc_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            rtt: dcerpc_old.rtt,
            named_pipe: dcerpc_old.named_pipe.clone(),
            endpoint: dcerpc_old.endpoint.clone(),
            operation: dcerpc_old.operation.clone(),
        };
        migrate_and_assert_raw_event::<DceRpcBeforeV26, DceRpcFromV26>(
            &dcerpc_store,
            sensor,
            timestamp,
            &dcerpc_old,
            new_dcerpc,
        );

        let ftp_old = FtpBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            user: "cluml".to_string(),
            password: "aice".to_string(),
            command: "command".to_string(),
            reply_code: "500".to_string(),
            reply_msg: "reply_message".to_string(),
            data_passive: false,
            data_orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            data_resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            data_resp_port: 80,
            file: "ftp_file".to_string(),
            file_size: 100,
            file_id: "1".to_string(),
        };
        let ftp_store = db.ftp_store().unwrap();
        let new_ftp = FtpFromV26 {
            orig_addr: ftp_old.orig_addr,
            orig_port: ftp_old.orig_port,
            resp_addr: ftp_old.resp_addr,
            resp_port: ftp_old.resp_port,
            proto: ftp_old.proto,
            start_time: timestamp,
            duration: ftp_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            user: ftp_old.user.clone(),
            password: ftp_old.password.clone(),
            commands: vec![FtpCommand {
                command: ftp_old.command.clone(),
                reply_code: ftp_old.reply_code.clone(),
                reply_msg: ftp_old.reply_msg.clone(),
                data_passive: ftp_old.data_passive,
                data_orig_addr: ftp_old.data_orig_addr,
                data_resp_addr: ftp_old.data_resp_addr,
                data_resp_port: ftp_old.data_resp_port,
                file: ftp_old.file.clone(),
                file_size: ftp_old.file_size,
                file_id: ftp_old.file_id.clone(),
            }],
        };
        migrate_and_assert_raw_event::<FtpBeforeV26, FtpFromV26>(
            &ftp_store, sensor, timestamp, &ftp_old, new_ftp,
        );

        let mqtt_old = MqttBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            protocol: "protocol".to_string(),
            version: 1,
            client_id: "1".to_string(),
            connack_reason: 1,
            subscribe: vec!["subscribe".to_string()],
            suback_reason: vec![1],
        };
        let mqtt_store = db.mqtt_store().unwrap();
        let new_mqtt = MqttFromV26 {
            orig_addr: mqtt_old.orig_addr,
            orig_port: mqtt_old.orig_port,
            resp_addr: mqtt_old.resp_addr,
            resp_port: mqtt_old.resp_port,
            proto: mqtt_old.proto,
            start_time: timestamp,
            duration: mqtt_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            protocol: mqtt_old.protocol.clone(),
            version: mqtt_old.version,
            client_id: mqtt_old.client_id.clone(),
            connack_reason: mqtt_old.connack_reason,
            subscribe: mqtt_old.subscribe.clone(),
            suback_reason: mqtt_old.suback_reason.clone(),
        };
        migrate_and_assert_raw_event::<MqttBeforeV26, MqttFromV26>(
            &mqtt_store,
            sensor,
            timestamp,
            &mqtt_old,
            new_mqtt,
        );

        let ldap_old = LdapBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            message_id: 1,
            version: 1,
            opcode: vec!["opcode".to_string()],
            result: vec!["result".to_string()],
            diagnostic_message: Vec::new(),
            object: Vec::new(),
            argument: Vec::new(),
        };
        let ldap_store = db.ldap_store().unwrap();
        let new_ldap = LdapFromV26 {
            orig_addr: ldap_old.orig_addr,
            orig_port: ldap_old.orig_port,
            resp_addr: ldap_old.resp_addr,
            resp_port: ldap_old.resp_port,
            proto: ldap_old.proto,
            start_time: timestamp,
            duration: ldap_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            message_id: ldap_old.message_id,
            version: ldap_old.version,
            opcode: ldap_old.opcode.clone(),
            result: ldap_old.result.clone(),
            diagnostic_message: ldap_old.diagnostic_message.clone(),
            object: ldap_old.object.clone(),
            argument: ldap_old.argument.clone(),
        };
        migrate_and_assert_raw_event::<LdapBeforeV26, LdapFromV26>(
            &ldap_store,
            sensor,
            timestamp,
            &ldap_old,
            new_ldap,
        );

        let tls_old = TlsBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            server_name: "server_name".to_string(),
            alpn_protocol: "alpn_protocol".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            client_cipher_suites: vec![771, 769, 770],
            client_extensions: vec![0, 1, 2],
            cipher: 10,
            extensions: vec![0, 1],
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
        let tls_store = db.tls_store().unwrap();
        let new_tls = TlsFromV26 {
            orig_addr: tls_old.orig_addr,
            orig_port: tls_old.orig_port,
            resp_addr: tls_old.resp_addr,
            resp_port: tls_old.resp_port,
            proto: tls_old.proto,
            start_time: timestamp,
            duration: tls_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            server_name: tls_old.server_name.clone(),
            alpn_protocol: tls_old.alpn_protocol.clone(),
            ja3: tls_old.ja3.clone(),
            version: tls_old.version.clone(),
            client_cipher_suites: tls_old.client_cipher_suites.clone(),
            client_extensions: tls_old.client_extensions.clone(),
            cipher: tls_old.cipher,
            extensions: tls_old.extensions.clone(),
            ja3s: tls_old.ja3s.clone(),
            serial: tls_old.serial.clone(),
            subject_country: tls_old.subject_country.clone(),
            subject_org_name: tls_old.subject_org_name.clone(),
            subject_common_name: tls_old.subject_common_name.clone(),
            validity_not_before: tls_old.validity_not_before,
            validity_not_after: tls_old.validity_not_after,
            subject_alt_name: tls_old.subject_alt_name.clone(),
            issuer_country: tls_old.issuer_country.clone(),
            issuer_org_name: tls_old.issuer_org_name.clone(),
            issuer_org_unit_name: tls_old.issuer_org_unit_name.clone(),
            issuer_common_name: tls_old.issuer_common_name.clone(),
            last_alert: tls_old.last_alert,
        };
        migrate_and_assert_raw_event::<TlsBeforeV26, TlsFromV26>(
            &tls_store, sensor, timestamp, &tls_old, new_tls,
        );

        let smb_old = SmbBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            command: 0,
            path: "something/path".to_string(),
            service: "service".to_string(),
            file_name: "fine_name".to_string(),
            file_size: 10,
            resource_type: 20,
            fid: 30,
            create_time: 10_000_000,
            access_time: 20_000_000,
            write_time: 10_000_000,
            change_time: 20_000_000,
        };
        let smb_store = db.smb_store().unwrap();
        let new_smb = SmbFromV26 {
            orig_addr: smb_old.orig_addr,
            orig_port: smb_old.orig_port,
            resp_addr: smb_old.resp_addr,
            resp_port: smb_old.resp_port,
            proto: smb_old.proto,
            start_time: timestamp,
            duration: smb_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            command: smb_old.command,
            path: smb_old.path.clone(),
            service: smb_old.service.clone(),
            file_name: smb_old.file_name.clone(),
            file_size: smb_old.file_size,
            resource_type: smb_old.resource_type,
            fid: smb_old.fid,
            create_time: smb_old.create_time,
            access_time: smb_old.access_time,
            write_time: smb_old.write_time,
            change_time: smb_old.change_time,
        };
        migrate_and_assert_raw_event::<SmbBeforeV26, SmbFromV26>(
            &smb_store, sensor, timestamp, &smb_old, new_smb,
        );

        let nfs_old = NfsBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            read_files: vec![],
            write_files: vec![],
        };
        let nfs_store = db.nfs_store().unwrap();
        let new_nfs = NfsFromV26 {
            orig_addr: nfs_old.orig_addr,
            orig_port: nfs_old.orig_port,
            resp_addr: nfs_old.resp_addr,
            resp_port: nfs_old.resp_port,
            proto: nfs_old.proto,
            start_time: timestamp,
            duration: nfs_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            read_files: nfs_old.read_files.clone(),
            write_files: nfs_old.write_files.clone(),
        };
        migrate_and_assert_raw_event::<NfsBeforeV26, NfsFromV26>(
            &nfs_store, sensor, timestamp, &nfs_old, new_nfs,
        );

        let bootp_old = BootpBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            op: 0,
            htype: 0,
            hops: 0,
            xid: 0,
            ciaddr: "192.168.4.1".parse::<IpAddr>().unwrap(),
            yiaddr: "192.168.4.2".parse::<IpAddr>().unwrap(),
            siaddr: "192.168.4.3".parse::<IpAddr>().unwrap(),
            giaddr: "192.168.4.4".parse::<IpAddr>().unwrap(),
            chaddr: vec![0, 1, 2],
            sname: "sname".to_string(),
            file: "file".to_string(),
        };
        let bootp_store = db.bootp_store().unwrap();
        let new_bootp = BootpFromV26 {
            orig_addr: bootp_old.orig_addr,
            orig_port: bootp_old.orig_port,
            resp_addr: bootp_old.resp_addr,
            resp_port: bootp_old.resp_port,
            proto: bootp_old.proto,
            start_time: timestamp,
            duration: bootp_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            op: bootp_old.op,
            htype: bootp_old.htype,
            hops: bootp_old.hops,
            xid: bootp_old.xid,
            ciaddr: bootp_old.ciaddr,
            yiaddr: bootp_old.yiaddr,
            siaddr: bootp_old.siaddr,
            giaddr: bootp_old.giaddr,
            chaddr: bootp_old.chaddr.clone(),
            sname: bootp_old.sname.clone(),
            file: bootp_old.file.clone(),
        };
        migrate_and_assert_raw_event::<BootpBeforeV26, BootpFromV26>(
            &bootp_store,
            sensor,
            timestamp,
            &bootp_old,
            new_bootp,
        );

        let dhcp_old = DhcpBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
            msg_type: 0,
            ciaddr: "192.168.4.1".parse::<IpAddr>().unwrap(),
            yiaddr: "192.168.4.2".parse::<IpAddr>().unwrap(),
            siaddr: "192.168.4.3".parse::<IpAddr>().unwrap(),
            giaddr: "192.168.4.4".parse::<IpAddr>().unwrap(),
            subnet_mask: "192.168.4.5".parse::<IpAddr>().unwrap(),
            router: vec![
                "192.168.1.11".parse::<IpAddr>().unwrap(),
                "192.168.1.22".parse::<IpAddr>().unwrap(),
            ],
            domain_name_server: vec![
                "192.168.1.33".parse::<IpAddr>().unwrap(),
                "192.168.1.44".parse::<IpAddr>().unwrap(),
            ],
            req_ip_addr: "192.168.4.6".parse::<IpAddr>().unwrap(),
            lease_time: 1,
            server_id: "192.168.4.7".parse::<IpAddr>().unwrap(),
            param_req_list: vec![0, 1, 2],
            message: "message".to_string(),
            renewal_time: 1,
            rebinding_time: 1,
            class_id: vec![0, 1, 2],
            client_id_type: 1,
            client_id: vec![0, 1, 2],
        };
        let dhcp_store = db.dhcp_store().unwrap();
        let new_dhcp = DhcpFromV26 {
            orig_addr: dhcp_old.orig_addr,
            orig_port: dhcp_old.orig_port,
            resp_addr: dhcp_old.resp_addr,
            resp_port: dhcp_old.resp_port,
            proto: dhcp_old.proto,
            start_time: timestamp,
            duration: dhcp_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            msg_type: dhcp_old.msg_type,
            ciaddr: dhcp_old.ciaddr,
            yiaddr: dhcp_old.yiaddr,
            siaddr: dhcp_old.siaddr,
            giaddr: dhcp_old.giaddr,
            subnet_mask: dhcp_old.subnet_mask,
            router: dhcp_old.router.clone(),
            domain_name_server: dhcp_old.domain_name_server.clone(),
            req_ip_addr: dhcp_old.req_ip_addr,
            lease_time: dhcp_old.lease_time,
            server_id: dhcp_old.server_id,
            param_req_list: dhcp_old.param_req_list.clone(),
            message: dhcp_old.message.clone(),
            renewal_time: dhcp_old.renewal_time,
            rebinding_time: dhcp_old.rebinding_time,
            class_id: dhcp_old.class_id.clone(),
            client_id_type: dhcp_old.client_id_type,
            client_id: dhcp_old.client_id.clone(),
        };
        migrate_and_assert_raw_event::<DhcpBeforeV26, DhcpFromV26>(
            &dhcp_store,
            sensor,
            timestamp,
            &dhcp_old,
            new_dhcp,
        );
    }

    #[test]
    fn migrate_data_dir_version_test() {
        // Test successful migration from a supported version (0.21.0)
        let version_dir = tempfile::tempdir().unwrap();
        mock_version_file(&version_dir, "0.21.0");
        let db_options = DbOptions::new(8000, 512, 8, 2, true);
        let result = migrate_data_dir(version_dir.path(), &db_options);
        assert!(result.is_ok());

        if let Ok(updated_version) = fs::read_to_string(version_dir.path().join("VERSION")) {
            let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");
            let diff = Version::parse(&updated_version).expect("valid semver");
            assert_eq!(current, diff);
        }
    }

    #[test]
    fn migrate_data_dir_unsupported_version_test() {
        // Test that migration from unsupported version (< 0.21.0) fails
        let version_dir = tempfile::tempdir().unwrap();
        mock_version_file(&version_dir, "0.13.0");
        let db_options = DbOptions::new(8000, 512, 8, 2, true);
        let result = migrate_data_dir(version_dir.path(), &db_options);
        let err = result.expect_err("Operation should have failed");
        assert!(
            err.to_string()
                .contains("Only versions 0.21.0 and above are supported")
        );
    }

    #[test]
    fn test_retrieve_or_create_version_creates_new_version() {
        let temp_dir = tempfile::tempdir().unwrap();
        let version = super::retrieve_or_create_version(temp_dir.path()).unwrap();

        // Should create VERSION file with current package version
        let expected = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid version");
        assert_eq!(version, expected);

        // Verify VERSION file exists
        assert!(temp_dir.path().join("VERSION").exists());
    }

    #[test]
    fn test_retrieve_or_create_version_reads_existing_version() {
        let temp_dir = tempfile::tempdir().unwrap();
        let version_path = temp_dir.path().join("VERSION");

        // Create VERSION file with specific version
        let mut file = File::create(&version_path).unwrap();
        file.write_all(b"0.25.0").unwrap();
        drop(file);

        let version = super::retrieve_or_create_version(temp_dir.path()).unwrap();
        assert_eq!(version, Version::parse("0.25.0").unwrap());
    }

    #[test]
    fn test_create_version_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let version_path = temp_dir.path().join("VERSION");

        super::create_version_file(&version_path).unwrap();

        let content = fs::read_to_string(&version_path).unwrap();
        assert_eq!(content, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_read_version_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let version_path = temp_dir.path().join("VERSION");

        let mut file = File::create(&version_path).unwrap();
        file.write_all(b"1.2.3").unwrap();
        drop(file);

        let version = super::read_version_file(&version_path).unwrap();
        assert_eq!(version, Version::parse("1.2.3").unwrap());
    }

    #[test]
    fn test_read_version_file_invalid_format() {
        let temp_dir = tempfile::tempdir().unwrap();
        let version_path = temp_dir.path().join("VERSION");

        let mut file = File::create(&version_path).unwrap();
        file.write_all(b"invalid_version").unwrap();
        drop(file);

        let result = super::read_version_file(&version_path);
        let err = result.expect_err("Operation should have failed");
        assert!(err.to_string().contains("cannot parse VERSION"));
    }

    #[test]
    fn test_read_version_file_not_exists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let version_path = temp_dir.path().join("NONEXISTENT");

        let result = super::read_version_file(&version_path);
        let err = result.expect_err("Operation should have failed");
        assert!(err.to_string().contains("cannot open VERSION"));
    }

    #[test]
    fn test_get_timestamp_from_key_valid() {
        let timestamp: i64 = 1_234_567_890;
        let timestamp_bytes = timestamp.to_be_bytes();

        // Create key with timestamp at the end
        let mut key = vec![1, 2, 3, 4, 5];
        key.extend_from_slice(&timestamp_bytes);

        let result = super::get_timestamp_from_key(&key).unwrap();
        assert_eq!(result, timestamp);
    }

    #[test]
    fn test_get_timestamp_from_key_exact_size() {
        let timestamp: i64 = 9_876_543_210;
        let key = timestamp.to_be_bytes();

        // Key with exactly TIMESTAMP_SIZE should fail based on current logic
        let result = super::get_timestamp_from_key(&key);
        let err = result.expect_err("Operation should have failed");
        assert!(err.to_string().contains("invalid database key length"));
    }

    #[test]
    fn test_get_timestamp_from_key_too_short() {
        let key = vec![1, 2, 3]; // Less than TIMESTAMP_SIZE (8 bytes)

        let result = super::get_timestamp_from_key(&key);
        let err = result.expect_err("Operation should have failed");
        assert!(err.to_string().contains("invalid database key length"));
    }

    #[test]
    fn test_migrate_data_dir_already_compatible() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create VERSION file with compatible version
        let version_path = temp_dir.path().join("VERSION");
        let version = env!("CARGO_PKG_VERSION");

        let mut file = File::create(&version_path).unwrap();
        file.write_all(version.as_bytes()).unwrap();
        drop(file);

        let db_options = DbOptions::default();
        let result = migrate_data_dir(temp_dir.path(), &db_options);

        // Should succeed without migration
        assert!(result.is_ok());

        // Verify that migration was NOT performed by checking that the 'db' directory
        // was not created. Migration functions (migrate_0_21_to_0_23, etc.)
        // would call Database::open() or rename_sources_to_sensors() which creates the 'db' path.
        let db_path = temp_dir.path().join("db");
        assert!(!db_path.exists());
    }

    #[test]
    fn test_migrate_data_dir_creates_directory_if_not_exists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let new_dir = temp_dir.path().join("new_data_dir");

        // Directory doesn't exist yet
        assert!(!new_dir.exists());

        let db_options = DbOptions::default();
        let result = migrate_data_dir(&new_dir, &db_options);

        // Should create directory and VERSION file
        assert!(result.is_ok());
        assert!(new_dir.exists());
        assert!(new_dir.join("VERSION").exists());
    }

    #[test]
    fn test_rename_sources_to_sensors_no_old_cf() {
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir_to_db_path(db_dir.path());

        // Create database without "sources" CF
        let db_options = DbOptions::default();
        {
            let db = Database::open(&db_path, &db_options).unwrap();
            let sensor_store = db.sensors_store().unwrap();
            sensor_store.insert("test_sensor", Utc::now()).unwrap();
        }

        // Should succeed without doing anything
        let result = super::rename_sources_to_sensors(&db_path, &db_options);
        assert!(result.is_ok());

        // Verify that "sources" CF does not exist and "sensors" CF exists
        let (rocksdb_opts, _) = rocksdb_options(&db_options);
        let cfs = DB::list_cf(&rocksdb_opts, &db_path).unwrap();
        assert!(cfs.iter().all(|cf| cf != "sources"));
        assert!(cfs.iter().any(|cf| cf == "sensors"));

        // Verify data in "sensors" CF is still there
        let db = Database::open(&db_path, &db_options).unwrap();
        let sensor_store = db.sensors_store().unwrap();
        let list = sensor_store.sensor_list();
        assert_eq!(list.len(), 1);
        assert!(list.contains("test_sensor"));
    }

    #[test]
    fn test_migrate_0_23_0_to_0_24_0_op_log_invalid_key() {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let store = db.op_log_store().unwrap();

        // Insert entry with key that's too short (no timestamp)
        let old_op_log = OpLogBeforeV24 {
            agent_name: "local".to_string(),
            log_level: OpLogLevel::Info,
            contents: "test".to_string(),
        };
        let serialized = bincode::serialize(&old_op_log).unwrap();
        let short_key = b"short"; // Key without proper timestamp

        store.append(short_key, &serialized).unwrap();

        // Should handle invalid key gracefully
        let result = super::migrate_0_23_0_to_0_24_0_op_log(&db);
        assert!(result.is_ok());

        // The invalid entry should be skipped
        let count = store.iter_forward().count();
        assert_eq!(count, 1); // Original entry still exists (not migrated)
    }

    #[test]
    fn test_migrate_0_24_to_0_26_http_combines_filenames_and_mime_types() {
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        let sensor = "test_sensor";

        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();

        // Create old HTTP entry with both orig and resp filenames/mime_types
        let old_http = HttpFromV21BeforeV26 {
            orig_addr: "192.168.1.1".parse().unwrap(),
            orig_port: 80,
            resp_addr: "192.168.1.2".parse().unwrap(),
            resp_port: 8080,
            proto: 6,
            end_time: timestamp + 1000,
            method: "POST".to_string(),
            host: "example.com".to_string(),
            uri: "/upload".to_string(),
            referer: String::new(),
            version: "1.1".to_string(),
            user_agent: "test".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: "multipart/form-data".to_string(),
            cache_control: String::new(),
            orig_filenames: vec!["file1.txt".to_string(), "file2.txt".to_string()],
            orig_mime_types: vec!["text/plain".to_string(), "text/plain".to_string()],
            resp_filenames: vec!["response.json".to_string()],
            resp_mime_types: vec!["application/json".to_string()],
            post_body: vec![1, 2, 3],
            state: String::new(),
        };

        let serialized = bincode::serialize(&old_http).unwrap();
        let key = build_storage_key(sensor, timestamp);

        let http_store = db.http_store().unwrap();
        http_store.append(&key, &serialized).unwrap();

        // Migrate
        super::migrate_0_24_to_0_26_http(&db).unwrap();

        // Verify migration - filenames and mime_types should be combined
        let (_, val) = http_store.iter_forward().next().unwrap().unwrap();
        let migrated: HttpFromV26 = bincode::deserialize(&val).unwrap();

        assert_eq!(migrated.filenames.len(), 3);
        assert_eq!(migrated.filenames[0], "file1.txt");
        assert_eq!(migrated.filenames[1], "file2.txt");
        assert_eq!(migrated.filenames[2], "response.json");

        assert_eq!(migrated.mime_types.len(), 3);
        assert_eq!(migrated.mime_types[0], "text/plain");
        assert_eq!(migrated.mime_types[1], "text/plain");
        assert_eq!(migrated.mime_types[2], "application/json");
    }

    #[test]
    fn test_migrate_0_21_to_0_23_netflow5_multiple_entries() {
        const TEST_SENSOR: &str = "sensor1";

        let db_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir_to_db_path(db_dir.path());
        let db = open_with_old_cfs(&db_path, &DbOptions::default());

        let netflow5_store = db.netflow5_store().unwrap();

        // Insert multiple entries
        for i in 0..5 {
            let key = StorageKey::builder()
                .start_key(TEST_SENSOR)
                .end_key(1000_i64 + i)
                .build()
                .key();
            let old = Netflow5BeforeV23 {
                source: String::new(),
                src_addr: "192.168.1.1".parse().unwrap(),
                dst_addr: "192.168.1.2".parse().unwrap(),
                next_hop: "192.168.1.254".parse().unwrap(),
                input: u16::try_from(i).unwrap(),
                output: 1,
                d_pkts: 10,
                d_octets: 1000,
                first: 100,
                last: 200,
                src_port: 1000 + u16::try_from(i).unwrap(),
                dst_port: 80,
                tcp_flags: 0,
                prot: 6,
                tos: 0,
                src_as: 0,
                dst_as: 0,
                src_mask: 0,
                dst_mask: 0,
                sequence: u32::try_from(i).unwrap(),
                engine_type: 0,
                engine_id: 0,
                sampling_mode: 0,
                sampling_rate: 0,
            };

            let serialized = bincode::serialize(&old).unwrap();
            netflow5_store.append(&key, &serialized).unwrap();
        }

        // Migrate
        super::migrate_0_21_to_0_23_netflow5(&db).unwrap();

        // Verify all entries migrated
        let count = netflow5_store.iter_forward().count();
        assert_eq!(count, 5);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn migrate_data_dir_migrates_data_and_updates_version() {
        const SENSOR: &str = "src_full";
        const OPLOG_SENSOR: &str = "local@src_full";
        const NETFLOW_TIMESTAMP: i64 = 1_000;
        const CONN_TIMESTAMP: i64 = 2_000;
        const HTTP_TIMESTAMP: i64 = 3_000;
        const DNS_TIMESTAMP: i64 = 4_000;
        const SSH_TIMESTAMP: i64 = 5_000;

        let data_dir = tempfile::tempdir().unwrap();
        mock_version_file(&data_dir, "0.21.0");
        let db_path = data_dir_to_db_path(data_dir.path());

        let netflow5_key = build_storage_key(SENSOR, NETFLOW_TIMESTAMP);
        let netflow5_old = setup_mock_netflow5_v21();
        let serialized_netflow5_old = bincode::serialize(&netflow5_old).unwrap();

        let op_log_old = OpLogBeforeV24 {
            agent_name: "agent-alpha".to_string(),
            log_level: OpLogLevel::Warn,
            contents: "disk space low".to_string(),
        };
        let op_log_key = build_storage_key(OPLOG_SENSOR, NETFLOW_TIMESTAMP);
        let serialized_op_log_old = bincode::serialize(&op_log_old).unwrap();

        let conn_key = build_storage_key(SENSOR, CONN_TIMESTAMP);
        let conn_old = setup_mock_conn_v21();
        let serialized_conn_old = bincode::serialize(&conn_old).unwrap();

        let http_key = build_storage_key(SENSOR, HTTP_TIMESTAMP);
        let http_old = HttpFromV21BeforeV26 {
            orig_addr: "10.1.1.1".parse().unwrap(),
            orig_port: 80,
            resp_addr: "10.1.1.2".parse().unwrap(),
            resp_port: 8080,
            proto: 6,
            end_time: HTTP_TIMESTAMP + 5,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/path".to_string(),
            referer: "http://ref".to_string(),
            version: "1.1".to_string(),
            user_agent: "agent".to_string(),
            request_len: 10,
            response_len: 20,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "gzip".to_string(),
            content_type: "text/html".to_string(),
            cache_control: "no-cache".to_string(),
            orig_filenames: vec!["a.txt".to_string()],
            orig_mime_types: vec!["text/plain".to_string()],
            resp_filenames: vec!["b.txt".to_string()],
            resp_mime_types: vec!["application/json".to_string()],
            post_body: vec![1, 2, 3],
            state: "done".to_string(),
        };
        let serialized_http_old = bincode::serialize(&http_old).unwrap();

        let dns_key = build_storage_key(SENSOR, DNS_TIMESTAMP);
        let dns_old = DnsBeforeV26 {
            orig_addr: "192.168.0.10".parse().unwrap(),
            orig_port: 5353,
            resp_addr: "192.168.0.11".parse().unwrap(),
            resp_port: 53,
            proto: 17,
            end_time: DNS_TIMESTAMP + 50,
            query: "test.com".to_string(),
            answer: vec!["1.1.1.1".to_string()],
            trans_id: 2,
            rtt: 10,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: true,
            tc_flag: false,
            rd_flag: true,
            ra_flag: false,
            ttl: vec![300],
        };
        let serialized_dns_old = bincode::serialize(&dns_old).unwrap();

        let ssh_key = build_storage_key(SENSOR, SSH_TIMESTAMP);
        let ssh_old = SshBeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: SSH_TIMESTAMP + 10,
            client: "client".to_string(),
            server: "server".to_string(),
            cipher_alg: "cipher_alg".to_string(),
            mac_alg: "mac_alg".to_string(),
            compression_alg: "compression_alg".to_string(),
            kex_alg: "kex_alg".to_string(),
            host_key_alg: "host_key_alg".to_string(),
            hassh_algorithms: "hassh_algorithms".to_string(),
            hassh: "hassh".to_string(),
            hassh_server_algorithms: "hassh_server_algorithms".to_string(),
            hassh_server: "hassh_server".to_string(),
            client_shka: "client_shka".to_string(),
            server_shka: "server_shka".to_string(),
        };
        let serialized_ssh_old = bincode::serialize(&ssh_old).unwrap();

        {
            let db = open_with_old_cfs(&db_path, &DbOptions::default());
            db.netflow5_store()
                .unwrap()
                .append(&netflow5_key, &serialized_netflow5_old)
                .unwrap();
            db.op_log_store()
                .unwrap()
                .append(&op_log_key, &serialized_op_log_old)
                .unwrap();
            db.conn_store()
                .unwrap()
                .append(&conn_key, &serialized_conn_old)
                .unwrap();
            db.http_store()
                .unwrap()
                .append(&http_key, &serialized_http_old)
                .unwrap();
            db.dns_store()
                .unwrap()
                .append(&dns_key, &serialized_dns_old)
                .unwrap();
            db.ssh_store()
                .unwrap()
                .append(&ssh_key, &serialized_ssh_old)
                .unwrap();
        }

        migrate_data_dir(data_dir.path(), &DbOptions::default()).unwrap();

        let version_content = fs::read_to_string(data_dir.path().join("VERSION")).unwrap();
        assert_eq!(version_content, env!("CARGO_PKG_VERSION"));

        let db = Database::open(&db_path, &DbOptions::default()).unwrap();

        let (rocksdb_opts, _) = rocksdb_options(&DbOptions::default());
        let cfs = DB::list_cf(&rocksdb_opts, &db_path).unwrap();
        assert!(cfs.iter().any(|cf| cf == "sensors"));
        assert!(cfs.iter().all(|cf| cf != "sources"));

        let (stored_netflow_key, stored_netflow_value) = db
            .netflow5_store()
            .unwrap()
            .iter_forward()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(stored_netflow_key.to_vec(), netflow5_key);
        let expected_netflow: Netflow5FromV23 = netflow5_old.into();
        let migrated_netflow = bincode::deserialize(&stored_netflow_value).unwrap();
        assert_eq!(expected_netflow, migrated_netflow);

        let op_log_store = db.op_log_store().unwrap();
        assert_eq!(op_log_store.iter_forward().count(), 1);
        let (_key, op_log_raw) = op_log_store.iter_forward().next().unwrap().unwrap();
        let op_log: OpLogFromV24 = bincode::deserialize(&op_log_raw).unwrap();
        assert_eq!(op_log.sensor, "src_full");
        assert_eq!(op_log.agent_name, op_log_old.agent_name);
        assert_eq!(op_log.contents, op_log_old.contents);
        assert_eq!(op_log.log_level, op_log_old.log_level);

        let (_, conn_val) = db
            .conn_store()
            .unwrap()
            .iter_forward()
            .next()
            .unwrap()
            .unwrap();
        let migrated_conn: ConnFromV26 = bincode::deserialize(&conn_val).unwrap();
        let expected_conn = ConnFromV26 {
            orig_addr: conn_old.orig_addr,
            orig_port: conn_old.orig_port,
            resp_addr: conn_old.resp_addr,
            resp_port: conn_old.resp_port,
            proto: conn_old.proto,
            conn_state: conn_old.conn_state,
            start_time: CONN_TIMESTAMP,
            duration: conn_old.duration,
            service: conn_old.service,
            orig_bytes: conn_old.orig_bytes,
            resp_bytes: conn_old.resp_bytes,
            orig_pkts: conn_old.orig_pkts,
            resp_pkts: conn_old.resp_pkts,
            orig_l2_bytes: conn_old.orig_l2_bytes,
            resp_l2_bytes: conn_old.resp_l2_bytes,
        };
        assert_eq!(migrated_conn, expected_conn);

        let (_, http_val) = db
            .http_store()
            .unwrap()
            .iter_forward()
            .next()
            .unwrap()
            .unwrap();
        let migrated_http: HttpFromV26 = bincode::deserialize(&http_val).unwrap();
        let expected_http = HttpFromV26 {
            orig_addr: http_old.orig_addr,
            orig_port: http_old.orig_port,
            resp_addr: http_old.resp_addr,
            resp_port: http_old.resp_port,
            proto: http_old.proto,
            start_time: HTTP_TIMESTAMP,
            duration: http_old.end_time - HTTP_TIMESTAMP,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            method: http_old.method,
            host: http_old.host,
            uri: http_old.uri,
            referer: http_old.referer,
            version: http_old.version,
            user_agent: http_old.user_agent,
            request_len: http_old.request_len,
            response_len: http_old.response_len,
            status_code: http_old.status_code,
            status_msg: http_old.status_msg,
            username: http_old.username,
            password: http_old.password,
            cookie: http_old.cookie,
            content_encoding: http_old.content_encoding,
            content_type: http_old.content_type,
            cache_control: http_old.cache_control,
            filenames: vec!["a.txt".to_string(), "b.txt".to_string()],
            mime_types: vec!["text/plain".to_string(), "application/json".to_string()],
            body: http_old.post_body,
            state: http_old.state,
        };
        assert_eq!(migrated_http, expected_http);

        let (_, dns_val) = db
            .dns_store()
            .unwrap()
            .iter_forward()
            .next()
            .unwrap()
            .unwrap();
        let migrated_dns: DnsFromV26 = bincode::deserialize(&dns_val).unwrap();
        let expected_dns = DnsFromV26 {
            orig_addr: dns_old.orig_addr,
            orig_port: dns_old.orig_port,
            resp_addr: dns_old.resp_addr,
            resp_port: dns_old.resp_port,
            proto: dns_old.proto,
            start_time: DNS_TIMESTAMP,
            duration: dns_old.end_time - DNS_TIMESTAMP,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: dns_old.query,
            answer: dns_old.answer,
            trans_id: dns_old.trans_id,
            rtt: dns_old.rtt,
            qclass: dns_old.qclass,
            qtype: dns_old.qtype,
            rcode: dns_old.rcode,
            aa_flag: dns_old.aa_flag,
            tc_flag: dns_old.tc_flag,
            rd_flag: dns_old.rd_flag,
            ra_flag: dns_old.ra_flag,
            ttl: dns_old.ttl,
        };
        assert_eq!(migrated_dns, expected_dns);

        let (_, ssh_val) = db
            .ssh_store()
            .unwrap()
            .iter_forward()
            .next()
            .unwrap()
            .unwrap();
        let migrated_ssh: SshFromV26 = bincode::deserialize(&ssh_val).unwrap();
        let expected_ssh = SshFromV26 {
            orig_addr: ssh_old.orig_addr,
            orig_port: ssh_old.orig_port,
            resp_addr: ssh_old.resp_addr,
            resp_port: ssh_old.resp_port,
            proto: ssh_old.proto,
            start_time: SSH_TIMESTAMP,
            duration: ssh_old.end_time - SSH_TIMESTAMP,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            client: ssh_old.client,
            server: ssh_old.server,
            cipher_alg: ssh_old.cipher_alg,
            mac_alg: ssh_old.mac_alg,
            compression_alg: ssh_old.compression_alg,
            kex_alg: ssh_old.kex_alg,
            host_key_alg: ssh_old.host_key_alg,
            hassh_algorithms: ssh_old.hassh_algorithms,
            hassh: ssh_old.hassh,
            hassh_server_algorithms: ssh_old.hassh_server_algorithms,
            hassh_server: ssh_old.hassh_server,
            client_shka: ssh_old.client_shka,
            server_shka: ssh_old.server_shka,
        };
        assert_eq!(migrated_ssh, expected_ssh);
    }
}
