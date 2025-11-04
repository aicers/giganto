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

const COMPATIBLE_VERSION_REQ: &str = ">=0.26.0-alpha.6,<0.26.0-alpha.8";

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
            VersionReq::parse(">=0.24.0,<0.26.0-alpha.7").expect("valid version requirement"),
            Version::parse("0.26.0-alpha.7").expect("valid version"),
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

        // Calculate end_time by adding duration to session start time
        let end_time = session_start_time + old.duration;

        // Create new conn structure with DateTime types and duration field
        let new_conn = ConnFromV26 {
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            proto: old.proto,
            conn_state: old.conn_state,
            start_time: chrono::DateTime::from_timestamp_nanos(session_start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(end_time),
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
            start_time: chrono::DateTime::from_timestamp_nanos(start_time),
            end_time: chrono::DateTime::from_timestamp_nanos(old.end_time),
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
    use std::{fs, fs::File, io::Write, net::IpAddr, path::Path, path::PathBuf};

    use chrono::Utc;
    use giganto_client::ingest::{log::OpLogLevel, network::FtpCommand};
    use rocksdb::{ColumnFamilyDescriptor, DB, Options, WriteBatch};
    use semver::{Version, VersionReq};
    use tempfile::TempDir;

    use super::COMPATIBLE_VERSION_REQ;
    use crate::storage::{
        Bootp as BootpFromV26, Conn as ConnFromV26, Database, DbOptions, DceRpc as DceRpcFromV26,
        Dhcp as DhcpFromV26, Dns as DnsFromV26, Ftp as FtpFromV26, Http as HttpFromV26,
        Kerberos as KerberosFromV26, Ldap as LdapFromV26, Mqtt as MqttFromV26,
        Netflow5 as Netflow5FromV23, Netflow9 as Netflow9FromV23, Nfs as NfsFromV26,
        Ntlm as NtlmFromV26, OpLog as OpLogFromV24, RAW_DATA_COLUMN_FAMILY_NAMES,
        Rdp as RdpFromV26, SecuLog as SecuLogFromV23, Smb as SmbFromV26, Smtp as SmtpFromV26,
        Ssh as SshFromV26, StorageKey, Tls as TlsFromV26, data_dir_to_db_path, migrate_data_dir,
        migration::migration_structures::{
            BootpBeforeV26, ConnFromV21BeforeV26, DceRpcBeforeV26, DhcpBeforeV26, DnsBeforeV26,
            FtpBeforeV26, HttpFromV21BeforeV26, KerberosBeforeV26, LdapBeforeV26, MqttBeforeV26,
            Netflow5BeforeV23, Netflow9BeforeV23, NfsBeforeV26, NtlmBeforeV26, OpLogBeforeV24,
            RdpBeforeV26, SecuLogBeforeV23, SmbBeforeV26, SmtpBeforeV26, SshBeforeV26,
            TlsBeforeV26,
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

        // open temp db & store
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();

        // prepare old conn raw data
        let old_conn = ConnFromV21BeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: String::new(),
            duration: 100,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
        };
        let ser_old_conn = bincode::serialize(&old_conn).unwrap();
        let conn_old_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let conn_store = db.conn_store().unwrap();
        conn_store.append(&conn_old_key, &ser_old_conn).unwrap();

        // migration conn raw events
        super::migrate_0_24_to_0_26_conn(&db).unwrap();

        // check conn migration
        let raw_event = conn_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_conn = bincode::deserialize::<ConnFromV26>(&val).unwrap();
        let new_conn = ConnFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: String::new(),
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(timestamp + 100),
            duration: 100,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
        };
        assert_eq!(new_conn, store_conn);

        // prepare old http raw data
        let old_http = HttpFromV21BeforeV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            end_time: 1,
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
            orig_filenames: vec!["a".to_string()],
            orig_mime_types: vec!["1".to_string()],
            resp_filenames: vec!["b".to_string()],
            resp_mime_types: vec!["2".to_string()],
            post_body: vec![30, 31],
            state: String::new(),
        };
        let ser_old_http = bincode::serialize(&old_http).unwrap();
        let http_old_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let http_store = db.http_store().unwrap();
        http_store.append(&http_old_key, &ser_old_http).unwrap();

        // migration http raw events
        super::migrate_0_24_to_0_26_http(&db).unwrap();

        // check http migration
        let raw_event = http_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_http = bincode::deserialize::<HttpFromV26>(&val).unwrap();
        let new_http = HttpFromV26 {
            orig_addr: old_http.orig_addr,
            orig_port: old_http.orig_port,
            resp_addr: old_http.resp_addr,
            resp_port: old_http.resp_port,
            proto: old_http.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(old_http.end_time),
            duration: old_http.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
            filenames: vec!["a".to_string(), "b".to_string()],
            mime_types: vec!["1".to_string(), "2".to_string()],
            body: vec![30, 31],
            state: String::new(),
        };
        assert_eq!(new_http, store_http);

        // prepare old dns raw data
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
        let ser_dns_old = bincode::serialize(&dns_old).unwrap();
        let dns_old_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let dns_store = db.dns_store().unwrap();
        dns_store.append(&dns_old_key, &ser_dns_old).unwrap();

        // migration dns raw events
        super::migrate_raw_event_0_24_to_0_26::<DnsBeforeV26, DnsFromV26>(&dns_store).unwrap();

        // check dns migration
        let (_, val) = dns_store.iter_forward().next().unwrap().unwrap();
        let store_dns: DnsFromV26 = bincode::deserialize(&val).unwrap();
        let new_dns = DnsFromV26 {
            orig_addr: dns_old.orig_addr,
            orig_port: dns_old.orig_port,
            resp_addr: dns_old.resp_addr,
            resp_port: dns_old.resp_port,
            proto: dns_old.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(dns_old.end_time),
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
        assert_eq!(store_dns, new_dns);

        // prepare old rdp raw data
        let rdp_old = RdpBeforeV26 {
            orig_addr: "10.0.0.1".parse().unwrap(),
            orig_port: 3389,
            resp_addr: "10.0.0.2".parse().unwrap(),
            resp_port: 3390,
            proto: 6,
            end_time: 123,
            cookie: "cookie_val".to_string(),
        };
        let ser_rdp_old = bincode::serialize(&rdp_old).unwrap();
        let rdp_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let rdp_store = db.rdp_store().unwrap();
        rdp_store.append(&rdp_key, &ser_rdp_old).unwrap();

        // migration rdp raw events
        super::migrate_raw_event_0_24_to_0_26::<RdpBeforeV26, RdpFromV26>(&rdp_store).unwrap();

        // check rdp migration
        let (_, val) = rdp_store.iter_forward().next().unwrap().unwrap();
        let store_rdp: RdpFromV26 = bincode::deserialize(&val).unwrap();
        let new_rdp = RdpFromV26 {
            orig_addr: rdp_old.orig_addr,
            orig_port: rdp_old.orig_port,
            resp_addr: rdp_old.resp_addr,
            resp_port: rdp_old.resp_port,
            proto: rdp_old.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(rdp_old.end_time),
            duration: rdp_old.end_time - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            cookie: rdp_old.cookie.clone(),
        };
        assert_eq!(store_rdp, new_rdp);

        // prepare old smtp raw data
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
        let ser_smtp_old = bincode::serialize(&smtp_old).unwrap();
        let smtp_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let smtp_store = db.smtp_store().unwrap();
        smtp_store.append(&smtp_key, &ser_smtp_old).unwrap();

        // migration smtp raw events
        super::migrate_raw_event_0_24_to_0_26::<SmtpBeforeV26, SmtpFromV26>(&smtp_store).unwrap();

        // check smtp migration
        let (_, val) = smtp_store.iter_forward().next().unwrap().unwrap();
        let store_smtp: SmtpFromV26 = bincode::deserialize(&val).unwrap();
        let new_smtp = SmtpFromV26 {
            orig_addr: smtp_old.orig_addr,
            orig_port: smtp_old.orig_port,
            resp_addr: smtp_old.resp_addr,
            resp_port: smtp_old.resp_port,
            proto: smtp_old.proto,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(smtp_old.end_time),
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
        assert_eq!(store_smtp, new_smtp);

        // prepare old ntlm raw data
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
        let ser_ntlm_old = bincode::serialize(&ntlm_old).unwrap();
        let ntlm_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let ntlm_store = db.ntlm_store().unwrap();
        ntlm_store.append(&ntlm_key, &ser_ntlm_old).unwrap();

        // migration ntlm raw events
        super::migrate_raw_event_0_24_to_0_26::<NtlmBeforeV26, NtlmFromV26>(&ntlm_store).unwrap();

        // check ntlm migration
        let (_, val) = ntlm_store.iter_forward().next().unwrap().unwrap();
        let store_ntlm: NtlmFromV26 = bincode::deserialize(&val).unwrap();
        let new_ntlm = NtlmFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            username: "bly".to_string(),
            hostname: "host".to_string(),
            domainname: "domain".to_string(),
            success: "tf".to_string(),
            protocol: "protocol".to_string(),
        };
        assert_eq!(store_ntlm, new_ntlm);

        // prepare old kerberos raw data
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
        let ser_kerberos_old = bincode::serialize(&kerberos_old).unwrap();
        let kerberos_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let kerberos_store = db.kerberos_store().unwrap();
        kerberos_store
            .append(&kerberos_key, &ser_kerberos_old)
            .unwrap();

        // migration kerberos raw events
        super::migrate_raw_event_0_24_to_0_26::<KerberosBeforeV26, KerberosFromV26>(
            &kerberos_store,
        )
        .unwrap();

        // check kerberos migration
        let (_, val) = kerberos_store.iter_forward().next().unwrap().unwrap();
        let store_kerberos: KerberosFromV26 = bincode::deserialize(&val).unwrap();
        let new_kerberos = KerberosFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
        assert_eq!(store_kerberos, new_kerberos);

        // prepare old ssh raw data
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
        let ser_ssh_old = bincode::serialize(&ssh_old).unwrap();
        let ssh_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let ssh_store = db.ssh_store().unwrap();
        ssh_store.append(&ssh_key, &ser_ssh_old).unwrap();

        // migration ssh raw events
        super::migrate_raw_event_0_24_to_0_26::<SshBeforeV26, SshFromV26>(&ssh_store).unwrap();

        // check ssh migration
        let (_, val) = ssh_store.iter_forward().next().unwrap().unwrap();
        let store_ssh: SshFromV26 = bincode::deserialize(&val).unwrap();
        let new_ssh = SshFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
        assert_eq!(store_ssh, new_ssh);

        // prepare old dcerpc raw data
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
        let ser_dcerpc_old = bincode::serialize(&dcerpc_old).unwrap();
        let dcerpc_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let dcerpc_store = db.dce_rpc_store().unwrap();
        dcerpc_store.append(&dcerpc_key, &ser_dcerpc_old).unwrap();

        // migration dcerpc raw events
        super::migrate_raw_event_0_24_to_0_26::<DceRpcBeforeV26, DceRpcFromV26>(&dcerpc_store)
            .unwrap();
        let (_, val) = dcerpc_store.iter_forward().next().unwrap().unwrap();
        let store_dcerpc: DceRpcFromV26 = bincode::deserialize(&val).unwrap();

        // check dcerpc migration
        let new_dcerpc = DceRpcFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            rtt: 3,
            named_pipe: "named_pipe".to_string(),
            endpoint: "endpoint".to_string(),
            operation: "operation".to_string(),
        };
        assert_eq!(store_dcerpc, new_dcerpc);

        // prepare old ftp raw data
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
        let ser_ftp_old = bincode::serialize(&ftp_old).unwrap();
        let ftp_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let ftp_store = db.ftp_store().unwrap();
        ftp_store.append(&ftp_key, &ser_ftp_old).unwrap();

        // migration ftp raw events
        super::migrate_raw_event_0_24_to_0_26::<FtpBeforeV26, FtpFromV26>(&ftp_store).unwrap();

        // check ftp migration
        let (_, val) = ftp_store.iter_forward().next().unwrap().unwrap();
        let store_ftp: FtpFromV26 = bincode::deserialize(&val).unwrap();
        let new_ftp = FtpFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            user: "cluml".to_string(),
            password: "aice".to_string(),
            commands: vec![FtpCommand {
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
            }],
        };
        assert_eq!(store_ftp, new_ftp);

        // prepare old mqtt raw data
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
        let ser_mqtt_old = bincode::serialize(&mqtt_old).unwrap();
        let mqtt_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let mqtt_store = db.mqtt_store().unwrap();
        mqtt_store.append(&mqtt_key, &ser_mqtt_old).unwrap();

        // migration mqtt raw events
        super::migrate_raw_event_0_24_to_0_26::<MqttBeforeV26, MqttFromV26>(&mqtt_store).unwrap();

        // check mqtt migration
        let (_, val) = mqtt_store.iter_forward().next().unwrap().unwrap();
        let store_mqtt: MqttFromV26 = bincode::deserialize(&val).unwrap();
        let new_mqtt = MqttFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            protocol: "protocol".to_string(),
            version: 1,
            client_id: "1".to_string(),
            connack_reason: 1,
            subscribe: vec!["subscribe".to_string()],
            suback_reason: vec![1],
        };
        assert_eq!(store_mqtt, new_mqtt);

        // prepare old ldap raw data
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
        let ser_ldap_old = bincode::serialize(&ldap_old).unwrap();
        let ldap_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let ldap_store = db.ldap_store().unwrap();
        ldap_store.append(&ldap_key, &ser_ldap_old).unwrap();

        // migration ldap raw events
        super::migrate_raw_event_0_24_to_0_26::<LdapBeforeV26, LdapFromV26>(&ldap_store).unwrap();

        // check ldap migration
        let (_, val) = ldap_store.iter_forward().next().unwrap().unwrap();
        let store_ldap: LdapFromV26 = bincode::deserialize(&val).unwrap();
        let new_ldap = LdapFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            message_id: 1,
            version: 1,
            opcode: vec!["opcode".to_string()],
            result: vec!["result".to_string()],
            diagnostic_message: Vec::new(),
            object: Vec::new(),
            argument: Vec::new(),
        };
        assert_eq!(store_ldap, new_ldap);

        // prepare old tls raw data
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
        let ser_tls_old = bincode::serialize(&tls_old).unwrap();
        let tls_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let tls_store = db.tls_store().unwrap();
        tls_store.append(&tls_key, &ser_tls_old).unwrap();

        // migration tls raw events
        super::migrate_raw_event_0_24_to_0_26::<TlsBeforeV26, TlsFromV26>(&tls_store).unwrap();

        // check tls migration
        let (_, val) = tls_store.iter_forward().next().unwrap().unwrap();
        let store_tls: TlsFromV26 = bincode::deserialize(&val).unwrap();
        let new_tls = TlsFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
        assert_eq!(store_tls, new_tls);

        // prepare old smb raw data
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
        let ser_smb_old = bincode::serialize(&smb_old).unwrap();
        let smb_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let smb_store = db.smb_store().unwrap();
        smb_store.append(&smb_key, &ser_smb_old).unwrap();

        // migration smb raw events
        super::migrate_raw_event_0_24_to_0_26::<SmbBeforeV26, SmbFromV26>(&smb_store).unwrap();

        // check smb migration
        let (_, val) = smb_store.iter_forward().next().unwrap().unwrap();
        let store_smb: SmbFromV26 = bincode::deserialize(&val).unwrap();
        let new_smb = SmbFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
        assert_eq!(store_smb, new_smb);

        // prepare old nfs raw data
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
        let ser_nfs_old = bincode::serialize(&nfs_old).unwrap();
        let nfs_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let nfs_store = db.nfs_store().unwrap();
        nfs_store.append(&nfs_key, &ser_nfs_old).unwrap();

        // migration nfs raw events
        super::migrate_raw_event_0_24_to_0_26::<NfsBeforeV26, NfsFromV26>(&nfs_store).unwrap();

        // check nfs migration
        let (_, val) = nfs_store.iter_forward().next().unwrap().unwrap();
        let store_nfs: NfsFromV26 = bincode::deserialize(&val).unwrap();
        let new_nfs = NfsFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            read_files: vec![],
            write_files: vec![],
        };
        assert_eq!(store_nfs, new_nfs);

        // prepare old bootp raw data
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
        let ser_bootp_old = bincode::serialize(&bootp_old).unwrap();
        let bootp_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let bootp_store = db.bootp_store().unwrap();
        bootp_store.append(&bootp_key, &ser_bootp_old).unwrap();

        // migration bootp raw events
        super::migrate_raw_event_0_24_to_0_26::<BootpBeforeV26, BootpFromV26>(&bootp_store)
            .unwrap();

        // check bootp migration
        let (_, val) = bootp_store.iter_forward().next().unwrap().unwrap();
        let store_bootp: BootpFromV26 = bincode::deserialize(&val).unwrap();
        let new_bootp = BootpFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
        assert_eq!(store_bootp, new_bootp);

        // prepare old dhcp raw data
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
        let ser_dhcp_old = bincode::serialize(&dhcp_old).unwrap();
        let dhcp_key = StorageKey::builder()
            .start_key(sensor)
            .end_key(timestamp)
            .build()
            .key();
        let dhcp_store = db.dhcp_store().unwrap();
        dhcp_store.append(&dhcp_key, &ser_dhcp_old).unwrap();

        // migration dhcp raw events
        super::migrate_raw_event_0_24_to_0_26::<DhcpBeforeV26, DhcpFromV26>(&dhcp_store).unwrap();

        // check dhcp migration
        let (_, val) = dhcp_store.iter_forward().next().unwrap().unwrap();
        let store_dhcp: DhcpFromV26 = bincode::deserialize(&val).unwrap();
        let new_dhcp = DhcpFromV26 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            start_time: chrono::DateTime::from_timestamp_nanos(timestamp),
            end_time: chrono::DateTime::from_timestamp_nanos(1),
            duration: 1 - timestamp,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
        assert_eq!(store_dhcp, new_dhcp);
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
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Only versions 0.21.0 and above are supported")
        );
    }
}
