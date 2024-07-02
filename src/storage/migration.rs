//! Routines to check the database format version and migrate it if necessary.
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    net::IpAddr,
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::log::SecuLog;
use semver::{Version, VersionReq};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::info;

use super::Database;
use crate::{
    graphql::TIMESTAMP_SIZE,
    ingest::implement::EventFilter,
    storage::{RawEventStore, StorageKey},
};

const COMPATIBLE_VERSION_REQ: &str = ">=0.19.0,<0.21.0";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format too old to be upgraded.
pub fn migrate_data_dir(data_dir: &Path, db: &Database) -> Result<()> {
    let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid version requirement");
    let mut version: Version = retrieve_or_create_version(data_dir)?;
    if compatible.matches(&version) {
        return Ok(());
    }

    let migration: Vec<(_, _, fn(_) -> Result<_, _>)> = vec![
        (
            VersionReq::parse(">=0.10.0,<0.12.0").expect("valid version requirement"),
            Version::parse("0.12.0").expect("valid version"),
            migrate_0_10_to_0_12,
        ),
        (
            VersionReq::parse(">=0.12.0,<0.13.0").expect("valid version requirement"),
            Version::parse("0.13.0").expect("valid version"),
            migrate_0_12_to_0_13_0,
        ),
        (
            VersionReq::parse(">=0.13.0,<0.19.0").expect("valid version requirement"),
            Version::parse("0.19.0").expect("valid version"),
            migrate_0_13_to_0_19_0,
        ),
    ];

    while let Some((_req, to, m)) = migration
        .iter()
        .find(|(req, _to, _m)| req.matches(&version))
    {
        info!("Migrating database to {to}");
        m(db)?;
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

#[allow(clippy::too_many_lines)]
fn migrate_0_10_to_0_12(db: &Database) -> Result<()> {
    #[derive(Deserialize, Serialize)]
    pub struct OldHttp {
        pub orig_addr: IpAddr,
        pub orig_port: u16,
        pub resp_addr: IpAddr,
        pub resp_port: u16,
        pub proto: u8,
        pub last_time: i64,
        pub method: String,
        pub host: String,
        pub uri: String,
        pub referrer: String,
        pub version: String,
        pub user_agent: String,
        pub request_len: usize,
        pub response_len: usize,
        pub status_code: u16,
        pub status_msg: String,
        pub username: String,
        pub password: String,
        pub cookie: String,
        pub content_encoding: String,
        pub content_type: String,
        pub cache_control: String,
    }

    #[derive(Deserialize, Serialize)]
    pub struct NewHttp {
        pub orig_addr: IpAddr,
        pub orig_port: u16,
        pub resp_addr: IpAddr,
        pub resp_port: u16,
        pub proto: u8,
        pub last_time: i64,
        pub method: String,
        pub host: String,
        pub uri: String,
        pub referrer: String,
        pub version: String,
        pub user_agent: String,
        pub request_len: usize,
        pub response_len: usize,
        pub status_code: u16,
        pub status_msg: String,
        pub username: String,
        pub password: String,
        pub cookie: String,
        pub content_encoding: String,
        pub content_type: String,
        pub cache_control: String,
        pub orig_filenames: Vec<String>,
        pub orig_mime_types: Vec<String>,
        pub resp_filenames: Vec<String>,
        pub resp_mime_types: Vec<String>,
    }

    impl From<OldHttp> for NewHttp {
        fn from(input: OldHttp) -> Self {
            Self {
                orig_addr: input.orig_addr,
                orig_port: input.orig_port,
                resp_addr: input.resp_addr,
                resp_port: input.resp_port,
                proto: input.proto,
                last_time: input.last_time,
                method: input.method,
                host: input.host,
                uri: input.uri,
                referrer: input.referrer,
                version: input.version,
                user_agent: input.user_agent,
                request_len: input.request_len,
                response_len: input.response_len,
                status_code: input.status_code,
                status_msg: input.status_msg,
                username: input.username,
                password: input.password,
                cookie: input.cookie,
                content_encoding: input.content_encoding,
                content_type: input.content_type,
                cache_control: input.cache_control,
                orig_filenames: vec!["-".to_string()],
                orig_mime_types: vec!["-".to_string()],
                resp_filenames: vec!["-".to_string()],
                resp_mime_types: vec!["-".to_string()],
            }
        }
    }

    let store = db.http_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<OldHttp>(&val)?;
        let convert_new: NewHttp = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }

    Ok(())
}

// Remove old statistics data because it's overwritten
// by the data of other core of same machine.
fn migrate_0_12_to_0_13_0(db: &Database) -> Result<()> {
    let store = db.statistics_store()?;
    for raw_event in store.iter_forward() {
        let (key, _) = raw_event.context("Failed to read Database")?;
        store.delete(&key)?;
    }
    Ok(())
}

// Delete the netflow5/netflow5/secuLog data in the old key and insert it with the new key.
fn migrate_0_13_to_0_19_0(db: &Database) -> Result<()> {
    let netflow5_store = db.netflow5_store()?;
    migrate_netflow(&netflow5_store)?;

    let netflow9_store = db.netflow9_store()?;
    migrate_netflow(&netflow9_store)?;

    let secu_log_store = db.secu_log_store()?;
    for raw_event in secu_log_store.iter_forward() {
        let Ok((key, value)) = raw_event else {
            continue;
        };
        secu_log_store.delete(&key)?;

        let (Ok(timestamp), Ok(secu_log_raw_event)) = (
            get_timestamp_from_key(&key),
            bincode::deserialize::<SecuLog>(&value),
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

fn migrate_netflow<T>(store: &RawEventStore<'_, T>) -> Result<()>
where
    T: DeserializeOwned + EventFilter,
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
            .start_key(&netflow_raw_event.source().unwrap()) //source is always exist
            .end_key(timestamp)
            .build();
        store.append(&new_key.key(), &value)?;
    }
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
    use std::net::IpAddr;

    use chrono::Utc;
    use giganto_client::ingest::{
        log::SecuLog,
        netflow::{Netflow5, Netflow9},
        network::Http,
    };
    use semver::{Version, VersionReq};
    use serde::{Deserialize, Serialize};

    use super::COMPATIBLE_VERSION_REQ;
    use crate::storage::{Database, DbOptions, StorageKey};

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
    fn migrate_0_10_to_0_12() {
        #[derive(Deserialize, Serialize)]
        pub struct OldHttp {
            pub orig_addr: IpAddr,
            pub orig_port: u16,
            pub resp_addr: IpAddr,
            pub resp_port: u16,
            pub proto: u8,
            pub last_time: i64,
            pub method: String,
            pub host: String,
            pub uri: String,
            pub referrer: String,
            pub version: String,
            pub user_agent: String,
            pub request_len: usize,
            pub response_len: usize,
            pub status_code: u16,
            pub status_msg: String,
            pub username: String,
            pub password: String,
            pub cookie: String,
            pub content_encoding: String,
            pub content_type: String,
            pub cache_control: String,
        }

        // open temp db & store
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let store = db.http_store().unwrap();

        // insert old http raw data
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        let source = "src1";
        let mut key = Vec::with_capacity(source.len() + 1 + std::mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let old_http = OldHttp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            method: "POST".to_string(),
            host: "einsis".to_string(),
            uri: "/einsis.gif".to_string(),
            referrer: "einsis.com".to_string(),
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
        };
        let ser_old_http = bincode::serialize(&old_http).unwrap();

        store.append(&key, &ser_old_http).unwrap();

        //migration 0.10.0 to 0.12.0
        super::migrate_0_10_to_0_12(&db).unwrap();

        //check migration
        let start_key = key;
        let mut end_key = Vec::with_capacity(source.len() + 1 + std::mem::size_of::<i64>());
        end_key.extend_from_slice(source.as_bytes());
        end_key.push(0);
        end_key.extend((timestamp + 1).to_be_bytes());

        let mut result_iter =
            store.boundary_iter(&start_key, &end_key, rocksdb::Direction::Forward);

        let new_http = Http {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            method: "POST".to_string(),
            host: "einsis".to_string(),
            uri: "/einsis.gif".to_string(),
            referrer: "einsis.com".to_string(),
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

        let (_, value) = result_iter.next().unwrap().unwrap();
        assert_eq!(new_http, value);
    }

    #[test]
    fn migrate_0_13_to_0_19() {
        const OLD_NETFLOW5_PREFIX_KEY: &str = "netflow5";
        const OLD_NETFLOW9_PREFIX_KEY: &str = "netflow9";
        const TEST_SOURCE: &str = "src1";
        const TEST_KIND: &str = "kind1"; //Used as prefix key in seculog's old key.
        const TEST_TIMESTAMP: i64 = 1000;

        // open temp db
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();

        // insert netflow5 data using the old key.
        let netflow5_store = db.netflow5_store().unwrap();
        let netflow5_body = Netflow5 {
            source: TEST_SOURCE.to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            next_hop: "192.168.4.78".parse::<IpAddr>().unwrap(),
            input: 65535,
            output: 1,
            d_pkts: 1,
            d_octets: 464,
            first: 3477280180,
            last: 3477280180,
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
        let netflow5_old_key = StorageKey::builder()
            .start_key(OLD_NETFLOW5_PREFIX_KEY)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();

        netflow5_store
            .append(&netflow5_old_key, &serialized_netflow5)
            .unwrap();

        // insert netflow9 data using the old key.
        let netflow9_store = db.netflow9_store().unwrap();
        let netflow9_body = Netflow9 {
            source: TEST_SOURCE.to_string(),
            sequence: 3282250832,
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
        let netflow9_old_key = StorageKey::builder()
            .start_key(OLD_NETFLOW9_PREFIX_KEY)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();
        netflow9_store
            .append(&netflow9_old_key, &serialized_netflow9)
            .unwrap();

        // insert secuLog data using the old key.
        let secu_log_store = db.secu_log_store().unwrap();
        let secu_log_body = SecuLog {
            source: TEST_SOURCE.to_string(),
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
        let secu_log_old_key = StorageKey::builder()
            .start_key(TEST_KIND)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();
        secu_log_store
            .append(&secu_log_old_key, &serialized_secu_log)
            .unwrap();

        //migration 0.13.0 to 0.19.0
        super::migrate_0_13_to_0_19_0(&db).unwrap();

        //check netflow5/9 migration
        let netflow_new_key = StorageKey::builder()
            .start_key(TEST_SOURCE)
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();

        let mut result_iter = netflow5_store.iter_forward();
        let (result_key, result_value) = result_iter.next().unwrap().unwrap();

        assert_ne!(netflow5_old_key, result_key.to_vec());
        assert_eq!(netflow_new_key, result_key.to_vec());
        assert_eq!(serialized_netflow5, result_value.to_vec());

        let mut result_iter = netflow9_store.iter_forward();
        let (result_key, result_value) = result_iter.next().unwrap().unwrap();

        assert_ne!(netflow9_old_key, result_key.to_vec());
        assert_eq!(netflow_new_key, result_key.to_vec());
        assert_eq!(serialized_netflow9, result_value.to_vec());

        //check secuLog migration
        let secu_log_new_key = StorageKey::builder()
            .start_key(TEST_SOURCE)
            .mid_key(Some(TEST_KIND.as_bytes().to_vec()))
            .end_key(TEST_TIMESTAMP)
            .build()
            .key();

        let mut result_iter = secu_log_store.iter_forward();
        let (result_key, result_value) = result_iter.next().unwrap().unwrap();

        assert_ne!(secu_log_old_key, result_key.to_vec());
        assert_eq!(secu_log_new_key, result_key.to_vec());
        assert_eq!(serialized_secu_log, result_value.to_vec());
    }
}
