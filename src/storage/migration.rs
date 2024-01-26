//! Routines to check the database format version and migrate it if necessary.
use super::Database;
use anyhow::{anyhow, Context, Result};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    net::IpAddr,
    path::Path,
};
use tracing::info;

const COMPATIBLE_VERSION_REQ: &str = ">0.13.0-alpha,<=0.17.0";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format too old to be upgraded.
pub fn migrate_data_dir(data_dir: &Path, db: &Database) -> Result<()> {
    let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid version requirement");
    let mut version = retrieve_or_create_version(data_dir)?;
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
            VersionReq::parse(">=0.12.0,<=0.13.0-alpha.1").expect("valid version requirement"),
            Version::parse("0.13.0").expect("valid version"),
            migrate_0_12_to_0_13_0,
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

#[cfg(test)]
mod tests {
    use super::COMPATIBLE_VERSION_REQ;
    use crate::storage::{Database, DbOptions};
    use chrono::Utc;
    use giganto_client::ingest::network::Http;
    use semver::{Version, VersionReq};
    use serde::{Deserialize, Serialize};
    use std::net::IpAddr;

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
                breaking.minor -= 5;
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
}
