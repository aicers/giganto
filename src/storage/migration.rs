//! Routines to check the database format version and migrate it if necessary.
mod migration_structures;

use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::log::SecuLog;
use semver::{Version, VersionReq};
use serde::de::DeserializeOwned;
use tracing::info;

use self::migration_structures::{
    ConnBeforeV21A1, ConnFromV21A1BeforeV21A2, HttpFromV12BeforeV21, NtlmBeforeV21, SmtpBeforeV21,
    SshBeforeV21, TlsBeforeV21,
};
use super::Database;
use crate::{
    graphql::TIMESTAMP_SIZE,
    ingest::implement::EventFilter,
    storage::{
        Conn as ConnFromV21, Http as HttpFromV21, Ntlm as NtlmFromV21, RawEventStore,
        Smtp as SmtpFromV21, Ssh as SshFromV21, StorageKey, Tls as TlsFromV21,
    },
};

const COMPATIBLE_VERSION_REQ: &str = ">=0.21.0-alpha.2,<0.22.0";

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
            VersionReq::parse(">=0.13.0,<0.19.0").expect("valid version requirement"),
            Version::parse("0.19.0").expect("valid version"),
            migrate_0_13_to_0_19_0,
        ),
        (
            VersionReq::parse(">=0.19.0,<0.21.0-alpha.1").expect("valid version requirement"),
            Version::parse("0.21.0-alpha.1").expect("valid version"),
            migrate_0_19_to_0_21_0_alpha_1,
        ),
        (
            VersionReq::parse(">=0.21.0-alpha.1,<0.21.0-alpha.2")
                .expect("valid version requirement"),
            Version::parse("0.21.0-alpha.2").expect("valid version"),
            migrate_0_21_0_alpha_1_to_0_21_0_alpha_2,
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

#[allow(clippy::too_many_lines)]
fn migrate_0_19_to_0_21_0_alpha_1(db: &Database) -> Result<()> {
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
        let old = bincode::deserialize::<ConnBeforeV21A1>(&val)?;
        let convert_new: ConnFromV21A1BeforeV21A2 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
    }
    info!("conn migration complete");

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn migrate_0_21_0_alpha_1_to_0_21_0_alpha_2(db: &Database) -> Result<()> {
    let store = db.conn_store()?;
    for raw_event in store.iter_forward() {
        let (key, val) = raw_event.context("Failed to read Database")?;
        let old = bincode::deserialize::<ConnFromV21A1BeforeV21A2>(&val)?;
        let convert_new: ConnFromV21 = old.into();
        let new = bincode::serialize(&convert_new)?;
        store.append(&key, &new)?;
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
    };
    use semver::{Version, VersionReq};

    use super::COMPATIBLE_VERSION_REQ;
    use crate::storage::{
        migration::migration_structures::{
            ConnBeforeV21A1, ConnFromV21A1BeforeV21A2, HttpFromV12BeforeV21, NtlmBeforeV21,
            SmtpBeforeV21, SshBeforeV21, TlsBeforeV21,
        },
        Conn as ConnFromV21, Database, DbOptions, Http as HttpFromV21, Ntlm as NtlmFromV21,
        Smtp as SmtpFromV21, Ssh as SshFromV21, StorageKey, Tls as TlsFromV21,
    };

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

    #[test]
    fn migrate_0_19_to_0_21_0_alpha_1() {
        // open temp db & store
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let conn_store = db.conn_store().unwrap();
        let http_store = db.http_store().unwrap();
        let smtp_store = db.smtp_store().unwrap();
        let ntlm_store = db.ntlm_store().unwrap();
        let ssh_store = db.ssh_store().unwrap();
        let tls_store = db.tls_store().unwrap();

        // generate key
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        let source = "src1";
        let mut key = Vec::with_capacity(source.len() + 1 + std::mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        // insert old conn raw data
        let old_conn = ConnBeforeV21A1 {
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
        conn_store.append(&key, &ser_old_conn).unwrap();

        // insert old http raw data
        let old_http = HttpFromV12BeforeV21 {
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
        let ser_old_http = bincode::serialize(&old_http).unwrap();
        http_store.append(&key, &ser_old_http).unwrap();

        // insert old smtp raw data
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
        smtp_store.append(&key, &ser_old_smtp).unwrap();

        // insert old ntlm raw data
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
        ntlm_store.append(&key, &ser_old_ntlm).unwrap();

        // insert old ssh raw data
        let old_ssh = SshBeforeV21 {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            version: 01,
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
        ssh_store.append(&key, &ser_old_ssh).unwrap();

        // insert old tls raw data
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
        tls_store.append(&key, &ser_old_tls).unwrap();

        //migration 0.19.0 to 0.21.0-alpha.1
        super::migrate_0_19_to_0_21_0_alpha_1(&db).unwrap();

        //check conn migration
        let raw_event = conn_store.iter_forward().next().unwrap();
        let (_, val) = raw_event.expect("Failed to read Database");
        let store_conn = bincode::deserialize::<ConnFromV21A1BeforeV21A2>(&val).unwrap();
        let new_conn = ConnFromV21A1BeforeV21A2 {
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
        };
        assert_eq!(new_conn, store_conn);

        //check http migration
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
            post_body: Vec::new(),
            state: String::new(),
        };
        assert_eq!(new_http, store_http);

        //check smtp migration
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

        //check ntlm migration
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

        //check ssh migration
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

        //check tls migration
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
    fn migrate_0_21_0_alpha_1_to_0_21_0_alpha_2() {
        // open temp db & store
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let conn_store = db.conn_store().unwrap();

        // generate key
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        let source = "src1";
        let mut key = Vec::with_capacity(source.len() + 1 + std::mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        // insert old conn raw data
        let old_conn = ConnFromV21A1BeforeV21A2 {
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
        };
        let ser_old_conn = bincode::serialize(&old_conn).unwrap();
        conn_store.append(&key, &ser_old_conn).unwrap();

        //migration 0.21.0-alpha.1 to 0.21.0-alpha.2
        super::migrate_0_21_0_alpha_1_to_0_21_0_alpha_2(&db).unwrap();

        //check conn migration
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
            resp_l2_bytes: 0,
            orig_l2_bytes: 0,
        };
        assert_eq!(new_conn, store_conn);
    }
}
