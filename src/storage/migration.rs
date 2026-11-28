//! Routines to check the format version of the data directory.
//!
//! No migration step exists: this release opens only data directories of its
//! own minor release. A later release that must keep opening an earlier one
//! adds its migration step to `migrate_data_dir`.

use std::{
    fs::{File, create_dir_all},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, anyhow};
use semver::{Version, VersionReq};

use super::DbOptions;
use crate::version_req::version_req;

// The `COMPATIBLE_VERSION_REQ` defines the data directory format versions this release opens.
// Its lower bound follows the crate's minor release, so a release refuses data directories of
// earlier minor releases. A later release that must keep opening an earlier one replaces the
// derived lower bound with a literal and adds a migration step to `migrate_data_dir`.
// The upper bound is derived too, so a release pull request needs no hand edit.
pub(crate) const COMPATIBLE_VERSION_REQ: &str = version_req!();

/// Checks the format version of the data directory.
///
/// Creates the data directory, and a `VERSION` file holding the crate version,
/// when either is absent. No migration step exists, so a data directory whose
/// version is outside `COMPATIBLE_VERSION_REQ` is refused and left unchanged.
/// `db_opts` is kept for the migration steps a later release may add.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// if its `VERSION` file cannot be created or read, or if its version is not
/// within `COMPATIBLE_VERSION_REQ`.
pub fn migrate_data_dir(data_dir: &Path, _db_opts: &DbOptions) -> Result<()> {
    let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid version requirement");
    let version = retrieve_or_create_version(data_dir)?;
    if compatible.matches(&version) {
        return Ok(());
    }
    Err(anyhow!(
        "data directory version {version} is not supported: this release opens only \
         {COMPATIBLE_VERSION_REQ} and migrates from no earlier version"
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

#[cfg(test)]
mod tests {
    use std::{fs, fs::File, io::Write, path::PathBuf};

    use semver::{Version, VersionReq};
    use tempfile::TempDir;

    use super::COMPATIBLE_VERSION_REQ;
    use crate::storage::{DbOptions, migrate_data_dir};
    use crate::version_req::previous_minor_version;

    fn mock_version_file(dir: &TempDir, version_content: &str) -> PathBuf {
        let version_path = dir.path().join("VERSION");
        let mut file = File::create(&version_path).expect("Failed to create VERSION file");
        file.write_all(version_content.as_bytes())
            .expect("Failed to write version");
        version_path
    }

    fn current_minor_version() -> Version {
        let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");
        Version::new(current.major, current.minor, 0)
    }

    #[test]
    fn version() {
        let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid semver");
        let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");

        // The crate version and the first release of its minor are compatible.
        assert!(compatible.matches(&current));
        assert!(compatible.matches(&current_minor_version()));

        // Earlier minor releases are not.
        assert!(!compatible.matches(&previous_minor_version()));
        assert!(!compatible.matches(&Version::new(0, 33, 0)));
    }

    #[test]
    fn migrate_data_dir_refuses_earlier_versions() {
        let previous_minor = previous_minor_version().to_string();
        for marker in ["0.13.0", "0.21.0", "0.33.0", previous_minor.as_str()] {
            let version_dir = tempfile::tempdir().unwrap();
            let version_path = mock_version_file(&version_dir, marker);
            let db_options = DbOptions::new(8000, 512, 8, 2, true);

            let err = migrate_data_dir(version_dir.path(), &db_options)
                .expect_err("an earlier data directory must be refused");

            assert_eq!(
                err.to_string(),
                format!(
                    "data directory version {marker} is not supported: this release opens only \
                     {COMPATIBLE_VERSION_REQ} and migrates from no earlier version"
                ),
            );
            assert_eq!(fs::read_to_string(&version_path).unwrap(), marker);
            assert!(!version_dir.path().join("db").exists());
            let entries: Vec<_> = fs::read_dir(version_dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(entries, ["VERSION"], "{marker}: nothing else is created");
        }
    }

    #[test]
    fn migrate_data_dir_opens_first_release_of_this_minor() {
        let version_dir = tempfile::tempdir().unwrap();
        let marker = current_minor_version().to_string();
        let version_path = mock_version_file(&version_dir, &marker);

        migrate_data_dir(version_dir.path(), &DbOptions::default())
            .expect("a data directory of this minor release must open");

        assert_eq!(fs::read_to_string(&version_path).unwrap(), marker);
        assert!(!version_dir.path().join("db").exists());
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

        // Should succeed without touching the database
        assert!(result.is_ok());

        // The version check alone must not open the database: opening it
        // would create the 'db' directory.
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
}
