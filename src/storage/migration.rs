//! Routines to check the database format version and migrate it if necessary.

use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::Path,
};

use anyhow::{bail, Context, Result};

/// Migrates the data directory to the up-to-date format if necessary.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format too old to be upgraded.
pub fn migrate_data_dir(data_dir: &Path) -> Result<()> {
    let version_path = data_dir.join("VERSION");
    if data_dir.exists() {
        if !data_dir
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
            return create_version_file(&version_path);
        }
    } else {
        create_dir_all(data_dir)?;
        return create_version_file(&version_path);
    }

    let mut ver = String::new();
    File::open(&version_path)
        .context("cannot open VERSION")?
        .read_to_string(&mut ver)
        .context("cannot read VERSION")?;
    match ver.trim() {
        env!("CARGO_PKG_VERSION") => Ok(()),
        _ => bail!(
            "incompatible version {:?}, require {:?}",
            ver,
            env!("CARGO_PKG_VERSION")
        ),
    }
}

fn create_version_file(path: &Path) -> Result<()> {
    let mut f = File::create(path).context("cannot create VERSION")?;
    f.write_all(env!("CARGO_PKG_VERSION").as_bytes())
        .context("cannot write VERSION")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::migrate_data_dir;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn db_verion_create() {
        let data_dir = tempfile::tempdir().unwrap();
        assert!(migrate_data_dir(&data_dir.path()).is_ok())
    }

    #[test]
    fn db_verion_ok() {
        let data_dir = tempfile::tempdir().unwrap();
        let file_path = data_dir.path().join("VERSION");
        let mut file = File::create(file_path).unwrap();
        writeln!(file, env!("CARGO_PKG_VERSION")).unwrap();
        assert!(migrate_data_dir(&data_dir.path()).is_ok())
    }

    #[test]
    fn db_verion_fail() {
        let data_dir = tempfile::tempdir().unwrap();
        let file_path = data_dir.path().join("VERSION");
        let mut file = File::create(file_path).unwrap();
        writeln!(file, "11.11.11").unwrap();
        assert!(migrate_data_dir(&data_dir.path()).is_err())
    }
}
