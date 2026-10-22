//! Start-up output of the real binary, under the systemd journal and outside
//! it.
//!
//! Each case runs the binary Cargo builds as a child with its standard output
//! redirected to a file, and either sets `JOURNAL_STREAM` to that file's
//! `<dev>:<ino>` ("under the journal") or removes it ("plain"). Every case ends
//! before certificates are read, so the certificate arguments name nothing.

// `JOURNAL_STREAM` names a file by its Unix device and inode.
#![cfg(unix)]

use std::{
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, ExitStatus, Stdio},
};

use tempfile::TempDir;

const LOG_PATH_REMOVED: &str =
    "--log-path was removed; logs go to standard output (the journal under systemd)";
const PRIORITIES: [&str; 4] = ["<3>", "<4>", "<6>", "<7>"];

/// Whether the child's standard output is the journal.
#[derive(Clone, Copy)]
enum Output {
    Journal,
    Plain,
}

/// What a child wrote, and how it exited.
struct Run {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl Run {
    fn lines(&self) -> Vec<&str> {
        self.stdout.lines().collect()
    }

    /// Returns the stdout lines starting with `priority` and holding `needle`.
    fn lines_with(&self, priority: &str, needle: &str) -> Vec<&str> {
        self.stdout
            .lines()
            .filter(|line| line.starts_with(priority) && line.contains(needle))
            .collect()
    }

    fn assert_every_line_prefixed(&self) {
        for line in self.lines() {
            assert!(
                PRIORITIES.iter().any(|priority| line.starts_with(priority)),
                "{line:?} starts with a priority\n{}",
                self.diagnostics()
            );
            assert!(!line.contains('\x1b'), "{line:?} holds no ESC byte");
        }
    }

    fn diagnostics(&self) -> String {
        format!(
            "status: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.status, self.stdout, self.stderr
        )
    }
}

/// Runs the binary in `dir` with `args`, its standard output a file in `dir`.
fn run(dir: &Path, output: Output, args: &[&str]) -> Run {
    let stdout_path = dir.join("stdout");
    let stdout = File::create(&stdout_path).expect("create the stdout capture");
    let metadata = stdout
        .metadata()
        .expect("read the stdout capture's metadata");

    let mut command = Command::new(env!("CARGO_BIN_EXE_giganto"));
    command
        .current_dir(dir)
        .args(args)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped());
    match output {
        Output::Journal => {
            command.env(
                "JOURNAL_STREAM",
                format!("{}:{}", metadata.dev(), metadata.ino()),
            );
        }
        Output::Plain => {
            command.env_remove("JOURNAL_STREAM");
        }
    }
    let child = command.output().expect("run the giganto binary");
    Run {
        status: child.status,
        stdout: fs::read_to_string(&stdout_path).expect("read the stdout capture"),
        stderr: String::from_utf8_lossy(&child.stderr).into_owned(),
    }
}

fn tempdir() -> TempDir {
    tempfile::tempdir().expect("create a temporary directory")
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("temporary paths are UTF-8")
}

/// Writes a configuration whose `data_dir` is `data_dir`, and returns its path.
fn write_config(dir: &Path, data_dir: &Path) -> String {
    let config = dir.join("config.toml");
    fs::write(&config, format!("data_dir = {:?}\n", path_str(data_dir)))
        .expect("write the configuration");
    path_str(&config).to_owned()
}

/// The arguments for the configuration `config`, with throwaway certificate
/// paths.
fn args_with<'a>(config: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["-c", config, "--cert", "c", "--key", "k", "--ca-certs", "a"];
    args.extend_from_slice(extra);
    args
}

#[test]
fn log_path_is_refused_plain() {
    let dir = tempdir();
    let config = path_str(&dir.path().join("config.toml")).to_owned();
    let log = dir.path().join("x.log");
    let run = run(
        dir.path(),
        Output::Plain,
        &args_with(&config, &["--log-path", path_str(&log)]),
    );
    assert_eq!(run.status.code(), Some(1), "{}", run.diagnostics());
    assert!(
        run.stderr.contains(&format!("Error: {LOG_PATH_REMOVED}")),
        "{}",
        run.diagnostics()
    );
    assert!(!log.exists(), "no log file is created");
}

#[test]
fn log_path_is_refused_under_the_journal() {
    let dir = tempdir();
    let config = path_str(&dir.path().join("config.toml")).to_owned();
    let log = dir.path().join("x.log");
    let run = run(
        dir.path(),
        Output::Journal,
        &args_with(&config, &["--log-path", path_str(&log)]),
    );
    assert_eq!(run.status.code(), Some(1), "{}", run.diagnostics());
    assert_eq!(
        run.lines_with("<3>", LOG_PATH_REMOVED).len(),
        1,
        "{}",
        run.diagnostics()
    );
    assert_eq!(run.lines().len(), 1, "{}", run.diagnostics());
    run.assert_every_line_prefixed();
    assert_eq!(run.stderr, "", "{}", run.diagnostics());
    assert!(!log.exists(), "no log file is created");
}

#[test]
fn log_path_is_refused_before_repair() {
    let dir = tempdir();
    let data_dir = dir.path().join("data");
    fs::create_dir(&data_dir).expect("create the data directory");
    let config = write_config(dir.path(), &data_dir);
    let log = dir.path().join("x.log");
    let run = run(
        dir.path(),
        Output::Journal,
        &args_with(&config, &["--repair", "--log-path", path_str(&log)]),
    );
    assert_eq!(run.status.code(), Some(1), "{}", run.diagnostics());
    assert_eq!(run.lines().len(), 1, "{}", run.diagnostics());
    assert_eq!(run.lines_with("<3>", LOG_PATH_REMOVED).len(), 1);
}

#[test]
fn log_path_without_a_value_is_a_usage_error() {
    let dir = tempdir();
    let config = path_str(&dir.path().join("config.toml")).to_owned();
    for log_path in ["--log-path", "--log-path="] {
        let run = run(
            dir.path(),
            Output::Journal,
            &args_with(&config, &[log_path]),
        );
        assert_eq!(run.status.code(), Some(2), "{}", run.diagnostics());
        assert_eq!(run.lines_with("<3>", "--log-path").len(), 1);
        assert!(
            !run.stdout.contains(LOG_PATH_REMOVED),
            "{}",
            run.diagnostics()
        );
        run.assert_every_line_prefixed();
        assert_eq!(run.stderr, "", "{}", run.diagnostics());
    }
}

#[test]
fn an_unreadable_configuration_is_logged_under_the_journal() {
    let dir = tempdir();
    let missing = path_str(&dir.path().join("missing.toml")).to_owned();
    let run = run(dir.path(), Output::Journal, &args_with(&missing, &[]));
    assert_eq!(run.status.code(), Some(1), "{}", run.diagnostics());
    assert_eq!(
        run.lines_with("<4>", "failed to read configuration file")
            .len(),
        1,
        "{}",
        run.diagnostics()
    );
    assert_eq!(
        run.lines_with(
            "<3>",
            "no valid configuration file available, and no backup found."
        )
        .len(),
        1,
        "{}",
        run.diagnostics()
    );
    run.assert_every_line_prefixed();
    assert_eq!(run.stderr, "", "{}", run.diagnostics());
}

#[test]
fn an_unreadable_configuration_is_logged_plain() {
    let dir = tempdir();
    let missing = path_str(&dir.path().join("missing.toml")).to_owned();
    let run = run(dir.path(), Output::Plain, &args_with(&missing, &[]));
    assert_eq!(run.status.code(), Some(1), "{}", run.diagnostics());
    let warning = run
        .lines()
        .into_iter()
        .find(|line| line.contains("failed to read configuration file"))
        .unwrap_or_else(|| panic!("the read failure is logged\n{}", run.diagnostics()));
    assert!(warning.contains("WARN"), "{}", run.diagnostics());
    for line in run.lines() {
        assert!(!line.starts_with('<'), "{line:?} has no priority prefix");
        assert!(!line.contains('\x1b'), "{line:?} holds no ESC byte");
    }
    assert!(
        run.stderr
            .contains("Error: no valid configuration file available, and no backup found."),
        "{}",
        run.diagnostics()
    );
}

#[test]
fn an_invalid_configuration_is_logged_under_the_journal() {
    let dir = tempdir();
    let config = write_config(dir.path(), &dir.path().join("missing-dir"));
    let run = run(dir.path(), Output::Journal, &args_with(&config, &[]));
    assert_eq!(run.status.code(), Some(1), "{}", run.diagnostics());
    assert_eq!(
        run.lines_with("<3>", "data directory is invalid").len(),
        1,
        "{}",
        run.diagnostics()
    );
    run.assert_every_line_prefixed();
    assert_eq!(run.stderr, "", "{}", run.diagnostics());
}

#[test]
fn a_command_line_error_is_one_error_line_under_the_journal() {
    let dir = tempdir();
    let run = run(dir.path(), Output::Journal, &["-c", "x"]);
    assert_eq!(run.status.code(), Some(2), "{}", run.diagnostics());
    assert_eq!(run.lines().len(), 1, "{}", run.diagnostics());
    assert_eq!(
        run.lines_with("<3>", "--cert").len(),
        1,
        "{}",
        run.diagnostics()
    );
    assert_eq!(run.stderr, "", "{}", run.diagnostics());
}

#[test]
fn a_command_line_error_is_printed_by_clap_plain() {
    let dir = tempdir();
    let run = run(dir.path(), Output::Plain, &["-c", "x"]);
    assert_eq!(run.status.code(), Some(2), "{}", run.diagnostics());
    assert!(run.stderr.contains("--cert"), "{}", run.diagnostics());
    assert!(run.stderr.contains("Usage:"), "{}", run.diagnostics());
}

#[test]
fn help_is_printed_unprefixed_under_the_journal() {
    let dir = tempdir();
    let run = run(dir.path(), Output::Journal, &["--help"]);
    assert_eq!(run.status.code(), Some(0), "{}", run.diagnostics());
    assert!(run.stdout.contains("Usage:"), "{}", run.diagnostics());
    assert!(!run.stdout.contains("--log-path"), "{}", run.diagnostics());
}

#[test]
fn repair_writes_its_events_under_the_journal() {
    let dir = tempdir();
    let data_dir = dir.path().join("data");
    fs::create_dir(&data_dir).expect("create the data directory");
    let config = write_config(dir.path(), &data_dir);
    let run = run(
        dir.path(),
        Output::Journal,
        &args_with(&config, &["--repair"]),
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.diagnostics());
    assert_eq!(
        run.lines_with("<6>", "Starting DB repair").len(),
        1,
        "{}",
        run.diagnostics()
    );
    assert_eq!(
        run.lines_with("<6>", "DB repair duration:").len(),
        1,
        "{}",
        run.diagnostics()
    );
}
