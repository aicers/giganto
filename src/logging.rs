//! Log output: journal detection, the journal line writer, the panic hook and
//! the subscriber set-up.
//!
//! Giganto logs to standard output. Under systemd a unit's standard output and
//! standard error are streams into the journal, which stores each line as one
//! entry and takes a leading `<N>` as the entry's syslog priority
//! (`SyslogLevelPrefix=`, on by default); an unprefixed line is stored at
//! priority 6 whatever it says. When standard output or standard error is the
//! journal, each event is therefore written as one prefixed line, without the
//! timestamp the journal records itself and without colour codes. Elsewhere the
//! `fmt` output is written as it is.

use std::{
    any::Any,
    ffi::OsStr,
    io::{self, IsTerminal, Write},
    os::fd::AsFd,
    panic::{self, PanicHookInfo},
    thread,
};

use anyhow::{Context, Result};
use nix::sys::stat::fstat;
use tracing::{Level, Metadata, error, metadata::LevelFilter};
use tracing_appender::non_blocking::{
    DEFAULT_BUFFERED_LINES_LIMIT, ErrorCounter, NonBlockingBuilder, WorkerGuard,
};
use tracing_subscriber::{
    EnvFilter, Layer, Registry,
    fmt::{self, MakeWriter},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// Environment variable systemd sets to the `<dev>:<ino>` of the stream it
/// connects a unit's standard output or standard error to.
pub(crate) const JOURNAL_STREAM_ENV: &str = "JOURNAL_STREAM";

/// The error for a command line that names the removed `--log-path` option.
pub(crate) const LOG_PATH_REMOVED: &str =
    "--log-path was removed; logs go to standard output (the journal under systemd)";

/// Separates the device from the inode in `JOURNAL_STREAM`.
const JOURNAL_STREAM_SEPARATOR: char = ':';

/// What the panic hook reports as the name of a thread that has none, as the
/// standard library's default hook does.
const UNNAMED_THREAD: &str = "<unnamed>";

/// What the panic hook reports as the message of a panic whose payload is not
/// text, as the standard library's default hook does.
const OPAQUE_PANIC_PAYLOAD: &str = "Box<dyn Any>";

/// The device and inode of an open file, as `JOURNAL_STREAM` names them.
///
/// The device is widened to `i128` because `dev_t` is unsigned on Linux and
/// signed on macOS; both convert into it losslessly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileId {
    dev: i128,
    ino: u64,
}

impl FileId {
    /// Returns the identity of the file `fd` refers to, or `None` when it
    /// cannot be read, as for a closed descriptor.
    fn of(fd: impl AsFd) -> Option<Self> {
        let stat = fstat(fd).ok()?;
        Some(Self {
            dev: i128::from(stat.st_dev),
            ino: stat.st_ino,
        })
    }

    /// Parses `JOURNAL_STREAM`'s `<dev>:<ino>`, two decimal integers, or
    /// returns `None` when it is anything else.
    fn parse(value: &OsStr) -> Option<Self> {
        let (dev, ino) = value.to_str()?.split_once(JOURNAL_STREAM_SEPARATOR)?;
        Some(Self {
            dev: i128::from(decimal(dev)?),
            ino: decimal(ino)?,
        })
    }
}

/// Parses `text` as a decimal integer of ASCII digits alone, refusing the sign
/// `u64`'s own parser accepts.
fn decimal(text: &str) -> Option<u64> {
    if text.bytes().all(|byte| byte.is_ascii_digit()) {
        text.parse().ok()
    } else {
        None
    }
}

/// Returns whether standard output or standard error is the journal stream
/// `journal_stream` names.
///
/// `journal_stream` is what `JOURNAL_STREAM` holds, read by the caller, so
/// that a test states it instead of setting it on the process.
#[must_use]
pub(crate) fn output_is_journal(journal_stream: Option<&OsStr>) -> bool {
    matches_journal_stream(
        journal_stream,
        [FileId::of(io::stdout()), FileId::of(io::stderr())],
    )
}

/// Returns whether `journal_stream` parses as `<dev>:<ino>` and names the file
/// one of `descriptors` (standard output, then standard error) refers to.
///
/// A `JOURNAL_STREAM` that names neither is what a unit leaves behind when a
/// wrapper redirected its output to a file or a pipe, and is not the journal.
fn matches_journal_stream(
    journal_stream: Option<&OsStr>,
    descriptors: [Option<FileId>; 2],
) -> bool {
    journal_stream
        .and_then(FileId::parse)
        .is_some_and(|stream| descriptors.contains(&Some(stream)))
}

/// Initializes the tracing subscriber, which writes to standard output through
/// a non-blocking writer, and returns its guard and rejected-event counter.
///
/// With `journal`, each event is written as one journal line without a
/// timestamp or ANSI codes, and the panic hook is replaced by one that logs a
/// panic as one error event. Otherwise ANSI codes are written only when
/// standard output is a terminal. INFO is the default level, and `RUST_LOG`
/// overrides it.
///
/// The guard must be held for as long as logging is expected to work, and
/// dropped before the process exits. Shutdown is best-effort with internal
/// timeouts: queued writes might not complete after a timeout. Events may also
/// be dropped while running when the queue is full. Blocked stdout can block
/// exit, including the direct exit writes.
///
/// # Errors
///
/// Returns an error if a global subscriber has already been set.
pub(crate) fn init_tracing(journal: bool) -> Result<Logging> {
    init_tracing_to(journal, io::stdout(), DEFAULT_BUFFERED_LINES_LIMIT)
}

/// The worker lifetime and count of events rejected by its queue.
pub(crate) struct Logging {
    pub(crate) guard: WorkerGuard,
    pub(crate) counter: ErrorCounter,
}

/// Initializes tracing with a caller-provided worker writer and queue limit.
///
/// # Errors
///
/// Returns an error if a global subscriber has already been set.
pub(crate) fn init_tracing_to(
    journal: bool,
    writer: impl Write + Send + 'static,
    buffer_limit: usize,
) -> Result<Logging> {
    let (writer, guard) = NonBlockingBuilder::default()
        .buffered_lines_limit(buffer_limit)
        .finish(writer);
    let counter = writer.error_counter();
    let layer: Box<dyn Layer<Registry> + Send + Sync> = if journal {
        fmt::Layer::default()
            .without_time()
            .with_ansi(false)
            .with_writer(JournalWriter::new(writer))
            .boxed()
    } else {
        fmt::Layer::default()
            .with_ansi(io::stdout().is_terminal())
            .with_writer(writer)
            .boxed()
    };
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(layer.with_filter(filter))
        .try_init()
        .context("failed to install the tracing subscriber")?;
    if journal {
        panic::set_hook(Box::new(log_panic));
    }
    Ok(Logging { guard, counter })
}

/// Attempts worker shutdown, then directly writes the final journal error and
/// any queue-rejection count. Output errors do not affect the caller's status.
pub(crate) fn finish_logging(
    guard: WorkerGuard,
    counter: &ErrorCounter,
    journal: bool,
    mut direct: impl Write,
    final_error: Option<&str>,
) {
    drop(guard);
    if let Some(message) = final_error.filter(|_| journal) {
        write_exit_line(&mut direct, Level::ERROR, true, message);
    }
    let dropped = counter.dropped_lines();
    if dropped > 0 {
        write_exit_line(
            &mut direct,
            Level::WARN,
            journal,
            &format!("log events dropped because the output queue was full or closed: {dropped}"),
        );
    }
}

fn write_exit_line(direct: &mut impl Write, level: Level, journal: bool, message: &str) {
    const TARGET: &str = "giganto";
    let event = format!("{:>5} {TARGET}: {message}\n", level.as_str());
    let line = if journal {
        journal_line(level, event.as_bytes())
    } else {
        event.into_bytes()
    };
    let _ = direct.write_all(&line);
    let _ = direct.flush();
}

/// Returns the syslog priority prefix the journal stores an event at `level`
/// with.
fn priority(level: Level) -> &'static str {
    match level {
        Level::ERROR => "<3>",
        Level::WARN => "<4>",
        Level::INFO => "<6>",
        Level::DEBUG | Level::TRACE => "<7>",
    }
}

/// Renders one formatted `event` as the single journal line for `level`: its
/// priority prefix, the event without its final line feed with every line feed
/// and NUL inside it written as `\n` and `\0`, and one line feed.
fn journal_line(level: Level, event: &[u8]) -> Vec<u8> {
    let event = event.strip_suffix(b"\n").unwrap_or(event);
    let priority = priority(level);
    let mut line = Vec::with_capacity(priority.len() + event.len() + 1);
    line.extend_from_slice(priority.as_bytes());
    for &byte in event {
        match byte {
            b'\n' => line.extend_from_slice(b"\\n"),
            0 => line.extend_from_slice(b"\\0"),
            byte => line.push(byte),
        }
    }
    line.push(b'\n');
    line
}

/// A [`MakeWriter`] that writes each event `inner` would write as one journal
/// line.
struct JournalWriter<M> {
    inner: M,
}

impl<M> JournalWriter<M> {
    fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for JournalWriter<M> {
    type Writer = JournalLine<M::Writer>;

    /// Writes at INFO's priority: `fmt` asks for a writer with the event's
    /// metadata, so this is only what a caller without one gets.
    fn make_writer(&'a self) -> Self::Writer {
        JournalLine::new(self.inner.make_writer(), Level::INFO)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        JournalLine::new(self.inner.make_writer_for(meta), *meta.level())
    }
}

/// One event on its way to the journal: buffered as `fmt` writes it, and
/// written to the inner writer as one line, in one write, when dropped.
struct JournalLine<W: Write> {
    inner: W,
    level: Level,
    event: Vec<u8>,
}

impl<W: Write> JournalLine<W> {
    fn new(inner: W, level: Level) -> Self {
        Self {
            inner,
            level,
            event: Vec::new(),
        }
    }
}

impl<W: Write> Write for JournalLine<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.event.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Writes nothing: a part of the event flushed on its own would become an
    /// entry of its own.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W: Write> Drop for JournalLine<W> {
    fn drop(&mut self) {
        if self.event.is_empty() {
            return;
        }
        // A log line that cannot be written has nowhere left to be reported.
        let _ = self.inner.write_all(&journal_line(self.level, &self.event));
    }
}

/// Logs the panic `info` describes as one ERROR event naming its message, where
/// it happened and the thread it happened on, in the text the standard
/// library's default hook writes. It writes nothing else.
fn log_panic(info: &PanicHookInfo<'_>) {
    let thread = thread::current();
    let name = thread.name().unwrap_or(UNNAMED_THREAD);
    let message = panic_message(info.payload());
    // `Location` displays as `file:line:column`.
    let at = info
        .location()
        .map_or_else(String::new, |location| format!(" at {location}"));
    error!("thread '{name}' panicked{at}: {message}");
}

/// Returns the text a panic was raised with, or a placeholder when its payload
/// is not text.
fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or(OPAQUE_PANIC_PAYLOAD)
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        ffi::OsStr,
        fs::{self, File},
        io::{self, Write},
        os::unix::fs::MetadataExt,
        process::{Command, Stdio},
        sync::{Arc, Mutex, mpsc},
        thread,
        time::{Duration, Instant},
    };

    use tracing::{Level, debug, error, info, warn};
    use tracing_subscriber::fmt::MakeWriter;

    use super::{
        FileId, JOURNAL_STREAM_ENV, JournalLine, JournalWriter, Logging, finish_logging,
        init_tracing, init_tracing_to, journal_line, matches_journal_stream, output_is_journal,
        panic_message, write_exit_line,
    };

    /// Marks the child process that sets up logging and runs a test body.
    const CHILD_PROCESS_ENV: &str = "GIGANTO_LOGGING_TEST_CHILD";
    const RUST_LOG: &str = "RUST_LOG";
    const PANIC_THREAD: &str = "journal-panic";
    const PANIC_MESSAGE: &str = "journal panic message";
    const PRIORITIES: [&str; 4] = ["<3>", "<4>", "<6>", "<7>"];

    const STDOUT: FileId = FileId { dev: 12, ino: 34 };
    const STDERR: FileId = FileId { dev: 56, ino: 78 };

    fn matches(journal_stream: Option<&str>, descriptors: [Option<FileId>; 2]) -> bool {
        matches_journal_stream(journal_stream.map(OsStr::new), descriptors)
    }

    #[test]
    fn a_journal_stream_naming_stdout_is_the_journal() {
        assert!(matches(Some("12:34"), [Some(STDOUT), Some(STDERR)]));
        assert!(matches(Some("12:34"), [Some(STDOUT), None]));
    }

    #[test]
    fn a_journal_stream_naming_only_stderr_is_the_journal() {
        assert!(matches(Some("56:78"), [Some(STDOUT), Some(STDERR)]));
        assert!(matches(Some("56:78"), [None, Some(STDERR)]));
    }

    #[test]
    fn a_journal_stream_naming_neither_descriptor_is_not_the_journal() {
        for value in ["12:78", "56:34", "0:0"] {
            assert!(
                !matches(Some(value), [Some(STDOUT), Some(STDERR)]),
                "{value}"
            );
        }
        assert!(!matches(Some("12:34"), [None, None]));
    }

    #[test]
    fn a_malformed_journal_stream_is_not_the_journal() {
        // Each would name stdout `12:34` if it were read leniently.
        let descriptors = [Some(STDOUT), Some(FileId { dev: 12, ino: 0 })];
        for value in [
            "12", "a:b", "1:2:3", "12:34:", "12:", ":34", "", "+12:34", "-12:34", " 12:34",
            "12:34 ", "12: 34",
        ] {
            assert!(!matches(Some(value), descriptors), "{value:?}");
        }
    }

    #[test]
    fn an_unset_journal_stream_is_not_the_journal() {
        assert!(!matches(None, [Some(STDOUT), Some(STDERR)]));
    }

    #[test]
    fn each_level_takes_its_priority() {
        for (level, prefix) in [
            (Level::ERROR, "<3>"),
            (Level::WARN, "<4>"),
            (Level::INFO, "<6>"),
            (Level::DEBUG, "<7>"),
            (Level::TRACE, "<7>"),
        ] {
            assert_eq!(
                journal_line(level, b"event\n"),
                format!("{prefix}event\n").into_bytes()
            );
        }
    }

    #[test]
    fn line_feeds_and_nuls_are_escaped_and_backslashes_kept() {
        assert_eq!(
            journal_line(Level::INFO, b"a\nb\0c\\d\n"),
            b"<6>a\\nb\\0c\\d\n".to_vec()
        );
        assert_eq!(
            journal_line(Level::INFO, b"a\rb\\n\n"),
            b"<6>a\rb\\n\n".to_vec()
        );
    }

    #[test]
    fn only_the_final_line_feed_ends_the_line() {
        assert_eq!(journal_line(Level::WARN, b"a\n\n"), b"<4>a\\n\n".to_vec());
        assert_eq!(journal_line(Level::WARN, b"a"), b"<4>a\n".to_vec());
    }

    /// A writer that records each write it is given separately.
    #[derive(Default)]
    struct Writes(Vec<Vec<u8>>);

    impl Write for &mut Writes {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_event_written_in_parts_is_one_write() {
        let mut writes = Writes::default();
        {
            let mut line = JournalLine::new(&mut writes, Level::ERROR);
            line.write_all(b"first\n").unwrap();
            line.flush().unwrap();
            line.write_all(b"second\n").unwrap();
        }
        assert_eq!(writes.0, vec![b"<3>first\\nsecond\n".to_vec()]);
    }

    #[test]
    fn an_event_with_nothing_written_writes_nothing() {
        let mut writes = Writes::default();
        drop(JournalLine::new(&mut writes, Level::ERROR));
        assert!(writes.0.is_empty(), "{:?}", writes.0);
    }

    #[test]
    fn a_writer_made_without_metadata_writes_at_info() {
        let writer = JournalWriter::new(Mutex::new(Vec::new()));
        writer.make_writer().write_all(b"event\n").unwrap();
        assert_eq!(*writer.inner.lock().unwrap(), b"<6>event\n".to_vec());
    }

    #[test]
    fn a_panic_message_is_read_from_text_payloads() {
        let borrowed: Box<dyn std::any::Any + Send> = Box::new("borrowed");
        let owned: Box<dyn std::any::Any + Send> = Box::new(String::from("owned"));
        let opaque: Box<dyn std::any::Any + Send> = Box::new(7_u8);
        assert_eq!(panic_message(borrowed.as_ref()), "borrowed");
        assert_eq!(panic_message(owned.as_ref()), "owned");
        assert_eq!(panic_message(opaque.as_ref()), "Box<dyn Any>");
    }

    // -----------------------------------------------------------------------
    // Child-process tests: the subscriber and the panic hook are process-wide,
    // so each body runs alone in a re-run of this test binary.
    // -----------------------------------------------------------------------

    /// How the child's `JOURNAL_STREAM` is set.
    enum Journal {
        /// The `<dev>:<ino>` of the child's standard output.
        Matching,
        /// A value that matches neither descriptor.
        Mismatching,
        Unset,
    }

    /// What a child test wrote.
    struct ChildOutput {
        /// The lines on standard output, without libtest's own.
        log_lines: Vec<String>,
        stderr: String,
    }

    /// Returns the libtest name of the test `name` in this module.
    fn test_name(name: &str) -> String {
        let module = module_path!()
            .strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))
            .expect("module path starts with the crate name");
        format!("{module}::{name}")
    }

    /// Returns whether `line` is one libtest writes around a single test.
    fn is_libtest_line(line: &str) -> bool {
        line.is_empty()
            || line == "running 1 test"
            || line.starts_with("test result: ")
            || (line.starts_with("test ") && line.ends_with(" ... ok"))
    }

    /// Runs the test `name` alone in a child process whose standard output is
    /// a file, and returns what it wrote after asserting that it passed.
    ///
    /// libtest reports a filter that matched nothing as a success, so the
    /// child's summary must also show that exactly one test ran. More than one
    /// test thread keeps libtest from writing the test name before the test
    /// runs, on the line its first event would continue.
    fn run_in_child_process(name: &str, journal: &Journal, rust_log: Option<&str>) -> ChildOutput {
        let dir = tempfile::tempdir().expect("create output directory");
        let stdout_path = dir.path().join("stdout");
        let stdout = File::create(&stdout_path).expect("create stdout file");
        let stderr_path = dir.path().join("stderr");
        let stderr = File::create(&stderr_path).expect("create stderr file");
        let metadata = stdout.metadata().expect("read stdout file metadata");

        let mut command = Command::new(env::current_exe().expect("locate test binary"));
        command
            .args([&test_name(name), "--exact", "--test-threads=2"])
            .env(CHILD_PROCESS_ENV, "1")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        match journal {
            Journal::Matching => {
                command.env(
                    JOURNAL_STREAM_ENV,
                    format!("{}:{}", metadata.dev(), metadata.ino()),
                );
            }
            Journal::Mismatching => {
                command.env(
                    JOURNAL_STREAM_ENV,
                    // Both captures are files in the same directory, so a
                    // different device matches neither, even if their inodes
                    // happen to be consecutive.
                    format!("{}:{}", metadata.dev().wrapping_add(1), metadata.ino()),
                );
            }
            Journal::Unset => {
                command.env_remove(JOURNAL_STREAM_ENV);
            }
        }
        match rust_log {
            Some(value) => command.env(RUST_LOG, value),
            None => command.env_remove(RUST_LOG),
        };
        let mut child = command.spawn().expect("spawn test in child process");
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out child");
                child.wait().expect("reap timed-out child");
                let stderr = fs::read_to_string(&stderr_path).expect("read child stderr");
                panic!("child test {name} exceeded 30 seconds: {stderr}");
            }
            // Polling a subprocess has no notification handle in std.
            thread::sleep(Duration::from_millis(10));
        };

        let stdout = fs::read_to_string(&stdout_path).expect("read child stdout");
        let stderr = fs::read_to_string(&stderr_path).expect("read child stderr");
        assert!(
            status.success() && stdout.contains("test result: ok. 1 passed"),
            "child test {name} failed ({status})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
        ChildOutput {
            log_lines: stdout
                .lines()
                .filter(|line| !is_libtest_line(line))
                .map(str::to_owned)
                .collect(),
            stderr,
        }
    }

    /// Sets logging up in the child as `main` does, returning the guard the
    /// child drops before it returns.
    fn init_child_logging() -> Logging {
        init_tracing(output_is_journal(
            env::var_os(JOURNAL_STREAM_ENV).as_deref(),
        ))
        .expect("initialize tracing")
    }

    fn is_child() -> bool {
        env::var_os(CHILD_PROCESS_ENV).is_some()
    }

    /// Returns the line holding `needle`, asserting that exactly one does.
    fn only_line_with<'a>(lines: &'a [String], needle: &str) -> &'a str {
        let matching: Vec<_> = lines.iter().filter(|line| line.contains(needle)).collect();
        assert_eq!(matching.len(), 1, "one line holds {needle:?}: {lines:#?}");
        matching[0]
    }

    /// Asserts that `line` starts with `priority`, followed by `level` after
    /// at most `fmt`'s padding, so without a timestamp.
    fn assert_journal_line(line: &str, priority: &str, level: &str) {
        let rest = line
            .strip_prefix(priority)
            .unwrap_or_else(|| panic!("{line:?} starts with {priority}"));
        assert!(
            rest.trim_start_matches(' ').starts_with(level),
            "{line:?} has no timestamp before {level}"
        );
    }

    fn assert_no_line_has(lines: &[String], needle: &str) {
        assert!(
            !lines.iter().any(|line| line.contains(needle)),
            "no line holds {needle:?}: {lines:#?}"
        );
    }

    #[derive(Clone, Default)]
    struct SharedOutput(Arc<Mutex<Vec<u8>>>);

    impl SharedOutput {
        fn snapshot(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    impl Write for SharedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct GatedWriter {
        output: SharedOutput,
        started: mpsc::Sender<()>,
        gate: Option<mpsc::Receiver<()>>,
    }

    impl Write for GatedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(gate) = self.gate.take() {
                self.started.send(()).unwrap();
                // Wait before taking the shared buffer lock, leaving direct
                // writes free to proceed while the worker is blocked.
                gate.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            self.output.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.output.flush()
        }
    }

    fn blocked_shutdown(journal: bool, overflow: bool) {
        let output = SharedOutput::default();
        let (started_tx, started_rx) = mpsc::channel();
        let (gate_tx, gate_rx) = mpsc::channel();
        let logging = init_tracing_to(
            journal,
            GatedWriter {
                output: output.clone(),
                started: started_tx,
                gate: Some(gate_rx),
            },
            4,
        )
        .unwrap();
        info!(target: "giganto", "blocked event");
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        if overflow {
            for n in 0..7 {
                info!(target: "giganto", "queued event {n}");
            }
            assert_eq!(logging.counter.dropped_lines(), 3);
        }
        finish_logging(
            logging.guard,
            &logging.counter,
            journal,
            output.clone(),
            if overflow {
                None
            } else {
                Some("final failure")
            },
        );
        assert_eq!(
            logging.counter.dropped_lines(),
            if overflow { 3 } else { 0 }
        );
        let expected = if overflow {
            format!(
                "{} WARN giganto: log events dropped because the output queue was full or closed: 3\n",
                if journal { "<4>" } else { "" }
            )
        } else {
            "<3>ERROR giganto: final failure\n".to_owned()
        };
        assert_eq!(output.snapshot(), expected.as_bytes());
        gate_tx.send(()).unwrap();
    }

    #[test]
    fn final_error_bypasses_blocked_worker() {
        if is_child() {
            blocked_shutdown(true, false);
            return;
        }
        run_in_child_process("final_error_bypasses_blocked_worker", &Journal::Unset, None);
    }

    #[test]
    fn full_queue_reports_exact_journal_count() {
        if is_child() {
            blocked_shutdown(true, true);
            return;
        }
        run_in_child_process(
            "full_queue_reports_exact_journal_count",
            &Journal::Unset,
            None,
        );
    }

    #[test]
    fn full_queue_reports_exact_plain_count() {
        if is_child() {
            blocked_shutdown(false, true);
            return;
        }
        run_in_child_process(
            "full_queue_reports_exact_plain_count",
            &Journal::Unset,
            None,
        );
    }

    #[test]
    fn zero_dropped_has_no_warning() {
        if is_child() {
            let output = SharedOutput::default();
            let (started_tx, started_rx) = mpsc::channel();
            let (gate_tx, gate_rx) = mpsc::channel();
            gate_tx.send(()).unwrap();
            let logging = init_tracing_to(
                true,
                GatedWriter {
                    output: output.clone(),
                    started: started_tx,
                    gate: Some(gate_rx),
                },
                4,
            )
            .unwrap();
            for n in 0..3 {
                info!(target: "giganto", "event {n}");
            }
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            finish_logging(logging.guard, &logging.counter, true, output.clone(), None);
            assert_eq!(logging.counter.dropped_lines(), 0);
            assert_eq!(output.snapshot(),
                b"<6> INFO giganto: event 0\n<6> INFO giganto: event 1\n<6> INFO giganto: event 2\n");
            return;
        }
        run_in_child_process("zero_dropped_has_no_warning", &Journal::Unset, None);
    }

    #[test]
    fn final_error_bypasses_filter() {
        if is_child() {
            let output = SharedOutput::default();
            let logging = init_tracing_to(true, output.clone(), 4).unwrap();
            for _ in 0..8 {
                error!(target: "giganto", "filtered event");
            }
            finish_logging(
                logging.guard,
                &logging.counter,
                true,
                output.clone(),
                Some("final failure"),
            );
            assert_eq!(logging.counter.dropped_lines(), 0);
            assert_eq!(output.snapshot(), b"<3>ERROR giganto: final failure\n");
            return;
        }
        run_in_child_process("final_error_bypasses_filter", &Journal::Unset, Some("off"));
    }

    #[test]
    fn direct_error_escaping_and_warning_bytes() {
        let mut output = Vec::new();
        write_exit_line(&mut output, Level::ERROR, true, "a\nb\0c");
        assert_eq!(output, b"<3>ERROR giganto: a\\nb\\0c\n");
        for (journal, prefix) in [(true, "<4>"), (false, "")] {
            output.clear();
            write_exit_line(
                &mut output,
                Level::WARN,
                journal,
                "log events dropped because the output queue was full or closed: 3",
            );
            assert_eq!(output, format!("{prefix} WARN giganto: log events dropped because the output queue was full or closed: 3\n").as_bytes());
        }
    }

    #[test]
    fn direct_error_matches_fmt_layer() {
        if is_child() {
            let output = SharedOutput::default();
            let logging = init_tracing_to(true, output.clone(), 4).unwrap();
            error!(target: "giganto", "{}", "same\nline");
            finish_logging(logging.guard, &logging.counter, true, output.clone(), None);
            let mut direct = Vec::new();
            write_exit_line(&mut direct, Level::ERROR, true, "same\nline");
            assert_eq!(direct, b"<3>ERROR giganto: same\\nline\n");
            assert_eq!(output.snapshot(), direct);
            return;
        }
        run_in_child_process("direct_error_matches_fmt_layer", &Journal::Unset, None);
    }

    #[test]
    fn journal_lines_carry_the_priority_of_their_level() {
        if is_child() {
            let _guard = init_child_logging();
            error!("journal error event");
            warn!("journal warn event");
            info!("journal info event");
            debug!("journal debug event");
            return;
        }

        let output = run_in_child_process(
            "journal_lines_carry_the_priority_of_their_level",
            &Journal::Matching,
            Some("debug"),
        );
        let lines = &output.log_lines;
        for (needle, priority, level) in [
            ("journal error event", "<3>", "ERROR"),
            ("journal warn event", "<4>", "WARN"),
            ("journal info event", "<6>", "INFO"),
            ("journal debug event", "<7>", "DEBUG"),
        ] {
            assert_journal_line(only_line_with(lines, needle), priority, level);
        }
        for line in lines {
            assert!(!line.contains('\x1b'), "{line:?} holds no ESC byte");
            assert!(
                PRIORITIES.iter().any(|priority| line.starts_with(priority)),
                "{line:?} starts with a priority"
            );
        }
        assert_eq!(output.stderr, "");
    }

    #[test]
    fn journal_event_is_one_line_with_escapes() {
        if is_child() {
            let _guard = init_child_logging();
            info!("first\nsecond\0third\\fourth");
            return;
        }

        let output = run_in_child_process(
            "journal_event_is_one_line_with_escapes",
            &Journal::Matching,
            None,
        );
        let line = only_line_with(&output.log_lines, "first");
        assert_journal_line(line, "<6>", "INFO");
        assert!(
            line.ends_with(r"first\nsecond\0third\fourth"),
            "{line:?} escapes line feed and NUL only"
        );
    }

    #[test]
    fn output_outside_the_journal_is_plain() {
        if is_child() {
            let _guard = init_child_logging();
            warn!("plain warn event");
            return;
        }

        for journal in [Journal::Mismatching, Journal::Unset] {
            let output =
                run_in_child_process("output_outside_the_journal_is_plain", &journal, None);
            let line = only_line_with(&output.log_lines, "plain warn event");
            assert!(line.contains("WARN"), "{line:?} names its level");
            for line in &output.log_lines {
                assert!(!line.starts_with('<'), "{line:?} has no priority prefix");
                assert!(!line.contains('\x1b'), "{line:?} holds no ESC byte");
            }
        }
    }

    #[test]
    fn journal_panic_is_one_error_line() {
        if is_child() {
            let _guard = init_child_logging();
            let result = thread::Builder::new()
                .name(PANIC_THREAD.to_string())
                .spawn(|| panic!("{PANIC_MESSAGE}"))
                .expect("spawn panicking thread")
                .join();
            assert!(result.is_err(), "the thread panicked");
            return;
        }

        let output =
            run_in_child_process("journal_panic_is_one_error_line", &Journal::Matching, None);
        let line = only_line_with(&output.log_lines, PANIC_MESSAGE);
        assert_journal_line(line, "<3>", "ERROR");
        assert!(
            line.contains(&format!("thread '{PANIC_THREAD}' panicked at ")),
            "{line:?} names the thread"
        );
        assert!(
            line.contains(concat!(file!(), ":")),
            "{line:?} names the location"
        );
        assert_eq!(
            output
                .log_lines
                .iter()
                .filter(|line| line.starts_with("<3>"))
                .count(),
            1,
            "{:#?}",
            output.log_lines
        );
        assert_eq!(output.stderr, "", "nothing else reaches stderr");
    }

    #[test]
    fn info_is_the_default_level_and_rust_log_overrides_it() {
        if is_child() {
            let _guard = init_child_logging();
            info!("level info event");
            debug!("level debug event");
            return;
        }

        let name = "info_is_the_default_level_and_rust_log_overrides_it";
        let output = run_in_child_process(name, &Journal::Matching, None);
        only_line_with(&output.log_lines, "level info event");
        assert_no_line_has(&output.log_lines, "level debug event");

        let output = run_in_child_process(name, &Journal::Matching, Some("debug"));
        only_line_with(&output.log_lines, "level info event");
        only_line_with(&output.log_lines, "level debug event");

        let output = run_in_child_process(name, &Journal::Matching, Some("warn"));
        assert_no_line_has(&output.log_lines, "level info event");
    }
}
