//! Cancellation primitives for cooperative subsystem shutdown and task tracking.
//!
//! This module provides two main primitives:
//!
//! - [`CancellationToken`]: A hierarchical cancellation token supporting
//!   parent-child relationships and cooperative cancellation checks.
//! - [`TaskTracker`]: A task tracker that spawns named, tracked tasks with
//!   automatic child token creation, drain-with-timeout, and pending-task
//!   logging.
//!
//! These primitives are intended to be shared by subsystems such as
//! `ingest`, `publish`, `peer`, retention work, and other long-running async
//! components that need a common cancellation and drain pattern.
//!
//! # Intended Pattern
//!
//! A subsystem creates a [`TaskTracker`] and uses it to spawn worker tasks.
//! Each spawned task receives a child [`CancellationToken`].
//!
//! When shutdown begins, the subsystem should:
//!
//! 1. stop accepting new work,
//! 2. signal cancellation to existing work,
//! 3. drain tracked tasks with a timeout.
//!
//! In most cases that means calling [`TaskTracker::cancel_and_drain`].
//! For subsystems with separate ingress shutdown, use the staged
//! [`TaskTracker::close`] -> [`TaskTracker::cancel_children`] ->
//! [`TaskTracker::drain`] sequence instead.
//!
//! # Granularity
//!
//! Use [`TaskTracker::spawn`] only for long-lived tasks: subsystem entry
//! points, one task per QUIC connection, or one task per bi-directional
//! stream. For per-event or per-batch hot paths, take only a child token via
//! [`TaskTracker::create_child_token`] and use `tokio::select!` or
//! [`CancellationToken::check_cancelled`], spawning directly with
//! `tokio::spawn` when needed. Calling [`TaskTracker::spawn`] per message
//! will turn the registry mutex into the throughput ceiling.
//!
//! ## Subsystem-level usage
//!
//! For async worker tasks, use `tokio::select!` with `token.cancelled()` so
//! that cancellation is observed while awaiting I/O, timers, or channels.
//! This is the **primary** pattern for async subsystems:
//!
//! ```ignore
//! use std::time::Duration;
//!
//! async fn run_subsystem() -> Result<(), Box<dyn std::error::Error>> {
//!     let tracker = crate::cancellation::TaskTracker::new();
//!
//!     tracker.spawn("worker-1", |token| async move {
//!         loop {
//!             tokio::select! {
//!                 result = do_work() => {
//!                     // process result ...
//!                 }
//!                 _ = token.cancelled() => {
//!                     // shutdown requested; cleanup and exit
//!                     break;
//!                 }
//!             }
//!         }
//!         Ok(())
//!     })?;
//!
//!     // ... later, when shutdown starts ...
//!     tracker.cancel_and_drain(Duration::from_secs(5)).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Staged Shutdown
//!
//! Under sustained load, callers often need to close ingress before signalling
//! all live tasks. Drive the stages independently when cleanup can pile up:
//!
//! ```ignore
//! use std::time::Duration;
//!
//! async fn stop_subsystem(
//!     tracker: &crate::cancellation::TaskTracker,
//!     endpoint: quinn::Endpoint,
//! ) -> Result<(), crate::cancellation::DrainError> {
//!     tracker.close();                               // 1) refuse new spawns
//!     endpoint.close(0_u32.into(), &[]);             // 2) close ingress
//!     tracker.cancel_children();                     // 3) signal live tasks
//!     tracker.drain(Duration::from_secs(30)).await?; // 4) graceful drain
//!     // Optionally escalate after this point if drain times out.
//!     Ok(())
//! }
//! ```
//!
//! ## `cancel()` vs `cancelled()`
//!
//! `cancel()` is used by the controller side to signal shutdown.
//! `cancelled().await` is used by worker tasks to wait for that signal,
//! typically inside a `tokio::select!` branch alongside the main work future.
//!
//! ## `check_cancelled()`
//!
//! Use [`CancellationToken::check_cancelled`] as a **secondary** cooperative
//! check in CPU-bound loops or hot-path sections where you need to test for
//! cancellation without introducing an `.await` point:
//!
//! ```ignore
//! async fn consume_batches(
//!     token: crate::cancellation::CancellationToken,
//! ) -> Result<(), crate::cancellation::CancelledError> {
//!     loop {
//!         token.check_cancelled()?;
//!         read_next_batch().await;
//!         token.check_cancelled()?;
//!         apply_batch();
//!     }
//! }
//! ```

use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::FutureExt;
use tokio_util::task::TaskTracker as TokioTaskTracker;
use tracing::{error, info, warn};

/// Error returned when a cancellation token has been cancelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelledError;

impl fmt::Display for CancelledError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation cancelled")
    }
}

impl std::error::Error for CancelledError {}

/// Snapshot of a task that was still pending when drain timed out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTaskSnapshot {
    /// Task identifier assigned by [`TaskTracker`].
    pub id: u64,
    /// Task name supplied at spawn time.
    pub name: String,
    /// Duration since the task was spawned.
    pub age: Duration,
}

/// Error returned when [`TaskTracker::cancel_and_drain`] or
/// [`TaskTracker::drain`] times out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainError {
    /// Number of tasks that were still pending when the timeout elapsed.
    pub pending_count: usize,
    /// Snapshot of tasks that were still pending when the timeout elapsed.
    pub pending: Vec<PendingTaskSnapshot>,
}

impl fmt::Display for DrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "drain timed out with {} pending task(s)",
            self.pending_count
        )
    }
}

impl std::error::Error for DrainError {}

/// Error returned when [`TaskTracker::spawn`] is called after the tracker
/// has been closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpawnError;

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tracker is closed; cannot spawn new tasks")
    }
}

impl std::error::Error for SpawnError {}

type TaskRegistry = Arc<Mutex<HashMap<u64, TaskMeta>>>;

/// A hierarchical cancellation token for cooperative cancellation.
///
/// Wraps [`tokio_util::sync::CancellationToken`] with convenience methods
/// for cooperative cancellation inside long-running loops.
///
/// Tokens are cheap to clone (internally `Arc`-based) and are `Send + Sync`.
#[derive(Clone)]
pub struct CancellationToken {
    inner: tokio_util::sync::CancellationToken,
}

impl CancellationToken {
    /// Creates a new root cancellation token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: tokio_util::sync::CancellationToken::new(),
        }
    }

    /// Creates a child token. Cancelling the parent also cancels the child,
    /// but cancelling the child does **not** cancel the parent.
    #[must_use]
    pub fn child_token(&self) -> Self {
        Self {
            inner: self.inner.child_token(),
        }
    }

    /// Cancels this token (and all its children).
    ///
    /// This is typically called by the controlling side of a subsystem when
    /// shutdown begins and existing tasks should start exiting cooperatively.
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    /// Returns `true` if this token has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// Returns a future that resolves when this token is cancelled.
    ///
    /// This is typically used inside worker tasks that should wait for a
    /// shutdown signal while doing other async work via `tokio::select!`.
    pub async fn cancelled(&self) {
        self.inner.cancelled().await;
    }

    /// Returns an error if the token has already been cancelled.
    ///
    /// This is useful in hot paths that want to check cancellation without
    /// introducing an `.await` point, such as synchronous processing or
    /// post-I/O validation before mutating local state.
    ///
    /// # Errors
    ///
    /// Returns [`CancelledError`] if the token is cancelled.
    pub fn check_cancelled(&self) -> Result<(), CancelledError> {
        if self.is_cancelled() {
            Err(CancelledError)
        } else {
            Ok(())
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancellationToken")
            .field("is_cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Metadata for a tracked task.
#[derive(Debug, Clone)]
struct TaskMeta {
    name: Cow<'static, str>,
    started_at: std::time::Instant,
}

/// RAII guard that removes a task from the registry when dropped,
/// guaranteeing cleanup on all termination paths (normal, cancel, panic).
struct RegistryGuard {
    id: u64,
    registry: TaskRegistry,
    live_count: Arc<AtomicUsize>,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.registry.lock() {
            reg.remove(&self.id);
        }
        self.live_count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A task tracker that spawns named tasks with cancellation token management
/// and graceful drain semantics.
///
/// Each spawned task receives a child [`CancellationToken`] tied to the
/// tracker's root token. The tracker keeps a registry of pending tasks
/// so it can log stragglers during drain.
///
/// Once [`close`](Self::close) or [`cancel_and_drain`](Self::cancel_and_drain)
/// is called, the tracker enters a shutdown boundary. Spawn admission is
/// serialized against `close`, so any spawn that begins to admit after `close`
/// returns will fail with [`SpawnError`]; any task that completed admission
/// before `close` is fully tracked and waited on by `drain`.
///
/// If the tracker is created with [`with_token`](Self::with_token), remember
/// that any other tracker sharing the same root token observes the same
/// cancellation tree: cancelling one shared root cancels tasks under both.
///
/// Typical subsystem usage:
///
/// ```ignore
/// use std::time::Duration;
///
/// async fn run_subsystem() -> Result<(), Box<dyn std::error::Error>> {
///     let tracker = crate::cancellation::TaskTracker::new();
///
///     tracker.spawn("worker", |token| async move {
///         loop {
///             token.check_cancelled()?;
///             // ... do one unit of work ...
///         }
///     })?;
///
///     // ... later, when shutdown starts ...
///     tracker.cancel_and_drain(Duration::from_secs(5)).await?;
///     Ok(())
/// }
/// ```
pub struct TaskTracker {
    root_token: CancellationToken,
    tasks: TokioTaskTracker,
    registry: TaskRegistry,
    next_id: AtomicU64,
    live_count: Arc<AtomicUsize>,
    panic_count: Arc<AtomicU64>,
    closed: std::sync::atomic::AtomicBool,
    /// Serializes the final admission step in [`TaskTracker::spawn`] against
    /// [`TaskTracker::close`] so that a task cannot be submitted to the inner
    /// tracker after the close flag has been observed by `drain`. The lock is
    /// only held across the re-check, registry insertion, and `tasks.spawn()`
    /// call — never across user code.
    admission: Mutex<()>,
}

impl TaskTracker {
    /// Creates a new task tracker with a fresh root cancellation token.
    #[must_use]
    pub fn new() -> Self {
        Self::with_token(CancellationToken::new())
    }

    /// Creates a new task tracker using the given root cancellation token.
    ///
    /// When two trackers share the same root token, cancellation propagates
    /// across both. Calling [`cancel_children`](Self::cancel_children) on one
    /// shared-root tracker cancels tasks spawned by the other tracker too.
    #[must_use]
    pub fn with_token(root_token: CancellationToken) -> Self {
        Self {
            root_token,
            tasks: TokioTaskTracker::new(),
            registry: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(0),
            live_count: Arc::new(AtomicUsize::new(0)),
            panic_count: Arc::new(AtomicU64::new(0)),
            closed: std::sync::atomic::AtomicBool::new(false),
            admission: Mutex::new(()),
        }
    }

    /// Returns a reference to the root cancellation token.
    #[must_use]
    pub fn token(&self) -> &CancellationToken {
        &self.root_token
    }

    /// Creates a child cancellation token tied to the tracker's root.
    #[must_use]
    pub fn create_child_token(&self) -> CancellationToken {
        self.root_token.child_token()
    }

    /// Returns `true` if the tracker has been closed against new spawns.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Closes the tracker so that no new tasks can be spawned.
    ///
    /// Does **not** cancel existing tasks. Call
    /// [`cancel_children`](Self::cancel_children) separately if needed.
    ///
    /// Spawn attempts that are already inside their admission critical
    /// section will complete and remain tracked; any spawn attempt that
    /// reaches the critical section after the closed flag is observed will
    /// return [`SpawnError`]. The admission lock guarantees that no task is
    /// submitted to the inner tracker after `close` observes the closed
    /// flag, so `drain` will never miss a tracked task.
    ///
    /// # Panics
    ///
    /// Panics if the admission lock is poisoned.
    pub fn close(&self) {
        let _admission = self
            .admission
            .lock()
            .expect("task admission lock should not be poisoned");
        self.closed.store(true, Ordering::Release);
        self.tasks.close();
    }

    /// Spawns a named task on the tracker.
    ///
    /// The closure receives a child [`CancellationToken`] that will be
    /// cancelled when the tracker's root token is cancelled. The task is
    /// automatically registered and deregistered in the pending-task
    /// registry on all termination paths (normal completion, cancellation,
    /// or panic).
    ///
    /// The spawned future returns `Result<(), CancelledError>`. Ordinary
    /// work errors should therefore be handled inside the task body, or
    /// explicitly converted if cancellation is the intended outcome.
    ///
    /// String-literal names are stored without allocation; dynamic names can
    /// still be passed with `String` or `format!(...)`.
    ///
    /// ```ignore
    /// let tracker = crate::cancellation::TaskTracker::new();
    ///
    /// tracker.spawn("stream-reader", |token| async move {
    ///     loop {
    ///         tokio::select! {
    ///             _ = token.cancelled() => break,
    ///             item = read_next_item() => {
    ///                 let item = match item {
    ///                     Ok(item) => item,
    ///                     Err(err) => {
    ///                         tracing::warn!(?err, "read error; exiting task");
    ///                         break;
    ///                     }
    ///                 };
    ///
    ///                 if let Err(err) = handle_item(item).await {
    ///                     tracing::warn!(?err, "handler error; exiting task");
    ///                     break;
    ///                 }
    ///             }
    ///         }
    ///     }
    ///     Ok(())
    /// })?;
    /// # Ok::<(), crate::cancellation::SpawnError>(())
    /// ```
    ///
    /// Existing `tokio::spawn(async move { ... -> Result<()> })` call sites
    /// should absorb domain errors inside the tracked task:
    ///
    /// ```ignore
    /// tracker.spawn("handle_connection", |token| async move {
    ///     if let Err(err) = handle_connection(conn, token).await {
    ///         tracing::error!(?err, "handle_connection failed");
    ///     }
    ///     Ok(())
    /// })?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError`] if the tracker has been closed (via
    /// [`close`](Self::close) or [`cancel_and_drain`](Self::cancel_and_drain)).
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    pub fn spawn<F, Fut>(&self, name: impl Into<Cow<'static, str>>, f: F) -> Result<(), SpawnError>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Result<(), CancelledError>> + Send + 'static,
    {
        // Fast path: cheap closed check before doing any allocation or
        // running the user factory.
        if self.is_closed() {
            return Err(SpawnError);
        }

        let name = name.into();
        let task_name = name.clone();
        let child_token = self.root_token.child_token();
        let registry = Arc::clone(&self.registry);
        let live_count = Arc::clone(&self.live_count);
        let panic_count = Arc::clone(&self.panic_count);

        // Relaxed is sufficient: task IDs only need uniqueness and do not
        // synchronize with any other memory.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let meta = TaskMeta {
            name,
            started_at: std::time::Instant::now(),
        };

        // Run the user factory *outside* the admission lock: it may panic
        // (which would poison the lock) or recursively call spawn/close
        // (which would deadlock or self-block on a non-reentrant mutex).
        let fut = f(child_token);

        // Admission critical section: re-check the closed flag, register
        // the task, and submit it to the inner tracker atomically with
        // respect to `close()`. This closes the window in which a concurrent
        // close+drain could observe an empty tracker just before `tasks.spawn`
        // submits a fresh task and lets it escape the drain.
        let _admission = self
            .admission
            .lock()
            .expect("task admission lock should not be poisoned");
        if self.is_closed() {
            return Err(SpawnError);
        }
        register_task(&registry, &live_count, id, meta);
        let guard = RegistryGuard {
            id,
            registry: Arc::clone(&registry),
            live_count: Arc::clone(&live_count),
        };
        let task = async move {
            // Move the guard into the future state at construction time so it
            // still runs if the task is dropped before its first poll.
            let _guard = guard;
            // Run the user future; ignore CancelledError since that's
            // the expected shutdown path. Panics are logged because the
            // tracked task handle is otherwise intentionally not exposed.
            if let Err(payload) = AssertUnwindSafe(fut).catch_unwind().await {
                panic_count.fetch_add(1, Ordering::Relaxed);
                error!(
                    task_id = id,
                    task_name = %task_name,
                    panic = %panic_payload_to_string(payload.as_ref()),
                    "tracked task panicked"
                );
            }
        };
        self.tasks.spawn(task);
        Ok(())
    }

    /// Cancels all child tokens by cancelling the root token.
    pub fn cancel_children(&self) {
        self.root_token.cancel();
    }

    /// Returns the number of tasks that are currently pending.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.live_count.load(Ordering::Relaxed)
    }

    /// Returns the number of tracked tasks that panicked.
    #[must_use]
    pub fn panic_count(&self) -> u64 {
        self.panic_count.load(Ordering::Relaxed)
    }

    /// Logs information about tasks that are still pending.
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    pub fn log_pending(&self) {
        let pending = self.pending_tasks();
        Self::log_pending_tasks(&pending);
    }

    /// Closes the tracker, cancels all children, and waits for tasks to
    /// complete within a timeout.
    ///
    /// After this call, [`spawn`](Self::spawn) will return
    /// [`SpawnError`].
    ///
    /// If all tasks finish within `timeout`, returns `Ok(())`. Otherwise
    /// logs pending tasks and returns `Err(DrainError)`.
    ///
    /// ```ignore
    /// use std::time::Duration;
    ///
    /// async fn stop_subsystem(
    ///     tracker: &crate::cancellation::TaskTracker,
    /// ) -> Result<(), crate::cancellation::DrainError> {
    ///     // Caller is expected to stop accepting new work before this point.
    ///     tracker.cancel_and_drain(Duration::from_secs(5)).await
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`DrainError`] if the timeout elapses before all tasks
    /// have completed.
    pub async fn cancel_and_drain(&self, timeout: Duration) -> Result<(), DrainError> {
        self.close();
        self.cancel_children();
        self.drain_after_close(timeout).await
    }

    /// Closes the tracker and waits for all tracked tasks to complete,
    /// with a timeout.
    ///
    /// Does **not** cancel children; call [`cancel_children`](Self::cancel_children)
    /// first if desired.
    ///
    /// # Errors
    ///
    /// Returns [`DrainError`] if the timeout elapses before all tasks
    /// have completed.
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    pub async fn drain(&self, timeout: Duration) -> Result<(), DrainError> {
        self.close();
        self.drain_after_close(timeout).await
    }

    async fn drain_after_close(&self, timeout: Duration) -> Result<(), DrainError> {
        if let Ok(()) = tokio::time::timeout(timeout, self.tasks.wait()).await {
            Ok(())
        } else {
            let pending = self.pending_tasks();
            Self::log_pending_tasks(&pending);
            Err(DrainError {
                pending_count: pending.len(),
                pending,
            })
        }
    }

    fn pending_tasks(&self) -> Vec<PendingTaskSnapshot> {
        self.registry
            .lock()
            .expect("task registry lock should not be poisoned")
            .iter()
            .map(|(id, meta)| PendingTaskSnapshot {
                id: *id,
                name: meta.name.to_string(),
                age: meta.started_at.elapsed(),
            })
            .collect()
    }

    fn log_pending_tasks(pending: &[PendingTaskSnapshot]) {
        if pending.is_empty() {
            info!("no pending tasks");
            return;
        }
        warn!("{} task(s) still pending:", pending.len());
        for pending_task in pending {
            warn!(
                "  task id={id} name={:?} age={:?}",
                pending_task.name,
                pending_task.age,
                id = pending_task.id,
            );
        }
    }
}

impl Default for TaskTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TaskTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskTracker")
            .field("root_token", &self.root_token)
            .field("is_closed", &self.is_closed())
            .field("pending_count", &self.pending_count())
            .finish_non_exhaustive()
    }
}

fn register_task(registry: &TaskRegistry, live_count: &AtomicUsize, id: u64, meta: TaskMeta) {
    let mut reg = registry
        .lock()
        .expect("task registry lock should not be poisoned");
    reg.insert(id, meta);
    live_count.fetch_add(1, Ordering::Relaxed);
}

fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> Cow<'_, str> {
    if let Some(message) = payload.downcast_ref::<&str>() {
        Cow::Borrowed(message)
    } else if let Some(message) = payload.downcast_ref::<String>() {
        Cow::Borrowed(message.as_str())
    } else {
        Cow::Borrowed("<non-string panic payload>")
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io::{self, Write},
        sync::atomic::{AtomicBool, AtomicU32, AtomicUsize},
    };

    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    #[derive(Clone, Default)]
    struct SharedLogBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedLogBuffer {
        fn contents(&self) -> String {
            let bytes = self
                .0
                .lock()
                .expect("log buffer lock should not be poisoned")
                .clone();
            String::from_utf8(bytes).expect("test log output should be valid utf-8")
        }
    }

    struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer lock should not be poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedLogBuffer {
        type Writer = SharedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogWriter(Arc::clone(&self.0))
        }
    }

    struct ReentrantPendingCountWriter {
        tracker: Arc<TaskTracker>,
        calls: Arc<AtomicUsize>,
    }

    impl Write for ReentrantPendingCountWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _ = self.tracker.pending_count();
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct ReentrantPendingCountBuffer {
        tracker: Arc<TaskTracker>,
        calls: Arc<AtomicUsize>,
    }

    impl ReentrantPendingCountBuffer {
        fn new(tracker: Arc<TaskTracker>) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    tracker,
                    calls: Arc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl<'a> MakeWriter<'a> for ReentrantPendingCountBuffer {
        type Writer = ReentrantPendingCountWriter;

        fn make_writer(&'a self) -> Self::Writer {
            ReentrantPendingCountWriter {
                tracker: Arc::clone(&self.tracker),
                calls: Arc::clone(&self.calls),
            }
        }
    }

    const THREAD_TEST_TIMEOUT: Duration = Duration::from_secs(1);

    fn run_on_current_thread_runtime<T, F>(future: F) -> T
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime should build");
            let output = runtime.block_on(future);
            done_tx.send(output).expect("result channel should be open");
        });

        done_rx
            .recv_timeout(THREAD_TEST_TIMEOUT)
            .expect("threaded runtime should complete without deadlocking")
    }

    // ── CancellationToken tests ─────────────────────────────────────

    #[test]
    fn token_starts_not_cancelled() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancel_sets_is_cancelled() {
        let token = CancellationToken::new();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn clone_shares_state() {
        let token = CancellationToken::new();
        let clone = token.clone();
        token.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn child_cancelled_when_parent_cancelled() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        assert!(!child.is_cancelled());
        parent.cancel();
        assert!(child.is_cancelled());
    }

    #[test]
    fn parent_not_cancelled_when_child_cancelled() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        child.cancel();
        assert!(!parent.is_cancelled());
        assert!(child.is_cancelled());
    }

    #[test]
    fn grandchild_cancelled_when_grandparent_cancelled() {
        let grandparent = CancellationToken::new();
        let parent = grandparent.child_token();
        let child = parent.child_token();
        grandparent.cancel();
        assert!(parent.is_cancelled());
        assert!(child.is_cancelled());
    }

    #[test]
    fn child_created_after_parent_cancelled_is_cancelled() {
        let parent = CancellationToken::new();
        parent.cancel();
        let child = parent.child_token();
        assert!(child.is_cancelled());
    }

    #[tokio::test]
    async fn cancelled_future_resolves_on_cancel() {
        let token = CancellationToken::new();
        let token2 = token.clone();
        let handle = tokio::spawn(async move {
            token2.cancelled().await;
            true
        });
        // Token not yet cancelled, task should be waiting.
        tokio::task::yield_now().await;
        token.cancel();
        assert!(handle.await.expect("task should not panic"));
    }

    // ── TaskTracker tests ───────────────────────────────────────────

    #[tokio::test]
    async fn spawn_and_complete() {
        let tracker = TaskTracker::new();
        let completed = Arc::new(AtomicBool::new(false));
        let completed2 = Arc::clone(&completed);

        tracker
            .spawn("test-task", move |_token| async move {
                completed2.store(true, Ordering::Release);
                Ok(())
            })
            .expect("spawn should succeed");

        let result = tracker.drain(Duration::from_secs(1)).await;
        assert!(result.is_ok());
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn spawn_receives_child_token() {
        let tracker = TaskTracker::new();
        let token_was_valid = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&token_was_valid);

        tracker
            .spawn("token-check", move |token| async move {
                flag.store(!token.is_cancelled(), Ordering::Release);
                Ok(())
            })
            .expect("spawn should succeed");

        tracker
            .drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");
        assert!(token_was_valid.load(Ordering::Acquire));
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn cancel_children_cancels_spawned_task_token() {
        let tracker = TaskTracker::new();
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&saw_cancel);

        tracker
            .spawn("cancel-watch", move |token| async move {
                token.cancelled().await;
                flag.store(true, Ordering::Release);
                Ok(())
            })
            .expect("spawn should succeed");

        // Let the task start waiting.
        tokio::task::yield_now().await;
        tracker.cancel_children();
        tracker
            .drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");
        assert!(saw_cancel.load(Ordering::Acquire));
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn cancel_and_drain_completes_cooperative_tasks() {
        let tracker = TaskTracker::new();
        let iterations = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&iterations);

        tracker
            .spawn("loop-task", move |token| async move {
                loop {
                    token.check_cancelled()?;
                    counter.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            })
            .expect("spawn should succeed");

        // Let the task run a few iterations.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let result = tracker.cancel_and_drain(Duration::from_secs(1)).await;
        assert!(result.is_ok());
        assert!(iterations.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn drain_timeout_returns_error() {
        let tracker = TaskTracker::new();

        tracker
            .spawn("stuck-task", |_token| async {
                // Intentionally never completes and ignores cancellation.
                tokio::time::sleep(Duration::from_hours(1)).await;
                Ok(())
            })
            .expect("spawn should succeed");

        // Give the task a moment to start.
        tokio::task::yield_now().await;

        let result = tracker.cancel_and_drain(Duration::from_millis(50)).await;
        let error = result.expect_err("drain should time out");
        assert_eq!(error.pending_count, 1);
        assert_eq!(error.pending.len(), 1);
        assert_eq!(error.pending[0].name, "stuck-task");
        // The lock-free fast path must stay consistent with the registry
        // snapshot after a timed-out drain.
        assert_eq!(tracker.pending_count(), 1);
    }

    #[tokio::test]
    async fn with_token_uses_provided_root() {
        let root = CancellationToken::new();
        let tracker = TaskTracker::with_token(root.clone());
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&saw_cancel);

        tracker
            .spawn("ext-token", move |token| async move {
                token.cancelled().await;
                flag.store(true, Ordering::Release);
                Ok(())
            })
            .expect("spawn should succeed");

        tokio::task::yield_now().await;
        // Cancel via the external root token.
        root.cancel();
        tracker
            .drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");
        assert!(saw_cancel.load(Ordering::Acquire));
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn create_child_token_is_child_of_root() {
        let tracker = TaskTracker::new();
        let child = tracker.create_child_token();
        assert!(!child.is_cancelled());
        tracker.cancel_children();
        assert!(child.is_cancelled());
    }

    #[tokio::test]
    async fn multiple_tasks_all_tracked() {
        let tracker = TaskTracker::new();
        let count = Arc::new(AtomicU32::new(0));

        for i in 0..5 {
            let c = Arc::clone(&count);
            tracker
                .spawn(format!("task-{i}"), move |_token| async move {
                    c.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })
                .expect("spawn should succeed");
        }

        tracker
            .drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");
        assert_eq!(count.load(Ordering::Relaxed), 5);
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn log_pending_reports_task_shape() {
        let tracker = TaskTracker::new();
        tracker
            .spawn("slow", |_token| async {
                tokio::time::sleep(Duration::from_hours(1)).await;
                Ok(())
            })
            .expect("spawn should succeed");
        tokio::task::yield_now().await;
        assert_eq!(tracker.pending_count(), 1);

        let logs = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(logs.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        tracker.log_pending();

        let output = logs.contents();
        assert!(output.contains("1 task(s) still pending:"));
        assert!(output.contains("task id="));
        assert!(output.contains("name=\"slow\""));
        assert!(output.contains("age="));
    }

    // ── Close / shutdown-boundary tests ───────────────────────────────

    #[tokio::test]
    async fn spawn_after_close_returns_error() {
        let tracker = TaskTracker::new();
        tracker.close();
        let result = tracker.spawn("late-task", |_token| async { Ok(()) });
        assert_eq!(result, Err(SpawnError));
    }

    #[tokio::test]
    async fn spawn_after_cancel_and_drain_returns_error() {
        let tracker = TaskTracker::new();
        tracker
            .spawn("normal-task", |_token| async { Ok(()) })
            .expect("spawn should succeed");

        tracker
            .cancel_and_drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");

        // Tracker is now closed; spawn must fail.
        let result = tracker.spawn("late-task", |_token| async { Ok(()) });
        assert_eq!(result, Err(SpawnError));
    }

    #[tokio::test]
    async fn close_does_not_cancel_existing_tasks() {
        let tracker = TaskTracker::new();
        let completed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&completed);

        tracker
            .spawn("before-close", move |_token| async move {
                flag.store(true, Ordering::Release);
                Ok(())
            })
            .expect("spawn should succeed");

        tracker.close();
        tracker
            .drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");
        assert!(completed.load(Ordering::Acquire));
    }

    // ── Panic cleanup tests ──────────────────────────────────────────

    #[tokio::test]
    async fn panicked_task_cleans_up_registry() {
        let tracker = TaskTracker::new();
        tracker
            .spawn("panicker", |_token| async {
                panic!("intentional panic in test");
            })
            .expect("spawn should succeed");

        // Give the task time to run and panic.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(tracker.pending_count(), 0);
        assert_eq!(tracker.panic_count(), 1);
    }

    #[tokio::test]
    async fn drain_does_not_timeout_after_panic() {
        let tracker = TaskTracker::new();
        tracker
            .spawn("panicker", |_token| async {
                panic!("intentional panic in test");
            })
            .expect("spawn should succeed");

        let result = tracker.drain(Duration::from_millis(100)).await;
        assert!(result.is_ok(), "drain should succeed, not timeout");
        assert_eq!(tracker.pending_count(), 0);
        assert_eq!(tracker.panic_count(), 1);
    }

    #[test]
    fn panicked_task_is_logged() {
        let logs = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(logs.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        // `set_default` installs a thread-local subscriber, so the tracked
        // task must run on this same thread for its panic log to be captured.
        // A current-thread runtime driven via `block_on` keeps the spawned
        // task on the test thread, making the capture deterministic.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime should build");

        let tracker = TaskTracker::new();
        runtime.block_on(async {
            tracker
                .spawn("visible-panicker", |_token| async {
                    panic!("visible panic in test");
                })
                .expect("spawn should succeed");

            tracker
                .drain(Duration::from_secs(1))
                .await
                .expect("drain should succeed");
        });

        let output = logs.contents();
        assert!(output.contains("tracked task panicked"));
        assert!(output.contains("visible-panicker"));
        assert!(output.contains("visible panic in test"));
        assert_eq!(tracker.panic_count(), 1);
    }

    #[test]
    fn panicking_task_factory_cleans_up_registry() {
        let tracker = TaskTracker::new();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tracker.spawn("factory-panics", |_token| {
                panic!("intentional panic while building future");
                #[allow(unreachable_code)]
                async {
                    Ok(())
                }
            });
        }));

        let panic_payload = result.expect_err("future factory should panic");
        let panic_message = panic_payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic_payload.downcast_ref::<String>().map(String::as_str))
            .expect("panic payload should be a string");
        assert_eq!(panic_message, "intentional panic while building future");
        assert_eq!(tracker.pending_count(), 0);
        // A future-factory panic is not a tracked task panic.
        assert_eq!(tracker.panic_count(), 0);
    }

    #[test]
    fn dropped_before_first_poll_cleans_up_registry() {
        let tracker = Arc::new(TaskTracker::new());
        let polled = Arc::new(AtomicBool::new(false));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime should build");

        {
            let tracker = Arc::clone(&tracker);
            let polled = Arc::clone(&polled);
            runtime.block_on(async move {
                tracker
                    .spawn("never-polled", move |_token| {
                        let polled = Arc::clone(&polled);
                        async move {
                            polled.store(true, Ordering::Release);
                            tokio::task::yield_now().await;
                            Ok(())
                        }
                    })
                    .expect("spawn should succeed");
                // Return without yielding so the task remains queued on the
                // current-thread runtime and gets dropped during shutdown.
            });
        }

        drop(runtime);

        assert!(
            !polled.load(Ordering::Acquire),
            "task should be dropped before its first poll"
        );
        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn nested_spawn_in_future_factory_does_not_deadlock() {
        let (spawn_result, drain_result, nested_ran) = run_on_current_thread_runtime(async move {
            let tracker = Arc::new(TaskTracker::new());
            let nested_ran = Arc::new(AtomicBool::new(false));
            let outer_tracker = Arc::clone(&tracker);
            let nested_flag = Arc::clone(&nested_ran);

            let result = tracker.spawn("outer", move |_token| {
                let inner_tracker = Arc::clone(&outer_tracker);
                let inner_flag = Arc::clone(&nested_flag);
                inner_tracker
                    .spawn("inner", move |_token| async move {
                        inner_flag.store(true, Ordering::Release);
                        Ok(())
                    })
                    .expect("nested spawn should succeed");
                async { Ok(()) }
            });

            let drained = tracker.drain(Duration::from_secs(1)).await;
            (result, drained, nested_ran.load(Ordering::Acquire))
        });
        assert!(spawn_result.is_ok(), "outer spawn should succeed");
        assert!(drain_result.is_ok(), "tracker drain should succeed");
        assert!(nested_ran, "nested task should run");
    }

    #[test]
    fn close_in_future_factory_returns_spawn_error_without_deadlock() {
        let (spawn_result, drain_result) = run_on_current_thread_runtime(async move {
            let tracker = Arc::new(TaskTracker::new());
            let tracker_for_factory = Arc::clone(&tracker);

            // The factory closes the tracker before returning. With
            // serialized admission, the surrounding spawn observes the close
            // when it reaches the admission critical section and refuses to
            // admit the task.
            let result = tracker.spawn("close-from-factory", move |_token| {
                tracker_for_factory.close();
                async { Ok(()) }
            });

            let drained = tracker.drain(Duration::from_secs(1)).await;
            (result, drained)
        });
        assert_eq!(
            spawn_result,
            Err(SpawnError),
            "spawn must observe the close that happened inside the factory"
        );
        assert!(drain_result.is_ok(), "tracker drain should succeed");
    }

    // Stress regression for the admission race: many concurrent spawns
    // racing against a single close+drain must never leave an admitted task
    // unobserved by drain. Either spawn returns SpawnError, or the task is
    // tracked and drain waits for it.
    #[test]
    fn concurrent_spawn_and_close_never_escapes_drain() {
        for _ in 0..32 {
            let tracker = Arc::new(TaskTracker::new());
            let observed = Arc::new(AtomicUsize::new(0));
            let admitted_count = Arc::new(AtomicUsize::new(0));

            // Use a multi-threaded runtime so spawners and the closer can
            // race inside `block_on` from independent threads.
            let runtime = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("runtime should build"),
            );

            let mut spawn_threads = Vec::new();
            for _ in 0..8 {
                let tracker_for_thread = Arc::clone(&tracker);
                let observed_for_thread = Arc::clone(&observed);
                let admitted_count_for_thread = Arc::clone(&admitted_count);
                let runtime_for_thread = Arc::clone(&runtime);
                spawn_threads.push(std::thread::spawn(move || {
                    let _guard = runtime_for_thread.enter();
                    for _ in 0..16 {
                        let observed_for_task = Arc::clone(&observed_for_thread);
                        let result = tracker_for_thread.spawn("racer", move |_token| async move {
                            observed_for_task.fetch_add(1, Ordering::Relaxed);
                            Ok(())
                        });
                        if result.is_ok() {
                            admitted_count_for_thread.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }));
            }

            // Race the closer against the spawners.
            let tracker_for_close = Arc::clone(&tracker);
            let runtime_for_close = Arc::clone(&runtime);
            let closer = std::thread::spawn(move || {
                runtime_for_close.block_on(async move {
                    tracker_for_close
                        .cancel_and_drain(Duration::from_secs(5))
                        .await
                        .expect("drain should finish within timeout");
                });
            });

            for handle in spawn_threads {
                handle.join().expect("spawner thread should not panic");
            }
            closer.join().expect("closer thread should not panic");

            let admitted = admitted_count.load(Ordering::Relaxed);
            let observed_count = observed.load(Ordering::Relaxed);
            assert_eq!(
                admitted, observed_count,
                "every admitted task must have been observed by drain (admitted={admitted}, observed={observed_count})"
            );
            assert_eq!(
                tracker.pending_count(),
                0,
                "drain must leave no pending tasks"
            );
        }
    }

    #[test]
    fn log_pending_with_no_tasks_emits_info() {
        let tracker = TaskTracker::new();

        let logs = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(logs.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        tracker.log_pending();

        let output = logs.contents();
        assert!(output.contains("no pending tasks"));
    }

    #[test]
    fn cancellation_token_default_creates_uncancelled_token() {
        let token = CancellationToken::default();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn task_tracker_default_creates_usable_tracker() {
        let tracker = TaskTracker::default();
        assert!(!tracker.is_closed());
        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn cancellation_token_debug_format() {
        let token = CancellationToken::new();
        let s = format!("{token:?}");
        assert!(s.contains("CancellationToken"));
        assert!(s.contains("is_cancelled"));
    }

    #[test]
    fn task_tracker_debug_format() {
        let tracker = TaskTracker::new();
        let s = format!("{tracker:?}");
        assert!(s.contains("TaskTracker"));
        assert!(s.contains("is_closed"));
    }

    #[test]
    fn cancelled_error_display() {
        let e = CancelledError;
        assert_eq!(e.to_string(), "operation cancelled");
    }

    #[test]
    fn drain_error_display() {
        let e = DrainError {
            pending_count: 3,
            pending: Vec::new(),
        };
        assert_eq!(e.to_string(), "drain timed out with 3 pending task(s)");
    }

    #[test]
    fn spawn_error_display() {
        let e = SpawnError;
        assert_eq!(e.to_string(), "tracker is closed; cannot spawn new tasks");
    }

    #[test]
    fn task_tracker_token_returns_root() {
        let tracker = TaskTracker::new();
        let token = tracker.token();
        assert!(!token.is_cancelled());
        tracker.cancel_children();
        assert!(token.is_cancelled());
    }

    #[test]
    fn log_pending_with_reentrant_writer_does_not_deadlock() {
        let write_calls = run_on_current_thread_runtime(async move {
            let tracker = Arc::new(TaskTracker::new());
            tracker
                .spawn("slow", |_token| async {
                    tokio::time::sleep(Duration::from_hours(1)).await;
                    Ok(())
                })
                .expect("spawn should succeed");
            tokio::task::yield_now().await;

            let (writer, calls) = ReentrantPendingCountBuffer::new(Arc::clone(&tracker));
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .without_time()
                .with_target(false)
                .with_writer(writer)
                .finish();
            let _guard = tracing::subscriber::set_default(subscriber);

            tracker.log_pending();
            calls.load(Ordering::Relaxed)
        });
        assert!(write_calls > 0, "log writer should be invoked");
    }
}
