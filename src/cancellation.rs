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
//!
//! ## Subsystem-level usage
//!
//! ```ignore
//! use std::time::Duration;
//!
//! async fn run_subsystem() -> Result<(), Box<dyn std::error::Error>> {
//!     let tracker = crate::cancellation::TaskTracker::new();
//!
//!     tracker.spawn("worker-1", |token| async move {
//!         loop {
//!             token.check_cancelled()?;
//!             // ... process one unit of work ...
//!         }
//!     })?;
//!
//!     // ... later, when shutdown starts ...
//!     tracker.cancel_and_drain(Duration::from_secs(5)).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## `cancel()` vs `cancelled()`
//!
//! `cancel()` is used by the controller side to signal shutdown.
//! `cancelled().await` is used by worker tasks to wait for that signal.
//!
//! ```ignore
//! async fn worker(token: crate::cancellation::CancellationToken) {
//!     tokio::select! {
//!         _ = do_work() => {
//!             // completed normally
//!         }
//!         _ = token.cancelled() => {
//!             // shutdown requested; cleanup and exit
//!         }
//!     }
//! }
//! ```
//!
//! ## `check_cancelled()`
//!
//! Use [`CancellationToken::check_cancelled`] in loops or hot-path sections to
//! cooperatively check for cancellation without introducing an `.await` point.
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
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio_util::task::TaskTracker as TokioTaskTracker;
use tracing::{info, warn};

/// Error returned when a cancellation token has been cancelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelledError;

impl fmt::Display for CancelledError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation cancelled")
    }
}

impl std::error::Error for CancelledError {}

/// Error returned when [`TaskTracker::cancel_and_drain`] times out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainError {
    /// Number of tasks that were still pending when the timeout elapsed.
    pub pending_count: usize,
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
    name: String,
    started_at: std::time::Instant,
}

#[derive(Debug, Clone)]
struct PendingTask {
    id: u64,
    name: String,
    age: Duration,
}

/// RAII guard that removes a task from the registry when dropped,
/// guaranteeing cleanup on all termination paths (normal, cancel, panic).
struct RegistryGuard {
    id: u64,
    registry: TaskRegistry,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.registry.lock() {
            reg.remove(&self.id);
        }
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
/// is called, the tracker enters a shutdown boundary: new spawn attempts that
/// observe the closed flag will fail, while tasks that were already admitted
/// continue to be tracked until they exit.
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
    closed: std::sync::atomic::AtomicBool,
}

impl TaskTracker {
    /// Creates a new task tracker with a fresh root cancellation token.
    #[must_use]
    pub fn new() -> Self {
        Self::with_token(CancellationToken::new())
    }

    /// Creates a new task tracker using the given root cancellation token.
    #[must_use]
    pub fn with_token(root_token: CancellationToken) -> Self {
        Self {
            root_token,
            tasks: TokioTaskTracker::new(),
            registry: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(0),
            closed: std::sync::atomic::AtomicBool::new(false),
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
    /// Spawn attempts that have already passed the closed check may still
    /// complete after this method is called. However, any spawn attempt that
    /// begins after the closed flag is observed will return [`SpawnError`].
    pub fn close(&self) {
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
    /// # Errors
    ///
    /// Returns [`SpawnError`] if the tracker has been closed (via
    /// [`close`](Self::close) or [`cancel_and_drain`](Self::cancel_and_drain)).
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    pub fn spawn<F, Fut>(&self, name: impl Into<String>, f: F) -> Result<(), SpawnError>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Result<(), CancelledError>> + Send + 'static,
    {
        if self.is_closed() {
            return Err(SpawnError);
        }

        let name = name.into();
        let child_token = self.root_token.child_token();
        let registry = Arc::clone(&self.registry);

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let meta = TaskMeta {
            name,
            started_at: std::time::Instant::now(),
        };
        register_task(&registry, id, meta);

        let guard = RegistryGuard {
            id,
            registry: Arc::clone(&registry),
        };
        let fut = f(child_token);
        let task = async move {
            // Move the guard into the future state at construction time so it
            // still runs if the task is dropped before its first poll.
            let _guard = guard;
            // Run the user future; ignore CancelledError since that's
            // the expected shutdown path.
            let _result = fut.await;
        };

        self.tasks.spawn(task);
        Ok(())
    }

    /// Cancels all child tokens by cancelling the root token.
    pub fn cancel_children(&self) {
        self.root_token.cancel();
    }

    /// Returns the number of tasks that are currently pending.
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.registry
            .lock()
            .expect("task registry lock should not be poisoned")
            .len()
    }

    /// Logs information about tasks that are still pending.
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    pub fn log_pending(&self) {
        let pending = self.pending_tasks();

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
            self.log_pending();
            Err(DrainError {
                pending_count: self.pending_count(),
            })
        }
    }

    fn pending_tasks(&self) -> Vec<PendingTask> {
        self.registry
            .lock()
            .expect("task registry lock should not be poisoned")
            .iter()
            .map(|(id, meta)| PendingTask {
                id: *id,
                name: meta.name.clone(),
                age: meta.started_at.elapsed(),
            })
            .collect()
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

fn register_task(registry: &TaskRegistry, id: u64, meta: TaskMeta) {
    let mut reg = registry
        .lock()
        .expect("task registry lock should not be poisoned");
    reg.insert(id, meta);
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

        tracker.drain(Duration::from_secs(1)).await.ok();
        assert!(token_was_valid.load(Ordering::Acquire));
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
        tracker.drain(Duration::from_secs(1)).await.ok();
        assert!(saw_cancel.load(Ordering::Acquire));
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
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Ok(())
            })
            .expect("spawn should succeed");

        // Give the task a moment to start.
        tokio::task::yield_now().await;

        let result = tracker.cancel_and_drain(Duration::from_millis(50)).await;
        assert_eq!(result, Err(DrainError { pending_count: 1 }));
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
        tracker.drain(Duration::from_secs(1)).await.ok();
        assert!(saw_cancel.load(Ordering::Acquire));
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

        tracker.drain(Duration::from_secs(1)).await.ok();
        assert_eq!(count.load(Ordering::Relaxed), 5);
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn log_pending_reports_task_shape() {
        let tracker = TaskTracker::new();
        tracker
            .spawn("slow", |_token| async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
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
    fn close_in_future_factory_does_not_deadlock() {
        let (spawn_result, drain_result) = run_on_current_thread_runtime(async move {
            let tracker = Arc::new(TaskTracker::new());
            let tracker_for_factory = Arc::clone(&tracker);

            let result = tracker.spawn("close-from-factory", move |_token| {
                tracker_for_factory.close();
                async { Ok(()) }
            });

            let drained = tracker.drain(Duration::from_secs(1)).await;
            (result, drained)
        });
        assert!(spawn_result.is_ok(), "spawn should succeed");
        assert!(drain_result.is_ok(), "tracker drain should succeed");
    }

    #[test]
    fn log_pending_with_reentrant_writer_does_not_deadlock() {
        let write_calls = run_on_current_thread_runtime(async move {
            let tracker = Arc::new(TaskTracker::new());
            tracker
                .spawn("slow", |_token| async {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
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
