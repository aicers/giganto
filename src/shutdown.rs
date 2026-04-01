//! Shutdown primitives for cooperative cancellation and task tracking.
//!
//! This module provides two main primitives:
//!
//! - [`CancellationToken`]: A hierarchical cancellation token supporting
//!   parent-child relationships and cooperative cancellation checkpoints.
//! - [`TaskTracker`]: A task tracker that spawns named, tracked tasks with
//!   automatic child token creation, drain-with-timeout, and pending-task
//!   logging.
//!
//! # Usage
//!
//! A subsystem creates a [`TaskTracker`] (which owns a root
//! [`CancellationToken`]) and uses it to spawn worker tasks. Each spawned
//! task receives a child [`CancellationToken`] and should periodically call
//! [`CancellationToken::checkpoint`] to cooperate with shutdown requests.
//!
//! When the subsystem shuts down, it calls
//! [`TaskTracker::cancel_and_drain`] which cancels all child tokens and
//! waits for tasks to complete within a timeout.
//!
//! ```rust,no_run
//! use std::time::Duration;
//! use giganto_proc_macro; // placeholder for crate reference
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Subsystem creates a tracker:
//! let tracker = crate::shutdown::TaskTracker::new();
//!
//! // Spawn workers:
//! tracker.spawn("worker-1", |token| async move {
//!     loop {
//!         token.checkpoint().await?;
//!         // ... do work ...
//!     }
//! });
//!
//! // On shutdown:
//! tracker.cancel_and_drain(Duration::from_secs(5)).await?;
//! # Ok(())
//! # }
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

use tokio::task::JoinSet;
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

/// A hierarchical cancellation token for cooperative shutdown.
///
/// Wraps [`tokio_util::sync::CancellationToken`] with convenience methods
/// including [`checkpoint`](Self::checkpoint) for cooperative cancellation
/// inside long-running loops.
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
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    /// Returns `true` if this token has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// Returns a future that resolves when this token is cancelled.
    pub async fn cancelled(&self) {
        self.inner.cancelled().await;
    }

    /// Cooperative cancellation checkpoint.
    ///
    /// Returns `Ok(())` immediately if the token is not yet cancelled, or
    /// `Err(CancelledError)` if it has been cancelled. Use this in
    /// long-running loops to enable prompt cooperative shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`CancelledError`] if the token is cancelled.
    pub async fn checkpoint(&self) -> Result<(), CancelledError> {
        if self.is_cancelled() {
            return Err(CancelledError);
        }
        // Yield to allow other tasks to run and check for cancellation
        // propagation that may be in progress.
        tokio::task::yield_now().await;
        if self.is_cancelled() {
            return Err(CancelledError);
        }
        Ok(())
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

/// RAII guard that removes a task from the registry when dropped,
/// guaranteeing cleanup on all termination paths (normal, cancel, panic).
struct RegistryGuard {
    id: u64,
    registry: Arc<Mutex<HashMap<u64, TaskMeta>>>,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.registry.lock() {
            reg.remove(&self.id);
        }
    }
}

/// A task tracker that spawns named tasks with automatic cancellation
/// token management and graceful drain semantics.
///
/// Each spawned task receives a child [`CancellationToken`] tied to the
/// tracker's root token. The tracker keeps a registry of pending tasks
/// so it can log stragglers during drain.
///
/// Once [`close`](Self::close) or [`cancel_and_drain`](Self::cancel_and_drain)
/// is called, no new tasks can be spawned.
pub struct TaskTracker {
    root_token: CancellationToken,
    join_set: Mutex<JoinSet<()>>,
    registry: Arc<Mutex<HashMap<u64, TaskMeta>>>,
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
            join_set: Mutex::new(JoinSet::new()),
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
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Spawns a named task on the tracker.
    ///
    /// The closure receives a child [`CancellationToken`] that will be
    /// cancelled when the tracker's root token is cancelled. The task is
    /// automatically registered and deregistered in the pending-task
    /// registry on all termination paths (normal completion, cancellation,
    /// or panic).
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

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let name = name.into();
        let child_token = self.root_token.child_token();
        let registry = Arc::clone(&self.registry);

        let meta = TaskMeta {
            name: name.clone(),
            started_at: std::time::Instant::now(),
        };

        {
            let mut reg = registry
                .lock()
                .expect("task registry lock should not be poisoned");
            reg.insert(id, meta);
        }

        let fut = f(child_token);
        let task = async move {
            // The guard ensures the registry entry is removed on all
            // exit paths, including panics.
            let _guard = RegistryGuard {
                id,
                registry: Arc::clone(&registry),
            };
            // Run the user future; ignore CancelledError since that's
            // the expected shutdown path.
            let _result = fut.await;
        };

        let mut js = self
            .join_set
            .lock()
            .expect("join set lock should not be poisoned");
        js.spawn(task);
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
        let reg = self
            .registry
            .lock()
            .expect("task registry lock should not be poisoned");
        if reg.is_empty() {
            info!("no pending tasks");
            return;
        }
        warn!("{} task(s) still pending:", reg.len());
        for (id, meta) in &*reg {
            warn!(
                "  task id={id} name={:?} age={:?}",
                meta.name,
                meta.started_at.elapsed()
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
    /// # Errors
    ///
    /// Returns [`DrainError`] if the timeout elapses before all tasks
    /// have completed.
    pub async fn cancel_and_drain(&self, timeout: Duration) -> Result<(), DrainError> {
        self.close();
        self.cancel_children();
        self.drain(timeout).await
    }

    /// Waits for all tracked tasks to complete, with a timeout.
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
        let drain_all = async {
            loop {
                let maybe_result = {
                    let mut js = self
                        .join_set
                        .lock()
                        .expect("join set lock should not be poisoned");
                    js.try_join_next()
                };
                match maybe_result {
                    Some(Ok(())) => {}
                    Some(Err(e)) => {
                        warn!("tracked task panicked: {e}");
                    }
                    None if self.pending_count() == 0 => return,
                    None => {
                        // Yield and retry to allow tasks to make progress.
                        tokio::task::yield_now().await;
                    }
                }
            }
        };

        tokio::select! {
            () = drain_all => Ok(()),
            () = tokio::time::sleep(timeout) => {
                self.log_pending();
                Err(DrainError {
                    pending_count: self.pending_count(),
                })
            }
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
            .field("pending_count", &self.pending_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU32};

    use super::*;

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
    async fn checkpoint_ok_when_not_cancelled() {
        let token = CancellationToken::new();
        assert!(token.checkpoint().await.is_ok());
    }

    #[tokio::test]
    async fn checkpoint_err_when_cancelled() {
        let token = CancellationToken::new();
        token.cancel();
        assert_eq!(token.checkpoint().await, Err(CancelledError));
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
                    token.checkpoint().await?;
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
        assert!(result.is_err());
        let err = result.expect_err("should be DrainError");
        assert_eq!(err.pending_count, 1);
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
    async fn log_pending_emits_warnings() {
        // We just verify it doesn't panic and the count is correct.
        let tracker = TaskTracker::new();
        tracker
            .spawn("slow", |_token| async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Ok(())
            })
            .expect("spawn should succeed");
        tokio::task::yield_now().await;
        assert_eq!(tracker.pending_count(), 1);
        // This should log without panicking.
        tracker.log_pending();
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
}
