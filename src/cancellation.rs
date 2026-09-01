//! Task tracking for cooperative subsystem shutdown.
//!
//! This module provides [`TaskTracker`]: a task tracker that spawns named,
//! tracked tasks with automatic child token creation, admission control, and
//! drain-with-timeout diagnostics.
//!
//! Cancellation tokens themselves are
//! [`tokio_util::sync::CancellationToken`]; this module does not wrap them, so
//! its full API (`child_token`, `cancelled`, `run_until_cancelled`,
//! `drop_guard`, ...) is available to call sites directly.
//!
//! [`TaskTracker`] is intended to be shared by subsystems such as `ingest`,
//! `publish`, `peer`, retention work, and other long-running async components
//! that need a common cancellation and drain pattern.
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
//! In most cases that means calling [`drain_with_report`], which wraps the
//! staged [`TaskTracker::close`] -> [`TaskTracker::cancel_children`] ->
//! [`TaskTracker::drain`] sequence in the repeat-until-empty policy the whole
//! process follows. [`TaskTracker::cancel_and_drain`] is the one-shot form for
//! callers that report the outcome themselves.
//!
//! Three rules cover the task side:
//!
//! 1. Observe cancellation with `tokio::select!` on
//!    [`CancellationToken::cancelled`] or with
//!    [`CancellationToken::run_until_cancelled`].
//! 2. In a CPU-bound section with no `.await` point, check
//!    [`CancellationToken::is_cancelled`].
//! 3. `drain` only waits for tasks to exit; it does not report their returned
//!    results or panics. Keep the [`tokio::task::JoinHandle`] returned by
//!    [`TaskTracker::spawn`] when the result matters, or spawn through
//!    [`TaskTracker::spawn_supervised`] when the report has to name the task
//!    as well — the registry entry that holds its name is gone by the time
//!    the handle resolves.
//!
//! Worked examples live in this module's tests:
//! `cancel_children_cancels_spawned_task_token` (select-based observation),
//! `cancel_and_drain_completes_cooperative_tasks` (cooperative loop),
//! `drain_returns_pending_on_timeout` (drain timeout and pending
//! diagnostics), `spawn_returns_join_handle_for_task_outcome` (result
//! observation), and `staged_shutdown_closes_cancels_then_drains` (staged
//! shutdown).
//!
//! # Granularity
//!
//! [`TaskTracker`] is the right tool when a tracked task spawns further tasks
//! that must be drained too, and when task results are observed through the
//! [`tokio::task::JoinHandle`] rather than harvested by the tracker. A flat
//! set of tasks whose results are collected in one place is better served by
//! `tokio::task::JoinSet` or `tokio_util::task::JoinMap`.
//!
//! Cancellation reaches a child tracker only if the child was built from the
//! parent's token. A tracker built with
//! [`with_token`](TaskTracker::with_token) from a token handed down by its
//! parent stays inside the parent's cancellation tree, so the parent's
//! [`cancel_children`](TaskTracker::cancel_children) reaches the child
//! tracker's tasks. A tracker built with [`new`](TaskTracker::new) starts a
//! fresh root, so the parent's cancellation never reaches it. Neither the
//! compiler nor a type signature catches the difference.
//!
//! Cleanup that a task must perform after observing cancellation has to run
//! before the task returns. `Drop` is synchronous and cannot `.await`, so
//! cleanup cannot be deferred to it, and `drain` only ends once every tracked
//! task has returned.
//!
//! Use [`TaskTracker::spawn`] only for long-lived tasks. On the per-event or
//! per-batch hot path, take only a child token via
//! [`TaskTracker::create_child_token`] and spawn directly with `tokio::spawn`
//! when needed. Calling [`TaskTracker::spawn`] per message will turn the
//! registry mutex into the throughput ceiling.

use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::task::{AbortHandle, JoinError, JoinHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker as TokioTaskTracker};
use tracing::{info, warn};

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

/// Error returned when an internal [`TaskTracker`] mutex is poisoned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockPoisonedError;

impl fmt::Display for LockPoisonedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "task tracker lock was poisoned")
    }
}

impl std::error::Error for LockPoisonedError {}

/// Result of [`TaskTracker::drain`] or [`TaskTracker::cancel_and_drain`].
///
/// A timeout is not a failure: it is the signal to report progress and wait
/// again. Callers are expected to repeat the drain until it returns
/// [`Drained`](Self::Drained), deciding for themselves how often and at what
/// level to log the pending snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainOutcome {
    /// All tracked tasks completed within the timeout.
    Drained,
    /// The timeout elapsed while these tasks were still running.
    Pending(Vec<PendingTaskSnapshot>),
}

/// Error returned when [`TaskTracker::spawn`] cannot admit a new task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpawnError {
    /// The tracker has been closed (via [`TaskTracker::close`],
    /// [`TaskTracker::drain`], or [`TaskTracker::cancel_and_drain`]).
    Closed,
    /// An internal mutex was poisoned during spawn admission.
    LockPoisoned,
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "tracker is closed; cannot spawn new tasks"),
            Self::LockPoisoned => write!(f, "task tracker lock was poisoned"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// Metadata for a tracked task.
#[derive(Debug, Clone)]
struct TaskMeta {
    name: Cow<'static, str>,
    started_at: Instant,
}

/// A [`JoinHandle`] that carries the tracker metadata of the task it joins.
///
/// [`TaskTracker::spawn`] hands back a bare [`JoinHandle`], and the registry
/// entry holding a task's name and start time is removed the moment that task
/// returns — which is the very moment a supervisor reads the handle back. The
/// copy kept here is what survives deregistration, so a task can still be
/// named and aged after the registry has forgotten it.
///
/// It stands in for the [`JoinHandle`] it owns: it awaits to the same output,
/// it is [`Unpin`] so it can be polled from a `select!` arm, and it forwards
/// [`is_finished`](Self::is_finished), [`abort`](Self::abort) and
/// [`abort_handle`](Self::abort_handle).
pub struct SupervisedHandle<T> {
    handle: JoinHandle<T>,
    id: u64,
    name: Cow<'static, str>,
    started_at: Instant,
}

impl<T> SupervisedHandle<T> {
    /// The tracker-assigned id of the task this handle joins.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The name the task was registered under.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How long it has been since the tracker stamped this task at spawn.
    ///
    /// The origin is the same one [`PendingTaskSnapshot::age`] is measured
    /// from, so a task reported here and a task reported by a drain round are
    /// aged alike.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Returns `true` if the task has already finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    /// Aborts the task.
    pub fn abort(&self) {
        self.handle.abort();
    }

    /// Returns an [`AbortHandle`] for the task.
    #[must_use]
    pub fn abort_handle(&self) -> AbortHandle {
        self.handle.abort_handle()
    }

    /// Gives up the metadata and returns the [`JoinHandle`] underneath.
    #[must_use]
    pub fn into_inner(self) -> JoinHandle<T> {
        self.handle
    }
}

impl<T> Future for SupervisedHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().handle).poll(cx)
    }
}

impl<T> fmt::Debug for SupervisedHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupervisedHandle")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("age", &self.age())
            .field("is_finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

/// Shared state behind every [`TaskTracker`] clone.
struct Inner {
    root_token: CancellationToken,
    tasks: TokioTaskTracker,
    registry: Mutex<HashMap<u64, TaskMeta>>,
    next_id: AtomicU64,
    closed: AtomicBool,
    /// Serializes the final admission step in [`TaskTracker::spawn`] against
    /// [`TaskTracker::close`] so that a task cannot be submitted to the inner
    /// tracker after the close flag has been observed by `drain`. The lock is
    /// only held across the re-check, registry insertion, and `tasks.spawn()`
    /// call — never across user code.
    admission: Mutex<()>,
}

impl Inner {
    /// Removes a task from the registry, returning its metadata.
    ///
    /// A poisoned registry still holds a consistent map — the only code that
    /// takes this lock is registry bookkeeping — so read through the poison
    /// rather than leaking the entry.
    fn deregister(&self, id: u64) -> Option<TaskMeta> {
        self.registry.lock().map_or_else(
            |poisoned| poisoned.into_inner().remove(&id),
            |mut reg| reg.remove(&id),
        )
    }
}

/// RAII guard that removes a task from the registry when dropped,
/// guaranteeing cleanup on all termination paths (normal, cancel, abort,
/// panic, and drop before the first poll).
///
/// The guard doubles as the safety net for the "every tracked task eventually
/// returns" contract: [`TaskTracker::spawn`] flips `completed` just before the
/// task returns, so a guard dropped with `completed` still unset names a task
/// that vanished without running to the end.
struct RegistryGuard {
    id: u64,
    inner: Arc<Inner>,
    completed: bool,
}

impl RegistryGuard {
    fn mark_completed(&mut self) {
        self.completed = true;
    }
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        let meta = self.inner.deregister(self.id);
        if self.completed {
            return;
        }
        // Logged outside the registry lock: the subscriber's writer may call
        // back into the tracker. The name is recorded with `?` so a dynamic
        // name cannot break the line-oriented log format.
        if let Some(meta) = meta {
            warn!(
                id = self.id,
                name = ?meta.name,
                age = ?meta.started_at.elapsed(),
                "tracked task did not run to completion"
            );
        }
    }
}

/// A task tracker that spawns named tasks with cancellation token management
/// and graceful drain semantics.
///
/// Each spawned task receives a child [`CancellationToken`] tied to the
/// tracker's root token. The tracker keeps a registry of pending tasks so it
/// can report stragglers when drain times out.
///
/// The tracker is cheap to clone (internally `Arc`-based); every clone shares
/// one root token, one registry, and one admission boundary, so a tracked task
/// can carry a clone and register the tasks it spawns in turn.
///
/// Once [`close`](Self::close), [`drain`](Self::drain), or
/// [`cancel_and_drain`](Self::cancel_and_drain) is called, the tracker enters a
/// shutdown boundary. Spawn admission is serialized against `close`, so any
/// spawn that begins to admit after `close` returns will fail with
/// [`SpawnError`]; any task that completed admission before `close` is fully
/// tracked and waited on by `drain`.
///
/// If the tracker is created with [`with_token`](Self::with_token), remember
/// that any other tracker sharing the same root token observes the same
/// cancellation tree: cancelling one shared root cancels tasks under both.
///
/// `drain` and `cancel_and_drain` wait for task exit, but they do not surface
/// task return values or [`tokio::task::JoinError`]. Keep the returned
/// [`JoinHandle`] for critical tasks and await or select on it at the
/// subsystem boundary.
#[derive(Clone)]
pub struct TaskTracker {
    inner: Arc<Inner>,
}

impl TaskTracker {
    /// Creates a new task tracker with a fresh root cancellation token.
    ///
    /// The new root is detached from every other cancellation tree: if this
    /// tracker is used as a child of another one, use
    /// [`with_token`](Self::with_token) instead, or the parent's
    /// [`cancel_children`](Self::cancel_children) will not reach these tasks.
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
            inner: Arc::new(Inner {
                root_token,
                tasks: TokioTaskTracker::new(),
                registry: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(0),
                closed: AtomicBool::new(false),
                admission: Mutex::new(()),
            }),
        }
    }

    /// Returns a reference to the tracker's root cancellation token.
    #[must_use]
    pub fn root_token(&self) -> &CancellationToken {
        &self.inner.root_token
    }

    /// Creates a child cancellation token tied to the tracker's root.
    #[must_use]
    pub fn create_child_token(&self) -> CancellationToken {
        self.inner.root_token.child_token()
    }

    /// Returns `true` if the tracker has been closed against new spawns.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// Closes the tracker so that no new tasks can be spawned.
    ///
    /// Does **not** cancel existing tasks. Call
    /// [`cancel_children`](Self::cancel_children) separately if needed.
    ///
    /// Spawn attempts that are already inside their admission critical
    /// section will complete and remain tracked; any spawn attempt that
    /// reaches the critical section after the closed flag is observed will
    /// return [`SpawnError::Closed`]. The admission lock guarantees that no
    /// task is submitted to the inner tracker after `close` observes the
    /// closed flag, so `drain` will never miss a tracked task.
    ///
    /// # Errors
    ///
    /// Returns [`LockPoisonedError`] if the admission lock is poisoned.
    pub fn close(&self) -> Result<(), LockPoisonedError> {
        let _admission = self.inner.admission.lock().map_err(|_| LockPoisonedError)?;
        self.inner.closed.store(true, Ordering::Release);
        self.inner.tasks.close();
        Ok(())
    }

    /// Spawns a named task on the tracker.
    ///
    /// The closure receives a child [`CancellationToken`] that will be
    /// cancelled when the tracker's root token is cancelled. The task is
    /// automatically registered and deregistered in the pending-task registry
    /// when the task future is dropped after normal completion, cancellation,
    /// abort, or panic. A task that is deregistered without having returned
    /// normally is reported with its name and age at `WARN`.
    ///
    /// The task's output type is preserved, so an entry point returning
    /// `Result` can be spawned without wrapping. Returns the spawned task's
    /// [`JoinHandle`]; `drain` only waits for task exit and does not report
    /// task outcomes, so callers that own critical tasks should keep this
    /// handle and await or select on it to observe both the task's output and
    /// [`tokio::task::JoinError`] for panics or aborts.
    ///
    /// String-literal names are stored without allocation; dynamic names can
    /// still be passed with `String` or `format!(...)`.
    ///
    /// `f` runs before the final admission check, so a losing race against
    /// [`close`](Self::close) returns [`SpawnError::Closed`] after `f` has
    /// already run, and the future it built is dropped without ever being
    /// polled. Keep resource acquisition inside the future rather than in `f`
    /// when the acquisition needs a matching release.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::Closed`] if the tracker has been closed (via
    /// [`close`](Self::close), [`drain`](Self::drain), or
    /// [`cancel_and_drain`](Self::cancel_and_drain)).
    ///
    /// Returns [`SpawnError::LockPoisoned`] if an internal mutex is poisoned.
    pub fn spawn<F, Fut>(
        &self,
        name: impl Into<Cow<'static, str>>,
        f: F,
    ) -> Result<JoinHandle<Fut::Output>, SpawnError>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        self.admit(name.into(), f).map(|(handle, _, _)| handle)
    }

    /// Spawns a named task and hands back a handle that knows what it joins.
    ///
    /// The same admission, registration and cancellation as
    /// [`spawn`](Self::spawn); what differs is the return, a
    /// [`SupervisedHandle`] carrying the task's id, its name and the instant
    /// the tracker stamped it. The registry entry is gone by the time the
    /// handle resolves, so a supervisor that has to name a task in the report
    /// it writes at that moment cannot get any of it back from the tracker.
    ///
    /// Use this for a task whose ending is acted on rather than merely waited
    /// for. Everything else is better served by [`spawn`](Self::spawn), which
    /// costs no metadata copy.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::Closed`] if the tracker has been closed, and
    /// [`SpawnError::LockPoisoned`] if an internal mutex is poisoned — the
    /// same two outcomes [`spawn`](Self::spawn) returns, for the same reasons.
    pub fn spawn_supervised<F, Fut>(
        &self,
        name: impl Into<Cow<'static, str>>,
        f: F,
    ) -> Result<SupervisedHandle<Fut::Output>, SpawnError>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let name = name.into();
        let (handle, id, started_at) = self.admit(name.clone(), f)?;
        Ok(SupervisedHandle {
            handle,
            id,
            name,
            started_at,
        })
    }

    /// The whole of spawning: the admission both entry points share.
    ///
    /// It returns the id and the spawn instant alongside the handle because
    /// they are stamped here and nowhere else, and the registry entry that
    /// holds them does not outlive the task.
    fn admit<F, Fut>(
        &self,
        name: Cow<'static, str>,
        f: F,
    ) -> Result<(JoinHandle<Fut::Output>, u64, Instant), SpawnError>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        // Fast path: cheap closed check before doing any allocation or
        // running the user factory.
        if self.is_closed() {
            return Err(SpawnError::Closed);
        }

        let child_token = self.inner.root_token.child_token();

        // Relaxed is sufficient: task IDs only need uniqueness and do not
        // synchronize with any other memory.
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let started_at = Instant::now();
        let meta = TaskMeta { name, started_at };

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
            .inner
            .admission
            .lock()
            .map_err(|_| SpawnError::LockPoisoned)?;
        if self.is_closed() {
            return Err(SpawnError::Closed);
        }
        self.register_task(id, meta)?;
        let guard = RegistryGuard {
            id,
            inner: Arc::clone(&self.inner),
            completed: false,
        };
        let task = async move {
            // Move the guard into the future state at construction time so it
            // still runs if the task is dropped before its first poll.
            let mut guard = guard;
            let output = fut.await;
            guard.mark_completed();
            output
        };
        Ok((self.inner.tasks.spawn(task), id, started_at))
    }

    /// Cancels all child tokens by cancelling the root token.
    pub fn cancel_children(&self) {
        self.inner.root_token.cancel();
    }

    /// Returns the number of tasks that are currently pending.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        // The registry is the single source of truth for pending tasks. A
        // poisoned lock still holds a consistent map, so read through it
        // rather than reporting a bogus zero.
        self.inner
            .registry
            .lock()
            .map_or_else(|poisoned| poisoned.into_inner().len(), |reg| reg.len())
    }

    /// Logs information about tasks that are still pending.
    ///
    /// Drain never calls this on its own: when and how often to report
    /// stragglers is the caller's policy.
    ///
    /// # Errors
    ///
    /// Returns [`LockPoisonedError`] if the task registry lock is poisoned.
    pub fn log_pending(&self) -> Result<(), LockPoisonedError> {
        let pending = self.pending_tasks()?;
        Self::log_pending_tasks(&pending);
        Ok(())
    }

    /// Closes the tracker, cancels all children, and waits for tasks to
    /// complete within a timeout.
    ///
    /// After this call, [`spawn`](Self::spawn) will return [`SpawnError`].
    ///
    /// Returns [`DrainOutcome::Drained`] if all tasks finished within
    /// `timeout`, and [`DrainOutcome::Pending`] with a snapshot of the
    /// stragglers otherwise. A pending outcome is not a failure; call again to
    /// keep waiting.
    ///
    /// # Errors
    ///
    /// Returns [`LockPoisonedError`] if an internal mutex is poisoned.
    pub async fn cancel_and_drain(
        &self,
        timeout: Duration,
    ) -> Result<DrainOutcome, LockPoisonedError> {
        self.close()?;
        self.cancel_children();
        self.drain_after_close(timeout).await
    }

    /// Closes the tracker and waits for all tracked tasks to complete,
    /// with a timeout.
    ///
    /// Does **not** cancel children; call
    /// [`cancel_children`](Self::cancel_children) first if desired.
    ///
    /// Returns [`DrainOutcome::Drained`] if all tasks finished within
    /// `timeout`, and [`DrainOutcome::Pending`] with a snapshot of the
    /// stragglers otherwise. A pending outcome is not a failure; call again to
    /// keep waiting.
    ///
    /// # Errors
    ///
    /// Returns [`LockPoisonedError`] if an internal mutex is poisoned.
    pub async fn drain(&self, timeout: Duration) -> Result<DrainOutcome, LockPoisonedError> {
        self.close()?;
        self.drain_after_close(timeout).await
    }

    async fn drain_after_close(
        &self,
        timeout: Duration,
    ) -> Result<DrainOutcome, LockPoisonedError> {
        if tokio::time::timeout(timeout, self.inner.tasks.wait())
            .await
            .is_ok()
        {
            Ok(DrainOutcome::Drained)
        } else {
            Ok(DrainOutcome::Pending(self.pending_tasks()?))
        }
    }

    fn register_task(&self, id: u64, meta: TaskMeta) -> Result<(), SpawnError> {
        let mut reg = self
            .inner
            .registry
            .lock()
            .map_err(|_| SpawnError::LockPoisoned)?;
        reg.insert(id, meta);
        Ok(())
    }

    fn pending_tasks(&self) -> Result<Vec<PendingTaskSnapshot>, LockPoisonedError> {
        let reg = self.inner.registry.lock().map_err(|_| LockPoisonedError)?;
        Ok(reg
            .iter()
            .map(|(id, meta)| PendingTaskSnapshot {
                id: *id,
                name: meta.name.to_string(),
                age: meta.started_at.elapsed(),
            })
            .collect())
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
            .field("root_token", &self.inner.root_token)
            .field("is_closed", &self.is_closed())
            .field("pending_count", &self.pending_count())
            .finish_non_exhaustive()
    }
}

/// How often a drain that is still waiting reports its progress.
///
/// A reporting cadence, not a deadline: the drain is retried until the tracker
/// is empty, and this only decides how often a shutdown that is waiting says
/// so. Making it configurable belongs to the settings work in #1569.
pub const DRAIN_REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// Closes and cancels `tracker`, then drains it repeatedly until every tracked
/// task has returned.
///
/// This is the drain policy every tracker in the process follows, the
/// per-generation top-level one and each subsystem's alike, so `label` names
/// the tracker being drained in the log lines the rounds emit.
///
/// `report_interval` is a reporting cadence, not a deadline. Each time it
/// expires with tasks still tracked, the round is reported and the drain is
/// retried. Stragglers are never aborted: [`tokio::task::JoinHandle::abort`]
/// drops a task future at an arbitrary await point, which voids the
/// cleanup-before-return contract every tracked task is written to. Shutdown
/// therefore ends only when the tasks themselves return, and the repeated
/// report is what narrows down a task that never does.
///
/// The loop is re-callable. [`TaskTracker::close`] is idempotent and the wait
/// can repeat, so calling it again on an already drained tracker returns as
/// soon as the tracker is observed empty.
///
/// `report_interval` must be non-zero. A zero cadence still drains, because
/// each round polls the tracker before its deadline is checked, but it spins
/// the loop and floods the log with one round per poll. Rejecting an
/// unusable cadence belongs to the settings that supply it.
///
/// # Errors
///
/// Returns [`LockPoisonedError`] if an internal tracker mutex is poisoned. A
/// poisoned lock is the one outcome this policy treats as a real error;
/// pending tasks are not.
pub async fn drain_with_report(
    tracker: &TaskTracker,
    report_interval: Duration,
    label: &str,
) -> Result<(), LockPoisonedError> {
    tracker.close()?;
    tracker.cancel_children();

    let mut round: u64 = 0;
    let mut reported_snapshot: Option<Vec<(u64, String)>> = None;
    loop {
        match tracker.drain(report_interval).await? {
            DrainOutcome::Drained => {
                if round > 0 {
                    info!("{label} drain complete after {round} pending round(s)");
                }
                return Ok(());
            }
            DrainOutcome::Pending(pending) => {
                round = round.saturating_add(1);
                report_pending_round(label, round, &pending, &mut reported_snapshot);
            }
        }
    }
}

/// Reports one drain round that timed out with tasks still pending.
///
/// Every round emits a single progress line, so a shutdown that is waiting is
/// always visible. The detailed snapshot is one line per task, and the wait is
/// unbounded, so repeating it every round would bury the log while the same
/// tasks hang; it is emitted only when the set of pending tasks differs from
/// the one last reported through `reported_snapshot`. Ages are left out of that
/// comparison because they advance every round and would make every snapshot
/// look changed.
fn report_pending_round(
    label: &str,
    round: u64,
    pending: &[PendingTaskSnapshot],
    reported_snapshot: &mut Option<Vec<(u64, String)>>,
) {
    warn!(
        "{label} drain round {round}: {} task(s) still pending",
        pending.len()
    );

    // The registry is a hash map, so order by id to keep both the comparison
    // and the report stable across rounds.
    let mut pending: Vec<&PendingTaskSnapshot> = pending.iter().collect();
    pending.sort_unstable_by_key(|task| task.id);
    let snapshot: Vec<(u64, String)> = pending
        .iter()
        .map(|task| (task.id, task.name.clone()))
        .collect();

    if reported_snapshot
        .as_ref()
        .is_some_and(|last| *last == snapshot)
    {
        return;
    }

    for task in pending {
        warn!(
            "  pending task id={id} name={:?} age={:?}",
            task.name,
            task.age,
            id = task.id,
        );
    }
    *reported_snapshot = Some(snapshot);
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io::{self, Write},
        sync::atomic::{AtomicBool, AtomicU32, AtomicUsize},
    };

    use tokio::{sync::oneshot, time::sleep};
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

    /// Installs a log-capturing subscriber for the current thread.
    fn capture_logs() -> (SharedLogBuffer, tracing::subscriber::DefaultGuard) {
        let logs = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(logs.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (logs, guard)
    }

    struct ReentrantPendingCountWriter {
        tracker: TaskTracker,
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
        tracker: TaskTracker,
        calls: Arc<AtomicUsize>,
    }

    impl ReentrantPendingCountBuffer {
        fn new(tracker: TaskTracker) -> (Self, Arc<AtomicUsize>) {
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
                tracker: self.tracker.clone(),
                calls: Arc::clone(&self.calls),
            }
        }
    }

    /// Reporting cadence used by the drain-loop tests. The tests run on a
    /// paused clock, so this is virtual time only — no test waits on it.
    const REPORT_INTERVAL: Duration = Duration::from_secs(5);
    /// Upper bound on how long a drain loop may take to finish once its tasks
    /// have been released. Also virtual time: a loop that fails to make
    /// progress cannot hang the test, it fails it.
    const DRAIN_LOOP_TIMEOUT: Duration = Duration::from_mins(10);
    /// Label the drain-loop tests report under. It is the one `main` uses for
    /// the top-level tracker, so the log lines these tests assert on are the
    /// lines a real shutdown emits.
    const TEST_DRAIN_LABEL: &str = "shutdown";
    /// Prefix of the per-round progress line `TEST_DRAIN_LABEL` produces.
    const DRAIN_ROUND_NEEDLE: &str = "shutdown drain round";

    fn count_lines_containing(output: &str, needle: &str) -> usize {
        output.lines().filter(|line| line.contains(needle)).count()
    }

    /// Spawns a task on `tracker` that stays pending until `release` fires,
    /// deliberately ignoring cancellation so the drain loop has to report
    /// progress across several rounds. The returned flag is set only if the
    /// task runs to the end, so an aborted task leaves it `false`.
    fn spawn_pending_task(
        tracker: &TaskTracker,
        name: &'static str,
        release: oneshot::Receiver<()>,
    ) -> (JoinHandle<()>, Arc<AtomicBool>) {
        let completed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&completed);
        let handle = tracker
            .spawn(name, move |_token| async move {
                let _ = release.await;
                flag.store(true, Ordering::SeqCst);
            })
            .expect("spawn should succeed");
        (handle, completed)
    }

    #[tokio::test(start_paused = true)]
    async fn drain_with_report_reports_each_round_until_drained() {
        let (logs, _guard) = capture_logs();

        let tracker = TaskTracker::new();
        let (release_tx, release_rx) = oneshot::channel();
        let (task_handle, completed) = spawn_pending_task(&tracker, "synthetic-top", release_rx);

        let drain = tokio::spawn({
            let tracker = tracker.clone();
            async move { drain_with_report(&tracker, REPORT_INTERVAL, TEST_DRAIN_LABEL).await }
        });

        // Virtual time: the clock only advances while every task is idle, so
        // this lets exactly two drain rounds expire without any wall-clock
        // wait, and releases the task while the third round is in flight.
        sleep(REPORT_INTERVAL * 2 + REPORT_INTERVAL / 2).await;
        assert!(!completed.load(Ordering::SeqCst));
        release_tx
            .send(())
            .expect("drain loop should still be waiting");

        tokio::time::timeout(DRAIN_LOOP_TIMEOUT, drain)
            .await
            .expect("drain loop should finish once the task returns")
            .expect("drain loop task should not panic")
            .expect("drain loop should not report a poisoned lock");

        // The task returned on its own; it was neither aborted nor dropped.
        task_handle
            .await
            .expect("task should not have been aborted");
        assert!(completed.load(Ordering::SeqCst));
        assert!(tracker.is_closed());
        assert_eq!(tracker.pending_count(), 0);

        let output = logs.contents();
        assert!(
            !output.contains("tracked task did not run to completion"),
            "no task should have been aborted, got: {output}"
        );

        // Every round reports progress ...
        assert!(
            output.contains("shutdown drain round 1: 1 task(s) still pending"),
            "round 1 should be reported, got: {output}"
        );
        assert!(
            output.contains("shutdown drain round 2: 1 task(s) still pending"),
            "round 2 should be reported, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, DRAIN_ROUND_NEEDLE),
            2,
            "exactly the pending rounds should be reported, got: {output}"
        );
        // ... while the unchanged detailed snapshot is logged only once.
        assert_eq!(
            count_lines_containing(&output, "pending task id="),
            1,
            "the unchanged snapshot should not be repeated, got: {output}"
        );
        assert!(
            output.contains("shutdown drain complete after 2 pending round(s)"),
            "completion should be reported, got: {output}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn drain_with_report_relogs_snapshot_when_pending_set_changes() {
        let (logs, _guard) = capture_logs();

        let tracker = TaskTracker::new();
        let (first_tx, first_rx) = oneshot::channel();
        let (second_tx, second_rx) = oneshot::channel();
        let (first_handle, first_done) = spawn_pending_task(&tracker, "synthetic-a", first_rx);
        let (second_handle, second_done) = spawn_pending_task(&tracker, "synthetic-b", second_rx);

        let drain = tokio::spawn({
            let tracker = tracker.clone();
            async move { drain_with_report(&tracker, REPORT_INTERVAL, TEST_DRAIN_LABEL).await }
        });

        // Two rounds see both tasks, then one task returns and the next round
        // sees a changed set.
        sleep(REPORT_INTERVAL * 2 + REPORT_INTERVAL / 2).await;
        first_tx
            .send(())
            .expect("drain loop should still be waiting");
        first_handle
            .await
            .expect("task should not have been aborted");
        sleep(REPORT_INTERVAL * 2).await;
        second_tx
            .send(())
            .expect("drain loop should still be waiting");

        tokio::time::timeout(DRAIN_LOOP_TIMEOUT, drain)
            .await
            .expect("drain loop should finish once the tasks return")
            .expect("drain loop task should not panic")
            .expect("drain loop should not report a poisoned lock");

        second_handle
            .await
            .expect("task should not have been aborted");
        assert!(first_done.load(Ordering::SeqCst));
        assert!(second_done.load(Ordering::SeqCst));

        let output = logs.contents();
        assert!(
            !output.contains("tracked task did not run to completion"),
            "no task should have been aborted, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, DRAIN_ROUND_NEEDLE),
            4,
            "each pending round should be reported, got: {output}"
        );
        // Round 1 lists both tasks, round 2 repeats nothing, and the round
        // after the set shrinks lists the one that is left.
        assert_eq!(
            count_lines_containing(&output, "pending task id="),
            3,
            "the snapshot should be relogged only when the set changes, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, "synthetic-a"),
            1,
            "the task that returned should be listed once, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, "synthetic-b"),
            2,
            "the remaining task should be listed in both snapshots, got: {output}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn drain_with_report_is_re_callable() {
        let tracker = TaskTracker::new();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        let handle = tracker
            .spawn("cooperative", move |token| async move {
                token.cancelled().await;
                flag.store(true, Ordering::SeqCst);
            })
            .expect("spawn should succeed");

        tokio::time::timeout(
            DRAIN_LOOP_TIMEOUT,
            drain_with_report(&tracker, REPORT_INTERVAL, TEST_DRAIN_LABEL),
        )
        .await
        .expect("a cooperative task should drain on the first round")
        .expect("drain loop should not report a poisoned lock");
        handle.await.expect("task should not have been aborted");
        assert!(cancelled.load(Ordering::SeqCst));

        // `close` is idempotent and the wait can repeat, so the drained
        // tracker can be handed to the loop again.
        tokio::time::timeout(
            DRAIN_LOOP_TIMEOUT,
            drain_with_report(&tracker, REPORT_INTERVAL, TEST_DRAIN_LABEL),
        )
        .await
        .expect("a second call should return immediately")
        .expect("drain loop should not report a poisoned lock");
    }

    /// A poisoned tracker lock ends the loop instead of being retried. Unlike
    /// a pending task, a poison never clears, so every later round would fail
    /// the same way and the loop would spin.
    ///
    /// The lock is poisoned the way `cancellation`'s own poison test does it:
    /// outside a runtime the inner `tasks.spawn` panics while the admission
    /// lock is held. That has to happen before any runtime is entered, so this
    /// test builds the runtime itself rather than using `#[tokio::test]`.
    #[test]
    fn drain_with_report_surfaces_a_poisoned_lock() {
        let tracker = TaskTracker::new();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tracker.spawn("no-runtime", |_token| async {});
        }));
        assert!(outcome.is_err(), "spawn outside a runtime should panic");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .expect("current-thread runtime should build");
        let result = runtime.block_on(async {
            tokio::time::timeout(
                DRAIN_LOOP_TIMEOUT,
                drain_with_report(&tracker, REPORT_INTERVAL, TEST_DRAIN_LABEL),
            )
            .await
            .expect("a poisoned lock should end the loop, not be retried")
        });

        assert_eq!(result, Err(LockPoisonedError));
    }

    #[test]
    fn report_pending_round_skips_unchanged_snapshot_and_relogs_changes() {
        let (logs, _guard) = capture_logs();

        let first = vec![
            PendingTaskSnapshot {
                id: 1,
                name: "task-one".to_string(),
                age: Duration::from_secs(1),
            },
            PendingTaskSnapshot {
                id: 0,
                name: "task-zero".to_string(),
                age: Duration::from_secs(2),
            },
        ];
        // Same tasks, different ages and iteration order: still unchanged.
        let unchanged = vec![
            PendingTaskSnapshot {
                id: 0,
                name: "task-zero".to_string(),
                age: Duration::from_secs(7),
            },
            PendingTaskSnapshot {
                id: 1,
                name: "task-one".to_string(),
                age: Duration::from_secs(7),
            },
        ];
        let changed = vec![PendingTaskSnapshot {
            id: 1,
            name: "task-one".to_string(),
            age: Duration::from_secs(9),
        }];

        let mut reported = None;
        report_pending_round(TEST_DRAIN_LABEL, 1, &first, &mut reported);
        report_pending_round(TEST_DRAIN_LABEL, 2, &unchanged, &mut reported);
        report_pending_round(TEST_DRAIN_LABEL, 3, &changed, &mut reported);

        let output = logs.contents();
        assert_eq!(count_lines_containing(&output, DRAIN_ROUND_NEEDLE), 3);
        assert_eq!(count_lines_containing(&output, "pending task id="), 3);

        // The first snapshot is ordered by id regardless of the order the
        // registry handed the tasks over in.
        let detail: Vec<&str> = output
            .lines()
            .filter(|line| line.contains("pending task id="))
            .collect();
        assert!(detail[0].contains("id=0"), "got: {output}");
        assert!(detail[1].contains("id=1"), "got: {output}");
        assert!(detail[2].contains("id=1"), "got: {output}");
    }

    /// A pending round can carry an empty snapshot: the registry may be
    /// emptied between the drain timing out and the snapshot being read. The
    /// round is still reported, and the empty snapshot does not suppress the
    /// next one that has tasks in it.
    #[test]
    fn report_pending_round_handles_an_empty_pending_snapshot() {
        let (logs, _guard) = capture_logs();

        let pending = vec![PendingTaskSnapshot {
            id: 0,
            name: "task-zero".to_string(),
            age: Duration::from_secs(1),
        }];

        let mut reported = None;
        report_pending_round(TEST_DRAIN_LABEL, 1, &[], &mut reported);
        report_pending_round(TEST_DRAIN_LABEL, 2, &pending, &mut reported);

        let output = logs.contents();
        assert!(
            output.contains("shutdown drain round 1: 0 task(s) still pending"),
            "an empty round should still be reported, got: {output}"
        );
        assert_eq!(
            count_lines_containing(&output, "pending task id="),
            1,
            "the empty snapshot should not suppress the next one, got: {output}"
        );
    }
    const THREAD_TEST_TIMEOUT: Duration = Duration::from_secs(1);
    const UNFINISHED_TASK_LOG: &str = "tracked task did not run to completion";

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

    fn expect_pending(outcome: DrainOutcome) -> Vec<PendingTaskSnapshot> {
        match outcome {
            DrainOutcome::Pending(pending) => pending,
            DrainOutcome::Drained => panic!("drain should not have completed yet"),
        }
    }

    // ── TaskTracker tests ───────────────────────────────────────────

    #[tokio::test]
    async fn spawn_and_complete() {
        let tracker = TaskTracker::new();
        let completed = Arc::new(AtomicBool::new(false));
        let completed2 = Arc::clone(&completed);

        let _handle = tracker
            .spawn("test-task", move |_token| async move {
                completed2.store(true, Ordering::Release);
            })
            .expect("spawn should succeed");

        let outcome = tracker
            .drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");
        assert_eq!(outcome, DrainOutcome::Drained);
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn spawn_receives_child_token() {
        let tracker = TaskTracker::new();
        let token_was_valid = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&token_was_valid);

        let _handle = tracker
            .spawn("token-check", move |token| async move {
                flag.store(!token.is_cancelled(), Ordering::Release);
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

        let _handle = tracker
            .spawn("cancel-watch", move |token| async move {
                token.cancelled().await;
                flag.store(true, Ordering::Release);
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

        let _handle = tracker
            .spawn("loop-task", move |token| async move {
                while !token.is_cancelled() {
                    counter.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            })
            .expect("spawn should succeed");

        // Let the task run a few iterations.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let outcome = tracker
            .cancel_and_drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");
        assert_eq!(outcome, DrainOutcome::Drained);
        assert!(iterations.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn drain_returns_pending_on_timeout() {
        let tracker = TaskTracker::new();

        let _handle = tracker
            .spawn("stuck-task", |_token| async {
                // Intentionally never completes and ignores cancellation.
                tokio::time::sleep(Duration::from_hours(1)).await;
            })
            .expect("spawn should succeed");

        // Give the task a moment to start.
        tokio::task::yield_now().await;

        let outcome = tracker
            .cancel_and_drain(Duration::from_millis(50))
            .await
            .expect("drain should not fail");
        let pending = expect_pending(outcome);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].name, "stuck-task");
        // The registry is the single source of truth for the pending count.
        assert_eq!(tracker.pending_count(), 1);
    }

    #[tokio::test]
    async fn drain_does_not_log_pending_tasks() {
        let tracker = TaskTracker::new();
        let _handle = tracker
            .spawn("stuck-task", |_token| async {
                tokio::time::sleep(Duration::from_hours(1)).await;
            })
            .expect("spawn should succeed");
        tokio::task::yield_now().await;

        let (logs, _guard) = capture_logs();
        let outcome = tracker
            .drain(Duration::from_millis(50))
            .await
            .expect("drain should not fail");
        assert_eq!(expect_pending(outcome).len(), 1);

        let output = logs.contents();
        assert!(
            !output.contains("still pending"),
            "drain must leave the reporting cadence to the caller, got: {output}"
        );
        assert!(output.is_empty(), "drain must not log on its own: {output}");
    }

    #[tokio::test]
    async fn with_token_uses_provided_root() {
        let root = CancellationToken::new();
        let tracker = TaskTracker::with_token(root.clone());
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&saw_cancel);

        let _handle = tracker
            .spawn("ext-token", move |token| async move {
                token.cancelled().await;
                flag.store(true, Ordering::Release);
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

    /// A child tracker inherits the parent's cancellation only when it is
    /// built from a token handed down by the parent. Neither the compiler nor
    /// a type signature catches the difference, so pin it with a test.
    #[tokio::test]
    async fn parent_cancellation_reaches_with_token_child_only() {
        let parent = TaskTracker::new();
        let inherited = TaskTracker::with_token(parent.create_child_token());
        let detached = TaskTracker::new();

        let inherited_flag = Arc::new(AtomicBool::new(false));
        let detached_flag = Arc::new(AtomicBool::new(false));

        for (tracker, name, flag) in [
            (&inherited, "inherited", Arc::clone(&inherited_flag)),
            (&detached, "detached", Arc::clone(&detached_flag)),
        ] {
            let _handle = tracker
                .spawn(name, move |token| async move {
                    token.cancelled().await;
                    flag.store(true, Ordering::Release);
                })
                .expect("spawn should succeed");
        }
        tokio::task::yield_now().await;

        parent.cancel_children();

        assert_eq!(
            inherited
                .drain(Duration::from_secs(1))
                .await
                .expect("drain should not fail"),
            DrainOutcome::Drained
        );
        assert!(inherited_flag.load(Ordering::Acquire));

        let pending = expect_pending(
            detached
                .drain(Duration::from_millis(50))
                .await
                .expect("drain should not fail"),
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].name, "detached");
        assert!(!detached_flag.load(Ordering::Acquire));

        // Its own root still cancels it.
        detached.cancel_children();
        assert_eq!(
            detached
                .drain(Duration::from_secs(1))
                .await
                .expect("drain should not fail"),
            DrainOutcome::Drained
        );
        assert!(detached_flag.load(Ordering::Acquire));
    }

    /// A tracked task carries a tracker clone and registers a task of its own
    /// in the same registry, as a connection task does for its streams.
    #[tokio::test]
    async fn tracked_task_clone_registers_nested_task() {
        let tracker = TaskTracker::new();
        let nested_cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&nested_cancelled);
        let nested_tracker = tracker.clone();
        let (spawned_tx, spawned_rx) = tokio::sync::oneshot::channel();

        let _handle = tracker
            .spawn("connection", move |_token| async move {
                let _nested = nested_tracker
                    .spawn("stream", move |token| async move {
                        token.cancelled().await;
                        flag.store(true, Ordering::Release);
                    })
                    .expect("nested spawn should succeed");
                spawned_tx.send(()).expect("receiver should be alive");
            })
            .expect("spawn should succeed");

        spawned_rx
            .await
            .expect("connection task should register the nested task");

        // The nested task is in the parent tracker's registry and drain waits
        // for it.
        let pending = expect_pending(
            tracker
                .drain(Duration::from_millis(50))
                .await
                .expect("drain should not fail"),
        );
        assert!(
            pending.iter().any(|task| task.name == "stream"),
            "nested task should be registered in the shared registry: {pending:?}"
        );

        tracker.cancel_children();
        assert_eq!(
            tracker
                .drain(Duration::from_secs(1))
                .await
                .expect("drain should not fail"),
            DrainOutcome::Drained
        );
        assert!(nested_cancelled.load(Ordering::Acquire));
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn clone_shares_close_state() {
        let tracker = TaskTracker::new();
        let clone = tracker.clone();

        tracker.close().expect("close should succeed");

        assert!(clone.is_closed());
        assert!(matches!(
            clone.spawn("late-task", |_token| async {}),
            Err(SpawnError::Closed)
        ));
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
            let _handle = tracker
                .spawn(format!("task-{i}"), move |_token| async move {
                    c.fetch_add(1, Ordering::Relaxed);
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
        let _handle = tracker
            .spawn("slow", |_token| async {
                tokio::time::sleep(Duration::from_hours(1)).await;
            })
            .expect("spawn should succeed");
        tokio::task::yield_now().await;
        assert_eq!(tracker.pending_count(), 1);

        let (logs, _guard) = capture_logs();

        tracker.log_pending().expect("log_pending should succeed");

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
        tracker.close().expect("close should succeed");
        let result = tracker.spawn("late-task", |_token| async {});
        assert!(matches!(result, Err(SpawnError::Closed)));
    }

    #[tokio::test]
    async fn spawn_after_cancel_and_drain_returns_error() {
        let tracker = TaskTracker::new();
        let _handle = tracker
            .spawn("normal-task", |_token| async {})
            .expect("spawn should succeed");

        tracker
            .cancel_and_drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");

        // Tracker is now closed; spawn must fail.
        let result = tracker.spawn("late-task", |_token| async {});
        assert!(matches!(result, Err(SpawnError::Closed)));
    }

    #[tokio::test]
    async fn close_does_not_cancel_existing_tasks() {
        let tracker = TaskTracker::new();
        let completed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&completed);

        let _handle = tracker
            .spawn("before-close", move |_token| async move {
                flag.store(true, Ordering::Release);
            })
            .expect("spawn should succeed");

        tracker.close().expect("close should succeed");
        tracker
            .drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");
        assert!(completed.load(Ordering::Acquire));
    }

    /// Staged shutdown: close ingress first, then signal live tasks, then
    /// wait. Tasks admitted before `close` still run their cleanup.
    #[tokio::test]
    async fn staged_shutdown_closes_cancels_then_drains() {
        let tracker = TaskTracker::new();
        let cleaned_up = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cleaned_up);

        let handle = tracker
            .spawn("worker", move |token| async move {
                token.cancelled().await;
                // Cleanup must happen before returning: `drain` ends only
                // when the task has returned, and `Drop` cannot await.
                tokio::task::yield_now().await;
                flag.store(true, Ordering::Release);
                "clean"
            })
            .expect("spawn should succeed");
        tokio::task::yield_now().await;

        // 1) refuse new spawns
        tracker.close().expect("close should succeed");
        assert!(matches!(
            tracker.spawn("late-task", |_token| async {}),
            Err(SpawnError::Closed)
        ));

        // 2) the worker is still running; drain has nothing to report yet
        assert_eq!(tracker.pending_count(), 1);

        // 3) signal live tasks, then 4) drain
        tracker.cancel_children();
        assert_eq!(
            tracker
                .drain(Duration::from_secs(1))
                .await
                .expect("drain should not fail"),
            DrainOutcome::Drained
        );

        assert!(cleaned_up.load(Ordering::Acquire));
        assert_eq!(handle.await.expect("task should not panic"), "clean");
        assert_eq!(tracker.pending_count(), 0);
    }

    // ── Panic cleanup tests ──────────────────────────────────────────

    #[tokio::test]
    async fn panicked_task_cleans_up_registry() {
        let tracker = TaskTracker::new();
        let handle = tracker
            .spawn("panicker", |_token| async {
                panic!("intentional panic in test");
            })
            .expect("spawn should succeed");

        let join_error = handle.await.expect_err("task should panic");

        assert!(join_error.is_panic());
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn drain_does_not_timeout_after_panic() {
        let tracker = TaskTracker::new();
        let handle = tracker
            .spawn("panicker", |_token| async {
                panic!("intentional panic in test");
            })
            .expect("spawn should succeed");

        let outcome = tracker
            .drain(Duration::from_millis(100))
            .await
            .expect("drain should not fail");
        assert_eq!(outcome, DrainOutcome::Drained, "drain should not time out");
        let join_error = handle.await.expect_err("task should panic");
        assert!(join_error.is_panic());
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test]
    async fn spawn_returns_join_handle_for_task_outcome() {
        let tracker = TaskTracker::new();
        let handle = tracker
            .spawn("outcome", |_token| async {
                Err::<(), String>("domain failure".to_string())
            })
            .expect("spawn should succeed");

        assert_eq!(
            handle.await.expect("task should not panic"),
            Err("domain failure".to_string())
        );
        tracker
            .drain(Duration::from_secs(1))
            .await
            .expect("drain should succeed");
    }

    /// The metadata a supervised handle carries outlives the registry entry
    /// it was copied from.
    ///
    /// The registration guard deregisters the task as it returns, which is the
    /// very moment a supervisor reads the handle back, so nothing about the
    /// task is recoverable from the tracker by then.
    #[tokio::test]
    async fn spawn_supervised_names_a_task_the_registry_has_forgotten() {
        let tracker = TaskTracker::new();
        let handle = tracker
            .spawn_supervised("supervised", |_token| async { 7_u32 })
            .expect("spawn should succeed");

        assert_eq!(handle.name(), "supervised");
        let id = handle.id();
        assert_eq!(handle.await.expect("task should not panic"), 7);

        // Re-read after the task returned: the registry is empty, and the
        // handle still answers.
        let handle = tracker
            .spawn_supervised(String::from("dynamic"), |_token| async { 8_u32 })
            .expect("spawn should succeed");
        assert_eq!(handle.id(), id + 1, "ids come from the same counter");
        assert_eq!(handle.name(), "dynamic", "a dynamic name is stored too");
        assert!(
            handle.age() <= Duration::from_secs(60),
            "the age is measured from the tracker's own spawn stamp"
        );
        assert_eq!(handle.await.expect("task should not panic"), 8);
        assert_eq!(tracker.pending_count(), 0);

        // The `Debug` rendering carries the same metadata, for a supervisor
        // that logs the handle rather than its fields.
        let handle = tracker
            .spawn_supervised("rendered", |_token| async {})
            .expect("spawn should succeed");
        let rendered = format!("{handle:?}");
        assert!(rendered.contains("rendered"), "got: {rendered}");
        assert!(rendered.contains("is_finished"), "got: {rendered}");
        handle.await.expect("task should not panic");
    }

    /// A supervised handle stands in for the `JoinHandle` it owns.
    ///
    /// A supervisor needs all three: `is_finished` to check readiness without
    /// awaiting, an abort handle to stop the task, and the join itself.
    #[tokio::test]
    async fn a_supervised_handle_forwards_the_join_handle_api() {
        // The abort below leaves a tracked task that never returned, which the
        // registration guard reports. Capturing here keeps that report inside a
        // subscriber: a callsite first reached from a thread that has none is
        // cached as uninteresting process-wide, and the tests that assert on
        // that very report then read an empty log.
        let (_logs, _guard) = capture_logs();
        let tracker = TaskTracker::new();
        let handle = tracker
            .spawn_supervised("forwarding", |token| async move {
                token.cancelled().await;
            })
            .expect("spawn should succeed");

        assert!(!handle.is_finished(), "the task is parked on its token");
        handle.abort_handle().abort();
        let error = handle.await.expect_err("an aborted task does not join");
        assert!(error.is_cancelled());

        let inner = tracker
            .spawn_supervised("inner", |_token| async { 1_u8 })
            .expect("spawn should succeed")
            .into_inner();
        assert_eq!(inner.await.expect("task should not panic"), 1);
    }

    /// The new entry point is additive: `spawn` keeps its signature and its
    /// return type, and the two share one id counter and one registry.
    #[tokio::test]
    async fn spawn_is_unaffected_by_the_supervised_entry_point() {
        let tracker = TaskTracker::new();
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let plain: JoinHandle<u8> = tracker
            .spawn("plain", |_token| async move {
                let _ = started_tx.send(());
                let _ = release_rx.await;
                3
            })
            .expect("spawn should succeed");
        started_rx
            .await
            .expect("the plain task should have started");

        let supervised = tracker
            .spawn_supervised("supervised", |_token| async { 4_u8 })
            .expect("spawn should succeed");
        assert_eq!(supervised.name(), "supervised");
        assert_eq!(supervised.await.expect("task should not panic"), 4);

        // Both are tracked by the one registry, so the drain waits for both.
        assert_eq!(tracker.pending_count(), 1);
        release_tx.send(()).expect("the plain task is waiting");
        assert_eq!(plain.await.expect("task should not panic"), 3);
        assert_eq!(
            tracker
                .drain(Duration::from_secs(1))
                .await
                .expect("drain should succeed"),
            DrainOutcome::Drained
        );
    }

    /// A supervised handle is cancelled by the tracker like any other task.
    #[tokio::test]
    async fn a_supervised_task_is_cancelled_with_the_tracker() {
        let tracker = TaskTracker::new();
        let handle = tracker
            .spawn_supervised("cancelled-with-tracker", |token| async move {
                token.cancelled().await;
                "stopped"
            })
            .expect("spawn should succeed");

        assert_eq!(
            tracker
                .cancel_and_drain(Duration::from_secs(5))
                .await
                .expect("drain should succeed"),
            DrainOutcome::Drained
        );
        assert_eq!(handle.await.expect("task should not panic"), "stopped");
    }

    #[test]
    fn panicking_task_factory_cleans_up_registry() {
        let tracker = TaskTracker::new();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tracker.spawn("factory-panics", |_token| {
                panic!("intentional panic while building future");
                #[allow(unreachable_code)]
                async {}
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

    // ── Contract safety net: tasks that did not run to the end ───────

    #[tokio::test]
    async fn panicked_task_is_reported_as_unfinished() {
        let (logs, _guard) = capture_logs();
        let tracker = TaskTracker::new();
        let handle = tracker
            .spawn("panicker", |_token| async {
                panic!("intentional panic in test");
            })
            .expect("spawn should succeed");
        handle.await.expect_err("task should panic");

        let output = logs.contents();
        assert!(output.contains(UNFINISHED_TASK_LOG), "got: {output}");
        assert!(output.contains(r#"name="panicker""#), "got: {output}");
        assert!(output.contains("age="), "got: {output}");
    }

    #[tokio::test]
    async fn aborted_task_is_reported_as_unfinished() {
        let (logs, _guard) = capture_logs();
        let tracker = TaskTracker::new();
        let handle = tracker
            .spawn("aborted", |_token| async {
                tokio::time::sleep(Duration::from_hours(1)).await;
            })
            .expect("spawn should succeed");
        tokio::task::yield_now().await;

        handle.abort();
        let join_error = handle.await.expect_err("task should be cancelled");
        assert!(join_error.is_cancelled());
        tokio::task::yield_now().await;

        let output = logs.contents();
        assert!(output.contains(UNFINISHED_TASK_LOG), "got: {output}");
        assert!(output.contains(r#"name="aborted""#), "got: {output}");
    }

    #[test]
    fn task_dropped_at_runtime_shutdown_is_reported_as_unfinished() {
        let tracker = TaskTracker::new();
        let polled = Arc::new(AtomicBool::new(false));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime should build");

        {
            let tracker = tracker.clone();
            let polled = Arc::clone(&polled);
            runtime.block_on(async move {
                let _handle = tracker
                    .spawn("never-polled", move |_token| {
                        let polled = Arc::clone(&polled);
                        async move {
                            polled.store(true, Ordering::Release);
                            tokio::task::yield_now().await;
                        }
                    })
                    .expect("spawn should succeed");
                // Return without yielding so the task remains queued on the
                // current-thread runtime and gets dropped during shutdown.
            });
        }

        let (logs, _guard) = capture_logs();
        drop(runtime);

        assert!(
            !polled.load(Ordering::Acquire),
            "task should be dropped before its first poll"
        );
        assert_eq!(tracker.pending_count(), 0);
        let output = logs.contents();
        assert!(output.contains(UNFINISHED_TASK_LOG), "got: {output}");
        assert!(output.contains(r#"name="never-polled""#), "got: {output}");
    }

    #[tokio::test]
    async fn task_returning_after_cancellation_is_not_reported() {
        let (logs, _guard) = capture_logs();
        let tracker = TaskTracker::new();
        let _handle = tracker
            .spawn("cooperative", |token| async move {
                token.cancelled().await;
            })
            .expect("spawn should succeed");
        tokio::task::yield_now().await;

        assert_eq!(
            tracker
                .cancel_and_drain(Duration::from_secs(1))
                .await
                .expect("drain should not fail"),
            DrainOutcome::Drained
        );

        let output = logs.contents();
        assert!(
            !output.contains(UNFINISHED_TASK_LOG),
            "a task that returned after cancellation kept the contract: {output}"
        );
    }

    // ── Admission-boundary tests ─────────────────────────────────────

    #[test]
    fn nested_spawn_in_future_factory_does_not_deadlock() {
        let (spawn_result, drain_result, nested_ran) = run_on_current_thread_runtime(async move {
            let tracker = TaskTracker::new();
            let nested_ran = Arc::new(AtomicBool::new(false));
            let outer_tracker = tracker.clone();
            let nested_flag = Arc::clone(&nested_ran);

            let result = tracker.spawn("outer", move |_token| {
                let inner_flag = Arc::clone(&nested_flag);
                let _handle = outer_tracker
                    .spawn("inner", move |_token| async move {
                        inner_flag.store(true, Ordering::Release);
                    })
                    .expect("nested spawn should succeed");
                async {}
            });

            let drained = tracker.drain(Duration::from_secs(1)).await;
            (
                result.is_ok(),
                drained.expect("drain should not fail"),
                nested_ran.load(Ordering::Acquire),
            )
        });
        assert!(spawn_result, "outer spawn should succeed");
        assert_eq!(drain_result, DrainOutcome::Drained);
        assert!(nested_ran, "nested task should run");
    }

    #[test]
    fn close_in_future_factory_returns_spawn_error_without_deadlock() {
        let (spawn_result, drain_result) = run_on_current_thread_runtime(async move {
            let tracker = TaskTracker::new();
            let tracker_for_factory = tracker.clone();

            // The factory closes the tracker before returning. With
            // serialized admission, the surrounding spawn observes the close
            // when it reaches the admission critical section and refuses to
            // admit the task.
            let result = tracker.spawn("close-from-factory", move |_token| {
                let _ = tracker_for_factory.close();
                async {}
            });

            let drained = tracker.drain(Duration::from_secs(1)).await;
            (
                matches!(result, Err(SpawnError::Closed)),
                drained.expect("drain should not fail"),
            )
        });
        assert!(
            spawn_result,
            "spawn must observe the close that happened inside the factory"
        );
        assert_eq!(drain_result, DrainOutcome::Drained);
    }

    // Stress regression for the admission race: many concurrent spawns
    // racing against a single close+drain must never leave an admitted task
    // unobserved by drain. Either spawn returns SpawnError, or the task is
    // tracked and drain waits for it.
    #[test]
    fn concurrent_spawn_and_close_never_escapes_drain() {
        for _ in 0..32 {
            let tracker = TaskTracker::new();
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
                let tracker_for_thread = tracker.clone();
                let observed_for_thread = Arc::clone(&observed);
                let admitted_count_for_thread = Arc::clone(&admitted_count);
                let runtime_for_thread = Arc::clone(&runtime);
                spawn_threads.push(std::thread::spawn(move || {
                    let _guard = runtime_for_thread.enter();
                    for _ in 0..16 {
                        let observed_for_task = Arc::clone(&observed_for_thread);
                        let result = tracker_for_thread.spawn("racer", move |_token| async move {
                            observed_for_task.fetch_add(1, Ordering::Relaxed);
                        });
                        if result.is_ok() {
                            admitted_count_for_thread.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }));
            }

            // Race the closer against the spawners.
            let tracker_for_close = tracker.clone();
            let runtime_for_close = Arc::clone(&runtime);
            let closer = std::thread::spawn(move || {
                runtime_for_close.block_on(async move {
                    assert_eq!(
                        tracker_for_close
                            .cancel_and_drain(Duration::from_secs(5))
                            .await
                            .expect("drain should not fail"),
                        DrainOutcome::Drained,
                        "drain should finish within timeout"
                    );
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

    /// A panic inside the admission critical section poisons the admission
    /// lock. The tracker then reports the poison as an error instead of
    /// panicking again — the right choice for a daemon — and the task that
    /// never reached the runtime is still deregistered.
    #[test]
    fn poisoned_admission_lock_surfaces_as_error() {
        let tracker = TaskTracker::new();

        // The inner `tasks.spawn` panics when no runtime is active, and it
        // runs while the admission lock is held, so the unwind poisons it.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tracker.spawn("no-runtime", |_token| async {});
        }));
        assert!(outcome.is_err(), "spawn outside a runtime should panic");
        assert_eq!(tracker.pending_count(), 0, "the guard should deregister");

        assert!(matches!(
            tracker.spawn("after-poison", |_token| async {}),
            Err(SpawnError::LockPoisoned)
        ));
        assert_eq!(tracker.close(), Err(LockPoisonedError));
    }

    // ── Miscellaneous ────────────────────────────────────────────────

    #[test]
    fn log_pending_with_no_tasks_emits_info() {
        let tracker = TaskTracker::new();

        let (logs, _guard) = capture_logs();

        tracker.log_pending().expect("log_pending should succeed");

        let output = logs.contents();
        assert!(output.contains("no pending tasks"));
    }

    #[test]
    fn task_tracker_default_creates_usable_tracker() {
        let tracker = TaskTracker::default();
        assert!(!tracker.is_closed());
        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn task_tracker_debug_format() {
        let tracker = TaskTracker::new();
        let s = format!("{tracker:?}");
        assert!(s.contains("TaskTracker"));
        assert!(s.contains("is_closed"));
    }

    #[test]
    fn spawn_error_display() {
        assert_eq!(
            SpawnError::Closed.to_string(),
            "tracker is closed; cannot spawn new tasks"
        );
        assert_eq!(
            SpawnError::LockPoisoned.to_string(),
            "task tracker lock was poisoned"
        );
    }

    #[test]
    fn lock_poisoned_error_display() {
        assert_eq!(
            LockPoisonedError.to_string(),
            "task tracker lock was poisoned"
        );
    }

    #[test]
    fn task_tracker_root_token_returns_root() {
        let tracker = TaskTracker::new();
        let token = tracker.root_token();
        assert!(!token.is_cancelled());
        tracker.cancel_children();
        assert!(token.is_cancelled());
    }

    #[test]
    fn log_pending_with_reentrant_writer_does_not_deadlock() {
        let write_calls = run_on_current_thread_runtime(async move {
            let tracker = TaskTracker::new();
            let _handle = tracker
                .spawn("slow", |_token| async {
                    tokio::time::sleep(Duration::from_hours(1)).await;
                })
                .expect("spawn should succeed");
            tokio::task::yield_now().await;

            let (writer, calls) = ReentrantPendingCountBuffer::new(tracker.clone());
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .without_time()
                .with_target(false)
                .with_writer(writer)
                .finish();
            let _guard = tracing::subscriber::set_default(subscriber);

            tracker.log_pending().expect("log_pending should succeed");
            calls.load(Ordering::Relaxed)
        });
        assert!(write_calls > 0, "log writer should be invoked");
    }
}
