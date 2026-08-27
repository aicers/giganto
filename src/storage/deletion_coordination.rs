//! Mutual exclusion between customer data deletion and retention cleanup.
//!
//! Both are bulk RocksDB range deletes over the same store, so at most one of
//! them may run at a time, and only one customer's deletion may run at once.
//! This module holds the state both sides consult: the GraphQL
//! `deleteCustomerData` resolver on one side and
//! [`retain_periodically`](super::retain_periodically) on the other.
//!
//! The state is one small enum behind a [`Mutex`]. That mutex is taken only to
//! read the enum and replace it — never across an `.await`, and never across
//! the RocksDB work itself. What outlives the critical section is a guard: an
//! RAII token whose `Drop` puts the state back to [`Activity::Idle`]. Every
//! terminal outcome therefore releases the claim, including the ones no
//! success path can be written for — a failed deletion, a panicking
//! supervisor, and a worker future that was built but never admitted to the
//! shutdown tracker.
//!
//! The two sides give way differently, and deliberately so. A deletion is a
//! request an operator is waiting on an answer to, so it is refused outright
//! and told which side of the exclusion turned it away. A retention cycle has
//! nobody waiting on it and nothing to lose by deferring: expired data stays
//! expired, so the cycle is skipped and the next tick deletes what this one
//! did not.

use std::sync::{
    Arc, Mutex, MutexGuard, PoisonError,
    atomic::{AtomicU64, Ordering},
};

/// Why the store could not be claimed for a customer's deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletionBlocked {
    /// This customer's own deletion is already in flight on this node.
    SameCustomer,
    /// Another customer's deletion is in flight.
    AnotherDeletion,
    /// A retention cleanup cycle is in flight.
    Retention,
}

/// What the store is currently busy with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Activity {
    #[default]
    Idle,
    /// A deletion for this customer is in flight.
    Deleting(u32),
    /// A retention cleanup cycle is in flight.
    Retaining,
}

/// The state customer deletion and retention agree on.
///
/// One instance per generation, shared by the GraphQL context and the
/// retention entry task. It is not persisted: a claim only ever describes work
/// running in this process, and a generation that ends takes its claims with
/// it.
#[derive(Debug, Default)]
pub struct CustomerDeletionCoordinator {
    activity: Mutex<Activity>,
    skipped_retention_cycles: AtomicU64,
}

impl CustomerDeletionCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Claims the store for `customer_id`'s deletion until the returned guard
    /// is dropped.
    ///
    /// # Errors
    ///
    /// Returns the [`DeletionBlocked`] reason the claim was refused for, which
    /// is what the resolver turns into its response: a repeat request for the
    /// customer already deleting is [`SameCustomer`](DeletionBlocked::SameCustomer),
    /// not a conflict.
    pub fn begin_deletion(
        self: &Arc<Self>,
        customer_id: u32,
    ) -> Result<DeletionGuard, DeletionBlocked> {
        let mut activity = self.lock_activity();
        match *activity {
            Activity::Idle => *activity = Activity::Deleting(customer_id),
            Activity::Deleting(active) if active == customer_id => {
                return Err(DeletionBlocked::SameCustomer);
            }
            Activity::Deleting(_) => return Err(DeletionBlocked::AnotherDeletion),
            Activity::Retaining => return Err(DeletionBlocked::Retention),
        }
        drop(activity);
        Ok(DeletionGuard {
            coordinator: Arc::clone(self),
        })
    }

    /// Claims the store for one retention cleanup cycle, or reports that the
    /// cycle has to be skipped.
    ///
    /// Returns `None` when a deletion owns the store. The refusal is counted,
    /// so a caller — or a test — can tell a cycle that gave way from one that
    /// never came due.
    pub fn begin_retention(self: &Arc<Self>) -> Option<RetentionGuard> {
        let mut activity = self.lock_activity();
        if *activity == Activity::Idle {
            *activity = Activity::Retaining;
            drop(activity);
            return Some(RetentionGuard {
                coordinator: Arc::clone(self),
            });
        }
        drop(activity);
        // Counted outside the lock: the counter is only ever read for
        // reporting, so it does not have to move with the state.
        self.skipped_retention_cycles
            .fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Returns how many retention cycles have given way to a deletion.
    #[must_use]
    pub fn skipped_retention_cycles(&self) -> u64 {
        self.skipped_retention_cycles.load(Ordering::Relaxed)
    }

    /// Locks the activity state, reading through a poisoned lock.
    ///
    /// The only code that takes this lock is the four-line state machine
    /// above, so a poisoned lock still holds a valid [`Activity`]. Refusing to
    /// read it would strand the store as claimed forever, which is the one
    /// outcome worse than the panic that poisoned it.
    fn lock_activity(&self) -> MutexGuard<'_, Activity> {
        self.activity.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn release(&self) {
        *self.lock_activity() = Activity::Idle;
    }
}

/// The store, claimed for one customer's deletion.
///
/// Held for the whole of the deletion — the blocking RocksDB range deletes,
/// the runtime cleanup that follows, and the terminal status write — and
/// dropped exactly once, however that work ends.
#[derive(Debug)]
#[must_use = "dropping the guard releases the store to retention and other customers"]
pub struct DeletionGuard {
    coordinator: Arc<CustomerDeletionCoordinator>,
}

impl Drop for DeletionGuard {
    fn drop(&mut self) {
        self.coordinator.release();
    }
}

/// The store, claimed for one retention cleanup cycle.
#[derive(Debug)]
#[must_use = "dropping the guard releases the store to customer deletion"]
pub struct RetentionGuard {
    coordinator: Arc<CustomerDeletionCoordinator>,
}

impl Drop for RetentionGuard {
    fn drop(&mut self) {
        self.coordinator.release();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{CustomerDeletionCoordinator, DeletionBlocked};

    fn coordinator() -> Arc<CustomerDeletionCoordinator> {
        Arc::new(CustomerDeletionCoordinator::new())
    }

    #[test]
    fn an_idle_store_admits_either_side() {
        let coordinator = coordinator();
        drop(coordinator.begin_deletion(1).expect("idle store"));
        drop(coordinator.begin_retention().expect("idle store"));
        assert_eq!(coordinator.skipped_retention_cycles(), 0);
    }

    #[test]
    fn a_deletion_in_flight_refuses_every_other_claim() {
        let coordinator = coordinator();
        let guard = coordinator.begin_deletion(1).expect("idle store");

        assert_eq!(
            coordinator.begin_deletion(1).unwrap_err(),
            DeletionBlocked::SameCustomer
        );
        assert_eq!(
            coordinator.begin_deletion(2).unwrap_err(),
            DeletionBlocked::AnotherDeletion
        );
        assert!(coordinator.begin_retention().is_none());
        assert_eq!(coordinator.skipped_retention_cycles(), 1);

        drop(guard);
        drop(
            coordinator
                .begin_deletion(2)
                .expect("the store was released"),
        );
        assert!(coordinator.begin_retention().is_some());
    }

    #[test]
    fn a_retention_cycle_in_flight_refuses_deletion() {
        let coordinator = coordinator();
        let guard = coordinator.begin_retention().expect("idle store");

        assert_eq!(
            coordinator.begin_deletion(1).unwrap_err(),
            DeletionBlocked::Retention
        );

        drop(guard);
        drop(
            coordinator
                .begin_deletion(1)
                .expect("the store was released"),
        );
    }

    /// A guard dropped by unwinding releases the store the same way a guard
    /// dropped on the success path does.
    #[test]
    fn a_panic_under_a_guard_releases_the_store() {
        let coordinator = coordinator();
        let panicked = std::panic::catch_unwind({
            let coordinator = Arc::clone(&coordinator);
            move || {
                let _guard = coordinator.begin_deletion(7).expect("idle store");
                panic!("injected panic while the store was claimed");
            }
        });

        assert!(panicked.is_err());
        drop(
            coordinator
                .begin_deletion(8)
                .expect("unwinding released the store"),
        );
    }

    /// The counter separates a cycle that gave way from one that never came
    /// due, which is what lets a test wait for the skip instead of sleeping
    /// past it.
    #[test]
    fn only_refused_retention_cycles_are_counted() {
        let coordinator = coordinator();
        drop(coordinator.begin_retention().expect("idle store"));
        assert_eq!(coordinator.skipped_retention_cycles(), 0);

        let guard = coordinator.begin_deletion(1).expect("idle store");
        assert!(coordinator.begin_retention().is_none());
        assert!(coordinator.begin_retention().is_none());
        assert_eq!(coordinator.skipped_retention_cycles(), 2);

        drop(guard);
        drop(
            coordinator
                .begin_retention()
                .expect("the store was released"),
        );
        assert_eq!(coordinator.skipped_retention_cycles(), 2);
    }
}
