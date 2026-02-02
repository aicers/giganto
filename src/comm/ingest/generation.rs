use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{Datelike, Utc};

/// A thread-safe sequence number generator that resets daily.
///
/// The generator uses a single `AtomicU64` to pack both the date key (upper 32 bits)
/// and the counter (lower 32 bits). This allows atomic reset operations using
/// compare-and-swap to prevent duplicate sequence numbers under concurrent access.
///
/// # Date Key
///
/// The date key is computed as days since the Common Era (CE), which provides a
/// monotonically increasing value that correctly handles month and year boundaries.
///
/// # Sequence Numbers
///
/// - Counter starts at 0 on initialization and after each daily reset
/// - First generated sequence number is 1 (counter is incremented before returning)
/// - Maximum sequence number per day is `u32::MAX`
pub struct SequenceGenerator {
    /// Packed state: upper 32 bits = `date_key`, lower 32 bits = counter
    state: AtomicU64,
}

impl SequenceGenerator {
    /// Creates a new `SequenceGenerator` initialized with today's date and counter at 0.
    pub(crate) fn new() -> Self {
        let today = Self::get_date_key();
        let initial_state = Self::pack(today, 0);
        Self {
            state: AtomicU64::new(initial_state),
        }
    }

    /// Generates the next sequence number, resetting if the date has changed.
    ///
    /// This method is thread-safe and ensures:
    /// - Only one thread performs the reset when the date changes
    /// - No duplicate sequence numbers are generated during concurrent resets
    /// - Sequence numbers start from 1 each day
    ///
    /// # Panics
    ///
    /// Panics if the counter overflows (exceeds `u32::MAX`).
    pub(crate) fn generate_sequence_number(&self) -> usize {
        let today = Self::get_date_key();

        loop {
            let current = self.state.load(Ordering::Acquire);
            let (cur_date, _cur_counter) = Self::unpack(current);

            if cur_date != today {
                // Date has changed; attempt to reset to (today, 0)
                let desired = Self::pack(today, 0);
                if self
                    .state
                    .compare_exchange(current, desired, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    // Another thread beat us; retry the loop
                    continue;
                }
                // Reset successful; now increment to get the first sequence number (1)
            }

            // Increment counter atomically
            // We use a compare-exchange loop to ensure we only increment if state hasn't changed
            let current = self.state.load(Ordering::Acquire);
            let (date, counter) = Self::unpack(current);

            // If date changed again while we were processing, retry
            if date != today {
                continue;
            }

            let new_counter = counter
                .checked_add(1)
                .expect("sequence counter overflow: exceeded u32::MAX");
            let new_state = Self::pack(date, new_counter);

            if self
                .state
                .compare_exchange(current, new_state, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return new_counter as usize;
            }
            // CAS failed; another thread modified state, retry
        }
    }

    /// Creates a new `Arc<SequenceGenerator>`.
    pub(crate) fn init_generator() -> Arc<SequenceGenerator> {
        Arc::new(SequenceGenerator::new())
    }

    /// Returns the current date as days since the Common Era.
    ///
    /// This provides a stable, monotonically increasing value that correctly
    /// handles month and year boundaries (e.g., January 15 → February 15 are different).
    fn get_date_key() -> u32 {
        let utc_now = Utc::now();
        // num_days_from_ce() returns i32, but it's always positive for dates after year 0
        // For year 2025, this is approximately 739,000, well within u32 range
        utc_now
            .num_days_from_ce()
            .try_into()
            .expect("date should be in valid range")
    }

    /// Packs a date key and counter into a single u64.
    ///
    /// Layout: `[date_key (32 bits) | counter (32 bits)]`
    #[inline]
    const fn pack(date_key: u32, counter: u32) -> u64 {
        ((date_key as u64) << 32) | (counter as u64)
    }

    /// Unpacks a u64 into (`date_key`, counter).
    #[inline]
    const fn unpack(packed: u64) -> (u32, u32) {
        let date_key = (packed >> 32) as u32;
        let counter = (packed & 0xFFFF_FFFF) as u32;
        (date_key, counter)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread;

    use super::SequenceGenerator;

    #[test]
    fn pack_unpack_roundtrip() {
        // Test that pack and unpack are inverses
        let date_key = 739_000_u32; // Approximate days since CE for year 2025
        let counter = 12345_u32;

        let packed = SequenceGenerator::pack(date_key, counter);
        let (unpacked_date, unpacked_counter) = SequenceGenerator::unpack(packed);

        assert_eq!(unpacked_date, date_key);
        assert_eq!(unpacked_counter, counter);
    }

    #[test]
    fn pack_unpack_edge_cases() {
        // Test with zero values
        let packed = SequenceGenerator::pack(0, 0);
        let (date, counter) = SequenceGenerator::unpack(packed);
        assert_eq!(date, 0);
        assert_eq!(counter, 0);

        // Test with max values
        let packed = SequenceGenerator::pack(u32::MAX, u32::MAX);
        let (date, counter) = SequenceGenerator::unpack(packed);
        assert_eq!(date, u32::MAX);
        assert_eq!(counter, u32::MAX);
    }

    #[test]
    fn sequential_generation() {
        let generator = SequenceGenerator::new();

        // Generate several sequence numbers and verify they are sequential
        let seq1 = generator.generate_sequence_number();
        let seq2 = generator.generate_sequence_number();
        let seq3 = generator.generate_sequence_number();

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);
    }

    #[test]
    fn concurrent_generation_no_duplicates() {
        let generator = Arc::new(SequenceGenerator::new());
        let num_threads = 8;
        let iterations_per_thread = 1000;

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let seq_gen = Arc::clone(&generator);
                thread::spawn(move || {
                    let mut results = Vec::with_capacity(iterations_per_thread);
                    for _ in 0..iterations_per_thread {
                        results.push(seq_gen.generate_sequence_number());
                    }
                    results
                })
            })
            .collect();

        let mut all_sequences: Vec<usize> = Vec::new();
        for handle in handles {
            all_sequences.extend(handle.join().expect("thread panicked"));
        }

        // Verify no duplicates
        let unique: HashSet<_> = all_sequences.iter().copied().collect();
        assert_eq!(
            unique.len(),
            all_sequences.len(),
            "duplicate sequence numbers detected"
        );

        // Verify all expected values are present (1 to total_count)
        let total_count = num_threads * iterations_per_thread;
        for i in 1..=total_count {
            assert!(unique.contains(&i), "missing sequence number {i}");
        }
    }

    #[test]
    fn date_reset_produces_unique_sequences() {
        use std::sync::atomic::Ordering;

        // Create generator with yesterday's date to simulate date change
        let generator = SequenceGenerator::new();

        // Manually set state to an old date with counter at 100
        let old_date = SequenceGenerator::get_date_key().saturating_sub(1);
        let old_state = SequenceGenerator::pack(old_date, 100);
        generator.state.store(old_state, Ordering::Release);

        // Spawn multiple threads that will all see the date change
        let generator = Arc::new(generator);
        let num_threads = 8;
        let iterations_per_thread = 100;

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let seq_gen = Arc::clone(&generator);
                thread::spawn(move || {
                    let mut results = Vec::with_capacity(iterations_per_thread);
                    for _ in 0..iterations_per_thread {
                        results.push(seq_gen.generate_sequence_number());
                    }
                    results
                })
            })
            .collect();

        let mut all_sequences: Vec<usize> = Vec::new();
        for handle in handles {
            all_sequences.extend(handle.join().expect("thread panicked"));
        }

        // Verify no duplicates after reset
        let unique: HashSet<_> = all_sequences.iter().copied().collect();
        assert_eq!(
            unique.len(),
            all_sequences.len(),
            "duplicate sequence numbers detected after date reset"
        );

        // Verify sequences start from 1 (after reset)
        let total_count = num_threads * iterations_per_thread;
        for i in 1..=total_count {
            assert!(
                unique.contains(&i),
                "missing sequence number {i} after reset"
            );
        }
    }

    #[test]
    fn start_value_policy_consistency() {
        use std::sync::atomic::Ordering;

        // Test 1: Fresh generator starts counter at 0, first sequence is 1
        let generator = SequenceGenerator::new();
        let (_, initial_counter) =
            SequenceGenerator::unpack(generator.state.load(Ordering::Acquire));
        assert_eq!(initial_counter, 0, "initial counter should be 0");
        assert_eq!(
            generator.generate_sequence_number(),
            1,
            "first sequence should be 1"
        );

        // Test 2: After reset, counter goes to 0, first sequence after reset is 1
        let old_date = SequenceGenerator::get_date_key().saturating_sub(1);
        let old_state = SequenceGenerator::pack(old_date, 50);
        generator.state.store(old_state, Ordering::Release);

        let first_after_reset = generator.generate_sequence_number();
        assert_eq!(
            first_after_reset, 1,
            "first sequence after reset should be 1"
        );
    }

    #[test]
    fn date_key_uses_full_date() {
        // This test verifies that different months with the same day-of-month
        // produce different date keys. We can't easily test real date changes,
        // but we verify the date key computation uses num_days_from_ce().
        let date_key = SequenceGenerator::get_date_key();

        // The date key should be around 739,000 for year 2025
        // (365.25 * 2025 ≈ 739,000)
        assert!(
            date_key > 700_000,
            "date_key should be large (days since CE)"
        );
        assert!(
            date_key < 800_000,
            "date_key should be reasonable for current era"
        );
    }
}
