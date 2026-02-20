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
/// - On initialization, the counter is stored as 0; the first generated sequence number
///   is 1 (the counter is incremented before returning)
/// - On daily reset, the counter is stored as 1 and returned directly, so the first
///   sequence number after a reset is also 1
/// - On overflow (`u32::MAX`), the counter rolls over to 1 (not 0) to maintain unique
///   non-zero sequence numbers
///
/// # Clock Rollback Handling
///
/// If the system clock is rolled back (e.g., NTP adjustment), the generator treats
/// the rollback as a date change and resets the counter, ensuring continued operation.
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
    /// On counter overflow, the counter rolls over to 1 to maintain unique non-zero
    /// sequence numbers. Note that after rollover, duplicate sequence numbers may
    /// occur within the same day if more than `u32::MAX` sequences are generated.
    pub(crate) fn generate_sequence_number(&self) -> usize {
        loop {
            // Recalculate `today` on each iteration to ensure correctness across
            // date transitions. If a CAS fails near midnight and the date changes
            // during the retry, we must use the updated date.
            let today = Self::get_date_key();
            let current = self.state.load(Ordering::Acquire);
            let (cur_date, cur_counter) = Self::unpack(current);

            // Check if date has changed (including clock rollback)
            let new_state = if cur_date == today {
                // Same date; increment counter, rolling over to 1 on overflow
                let new_counter = cur_counter.checked_add(1).unwrap_or(1);
                Self::pack(cur_date, new_counter)
            } else {
                // Date has changed; reset to (today, 1) - first sequence number
                Self::pack(today, 1)
            };

            if self
                .state
                .compare_exchange(current, new_state, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Self::unpack(new_state).1 as usize;
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
        // num_days_from_ce() returns i32, but it's always positive for dates after year 0.
        // The value grows by ~365 per year; for reference, year 2000 ≈ 730,000 days.
        // u32::MAX (~4.3 billion) can hold dates for millions of years.
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
    use std::sync::atomic::Ordering;
    use std::thread;

    use super::SequenceGenerator;

    /// Sets the generator state to a past date with the given counter value.
    /// Returns the old date key that was set.
    fn set_to_yesterday(generator: &SequenceGenerator, counter: u32) -> u32 {
        let old_date = SequenceGenerator::get_date_key().saturating_sub(1);
        let old_state = SequenceGenerator::pack(old_date, counter);
        generator.state.store(old_state, Ordering::Release);
        old_date
    }

    /// Spawns multiple threads that each generate sequence numbers concurrently.
    /// Returns all generated sequence numbers collected from all threads.
    fn generate_sequences_concurrently(
        generator: &Arc<SequenceGenerator>,
        num_threads: usize,
        iterations_per_thread: usize,
    ) -> Vec<usize> {
        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let seq_gen = Arc::clone(generator);
                thread::spawn(move || {
                    (0..iterations_per_thread)
                        .map(|_| seq_gen.generate_sequence_number())
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        handles
            .into_iter()
            .flat_map(|h| h.join().expect("thread panicked"))
            .collect()
    }

    /// Asserts that all sequences are unique and form a contiguous range from 1 to `total_count`.
    fn assert_unique_contiguous_sequences(sequences: &[usize], total_count: usize, context: &str) {
        let unique: HashSet<_> = sequences.iter().copied().collect();
        assert_eq!(
            unique.len(),
            sequences.len(),
            "duplicate sequence numbers detected{context}"
        );
        for i in 1..=total_count {
            assert!(unique.contains(&i), "missing sequence number {i}{context}");
        }
    }

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

        let all_sequences =
            generate_sequences_concurrently(&generator, num_threads, iterations_per_thread);

        assert_unique_contiguous_sequences(&all_sequences, num_threads * iterations_per_thread, "");
    }

    #[test]
    fn date_reset_produces_unique_sequences() {
        // Create generator with yesterday's date to simulate date change
        let generator = SequenceGenerator::new();
        set_to_yesterday(&generator, 100);

        // Spawn multiple threads that will all see the date change
        let generator = Arc::new(generator);
        let num_threads = 8;
        let iterations_per_thread = 100;

        let all_sequences =
            generate_sequences_concurrently(&generator, num_threads, iterations_per_thread);

        assert_unique_contiguous_sequences(
            &all_sequences,
            num_threads * iterations_per_thread,
            " after date reset",
        );
    }

    #[test]
    fn first_value_is_one_before_and_after_reset() {
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

        // Test 2: After reset, counter is set to 1, first sequence after reset is 1
        set_to_yesterday(&generator, 50);

        let first_after_reset = generator.generate_sequence_number();
        assert_eq!(
            first_after_reset, 1,
            "first sequence after reset should be 1"
        );
    }

    #[test]
    fn date_key_uses_full_date() {
        use chrono::{Datelike, Utc};

        // This test verifies that the date key matches the exact value from
        // num_days_from_ce(), ensuring the implementation uses the full date
        // (not just day-of-month or day-of-year).
        let date_key = SequenceGenerator::get_date_key();
        let now = Utc::now();

        // Compute the expected value directly using num_days_from_ce()
        let expected: u32 = now
            .num_days_from_ce()
            .try_into()
            .expect("date should be positive");

        assert_eq!(
            date_key, expected,
            "date_key should equal num_days_from_ce()"
        );

        // Additional sanity check: verify the value is reasonable for current era
        // (days since CE for year 2000+ should be > 730,000)
        assert!(
            date_key > 730_000,
            "date_key {date_key} should be > 730,000 for dates after year 2000"
        );
    }

    #[test]
    fn overflow_rolls_over_to_one() {
        // Set counter to u32::MAX to test overflow rollover
        let generator = SequenceGenerator::new();
        let today = SequenceGenerator::get_date_key();
        let near_overflow_state = SequenceGenerator::pack(today, u32::MAX);
        generator
            .state
            .store(near_overflow_state, Ordering::Release);

        // Generate should roll over to 1 instead of panicking
        let seq = generator.generate_sequence_number();
        assert_eq!(seq, 1, "overflow should roll over to 1");

        // Verify state was updated correctly
        let (date, counter) = SequenceGenerator::unpack(generator.state.load(Ordering::Acquire));
        assert_eq!(date, today, "date should remain unchanged");
        assert_eq!(counter, 1, "counter should be 1 after rollover");

        // Next sequence should be 2
        let seq2 = generator.generate_sequence_number();
        assert_eq!(seq2, 2, "sequence after rollover should continue normally");
    }

    #[test]
    fn concurrent_date_rollover_single_reset() {
        use std::sync::Barrier;
        use std::sync::atomic::AtomicUsize;

        // Create generator with yesterday's date
        let generator = SequenceGenerator::new();
        set_to_yesterday(&generator, 100);

        let generator = Arc::new(generator);
        let reset_count = Arc::new(AtomicUsize::new(0));
        let num_threads = 8;
        let barrier = Arc::new(Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let seq_gen = Arc::clone(&generator);
                let reset_counter = Arc::clone(&reset_count);
                let bar = Arc::clone(&barrier);
                thread::spawn(move || {
                    // Synchronize all threads to start at the same time
                    bar.wait();

                    // Each thread attempts to generate a sequence number
                    // We check if this thread sees itself doing the reset
                    let before = seq_gen.state.load(Ordering::Acquire);
                    let (before_date, _) = SequenceGenerator::unpack(before);
                    let today = SequenceGenerator::get_date_key();

                    let seq = seq_gen.generate_sequence_number();

                    // If before_date != today and we got seq == 1, this thread performed
                    // the reset. This is deterministic: only the thread whose CAS succeeded
                    // with the reset state (today, 1) will return sequence 1.
                    if before_date != today && seq == 1 {
                        reset_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    seq
                })
            })
            .collect();

        let mut all_sequences: Vec<usize> = Vec::new();
        for handle in handles {
            all_sequences.extend(std::iter::once(handle.join().expect("thread panicked")));
        }

        // Verify no duplicates - this is the critical correctness check
        let unique: HashSet<_> = all_sequences.iter().copied().collect();
        assert_eq!(
            unique.len(),
            all_sequences.len(),
            "duplicate sequence numbers detected during concurrent reset"
        );

        // Verify exactly one thread got sequence 1 (the reset sequence)
        let ones_count = all_sequences.iter().filter(|&&x| x == 1).count();
        assert_eq!(
            ones_count, 1,
            "exactly one thread should get sequence 1 after reset"
        );

        // The reset_count should be exactly 1 (the thread that did the reset)
        let resets = reset_count.load(Ordering::Relaxed);
        assert_eq!(
            resets, 1,
            "exactly one thread should observe it did the reset"
        );
    }

    #[test]
    fn clock_rollback_triggers_reset() {
        // Set generator to a future date to simulate clock rollback
        let generator = SequenceGenerator::new();
        let future_date = SequenceGenerator::get_date_key().saturating_add(10);
        let future_state = SequenceGenerator::pack(future_date, 500);
        generator.state.store(future_state, Ordering::Release);

        // Generate should reset due to date mismatch (clock went "backwards")
        let seq = generator.generate_sequence_number();
        assert_eq!(seq, 1, "clock rollback should trigger reset to 1");

        // Verify date was updated to today
        let (date, counter) = SequenceGenerator::unpack(generator.state.load(Ordering::Acquire));
        let today = SequenceGenerator::get_date_key();
        assert_eq!(date, today, "date should be updated to today");
        assert_eq!(counter, 1, "counter should be 1 after reset");
    }
}
