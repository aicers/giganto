use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use jiff::Zoned;

/// Thread-safe daily sequence generator.
///
/// State is packed in one `AtomicU64` as `[date_key:24 | counter:40]`, so reset and
/// increment are updated atomically with CAS (`fetch_update`).
///
/// - Resets to `[date_key, counter=1]` when `date_key` increases.
/// - Stale `date_key` values do not reset the state.
/// - Counter overflow resets counter to `1`.
/// - Canonical usage is `generate_sequence_number(get_date_key())`.
/// - For out-of-range `date_key` inputs, packing masks to 24 bits.
#[repr(align(64))]
pub struct SequenceGenerator {
    /// Packed state: `[date_key:24 | counter:40]`
    state: AtomicU64,
}

impl SequenceGenerator {
    const DATE_BITS: u32 = 24;
    const COUNTER_BITS: u32 = 40;

    const DATE_SHIFT: u32 = Self::COUNTER_BITS;

    const DATE_MASK: u32 = (1_u32 << Self::DATE_BITS) - 1;
    const COUNTER_MASK: u64 = (1_u64 << Self::COUNTER_BITS) - 1;

    const MAX_COUNTER: u64 = Self::COUNTER_MASK;

    /// Creates a new `SequenceGenerator` initialized with today's date and counter 0.
    pub(crate) fn new() -> Self {
        let today = Self::get_date_key();
        let initial_state = Self::pack(today, 0);
        Self {
            state: AtomicU64::new(initial_state),
        }
    }

    /// Returns the next packed sequence id (`[date:24 | counter:40]`).
    ///
    /// # Arguments
    ///
    /// * `date_key` - Caller-provided date key (`days since CE`).
    ///   The canonical and guaranteed-safe input is the return value of
    ///   [`Self::get_date_key()`], which is normalized to 24 bits.
    ///   If it is newer than the stored date, state resets to `[date_key, counter=1]`;
    ///   otherwise state keeps its date.
    ///   Out-of-range inputs are masked to 24 bits by the packed layout.
    pub(crate) fn generate_sequence_number(&self, date_key: u32) -> u64 {
        // fetch_update returns the previous value on success.
        let prev = self
            .state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(Self::next_state(current, date_key))
            })
            .expect("closure always returns Some");

        Self::next_state(prev, date_key)
    }

    #[inline]
    fn next_state(current: u64, date_key: u32) -> u64 {
        let (cur_date, cur_counter) = Self::unpack(current);

        if date_key > cur_date {
            Self::pack(date_key, 1)
        } else if cur_counter == Self::MAX_COUNTER {
            Self::pack(cur_date, 1)
        } else {
            Self::pack(cur_date, cur_counter + 1)
        }
    }

    /// Creates a new `Arc<SequenceGenerator>`.
    pub(crate) fn init_generator() -> Arc<SequenceGenerator> {
        Arc::new(SequenceGenerator::new())
    }

    /// Returns the current date key (`days since CE`).
    pub(crate) fn get_date_key() -> u32 {
        let now = Zoned::now();
        let date = now.date();
        let y = i32::from(date.year()) - 1;
        let ordinal = i32::from(date.day_of_year());
        let days = 365 * y + y / 4 - y / 100 + y / 400 + ordinal;
        let date_key: u32 = days.try_into().expect("date should be in valid range");
        Self::normalize_date_key(date_key)
    }

    /// Packs (`date_key`, `counter`) into one `u64`.
    ///
    /// Layout: `[date_key (24 bits) | counter (40 bits)]`
    #[inline]
    const fn pack(date_key: u32, counter: u64) -> u64 {
        (((date_key & Self::DATE_MASK) as u64) << Self::DATE_SHIFT) | (counter & Self::COUNTER_MASK)
    }

    /// Unpacks `u64` into (`date_key`, `counter`).
    #[inline]
    fn unpack(packed: u64) -> (u32, u64) {
        let date_key = u32::try_from((packed >> Self::DATE_SHIFT) & u64::from(Self::DATE_MASK))
            .expect("upper 24 bits are always representable as u32");
        let counter = packed & Self::COUNTER_MASK;
        (date_key, counter)
    }

    #[inline]
    /// Normalizes a raw date key into the supported 24-bit range.
    /// Used for values derived from time sources (e.g., `get_date_key`) and
    /// intentionally remains non-panicking by clamping overflow values.
    fn normalize_date_key(date_key: u32) -> u32 {
        if date_key > Self::DATE_MASK {
            Self::DATE_MASK
        } else {
            date_key
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::thread;

    use super::SequenceGenerator;

    mod fixture {
        use super::*;

        pub(super) fn set_state(generator: &SequenceGenerator, date_key: u32, counter: u64) {
            generator.state.store(
                SequenceGenerator::pack(date_key, counter),
                Ordering::Release,
            );
        }

        /// Sets the generator state to a past date with the given counter value.
        pub(super) fn set_to_yesterday(generator: &SequenceGenerator, counter: u64) {
            let old_date = SequenceGenerator::get_date_key().saturating_sub(1);
            set_state(generator, old_date, counter);
        }

        /// Spawns multiple threads that each generate sequence numbers concurrently.
        /// Returns all generated sequence numbers collected from all threads.
        pub(super) fn generate_sequences_concurrently(
            generator: &Arc<SequenceGenerator>,
            date_key: u32,
            num_threads: usize,
            iterations_per_thread: usize,
        ) -> Vec<u64> {
            let handles: Vec<_> = (0..num_threads)
                .map(|_| {
                    let seq_gen = Arc::clone(generator);
                    thread::spawn(move || {
                        (0..iterations_per_thread)
                            .map(|_| seq_gen.generate_sequence_number(date_key))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();

            handles
                .into_iter()
                .flat_map(|h| h.join().expect("thread panicked"))
                .collect()
        }

        /// Asserts that all sequences are unique and form a contiguous range.
        pub(super) fn assert_unique_range(
            sequences: &[u64],
            start: u64,
            total_count: usize,
            context: &str,
        ) {
            let unique: HashSet<_> = sequences.iter().copied().collect();
            assert_eq!(
                unique.len(),
                sequences.len(),
                "duplicate sequence numbers detected{context}"
            );
            for i in 0..total_count {
                let expected = start + (i as u64);
                assert!(
                    unique.contains(&expected),
                    "missing sequence number {expected}{context}"
                );
            }
        }

        pub(super) fn assert_sequence_parts(
            sequence: u64,
            expected_date: u32,
            expected_counter: u64,
        ) {
            let (date, counter) = SequenceGenerator::unpack(sequence);
            assert_eq!(date, expected_date);
            assert_eq!(counter, expected_counter);
        }

        pub(super) fn assert_state_parts(
            generator: &SequenceGenerator,
            expected_date: u32,
            expected_counter: u64,
        ) {
            let state = generator.state.load(Ordering::Relaxed);
            assert_sequence_parts(state, expected_date, expected_counter);
        }
    }

    use fixture::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let date_key = 739_000_u32;
        let counter = 12_345_u64;

        let packed = SequenceGenerator::pack(date_key, counter);
        let (unpacked_date, unpacked_counter) = SequenceGenerator::unpack(packed);

        assert_eq!(unpacked_date, date_key);
        assert_eq!(unpacked_counter, counter);
    }

    #[test]
    fn pack_unpack_edge_cases() {
        let packed = SequenceGenerator::pack(0, 0);
        let (date, counter) = SequenceGenerator::unpack(packed);
        assert_eq!(date, 0);
        assert_eq!(counter, 0);

        let packed =
            SequenceGenerator::pack(SequenceGenerator::DATE_MASK, SequenceGenerator::MAX_COUNTER);
        let (date, counter) = SequenceGenerator::unpack(packed);
        assert_eq!(date, SequenceGenerator::DATE_MASK);
        assert_eq!(counter, SequenceGenerator::MAX_COUNTER);
    }

    #[test]
    fn returns_incrementing_sequences_on_same_day() {
        let generator = SequenceGenerator::new();
        let today = SequenceGenerator::get_date_key();

        let seq1 = generator.generate_sequence_number(today);
        let seq2 = generator.generate_sequence_number(today);
        let seq3 = generator.generate_sequence_number(today);

        assert_sequence_parts(seq1, today, 1);
        assert_sequence_parts(seq2, today, 2);
        assert_sequence_parts(seq3, today, 3);
    }

    #[test]
    fn concurrent_requests_on_same_day_produce_unique_contiguous_sequences() {
        let generator = Arc::new(SequenceGenerator::new());
        let today = SequenceGenerator::get_date_key();
        let num_threads = 8;
        let iterations_per_thread = 1000;

        let all_sequences =
            generate_sequences_concurrently(&generator, today, num_threads, iterations_per_thread);

        assert_unique_range(
            &all_sequences,
            SequenceGenerator::pack(today, 1),
            num_threads * iterations_per_thread,
            "",
        );
    }

    #[test]
    fn after_date_change_concurrent_requests_start_at_one_without_duplicates() {
        let generator = SequenceGenerator::new();
        set_to_yesterday(&generator, 100);
        let today = SequenceGenerator::get_date_key();

        let generator = Arc::new(generator);
        let num_threads = 8;
        let iterations_per_thread = 100;

        let all_sequences =
            generate_sequences_concurrently(&generator, today, num_threads, iterations_per_thread);

        assert_unique_range(
            &all_sequences,
            SequenceGenerator::pack(today, 1),
            num_threads * iterations_per_thread,
            " after date reset",
        );
    }

    #[test]
    fn first_sequence_is_one_on_new_generator_and_after_date_reset() {
        let today = SequenceGenerator::get_date_key();

        let generator = SequenceGenerator::new();
        assert_state_parts(&generator, today, 0);
        assert_sequence_parts(generator.generate_sequence_number(today), today, 1);

        set_to_yesterday(&generator, 50);

        let first_after_reset = generator.generate_sequence_number(today);
        assert_sequence_parts(first_after_reset, today, 1);
    }

    #[test]
    fn get_date_key_matches_num_days_from_ce() {
        fn days_from_ce(date: jiff::civil::Date) -> u32 {
            let y = i32::from(date.year()) - 1;
            let ordinal = i32::from(date.day_of_year());
            let days = 365 * y + y / 4 - y / 100 + y / 400 + ordinal;
            days.try_into().expect("date should be positive")
        }

        let before = days_from_ce(jiff::Zoned::now().date());
        let date_key = SequenceGenerator::get_date_key();
        let after = days_from_ce(jiff::Zoned::now().date());

        assert!(
            (before..=after).contains(&date_key),
            "date_key should be within current day boundary window"
        );

        assert!(
            date_key > 730_000,
            "date_key {date_key} should be > 730,000 for dates after year 2000"
        );
    }

    #[test]
    fn get_date_key_always_returns_24bit_value() {
        let key = SequenceGenerator::get_date_key();
        assert!(
            key <= SequenceGenerator::DATE_MASK,
            "get_date_key must return a 24-bit date key"
        );
    }

    #[test]
    fn normalize_date_key_clamps_out_of_range_value() {
        let overflow = SequenceGenerator::DATE_MASK.saturating_add(1);
        let normalized = SequenceGenerator::normalize_date_key(overflow);
        assert_eq!(
            normalized,
            SequenceGenerator::DATE_MASK,
            "out-of-range date keys must be clamped"
        );
    }

    #[test]
    fn counter_wraps_to_one_after_reaching_u40_max() {
        let generator = SequenceGenerator::new();
        let today = SequenceGenerator::get_date_key();
        set_state(&generator, today, SequenceGenerator::MAX_COUNTER - 1);

        let seq = generator.generate_sequence_number(today);
        assert_sequence_parts(seq, today, SequenceGenerator::MAX_COUNTER);

        let seq2 = generator.generate_sequence_number(today);
        assert_sequence_parts(seq2, today, 1);
        assert_state_parts(&generator, today, 1);
    }

    #[test]
    fn on_concurrent_date_rollover_only_one_thread_obtains_sequence_one() {
        use std::sync::Barrier;

        let generator = SequenceGenerator::new();
        set_to_yesterday(&generator, 100);
        let today = SequenceGenerator::get_date_key();

        let generator = Arc::new(generator);
        let num_threads = 8;
        let barrier = Arc::new(Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let seq_gen = Arc::clone(&generator);
                let bar = Arc::clone(&barrier);
                thread::spawn(move || {
                    bar.wait();
                    seq_gen.generate_sequence_number(today)
                })
            })
            .collect();

        let all_sequences: Vec<u64> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();

        let first_seq = SequenceGenerator::pack(today, 1);
        assert_unique_range(
            &all_sequences,
            first_seq,
            num_threads,
            " during concurrent date rollover",
        );
        let first_count = all_sequences.iter().filter(|&&x| x == first_seq).count();
        assert_eq!(
            first_count, 1,
            "exactly one thread should get the first sequence after reset"
        );
    }

    #[test]
    fn older_date_key_does_not_move_state_date_backward() {
        let today = SequenceGenerator::get_date_key();

        let generator = SequenceGenerator::new();
        let future_date = today.saturating_add(10);
        set_state(&generator, future_date, 500);

        let seq = generator.generate_sequence_number(today);
        assert_sequence_parts(seq, future_date, 501);
        assert_state_parts(&generator, future_date, 501);
    }

    #[test]
    fn mixed_fresh_and_stale_date_keys_remain_unique_after_reset() {
        let generator = SequenceGenerator::new();
        let today = SequenceGenerator::get_date_key();
        let yesterday = today.saturating_sub(1);

        // Move state to yesterday and force a reset to today first.
        set_state(&generator, yesterday, 100);
        let first = generator.generate_sequence_number(today);
        assert_sequence_parts(first, today, 1);

        let generator = Arc::new(generator);
        let num_threads = 8;
        let iterations_per_thread = 200;
        let total = num_threads * iterations_per_thread;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let seq_gen = Arc::clone(&generator);
                let bar = Arc::clone(&barrier);
                thread::spawn(move || {
                    bar.wait();
                    let key = if i % 2 == 0 { today } else { yesterday };
                    (0..iterations_per_thread)
                        .map(|_| seq_gen.generate_sequence_number(key))
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        let all_sequences: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("thread panicked"))
            .collect();

        assert_unique_range(
            &all_sequences,
            SequenceGenerator::pack(today, 2),
            total,
            " with mixed stale/fresh date keys after reset",
        );
    }

    #[test]
    fn stale_date_key_increments_counter_without_resetting_date() {
        let today = SequenceGenerator::get_date_key();
        let generator = SequenceGenerator::new();
        let future_date = today.saturating_add(1);
        set_state(&generator, future_date, 41);

        let seq = generator.generate_sequence_number(today);
        assert_sequence_parts(seq, future_date, 42);
        assert_state_parts(&generator, future_date, 42);
    }

    #[test]
    fn stale_date_key_with_overflow_wraps_to_one_without_date_reset() {
        let today = SequenceGenerator::get_date_key();
        let generator = SequenceGenerator::new();
        let future_date = today.saturating_add(1);
        set_state(&generator, future_date, SequenceGenerator::MAX_COUNTER);

        let seq = generator.generate_sequence_number(today);
        assert_sequence_parts(seq, future_date, 1);
        assert_state_parts(&generator, future_date, 1);
    }

    #[test]
    fn after_midnight_rollover_old_date_key_does_not_trigger_second_reset() {
        let generator = SequenceGenerator::new();
        let today = SequenceGenerator::get_date_key();
        let tomorrow = today.saturating_add(1);

        assert_sequence_parts(generator.generate_sequence_number(today), today, 1);
        assert_sequence_parts(generator.generate_sequence_number(today), today, 2);

        let first_tomorrow = generator.generate_sequence_number(tomorrow);
        assert_sequence_parts(first_tomorrow, tomorrow, 1);

        let stale_today = generator.generate_sequence_number(today);
        assert_sequence_parts(stale_today, tomorrow, 2);
        assert_state_parts(&generator, tomorrow, 2);
    }

    #[test]
    fn out_of_range_date_key_is_masked_by_pack() {
        let generator = SequenceGenerator::new();
        let today = SequenceGenerator::get_date_key();
        set_state(&generator, today, 100);

        let invalid_date_key = SequenceGenerator::DATE_MASK + 1;
        let seq = generator.generate_sequence_number(invalid_date_key);

        // The `pack` layout masks date_key to 24 bits (2^24 -> 0).
        assert_sequence_parts(seq, 0, 1);
        assert_state_parts(&generator, 0, 1);
    }
}
