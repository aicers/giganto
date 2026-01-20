use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use chrono::{Datelike, Utc};

pub struct SequenceGenerator {
    counter: AtomicUsize,
    last_reset_date: AtomicU32,
}

impl SequenceGenerator {
    pub(crate) fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
            last_reset_date: AtomicU32::new(SequenceGenerator::get_current_date_time()),
        }
    }

    pub(crate) fn generate_sequence_number(&self) -> usize {
        let current_date_time = SequenceGenerator::get_current_date_time();
        let last_reset_day = self.last_reset_date.load(Ordering::Acquire);

        if last_reset_day == current_date_time {
            return self.counter.fetch_add(1, Ordering::Relaxed);
        }

        self.last_reset_date
            .store(current_date_time, Ordering::Release);
        self.counter.store(1, Ordering::Release);
        1
    }

    pub(crate) fn init_generator() -> Arc<SequenceGenerator> {
        let generator = SequenceGenerator::new();
        Arc::new(generator)
    }

    fn get_current_date_time() -> u32 {
        let utc_now = Utc::now();
        utc_now.day()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread;

    use super::*;

    fn set_last_reset_day_for_test(generator: &SequenceGenerator, day: u32) {
        generator.last_reset_date.store(day, Ordering::SeqCst);
    }

    #[test]
    fn test_sequence_generator_increment() {
        let generator = SequenceGenerator::new();
        assert_eq!(generator.generate_sequence_number(), 0);
        assert_eq!(generator.generate_sequence_number(), 1);
        assert_eq!(generator.generate_sequence_number(), 2);
    }

    #[test]
    fn test_sequence_generator_thread_safety() {
        let generator = Arc::new(SequenceGenerator::new());
        let mut handles = vec![];
        let num_threads = 10;
        let counts_per_thread = 100;

        for _ in 0..num_threads {
            let gen_clone = Arc::clone(&generator);
            let handle = thread::spawn(move || {
                let mut local_sequences = Vec::new();
                for _ in 0..counts_per_thread {
                    local_sequences.push(gen_clone.generate_sequence_number());
                }
                local_sequences
            });
            handles.push(handle);
        }

        let mut all_sequences = Vec::new();
        for handle in handles {
            all_sequences.extend(handle.join().unwrap());
        }

        assert_eq!(all_sequences.len(), num_threads * counts_per_thread);
        let unique_sequences: HashSet<_> = all_sequences.into_iter().collect();
        assert_eq!(unique_sequences.len(), num_threads * counts_per_thread);
        assert!(unique_sequences.contains(&0));
        assert!(unique_sequences.contains(&(num_threads * counts_per_thread - 1)));
    }

    #[test]
    fn test_init_generator() {
        let generator = SequenceGenerator::init_generator();
        assert_eq!(generator.generate_sequence_number(), 0);
    }

    #[test]
    fn test_get_current_date_time() {
        let date = SequenceGenerator::get_current_date_time();
        assert!((1..=31).contains(&date));
    }

    #[test]
    fn test_sequence_generator_reset() {
        let generator = SequenceGenerator::new();
        // Advance the counter to make reset behavior explicit.
        assert_eq!(generator.generate_sequence_number(), 0);
        assert_eq!(generator.generate_sequence_number(), 1);
        assert_eq!(generator.generate_sequence_number(), 2);

        // Force a different day to trigger reset.
        let today = SequenceGenerator::get_current_date_time();
        let different_day = if today == 31 { 1 } else { today + 1 };
        set_last_reset_day_for_test(&generator, different_day);

        // Next call: should detect date change, reset counter to 1, and return 1
        assert_eq!(generator.generate_sequence_number(), 1);

        // Subsequent call returns the previous value (fetch_add semantics).
        assert_eq!(generator.generate_sequence_number(), 1);

        // Next call: should return 2
        assert_eq!(generator.generate_sequence_number(), 2);
    }

    #[test]
    fn test_sequence_generator_reset_race() {
        let generator = Arc::new(SequenceGenerator::new());
        let today = SequenceGenerator::get_current_date_time();
        let different_day = if today == 31 { 1 } else { today + 1 };

        set_last_reset_day_for_test(&generator, different_day);

        let threads = 16;
        let mut handles = Vec::new();
        for _ in 0..threads {
            let gen_clone = Arc::clone(&generator);
            handles.push(thread::spawn(move || gen_clone.generate_sequence_number()));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        let unique: HashSet<_> = results.iter().copied().collect();
        assert!(unique.contains(&1));
        assert!(results.iter().all(|v| *v <= threads));
    }
}
