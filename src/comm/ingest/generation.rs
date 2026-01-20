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
        // First call: initial state (0)
        assert_eq!(generator.generate_sequence_number(), 0);

        // Manually manipulate the last_reset_date to simulate a "yesterday"
        // Use a value that is definitely different from today (e.g., today + 1 mod 31 + 1)
        let today = SequenceGenerator::get_current_date_time();
        let different_day = if today == 1 { 2 } else { 1 };
        generator
            .last_reset_date
            .store(different_day, Ordering::SeqCst);

        // Next call: should detect date change, reset counter to 1, and return 1
        assert_eq!(generator.generate_sequence_number(), 1);

        // Subsequent call: should increment from 1, so fetch_add(1) returns 1
        assert_eq!(generator.generate_sequence_number(), 1);

        // Next call: should return 2
        assert_eq!(generator.generate_sequence_number(), 2);
    }
}
