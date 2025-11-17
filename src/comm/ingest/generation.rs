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
