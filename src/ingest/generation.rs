use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{Datelike, FixedOffset, Utc};

pub struct SequenceGenerator {
    counter: AtomicUsize,
    last_reset_date: Mutex<u32>,
}

impl SequenceGenerator {
    pub(crate) fn new() -> Self {
        Self {
            counter: AtomicUsize::new(1),
            last_reset_date: Mutex::new(SequenceGenerator::get_current_date_time()),
        }
    }

    pub(crate) fn generate_sequence_number(&self) -> usize {
        let current_date_time = SequenceGenerator::get_current_date_time();
        {
            let mut last_reset_day = self
                .last_reset_date
                .lock()
                .expect("last_reset_date should be exist.");

            if *last_reset_day != current_date_time {
                self.counter.store(1, Ordering::Release);
                *last_reset_day = current_date_time;
            }
        }
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn init_generator() -> Arc<SequenceGenerator> {
        let generator = SequenceGenerator::new();
        Arc::new(generator)
    }

    pub(crate) fn get_current_date_time() -> u32 {
        let utc_now = Utc::now();
        // east_opt is always exists.
        let utc_9_offset = FixedOffset::east_opt(9 * 3600).unwrap();
        let current_date_time = utc_now.with_timezone(&utc_9_offset);
        current_date_time.day()
    }
}
