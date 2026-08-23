pub mod metrics;
pub mod online_tracker;

pub use online_tracker::OnlineTracker;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Counters {
    pub connections_total: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

impl Counters {
    pub fn add_conn(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_up(&self, n: u64) {
        self.bytes_up.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: u64) {
        self.bytes_down.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> HashMap<&'static str, u64> {
        let mut m = HashMap::new();
        m.insert(
            "connections",
            self.connections_total.load(Ordering::Relaxed),
        );
        m.insert("bytes_up", self.bytes_up.load(Ordering::Relaxed));
        m.insert("bytes_down", self.bytes_down.load(Ordering::Relaxed));
        m
    }
}
