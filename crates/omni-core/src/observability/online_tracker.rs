use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct OnlineTracker {
    by_user: DashMap<String, i64>,
    total: AtomicU64,
}

impl OnlineTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn mark_online(&self, user: &str) {
        let prev = self
            .by_user
            .entry(user.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        if *prev == 1 {
            self.total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn mark_offline(&self, user: &str) {
        if let Some(mut c) = self.by_user.get_mut(user) {
            *c -= 1;
            if *c <= 0 {
                drop(c);
                self.total.fetch_sub(1, Ordering::Relaxed);
                self.by_user.remove_if(user, |_, v| v <= &mut 0);
            }
        }
    }

    pub fn snapshot(&self) -> HashMap<String, i64> {
        self.by_user
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect()
    }

    pub fn online_total(&self) -> u64 {
        self.total.load(Ordering::Relaxed).max(0) as u64
    }
}
