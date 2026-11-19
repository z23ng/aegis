use std::collections::{HashMap, VecDeque};

use sbx_proto::{BackendKind, SecurityPolicy};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::ManagedSandbox;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolBucketStats {
    pub image: String,
    pub backend: BackendKind,
    pub target_count: usize,
    pub ready_count: usize,
}

struct PoolBucket {
    target_count: usize,
    _policy: SecurityPolicy,
    ready: VecDeque<ManagedSandbox>,
}

/// Pre-warmed sandbox pool scheduler delivering sub-5ms sandbox acquisition on warm hits.
pub struct WarmPoolScheduler {
    buckets: Mutex<HashMap<(String, BackendKind), PoolBucket>>,
}

impl WarmPoolScheduler {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub async fn set_target(
        &self,
        image: &str,
        backend: BackendKind,
        policy: SecurityPolicy,
        target_count: usize,
    ) {
        let mut buckets = self.buckets.lock().await;
        let entry = buckets
            .entry((image.to_string(), backend))
            .or_insert_with(|| PoolBucket {
                target_count,
                _policy: policy.clone(),
                ready: VecDeque::new(),
            });
        entry.target_count = target_count;
        entry._policy = policy;
    }

    pub async fn deficit(&self, image: &str, backend: BackendKind) -> usize {
        let buckets = self.buckets.lock().await;
        buckets
            .get(&(image.to_string(), backend))
            .map_or(0, |b| b.target_count.saturating_sub(b.ready.len()))
    }

    pub(crate) async fn push_warm(&self, image: &str, backend: BackendKind, sbx: ManagedSandbox) {
        let mut buckets = self.buckets.lock().await;
        if let Some(b) = buckets.get_mut(&(image.to_string(), backend)) {
            b.ready.push_back(sbx);
        }
    }

    pub(crate) async fn pop_excess(&self, image: &str, backend: BackendKind) -> Vec<ManagedSandbox> {
        let mut buckets = self.buckets.lock().await;
        let mut removed = Vec::new();
        if let Some(b) = buckets.get_mut(&(image.to_string(), backend)) {
            while b.ready.len() > b.target_count {
                if let Some(item) = b.ready.pop_front() {
                    removed.push(item);
                }
            }
        }
        removed
    }

    pub(crate) async fn try_acquire(&self, image: &str, backend: BackendKind) -> Option<ManagedSandbox> {
        let mut buckets = self.buckets.lock().await;
        buckets
            .get_mut(&(image.to_string(), backend))
            .and_then(|b| b.ready.pop_front())
    }

    pub async fn stats(&self) -> Vec<PoolBucketStats> {
        let buckets = self.buckets.lock().await;
        let mut out: Vec<PoolBucketStats> = buckets
            .iter()
            .map(|((image, backend), b)| PoolBucketStats {
                image: image.clone(),
                backend: *backend,
                target_count: b.target_count,
                ready_count: b.ready.len(),
            })
            .collect();
        out.sort_by(|a, b| a.image.cmp(&b.image));
        out
    }

    pub(crate) async fn drain_all(&self) -> Vec<ManagedSandbox> {
        let mut buckets = self.buckets.lock().await;
        let mut all = Vec::new();
        for (_, mut b) in buckets.drain() {
            while let Some(item) = b.ready.pop_front() {
                all.push(item);
            }
        }
        all
    }
}

impl Default for WarmPoolScheduler {
    fn default() -> Self {
        Self::new()
    }
}
