use std::sync::Arc;
use std::time::Duration;

use sbx_proto::SandboxState;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::{now_unix, ControlPlane};

/// Run one sweep of idle-sleep and TTL-expiration reaping across all managed sandboxes.
pub async fn reap_once(cp: &ControlPlane) -> (usize, usize) {
    let now = now_unix();
    let mut to_destroy = Vec::new();
    let mut to_sleep = Vec::new();

    {
        let map = cp.sandboxes.lock().await;
        for (id, sbx) in map.iter() {
            let ttl = sbx.info.policy.max_ttl_sec;
            if ttl > 0
                && sbx.info.policy.auto_destroy
                && now.saturating_sub(sbx.info.created_at_unix) >= ttl
            {
                to_destroy.push(id.clone());
                continue;
            }
            let idle = sbx.info.policy.idle_sleep_sec;
            if sbx.info.state == SandboxState::Running
                && idle > 0
                && now.saturating_sub(sbx.info.last_active_unix) >= idle
            {
                to_sleep.push(id.clone());
            }
        }
    }

    let mut slept = 0;
    for id in to_sleep {
        if cp.sleep(&id).await.is_ok() {
            debug!(sandbox_id = %id, "auto-slept idle sandbox");
            slept += 1;
        }
    }

    let mut destroyed = 0;
    for id in to_destroy {
        if cp.destroy_sandbox(&id).await.is_ok() {
            info!(sandbox_id = %id, "reaped expired TTL sandbox");
            destroyed += 1;
        }
    }

    if let Some(ref ctrd) = cp.containerd {
        let _ = ctrd.reap_expired_leases().await;
    }

    (slept, destroyed)
}

/// Spawn periodic background reaper checking TTLs and idle sandboxes.
pub fn spawn_reaper_loop(
    cp: Arc<ControlPlane>,
    interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    let _ = reap_once(&cp).await;
                }
            }
        }
    })
}
