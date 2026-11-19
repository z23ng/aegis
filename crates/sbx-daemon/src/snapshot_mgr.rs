use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sbx_containerd::{compute_dir_diff, PreparedRootfs};
use sbx_net::SecretVault;
use sbx_proto::{
    CheckpointMeta, FsDiffEntry, SandboxId, SandboxState, SecurityPolicy, SnapshotMeta,
};
use sbx_runtime::{copy_dir_recursive, SandboxRuntimeConfig};
use tokio::sync::Mutex;

use crate::{now_unix, ControlPlane, ManagedSandbox, SandboxInfo};

#[derive(Clone)]
struct StoredSnapshot {
    meta: SnapshotMeta,
    image: String,
    policy: SecurityPolicy,
    local_fs_dir: Option<PathBuf>,
    containerd_backed: bool,
}

#[derive(Clone)]
struct StoredCheckpoint {
    meta: CheckpointMeta,
    ckpt_dir: PathBuf,
    policy: SecurityPolicy,
    env: Vec<(String, String)>,
}

/// Orchestrates step-level snapshots (`OP_FREEZE` -> commit -> `OP_THAW`), filesystem diffs,
/// rollback, parallel CoW fork, and memory+state checkpoint/restore.
pub struct SnapshotManager {
    data_root: PathBuf,
    snapshots: Mutex<HashMap<String, StoredSnapshot>>,
    checkpoints: Mutex<HashMap<String, StoredCheckpoint>>,
    seq: AtomicU64,
}

impl SnapshotManager {
    pub fn new(data_root: PathBuf) -> Self {
        Self {
            data_root,
            snapshots: Mutex::new(HashMap::new()),
            checkpoints: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(1),
        }
    }

    pub async fn create_snapshot(
        &self,
        cp: &ControlPlane,
        sandbox_id: &str,
        label: Option<String>,
    ) -> Result<SnapshotMeta> {
        let (handle, mounts, chain_id, image, policy, local_upper) = {
            let map = cp.sandboxes.lock().await;
            let sbx = map
                .get(sandbox_id)
                .with_context(|| format!("sandbox '{sandbox_id}' not found"))?;
            (
                Arc::clone(&sbx.handle),
                sbx.mounts.clone(),
                sbx.chain_id.clone(),
                sbx.info.image.clone(),
                sbx.info.policy.clone(),
                sbx.local_upper_dir.clone(),
            )
        };

        handle.freeze().await?;

        let ttl = Duration::from_secs(policy.max_ttl_sec.max(3600));
        let res = if let Some(ctrd) = &cp.containerd {
            match ctrd
                .create_step_snapshot(sandbox_id, &chain_id, &mounts, label.as_deref(), ttl)
                .await
            {
                Ok(meta) => Ok((meta, None, true)),
                Err(e) => Err(e),
            }
        } else {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            let now = now_unix();
            let snap_id = format!("snap-{sandbox_id}-{now}-{seq}");
            let snap_fs = self.data_root.join("snapshots").join(&snap_id).join("fs");
            std::fs::create_dir_all(&snap_fs)?;
            if let Some(upper) = local_upper {
                if upper.is_dir() {
                    copy_dir_recursive(&upper, &snap_fs)?;
                }
            }
            let meta = SnapshotMeta {
                id: snap_id,
                sandbox_id: SandboxId::from(sandbox_id),
                parent_id: Some(chain_id),
                label,
                created_at_unix: now,
            };
            Ok((meta, Some(snap_fs), false))
        };

        let _ = handle.thaw().await;
        let (meta, local_fs_dir, containerd_backed) = res?;

        self.snapshots.lock().await.insert(
            meta.id.clone(),
            StoredSnapshot {
                meta: meta.clone(),
                image,
                policy,
                local_fs_dir,
                containerd_backed,
            },
        );
        Ok(meta)
    }

    pub async fn diff_sandbox(
        &self,
        cp: &ControlPlane,
        sandbox_id: &str,
    ) -> Result<Vec<FsDiffEntry>> {
        let (mounts, local_upper, local_lowers) = {
            let map = cp.sandboxes.lock().await;
            let sbx = map
                .get(sandbox_id)
                .with_context(|| format!("sandbox '{sandbox_id}' not found"))?;
            (
                sbx.mounts.clone(),
                sbx.local_upper_dir.clone(),
                sbx.local_lower_dirs.clone(),
            )
        };

        if let Some(ctrd) = &cp.containerd {
            if !mounts.is_empty() {
                return ctrd.diff_sandbox_rootfs(&mounts);
            }
        }

        if let Some(upper) = local_upper {
            if upper.is_dir() {
                return compute_dir_diff(&upper, &local_lowers);
            }
        }
        Ok(Vec::new())
    }

    pub async fn rollback_sandbox(
        &self,
        cp: &ControlPlane,
        sandbox_id: &str,
        snapshot_id: &str,
    ) -> Result<SandboxInfo> {
        let snap = self
            .snapshots
            .lock()
            .await
            .get(snapshot_id)
            .cloned()
            .with_context(|| format!("snapshot '{snapshot_id}' not found"))?;

        let (old_handle, env) = {
            let mut map = cp.sandboxes.lock().await;
            let old = map
                .remove(sandbox_id)
                .with_context(|| format!("sandbox '{sandbox_id}' not found"))?;
            (old.handle, old.env)
        };

        let _ = old_handle.destroy().await;

        let ttl = Duration::from_secs(snap.policy.max_ttl_sec.max(3600));
        let new_managed = if snap.containerd_backed {
            let ctrd = cp
                .containerd
                .as_ref()
                .context("containerd unavailable for snapshot rollback")?;
            let prep = ctrd.rollback_to_snapshot(sandbox_id, snapshot_id, ttl).await?;
            cp.boot_fresh_sandbox(
                sandbox_id,
                &snap.image,
                snap.policy.clone(),
                env,
                HashMap::new(),
                Some((prep, Some(snapshot_id.to_string()))),
            )
            .await?
        } else {
            let storage_dir = cp.data_root.join("storage").join(sandbox_id);
            let upper = storage_dir.join("upper");
            let _ = std::fs::remove_dir_all(&upper);
            std::fs::create_dir_all(&upper)?;
            let mut lowers = Vec::new();
            if let Some(ref fs_dir) = snap.local_fs_dir {
                if fs_dir.is_dir() {
                    copy_dir_recursive(fs_dir, &upper)?;
                    lowers.push(fs_dir.clone());
                }
            }
            let mut m = cp
                .boot_fresh_sandbox(
                    sandbox_id,
                    &snap.image,
                    snap.policy.clone(),
                    env,
                    HashMap::new(),
                    None,
                )
                .await?;
            m.info.parent_snapshot = Some(snapshot_id.to_string());
            m.local_lower_dirs = lowers;
            m
        };

        let info = new_managed.info.clone();
        cp.sandboxes
            .lock()
            .await
            .insert(sandbox_id.to_string(), new_managed);
        Ok(info)
    }

    pub async fn fork_snapshot(
        &self,
        cp: &ControlPlane,
        snapshot_id: &str,
        count: usize,
        policy_override: Option<SecurityPolicy>,
    ) -> Result<Vec<SandboxInfo>> {
        if count == 0 {
            bail!("fork count must be >= 1");
        }
        let snap = self
            .snapshots
            .lock()
            .await
            .get(snapshot_id)
            .cloned()
            .with_context(|| format!("snapshot '{snapshot_id}' not found"))?;
        let policy = policy_override.unwrap_or_else(|| snap.policy.clone());
        let ttl = Duration::from_secs(policy.max_ttl_sec.max(3600));

        let mut created = Vec::with_capacity(count);
        for _ in 0..count {
            let new_id = cp.gen_id("fork");
            let managed = if snap.containerd_backed {
                let ctrd = cp
                    .containerd
                    .as_ref()
                    .context("containerd unavailable for snapshot fork")?;
                let prep: PreparedRootfs =
                    ctrd.fork_from_snapshot(snapshot_id, &new_id, ttl).await?;
                cp.boot_fresh_sandbox(
                    &new_id,
                    &snap.image,
                    policy.clone(),
                    Vec::new(),
                    HashMap::new(),
                    Some((prep, Some(snapshot_id.to_string()))),
                )
                .await?
            } else {
                let upper = cp.data_root.join("storage").join(&new_id).join("upper");
                std::fs::create_dir_all(&upper)?;
                let mut lowers = Vec::new();
                if let Some(ref fs_dir) = snap.local_fs_dir {
                    if fs_dir.is_dir() {
                        copy_dir_recursive(fs_dir, &upper)?;
                        lowers.push(fs_dir.clone());
                    }
                }
                let mut m = cp
                    .boot_fresh_sandbox(
                        &new_id,
                        &snap.image,
                        policy.clone(),
                        Vec::new(),
                        HashMap::new(),
                        None,
                    )
                    .await?;
                m.info.parent_snapshot = Some(snapshot_id.to_string());
                m.local_lower_dirs = lowers;
                m
            };
            let info = managed.info.clone();
            cp.sandboxes.lock().await.insert(new_id, managed);
            created.push(info);
        }

        Ok(created)
    }

    pub async fn checkpoint_sandbox(
        &self,
        cp: &ControlPlane,
        sandbox_id: &str,
    ) -> Result<CheckpointMeta> {
        let (handle, image, policy, env) = {
            let map = cp.sandboxes.lock().await;
            let sbx = map
                .get(sandbox_id)
                .with_context(|| format!("sandbox '{sandbox_id}' not found"))?;
            (
                Arc::clone(&sbx.handle),
                sbx.info.image.clone(),
                sbx.info.policy.clone(),
                sbx.env.clone(),
            )
        };

        let snap_meta = self.create_snapshot(cp, sandbox_id, Some(String::from("checkpoint"))).await?;
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let now = now_unix();
        let ckpt_id = format!("ckpt-{sandbox_id}-{now}-{seq}");
        let ckpt_dir = self.data_root.join("checkpoints").join(&ckpt_id);

        let rec = handle.checkpoint(&ckpt_dir).await?;
        let meta = CheckpointMeta {
            id: ckpt_id.clone(),
            sandbox_id: SandboxId::from(sandbox_id),
            image,
            snapshot_id: snap_meta.id,
            created_at_unix: now,
            has_repl_state: rec.has_repl_state,
        };

        self.checkpoints.lock().await.insert(
            ckpt_id,
            StoredCheckpoint {
                meta: meta.clone(),
                ckpt_dir,
                policy,
                env,
            },
        );

        Ok(meta)
    }

    pub async fn restore_checkpoint(
        &self,
        cp: &ControlPlane,
        checkpoint_id: &str,
        new_sandbox_id: Option<String>,
    ) -> Result<SandboxInfo> {
        let ckpt = self
            .checkpoints
            .lock()
            .await
            .get(checkpoint_id)
            .cloned()
            .with_context(|| format!("checkpoint '{checkpoint_id}' not found"))?;

        let target_id = new_sandbox_id.unwrap_or_else(|| cp.gen_id("restored"));
        let snap = self
            .snapshots
            .lock()
            .await
            .get(&ckpt.meta.snapshot_id)
            .cloned();

        let ttl = Duration::from_secs(ckpt.policy.max_ttl_sec.max(3600));
        let (mounts, chain_id, local_upper, local_lowers) = if let Some(ref s) = snap {
            if s.containerd_backed {
                let ctrd = cp
                    .containerd
                    .as_ref()
                    .context("containerd unavailable for checkpoint restore")?;
                let prep = ctrd.fork_from_snapshot(&s.meta.id, &target_id, ttl).await?;
                (prep.mounts, prep.image.chain_id, None, Vec::new())
            } else {
                let upper = cp.data_root.join("storage").join(&target_id).join("upper");
                std::fs::create_dir_all(&upper)?;
                let mut lowers = Vec::new();
                if let Some(ref fs_dir) = s.local_fs_dir {
                    if fs_dir.is_dir() {
                        copy_dir_recursive(fs_dir, &upper)?;
                        lowers.push(fs_dir.clone());
                    }
                }
                (Vec::new(), s.meta.id.clone(), Some(upper), lowers)
            }
        } else {
            (Vec::new(), String::new(), None, Vec::new())
        };

        let vault = SecretVault::new();
        vault.load_from_host_env(&ckpt.policy.secret_bindings);
        let mut cfg = SandboxRuntimeConfig::new(target_id.as_str(), mounts.clone(), ckpt.policy.clone());
        cfg.secret_vault = vault;
        cfg.rootfs_hint = local_upper.clone();

        let handle = Arc::new(
            cp.dispatcher
                .backend_for(ckpt.policy.backend)
                .restore(&ckpt.ckpt_dir, &cfg)
                .await?,
        );

        let now = now_unix();
        let info = SandboxInfo {
            id: target_id.clone(),
            image: ckpt.meta.image,
            state: SandboxState::Running,
            backend: ckpt.policy.backend,
            parent_snapshot: Some(ckpt.meta.snapshot_id),
            created_at_unix: now,
            last_active_unix: now,
            policy: ckpt.policy,
            warm_hit: false,
        };

        let managed = ManagedSandbox {
            info: info.clone(),
            handle,
            mounts,
            chain_id,
            env: ckpt.env,
            local_upper_dir: local_upper,
            local_lower_dirs: local_lowers,
        };

        cp.sandboxes.lock().await.insert(target_id, managed);
        Ok(info)
    }
}
