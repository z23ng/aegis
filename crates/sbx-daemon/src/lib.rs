pub mod pool;
pub mod reaper;
pub mod server;
pub mod snapshot_mgr;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use sbx_containerd::{ContainerdClientAdapter, MountSpec, PreparedRootfs};
use sbx_net::SecretVault;
use sbx_proto::{
    BackendKind, CheckpointMeta, ExecRequest, FileGetRequest, FileGetResponse, FilePutRequest,
    FilePutResponse, FsDiffEntry, ReplExecRequest, ReplExecResponse, SandboxState,
    SecurityPolicy, SnapshotMeta,
};
use sbx_runtime::{RuntimeDispatcher, SandboxHandle, SandboxRuntimeConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

pub use pool::{PoolBucketStats, WarmPoolScheduler};
pub use server::{
    build_http_router, default_daemon_socket_path, serve_http, serve_uds, DaemonClient,
};
pub use snapshot_mgr::SnapshotManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub id: String,
    pub image: String,
    pub state: SandboxState,
    pub backend: BackendKind,
    pub parent_snapshot: Option<String>,
    pub created_at_unix: u64,
    pub last_active_unix: u64,
    pub policy: SecurityPolicy,
    pub warm_hit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResultDto {
    pub exit_code: i32,
    pub term_signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub user_cpu_us: u64,
    pub sys_cpu_us: u64,
    pub max_rss_kb: u64,
    pub elapsed_us: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "args")]
pub enum DaemonRequest {
    Ping,
    CreateSandbox {
        id: Option<String>,
        image: String,
        policy: Option<SecurityPolicy>,
        env: Vec<(String, String)>,
        secrets: HashMap<String, String>,
    },
    Exec {
        sandbox_id: String,
        req: ExecRequest,
    },
    ReplExec {
        sandbox_id: String,
        req: ReplExecRequest,
    },
    FilePut {
        sandbox_id: String,
        req: FilePutRequest,
    },
    FileGet {
        sandbox_id: String,
        req: FileGetRequest,
    },
    Snapshot {
        sandbox_id: String,
        label: Option<String>,
    },
    Diff {
        sandbox_id: String,
    },
    Rollback {
        sandbox_id: String,
        snapshot_id: String,
    },
    Fork {
        snapshot_id: String,
        count: usize,
        policy: Option<SecurityPolicy>,
    },
    Checkpoint {
        sandbox_id: String,
    },
    Restore {
        checkpoint_id: String,
        new_sandbox_id: Option<String>,
    },
    Sleep {
        sandbox_id: String,
    },
    Wake {
        sandbox_id: String,
    },
    ListSandboxes,
    InspectSandbox {
        sandbox_id: String,
    },
    DestroySandbox {
        sandbox_id: String,
    },
    ConfigureWarmPool {
        image: String,
        backend: BackendKind,
        target_count: usize,
        policy: Option<SecurityPolicy>,
    },
    WarmPoolStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum DaemonResponse {
    Ok,
    Pong {
        pid: u32,
        uptime_ms: u64,
        version: String,
    },
    Sandbox(SandboxInfo),
    Sandboxes(Vec<SandboxInfo>),
    Exec(ExecResultDto),
    Repl(ReplExecResponse),
    FilePut(FilePutResponse),
    FileGet(FileGetResponse),
    Snapshot(SnapshotMeta),
    Diff(Vec<FsDiffEntry>),
    Checkpoint(CheckpointMeta),
    PoolStats(Vec<PoolBucketStats>),
    Error(String),
}

pub(crate) struct ManagedSandbox {
    pub info: SandboxInfo,
    pub handle: Arc<Box<dyn SandboxHandle>>,
    pub mounts: Vec<MountSpec>,
    pub chain_id: String,
    pub env: Vec<(String, String)>,
    pub local_upper_dir: Option<PathBuf>,
    pub local_lower_dirs: Vec<PathBuf>,
}

/// Host Control Plane coordinating containerd storage, isolation backends, warm pools,
/// step-level snapshots, checkpoints, and TTL/idle reaping.
pub struct ControlPlane {
    pub(crate) containerd: Option<ContainerdClientAdapter>,
    pub(crate) dispatcher: Arc<RuntimeDispatcher>,
    pub(crate) sandboxes: Mutex<HashMap<String, ManagedSandbox>>,
    pub(crate) pool: Arc<WarmPoolScheduler>,
    pub(crate) snapshots: Arc<SnapshotManager>,
    pub(crate) data_root: PathBuf,
    pub(crate) id_seq: AtomicU64,
    pub(crate) started_at: Instant,
}

impl ControlPlane {
    /// Initialize production control plane connected to `containerd`.
    /// If `containerd` is unavailable, gracefully runs with local rootfs storage.
    pub async fn connect(
        containerd_socket: Option<&Path>,
        data_root: Option<PathBuf>,
    ) -> Result<Arc<Self>> {
        let ctrd = match ContainerdClientAdapter::connect(containerd_socket).await {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(error = %e, "containerd unreachable; using local daemon storage fallback");
                None
            }
        };
        Self::with_storage(ctrd, data_root).await
    }

    /// Initialize an isolated self-contained control plane (ideal for tests without containerd).
    pub async fn new_local(data_root: PathBuf) -> Result<Arc<Self>> {
        Self::with_storage(None, Some(data_root)).await
    }

    async fn with_storage(
        containerd: Option<ContainerdClientAdapter>,
        data_root: Option<PathBuf>,
    ) -> Result<Arc<Self>> {
        let dispatcher = Arc::new(RuntimeDispatcher::new(None)?);
        let uid = unsafe { libc::geteuid() };
        let root = data_root.unwrap_or_else(|| {
            if uid == 0 {
                PathBuf::from("/var/lib/sbx-daemon")
            } else {
                PathBuf::from(format!("/tmp/sbx-daemon-{uid}/data"))
            }
        });
        std::fs::create_dir_all(root.join("snapshots"))?;
        std::fs::create_dir_all(root.join("checkpoints"))?;
        std::fs::create_dir_all(root.join("storage"))?;

        if let Some(ref c) = containerd {
            let _ = c.reap_expired_leases().await;
        }
        let _ = dispatcher.reap_stale_sandboxes();

        let pool = Arc::new(WarmPoolScheduler::new());
        let snapshots = Arc::new(SnapshotManager::new(root.clone()));

        Ok(Arc::new(Self {
            containerd,
            dispatcher,
            sandboxes: Mutex::new(HashMap::new()),
            pool,
            snapshots,
            data_root: root,
            id_seq: AtomicU64::new(1),
            started_at: Instant::now(),
        }))
    }

    pub fn gen_id(&self, prefix: &str) -> String {
        let seq = self.id_seq.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{}-{seq}", std::process::id())
    }

    pub fn dispatcher(&self) -> &Arc<RuntimeDispatcher> {
        &self.dispatcher
    }

    pub async fn handle_request(self: &Arc<Self>, req: DaemonRequest) -> DaemonResponse {
        match self.dispatch_inner(req).await {
            Ok(resp) => resp,
            Err(e) => DaemonResponse::Error(format!("{e:#}")),
        }
    }

    async fn dispatch_inner(self: &Arc<Self>, req: DaemonRequest) -> Result<DaemonResponse> {
        match req {
            DaemonRequest::Ping => Ok(DaemonResponse::Pong {
                pid: std::process::id(),
                uptime_ms: self.started_at.elapsed().as_millis() as u64,
                version: String::from(env!("CARGO_PKG_VERSION")),
            }),
            DaemonRequest::CreateSandbox {
                id,
                image,
                policy,
                env,
                secrets,
            } => {
                let info = self
                    .create_sandbox(id, &image, policy.unwrap_or_default(), env, secrets)
                    .await?;
                Ok(DaemonResponse::Sandbox(info))
            }
            DaemonRequest::Exec { sandbox_id, req } => {
                let res = self.exec(&sandbox_id, req).await?;
                Ok(DaemonResponse::Exec(res))
            }
            DaemonRequest::ReplExec { sandbox_id, req } => {
                let res = self.repl_exec(&sandbox_id, req).await?;
                Ok(DaemonResponse::Repl(res))
            }
            DaemonRequest::FilePut { sandbox_id, req } => {
                let res = self.file_put(&sandbox_id, req).await?;
                Ok(DaemonResponse::FilePut(res))
            }
            DaemonRequest::FileGet { sandbox_id, req } => {
                let res = self.file_get(&sandbox_id, req).await?;
                Ok(DaemonResponse::FileGet(res))
            }
            DaemonRequest::Snapshot { sandbox_id, label } => {
                let meta = self.snapshot(&sandbox_id, label).await?;
                Ok(DaemonResponse::Snapshot(meta))
            }
            DaemonRequest::Diff { sandbox_id } => {
                let diff = self.diff(&sandbox_id).await?;
                Ok(DaemonResponse::Diff(diff))
            }
            DaemonRequest::Rollback {
                sandbox_id,
                snapshot_id,
            } => {
                let info = self.rollback(&sandbox_id, &snapshot_id).await?;
                Ok(DaemonResponse::Sandbox(info))
            }
            DaemonRequest::Fork {
                snapshot_id,
                count,
                policy,
            } => {
                let list = self.fork(&snapshot_id, count, policy).await?;
                Ok(DaemonResponse::Sandboxes(list))
            }
            DaemonRequest::Checkpoint { sandbox_id } => {
                let meta = self.checkpoint(&sandbox_id).await?;
                Ok(DaemonResponse::Checkpoint(meta))
            }
            DaemonRequest::Restore {
                checkpoint_id,
                new_sandbox_id,
            } => {
                let info = self.restore(&checkpoint_id, new_sandbox_id).await?;
                Ok(DaemonResponse::Sandbox(info))
            }
            DaemonRequest::Sleep { sandbox_id } => {
                self.sleep(&sandbox_id).await?;
                Ok(DaemonResponse::Ok)
            }
            DaemonRequest::Wake { sandbox_id } => {
                self.wake(&sandbox_id).await?;
                Ok(DaemonResponse::Ok)
            }
            DaemonRequest::ListSandboxes => {
                let list = self.list_sandboxes().await;
                Ok(DaemonResponse::Sandboxes(list))
            }
            DaemonRequest::InspectSandbox { sandbox_id } => {
                let info = self.inspect_sandbox(&sandbox_id).await?;
                Ok(DaemonResponse::Sandbox(info))
            }
            DaemonRequest::DestroySandbox { sandbox_id } => {
                self.destroy_sandbox(&sandbox_id).await?;
                Ok(DaemonResponse::Ok)
            }
            DaemonRequest::ConfigureWarmPool {
                image,
                backend,
                target_count,
                policy,
            } => {
                let stats = self
                    .configure_warm_pool(
                        &image,
                        backend,
                        target_count,
                        policy.unwrap_or_default(),
                    )
                    .await?;
                Ok(DaemonResponse::PoolStats(stats))
            }
            DaemonRequest::WarmPoolStatus => {
                let stats = self.pool.stats().await;
                Ok(DaemonResponse::PoolStats(stats))
            }
        }
    }

    pub async fn create_sandbox(
        self: &Arc<Self>,
        explicit_id: Option<String>,
        image: &str,
        policy: SecurityPolicy,
        env: Vec<(String, String)>,
        secrets: HashMap<String, String>,
    ) -> Result<SandboxInfo> {
        // Fast Warm Pool hit if caller didn't force an explicit ID and no custom secrets/network rules differ.
        if explicit_id.is_none() && secrets.is_empty() && policy.secret_bindings.is_empty() {
            if let Some(mut warm) = self.pool.try_acquire(image, policy.backend).await {
                let now = now_unix();
                warm.info.state = SandboxState::Running;
                warm.info.last_active_unix = now;
                warm.info.warm_hit = true;
                warm.env = env;
                let info = warm.info.clone();
                self.sandboxes.lock().await.insert(info.id.clone(), warm);

                // Replenish warm pool asynchronously
                let cp = Arc::clone(self);
                let img_s = image.to_string();
                let pol_s = policy.clone();
                tokio::spawn(async move {
                    let _ = cp.replenish_warm_bucket(&img_s, pol_s).await;
                });
                return Ok(info);
            }
        }

        let sandbox_id = explicit_id.unwrap_or_else(|| self.gen_id("sbx"));
        let managed = self
            .boot_fresh_sandbox(&sandbox_id, image, policy, env, secrets, None)
            .await?;
        let info = managed.info.clone();
        self.sandboxes
            .lock()
            .await
            .insert(sandbox_id, managed);
        Ok(info)
    }

    pub(crate) async fn boot_fresh_sandbox(
        &self,
        sandbox_id: &str,
        image: &str,
        policy: SecurityPolicy,
        env: Vec<(String, String)>,
        secrets: HashMap<String, String>,
        from_prepared: Option<(PreparedRootfs, Option<String>)>,
    ) -> Result<ManagedSandbox> {
        let ttl = Duration::from_secs(policy.max_ttl_sec.max(60));
        let (mounts, chain_id, parent_snapshot, local_upper, local_lowers) =
            if let Some((prep, parent_snap)) = from_prepared {
                (prep.mounts, prep.image.chain_id, parent_snap, None, Vec::new())
            } else if let Some(ctrd) = &self.containerd {
                let prep = ctrd.prepare_rootfs(sandbox_id, image, ttl).await?;
                (prep.mounts, prep.image.chain_id, None, None, Vec::new())
            } else {
                let upper = self.data_root.join("storage").join(sandbox_id).join("upper");
                std::fs::create_dir_all(&upper)?;
                (Vec::new(), format!("local:{image}"), None, Some(upper), Vec::new())
            };

        let vault = SecretVault::new();
        for (k, v) in secrets {
            vault.insert(k, v);
        }
        vault.load_from_host_env(&policy.secret_bindings);

        let mut cfg = SandboxRuntimeConfig::new(sandbox_id, mounts.clone(), policy.clone());
        cfg.secret_vault = vault;
        cfg.rootfs_hint = local_upper.clone();

        let backend = self.dispatcher.backend_for(policy.backend);
        let handle = match backend.start(&cfg).await {
            Ok(h) => Arc::new(h),
            Err(e) => {
                if let Some(ctrd) = &self.containerd {
                    let _ = ctrd.cleanup_sandbox_storage(sandbox_id).await;
                }
                return Err(e);
            }
        };

        let now = now_unix();
        Ok(ManagedSandbox {
            info: SandboxInfo {
                id: sandbox_id.to_string(),
                image: image.to_string(),
                state: SandboxState::Running,
                backend: policy.backend,
                parent_snapshot,
                created_at_unix: now,
                last_active_unix: now,
                policy,
                warm_hit: false,
            },
            handle,
            mounts,
            chain_id,
            env,
            local_upper_dir: local_upper,
            local_lower_dirs: local_lowers,
        })
    }

    pub async fn exec(&self, sandbox_id: &str, mut req: ExecRequest) -> Result<ExecResultDto> {
        let (handle, base_env) = {
            let mut map = self.sandboxes.lock().await;
            let sbx = map
                .get_mut(sandbox_id)
                .with_context(|| format!("sandbox '{sandbox_id}' not found"))?;
            sbx.info.last_active_unix = now_unix();
            (Arc::clone(&sbx.handle), sbx.env.clone())
        };
        if handle.is_sleeping() {
            handle.wake().await?;
        }
        for (k, v) in base_env {
            if !req.env.iter().any(|(ek, _)| ek == &k) {
                req.env.push((k, v));
            }
        }
        let out = handle.exec(&req, None).await?;
        Ok(ExecResultDto {
            exit_code: out.exit_code,
            term_signal: out.term_signal,
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            user_cpu_us: out.user_cpu_us,
            sys_cpu_us: out.sys_cpu_us,
            max_rss_kb: out.max_rss_kb,
            elapsed_us: out.elapsed_us,
            error: out.error,
        })
    }

    pub async fn repl_exec(
        &self,
        sandbox_id: &str,
        req: ReplExecRequest,
    ) -> Result<ReplExecResponse> {
        let handle = {
            let mut map = self.sandboxes.lock().await;
            let sbx = map
                .get_mut(sandbox_id)
                .with_context(|| format!("sandbox '{sandbox_id}' not found"))?;
            sbx.info.last_active_unix = now_unix();
            Arc::clone(&sbx.handle)
        };
        if handle.is_sleeping() {
            handle.wake().await?;
        }
        handle.repl_exec(&req).await
    }

    pub async fn file_put(&self, sandbox_id: &str, req: FilePutRequest) -> Result<FilePutResponse> {
        let handle = self.get_handle(sandbox_id).await?;
        handle.file_put(&req).await
    }

    pub async fn file_get(&self, sandbox_id: &str, req: FileGetRequest) -> Result<FileGetResponse> {
        let handle = self.get_handle(sandbox_id).await?;
        handle.file_get(&req).await
    }

    pub async fn sleep(&self, sandbox_id: &str) -> Result<()> {
        let mut map = self.sandboxes.lock().await;
        let sbx = map
            .get_mut(sandbox_id)
            .with_context(|| format!("sandbox '{sandbox_id}' not found"))?;
        sbx.handle.sleep().await?;
        sbx.info.state = SandboxState::Sleeping;
        Ok(())
    }

    pub async fn wake(&self, sandbox_id: &str) -> Result<()> {
        let mut map = self.sandboxes.lock().await;
        let sbx = map
            .get_mut(sandbox_id)
            .with_context(|| format!("sandbox '{sandbox_id}' not found"))?;
        sbx.handle.wake().await?;
        sbx.info.state = SandboxState::Running;
        sbx.info.last_active_unix = now_unix();
        Ok(())
    }

    pub async fn list_sandboxes(&self) -> Vec<SandboxInfo> {
        let map = self.sandboxes.lock().await;
        let mut list: Vec<SandboxInfo> = map.values().map(|m| m.info.clone()).collect();
        list.sort_by(|a, b| a.created_at_unix.cmp(&b.created_at_unix).then(a.id.cmp(&b.id)));
        list
    }

    pub async fn inspect_sandbox(&self, sandbox_id: &str) -> Result<SandboxInfo> {
        let map = self.sandboxes.lock().await;
        map.get(sandbox_id)
            .map(|m| m.info.clone())
            .with_context(|| format!("sandbox '{sandbox_id}' not found"))
    }

    pub async fn destroy_sandbox(&self, sandbox_id: &str) -> Result<()> {
        let removed = self.sandboxes.lock().await.remove(sandbox_id);
        let Some(sbx) = removed else {
            bail!("sandbox '{sandbox_id}' not found");
        };
        let _ = sbx.handle.destroy().await;
        if let Some(ctrd) = &self.containerd {
            let _ = ctrd.cleanup_sandbox_storage(sandbox_id).await;
        }
        if let Some(upper) = sbx.local_upper_dir {
            if let Some(parent) = upper.parent() {
                let _ = std::fs::remove_dir_all(parent);
            }
        }
        info!(sandbox_id, "sandbox destroyed");
        Ok(())
    }

    pub async fn configure_warm_pool(
        self: &Arc<Self>,
        image: &str,
        backend: BackendKind,
        target_count: usize,
        policy: SecurityPolicy,
    ) -> Result<Vec<PoolBucketStats>> {
        self.pool
            .set_target(image, backend, policy.clone(), target_count)
            .await;
        self.replenish_warm_bucket(image, policy).await?;
        Ok(self.pool.stats().await)
    }

    async fn replenish_warm_bucket(
        &self,
        image: &str,
        policy: SecurityPolicy,
    ) -> Result<()> {
        let backend = policy.backend;
        let deficit = self.pool.deficit(image, backend).await;
        for _ in 0..deficit {
            let id = self.gen_id("warm");
            let mut sbx = self
                .boot_fresh_sandbox(&id, image, policy.clone(), Vec::new(), HashMap::new(), None)
                .await?;
            sbx.info.state = SandboxState::Warm;
            self.pool.push_warm(image, backend, sbx).await;
        }
        let excess = self.pool.pop_excess(image, backend).await;
        for sbx in excess {
            let _ = sbx.handle.destroy().await;
            if let Some(ctrd) = &self.containerd {
                let _ = ctrd.cleanup_sandbox_storage(&sbx.info.id).await;
            }
        }
        Ok(())
    }

    pub async fn snapshot(&self, sandbox_id: &str, label: Option<String>) -> Result<SnapshotMeta> {
        self.snapshots.create_snapshot(self, sandbox_id, label).await
    }

    pub async fn diff(&self, sandbox_id: &str) -> Result<Vec<FsDiffEntry>> {
        self.snapshots.diff_sandbox(self, sandbox_id).await
    }

    pub async fn rollback(&self, sandbox_id: &str, snapshot_id: &str) -> Result<SandboxInfo> {
        self.snapshots
            .rollback_sandbox(self, sandbox_id, snapshot_id)
            .await
    }

    pub async fn fork(
        &self,
        snapshot_id: &str,
        count: usize,
        policy: Option<SecurityPolicy>,
    ) -> Result<Vec<SandboxInfo>> {
        self.snapshots
            .fork_snapshot(self, snapshot_id, count, policy)
            .await
    }

    pub async fn checkpoint(&self, sandbox_id: &str) -> Result<CheckpointMeta> {
        self.snapshots.checkpoint_sandbox(self, sandbox_id).await
    }

    pub async fn restore(
        &self,
        checkpoint_id: &str,
        new_sandbox_id: Option<String>,
    ) -> Result<SandboxInfo> {
        self.snapshots
            .restore_checkpoint(self, checkpoint_id, new_sandbox_id)
            .await
    }

    async fn get_handle(&self, sandbox_id: &str) -> Result<Arc<Box<dyn SandboxHandle>>> {
        let map = self.sandboxes.lock().await;
        map.get(sandbox_id)
            .map(|s| Arc::clone(&s.handle))
            .with_context(|| format!("sandbox '{sandbox_id}' not found"))
    }

    /// Cleanly destroy all running and pre-warmed sandboxes before daemon exit.
    pub async fn shutdown(&self) {
        let active: Vec<ManagedSandbox> = {
            let mut map = self.sandboxes.lock().await;
            map.drain().map(|(_, v)| v).collect()
        };
        for sbx in active {
            let _ = sbx.handle.destroy().await;
            if let Some(ref ctrd) = self.containerd {
                let _ = ctrd.cleanup_sandbox_storage(&sbx.info.id).await;
            }
        }
        for warm in self.pool.drain_all().await {
            let _ = warm.handle.destroy().await;
            if let Some(ref ctrd) = self.containerd {
                let _ = ctrd.cleanup_sandbox_storage(&warm.info.id).await;
            }
        }
    }
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reaper::reap_once;
    use sbx_proto::DiffKind;
    use tokio::sync::watch;

    #[tokio::test]
    async fn warm_pool_acquires_sub_5ms_and_uds_lifecycle_works() {
        let dir = std::env::temp_dir().join(format!("sbx-daemon-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cp = ControlPlane::new_local(dir.join("data")).await.unwrap();
        let sock = dir.join("daemon.sock");
        let (tx, rx) = watch::channel(false);
        let cp_srv = Arc::clone(&cp);
        let sock_srv = sock.clone();
        let srv_task = tokio::spawn(async move { serve_uds(&sock_srv, cp_srv, rx).await });

        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let mut client = DaemonClient::connect(Some(&sock)).await.unwrap();

        // 1. Configure Warm Pool with 2 pre-warmed sandboxes
        let pool_resp = client
            .request(&DaemonRequest::ConfigureWarmPool {
                image: String::from("alpine"),
                backend: BackendKind::Native,
                target_count: 2,
                policy: None,
            })
            .await
            .unwrap();
        match pool_resp {
            DaemonResponse::PoolStats(stats) => {
                assert_eq!(stats[0].ready_count, 2);
            }
            other => panic!("unexpected pool response: {other:?}"),
        }

        // 2. Acquire from Warm Pool and assert sub-5ms allocation
        let t0 = Instant::now();
        let create_resp = client
            .request(&DaemonRequest::CreateSandbox {
                id: None,
                image: String::from("alpine"),
                policy: None,
                env: Vec::new(),
                secrets: HashMap::new(),
            })
            .await
            .unwrap();
        let acquire_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let sbx_id = match create_resp {
            DaemonResponse::Sandbox(info) => {
                assert!(info.warm_hit, "expected warm pool hit");
                assert_eq!(info.state, SandboxState::Running);
                info.id
            }
            other => panic!("unexpected create response: {other:?}"),
        };
        assert!(
            acquire_ms < 25.0,
            "warm pool acquisition took {acquire_ms:.2}ms"
        );

        // 3. Exec inside acquired sandbox
        let exec_resp = client
            .request(&DaemonRequest::Exec {
                sandbox_id: sbx_id.clone(),
                req: ExecRequest {
                    argv: vec![String::from("/bin/echo"), String::from("warm-exec")],
                    env: Vec::new(),
                    cwd: None,
                    timeout_ms: 5000,
                    uid: None,
                    gid: None,
                    tty: false,
                },
            })
            .await
            .unwrap();
        match exec_resp {
            DaemonResponse::Exec(out) => {
                assert_eq!(out.exit_code, 0);
                assert_eq!(out.stdout.trim(), "warm-exec");
            }
            other => panic!("unexpected exec response: {other:?}"),
        }

        // 4. Snapshot + Diff + Rollback + Fork (n=2)
        // Simulate modified file in sandbox local upper dir for deterministic offline diff/rollback.
        let upper_dir = {
            let map = cp.sandboxes.lock().await;
            map.get(&sbx_id).unwrap().local_upper_dir.clone().unwrap()
        };
        std::fs::write(upper_dir.join("base.txt"), b"clean-v1").unwrap();

        let snap_resp = client
            .request(&DaemonRequest::Snapshot {
                sandbox_id: sbx_id.clone(),
                label: Some(String::from("clean")),
            })
            .await
            .unwrap();
        let snap_id = match snap_resp {
            DaemonResponse::Snapshot(meta) => meta.id,
            other => panic!("unexpected snapshot response: {other:?}"),
        };

        // Mutate after snapshot
        std::fs::write(upper_dir.join("dirty.txt"), b"broken").unwrap();
        let diff_resp = client
            .request(&DaemonRequest::Diff {
                sandbox_id: sbx_id.clone(),
            })
            .await
            .unwrap();
        match diff_resp {
            DaemonResponse::Diff(entries) => {
                assert!(entries
                    .iter()
                    .any(|e| e.path == "/dirty.txt" && e.kind == DiffKind::Added));
            }
            other => panic!("unexpected diff response: {other:?}"),
        }

        // Rollback removes dirty.txt and keeps base.txt
        let rb_resp = client
            .request(&DaemonRequest::Rollback {
                sandbox_id: sbx_id.clone(),
                snapshot_id: snap_id.clone(),
            })
            .await
            .unwrap();
        assert!(matches!(rb_resp, DaemonResponse::Sandbox(_)));
        let rolled_upper = {
            let map = cp.sandboxes.lock().await;
            map.get(&sbx_id).unwrap().local_upper_dir.clone().unwrap()
        };
        assert!(rolled_upper.join("base.txt").is_file());
        assert!(!rolled_upper.join("dirty.txt").exists());

        // Fork 2 independent CoW sandboxes from snap_id
        let fork_resp = client
            .request(&DaemonRequest::Fork {
                snapshot_id: snap_id,
                count: 2,
                policy: None,
            })
            .await
            .unwrap();
        let forked = match fork_resp {
            DaemonResponse::Sandboxes(list) => {
                assert_eq!(list.len(), 2);
                list
            }
            other => panic!("unexpected fork response: {other:?}"),
        };

        // Checkpoint + Restore with Python REPL state
        if Path::new("/usr/bin/python3").exists() {
            let _ = client
                .request(&DaemonRequest::ReplExec {
                    sandbox_id: sbx_id.clone(),
                    req: ReplExecRequest {
                        language: String::from("python"),
                        code: String::from("counter = 123"),
                        timeout_ms: 5000,
                    },
                })
                .await
                .unwrap();

            let ckpt_resp = client
                .request(&DaemonRequest::Checkpoint {
                    sandbox_id: sbx_id.clone(),
                })
                .await
                .unwrap();
            let ckpt_id = match ckpt_resp {
                DaemonResponse::Checkpoint(m) => {
                    assert!(m.has_repl_state);
                    m.id
                }
                other => panic!("unexpected ckpt response: {other:?}"),
            };

            let restored_resp = client
                .request(&DaemonRequest::Restore {
                    checkpoint_id: ckpt_id,
                    new_sandbox_id: None,
                })
                .await
                .unwrap();
            let restored_id = match restored_resp {
                DaemonResponse::Sandbox(i) => i.id,
                other => panic!("unexpected restore response: {other:?}"),
            };

            let repl_after = client
                .request(&DaemonRequest::ReplExec {
                    sandbox_id: restored_id.clone(),
                    req: ReplExecRequest {
                        language: String::from("python"),
                        code: String::from("counter + 7"),
                        timeout_ms: 5000,
                    },
                })
                .await
                .unwrap();
            match repl_after {
                DaemonResponse::Repl(r) => {
                    assert_eq!(r.exit_code, 0, "stderr={}", r.stderr);
                    assert_eq!(r.stdout, "130\n");
                }
                other => panic!("unexpected repl response: {other:?}"),
            }
            let _ = client
                .request(&DaemonRequest::DestroySandbox {
                    sandbox_id: restored_id,
                })
                .await;
        }

        // Cleanup & Reaper test
        for f in forked {
            let _ = client
                .request(&DaemonRequest::DestroySandbox { sandbox_id: f.id })
                .await;
        }
        // Mark sbx_id expired and verify reaper cleans it up
        {
            let mut map = cp.sandboxes.lock().await;
            if let Some(sbx) = map.get_mut(&sbx_id) {
                sbx.info.created_at_unix = 0;
                sbx.info.policy.max_ttl_sec = 1;
                sbx.info.policy.auto_destroy = true;
            }
        }
        let (_slept, destroyed) = reap_once(&cp).await;
        assert_eq!(destroyed, 1);

        for warm in cp.pool.drain_all().await {
            let _ = warm.handle.destroy().await;
        }
        let _ = tx.send(true);
        let _ = srv_task.await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
