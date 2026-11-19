pub mod cgroup;
pub mod gvisor;
pub mod landlock;
pub mod microvm;
pub mod native;
pub mod seccomp;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use sbx_containerd::MountSpec;
use sbx_net::SecretVault;
use sbx_proto::{
    BackendKind, ExecRequest, FileGetRequest, FileGetResponse, FilePutRequest, FilePutResponse,
    ReplExecRequest, ReplExecResponse, SandboxId, SecurityPolicy, SignalRequest,
};
use serde::{Deserialize, Serialize};

pub use cgroup::CgroupManager;
pub use gvisor::GvisorBackend;
pub use landlock::{apply_landlock_for_paths, landlock_abi_version, PreparedLandlock};
pub use microvm::{build_initramfs_cpio, MicroVmBackend};
pub use native::{
    copy_dir_recursive, locate_guest_agent_binary, NativeBackend, NativeSandboxHandle,
};
pub use seccomp::{build_seccomp_bpf, install_seccomp_filter, PreparedSeccomp};

/// Configuration passed to an `IsolationBackend` to start a sandbox instance.
#[derive(Debug, Clone)]
pub struct SandboxRuntimeConfig {
    pub sandbox_id: SandboxId,
    pub mounts: Vec<MountSpec>,
    pub policy: SecurityPolicy,
    pub rootfs_hint: Option<PathBuf>,
    pub secret_vault: SecretVault,
    pub host_overrides: HashMap<String, Vec<SocketAddr>>,
}

impl SandboxRuntimeConfig {
    pub fn new(
        sandbox_id: impl Into<SandboxId>,
        mounts: Vec<MountSpec>,
        policy: SecurityPolicy,
    ) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            mounts,
            policy,
            rootfs_hint: None,
            secret_vault: SecretVault::new(),
            host_overrides: HashMap::new(),
        }
    }
}

/// Persisted metadata produced by `SandboxHandle::checkpoint` / `IsolationBackend::checkpoint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRecord {
    pub sandbox_id: String,
    pub created_at_unix: u64,
    pub has_repl_state: bool,
    pub has_upper_delta: bool,
    pub criu_dumped: bool,
    pub backend: String,
}

/// Completed command execution output and resource statistics.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub term_signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub user_cpu_us: u64,
    pub sys_cpu_us: u64,
    pub max_rss_kb: u64,
    pub elapsed_us: u64,
    pub error: Option<String>,
}

/// Streaming callback `(is_stdout, bytes)`.
pub type StreamCallback<'a> = Box<dyn FnMut(bool, &[u8]) + Send + 'a>;

/// Handle to a running sandbox instance communicating with `sbx-guest-agent`.
#[async_trait]
pub trait SandboxHandle: Send + Sync {
    fn id(&self) -> &SandboxId;

    fn backend_kind(&self) -> BackendKind {
        BackendKind::Native
    }

    fn proxy_env(&self) -> &[(String, String)] {
        &[]
    }

    fn is_sleeping(&self) -> bool {
        false
    }

    async fn exec(
        &self,
        req: &ExecRequest,
        on_output: Option<StreamCallback<'_>>,
    ) -> Result<ExecOutput>;

    async fn repl_exec(&self, req: &ReplExecRequest) -> Result<ReplExecResponse>;

    async fn file_put(&self, req: &FilePutRequest) -> Result<FilePutResponse>;

    async fn file_get(&self, req: &FileGetRequest) -> Result<FileGetResponse>;

    async fn signal(&self, req: &SignalRequest) -> Result<()>;

    async fn freeze(&self) -> Result<()>;

    async fn thaw(&self) -> Result<()>;

    async fn sleep(&self) -> Result<()>;

    async fn wake(&self) -> Result<()>;

    async fn checkpoint(&self, dest_dir: &Path) -> Result<CheckpointRecord>;

    async fn destroy(&self) -> Result<()>;
}

/// Unified isolation backend trait (`Native`, `gVisor`, `MicroVM`).
#[async_trait]
pub trait IsolationBackend: Send + Sync {
    async fn start(&self, cfg: &SandboxRuntimeConfig) -> Result<Box<dyn SandboxHandle>>;

    async fn sleep(&self, id: &SandboxId) -> Result<()>;

    async fn wake(&self, id: &SandboxId) -> Result<()>;

    async fn checkpoint(&self, id: &SandboxId, dest: &Path) -> Result<()>;

    async fn restore(
        &self,
        src: &Path,
        cfg: &SandboxRuntimeConfig,
    ) -> Result<Box<dyn SandboxHandle>>;

    async fn destroy(&self, id: &SandboxId) -> Result<()>;
}

/// Multi-backend runtime dispatcher routing `Native`, `Gvisor`, and `MicroVm` requests.
#[derive(Clone)]
pub struct RuntimeDispatcher {
    native: Arc<NativeBackend>,
    gvisor: Arc<GvisorBackend>,
    microvm: Arc<MicroVmBackend>,
}

impl RuntimeDispatcher {
    pub fn new(guest_agent_bin: Option<PathBuf>) -> Result<Self> {
        let native = Arc::new(NativeBackend::new(guest_agent_bin)?);
        let gvisor = Arc::new(GvisorBackend::new(Arc::clone(&native)));
        let microvm = Arc::new(MicroVmBackend::new(Arc::clone(&native)));
        Ok(Self {
            native,
            gvisor,
            microvm,
        })
    }

    pub fn native(&self) -> &Arc<NativeBackend> {
        &self.native
    }

    pub fn gvisor(&self) -> &Arc<GvisorBackend> {
        &self.gvisor
    }

    pub fn microvm(&self) -> &Arc<MicroVmBackend> {
        &self.microvm
    }

    pub fn backend_for(&self, kind: BackendKind) -> &dyn IsolationBackend {
        match kind {
            BackendKind::Native => self.native.as_ref(),
            BackendKind::Gvisor => self.gvisor.as_ref(),
            BackendKind::MicroVm => self.microvm.as_ref(),
        }
    }

    pub fn reap_stale_sandboxes(&self) -> Result<usize> {
        self.native.reap_stale_sandboxes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbx_net::SecretVault;
    use sbx_proto::{NetworkPolicy, SecretRule};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn dispatcher_runs_exec_repl_file_transfer_and_sleep_wake_across_backends() {
        let dispatcher = RuntimeDispatcher::new(None).expect("dispatcher init");
        for (idx, kind) in [
            BackendKind::Native,
            BackendKind::Gvisor,
            BackendKind::MicroVm,
        ]
        .into_iter()
        .enumerate()
        {
            let sbx_id = format!("rt-test-{}-{idx}", std::process::id());
            let mut policy = SecurityPolicy::default();
            policy.backend = kind;
            let cfg = SandboxRuntimeConfig::new(sbx_id.as_str(), Vec::new(), policy);
            let handle = dispatcher.backend_for(kind).start(&cfg).await.expect("start");
            assert_eq!(handle.backend_kind(), kind);

            // 1. Direct clone3 exec
            let out = handle
                .exec(
                    &ExecRequest {
                        argv: vec![String::from("/bin/echo"), String::from("hello-sbx")],
                        env: Vec::new(),
                        cwd: None,
                        timeout_ms: 5000,
                        uid: None,
                        gid: None,
                        tty: false,
                    },
                    None,
                )
                .await
                .expect("exec");
            assert_eq!(out.exit_code, 0);
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello-sbx");

            // 2. File put + file get
            let tmp_file = format!("/tmp/sbx-rt-file-{}-{idx}.txt", std::process::id());
            let put = handle
                .file_put(&FilePutRequest {
                    path: tmp_file.clone(),
                    mode: 0o644,
                    data: b"payload-123".to_vec(),
                })
                .await
                .expect("file_put");
            assert!(put.ok, "put err: {:?}", put.error);
            let got = handle
                .file_get(&FileGetRequest {
                    path: tmp_file.clone(),
                    max_bytes: 4096,
                })
                .await
                .expect("file_get");
            assert!(got.ok);
            assert_eq!(got.data, b"payload-123");
            let _ = std::fs::remove_file(&tmp_file);

            // 3. Sleep & Wake
            handle.sleep().await.expect("sleep");
            assert!(handle.is_sleeping());
            handle.wake().await.expect("wake");
            assert!(!handle.is_sleeping());

            // 4. Stateful Python REPL
            if Path::new("/usr/bin/python3").exists() {
                let r1 = handle
                    .repl_exec(&ReplExecRequest {
                        language: String::from("python"),
                        code: String::from("val = 20 + 1"),
                        timeout_ms: 5000,
                    })
                    .await
                    .expect("repl1");
                assert_eq!(r1.exit_code, 0, "stderr={}", r1.stderr);

                let r2 = handle
                    .repl_exec(&ReplExecRequest {
                        language: String::from("python"),
                        code: String::from("val * 2"),
                        timeout_ms: 5000,
                    })
                    .await
                    .expect("repl2");
                assert_eq!(r2.exit_code, 0);
                assert_eq!(r2.stdout, "42\n");
            }

            handle.destroy().await.expect("destroy");
        }
    }

    #[tokio::test]
    async fn checkpoint_and_restore_preserves_python_repl_state() {
        if !Path::new("/usr/bin/python3").exists() {
            return;
        }
        let dispatcher = RuntimeDispatcher::new(None).expect("dispatcher");
        let ckpt_dir = std::env::temp_dir().join(format!("sbx-ckpt-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ckpt_dir);

        let id1 = format!("ckpt-src-{}", std::process::id());
        let cfg1 = SandboxRuntimeConfig::new(id1.as_str(), Vec::new(), SecurityPolicy::default());
        let h1 = dispatcher.native().start(&cfg1).await.expect("start1");

        let r1 = h1
            .repl_exec(&ReplExecRequest {
                language: String::from("python"),
                code: String::from("import math\nstate_num = 777"),
                timeout_ms: 5000,
            })
            .await
            .expect("repl set");
        assert_eq!(r1.exit_code, 0, "stderr={}", r1.stderr);

        let rec = h1.checkpoint(&ckpt_dir).await.expect("checkpoint");
        assert!(rec.has_repl_state);
        h1.destroy().await.expect("destroy1");

        let id2 = format!("ckpt-dst-{}", std::process::id());
        let cfg2 = SandboxRuntimeConfig::new(id2.as_str(), Vec::new(), SecurityPolicy::default());
        let h2 = dispatcher
            .native()
            .restore(&ckpt_dir, &cfg2)
            .await
            .expect("restore");

        let r2 = h2
            .repl_exec(&ReplExecRequest {
                language: String::from("python"),
                code: String::from("state_num + int(math.sqrt(16))"),
                timeout_ms: 5000,
            })
            .await
            .expect("repl restored");
        assert_eq!(r2.exit_code, 0, "stderr={}", r2.stderr);
        assert_eq!(r2.stdout, "781\n");

        h2.destroy().await.expect("destroy2");
        let _ = std::fs::remove_dir_all(&ckpt_dir);
    }

    #[tokio::test]
    async fn zero_trust_egress_proxy_works_inside_running_sandbox() {
        if !Path::new("/usr/bin/python3").exists() {
            return;
        }
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = upstream.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        req.len(),
                        req
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });

        let mut policy = SecurityPolicy::default();
        policy.network = NetworkPolicy::AllowlistProxy {
            allowed_hosts: vec![String::from("api.github.com")],
            block_private_cidrs: true,
        };
        policy.secret_bindings = vec![SecretRule {
            placeholder: String::from("sbx_tok_placeholder"),
            allowed_hosts: vec![String::from("api.github.com")],
            header_name: String::from("Authorization"),
            secret_ref: String::from("gh_token"),
        }];

        let vault = SecretVault::new();
        vault.insert("gh_token", "ghp_REAL_TOKEN_ABC");

        let id = format!("net-rt-{}", std::process::id());
        let mut cfg = SandboxRuntimeConfig::new(id.as_str(), Vec::new(), policy);
        cfg.secret_vault = vault;
        cfg.host_overrides
            .insert(String::from("api.github.com"), vec![upstream_addr]);

        let dispatcher = RuntimeDispatcher::new(None).expect("dispatcher");
        let handle = dispatcher.native().start(&cfg).await.expect("start");

        let py_script = r#"
import os, urllib.request, urllib.error
tok = os.environ["GH_TOKEN"]
assert tok == "sbx_tok_placeholder", f"unexpected real secret in env: {tok}"
req = urllib.request.Request("http://api.github.com/user", headers={"Authorization": f"Bearer {tok}"})
body = urllib.request.urlopen(req, timeout=5).read().decode()
print("ALLOWED_BODY=" + ("ghp_REAL_TOKEN_ABC" in body and "sbx_tok_placeholder" not in body).__str__())
try:
    urllib.request.urlopen("http://evil.example.com/", timeout=5)
    print("EVIL_ALLOWED=True")
except urllib.error.HTTPError as e:
    print(f"EVIL_STATUS={e.code}")
"#;
        let out = handle
            .exec(
                &ExecRequest {
                    argv: vec![
                        String::from("/usr/bin/python3"),
                        String::from("-c"),
                        String::from(py_script),
                    ],
                    env: vec![(String::from("GH_TOKEN"), String::from("sbx_tok_placeholder"))],
                    cwd: None,
                    timeout_ms: 8000,
                    uid: None,
                    gid: None,
                    tty: false,
                },
                None,
            )
            .await
            .expect("exec net test");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.exit_code, 0, "stdout={stdout}\nstderr={stderr}");
        assert!(stdout.contains("ALLOWED_BODY=True"), "stdout={stdout}");
        assert!(stdout.contains("EVIL_STATUS=403"), "stdout={stdout}");

        handle.destroy().await.expect("destroy");
    }
}
