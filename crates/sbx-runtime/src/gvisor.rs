use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use sbx_proto::{
    decode_postcard_payload, encode_postcard_frame, BackendKind, ExecExitPayload, ExecRequest,
    FileGetRequest, FileGetResponse, FilePutRequest, FilePutResponse, OpCode, PingPayload,
    PongPayload, ReplExecRequest, ReplExecResponse, SandboxId, SeccompMode, SignalRequest,
    VsockFrameHeader, FLAG_NONE, FLAG_PONG, HEADER_LEN, MAX_PAYLOAD_LEN,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::native::NativeBackend;
use crate::{
    CheckpointRecord, ExecOutput, IsolationBackend, SandboxHandle, SandboxRuntimeConfig,
    StreamCallback,
};

/// gVisor (`runsc`) user-space kernel isolation backend with strict-native fallback when `runsc` is absent.
pub struct GvisorBackend {
    native_fallback: Arc<NativeBackend>,
    runsc_bin: Option<PathBuf>,
    state_root: PathBuf,
}

impl GvisorBackend {
    pub fn new(native_fallback: Arc<NativeBackend>) -> Self {
        let runsc_bin = locate_runsc_binary();
        let state_root = native_fallback
            .state_root()
            .parent()
            .unwrap_or_else(|| native_fallback.state_root())
            .join("gvisor");
        let _ = fs::create_dir_all(&state_root);
        Self {
            native_fallback,
            runsc_bin,
            state_root,
        }
    }

    pub fn has_runsc(&self) -> bool {
        self.runsc_bin.is_some()
    }

    pub fn runsc_bin(&self) -> Option<&Path> {
        self.runsc_bin.as_deref()
    }

    fn strict_cfg(cfg: &SandboxRuntimeConfig) -> SandboxRuntimeConfig {
        let mut strict = cfg.clone();
        strict.policy.seccomp_mode = SeccompMode::Strict;
        strict.policy.readonly_rootfs = true;
        strict
    }

    fn write_oci_bundle(
        &self,
        bundle_dir: &Path,
        rootfs_dir: &Path,
        sock_dir: &Path,
        cfg: &SandboxRuntimeConfig,
    ) -> Result<()> {
        fs::create_dir_all(bundle_dir)?;
        fs::create_dir_all(rootfs_dir)?;
        fs::create_dir_all(sock_dir)?;

        let agent_dest = rootfs_dir.join(".sbx-guest-agent");
        let _ = fs::copy(self.native_fallback.guest_agent_bin(), &agent_dest);

        let mem_bytes = cfg.policy.memory_limit_mb.max(32) * 1024 * 1024;
        let pids_limit = cfg.policy.pids_limit.max(16) as i64;
        let spec = json!({
            "ociVersion": "1.0.2",
            "process": {
                "terminal": false,
                "user": { "uid": 0, "gid": 0 },
                "args": ["/.sbx-guest-agent", "--socket", "/run/sbx/agent.sock"],
                "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                "cwd": "/"
            },
            "root": {
                "path": rootfs_dir,
                "readonly": cfg.policy.readonly_rootfs
            },
            "hostname": format!("sbx-gv-{}", cfg.sandbox_id.as_str()),
            "mounts": [
                { "destination": "/proc", "type": "proc", "source": "proc" },
                { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs" },
                {
                    "destination": "/run/sbx",
                    "type": "bind",
                    "source": sock_dir,
                    "options": ["rbind", "rw"]
                }
            ],
            "linux": {
                "resources": {
                    "memory": { "limit": mem_bytes },
                    "pids": { "limit": pids_limit }
                },
                "namespaces": [
                    { "type": "pid" },
                    { "type": "ipc" },
                    { "type": "uts" },
                    { "type": "mount" },
                    { "type": "network" }
                ]
            }
        });
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_vec_pretty(&spec)?,
        )?;
        Ok(())
    }
}

pub struct GvisorSandboxHandle {
    id: SandboxId,
    runsc_bin: PathBuf,
    bundle_dir: PathBuf,
    conn: Mutex<UnixStream>,
    next_req_id: AtomicU32,
    sleeping: AtomicBool,
    destroyed: AtomicBool,
}

impl GvisorSandboxHandle {
    async fn ping(&self) -> Result<()> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let payload = PingPayload {
            timestamp_ns: 0,
            agent_pid: 0,
        };
        let mut buf = [0u8; 256];
        let total = encode_postcard_frame(OpCode::Ping, req_id, FLAG_NONE, &payload, &mut buf)?;
        let mut stream = self.conn.lock().await;
        stream.write_all(&buf[..total]).await?;
        let mut hdr_buf = [0u8; HEADER_LEN];
        stream.read_exact(&mut hdr_buf).await?;
        let hdr = VsockFrameHeader::from_bytes(&hdr_buf)?;
        if hdr.opcode != OpCode::Ping || (hdr.flags & FLAG_PONG) == 0 {
            bail!("unexpected gvisor ping reply");
        }
        let plen = hdr.payload_len as usize;
        if plen > 0 {
            let mut rx = vec![0u8; plen];
            stream.read_exact(&mut rx).await?;
            let _: PongPayload = decode_postcard_payload(&rx)?;
        }
        Ok(())
    }

    async fn rpc_postcard<Req: serde::Serialize, Resp: for<'a> serde::Deserialize<'a>>(
        &self,
        opcode: OpCode,
        req: &Req,
        cap: usize,
    ) -> Result<Resp> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let mut tx = vec![0u8; cap.max(1024)];
        let total = encode_postcard_frame(opcode, req_id, FLAG_NONE, req, &mut tx)?;
        let mut stream = self.conn.lock().await;
        stream.write_all(&tx[..total]).await?;
        let mut hdr_buf = [0u8; HEADER_LEN];
        stream.read_exact(&mut hdr_buf).await?;
        let hdr = VsockFrameHeader::from_bytes(&hdr_buf)?;
        let plen = hdr.payload_len as usize;
        let mut rx = vec![0u8; plen];
        if plen > 0 {
            stream.read_exact(&mut rx).await?;
        }
        Ok(decode_postcard_payload(&rx)?)
    }
}

impl Drop for GvisorSandboxHandle {
    fn drop(&mut self) {
        if !self.destroyed.swap(true, Ordering::SeqCst) {
            let _ = Command::new(&self.runsc_bin)
                .args(["delete", "-force", self.id.as_str()])
                .status();
            let _ = fs::remove_dir_all(&self.bundle_dir);
        }
    }
}

#[async_trait]
impl SandboxHandle for GvisorSandboxHandle {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn backend_kind(&self) -> BackendKind {
        BackendKind::Gvisor
    }

    fn is_sleeping(&self) -> bool {
        self.sleeping.load(Ordering::Relaxed)
    }

    async fn exec(
        &self,
        req: &ExecRequest,
        mut on_output: Option<StreamCallback<'_>>,
    ) -> Result<ExecOutput> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let mut tx = vec![0u8; 64 * 1024];
        let total = encode_postcard_frame(OpCode::ExecReq, req_id, FLAG_NONE, req, &mut tx)?;
        let mut stream = self.conn.lock().await;
        stream.write_all(&tx[..total]).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut hdr_buf = [0u8; HEADER_LEN];
        let mut rx_buf = vec![0u8; 64 * 1024];
        loop {
            stream.read_exact(&mut hdr_buf).await?;
            let hdr = VsockFrameHeader::from_bytes(&hdr_buf)?;
            let plen = hdr.payload_len as usize;
            if plen > MAX_PAYLOAD_LEN as usize {
                bail!("gvisor guest frame too large");
            }
            if rx_buf.len() < plen {
                rx_buf.resize(plen, 0);
            }
            if plen > 0 {
                stream.read_exact(&mut rx_buf[..plen]).await?;
            }
            match hdr.opcode {
                OpCode::StdoutData => {
                    if let Some(cb) = on_output.as_deref_mut() {
                        cb(true, &rx_buf[..plen]);
                    }
                    stdout.extend_from_slice(&rx_buf[..plen]);
                }
                OpCode::StderrData => {
                    if let Some(cb) = on_output.as_deref_mut() {
                        cb(false, &rx_buf[..plen]);
                    }
                    stderr.extend_from_slice(&rx_buf[..plen]);
                }
                OpCode::ExecExit => {
                    let exit: ExecExitPayload = decode_postcard_payload(&rx_buf[..plen])?;
                    return Ok(ExecOutput {
                        exit_code: exit.exit_code,
                        term_signal: exit.term_signal,
                        stdout,
                        stderr,
                        user_cpu_us: exit.user_cpu_us,
                        sys_cpu_us: exit.sys_cpu_us,
                        max_rss_kb: exit.max_rss_kb,
                        elapsed_us: exit.elapsed_us,
                        error: exit.error,
                    });
                }
                _ => {}
            }
        }
    }

    async fn repl_exec(&self, req: &ReplExecRequest) -> Result<ReplExecResponse> {
        self.rpc_postcard(OpCode::ReplExec, req, HEADER_LEN + req.code.len() + 256)
            .await
    }

    async fn file_put(&self, req: &FilePutRequest) -> Result<FilePutResponse> {
        self.rpc_postcard(OpCode::FilePut, req, HEADER_LEN + req.data.len() + 256)
            .await
    }

    async fn file_get(&self, req: &FileGetRequest) -> Result<FileGetResponse> {
        self.rpc_postcard(OpCode::FileGet, req, HEADER_LEN + req.path.len() + 256)
            .await
    }

    async fn signal(&self, req: &SignalRequest) -> Result<()> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let mut tx = [0u8; 128];
        let total = encode_postcard_frame(OpCode::Signal, req_id, FLAG_NONE, req, &mut tx)?;
        self.conn.lock().await.write_all(&tx[..total]).await?;
        Ok(())
    }

    async fn freeze(&self) -> Result<()> {
        let status = Command::new(&self.runsc_bin)
            .args(["pause", self.id.as_str()])
            .status()?;
        if !status.success() {
            bail!("runsc pause failed");
        }
        Ok(())
    }

    async fn thaw(&self) -> Result<()> {
        let status = Command::new(&self.runsc_bin)
            .args(["resume", self.id.as_str()])
            .status()?;
        if !status.success() {
            bail!("runsc resume failed");
        }
        Ok(())
    }

    async fn sleep(&self) -> Result<()> {
        self.freeze().await?;
        self.sleeping.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn wake(&self) -> Result<()> {
        self.thaw().await?;
        self.sleeping.store(false, Ordering::Relaxed);
        Ok(())
    }

    async fn checkpoint(&self, dest_dir: &Path) -> Result<CheckpointRecord> {
        fs::create_dir_all(dest_dir)?;
        let status = Command::new(&self.runsc_bin)
            .args([
                "checkpoint",
                "--image-path",
                &dest_dir.to_string_lossy(),
                self.id.as_str(),
            ])
            .status()?;
        if !status.success() {
            bail!("runsc checkpoint failed");
        }
        let rec = CheckpointRecord {
            sandbox_id: self.id.as_str().to_string(),
            created_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            has_repl_state: true,
            has_upper_delta: true,
            criu_dumped: true,
            backend: String::from("gvisor"),
        };
        fs::write(
            dest_dir.join("checkpoint.json"),
            serde_json::to_vec_pretty(&rec)?,
        )?;
        Ok(rec)
    }

    async fn destroy(&self) -> Result<()> {
        if !self.destroyed.swap(true, Ordering::SeqCst) {
            let _ = Command::new(&self.runsc_bin)
                .args(["delete", "-force", self.id.as_str()])
                .status();
            let _ = fs::remove_dir_all(&self.bundle_dir);
        }
        Ok(())
    }
}

/// Wrapper delegating to `NativeSandboxHandle` while reporting `BackendKind::Gvisor` when
/// `runsc` is absent on the host.
struct StrictNativeGvisorFallback(Box<dyn SandboxHandle>);

#[async_trait]
impl SandboxHandle for StrictNativeGvisorFallback {
    fn id(&self) -> &SandboxId {
        self.0.id()
    }
    fn backend_kind(&self) -> BackendKind {
        BackendKind::Gvisor
    }
    fn proxy_env(&self) -> &[(String, String)] {
        self.0.proxy_env()
    }
    fn is_sleeping(&self) -> bool {
        self.0.is_sleeping()
    }
    async fn exec(
        &self,
        req: &ExecRequest,
        on_output: Option<StreamCallback<'_>>,
    ) -> Result<ExecOutput> {
        self.0.exec(req, on_output).await
    }
    async fn repl_exec(&self, req: &ReplExecRequest) -> Result<ReplExecResponse> {
        self.0.repl_exec(req).await
    }
    async fn file_put(&self, req: &FilePutRequest) -> Result<FilePutResponse> {
        self.0.file_put(req).await
    }
    async fn file_get(&self, req: &FileGetRequest) -> Result<FileGetResponse> {
        self.0.file_get(req).await
    }
    async fn signal(&self, req: &SignalRequest) -> Result<()> {
        self.0.signal(req).await
    }
    async fn freeze(&self) -> Result<()> {
        self.0.freeze().await
    }
    async fn thaw(&self) -> Result<()> {
        self.0.thaw().await
    }
    async fn sleep(&self) -> Result<()> {
        self.0.sleep().await
    }
    async fn wake(&self) -> Result<()> {
        self.0.wake().await
    }
    async fn checkpoint(&self, dest_dir: &Path) -> Result<CheckpointRecord> {
        let mut rec = self.0.checkpoint(dest_dir).await?;
        rec.backend = String::from("gvisor-fallback-native");
        Ok(rec)
    }
    async fn destroy(&self) -> Result<()> {
        self.0.destroy().await
    }
}

#[async_trait]
impl IsolationBackend for GvisorBackend {
    async fn start(&self, cfg: &SandboxRuntimeConfig) -> Result<Box<dyn SandboxHandle>> {
        let Some(runsc) = &self.runsc_bin else {
            warn!(
                sandbox_id = %cfg.sandbox_id,
                "runsc binary not found; falling back to NativeBackend with SeccompMode::Strict + readonly_rootfs"
            );
            let strict = Self::strict_cfg(cfg);
            let inner = self.native_fallback.start(&strict).await?;
            return Ok(Box::new(StrictNativeGvisorFallback(inner)));
        };

        let bundle_dir = self.state_root.join(cfg.sandbox_id.as_str());
        let rootfs_dir = bundle_dir.join("rootfs");
        let sock_dir = bundle_dir.join("run");
        self.write_oci_bundle(&bundle_dir, &rootfs_dir, &sock_dir, cfg)?;

        info!(sandbox_id = %cfg.sandbox_id, runsc = %runsc.display(), "starting gVisor sandbox");
        let status = Command::new(runsc)
            .args([
                "run",
                "--detach",
                "--bundle",
                &bundle_dir.to_string_lossy(),
                cfg.sandbox_id.as_str(),
            ])
            .stdin(Stdio::null())
            .status()
            .context("failed spawning runsc")?;
        if !status.success() {
            let _ = fs::remove_dir_all(&bundle_dir);
            bail!("runsc exited with status {status}");
        }

        let sock_path = sock_dir.join("agent.sock");
        let mut stream = None;
        for _ in 0..50 {
            if let Ok(s) = UnixStream::connect(&sock_path).await {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stream = stream.with_context(|| {
            format!("timed out connecting to gVisor guest agent at {}", sock_path.display())
        })?;

        let handle = GvisorSandboxHandle {
            id: cfg.sandbox_id.clone(),
            runsc_bin: runsc.clone(),
            bundle_dir,
            conn: Mutex::new(stream),
            next_req_id: AtomicU32::new(1),
            sleeping: AtomicBool::new(false),
            destroyed: AtomicBool::new(false),
        };
        handle.ping().await?;
        Ok(Box::new(handle))
    }

    async fn sleep(&self, id: &SandboxId) -> Result<()> {
        if let Some(runsc) = &self.runsc_bin {
            let _ = Command::new(runsc).args(["pause", id.as_str()]).status()?;
            return Ok(());
        }
        self.native_fallback.sleep(id).await
    }

    async fn wake(&self, id: &SandboxId) -> Result<()> {
        if let Some(runsc) = &self.runsc_bin {
            let _ = Command::new(runsc).args(["resume", id.as_str()]).status()?;
            return Ok(());
        }
        self.native_fallback.wake(id).await
    }

    async fn checkpoint(&self, id: &SandboxId, dest: &Path) -> Result<()> {
        if let Some(runsc) = &self.runsc_bin {
            fs::create_dir_all(dest)?;
            let status = Command::new(runsc)
                .args(["checkpoint", "--image-path", &dest.to_string_lossy(), id.as_str()])
                .status()?;
            if !status.success() {
                bail!("runsc checkpoint failed");
            }
            return Ok(());
        }
        self.native_fallback.checkpoint(id, dest).await
    }

    async fn restore(
        &self,
        src: &Path,
        cfg: &SandboxRuntimeConfig,
    ) -> Result<Box<dyn SandboxHandle>> {
        if let Some(runsc) = &self.runsc_bin {
            let bundle_dir = self.state_root.join(cfg.sandbox_id.as_str());
            let sock_dir = bundle_dir.join("run");
            let status = Command::new(runsc)
                .args([
                    "restore",
                    "--detach",
                    "--image-path",
                    &src.to_string_lossy(),
                    "--bundle",
                    &bundle_dir.to_string_lossy(),
                    cfg.sandbox_id.as_str(),
                ])
                .status()?;
            if !status.success() {
                bail!("runsc restore failed");
            }
            let stream = UnixStream::connect(sock_dir.join("agent.sock")).await?;
            let handle = GvisorSandboxHandle {
                id: cfg.sandbox_id.clone(),
                runsc_bin: runsc.clone(),
                bundle_dir,
                conn: Mutex::new(stream),
                next_req_id: AtomicU32::new(1),
                sleeping: AtomicBool::new(false),
                destroyed: AtomicBool::new(false),
            };
            handle.ping().await?;
            return Ok(Box::new(handle));
        }
        let strict = Self::strict_cfg(cfg);
        let inner = self.native_fallback.restore(src, &strict).await?;
        Ok(Box::new(StrictNativeGvisorFallback(inner)))
    }

    async fn destroy(&self, id: &SandboxId) -> Result<()> {
        if let Some(runsc) = &self.runsc_bin {
            let _ = Command::new(runsc)
                .args(["delete", "-force", id.as_str()])
                .status();
            let _ = fs::remove_dir_all(self.state_root.join(id.as_str()));
            return Ok(());
        }
        self.native_fallback.destroy(id).await
    }
}

fn locate_runsc_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SBX_RUNSC_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let candidate = Path::new(dir).join("runsc");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}
