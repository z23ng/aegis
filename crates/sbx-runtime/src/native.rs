use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use sbx_containerd::MountSpec;
use sbx_net::EgressProxy;
use sbx_proto::{
    decode_postcard_payload, encode_postcard_frame, ExecExitPayload, ExecRequest, FileGetRequest,
    FileGetResponse, FilePutRequest, FilePutResponse, NetworkPolicy, OpCode, PingPayload,
    PongPayload, ReplExecRequest, ReplExecResponse, SandboxId, SignalRequest, VsockFrameHeader,
    FLAG_NONE, FLAG_PONG, HEADER_LEN, MAX_PAYLOAD_LEN,
};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::cgroup::CgroupManager;
use crate::landlock::PreparedLandlock;
use crate::seccomp::PreparedSeccomp;
use crate::{
    CheckpointRecord, ExecOutput, IsolationBackend, SandboxHandle, SandboxRuntimeConfig,
    StreamCallback,
};

const CLONE_INTO_CGROUP: u64 = 0x200000000;
const IN_NETNS_PROXY_PORT: u16 = 3128;

/// Linux `struct clone_args` for `SYS_clone3`.
#[repr(C, align(8))]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Native Linux isolation backend using `clone3` + Namespaces + `pivot_root` + `cgroup v2`
/// + `Seccomp-BPF` + `Landlock LSM` + `sbx-net` Egress Proxy.
pub struct NativeBackend {
    cgroups: Arc<CgroupManager>,
    state_root: PathBuf,
    guest_agent_bin: PathBuf,
}

impl NativeBackend {
    pub fn new(guest_agent_bin: Option<PathBuf>) -> Result<Self> {
        let cgroups = Arc::new(CgroupManager::new()?);
        let uid = unsafe { libc::geteuid() };
        let state_root = if uid == 0 {
            PathBuf::from("/run/sbx/sandboxes")
        } else {
            PathBuf::from(format!("/tmp/sbx-runtime-{uid}/sandboxes"))
        };
        fs::create_dir_all(&state_root).with_context(|| {
            format!(
                "failed to create sandbox state root {}",
                state_root.display()
            )
        })?;

        let agent_bin = match guest_agent_bin {
            Some(p) => p,
            None => locate_guest_agent_binary()?,
        };
        if !agent_bin.is_file() {
            bail!(
                "sbx-guest-agent binary does not exist at {}",
                agent_bin.display()
            );
        }

        Ok(Self {
            cgroups,
            state_root,
            guest_agent_bin: agent_bin,
        })
    }

    pub fn cgroups(&self) -> &CgroupManager {
        &self.cgroups
    }

    pub fn guest_agent_bin(&self) -> &Path {
        &self.guest_agent_bin
    }

    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Remove stale runtime state directories and cgroups left by crashed sandboxes.
    pub fn reap_stale_sandboxes(&self) -> Result<usize> {
        let mut reaped = 0;
        if let Ok(entries) = fs::read_dir(&self.state_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let pid_file = path.join("init.pid");
                let alive = fs::read_to_string(&pid_file)
                    .ok()
                    .and_then(|s| s.trim().parse::<libc::pid_t>().ok())
                    .is_some_and(|pid| unsafe { libc::kill(pid, 0) == 0 });
                if !alive {
                    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                        let id = SandboxId::from(name);
                        let _ = self.cgroups.destroy_sandbox_cgroup(&id);
                    }
                    let _ = fs::remove_dir_all(&path);
                    reaped += 1;
                }
            }
        }
        Ok(reaped)
    }

    async fn start_degraded_confined(
        &self,
        cfg: &SandboxRuntimeConfig,
        state_dir: PathBuf,
        sock_path: PathBuf,
        listen_fd: RawFd,
        mut listen_guard: FdGuard,
    ) -> Result<Box<dyn SandboxHandle>> {
        let wants_proxy = matches!(cfg.policy.network, NetworkPolicy::AllowlistProxy { .. });
        let proxy = if wants_proxy {
            Some(
                EgressProxy::start(
                    &cfg.policy.network,
                    cfg.policy.secret_bindings.clone(),
                    cfg.secret_vault.clone(),
                    cfg.host_overrides.clone(),
                )
                .await?,
            )
        } else {
            None
        };
        let proxy_env = proxy.as_ref().map(|p| p.sandbox_env()).unwrap_or_default();

        let child_pid = spawn_degraded_child(
            &self.guest_agent_bin,
            listen_fd,
            &proxy_env,
            cfg.policy.seccomp_mode,
        )
        .inspect_err(|_| {
            let _ = fs::remove_dir_all(&state_dir);
        })?;

        close_fd(listen_guard.0);
        listen_guard.0 = -1;
        let _ = fs::write(state_dir.join("init.pid"), child_pid.to_string());

        let stream = UnixStream::connect(&sock_path).await.with_context(|| {
            format!("failed to connect to guest agent socket {}", sock_path.display())
        })?;

        let handle = NativeSandboxHandle {
            id: cfg.sandbox_id.clone(),
            child_pid,
            state_dir,
            upper_dir: extract_upper_dir(&cfg.mounts).or_else(|| cfg.rootfs_hint.clone()),
            cgroups: Arc::clone(&self.cgroups),
            conn: Mutex::new(stream),
            next_req_id: AtomicU32::new(1),
            destroyed: AtomicBool::new(false),
            sleeping: AtomicBool::new(false),
            namespace_isolated: false,
            _proxy: proxy,
            proxy_env,
        };

        let _pong = handle
            .ping()
            .await
            .context("guest agent failed OP_PING readiness check")?;
        Ok(Box::new(handle))
    }
}

struct FdGuard(RawFd);
impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

pub struct NativeSandboxHandle {
    id: SandboxId,
    child_pid: libc::pid_t,
    state_dir: PathBuf,
    upper_dir: Option<PathBuf>,
    cgroups: Arc<CgroupManager>,
    conn: Mutex<UnixStream>,
    next_req_id: AtomicU32,
    destroyed: AtomicBool,
    sleeping: AtomicBool,
    namespace_isolated: bool,
    _proxy: Option<EgressProxy>,
    proxy_env: Vec<(String, String)>,
}

impl NativeSandboxHandle {
    pub fn is_namespace_isolated(&self) -> bool {
        self.namespace_isolated
    }

    pub fn upper_dir(&self) -> Option<&Path> {
        self.upper_dir.as_deref()
    }

    pub fn child_pid(&self) -> libc::pid_t {
        self.child_pid
    }

    async fn ping(&self) -> Result<PongPayload> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let payload = PingPayload {
            timestamp_ns: now_ns,
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
            bail!("unexpected ping reply header: {hdr:?}");
        }
        let plen = hdr.payload_len as usize;
        let mut rx = vec![0u8; plen];
        if plen > 0 {
            stream.read_exact(&mut rx).await?;
        }
        let pong: PongPayload = decode_postcard_payload(&rx)?;
        Ok(pong)
    }

    async fn rpc_postcard<Req: Serialize, Resp: for<'a> serde::Deserialize<'a>>(
        &self,
        opcode: OpCode,
        req: &Req,
        max_tx_buf: usize,
    ) -> Result<Resp> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let mut tx_buf = vec![0u8; max_tx_buf.max(1024)];
        let total = encode_postcard_frame(opcode, req_id, FLAG_NONE, req, &mut tx_buf)?;

        let mut stream = self.conn.lock().await;
        stream.write_all(&tx_buf[..total]).await?;

        let mut hdr_buf = [0u8; HEADER_LEN];
        stream.read_exact(&mut hdr_buf).await?;
        let hdr = VsockFrameHeader::from_bytes(&hdr_buf)?;
        if hdr.opcode != opcode {
            bail!("unexpected reply opcode {:?} (expected {:?})", hdr.opcode, opcode);
        }
        let plen = hdr.payload_len as usize;
        let mut rx = vec![0u8; plen];
        if plen > 0 {
            stream.read_exact(&mut rx).await?;
        }
        let resp: Resp = decode_postcard_payload(&rx)?;
        Ok(resp)
    }

    async fn send_control_ack(&self, opcode: OpCode) -> Result<()> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let hdr = VsockFrameHeader::new(opcode, req_id, 0, FLAG_NONE);

        let mut stream = self.conn.lock().await;
        stream.write_all(&hdr.to_bytes()).await?;

        let mut reply_buf = [0u8; HEADER_LEN];
        stream.read_exact(&mut reply_buf).await?;
        let reply = VsockFrameHeader::from_bytes(&reply_buf)?;
        if reply.opcode != opcode {
            bail!("unexpected reply opcode {:?} for {:?}", reply.opcode, opcode);
        }
        let plen = reply.payload_len as usize;
        if plen > 0 {
            let mut discard = vec![0u8; plen];
            stream.read_exact(&mut discard).await?;
        }
        Ok(())
    }

    fn destroy_sync(&self) {
        if self.destroyed.swap(true, Ordering::SeqCst) {
            return;
        }

        if self.child_pid > 0 {
            unsafe {
                libc::kill(self.child_pid, libc::SIGKILL);
            }
            let mut status: libc::c_int = 0;
            loop {
                let rc = unsafe { libc::waitpid(self.child_pid, &mut status, 0) };
                if rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
        }
        let _ = self.cgroups.destroy_sandbox_cgroup(&self.id);
        let _ = fs::remove_dir_all(&self.state_dir);
    }
}

impl Drop for NativeSandboxHandle {
    fn drop(&mut self) {
        self.destroy_sync();
    }
}

#[async_trait]
impl SandboxHandle for NativeSandboxHandle {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn proxy_env(&self) -> &[(String, String)] {
        &self.proxy_env
    }

    fn is_sleeping(&self) -> bool {
        self.sleeping.load(Ordering::Relaxed)
    }

    async fn exec(
        &self,
        req: &ExecRequest,
        mut on_output: Option<StreamCallback<'_>>,
    ) -> Result<ExecOutput> {
        let mut effective_req = req.clone();
        for (k, v) in &self.proxy_env {
            if !effective_req.env.iter().any(|(ek, _)| ek == k) {
                effective_req.env.push((k.clone(), v.clone()));
            }
        }

        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let mut tx_buf = vec![0u8; 64 * 1024];
        let total = encode_postcard_frame(
            OpCode::ExecReq,
            req_id,
            FLAG_NONE,
            &effective_req,
            &mut tx_buf,
        )?;

        let mut stream = self.conn.lock().await;
        stream.write_all(&tx_buf[..total]).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut hdr_buf = [0u8; HEADER_LEN];
        let mut rx_buf = vec![0u8; 64 * 1024];

        loop {
            stream.read_exact(&mut hdr_buf).await?;
            let hdr = VsockFrameHeader::from_bytes(&hdr_buf)?;
            let plen = hdr.payload_len as usize;
            if plen > MAX_PAYLOAD_LEN as usize {
                bail!("guest frame payload too large: {plen}");
            }
            if rx_buf.len() < plen {
                rx_buf.resize(plen, 0);
            }
            if plen > 0 {
                stream.read_exact(&mut rx_buf[..plen]).await?;
            }

            match hdr.opcode {
                OpCode::StdoutData => {
                    let chunk = &rx_buf[..plen];
                    if let Some(cb) = on_output.as_deref_mut() {
                        cb(true, chunk);
                    }
                    stdout.extend_from_slice(chunk);
                }
                OpCode::StderrData => {
                    let chunk = &rx_buf[..plen];
                    if let Some(cb) = on_output.as_deref_mut() {
                        cb(false, chunk);
                    }
                    stderr.extend_from_slice(chunk);
                }
                OpCode::ExecExit => {
                    let exit: ExecExitPayload = if plen > 0 {
                        decode_postcard_payload(&rx_buf[..plen])?
                    } else {
                        ExecExitPayload {
                            exit_code: -1,
                            term_signal: None,
                            user_cpu_us: 0,
                            sys_cpu_us: 0,
                            max_rss_kb: 0,
                            elapsed_us: 0,
                            error: Some(String::from("empty ExecExit payload")),
                        }
                    };
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
                other => {
                    warn!(?other, "unexpected frame from guest during exec");
                }
            }
        }
    }

    async fn repl_exec(&self, req: &ReplExecRequest) -> Result<ReplExecResponse> {
        let tx_cap = HEADER_LEN + req.code.len() + req.language.len() + 256;
        self.rpc_postcard(OpCode::ReplExec, req, tx_cap).await
    }

    async fn file_put(&self, req: &FilePutRequest) -> Result<FilePutResponse> {
        let tx_cap = HEADER_LEN + req.path.len() + req.data.len() + 256;
        self.rpc_postcard(OpCode::FilePut, req, tx_cap).await
    }

    async fn file_get(&self, req: &FileGetRequest) -> Result<FileGetResponse> {
        let tx_cap = HEADER_LEN + req.path.len() + 256;
        self.rpc_postcard(OpCode::FileGet, req, tx_cap).await
    }

    async fn signal(&self, req: &SignalRequest) -> Result<()> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let mut tx_buf = [0u8; 128];
        let total = encode_postcard_frame(OpCode::Signal, req_id, FLAG_NONE, req, &mut tx_buf)?;
        let mut stream = self.conn.lock().await;
        stream.write_all(&tx_buf[..total]).await?;
        Ok(())
    }

    async fn freeze(&self) -> Result<()> {
        self.send_control_ack(OpCode::Freeze).await?;
        if self.cgroups.is_delegated() {
            let _ = self.cgroups.freeze(&self.id);
        }
        Ok(())
    }

    async fn thaw(&self) -> Result<()> {
        if self.cgroups.is_delegated() {
            let _ = self.cgroups.thaw(&self.id);
        }
        self.send_control_ack(OpCode::Thaw).await
    }

    async fn sleep(&self) -> Result<()> {
        self.freeze().await?;
        if !self.cgroups.is_delegated() && self.child_pid > 0 {
            unsafe {
                libc::kill(self.child_pid, libc::SIGSTOP);
            }
        }
        self.sleeping.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn wake(&self) -> Result<()> {
        if !self.cgroups.is_delegated() && self.child_pid > 0 {
            unsafe {
                libc::kill(self.child_pid, libc::SIGCONT);
            }
        }
        self.thaw().await?;
        self.sleeping.store(false, Ordering::Relaxed);
        Ok(())
    }

    async fn checkpoint(&self, dest_dir: &Path) -> Result<CheckpointRecord> {
        fs::create_dir_all(dest_dir)
            .with_context(|| format!("failed to create checkpoint dir {}", dest_dir.display()))?;

        self.freeze().await?;
        let res = (async {
            let mut has_repl_state = false;
            if let Ok(resp) = self
                .file_get(&FileGetRequest {
                    path: String::from("/tmp/.sbx-repl-checkpoint.bin"),
                    max_bytes: 8 * 1024 * 1024,
                })
                .await
            {
                if resp.ok && !resp.data.is_empty() {
                    fs::write(dest_dir.join("repl-checkpoint.bin"), &resp.data)?;
                    has_repl_state = true;
                }
            }

            let mut has_upper_delta = false;
            if let Some(upper) = &self.upper_dir {
                if upper.is_dir() {
                    let upper_dest = dest_dir.join("rootfs-upper");
                    copy_dir_recursive(upper, &upper_dest)?;
                    has_upper_delta = true;
                }
            }

            let criu_dumped = if self.namespace_isolated && command_exists("criu") {
                let criu_dir = dest_dir.join("criu");
                let _ = fs::create_dir_all(&criu_dir);
                std::process::Command::new("criu")
                    .args([
                        "dump",
                        "-t",
                        &self.child_pid.to_string(),
                        "-D",
                        &criu_dir.to_string_lossy(),
                        "--shell-job",
                        "--leave-running",
                    ])
                    .status()
                    .is_ok_and(|s| s.success())
            } else {
                false
            };

            let record = CheckpointRecord {
                sandbox_id: self.id.as_str().to_string(),
                created_at_unix: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                has_repl_state,
                has_upper_delta,
                criu_dumped,
                backend: String::from("native"),
            };
            fs::write(
                dest_dir.join("checkpoint.json"),
                serde_json::to_vec_pretty(&record)?,
            )?;
            Ok(record)
        })
        .await;

        let _ = self.thaw().await;
        res
    }

    async fn destroy(&self) -> Result<()> {
        self.destroy_sync();
        Ok(())
    }
}

#[async_trait]
impl IsolationBackend for NativeBackend {
    async fn start(&self, cfg: &SandboxRuntimeConfig) -> Result<Box<dyn SandboxHandle>> {
        let state_dir = self.state_root.join(cfg.sandbox_id.as_str());
        if state_dir.exists() {
            let _ = fs::remove_dir_all(&state_dir);
        }
        let rootfs_dir = state_dir.join("rootfs");
        fs::create_dir_all(&rootfs_dir)?;

        let sock_path = state_dir.join("agent.sock");
        let listen_fd = bind_inheritable_unix_socket(&sock_path)?;
        let mut listen_guard = FdGuard(listen_fd);

        let cgroup_fd: RawFd = if self.cgroups.is_delegated() {
            let cgroup_dir = self
                .cgroups
                .create_sandbox_cgroup(&cfg.sandbox_id, &cfg.policy)?;
            let cgroup_cstr = CString::new(cgroup_dir.as_os_str().as_bytes())?;
            let fd = unsafe {
                libc::open(
                    cgroup_cstr.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let err = io::Error::last_os_error();
                let _ = self.cgroups.destroy_sandbox_cgroup(&cfg.sandbox_id);
                let _ = fs::remove_dir_all(&state_dir);
                return Err(err).with_context(|| {
                    format!("failed to open sandbox cgroup dir {}", cgroup_dir.display())
                });
            }
            fd
        } else {
            -1
        };
        let mut cgroup_guard = FdGuard(cgroup_fd);

        let wants_proxy = matches!(cfg.policy.network, NetworkPolicy::AllowlistProxy { .. });
        let (fd_pass_parent, fd_pass_child) = if wants_proxy {
            let mut fds = [-1 as RawFd; 2];
            if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) }
                != 0
            {
                return Err(io::Error::last_os_error()).context("socketpair for proxy fd failed");
            }
            unsafe {
                libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                libc::fcntl(fds[1], libc::F_SETFD, 0);
            }
            (fds[0], fds[1])
        } else {
            (-1, -1)
        };
        let mut fd_pass_parent_guard = FdGuard(fd_pass_parent);
        let mut fd_pass_child_guard = FdGuard(fd_pass_child);

        let host_uid = unsafe { libc::geteuid() };
        let host_gid = unsafe { libc::getegid() };
        let is_root = host_uid == 0;

        let proxy_url = if wants_proxy {
            Some(format!("http://127.0.0.1:{IN_NETNS_PROXY_PORT}"))
        } else {
            None
        };

        let prep = PreparedChildSetup::new(
            &rootfs_dir,
            &self.guest_agent_bin,
            &cfg.mounts,
            cfg.sandbox_id.as_str(),
            listen_fd,
            fd_pass_child,
            is_root,
            &cfg.policy,
            proxy_url.as_deref(),
        )?;

        let sync_pipe = create_cloexec_pipe()?;
        let err_pipe = create_cloexec_pipe()?;

        let mut clone_flags = (libc::CLONE_NEWNS
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWNET) as u64;
        if cgroup_fd >= 0 {
            clone_flags |= CLONE_INTO_CGROUP;
        }
        if !is_root {
            clone_flags |= libc::CLONE_NEWUSER as u64;
        }

        let clone_args = CloneArgs {
            flags: clone_flags,
            exit_signal: libc::SIGCHLD as u64,
            cgroup: if cgroup_fd >= 0 {
                cgroup_fd as u64
            } else {
                0
            },
            ..Default::default()
        };

        let child_pid = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &clone_args as *const CloneArgs,
                mem::size_of::<CloneArgs>(),
            )
        };
        if child_pid < 0 {
            let err = io::Error::last_os_error();
            let raw = err.raw_os_error();
            close_fd(cgroup_guard.0);
            cgroup_guard.0 = -1;
            close_fd(fd_pass_parent_guard.0);
            fd_pass_parent_guard.0 = -1;
            close_fd(fd_pass_child_guard.0);
            fd_pass_child_guard.0 = -1;
            close_fd(sync_pipe[0]);
            close_fd(sync_pipe[1]);
            close_fd(err_pipe[0]);
            close_fd(err_pipe[1]);
            let _ = self.cgroups.destroy_sandbox_cgroup(&cfg.sandbox_id);

            if matches!(
                raw,
                Some(libc::ENOSYS) | Some(libc::EPERM) | Some(libc::EINVAL)
            ) {
                warn!(
                    error = %err,
                    sandbox_id = %cfg.sandbox_id,
                    "nested namespaces unavailable in current environment; running sbx-guest-agent in confined local-process mode with seccomp/egress-proxy"
                );
                return self
                    .start_degraded_confined(cfg, state_dir, sock_path, listen_fd, listen_guard)
                    .await;
            }

            let _ = fs::remove_dir_all(&state_dir);
            return Err(err).context("SYS_clone3 failed creating sandbox namespaces");
        }

        if child_pid == 0 {
            close_fd(cgroup_fd);
            close_fd(fd_pass_parent);
            close_fd(sync_pipe[1]);
            close_fd(err_pipe[0]);
            child_init_and_exec(&prep, sync_pipe[0], err_pipe[1]);
        }

        let child_pid = child_pid as libc::pid_t;
        close_fd(cgroup_guard.0);
        cgroup_guard.0 = -1;
        close_fd(fd_pass_child_guard.0);
        fd_pass_child_guard.0 = -1;
        close_fd(sync_pipe[0]);
        close_fd(err_pipe[1]);
        close_fd(listen_guard.0);
        listen_guard.0 = -1;

        let _ = fs::write(state_dir.join("init.pid"), child_pid.to_string());

        let setup_res: Result<()> = (|| {
            if !is_root {
                write_proc_map(child_pid, "setgroups", "deny")?;
                write_proc_map(child_pid, "uid_map", &format!("0 {host_uid} 1\n"))?;
                write_proc_map(child_pid, "gid_map", &format!("0 {host_gid} 1\n"))?;
            }
            Ok(())
        })();

        if let Err(e) = setup_res {
            close_fd(fd_pass_parent_guard.0);
            fd_pass_parent_guard.0 = -1;
            close_fd(sync_pipe[1]);
            close_fd(err_pipe[0]);
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(child_pid, &mut status, 0);
            }
            let _ = self.cgroups.destroy_sandbox_cgroup(&cfg.sandbox_id);
            let _ = fs::remove_dir_all(&state_dir);
            return Err(e);
        }

        unsafe {
            let b: u8 = 1;
            libc::write(sync_pipe[1], (&b as *const u8).cast(), 1);
        }
        close_fd(sync_pipe[1]);

        let mut err_bytes = Vec::new();
        let mut err_file = unsafe { File::from_raw_fd(err_pipe[0]) };
        let _ = err_file.read_to_end(&mut err_bytes);
        if !err_bytes.is_empty() {
            let err_msg = String::from_utf8_lossy(&err_bytes).into_owned();
            close_fd(fd_pass_parent_guard.0);
            fd_pass_parent_guard.0 = -1;
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(child_pid, &mut status, 0);
            }
            let _ = self.cgroups.destroy_sandbox_cgroup(&cfg.sandbox_id);
            let _ = fs::remove_dir_all(&state_dir);
            bail!("sandbox init failed before execve: {err_msg}");
        }

        let (proxy, proxy_env) = if wants_proxy {
            let (in_netns_fd, actual_port) = sbx_net::recv_fd(fd_pass_parent_guard.0)
                .context("failed to receive in-netns proxy listener via SCM_RIGHTS")?;
            close_fd(fd_pass_parent_guard.0);
            fd_pass_parent_guard.0 = -1;
            let p = unsafe {
                EgressProxy::start_from_raw_fd(
                    in_netns_fd,
                    actual_port,
                    &cfg.policy.network,
                    cfg.policy.secret_bindings.clone(),
                    cfg.secret_vault.clone(),
                    cfg.host_overrides.clone(),
                )?
            };
            let env = p.sandbox_env();
            (Some(p), env)
        } else {
            (None, Vec::new())
        };

        let stream = UnixStream::connect(&sock_path).await.with_context(|| {
            format!("failed to connect to guest agent socket {}", sock_path.display())
        })?;

        let handle = NativeSandboxHandle {
            id: cfg.sandbox_id.clone(),
            child_pid,
            state_dir,
            upper_dir: extract_upper_dir(&cfg.mounts).or_else(|| cfg.rootfs_hint.clone()),
            cgroups: Arc::clone(&self.cgroups),
            conn: Mutex::new(stream),
            next_req_id: AtomicU32::new(1),
            destroyed: AtomicBool::new(false),
            sleeping: AtomicBool::new(false),
            namespace_isolated: true,
            _proxy: proxy,
            proxy_env,
        };

        let pong = handle
            .ping()
            .await
            .context("guest agent failed OP_PING readiness check")?;
        debug!(
            sandbox_id = %cfg.sandbox_id,
            host_pid = child_pid,
            guest_pid = pong.agent_pid,
            "native sandbox ready"
        );

        Ok(Box::new(handle))
    }

    async fn sleep(&self, id: &SandboxId) -> Result<()> {
        self.cgroups.freeze(id)
    }

    async fn wake(&self, id: &SandboxId) -> Result<()> {
        self.cgroups.thaw(id)
    }

    async fn checkpoint(&self, id: &SandboxId, dest: &Path) -> Result<()> {
        fs::create_dir_all(dest)?;
        self.cgroups.freeze(id)?;
        let state_dir = self.state_root.join(id.as_str());
        if let Ok(pid_str) = fs::read_to_string(state_dir.join("init.pid")) {
            let record = CheckpointRecord {
                sandbox_id: id.as_str().to_string(),
                created_at_unix: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                has_repl_state: false,
                has_upper_delta: false,
                criu_dumped: false,
                backend: String::from("native"),
            };
            fs::write(
                dest.join("checkpoint.json"),
                serde_json::to_vec_pretty(&record)?,
            )?;
            let _ = fs::write(dest.join("init.pid"), pid_str);
        }
        let _ = self.cgroups.thaw(id);
        Ok(())
    }

    async fn restore(
        &self,
        src: &Path,
        cfg: &SandboxRuntimeConfig,
    ) -> Result<Box<dyn SandboxHandle>> {
        let upper_src = src.join("rootfs-upper");
        if upper_src.is_dir() {
            if let Some(upper_dst) = extract_upper_dir(&cfg.mounts) {
                copy_dir_recursive(&upper_src, &upper_dst)?;
            }
        }

        let handle = self.start(cfg).await?;

        let repl_ckpt = src.join("repl-checkpoint.bin");
        if repl_ckpt.is_file() {
            let data = fs::read(&repl_ckpt)?;
            let resp = handle
                .file_put(&FilePutRequest {
                    path: String::from("/tmp/.sbx-repl-checkpoint.bin"),
                    mode: 0o600,
                    data: data.clone(),
                })
                .await?;
            if !resp.ok {
                warn!(
                    err = ?resp.error,
                    "failed uploading repl checkpoint to /tmp/.sbx-repl-checkpoint.bin"
                );
            }
            let _ = handle
                .file_put(&FilePutRequest {
                    path: String::from("/.sbx-repl-checkpoint.bin"),
                    mode: 0o600,
                    data,
                })
                .await;
        }

        Ok(handle)
    }

    async fn destroy(&self, id: &SandboxId) -> Result<()> {
        let state_dir = self.state_root.join(id.as_str());
        if let Ok(pid_str) = fs::read_to_string(state_dir.join("init.pid")) {
            if let Ok(pid) = pid_str.trim().parse::<libc::pid_t>() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        self.cgroups.destroy_sandbox_cgroup(id)?;
        if state_dir.exists() {
            let _ = fs::remove_dir_all(&state_dir);
        }
        Ok(())
    }
}

struct PreparedMount {
    source: CString,
    target: CString,
    fstype: Option<CString>,
    data: Option<CString>,
    is_bind: bool,
}

struct DeviceBind {
    host_dev: CString,
    guest_dev: CString,
}

struct PreparedChildSetup {
    rootfs: CString,
    mounts: Vec<PreparedMount>,
    dev_dir: CString,
    dev_shm: CString,
    dev_binds: Vec<DeviceBind>,
    proc_dir: CString,
    sys_dir: CString,
    tmp_dir: CString,
    old_root_dir: CString,
    host_agent: CString,
    guest_agent: CString,
    hostname: String,
    agent_argv: [CString; 3],
    agent_env: Vec<CString>,
    fd_pass_child: RawFd,
    seccomp: PreparedSeccomp,
    landlock: PreparedLandlock,
}

impl PreparedChildSetup {
    #[allow(clippy::too_many_arguments)]
    fn new(
        rootfs_dir: &Path,
        host_agent_bin: &Path,
        mounts: &[MountSpec],
        sandbox_id: &str,
        listen_fd: RawFd,
        fd_pass_child: RawFd,
        is_root: bool,
        policy: &sbx_proto::SecurityPolicy,
        proxy_url: Option<&str>,
    ) -> Result<Self> {
        let rootfs_cstr = CString::new(rootfs_dir.as_os_str().as_bytes())?;

        let mut prepared_mounts = Vec::with_capacity(mounts.len());
        for m in mounts {
            if m.r#type == "bind" {
                prepared_mounts.push(PreparedMount {
                    source: CString::new(m.source.as_str())?,
                    target: rootfs_cstr.clone(),
                    fstype: None,
                    data: None,
                    is_bind: true,
                });
            } else {
                let mut opts = m.options.join(",");
                if !is_root && m.r#type == "overlay" && !m.options.iter().any(|o| o == "userxattr")
                {
                    if !opts.is_empty() {
                        opts.push(',');
                    }
                    opts.push_str("userxattr");
                }
                prepared_mounts.push(PreparedMount {
                    source: CString::new(if m.source.is_empty() {
                        "overlay"
                    } else {
                        m.source.as_str()
                    })?,
                    target: rootfs_cstr.clone(),
                    fstype: Some(CString::new(m.r#type.as_str())?),
                    data: Some(CString::new(opts)?),
                    is_bind: false,
                });
            }
        }

        let dev_names = ["null", "zero", "full", "random", "urandom"];
        let mut dev_binds = Vec::with_capacity(dev_names.len());
        for name in dev_names {
            dev_binds.push(DeviceBind {
                host_dev: CString::new(format!("/dev/{name}"))?,
                guest_dev: CString::new(rootfs_dir.join("dev").join(name).as_os_str().as_bytes())?,
            });
        }

        let hostname = format!("sbx-{}", &sandbox_id[..sandbox_id.len().min(12)]);
        let agent_argv = [
            CString::new("/.sbx-guest-agent")?,
            CString::new("--listen-fd")?,
            CString::new(listen_fd.to_string())?,
        ];

        let mut agent_env = vec![CString::new(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )?];
        if let Some(url) = proxy_url {
            agent_env.push(CString::new(format!("HTTP_PROXY={url}"))?);
            agent_env.push(CString::new(format!("HTTPS_PROXY={url}"))?);
            agent_env.push(CString::new(format!("http_proxy={url}"))?);
            agent_env.push(CString::new(format!("https_proxy={url}"))?);
            agent_env.push(CString::new("NO_PROXY=localhost,127.0.0.1")?);
        }

        let enforce_ro = policy.readonly_rootfs || !policy.writable_paths.is_empty();
        Ok(Self {
            rootfs: rootfs_cstr,
            mounts: prepared_mounts,
            dev_dir: CString::new(rootfs_dir.join("dev").as_os_str().as_bytes())?,
            dev_shm: CString::new(rootfs_dir.join("dev/shm").as_os_str().as_bytes())?,
            dev_binds,
            proc_dir: CString::new(rootfs_dir.join("proc").as_os_str().as_bytes())?,
            sys_dir: CString::new(rootfs_dir.join("sys").as_os_str().as_bytes())?,
            tmp_dir: CString::new(rootfs_dir.join("tmp").as_os_str().as_bytes())?,
            old_root_dir: CString::new(rootfs_dir.join(".old_root").as_os_str().as_bytes())?,
            host_agent: CString::new(host_agent_bin.as_os_str().as_bytes())?,
            guest_agent: CString::new(
                rootfs_dir
                    .join(".sbx-guest-agent")
                    .as_os_str()
                    .as_bytes(),
            )?,
            hostname,
            agent_argv,
            agent_env,
            fd_pass_child,
            seccomp: PreparedSeccomp::new(policy.seccomp_mode),
            landlock: PreparedLandlock::new(&policy.writable_paths, enforce_ro),
        })
    }
}

fn child_init_and_exec(prep: &PreparedChildSetup, sync_r: RawFd, err_w: RawFd) -> ! {
    unsafe {
        let mut buf = [0u8; 1];
        let n = libc::read(sync_r, buf.as_mut_ptr().cast(), 1);
        libc::close(sync_r);
        if n <= 0 {
            write_err_and_exit(err_w, "parent aborted before uid_map sync");
        }

        if libc::mount(
            ptr::null(),
            c"/".as_ptr(),
            ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            ptr::null(),
        ) != 0
        {
            write_errno_and_exit(err_w, "mount MS_PRIVATE /");
        }

        for m in &prep.mounts {
            if m.is_bind {
                if libc::mount(
                    m.source.as_ptr(),
                    m.target.as_ptr(),
                    ptr::null(),
                    libc::MS_BIND | libc::MS_REC,
                    ptr::null(),
                ) != 0
                {
                    write_errno_and_exit(err_w, "bind mount rootfs");
                }
            } else {
                let fstype_ptr = m.fstype.as_ref().map_or(ptr::null(), |s| s.as_ptr());
                let data_ptr = m.data.as_ref().map_or(ptr::null(), |s| s.as_ptr().cast());
                if libc::mount(
                    m.source.as_ptr(),
                    m.target.as_ptr(),
                    fstype_ptr,
                    0,
                    data_ptr,
                ) != 0
                {
                    write_errno_and_exit(err_w, "mount overlay rootfs");
                }
            }
        }

        mkdir_if_missing(&prep.dev_dir, 0o755);
        mkdir_if_missing(&prep.dev_shm, 0o1777);
        mkdir_if_missing(&prep.proc_dir, 0o555);
        mkdir_if_missing(&prep.sys_dir, 0o555);
        mkdir_if_missing(&prep.tmp_dir, 0o1777);
        libc::chmod(prep.tmp_dir.as_ptr(), 0o1777);
        mkdir_if_missing(&prep.old_root_dir, 0o755);

        for db in &prep.dev_binds {
            touch_file_if_missing(&db.guest_dev, 0o666);
            if libc::mount(
                db.host_dev.as_ptr(),
                db.guest_dev.as_ptr(),
                ptr::null(),
                libc::MS_BIND,
                ptr::null(),
            ) != 0
            {
                write_errno_and_exit(err_w, "bind mount /dev device");
            }
        }

        let _ = libc::mount(
            c"tmpfs".as_ptr(),
            prep.dev_shm.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=1777,size=64m".as_ptr().cast(),
        );

        touch_file_if_missing(&prep.guest_agent, 0o755);
        if libc::mount(
            prep.host_agent.as_ptr(),
            prep.guest_agent.as_ptr(),
            ptr::null(),
            libc::MS_BIND,
            ptr::null(),
        ) != 0
        {
            write_errno_and_exit(err_w, "bind mount sbx-guest-agent");
        }
        let _ = libc::mount(
            ptr::null(),
            prep.guest_agent.as_ptr(),
            ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            ptr::null(),
        );

        let _ = libc::sethostname(prep.hostname.as_ptr().cast(), prep.hostname.len());

        if libc::chdir(prep.rootfs.as_ptr()) != 0 {
            write_errno_and_exit(err_w, "chdir to rootfs");
        }

        if libc::syscall(
            libc::SYS_pivot_root,
            c".".as_ptr(),
            c".old_root".as_ptr(),
        ) != 0
        {
            write_errno_and_exit(err_w, "pivot_root");
        }

        if libc::chdir(c"/".as_ptr()) != 0 {
            write_errno_and_exit(err_w, "chdir /");
        }

        if libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            ptr::null(),
        ) != 0
        {
            write_errno_and_exit(err_w, "mount /proc");
        }

        if libc::umount2(c"/.old_root".as_ptr(), libc::MNT_DETACH) != 0 {
            write_errno_and_exit(err_w, "umount2 /.old_root");
        }
        let _ = libc::rmdir(c"/.old_root".as_ptr());

        // Configure isolated network namespace loopback + proxy listener handoff before locking down.
        let _ = sbx_net::bring_up_loopback();
        if prep.fd_pass_child >= 0 {
            let bind_res = sbx_net::bind_in_netns_tcp_listener(IN_NETNS_PROXY_PORT)
                .or_else(|_| sbx_net::bind_in_netns_tcp_listener(0));
            match bind_res {
                Ok((tcp_fd, port)) => {
                    let _ = sbx_net::send_fd(prep.fd_pass_child, tcp_fd, port);
                    libc::close(tcp_fd);
                }
                Err(_) => write_errno_and_exit(err_w, "bind in-netns proxy listener"),
            }
            libc::close(prep.fd_pass_child);
        }

        // Enforce Landlock LSM + RO system directory remounts before Seccomp blocks mount/syscalls.
        prep.landlock.apply_in_child();

        // Install Seccomp-BPF filter as the final lock-down step before execve.
        if prep.seccomp.install().is_err() {
            write_errno_and_exit(err_w, "install seccomp-bpf filter");
        }

        let argv_ptrs: [*const libc::c_char; 4] = [
            prep.agent_argv[0].as_ptr(),
            prep.agent_argv[1].as_ptr(),
            prep.agent_argv[2].as_ptr(),
            ptr::null(),
        ];
        let mut envp_ptrs: Vec<*const libc::c_char> =
            prep.agent_env.iter().map(|s| s.as_ptr()).collect();
        envp_ptrs.push(ptr::null());

        libc::execve(
            prep.agent_argv[0].as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
        );
        write_errno_and_exit(err_w, "execve /.sbx-guest-agent");
    }
}

fn spawn_degraded_child(
    guest_agent_bin: &Path,
    listen_fd: RawFd,
    proxy_env: &[(String, String)],
    seccomp_mode: sbx_proto::SeccompMode,
) -> Result<libc::pid_t> {
    let err_pipe = create_cloexec_pipe()?;
    let agent_cstr = CString::new(guest_agent_bin.as_os_str().as_bytes())?;
    let argv_cstrs = [
        agent_cstr.clone(),
        CString::new("--listen-fd")?,
        CString::new(listen_fd.to_string())?,
    ];
    let argv_ptrs: [*const libc::c_char; 4] = [
        argv_cstrs[0].as_ptr(),
        argv_cstrs[1].as_ptr(),
        argv_cstrs[2].as_ptr(),
        ptr::null(),
    ];

    let mut env_cstrs = Vec::new();
    for (k, v) in std::env::vars() {
        if proxy_env.iter().any(|(pk, _)| pk == &k) {
            continue;
        }
        if let Ok(cs) = CString::new(format!("{k}={v}")) {
            env_cstrs.push(cs);
        }
    }
    for (k, v) in proxy_env {
        if let Ok(cs) = CString::new(format!("{k}={v}")) {
            env_cstrs.push(cs);
        }
    }
    let mut envp_ptrs: Vec<*const libc::c_char> = env_cstrs.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(ptr::null());

    let seccomp = PreparedSeccomp::new(seccomp_mode);
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        let err = io::Error::last_os_error();
        close_fd(err_pipe[0]);
        close_fd(err_pipe[1]);
        return Err(err).context("fork failed in degraded fallback");
    }

    if child_pid == 0 {
        unsafe {
            close_fd(err_pipe[0]);
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            let _ = seccomp.install();
            libc::execve(
                agent_cstr.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            );
            write_errno_and_exit(err_pipe[1], "execve degraded sbx-guest-agent");
        }
    }

    close_fd(err_pipe[1]);
    let mut err_bytes = Vec::new();
    let mut err_file = unsafe { File::from_raw_fd(err_pipe[0]) };
    let _ = err_file.read_to_end(&mut err_bytes);
    if !err_bytes.is_empty() {
        let err_msg = String::from_utf8_lossy(&err_bytes).into_owned();
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(child_pid, &mut status, 0);
        }
        bail!("degraded sandbox init failed before execve: {err_msg}");
    }

    Ok(child_pid)
}

pub fn extract_upper_dir(mounts: &[MountSpec]) -> Option<PathBuf> {
    for m in mounts {
        if m.r#type == "bind" && !m.source.is_empty() {
            return Some(PathBuf::from(&m.source));
        }
        if m.r#type == "overlay" {
            for opt in &m.options {
                if let Some(upper) = opt.strip_prefix("upperdir=") {
                    return Some(PathBuf::from(upper));
                }
            }
        }
    }
    None
}

pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if ft.is_file() {
            fs::copy(&src_path, &dst_path)?;
            if let Ok(meta) = fs::metadata(&src_path) {
                let _ = fs::set_permissions(&dst_path, meta.permissions());
            }
        } else if ft.is_symlink() {
            if let Ok(target) = fs::read_link(&src_path) {
                let _ = fs::remove_file(&dst_path);
                let _ = std::os::unix::fs::symlink(target, &dst_path);
            }
        }
    }
    Ok(())
}

fn command_exists(bin: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if Path::new(dir).join(bin).is_file() {
                return true;
            }
        }
    }
    false
}

unsafe fn mkdir_if_missing(path: &CStr, mode: libc::mode_t) {
    libc::mkdir(path.as_ptr(), mode);
}

unsafe fn touch_file_if_missing(path: &CStr, mode: libc::mode_t) {
    let fd = libc::open(path.as_ptr(), libc::O_CREAT | libc::O_WRONLY, mode);
    if fd >= 0 {
        libc::close(fd);
    }
}

unsafe fn write_err_and_exit(err_w: RawFd, msg: &str) -> ! {
    libc::write(err_w, msg.as_ptr().cast(), msg.len());
    libc::close(err_w);
    libc::_exit(126);
}

unsafe fn write_errno_and_exit(err_w: RawFd, stage: &str) -> ! {
    let errno_val = *libc::__errno_location();
    let msg = format!("{stage} failed (errno={errno_val})");
    libc::write(err_w, msg.as_ptr().cast(), msg.len());
    libc::close(err_w);
    libc::_exit(126);
}

fn bind_inheritable_unix_socket(path: &Path) -> Result<RawFd> {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_UNIX) failed");
    }

    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = c_path.as_bytes_with_nul();
    if bytes.len() > addr.sun_path.len() {
        close_fd(fd);
        bail!("unix socket path too long: {}", path.display());
    }
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }

    let len = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), len) } != 0 {
        let err = io::Error::last_os_error();
        close_fd(fd);
        return Err(err).with_context(|| format!("bind({}) failed", path.display()));
    }

    if unsafe { libc::listen(fd, 64) } != 0 {
        let err = io::Error::last_os_error();
        close_fd(fd);
        return Err(err).context("listen() failed");
    }

    unsafe {
        libc::fcntl(fd, libc::F_SETFD, 0);
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(fd)
}

fn create_cloexec_pipe() -> Result<[RawFd; 2]> {
    let mut fds = [-1 as RawFd; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error()).context("pipe2 failed");
    }
    Ok(fds)
}

fn close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn write_proc_map(pid: libc::pid_t, file: &str, content: &str) -> Result<()> {
    let path = format!("/proc/{pid}/{file}");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open {path}"))?;
    f.write_all(content.as_bytes())
        .with_context(|| format!("failed to write {path}"))?;
    Ok(())
}

/// Locate the static `sbx-guest-agent` binary automatically.
pub fn locate_guest_agent_binary() -> Result<PathBuf> {
    if let Ok(env_bin) = std::env::var("SBX_GUEST_AGENT_BIN") {
        let p = PathBuf::from(env_bin);
        if p.is_file() {
            return Ok(p);
        }
    }

    let arch_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        other => other,
    };

    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        for anc in exe.ancestors().take(7) {
            candidates.push(anc.join(arch_target).join("release/sbx-guest-agent"));
            candidates.push(anc.join(arch_target).join("debug/sbx-guest-agent"));
        }
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("sbx-guest-agent"));
        }
    }
    candidates.push(PathBuf::from(format!(
        "target/{arch_target}/release/sbx-guest-agent"
    )));
    candidates.push(PathBuf::from(format!(
        "target/{arch_target}/debug/sbx-guest-agent"
    )));
    candidates.push(PathBuf::from(format!(
        "../../target/{arch_target}/release/sbx-guest-agent"
    )));
    candidates.push(PathBuf::from("/usr/local/bin/sbx-guest-agent"));

    for c in &candidates {
        if c.is_file() && is_static_elf(c) {
            return Ok(c.clone());
        }
    }
    for c in &candidates {
        if c.is_file() {
            return Ok(c.clone());
        }
    }

    bail!(
        "could not locate sbx-guest-agent binary (checked SBX_GUEST_AGENT_BIN and {:?}); build with `cargo build --release --target {arch_target} -p sbx-guest-agent`",
        candidates
    )
}

/// Check ELF64 program headers for absence of `PT_INTERP` (p_type == 3).
fn is_static_elf(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut header = [0u8; 64];
    if f.read_exact(&mut header).is_err() {
        return false;
    }
    if &header[0..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return false;
    }
    let e_phoff = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(header[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(header[56..58].try_into().unwrap()) as usize;
    if e_phentsize < 4 || e_phnum > 128 {
        return false;
    }
    use std::io::Seek;
    if f.seek(io::SeekFrom::Start(e_phoff)).is_err() {
        return false;
    }
    let mut ph_buf = vec![0u8; e_phentsize * e_phnum];
    if f.read_exact(&mut ph_buf).is_err() {
        return false;
    }
    for i in 0..e_phnum {
        let off = i * e_phentsize;
        let p_type = u32::from_le_bytes(ph_buf[off..off + 4].try_into().unwrap());
        if p_type == 3 {
            return false;
        }
    }
    true
}
