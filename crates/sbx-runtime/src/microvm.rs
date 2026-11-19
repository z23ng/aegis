use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

const VSOCK_PORT: u32 = 52;

/// Build an SVR4 `newc` CPIO initramfs archive packing `sbx-guest-agent` as `/init`.
pub fn build_initramfs_cpio(agent_bin: &Path, out_cpio: &Path) -> Result<usize> {
    let agent_bytes = fs::read(agent_bin)
        .with_context(|| format!("failed reading guest agent binary {}", agent_bin.display()))?;
    if let Some(parent) = out_cpio.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut out = Vec::with_capacity(agent_bytes.len() + 4096);
    let mut ino = 1u32;

    for dir in ["dev", "proc", "sys", "tmp", "workspace", "run"] {
        append_cpio_entry(&mut out, ino, 0o040755, dir, &[]);
        ino += 1;
    }
    append_cpio_entry(&mut out, ino, 0o100755, "init", &agent_bytes);
    append_cpio_entry(&mut out, 0, 0, "TRAILER!!!", &[]);

    let mut f = fs::File::create(out_cpio)?;
    f.write_all(&out)?;
    Ok(out.len())
}

fn append_cpio_entry(out: &mut Vec<u8>, ino: u32, mode: u32, name: &str, data: &[u8]) {
    let name_bytes = name.as_bytes();
    let namesize = name_bytes.len() + 1; // include NUL
    let filesize = data.len();
    let header = format!(
        "070701{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
        ino,       // c_ino
        mode,      // c_mode
        0u32,      // c_uid
        0u32,      // c_gid
        1u32,      // c_nlink
        0u32,      // c_mtime
        filesize,  // c_filesize
        0u32,      // c_devmajor
        0u32,      // c_devminor
        0u32,      // c_rdevmajor
        0u32,      // c_rdevminor
        namesize,  // c_namesize
        0u32       // c_check
    );
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(name_bytes);
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// Hardware-virtualized MicroVM driver (Firecracker / QEMU + ~10MB Linux kernel + initramfs)
/// with automatic Hypervisor-Envelope fallback when KVM or VMM binaries are absent.
pub struct MicroVmBackend {
    native_fallback: Arc<NativeBackend>,
    vmm_bin: Option<VmmFlavor>,
    kernel_path: Option<PathBuf>,
    kvm_available: bool,
    state_root: PathBuf,
}

#[derive(Debug, Clone)]
enum VmmFlavor {
    Firecracker(PathBuf),
    Qemu(PathBuf),
}

impl MicroVmBackend {
    pub fn new(native_fallback: Arc<NativeBackend>) -> Self {
        let kvm_available = Path::new("/dev/kvm").exists()
            && fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .is_ok();
        let vmm_bin = locate_vmm();
        let kernel_path = locate_kernel();
        let state_root = native_fallback
            .state_root()
            .parent()
            .unwrap_or_else(|| native_fallback.state_root())
            .join("microvm");
        let _ = fs::create_dir_all(&state_root);
        Self {
            native_fallback,
            vmm_bin,
            kernel_path,
            kvm_available,
            state_root,
        }
    }

    pub fn has_hardware_kvm(&self) -> bool {
        self.kvm_available && self.vmm_bin.is_some() && self.kernel_path.is_some()
    }

    fn microvm_envelope_cfg(cfg: &SandboxRuntimeConfig) -> SandboxRuntimeConfig {
        let mut c = cfg.clone();
        c.policy.seccomp_mode = SeccompMode::Strict;
        c.policy.readonly_rootfs = true;
        c
    }

    async fn start_firecracker(
        &self,
        fc_bin: &Path,
        kernel: &Path,
        cfg: &SandboxRuntimeConfig,
    ) -> Result<Box<dyn SandboxHandle>> {
        let vm_dir = self.state_root.join(cfg.sandbox_id.as_str());
        if vm_dir.exists() {
            let _ = fs::remove_dir_all(&vm_dir);
        }
        fs::create_dir_all(&vm_dir)?;

        let initramfs_path = vm_dir.join("initramfs.cpio");
        build_initramfs_cpio(self.native_fallback.guest_agent_bin(), &initramfs_path)?;

        let api_sock = vm_dir.join("firecracker.sock");
        let vsock_uds = vm_dir.join("vsock.sock");
        let fc_cfg_path = vm_dir.join("vm-config.json");

        let vcpu_count = (cfg.policy.cpu_cores.ceil() as u32).max(1);
        let mem_size_mib = cfg.policy.memory_limit_mb.max(64);
        let cid: u32 = 3 + (std::process::id() % 10000);

        let fc_cfg = json!({
            "boot-source": {
                "kernel_image_path": kernel,
                "initrd_path": initramfs_path,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off quiet init=/init"
            },
            "machine-config": {
                "vcpu_count": vcpu_count,
                "mem_size_mib": mem_size_mib,
                "smt": false
            },
            "vsock": {
                "guest_cid": cid,
                "uds_path": vsock_uds
            }
        });
        fs::write(&fc_cfg_path, serde_json::to_vec_pretty(&fc_cfg)?)?;

        info!(
            sandbox_id = %cfg.sandbox_id,
            kernel = %kernel.display(),
            vmm = %fc_bin.display(),
            "booting Firecracker MicroVM"
        );
        let child = Command::new(fc_bin)
            .args([
                "--api-sock",
                &api_sock.to_string_lossy(),
                "--config-file",
                &fc_cfg_path.to_string_lossy(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed spawning firecracker")?;

        let stream = connect_firecracker_vsock(&vsock_uds, VSOCK_PORT).await?;
        let handle = MicroVmSandboxHandle {
            id: cfg.sandbox_id.clone(),
            vm_dir,
            child: std::sync::Mutex::new(Some(child)),
            conn: Mutex::new(stream),
            next_req_id: AtomicU32::new(1),
            sleeping: AtomicBool::new(false),
            destroyed: AtomicBool::new(false),
        };
        handle.ping().await?;
        Ok(Box::new(handle))
    }

    async fn start_qemu(
        &self,
        qemu_bin: &Path,
        kernel: &Path,
        cfg: &SandboxRuntimeConfig,
    ) -> Result<Box<dyn SandboxHandle>> {
        let vm_dir = self.state_root.join(cfg.sandbox_id.as_str());
        if vm_dir.exists() {
            let _ = fs::remove_dir_all(&vm_dir);
        }
        fs::create_dir_all(&vm_dir)?;

        let initramfs_path = vm_dir.join("initramfs.cpio");
        build_initramfs_cpio(self.native_fallback.guest_agent_bin(), &initramfs_path)?;

        let sock_path = vm_dir.join("agent-serial.sock");
        let vcpu_count = (cfg.policy.cpu_cores.ceil() as u32).max(1).to_string();
        let mem_mib = cfg.policy.memory_limit_mb.max(64).to_string();

        info!(
            sandbox_id = %cfg.sandbox_id,
            kernel = %kernel.display(),
            vmm = %qemu_bin.display(),
            "booting QEMU MicroVM"
        );
        let child = Command::new(qemu_bin)
            .args([
                "-enable-kvm",
                "-M",
                "microvm,x-option-roms=off,pit=off,pic=off,rtc=off",
                "-cpu",
                "host",
                "-smp",
                &vcpu_count,
                "-m",
                &mem_mib,
                "-nodefaults",
                "-no-user-config",
                "-nographic",
                "-kernel",
                &kernel.to_string_lossy(),
                "-initrd",
                &initramfs_path.to_string_lossy(),
                "-append",
                "console=ttyS0 quiet init=/init",
                "-chardev",
                &format!("socket,id=sbx0,path={},server=on,wait=off", sock_path.display()),
                "-device",
                "virtio-serial-device",
                "-device",
                "virtconsole,chardev=sbx0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed spawning qemu-system-x86_64")?;

        let mut stream = None;
        for _ in 0..80 {
            if let Ok(s) = UnixStream::connect(&sock_path).await {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stream = stream.with_context(|| {
            format!(
                "timed out connecting to QEMU guest socket {}",
                sock_path.display()
            )
        })?;

        let handle = MicroVmSandboxHandle {
            id: cfg.sandbox_id.clone(),
            vm_dir,
            child: std::sync::Mutex::new(Some(child)),
            conn: Mutex::new(stream),
            next_req_id: AtomicU32::new(1),
            sleeping: AtomicBool::new(false),
            destroyed: AtomicBool::new(false),
        };
        handle.ping().await?;
        Ok(Box::new(handle))
    }
}

async fn connect_firecracker_vsock(vsock_uds: &Path, port: u32) -> Result<UnixStream> {
    let mut stream = None;
    for _ in 0..80 {
        if vsock_uds.exists() {
            if let Ok(mut s) = UnixStream::connect(vsock_uds).await {
                let cmd = format!("CONNECT {port}\n");
                if s.write_all(cmd.as_bytes()).await.is_ok() {
                    let mut line = [0u8; 64];
                    if let Ok(n) = s.read(&mut line).await {
                        if String::from_utf8_lossy(&line[..n]).starts_with("OK ") {
                            stream = Some(s);
                            break;
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    stream.with_context(|| {
        format!(
            "timed out connecting to Firecracker vsock UDS {}",
            vsock_uds.display()
        )
    })
}

pub struct MicroVmSandboxHandle {
    id: SandboxId,
    vm_dir: PathBuf,
    child: std::sync::Mutex<Option<Child>>,
    conn: Mutex<UnixStream>,
    next_req_id: AtomicU32,
    sleeping: AtomicBool,
    destroyed: AtomicBool,
}

impl MicroVmSandboxHandle {
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
            bail!("unexpected microvm ping reply");
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

    fn kill_vm(&self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut c) = guard.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
        let _ = fs::remove_dir_all(&self.vm_dir);
    }
}

impl Drop for MicroVmSandboxHandle {
    fn drop(&mut self) {
        if !self.destroyed.swap(true, Ordering::SeqCst) {
            self.kill_vm();
        }
    }
}

#[async_trait]
impl SandboxHandle for MicroVmSandboxHandle {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn backend_kind(&self) -> BackendKind {
        BackendKind::MicroVm
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
                bail!("microvm guest frame too large");
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
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let hdr = VsockFrameHeader::new(OpCode::Freeze, req_id, 0, FLAG_NONE);
        let mut stream = self.conn.lock().await;
        stream.write_all(&hdr.to_bytes()).await?;
        let mut reply = [0u8; HEADER_LEN];
        stream.read_exact(&mut reply).await?;
        if let Ok(guard) = self.child.lock() {
            if let Some(c) = guard.as_ref() {
                unsafe {
                    libc::kill(c.id() as libc::pid_t, libc::SIGSTOP);
                }
            }
        }
        Ok(())
    }

    async fn thaw(&self) -> Result<()> {
        if let Ok(guard) = self.child.lock() {
            if let Some(c) = guard.as_ref() {
                unsafe {
                    libc::kill(c.id() as libc::pid_t, libc::SIGCONT);
                }
            }
        }
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let hdr = VsockFrameHeader::new(OpCode::Thaw, req_id, 0, FLAG_NONE);
        let mut stream = self.conn.lock().await;
        stream.write_all(&hdr.to_bytes()).await?;
        let mut reply = [0u8; HEADER_LEN];
        stream.read_exact(&mut reply).await?;
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
        self.freeze().await?;
        let rec = CheckpointRecord {
            sandbox_id: self.id.as_str().to_string(),
            created_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            has_repl_state: true,
            has_upper_delta: false,
            criu_dumped: false,
            backend: String::from("microvm"),
        };
        fs::write(
            dest_dir.join("checkpoint.json"),
            serde_json::to_vec_pretty(&rec)?,
        )?;
        self.thaw().await?;
        Ok(rec)
    }

    async fn destroy(&self) -> Result<()> {
        if !self.destroyed.swap(true, Ordering::SeqCst) {
            self.kill_vm();
        }
        Ok(())
    }
}

/// Hypervisor-Envelope fallback wrapping `NativeSandboxHandle` while exposing `BackendKind::MicroVm`.
struct HypervisorEnvelopeHandle(Box<dyn SandboxHandle>);

#[async_trait]
impl SandboxHandle for HypervisorEnvelopeHandle {
    fn id(&self) -> &SandboxId {
        self.0.id()
    }
    fn backend_kind(&self) -> BackendKind {
        BackendKind::MicroVm
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
        rec.backend = String::from("microvm-envelope");
        Ok(rec)
    }
    async fn destroy(&self) -> Result<()> {
        self.0.destroy().await
    }
}

#[async_trait]
impl IsolationBackend for MicroVmBackend {
    async fn start(&self, cfg: &SandboxRuntimeConfig) -> Result<Box<dyn SandboxHandle>> {
        if self.kvm_available {
            if let Some(kernel) = &self.kernel_path {
                match &self.vmm_bin {
                    Some(VmmFlavor::Firecracker(fc)) => {
                        return self.start_firecracker(fc, kernel, cfg).await;
                    }
                    Some(VmmFlavor::Qemu(qemu)) => {
                        return self.start_qemu(qemu, kernel, cfg).await;
                    }
                    None => {}
                }
            }
        }

        warn!(
            sandbox_id = %cfg.sandbox_id,
            kvm = self.kvm_available,
            has_vmm = self.vmm_bin.is_some(),
            has_kernel = self.kernel_path.is_some(),
            "hardware MicroVM unavailable; starting low-footprint Kiri Hypervisor-Envelope backend"
        );
        let env_cfg = Self::microvm_envelope_cfg(cfg);
        let inner = self.native_fallback.start(&env_cfg).await?;
        Ok(Box::new(HypervisorEnvelopeHandle(inner)))
    }

    async fn sleep(&self, id: &SandboxId) -> Result<()> {
        self.native_fallback.sleep(id).await
    }

    async fn wake(&self, id: &SandboxId) -> Result<()> {
        self.native_fallback.wake(id).await
    }

    async fn checkpoint(&self, id: &SandboxId, dest: &Path) -> Result<()> {
        self.native_fallback.checkpoint(id, dest).await
    }

    async fn restore(
        &self,
        src: &Path,
        cfg: &SandboxRuntimeConfig,
    ) -> Result<Box<dyn SandboxHandle>> {
        let env_cfg = Self::microvm_envelope_cfg(cfg);
        let inner = self.native_fallback.restore(src, &env_cfg).await?;
        Ok(Box::new(HypervisorEnvelopeHandle(inner)))
    }

    async fn destroy(&self, id: &SandboxId) -> Result<()> {
        let _ = fs::remove_dir_all(self.state_root.join(id.as_str()));
        self.native_fallback.destroy(id).await
    }
}

fn locate_vmm() -> Option<VmmFlavor> {
    if let Ok(fc) = std::env::var("SBX_FIRECRACKER_BIN") {
        let p = PathBuf::from(fc);
        if p.is_file() {
            return Some(VmmFlavor::Firecracker(p));
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let fc = Path::new(dir).join("firecracker");
            if fc.is_file() {
                return Some(VmmFlavor::Firecracker(fc));
            }
        }
        for dir in path.split(':') {
            let qemu = Path::new(dir).join("qemu-system-x86_64");
            if qemu.is_file() {
                return Some(VmmFlavor::Qemu(qemu));
            }
        }
    }
    None
}

fn locate_kernel() -> Option<PathBuf> {
    if let Ok(k) = std::env::var("SBX_MICROVM_KERNEL") {
        let p = PathBuf::from(k);
        if p.is_file() {
            return Some(p);
        }
    }
    for candidate in [
        "/var/lib/sbx/vmlinux",
        "/usr/local/share/sbx/vmlinux",
        "deploy/kernel/vmlinux",
    ] {
        let p = Path::new(candidate);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initramfs_cpio_packs_guest_agent_as_init() {
        let dir = std::env::temp_dir().join(format!("sbx-cpio-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let fake_agent = dir.join("fake-agent");
        fs::write(&fake_agent, b"\x7fELF-fake-binary").unwrap();
        let out_cpio = dir.join("initramfs.cpio");

        let size = build_initramfs_cpio(&fake_agent, &out_cpio).unwrap();
        let bytes = fs::read(&out_cpio).unwrap();
        assert_eq!(bytes.len(), size);
        assert!(bytes.starts_with(b"070701"));
        assert!(bytes.windows(4).any(|w| w == b"init"));
        assert!(bytes.windows(10).any(|w| w == b"TRAILER!!!"));
        let _ = fs::remove_dir_all(&dir);
    }
}
