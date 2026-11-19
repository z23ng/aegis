use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use sbx_proto::{SandboxId, SecurityPolicy};
use tracing::{debug, warn};

/// Manages `cgroup v2` hierarchies and hard resource quotas for sandboxes.
#[derive(Debug, Clone)]
pub struct CgroupManager {
    base_dir: PathBuf,
    delegated: bool,
}

impl CgroupManager {
    /// Initialize cgroup v2 manager, automatically delegating into systemd user slice when non-root.
    /// Degrades gracefully (`delegated = false`) inside outer containers without systemd D-Bus.
    pub fn new() -> Result<Self> {
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            let base_dir = PathBuf::from("/sys/fs/cgroup/sbx.slice");
            let delegated = fs::create_dir_all(&base_dir).is_ok();
            if delegated {
                enable_subtree_controllers(&base_dir);
            } else {
                warn!(
                    path = %base_dir.display(),
                    "cgroup v2 hierarchy is not writable; running without cgroup delegation"
                );
            }
            return Ok(Self {
                base_dir,
                delegated,
            });
        }

        let user_base = PathBuf::from(format!(
            "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/sbx.slice"
        ));
        let delegated = match ensure_in_user_service_slice(uid) {
            Ok(()) => {
                if fs::create_dir_all(&user_base).is_ok() {
                    enable_subtree_controllers(&user_base);
                    true
                } else {
                    false
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "systemd user cgroup delegation unavailable; degrading to non-cgroup mode"
                );
                false
            }
        };

        let base_dir = if delegated {
            user_base
        } else {
            let fallback = PathBuf::from(format!("/tmp/sbx-runtime-{uid}/cgroups"));
            let _ = fs::create_dir_all(&fallback);
            fallback
        };

        Ok(Self {
            base_dir,
            delegated,
        })
    }

    pub fn is_delegated(&self) -> bool {
        self.delegated
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn sandbox_dir(&self, id: &SandboxId) -> PathBuf {
        self.base_dir.join(format!("sbx-{}", id.as_str()))
    }

    /// Create a dedicated cgroup v2 leaf for `id` and apply `cpu.max`, `memory.max`, and `pids.max`.
    pub fn create_sandbox_cgroup(
        &self,
        id: &SandboxId,
        policy: &SecurityPolicy,
    ) -> Result<PathBuf> {
        let dir = self.sandbox_dir(id);
        if !self.delegated {
            return Ok(dir);
        }

        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create sandbox cgroup {}", dir.display()))?;

        let quota = policy.cpu_quota_us.max(1000);
        let mem_bytes = policy.memory_limit_mb.max(16).saturating_mul(1024 * 1024);
        let pids_max = policy.pids_limit.max(4);

        let _ = fs::write(dir.join("cpu.max"), format!("{quota} 100000"));
        let _ = fs::write(dir.join("memory.max"), format!("{mem_bytes}"));
        let _ = fs::write(dir.join("pids.max"), format!("{pids_max}"));

        debug!(cgroup = %dir.display(), quota, mem_bytes, pids_max, "created sandbox cgroup v2");
        Ok(dir)
    }

    /// Attach a host PID to the sandbox's `cgroup.procs`.
    pub fn attach_pid(&self, id: &SandboxId, pid: libc::pid_t) -> Result<()> {
        if !self.delegated {
            return Ok(());
        }
        let procs_path = self.sandbox_dir(id).join("cgroup.procs");
        fs::write(&procs_path, pid.to_string()).with_context(|| {
            format!(
                "failed to attach pid {pid} to cgroup {}",
                procs_path.display()
            )
        })?;
        Ok(())
    }

    pub fn freeze(&self, id: &SandboxId) -> Result<()> {
        if !self.delegated {
            return Ok(());
        }
        let path = self.sandbox_dir(id).join("cgroup.freeze");
        fs::write(&path, "1")
            .with_context(|| format!("failed to freeze cgroup {}", path.display()))
    }

    pub fn thaw(&self, id: &SandboxId) -> Result<()> {
        if !self.delegated {
            return Ok(());
        }
        let path = self.sandbox_dir(id).join("cgroup.freeze");
        fs::write(&path, "0")
            .with_context(|| format!("failed to thaw cgroup {}", path.display()))
    }

    /// Terminate any remaining processes in the cgroup and remove the cgroup directory.
    pub fn destroy_sandbox_cgroup(&self, id: &SandboxId) -> Result<()> {
        if !self.delegated {
            return Ok(());
        }
        let dir = self.sandbox_dir(id);
        if !dir.exists() {
            return Ok(());
        }

        let kill_file = dir.join("cgroup.kill");
        if kill_file.exists() {
            let _ = fs::write(&kill_file, "1");
        } else if let Ok(procs) = fs::read_to_string(dir.join("cgroup.procs")) {
            for line in procs.lines() {
                if let Ok(pid) = line.trim().parse::<libc::pid_t>() {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }

        let procs_file = dir.join("cgroup.procs");
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            let empty = fs::read_to_string(&procs_file)
                .map(|s| s.trim().is_empty())
                .unwrap_or(true);
            if empty {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }

        // Kernel may briefly return EBUSY immediately after process exit; retry briefly.
        let rm_deadline = Instant::now() + Duration::from_millis(200);
        loop {
            match fs::remove_dir(&dir) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(_e) if Instant::now() < rm_deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("failed to remove sandbox cgroup {}", dir.display())
                    });
                }
            }
        }
    }

    /// List any active `sbx-*` cgroup directories under `base_dir`.
    pub fn list_active_cgroups(&self) -> Vec<String> {
        if !self.delegated {
            return Vec::new();
        }
        let Ok(entries) = fs::read_dir(&self.base_dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("sbx-") && e.path().is_dir() {
                    Some(name)
                } else {
                    None
                }
            })
            .collect()
    }
}

fn enable_subtree_controllers(base_dir: &Path) {
    let subtree_ctrl = base_dir.join("cgroup.subtree_control");
    if let Err(e) = fs::write(&subtree_ctrl, "+cpu +memory +pids") {
        warn!(
            path = %subtree_ctrl.display(),
            error = %e,
            "failed to enable all cgroup v2 subtree controllers (continuing with available ones)"
        );
        for ctrl in ["+cpu", "+memory", "+pids"] {
            let _ = fs::write(&subtree_ctrl, ctrl);
        }
    }
}

fn ensure_in_user_service_slice(uid: libc::uid_t) -> Result<()> {
    let needle = format!("user@{uid}.service");
    let current = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    if current.contains(&needle) {
        return Ok(());
    }

    let pid = std::process::id();
    let unit = format!("sbx-runtime-{pid}.scope");
    let status = Command::new("busctl")
        .args([
            "--user",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            &unit,
            "fail",
            "1",
            "PIDs",
            "au",
            "1",
            &pid.to_string(),
            "0",
        ])
        .output()
        .context("failed to invoke busctl for rootless cgroup v2 delegation")?;

    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        bail!("busctl StartTransientUnit failed: {stderr}");
    }

    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        let updated = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        if updated.contains(&needle) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    bail!("timed out waiting to enter {needle} cgroup scope")
}
