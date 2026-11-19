use std::fs::{self, OpenOptions};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tracing::{debug, info};

/// Resolve the containerd gRPC Unix socket path according to precedence:
/// 1. Explicit path argument
/// 2. `SBX_CONTAINERD_SOCK` environment variable
/// 3. `/run/containerd/containerd.sock` (if reachable)
/// 4. `/tmp/sbx-containerd-{uid}/containerd.sock` (rootless local daemon)
pub fn resolve_socket_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    if let Ok(env_sock) = std::env::var("SBX_CONTAINERD_SOCK") {
        if !env_sock.trim().is_empty() {
            return PathBuf::from(env_sock);
        }
    }
    let system_sock = PathBuf::from("/run/containerd/containerd.sock");
    if is_socket_connectable(&system_sock) {
        return system_sock;
    }
    default_user_socket_path()
}

pub fn default_user_socket_path() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/sbx-containerd-{uid}/containerd.sock"))
}

pub fn is_socket_connectable(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    StdUnixStream::connect(path).is_ok()
}

/// Ensure a local `containerd` daemon is running at `socket_path` if it is not already reachable.
///
/// When running unprivileged (`geteuid() != 0`), `containerd` still attempts `mkdir /run/containerd`
/// on startup, so we launch it inside `unshare -Urm` with a private `tmpfs` mounted at `/run`
/// while storing `root`, `state`, and the gRPC socket in user-accessible directories.
pub async fn ensure_local_containerd_running(socket_path: &Path) -> Result<()> {
    if is_socket_connectable(socket_path) {
        return Ok(());
    }

    let uid = unsafe { libc::geteuid() };
    let user_sock = default_user_socket_path();

    // Only auto-bootstrap if targeting a user-writable socket (not system /run/containerd/containerd.sock as non-root).
    if uid != 0 && socket_path == Path::new("/run/containerd/containerd.sock") {
        bail!(
            "system socket {} is not reachable as non-root; use {}",
            socket_path.display(),
            user_sock.display()
        );
    }

    let sock_dir = socket_path
        .parent()
        .context("containerd socket path must have a parent directory")?;
    fs::create_dir_all(sock_dir)
        .with_context(|| format!("failed to create socket dir {}", sock_dir.display()))?;

    // Clean stale socket if left behind from a crashed daemon.
    if socket_path.exists() && !is_socket_connectable(socket_path) {
        let _ = fs::remove_file(socket_path);
    }
    let ttrpc_path = PathBuf::from(format!("{}.ttrpc", socket_path.display()));
    if ttrpc_path.exists() {
        let _ = fs::remove_file(&ttrpc_path);
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/tmp/sbx-home-{uid}")));
    let data_dir = home.join(".local/share/sbx/containerd");
    let root_dir = data_dir.join("root");
    let state_dir = sock_dir.join("state");
    fs::create_dir_all(&root_dir)?;
    fs::create_dir_all(&state_dir)?;

    let config_path = data_dir.join("config.toml");
    let config_contents = format!(
        r#"version = 2
root = "{root}"
state = "{state}"
disabled_plugins = [
  "io.containerd.grpc.v1.cri",
  "io.containerd.snapshotter.v1.aufs",
  "io.containerd.snapshotter.v1.btrfs",
  "io.containerd.snapshotter.v1.devmapper",
  "io.containerd.snapshotter.v1.zfs",
  "io.containerd.nri.v1.nri"
]
[grpc]
  address = "{grpc}"
[ttrpc]
  address = "{ttrpc}"
"#,
        root = root_dir.display(),
        state = state_dir.display(),
        grpc = socket_path.display(),
        ttrpc = ttrpc_path.display(),
    );
    fs::write(&config_path, config_contents)?;

    let log_path = data_dir.join("containerd.log");
    let log_out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open containerd log {}", log_path.display()))?;
    let log_err = log_out.try_clone()?;

    let containerd_bin = find_binary("containerd")?;
    info!(
        socket = %socket_path.display(),
        config = %config_path.display(),
        "starting local containerd daemon"
    );

    let mut cmd = if uid == 0 {
        let mut c = Command::new(&containerd_bin);
        c.arg("--config").arg(&config_path);
        c
    } else {
        let shell_cmd = format!(
            "mount -t tmpfs tmpfs /run && mkdir -p /run/containerd && exec '{}' --config '{}'",
            containerd_bin.display(),
            config_path.display()
        );
        let mut c = Command::new("unshare");
        c.args(["-Urm", "sh", "-c", &shell_cmd]);
        c
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err));

    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .context("failed to spawn local containerd daemon")?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if is_socket_connectable(socket_path) {
            debug!(socket = %socket_path.display(), "containerd socket ready");
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            let log_tail = fs::read_to_string(&log_path).unwrap_or_default();
            bail!(
                "containerd exited prematurely with {status}: {}",
                log_tail.lines().rev().take(10).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n")
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let log_tail = fs::read_to_string(&log_path).unwrap_or_default();
    bail!(
        "timed out waiting for containerd socket {} to listen; log tail:\n{}",
        socket_path.display(),
        log_tail
    )
}

fn find_binary(name: &str) -> Result<PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let local_bin = PathBuf::from(home).join(".local/bin").join(name);
        if local_bin.is_file() {
            return Ok(local_bin);
        }
    }
    bail!("could not locate `{name}` binary in PATH or ~/.local/bin")
}
