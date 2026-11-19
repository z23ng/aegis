use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use sbx_proto::{BackendKind, ExecRequest, ReplExecRequest, SecurityPolicy};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::{ControlPlane, DaemonRequest, DaemonResponse};

const MAX_RPC_FRAME: usize = 32 * 1024 * 1024;

/// Default Unix socket path for `sbx-daemon`.
pub fn default_daemon_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("SBX_DAEMON_SOCK") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        PathBuf::from("/run/sbx/daemon.sock")
    } else {
        PathBuf::from(format!("/tmp/sbx-daemon-{uid}/daemon.sock"))
    }
}

/// Serve length-prefixed JSON RPC over a Unix domain socket until shutdown.
pub async fn serve_uds(
    sock_path: &Path,
    cp: Arc<ControlPlane>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    if sock_path.exists() {
        let _ = std::fs::remove_file(sock_path);
    }
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(sock_path)
        .with_context(|| format!("failed to bind daemon socket {}", sock_path.display()))?;
    info!(socket = %sock_path.display(), "sbx-daemon UDS server listening");

    loop {
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let cp_c = Arc::clone(&cp);
                        tokio::spawn(async move {
                            if let Err(e) = handle_uds_conn(stream, cp_c).await {
                                debug!(error = %e, "daemon UDS client disconnected");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "daemon UDS accept failed");
                    }
                }
            }
        }
    }

    let _ = std::fs::remove_file(sock_path);
    Ok(())
}

async fn handle_uds_conn(mut stream: UnixStream, cp: Arc<ControlPlane>) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_RPC_FRAME {
            bail!("RPC request frame {len} exceeds maximum {MAX_RPC_FRAME}");
        }
        let mut body = vec![0u8; len];
        if len > 0 {
            stream.read_exact(&mut body).await?;
        }

        let resp = match serde_json::from_slice::<DaemonRequest>(&body) {
            Ok(req) => cp.handle_request(req).await,
            Err(e) => DaemonResponse::Error(format!("invalid request JSON: {e}")),
        };
        let resp_bytes = serde_json::to_vec(&resp)?;
        stream
            .write_all(&(resp_bytes.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&resp_bytes).await?;
    }
}

/// Client for communicating with `sbx-daemon` over its Unix domain socket.
pub struct DaemonClient {
    stream: UnixStream,
}

impl DaemonClient {
    pub async fn connect(explicit_socket: Option<&Path>) -> Result<Self> {
        let sock = explicit_socket
            .map(Path::to_path_buf)
            .unwrap_or_else(default_daemon_socket_path);
        let stream = UnixStream::connect(&sock)
            .await
            .with_context(|| format!("failed connecting to sbx-daemon at {}", sock.display()))?;
        Ok(Self { stream })
    }

    /// Connect to an existing `sbx-daemon` or auto-launch one in the background.
    pub async fn connect_or_autostart(explicit_socket: Option<&Path>) -> Result<Self> {
        let sock = explicit_socket
            .map(Path::to_path_buf)
            .unwrap_or_else(default_daemon_socket_path);
        if let Ok(client) = Self::connect(Some(&sock)).await {
            return Ok(client);
        }

        let daemon_bin = locate_daemon_binary()?;
        if let Some(parent) = sock.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log_path = sock
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join("sbx-daemon.log");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let log_err = log_file.try_clone()?;

        let mut cmd = Command::new(&daemon_bin);
        cmd.args(["--socket", &sock.to_string_lossy()])
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_err));
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let _child = cmd.spawn().with_context(|| {
            format!("failed auto-starting sbx-daemon from {}", daemon_bin.display())
        })?;

        for _ in 0..80 {
            if let Ok(mut c) = Self::connect(Some(&sock)).await {
                if matches!(c.request(&DaemonRequest::Ping).await, Ok(DaemonResponse::Pong { .. })) {
                    return Ok(c);
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        bail!(
            "timed out waiting for auto-started sbx-daemon at {} (log: {})",
            sock.display(),
            log_path.display()
        )
    }

    pub async fn request(&mut self, req: &DaemonRequest) -> Result<DaemonResponse> {
        let bytes = serde_json::to_vec(req)?;
        self.stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await?;
        self.stream.write_all(&bytes).await?;

        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_RPC_FRAME {
            bail!("RPC response frame {len} exceeds maximum {MAX_RPC_FRAME}");
        }
        let mut resp_bytes = vec![0u8; len];
        if len > 0 {
            self.stream.read_exact(&mut resp_bytes).await?;
        }
        let resp: DaemonResponse = serde_json::from_slice(&resp_bytes)?;
        Ok(resp)
    }
}

fn locate_daemon_binary() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("SBX_DAEMON_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        for anc in exe.ancestors().take(5) {
            for sub in ["sbx-daemon", "release/sbx-daemon", "debug/sbx-daemon"] {
                let c = anc.join(sub);
                if c.is_file() {
                    return Ok(c);
                }
            }
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let c = Path::new(dir).join("sbx-daemon");
            if c.is_file() {
                return Ok(c);
            }
        }
    }
    for c in [
        "target/release/sbx-daemon",
        "target/debug/sbx-daemon",
        "/usr/local/bin/sbx-daemon",
    ] {
        let p = Path::new(c);
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
    }
    bail!("could not locate sbx-daemon binary")
}

// --- Optional Axum HTTP Control API ---

pub fn build_http_router(cp: Arc<ControlPlane>) -> Router {
    Router::new()
        .route("/health", get(http_health))
        .route("/v1/sandboxes", get(http_list).post(http_create))
        .route("/v1/sandboxes/{id}", get(http_inspect).delete(http_destroy))
        .route("/v1/sandboxes/{id}/exec", post(http_exec))
        .route("/v1/sandboxes/{id}/repl", post(http_repl))
        .route("/v1/sandboxes/{id}/snapshot", post(http_snapshot))
        .route("/v1/sandboxes/{id}/diff", get(http_diff))
        .route("/v1/sandboxes/{id}/rollback", post(http_rollback))
        .route("/v1/snapshots/{id}/fork", post(http_fork))
        .route("/v1/sandboxes/{id}/checkpoint", post(http_checkpoint))
        .route("/v1/checkpoints/{id}/restore", post(http_restore))
        .route("/v1/sandboxes/{id}/sleep", post(http_sleep))
        .route("/v1/sandboxes/{id}/wake", post(http_wake))
        .route(
            "/v1/warm-pool",
            get(http_pool_status).post(http_pool_configure),
        )
        .with_state(cp)
}

pub async fn serve_http(
    addr: SocketAddr,
    cp: Arc<ControlPlane>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let router = build_http_router(cp);
    info!(%addr, "sbx-daemon HTTP API listening");
    loop {
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let svc = TowerToHyperService::new(router.clone());
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .await;
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "HTTP accept failed");
                    }
                }
            }
        }
    }
    Ok(())
}

fn to_http_response(resp: DaemonResponse) -> Response {
    let status = match resp {
        DaemonResponse::Error(ref msg) if msg.contains("not found") => StatusCode::NOT_FOUND,
        DaemonResponse::Error(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::OK,
    };
    let body = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{}".to_vec());
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn parse_json_body<T: serde::de::DeserializeOwned>(bytes: &Bytes) -> Result<T, Response> {
    serde_json::from_slice(bytes)
        .map_err(|e| to_http_response(DaemonResponse::Error(format!("invalid JSON body: {e}"))))
}

async fn http_health(State(cp): State<Arc<ControlPlane>>) -> Response {
    to_http_response(cp.handle_request(DaemonRequest::Ping).await)
}

async fn http_list(State(cp): State<Arc<ControlPlane>>) -> Response {
    to_http_response(cp.handle_request(DaemonRequest::ListSandboxes).await)
}

#[derive(Deserialize)]
struct CreateBody {
    id: Option<String>,
    image: String,
    policy: Option<SecurityPolicy>,
    #[serde(default)]
    env: Vec<(String, String)>,
    #[serde(default)]
    secrets: HashMap<String, String>,
}

async fn http_create(State(cp): State<Arc<ControlPlane>>, body: Bytes) -> Response {
    let b: CreateBody = match parse_json_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    to_http_response(
        cp.handle_request(DaemonRequest::CreateSandbox {
            id: b.id,
            image: b.image,
            policy: b.policy,
            env: b.env,
            secrets: b.secrets,
        })
        .await,
    )
}

async fn http_inspect(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    to_http_response(
        cp.handle_request(DaemonRequest::InspectSandbox { sandbox_id: id })
            .await,
    )
}

async fn http_destroy(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    to_http_response(
        cp.handle_request(DaemonRequest::DestroySandbox { sandbox_id: id })
            .await,
    )
}

async fn http_exec(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    let req: ExecRequest = match parse_json_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    to_http_response(
        cp.handle_request(DaemonRequest::Exec {
            sandbox_id: id,
            req,
        })
        .await,
    )
}

async fn http_repl(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    let req: ReplExecRequest = match parse_json_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    to_http_response(
        cp.handle_request(DaemonRequest::ReplExec {
            sandbox_id: id,
            req,
        })
        .await,
    )
}

#[derive(Deserialize, Default)]
struct SnapshotBody {
    label: Option<String>,
}

async fn http_snapshot(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    let b: SnapshotBody = if body.is_empty() {
        SnapshotBody::default()
    } else {
        match parse_json_body(&body) {
            Ok(v) => v,
            Err(r) => return r,
        }
    };
    to_http_response(
        cp.handle_request(DaemonRequest::Snapshot {
            sandbox_id: id,
            label: b.label,
        })
        .await,
    )
}

async fn http_diff(State(cp): State<Arc<ControlPlane>>, AxumPath(id): AxumPath<String>) -> Response {
    to_http_response(cp.handle_request(DaemonRequest::Diff { sandbox_id: id }).await)
}

#[derive(Deserialize)]
struct RollbackBody {
    snapshot_id: String,
}

async fn http_rollback(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    let b: RollbackBody = match parse_json_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    to_http_response(
        cp.handle_request(DaemonRequest::Rollback {
            sandbox_id: id,
            snapshot_id: b.snapshot_id,
        })
        .await,
    )
}

#[derive(Deserialize)]
struct ForkBody {
    count: usize,
    policy: Option<SecurityPolicy>,
}

async fn http_fork(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    let b: ForkBody = match parse_json_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    to_http_response(
        cp.handle_request(DaemonRequest::Fork {
            snapshot_id: id,
            count: b.count,
            policy: b.policy,
        })
        .await,
    )
}

async fn http_checkpoint(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    to_http_response(
        cp.handle_request(DaemonRequest::Checkpoint { sandbox_id: id })
            .await,
    )
}

#[derive(Deserialize, Default)]
struct RestoreBody {
    new_sandbox_id: Option<String>,
}

async fn http_restore(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    let b: RestoreBody = if body.is_empty() {
        RestoreBody::default()
    } else {
        match parse_json_body(&body) {
            Ok(v) => v,
            Err(r) => return r,
        }
    };
    to_http_response(
        cp.handle_request(DaemonRequest::Restore {
            checkpoint_id: id,
            new_sandbox_id: b.new_sandbox_id,
        })
        .await,
    )
}

async fn http_sleep(
    State(cp): State<Arc<ControlPlane>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    to_http_response(cp.handle_request(DaemonRequest::Sleep { sandbox_id: id }).await)
}

async fn http_wake(State(cp): State<Arc<ControlPlane>>, AxumPath(id): AxumPath<String>) -> Response {
    to_http_response(cp.handle_request(DaemonRequest::Wake { sandbox_id: id }).await)
}

async fn http_pool_status(State(cp): State<Arc<ControlPlane>>) -> Response {
    to_http_response(cp.handle_request(DaemonRequest::WarmPoolStatus).await)
}

#[derive(Deserialize)]
struct PoolConfigBody {
    image: String,
    #[serde(default)]
    backend: BackendKind,
    target_count: usize,
    policy: Option<SecurityPolicy>,
}

async fn http_pool_configure(State(cp): State<Arc<ControlPlane>>, body: Bytes) -> Response {
    let b: PoolConfigBody = match parse_json_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    to_http_response(
        cp.handle_request(DaemonRequest::ConfigureWarmPool {
            image: b.image,
            backend: b.backend,
            target_count: b.target_count,
            policy: b.policy,
        })
        .await,
    )
}
