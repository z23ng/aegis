use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use prost::Message;
use sbx_containerd::MountSpec;
use sbx_proto::{BackendKind, ExecRequest, SecurityPolicy, SignalRequest};
use sbx_runtime::{RuntimeDispatcher, SandboxHandle, SandboxRuntimeConfig};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{watch, Mutex};
use tracing::{debug, info, warn};

pub const TASK_SERVICE_NAME: &str = "containerd.task.v2.Task";
pub const TTRPC_MSG_TYPE_REQUEST: u8 = 1;
pub const TTRPC_MSG_TYPE_RESPONSE: u8 = 2;

/// TTRPC 10-byte wire frame header:
/// - `length`: u32 BE
/// - `stream_id`: u32 BE
/// - `msg_type`: u8 (1=request, 2=response)
/// - `flags`: u8
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtrpcFrameHeader {
    pub length: u32,
    pub stream_id: u32,
    pub msg_type: u8,
    pub flags: u8,
}

impl TtrpcFrameHeader {
    pub fn to_bytes(self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out[0..4].copy_from_slice(&self.length.to_be_bytes());
        out[4..8].copy_from_slice(&self.stream_id.to_be_bytes());
        out[8] = self.msg_type;
        out[9] = self.flags;
        out
    }

    pub fn from_bytes(buf: &[u8; 10]) -> Self {
        Self {
            length: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            stream_id: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            msg_type: buf[8],
            flags: buf[9],
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct TtrpcKeyValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct TtrpcRequest {
    #[prost(string, tag = "1")]
    pub service: String,
    #[prost(string, tag = "2")]
    pub method: String,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
    #[prost(int64, tag = "4")]
    pub timeout_nano: i64,
    #[prost(message, repeated, tag = "5")]
    pub metadata: Vec<TtrpcKeyValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct TtrpcStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct TtrpcResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<TtrpcStatus>,
    #[prost(bytes = "vec", tag = "2")]
    pub payload: Vec<u8>,
}

// --- containerd.types.Mount ---
#[derive(Clone, PartialEq, Message)]
pub struct ProtoMount {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(string, tag = "2")]
    pub source: String,
    #[prost(string, tag = "3")]
    pub target: String,
    #[prost(string, repeated, tag = "4")]
    pub options: Vec<String>,
}

// --- containerd.task.v2.Task Status enum ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TaskStatus {
    Unknown = 0,
    Created = 1,
    Running = 2,
    Stopped = 3,
    Paused = 4,
}

#[derive(Clone, PartialEq, Message)]
pub struct CreateTaskRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub bundle: String,
    #[prost(message, repeated, tag = "3")]
    pub rootfs: Vec<ProtoMount>,
    #[prost(bool, tag = "4")]
    pub terminal: bool,
    #[prost(string, tag = "5")]
    pub stdin: String,
    #[prost(string, tag = "6")]
    pub stdout: String,
    #[prost(string, tag = "7")]
    pub stderr: String,
    #[prost(string, tag = "8")]
    pub checkpoint: String,
    #[prost(string, tag = "9")]
    pub parent_checkpoint: String,
    #[prost(message, optional, tag = "10")]
    pub options: Option<prost_types::Any>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CreateTaskResponse {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct StartRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct StartResponse {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct StateRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct StateResponse {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub bundle: String,
    #[prost(uint32, tag = "3")]
    pub pid: u32,
    #[prost(int32, tag = "4")]
    pub status: i32,
    #[prost(string, tag = "5")]
    pub stdin: String,
    #[prost(string, tag = "6")]
    pub stdout: String,
    #[prost(string, tag = "7")]
    pub stderr: String,
    #[prost(bool, tag = "8")]
    pub terminal: bool,
    #[prost(uint32, tag = "9")]
    pub exit_status: u32,
    #[prost(message, optional, tag = "10")]
    pub exited_at: Option<prost_types::Timestamp>,
    #[prost(string, tag = "11")]
    pub exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ExecProcessRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub exec_id: String,
    #[prost(bool, tag = "3")]
    pub terminal: bool,
    #[prost(string, tag = "4")]
    pub stdin: String,
    #[prost(string, tag = "5")]
    pub stdout: String,
    #[prost(string, tag = "6")]
    pub stderr: String,
    #[prost(message, optional, tag = "7")]
    pub spec: Option<prost_types::Any>,
}

#[derive(Clone, PartialEq, Message)]
pub struct WaitRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct WaitResponse {
    #[prost(uint32, tag = "1")]
    pub exit_status: u32,
    #[prost(message, optional, tag = "2")]
    pub exited_at: Option<prost_types::Timestamp>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PidsRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProcessInfo {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct PidsResponse {
    #[prost(message, repeated, tag = "1")]
    pub processes: Vec<ProcessInfo>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PauseRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ResumeRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct CheckpointTaskRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub path: String,
    #[prost(message, optional, tag = "3")]
    pub options: Option<prost_types::Any>,
}

#[derive(Clone, PartialEq, Message)]
pub struct KillRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub exec_id: String,
    #[prost(uint32, tag = "3")]
    pub signal: u32,
    #[prost(bool, tag = "4")]
    pub all: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct DeleteRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct DeleteResponse {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
    #[prost(uint32, tag = "2")]
    pub exit_status: u32,
    #[prost(message, optional, tag = "3")]
    pub exited_at: Option<prost_types::Timestamp>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ShutdownRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(bool, tag = "2")]
    pub now: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct ConnectRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ConnectResponse {
    #[prost(uint32, tag = "1")]
    pub shim_pid: u32,
    #[prost(uint32, tag = "2")]
    pub task_pid: u32,
    #[prost(string, tag = "3")]
    pub version: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Empty {}

#[derive(Debug, Deserialize)]
struct OciConfig {
    process: Option<OciProcess>,
    root: Option<OciRoot>,
}

#[derive(Debug, Deserialize)]
struct OciRoot {
    path: Option<String>,
    readonly: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct OciProcess {
    args: Option<Vec<String>>,
    env: Option<Vec<String>>,
    cwd: Option<String>,
}

struct ProcessSlot {
    pid: u32,
    status: TaskStatus,
    exit_status: u32,
    exited_at: Option<prost_types::Timestamp>,
    req: Option<ExecRequest>,
    stdout_path: String,
    stderr_path: String,
    terminal: bool,
    stdin_path: String,
    done_tx: watch::Sender<bool>,
    done_rx: watch::Receiver<bool>,
}

struct ManagedTask {
    id: String,
    bundle: String,
    handle: Arc<Box<dyn SandboxHandle>>,
    primary_pid: u32,
    processes: HashMap<String, ProcessSlot>,
}

/// containerd Runtime v2 `Task` service backed by `sbx-runtime`.
pub struct ShimTaskService {
    dispatcher: Arc<RuntimeDispatcher>,
    tasks: Mutex<HashMap<String, ManagedTask>>,
    next_pid: AtomicU32,
    shutdown_tx: watch::Sender<bool>,
}

impl ShimTaskService {
    pub fn new(dispatcher: Arc<RuntimeDispatcher>) -> (Arc<Self>, watch::Receiver<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let svc = Arc::new(Self {
            dispatcher,
            tasks: Mutex::new(HashMap::new()),
            next_pid: AtomicU32::new(100),
            shutdown_tx,
        });
        (svc, shutdown_rx)
    }

    pub async fn dispatch(self: &Arc<Self>, req: TtrpcRequest) -> TtrpcResponse {
        if req.service != TASK_SERVICE_NAME {
            return err_response(12, format!("unknown service: {}", req.service));
        }
        debug!(method = %req.method, "shim TTRPC dispatch");
        match req.method.as_str() {
            "Create" => self.handle_create(&req.payload).await,
            "Start" => self.handle_start(&req.payload).await,
            "State" => self.handle_state(&req.payload).await,
            "Exec" => self.handle_exec(&req.payload).await,
            "Wait" => self.handle_wait(&req.payload).await,
            "Pids" => self.handle_pids(&req.payload).await,
            "Pause" => self.handle_pause(&req.payload).await,
            "Resume" => self.handle_resume(&req.payload).await,
            "Checkpoint" => self.handle_checkpoint(&req.payload).await,
            "Kill" => self.handle_kill(&req.payload).await,
            "Delete" => self.handle_delete(&req.payload).await,
            "Shutdown" => self.handle_shutdown(&req.payload).await,
            "Connect" => self.handle_connect(&req.payload).await,
            other => err_response(12, format!("unimplemented method: {other}")),
        }
    }

    async fn handle_create(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match CreateTaskRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode CreateTaskRequest: {e}")),
        };

        let mut policy = SecurityPolicy::default();
        policy.backend = BackendKind::Native;
        let mut init_exec: Option<ExecRequest> = None;
        let mut mounts: Vec<MountSpec> = req
            .rootfs
            .iter()
            .map(|m| MountSpec {
                r#type: m.r#type.clone(),
                source: m.source.clone(),
                target: m.target.clone(),
                options: m.options.clone(),
            })
            .collect();

        if !req.bundle.is_empty() {
            let cfg_path = Path::new(&req.bundle).join("config.json");
            if let Ok(raw) = std::fs::read(&cfg_path) {
                if let Ok(oci) = serde_json::from_slice::<OciConfig>(&raw) {
                    if let Some(root) = oci.root {
                        if root.readonly == Some(true) {
                            policy.readonly_rootfs = true;
                        }
                        if mounts.is_empty() {
                            if let Some(p) = root.path {
                                let abs = if Path::new(&p).is_absolute() {
                                    PathBuf::from(p)
                                } else {
                                    Path::new(&req.bundle).join(p)
                                };
                                if abs.exists() {
                                    mounts.push(MountSpec {
                                        r#type: String::from("bind"),
                                        source: abs.to_string_lossy().into_owned(),
                                        target: String::from("/"),
                                        options: vec![String::from("rbind")],
                                    });
                                }
                            }
                        }
                    }
                    if let Some(proc) = oci.process {
                        if let Some(args) = proc.args {
                            if !args.is_empty() {
                                init_exec = Some(ExecRequest {
                                    argv: args,
                                    env: parse_env_vec(proc.env.unwrap_or_default()),
                                    cwd: proc.cwd,
                                    timeout_ms: 0,
                                    uid: None,
                                    gid: None,
                                    tty: req.terminal,
                                });
                            }
                        }
                    }
                }
            }
        }

        let cfg = SandboxRuntimeConfig::new(req.id.as_str(), mounts, policy);
        let handle = if !req.parent_checkpoint.is_empty() {
            self.dispatcher
                .backend_for(BackendKind::Native)
                .restore(Path::new(&req.parent_checkpoint), &cfg)
                .await
        } else if !req.checkpoint.is_empty() {
            self.dispatcher
                .backend_for(BackendKind::Native)
                .restore(Path::new(&req.checkpoint), &cfg)
                .await
        } else {
            self.dispatcher
                .backend_for(BackendKind::Native)
                .start(&cfg)
                .await
        };

        let handle = match handle {
            Ok(h) => Arc::new(h),
            Err(e) => return err_response(13, format!("failed starting sandbox task: {e}")),
        };

        let pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
        let (done_tx, done_rx) = watch::channel(false);
        let slot = ProcessSlot {
            pid,
            status: TaskStatus::Created,
            exit_status: 0,
            exited_at: None,
            req: init_exec,
            stdout_path: req.stdout.clone(),
            stderr_path: req.stderr.clone(),
            terminal: req.terminal,
            stdin_path: req.stdin.clone(),
            done_tx,
            done_rx,
        };

        let mut processes = HashMap::new();
        processes.insert(String::new(), slot);

        let mut tasks = self.tasks.lock().await;
        tasks.insert(
            req.id.clone(),
            ManagedTask {
                id: req.id,
                bundle: req.bundle,
                handle,
                primary_pid: pid,
                processes,
            },
        );

        ok_response(&CreateTaskResponse { pid })
    }

    async fn handle_start(self: &Arc<Self>, payload: &[u8]) -> TtrpcResponse {
        let req = match StartRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode StartRequest: {e}")),
        };

        let (pid, handle, exec_req_opt, stdout_path, stderr_path, done_tx) = {
            let mut tasks = self.tasks.lock().await;
            let Some(task) = tasks.get_mut(&req.id) else {
                return err_response(5, format!("task {} not found", req.id));
            };
            let Some(slot) = task.processes.get_mut(&req.exec_id) else {
                return err_response(5, format!("exec {} not found", req.exec_id));
            };
            slot.status = TaskStatus::Running;
            (
                slot.pid,
                Arc::clone(&task.handle),
                slot.req.take(),
                slot.stdout_path.clone(),
                slot.stderr_path.clone(),
                slot.done_tx.clone(),
            )
        };

        if let Some(exec_req) = exec_req_opt {
            let svc = Arc::clone(self);
            let task_id = req.id.clone();
            let exec_id = req.exec_id.clone();
            tokio::spawn(async move {
                let res = handle.exec(&exec_req, None).await;
                let now = now_timestamp();
                let (code, out_bytes, err_bytes) = match res {
                    Ok(out) => (out.exit_code.max(0) as u32, out.stdout, out.stderr),
                    Err(e) => (1, Vec::new(), e.to_string().into_bytes()),
                };
                if !stdout_path.is_empty() && !out_bytes.is_empty() {
                    let _ = tokio::fs::write(&stdout_path, &out_bytes).await;
                }
                if !stderr_path.is_empty() && !err_bytes.is_empty() {
                    let _ = tokio::fs::write(&stderr_path, &err_bytes).await;
                }
                {
                    let mut tasks = svc.tasks.lock().await;
                    if let Some(task) = tasks.get_mut(&task_id) {
                        if let Some(slot) = task.processes.get_mut(&exec_id) {
                            slot.status = TaskStatus::Stopped;
                            slot.exit_status = code;
                            slot.exited_at = Some(now);
                        }
                    }
                }
                let _ = done_tx.send(true);
            });
        } else {
            let _ = done_tx.send(true);
        }

        ok_response(&StartResponse { pid })
    }

    async fn handle_state(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match StateRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode StateRequest: {e}")),
        };
        let tasks = self.tasks.lock().await;
        let Some(task) = tasks.get(&req.id) else {
            return err_response(5, format!("task {} not found", req.id));
        };
        let Some(slot) = task.processes.get(&req.exec_id) else {
            return err_response(5, format!("exec {} not found", req.exec_id));
        };
        ok_response(&StateResponse {
            id: task.id.clone(),
            bundle: task.bundle.clone(),
            pid: slot.pid,
            status: slot.status as i32,
            stdin: slot.stdin_path.clone(),
            stdout: slot.stdout_path.clone(),
            stderr: slot.stderr_path.clone(),
            terminal: slot.terminal,
            exit_status: slot.exit_status,
            exited_at: slot.exited_at,
            exec_id: req.exec_id,
        })
    }

    async fn handle_exec(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match ExecProcessRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode ExecProcessRequest: {e}")),
        };
        let proc_spec: OciProcess = match req.spec.as_ref() {
            Some(any) => match serde_json::from_slice(&any.value) {
                Ok(p) => p,
                Err(e) => return err_response(3, format!("invalid OCI Process JSON: {e}")),
            },
            None => return err_response(3, "missing OCI Process spec".to_string()),
        };

        let argv = proc_spec.args.unwrap_or_default();
        if argv.is_empty() {
            return err_response(3, "empty exec argv".to_string());
        }

        let exec_req = ExecRequest {
            argv,
            env: parse_env_vec(proc_spec.env.unwrap_or_default()),
            cwd: proc_spec.cwd,
            timeout_ms: 0,
            uid: None,
            gid: None,
            tty: req.terminal,
        };

        let mut tasks = self.tasks.lock().await;
        let Some(task) = tasks.get_mut(&req.id) else {
            return err_response(5, format!("task {} not found", req.id));
        };
        let pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
        let (done_tx, done_rx) = watch::channel(false);
        task.processes.insert(
            req.exec_id,
            ProcessSlot {
                pid,
                status: TaskStatus::Created,
                exit_status: 0,
                exited_at: None,
                req: Some(exec_req),
                stdout_path: req.stdout,
                stderr_path: req.stderr,
                terminal: req.terminal,
                stdin_path: req.stdin,
                done_tx,
                done_rx,
            },
        );
        ok_response(&Empty {})
    }

    async fn handle_wait(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match WaitRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode WaitRequest: {e}")),
        };

        let mut done_rx = {
            let tasks = self.tasks.lock().await;
            let Some(task) = tasks.get(&req.id) else {
                return err_response(5, format!("task {} not found", req.id));
            };
            let Some(slot) = task.processes.get(&req.exec_id) else {
                return err_response(5, format!("exec {} not found", req.exec_id));
            };
            if slot.status == TaskStatus::Stopped {
                return ok_response(&WaitResponse {
                    exit_status: slot.exit_status,
                    exited_at: slot.exited_at,
                });
            }
            slot.done_rx.clone()
        };

        let _ = done_rx.wait_for(|&done| done).await;
        let tasks = self.tasks.lock().await;
        if let Some(slot) = tasks.get(&req.id).and_then(|t| t.processes.get(&req.exec_id)) {
            ok_response(&WaitResponse {
                exit_status: slot.exit_status,
                exited_at: slot.exited_at,
            })
        } else {
            ok_response(&WaitResponse {
                exit_status: 0,
                exited_at: Some(now_timestamp()),
            })
        }
    }

    async fn handle_pids(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match PidsRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode PidsRequest: {e}")),
        };
        let tasks = self.tasks.lock().await;
        let Some(task) = tasks.get(&req.id) else {
            return err_response(5, format!("task {} not found", req.id));
        };
        let processes = task
            .processes
            .values()
            .filter(|s| s.status != TaskStatus::Stopped)
            .map(|s| ProcessInfo { pid: s.pid })
            .collect();
        ok_response(&PidsResponse { processes })
    }

    async fn handle_pause(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match PauseRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode PauseRequest: {e}")),
        };
        let handle = {
            let mut tasks = self.tasks.lock().await;
            let Some(task) = tasks.get_mut(&req.id) else {
                return err_response(5, format!("task {} not found", req.id));
            };
            if let Some(slot) = task.processes.get_mut("") {
                slot.status = TaskStatus::Paused;
            }
            Arc::clone(&task.handle)
        };
        if let Err(e) = handle.sleep().await {
            return err_response(13, format!("pause failed: {e}"));
        }
        ok_response(&Empty {})
    }

    async fn handle_resume(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match ResumeRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode ResumeRequest: {e}")),
        };
        let handle = {
            let mut tasks = self.tasks.lock().await;
            let Some(task) = tasks.get_mut(&req.id) else {
                return err_response(5, format!("task {} not found", req.id));
            };
            if let Some(slot) = task.processes.get_mut("") {
                slot.status = TaskStatus::Running;
            }
            Arc::clone(&task.handle)
        };
        if let Err(e) = handle.wake().await {
            return err_response(13, format!("resume failed: {e}"));
        }
        ok_response(&Empty {})
    }

    async fn handle_checkpoint(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match CheckpointTaskRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode CheckpointTaskRequest: {e}")),
        };
        let handle = {
            let tasks = self.tasks.lock().await;
            let Some(task) = tasks.get(&req.id) else {
                return err_response(5, format!("task {} not found", req.id));
            };
            Arc::clone(&task.handle)
        };
        if let Err(e) = handle.checkpoint(Path::new(&req.path)).await {
            return err_response(13, format!("checkpoint failed: {e}"));
        }
        ok_response(&Empty {})
    }

    async fn handle_kill(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match KillRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode KillRequest: {e}")),
        };
        let handle = {
            let tasks = self.tasks.lock().await;
            let Some(task) = tasks.get(&req.id) else {
                return err_response(5, format!("task {} not found", req.id));
            };
            Arc::clone(&task.handle)
        };
        let _ = handle
            .signal(&SignalRequest {
                target_request_id: 0,
                signal: req.signal as i32,
            })
            .await;
        ok_response(&Empty {})
    }

    async fn handle_delete(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match DeleteRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode DeleteRequest: {e}")),
        };

        if !req.exec_id.is_empty() {
            let mut tasks = self.tasks.lock().await;
            let Some(task) = tasks.get_mut(&req.id) else {
                return err_response(5, format!("task {} not found", req.id));
            };
            if let Some(slot) = task.processes.remove(&req.exec_id) {
                return ok_response(&DeleteResponse {
                    pid: slot.pid,
                    exit_status: slot.exit_status,
                    exited_at: slot.exited_at.or_else(|| Some(now_timestamp())),
                });
            }
            return err_response(5, format!("exec {} not found", req.exec_id));
        }

        let task_opt = {
            let mut tasks = self.tasks.lock().await;
            tasks.remove(&req.id)
        };
        let Some(task) = task_opt else {
            return err_response(5, format!("task {} not found", req.id));
        };

        let _ = task.handle.destroy().await;
        let slot = task.processes.get("");
        ok_response(&DeleteResponse {
            pid: task.primary_pid,
            exit_status: slot.map_or(0, |s| s.exit_status),
            exited_at: slot
                .and_then(|s| s.exited_at)
                .or_else(|| Some(now_timestamp())),
        })
    }

    async fn handle_shutdown(&self, payload: &[u8]) -> TtrpcResponse {
        let _ = ShutdownRequest::decode(payload);
        let remaining: Vec<ManagedTask> = {
            let mut tasks = self.tasks.lock().await;
            tasks.drain().map(|(_, v)| v).collect()
        };
        for task in remaining {
            let _ = task.handle.destroy().await;
        }
        let _ = self.shutdown_tx.send(true);
        ok_response(&Empty {})
    }

    async fn handle_connect(&self, payload: &[u8]) -> TtrpcResponse {
        let req = match ConnectRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return err_response(3, format!("decode ConnectRequest: {e}")),
        };
        let tasks = self.tasks.lock().await;
        let task_pid = tasks.get(&req.id).map_or(0, |t| t.primary_pid);
        ok_response(&ConnectResponse {
            shim_pid: std::process::id(),
            task_pid,
            version: String::from("2"),
        })
    }
}

/// Serve `ShimTaskService` over a TTRPC Unix domain socket until `Shutdown` is requested.
pub async fn serve_ttrpc(
    sock_path: &Path,
    service: Arc<ShimTaskService>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    if sock_path.exists() {
        let _ = std::fs::remove_file(sock_path);
    }
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(sock_path)
        .with_context(|| format!("failed to bind TTRPC socket {}", sock_path.display()))?;
    info!(socket = %sock_path.display(), "containerd-shim-sbx-v2 TTRPC server listening");

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
                        let svc = Arc::clone(&service);
                        tokio::spawn(async move {
                            if let Err(e) = handle_ttrpc_conn(stream, svc).await {
                                debug!(error = %e, "TTRPC connection closed");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "TTRPC accept failed");
                    }
                }
            }
        }
    }
    let _ = std::fs::remove_file(sock_path);
    Ok(())
}

async fn handle_ttrpc_conn(mut stream: UnixStream, svc: Arc<ShimTaskService>) -> Result<()> {
    let mut hdr_buf = [0u8; 10];
    loop {
        if stream.read_exact(&mut hdr_buf).await.is_err() {
            return Ok(());
        }
        let hdr = TtrpcFrameHeader::from_bytes(&hdr_buf);
        if hdr.length > 16 * 1024 * 1024 {
            bail!("TTRPC frame too large: {}", hdr.length);
        }
        let mut payload = vec![0u8; hdr.length as usize];
        if !payload.is_empty() {
            stream.read_exact(&mut payload).await?;
        }
        if hdr.msg_type != TTRPC_MSG_TYPE_REQUEST {
            continue;
        }
        let req = TtrpcRequest::decode(&payload[..])?;
        let resp = svc.dispatch(req).await;
        let resp_bytes = resp.encode_to_vec();
        let reply_hdr = TtrpcFrameHeader {
            length: resp_bytes.len() as u32,
            stream_id: hdr.stream_id,
            msg_type: TTRPC_MSG_TYPE_RESPONSE,
            flags: 0,
        };
        stream.write_all(&reply_hdr.to_bytes()).await?;
        stream.write_all(&resp_bytes).await?;
    }
}

/// TTRPC client speaking `containerd.task.v2.Task` over a Unix domain socket.
pub struct ShimTaskClient {
    stream: UnixStream,
    next_stream_id: u32,
}

impl ShimTaskClient {
    pub async fn connect(sock_path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(sock_path)
            .await
            .with_context(|| format!("failed connecting to TTRPC socket {}", sock_path.display()))?;
        Ok(Self {
            stream,
            next_stream_id: 1,
        })
    }

    pub async fn call<Req: Message, Resp: Message + Default>(
        &mut self,
        method: &str,
        req: &Req,
    ) -> Result<Resp> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;

        let ttrpc_req = TtrpcRequest {
            service: String::from(TASK_SERVICE_NAME),
            method: method.to_string(),
            payload: req.encode_to_vec(),
            timeout_nano: 0,
            metadata: Vec::new(),
        };
        let req_bytes = ttrpc_req.encode_to_vec();
        let hdr = TtrpcFrameHeader {
            length: req_bytes.len() as u32,
            stream_id,
            msg_type: TTRPC_MSG_TYPE_REQUEST,
            flags: 0,
        };
        self.stream.write_all(&hdr.to_bytes()).await?;
        self.stream.write_all(&req_bytes).await?;

        let mut reply_hdr_buf = [0u8; 10];
        self.stream.read_exact(&mut reply_hdr_buf).await?;
        let reply_hdr = TtrpcFrameHeader::from_bytes(&reply_hdr_buf);
        let mut resp_buf = vec![0u8; reply_hdr.length as usize];
        if !resp_buf.is_empty() {
            self.stream.read_exact(&mut resp_buf).await?;
        }
        let resp = TtrpcResponse::decode(&resp_buf[..])?;
        if let Some(status) = resp.status {
            if status.code != 0 {
                bail!("TTRPC {method} error ({}): {}", status.code, status.message);
            }
        }
        Ok(Resp::decode(&resp.payload[..])?)
    }
}

fn ok_response<T: Message>(msg: &T) -> TtrpcResponse {
    TtrpcResponse {
        status: Some(TtrpcStatus {
            code: 0,
            message: String::new(),
        }),
        payload: msg.encode_to_vec(),
    }
}

fn err_response(code: i32, message: impl Into<String>) -> TtrpcResponse {
    TtrpcResponse {
        status: Some(TtrpcStatus {
            code,
            message: message.into(),
        }),
        payload: Vec::new(),
    }
}

fn parse_env_vec(raw: Vec<String>) -> Vec<(String, String)> {
    raw.into_iter()
        .filter_map(|item| {
            item.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn now_timestamp() -> prost_types::Timestamp {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    prost_types::Timestamp {
        seconds: dur.as_secs() as i64,
        nanos: dur.subsec_nanos() as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ttrpc_shim_full_container_task_lifecycle() {
        let dir = std::env::temp_dir().join(format!("sbx-shim-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bundle = dir.join("bundle");
        let rootfs = bundle.join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        let stdout_log = dir.join("task.stdout");
        let exec_stdout = dir.join("exec.stdout");
        let ckpt_dir = dir.join("ckpt");

        let oci_cfg = serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs", "readonly": false },
            "process": {
                "args": ["/bin/echo", "shim-init-ok"],
                "env": ["PATH=/bin:/usr/bin"],
                "cwd": "/tmp"
            }
        });
        std::fs::write(
            bundle.join("config.json"),
            serde_json::to_vec(&oci_cfg).unwrap(),
        )
        .unwrap();

        let sock = dir.join("shim.sock");
        let dispatcher = Arc::new(RuntimeDispatcher::new(None).expect("dispatcher"));
        let (svc, rx) = ShimTaskService::new(dispatcher);
        let sock_srv = sock.clone();
        let srv_task = tokio::spawn(async move { serve_ttrpc(&sock_srv, svc, rx).await });

        for _ in 0..30 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let mut client = ShimTaskClient::connect(&sock).await.expect("ttrpc connect");

        // 1. Create
        let created: CreateTaskResponse = client
            .call(
                "Create",
                &CreateTaskRequest {
                    id: String::from("ctr-task-1"),
                    bundle: bundle.to_string_lossy().into_owned(),
                    rootfs: Vec::new(),
                    terminal: false,
                    stdin: String::new(),
                    stdout: stdout_log.to_string_lossy().into_owned(),
                    stderr: String::new(),
                    checkpoint: String::new(),
                    parent_checkpoint: String::new(),
                    options: None,
                },
            )
            .await
            .expect("Create");
        assert!(created.pid > 0);

        // 2. Connect
        let conn_resp: ConnectResponse = client
            .call(
                "Connect",
                &ConnectRequest {
                    id: String::from("ctr-task-1"),
                },
            )
            .await
            .expect("Connect");
        assert_eq!(conn_resp.task_pid, created.pid);

        // 3. Start primary workload + Wait
        let started: StartResponse = client
            .call(
                "Start",
                &StartRequest {
                    id: String::from("ctr-task-1"),
                    exec_id: String::new(),
                },
            )
            .await
            .expect("Start");
        assert_eq!(started.pid, created.pid);

        let waited: WaitResponse = client
            .call(
                "Wait",
                &WaitRequest {
                    id: String::from("ctr-task-1"),
                    exec_id: String::new(),
                },
            )
            .await
            .expect("Wait");
        assert_eq!(waited.exit_status, 0);
        assert_eq!(std::fs::read_to_string(&stdout_log).unwrap().trim(), "shim-init-ok");

        // 4. Secondary Exec
        let proc_json = serde_json::json!({
            "args": ["/bin/echo", "shim-exec-ok"],
            "env": ["PATH=/bin:/usr/bin"]
        });
        let _: Empty = client
            .call(
                "Exec",
                &ExecProcessRequest {
                    id: String::from("ctr-task-1"),
                    exec_id: String::from("exec-2"),
                    terminal: false,
                    stdin: String::new(),
                    stdout: exec_stdout.to_string_lossy().into_owned(),
                    stderr: String::new(),
                    spec: Some(prost_types::Any {
                        type_url: String::from("types.containerd.io/opencontainers/runtime-spec/1/Process"),
                        value: serde_json::to_vec(&proc_json).unwrap(),
                    }),
                },
            )
            .await
            .expect("Exec");
        let _: StartResponse = client
            .call(
                "Start",
                &StartRequest {
                    id: String::from("ctr-task-1"),
                    exec_id: String::from("exec-2"),
                },
            )
            .await
            .expect("Start exec-2");
        let wait2: WaitResponse = client
            .call(
                "Wait",
                &WaitRequest {
                    id: String::from("ctr-task-1"),
                    exec_id: String::from("exec-2"),
                },
            )
            .await
            .expect("Wait exec-2");
        assert_eq!(wait2.exit_status, 0);
        assert_eq!(std::fs::read_to_string(&exec_stdout).unwrap().trim(), "shim-exec-ok");

        // 5. Pause / Resume / Checkpoint / Delete / Shutdown
        let _: Empty = client
            .call(
                "Pause",
                &PauseRequest {
                    id: String::from("ctr-task-1"),
                },
            )
            .await
            .expect("Pause");
        let _: Empty = client
            .call(
                "Resume",
                &ResumeRequest {
                    id: String::from("ctr-task-1"),
                },
            )
            .await
            .expect("Resume");
        let _: Empty = client
            .call(
                "Checkpoint",
                &CheckpointTaskRequest {
                    id: String::from("ctr-task-1"),
                    path: ckpt_dir.to_string_lossy().into_owned(),
                    options: None,
                },
            )
            .await
            .expect("Checkpoint");
        assert!(ckpt_dir.join("checkpoint.json").is_file());

        let del: DeleteResponse = client
            .call(
                "Delete",
                &DeleteRequest {
                    id: String::from("ctr-task-1"),
                    exec_id: String::new(),
                },
            )
            .await
            .expect("Delete");
        assert_eq!(del.pid, created.pid);

        let _: Empty = client
            .call(
                "Shutdown",
                &ShutdownRequest {
                    id: String::from("ctr-task-1"),
                    now: true,
                },
            )
            .await
            .expect("Shutdown");

        let _ = srv_task.await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
