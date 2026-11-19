use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use sbx_daemon::{ControlPlane, DaemonClient, DaemonRequest, DaemonResponse};
use sbx_proto::{BackendKind, ExecRequest, NetworkPolicy, ReplExecRequest, SecurityPolicy};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

enum McpBackend {
    InProcess(Arc<ControlPlane>),
    DaemonSocket {
        path: PathBuf,
        client: Mutex<Option<DaemonClient>>,
    },
}

/// Model Context Protocol server exposing `sbx` sandbox tools over `stdio` and HTTP/SSE.
pub struct McpServer {
    backend: McpBackend,
}

impl McpServer {
    pub fn with_control_plane(cp: Arc<ControlPlane>) -> Arc<Self> {
        Arc::new(Self {
            backend: McpBackend::InProcess(cp),
        })
    }

    pub fn with_daemon_socket(sock: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            backend: McpBackend::DaemonSocket {
                path: sock,
                client: Mutex::new(None),
            },
        })
    }

    async fn call_daemon(&self, req: DaemonRequest) -> Result<DaemonResponse> {
        match &self.backend {
            McpBackend::InProcess(cp) => Ok(cp.handle_request(req).await),
            McpBackend::DaemonSocket { path, client } => {
                let mut guard = client.lock().await;
                if guard.is_none() {
                    *guard = Some(DaemonClient::connect_or_autostart(Some(path)).await?);
                }
                let c = guard.as_mut().unwrap();
                match c.request(&req).await {
                    Ok(resp) => Ok(resp),
                    Err(_) => {
                        *guard = Some(DaemonClient::connect_or_autostart(Some(path)).await?);
                        guard.as_mut().unwrap().request(&req).await
                    }
                }
            }
        }
    }

    /// Process a single JSON-RPC 2.0 line. Returns `Ok(None)` for notifications.
    pub async fn handle_message(&self, raw_line: &str) -> Option<String> {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            return None;
        }
        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {e}"),
                    }),
                };
                return serde_json::to_string(&resp).ok();
            }
        };

        // Notifications have no `id` and require no response.
        let Some(id) = req.id.clone() else {
            debug!(method = %req.method, "MCP notification received");
            return None;
        };

        let resp = match req.method.as_str() {
            "initialize" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "sbx-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
                error: None,
            },
            "ping" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({})),
                error: None,
            },
            "tools/list" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({
                    "tools": tool_definitions()
                })),
                error: None,
            },
            "tools/call" => {
                let name = req
                    .params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let args = req
                    .params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let call_res = self.execute_tool(name, args).await;
                let result_val = match call_res {
                    Ok(payload) => json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
                        }],
                        "isError": false
                    }),
                    Err(e) => json!({
                        "content": [{
                            "type": "text",
                            "text": format!("error: {e:#}")
                        }],
                        "isError": true
                    }),
                };
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(result_val),
                    error: None,
                }
            }
            other => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {other}"),
                }),
            },
        };

        serde_json::to_string(&resp).ok()
    }

    async fn execute_tool(&self, name: &str, args: Value) -> Result<Value> {
        match name {
            "create_sandbox" => {
                let image = args
                    .get("image")
                    .and_then(Value::as_str)
                    .unwrap_or("alpine")
                    .to_string();
                let mut policy = SecurityPolicy::default();
                if let Some(b) = args.get("backend").and_then(Value::as_str) {
                    policy.backend = match b.to_ascii_lowercase().as_str() {
                        "gvisor" => BackendKind::Gvisor,
                        "microvm" => BackendKind::MicroVm,
                        _ => BackendKind::Native,
                    };
                }
                if let Some(mem) = args.get("memory_mb").and_then(Value::as_u64) {
                    policy.memory_limit_mb = mem;
                }
                if let Some(pids) = args.get("pids").and_then(Value::as_u64) {
                    policy.pids_limit = pids as u32;
                }
                if let Some(cpus) = args.get("cpus").and_then(Value::as_f64) {
                    policy.cpu_cores = cpus as f32;
                    policy.cpu_quota_us = ((cpus.max(0.1)) * 100_000.0) as u64;
                }
                if let Some(hosts) = args.get("allowed_hosts").and_then(Value::as_array) {
                    let list: Vec<String> = hosts
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect();
                    if !list.is_empty() {
                        policy.network = NetworkPolicy::AllowlistProxy {
                            allowed_hosts: list,
                            block_private_cidrs: true,
                        };
                    }
                }
                let env: Vec<(String, String)> = args
                    .get("env")
                    .and_then(Value::as_object)
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();

                let resp = self
                    .call_daemon(DaemonRequest::CreateSandbox {
                        id: args.get("id").and_then(Value::as_str).map(str::to_string),
                        image,
                        policy: Some(policy),
                        env,
                        secrets: HashMap::new(),
                    })
                    .await?;
                unwrap_daemon_value(resp)
            }
            "exec_command" => {
                let sandbox_id = req_str(&args, "sandbox_id")?;
                let mut argv = Vec::new();
                if let Some(cmd) = args.get("command").and_then(Value::as_str) {
                    if let Some(extra) = args.get("args").and_then(Value::as_array) {
                        argv.push(cmd.to_string());
                        for a in extra {
                            if let Some(s) = a.as_str() {
                                argv.push(s.to_string());
                            }
                        }
                    } else {
                        argv = vec![String::from("/bin/sh"), String::from("-c"), cmd.to_string()];
                    }
                } else if let Some(arr) = args.get("argv").and_then(Value::as_array) {
                    for a in arr {
                        if let Some(s) = a.as_str() {
                            argv.push(s.to_string());
                        }
                    }
                }
                anyhow::ensure!(!argv.is_empty(), "missing command or argv");

                let resp = self
                    .call_daemon(DaemonRequest::Exec {
                        sandbox_id,
                        req: ExecRequest {
                            argv,
                            env: Vec::new(),
                            cwd: args.get("cwd").and_then(Value::as_str).map(str::to_string),
                            timeout_ms: args
                                .get("timeout_ms")
                                .and_then(Value::as_u64)
                                .unwrap_or(10_000),
                            uid: None,
                            gid: None,
                            tty: false,
                        },
                    })
                    .await?;
                unwrap_daemon_value(resp)
            }
            "run_python" => {
                let sandbox_id = req_str(&args, "sandbox_id")?;
                let code = req_str(&args, "code")?;
                let timeout_ms = args
                    .get("timeout_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(10_000);
                let resp = self
                    .call_daemon(DaemonRequest::ReplExec {
                        sandbox_id,
                        req: ReplExecRequest {
                            language: String::from("python"),
                            code,
                            timeout_ms,
                        },
                    })
                    .await?;
                unwrap_daemon_value(resp)
            }
            "snapshot" => {
                let sandbox_id = req_str(&args, "sandbox_id")?;
                let label = args.get("label").and_then(Value::as_str).map(str::to_string);
                let resp = self
                    .call_daemon(DaemonRequest::Snapshot { sandbox_id, label })
                    .await?;
                unwrap_daemon_value(resp)
            }
            "diff_sandbox" => {
                let sandbox_id = req_str(&args, "sandbox_id")?;
                let resp = self
                    .call_daemon(DaemonRequest::Diff { sandbox_id })
                    .await?;
                unwrap_daemon_value(resp)
            }
            "rollback" => {
                let sandbox_id = req_str(&args, "sandbox_id")?;
                let snapshot_id = req_str(&args, "snapshot_id")?;
                let resp = self
                    .call_daemon(DaemonRequest::Rollback {
                        sandbox_id,
                        snapshot_id,
                    })
                    .await?;
                unwrap_daemon_value(resp)
            }
            "fork_sandbox" => {
                let snapshot_id = req_str(&args, "snapshot_id")?;
                let count = args.get("count").and_then(Value::as_u64).unwrap_or(2) as usize;
                let resp = self
                    .call_daemon(DaemonRequest::Fork {
                        snapshot_id,
                        count,
                        policy: None,
                    })
                    .await?;
                unwrap_daemon_value(resp)
            }
            "checkpoint_sandbox" => {
                let sandbox_id = req_str(&args, "sandbox_id")?;
                let resp = self
                    .call_daemon(DaemonRequest::Checkpoint { sandbox_id })
                    .await?;
                unwrap_daemon_value(resp)
            }
            "restore_sandbox" => {
                let checkpoint_id = req_str(&args, "checkpoint_id")?;
                let new_sandbox_id = args
                    .get("new_sandbox_id")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let resp = self
                    .call_daemon(DaemonRequest::Restore {
                        checkpoint_id,
                        new_sandbox_id,
                    })
                    .await?;
                unwrap_daemon_value(resp)
            }
            "list_sandboxes" => {
                let resp = self.call_daemon(DaemonRequest::ListSandboxes).await?;
                unwrap_daemon_value(resp)
            }
            "destroy_sandbox" => {
                let sandbox_id = req_str(&args, "sandbox_id")?;
                let resp = self
                    .call_daemon(DaemonRequest::DestroySandbox { sandbox_id })
                    .await?;
                unwrap_daemon_value(resp)
            }
            other => anyhow::bail!("unknown MCP tool: {other}"),
        }
    }
}

fn req_str(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("missing required string argument '{key}'"))
}

fn unwrap_daemon_value(resp: DaemonResponse) -> Result<Value> {
    match resp {
        DaemonResponse::Error(msg) => anyhow::bail!("{msg}"),
        DaemonResponse::Ok => Ok(json!({ "ok": true })),
        other => Ok(serde_json::to_value(other)?),
    }
}

pub fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "create_sandbox",
            "description": "Create or warm-acquire an isolated AI sandbox from an OCI image.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "image": { "type": "string", "description": "OCI image reference (e.g. alpine, python:3.12-slim)" },
                    "backend": { "type": "string", "enum": ["native", "gvisor", "microvm"] },
                    "memory_mb": { "type": "integer" },
                    "pids": { "type": "integer" },
                    "cpus": { "type": "number" },
                    "allowed_hosts": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["image"]
            }
        }),
        json!({
            "name": "exec_command",
            "description": "Execute a shell or binary command inside an existing sandbox via clone3.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sandbox_id": { "type": "string" },
                    "command": { "type": "string" },
                    "args": { "type": "array", "items": { "type": "string" } },
                    "cwd": { "type": "string" },
                    "timeout_ms": { "type": "integer" }
                },
                "required": ["sandbox_id", "command"]
            }
        }),
        json!({
            "name": "run_python",
            "description": "Run Python code inside the sandbox's persistent Stateful REPL worker.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sandbox_id": { "type": "string" },
                    "code": { "type": "string" },
                    "timeout_ms": { "type": "integer" }
                },
                "required": ["sandbox_id", "code"]
            }
        }),
        json!({
            "name": "snapshot",
            "description": "Create a step-level filesystem + REPL checkpoint snapshot for rollback or parallel fork.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sandbox_id": { "type": "string" },
                    "label": { "type": "string" }
                },
                "required": ["sandbox_id"]
            }
        }),
        json!({
            "name": "diff_sandbox",
            "description": "Inspect files added, modified, or deleted inside a sandbox.",
            "inputSchema": {
                "type": "object",
                "properties": { "sandbox_id": { "type": "string" } },
                "required": ["sandbox_id"]
            }
        }),
        json!({
            "name": "rollback",
            "description": "Discard dirty filesystem mutations and restore a sandbox to a previous snapshot.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sandbox_id": { "type": "string" },
                    "snapshot_id": { "type": "string" }
                },
                "required": ["sandbox_id", "snapshot_id"]
            }
        }),
        json!({
            "name": "fork_sandbox",
            "description": "Fork N independent Copy-on-Write sandboxes from an existing snapshot.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "snapshot_id": { "type": "string" },
                    "count": { "type": "integer", "default": 2 }
                },
                "required": ["snapshot_id"]
            }
        }),
        json!({
            "name": "checkpoint_sandbox",
            "description": "Save a live sandbox's Python REPL memory and filesystem state to a checkpoint.",
            "inputSchema": {
                "type": "object",
                "properties": { "sandbox_id": { "type": "string" } },
                "required": ["sandbox_id"]
            }
        }),
        json!({
            "name": "restore_sandbox",
            "description": "Restore a previously checkpointed sandbox into a new running sandbox instance.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "checkpoint_id": { "type": "string" },
                    "new_sandbox_id": { "type": "string" }
                },
                "required": ["checkpoint_id"]
            }
        }),
        json!({
            "name": "list_sandboxes",
            "description": "List all active, warm, and sleeping sandboxes.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "destroy_sandbox",
            "description": "Terminate a sandbox and clean up all namespaces, cgroups, and snapshots.",
            "inputSchema": {
                "type": "object",
                "properties": { "sandbox_id": { "type": "string" } },
                "required": ["sandbox_id"]
            }
        }),
    ]
}

/// Serve MCP JSON-RPC 2.0 over newline-delimited `stdio` streams.
pub async fn serve_stdio<R, W>(
    server: Arc<McpServer>,
    mut reader: R,
    mut writer: W,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        if let Some(reply) = server.handle_message(&line).await {
            writer.write_all(reply.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
    }
    Ok(())
}

/// Serve MCP over HTTP (`POST /mcp` and `GET /sse`).
pub async fn serve_http_sse(addr: SocketAddr, server: Arc<McpServer>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let router = Router::new()
        .route("/mcp", post(http_mcp_post))
        .route("/message", post(http_mcp_post))
        .route("/sse", get(http_mcp_sse))
        .with_state(server);
    info!(%addr, "sbx-mcp HTTP/SSE server listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let svc = TowerToHyperService::new(router.clone());
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                warn!(error = %e, "MCP HTTP connection error");
            }
        });
    }
}

async fn http_mcp_post(State(server): State<Arc<McpServer>>, body: Bytes) -> Response {
    let raw = String::from_utf8_lossy(&body);
    match server.handle_message(&raw).await {
        Some(reply) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            reply,
        )
            .into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

async fn http_mcp_sse() -> Response {
    let body = "event: endpoint\ndata: /message\n\n";
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn mcp_stdio_initialize_list_and_tool_calls_work() {
        let dir = std::env::temp_dir().join(format!("sbx-mcp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cp = ControlPlane::new_local(dir.clone()).await.unwrap();
        let mcp = McpServer::with_control_plane(cp);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(server_io);
        let (cli_r, mut cli_w) = tokio::io::split(client_io);

        let srv_task = tokio::spawn(async move {
            serve_stdio(mcp, BufReader::new(srv_r), srv_w)
                .await
                .unwrap();
        });

        let mut reader = BufReader::new(cli_r);
        let mut resp_line = String::new();

        // 1. initialize
        cli_w
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n")
            .await
            .unwrap();
        reader.read_line(&mut resp_line).await.unwrap();
        let init_v: Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(init_v["id"], 1);
        assert_eq!(init_v["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);

        // 2. tools/list
        resp_line.clear();
        cli_w
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n")
            .await
            .unwrap();
        reader.read_line(&mut resp_line).await.unwrap();
        let list_v: Value = serde_json::from_str(&resp_line).unwrap();
        let tools = list_v["result"]["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "create_sandbox"));
        assert!(tools.iter().any(|t| t["name"] == "run_python"));
        assert!(tools.iter().any(|t| t["name"] == "rollback"));

        // 3. create_sandbox
        resp_line.clear();
        cli_w
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"create_sandbox\",\"arguments\":{\"image\":\"alpine\"}}}\n")
            .await
            .unwrap();
        reader.read_line(&mut resp_line).await.unwrap();
        let create_v: Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(create_v["result"]["isError"], false);
        let create_text = create_v["result"]["content"][0]["text"].as_str().unwrap();
        let created_json: Value = serde_json::from_str(create_text).unwrap();
        let sbx_id = created_json["data"]["id"].as_str().unwrap().to_string();

        // 4. exec_command
        resp_line.clear();
        let exec_call = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "exec_command",
                "arguments": {
                    "sandbox_id": sbx_id,
                    "command": "/bin/echo",
                    "args": ["mcp-exec-ok"]
                }
            }
        });
        cli_w
            .write_all(format!("{exec_call}\n").as_bytes())
            .await
            .unwrap();
        reader.read_line(&mut resp_line).await.unwrap();
        let exec_v: Value = serde_json::from_str(&resp_line).unwrap();
        let exec_text = exec_v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(exec_text.contains("mcp-exec-ok"));

        // 5. run_python
        if Path::new("/usr/bin/python3").exists() {
            resp_line.clear();
            let py_call = json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "run_python",
                    "arguments": {
                        "sandbox_id": sbx_id,
                        "code": "a = 6 * 7\na"
                    }
                }
            });
            cli_w
                .write_all(format!("{py_call}\n").as_bytes())
                .await
                .unwrap();
            reader.read_line(&mut resp_line).await.unwrap();
            let py_v: Value = serde_json::from_str(&resp_line).unwrap();
            let py_text = py_v["result"]["content"][0]["text"].as_str().unwrap();
            assert!(py_text.contains("42"));
        }

        // 6. destroy_sandbox
        resp_line.clear();
        let rm_call = json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "destroy_sandbox",
                "arguments": { "sandbox_id": sbx_id }
            }
        });
        cli_w
            .write_all(format!("{rm_call}\n").as_bytes())
            .await
            .unwrap();
        reader.read_line(&mut resp_line).await.unwrap();
        let rm_v: Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(rm_v["result"]["isError"], false);

        cli_w.shutdown().await.unwrap();
        drop(cli_w);
        drop(reader);
        let _ = srv_task.await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
