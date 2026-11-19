"""Python SDK client for AI Sandbox (sbx-daemon UDS & HTTP REST API)."""

from __future__ import annotations

import json
import os
import socket
import struct
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


def default_socket_path() -> str:
    env = os.environ.get("SBX_DAEMON_SOCK")
    if env:
        return env
    uid = os.geteuid()
    return "/run/sbx/daemon.sock" if uid == 0 else f"/tmp/sbx-daemon-{uid}/daemon.sock"


@dataclass
class SbxClient:
    """Thin client talking to `sbx-daemon` via Unix domain socket or HTTP REST URL."""

    socket_path: Optional[str] = None
    http_url: Optional[str] = None

    def _uds_call(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        sock_path = self.socket_path or default_socket_path()
        raw = json.dumps(payload).encode("utf-8")
        frame = struct.pack(">I", len(raw)) + raw
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(sock_path)
            s.sendall(frame)
            hdr = self._recv_exact(s, 4)
            (resp_len,) = struct.unpack(">I", hdr)
            resp_bytes = self._recv_exact(s, resp_len)
        resp = json.loads(resp_bytes.decode("utf-8"))
        if resp.get("status") == "Error":
            raise RuntimeError(resp.get("data", "unknown sbx-daemon error"))
        return resp

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        chunks: List[bytes] = []
        rem = n
        while rem > 0:
            buf = sock.recv(rem)
            if not buf:
                raise EOFError("unexpected EOF from sbx-daemon")
            chunks.append(buf)
            rem -= len(buf)
        return b"".join(chunks)

    def _http_call(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        assert self.http_url is not None
        url = self.http_url.rstrip("/") + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"sbx-daemon HTTP {e.code}: {err_body}") from e

    def ping(self) -> Dict[str, Any]:
        if self.http_url:
            return self._http_call("GET", "/health")["data"]
        return self._uds_call({"op": "Ping"})["data"]

    def create_sandbox(
        self,
        image: str = "alpine",
        backend: str = "native",
        memory_mb: int = 1024,
        pids: int = 128,
        cpus: float = 2.0,
        allowed_hosts: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        secrets: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        network: Any = "Disabled"
        if allowed_hosts:
            network = {
                "AllowlistProxy": {
                    "allowed_hosts": allowed_hosts,
                    "block_private_cidrs": True,
                }
            }
        policy = {
            "backend": {"native": "Native", "gvisor": "Gvisor", "microvm": "MicroVm"}.get(backend.lower(), "Native"),
            "cpu_cores": cpus,
            "cpu_quota_us": int(max(0.1, cpus) * 100_000),
            "memory_limit_mb": memory_mb,
            "pids_limit": pids,
            "disk_quota_mb": 2048,
            "readonly_rootfs": False,
            "seccomp_mode": "Standard",
            "writable_paths": ["/workspace", "/tmp"],
            "network": network,
            "secret_bindings": [],
            "max_ttl_sec": 3600,
            "idle_sleep_sec": 300,
            "auto_destroy": True,
        }
        env_list = [[k, v] for k, v in (env or {}).items()]
        args = {
            "id": None,
            "image": image,
            "policy": policy,
            "env": env_list,
            "secrets": secrets or {},
        }
        if self.http_url:
            return self._http_call("POST", "/v1/sandboxes", args)["data"]
        return self._uds_call({"op": "CreateSandbox", "args": args})["data"]

    def exec(self, sandbox_id: str, argv: List[str], timeout_ms: int = 10_000) -> Dict[str, Any]:
        req = {
            "argv": argv,
            "env": [],
            "cwd": None,
            "timeout_ms": timeout_ms,
            "uid": None,
            "gid": None,
            "tty": False,
        }
        if self.http_url:
            return self._http_call("POST", f"/v1/sandboxes/{sandbox_id}/exec", req)["data"]
        return self._uds_call({"op": "Exec", "args": {"sandbox_id": sandbox_id, "req": req}})["data"]

    def run_python(self, sandbox_id: str, code: str, timeout_ms: int = 10_000) -> Dict[str, Any]:
        req = {"language": "python", "code": code, "timeout_ms": timeout_ms}
        if self.http_url:
            return self._http_call("POST", f"/v1/sandboxes/{sandbox_id}/repl", req)["data"]
        return self._uds_call({"op": "ReplExec", "args": {"sandbox_id": sandbox_id, "req": req}})["data"]

    def snapshot(self, sandbox_id: str, label: Optional[str] = None) -> Dict[str, Any]:
        if self.http_url:
            return self._http_call("POST", f"/v1/sandboxes/{sandbox_id}/snapshot", {"label": label})["data"]
        return self._uds_call({"op": "Snapshot", "args": {"sandbox_id": sandbox_id, "label": label}})["data"]

    def diff(self, sandbox_id: str) -> List[Dict[str, Any]]:
        if self.http_url:
            return self._http_call("GET", f"/v1/sandboxes/{sandbox_id}/diff")["data"]
        return self._uds_call({"op": "Diff", "args": {"sandbox_id": sandbox_id}})["data"]

    def rollback(self, sandbox_id: str, snapshot_id: str) -> Dict[str, Any]:
        if self.http_url:
            return self._http_call("POST", f"/v1/sandboxes/{sandbox_id}/rollback", {"snapshot_id": snapshot_id})["data"]
        return self._uds_call({"op": "Rollback", "args": {"sandbox_id": sandbox_id, "snapshot_id": snapshot_id}})["data"]

    def fork(self, snapshot_id: str, count: int = 2) -> List[Dict[str, Any]]:
        if self.http_url:
            return self._http_call("POST", f"/v1/snapshots/{snapshot_id}/fork", {"count": count})["data"]
        return self._uds_call({"op": "Fork", "args": {"snapshot_id": snapshot_id, "count": count, "policy": None}})["data"]

    def destroy(self, sandbox_id: str) -> None:
        if self.http_url:
            self._http_call("DELETE", f"/v1/sandboxes/{sandbox_id}")
        else:
            self._uds_call({"op": "DestroySandbox", "args": {"sandbox_id": sandbox_id}})
