use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use std::path::Path;
use std::ptr;

use sbx_proto::{ReplExecRequest, ReplExecResponse};

use crate::init::reap_zombies;
use crate::spawner::{
    close_fd_quiet, create_cloexec_pipe, monotonic_ns, resolve_executable, set_nonblocking,
    spawn_via_clone3,
};
use crate::transport::write_all_fd;

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const PYTHON_REPL_DRIVER: &str = r#"
import ast, contextlib, importlib, io, os, pickle, sys, traceback, types

_PROTO_OUT = os.fdopen(os.dup(1), "wb", 0)
_STDIN = sys.stdin.buffer
_CKPT_PATHS = ("/.sbx-repl-checkpoint.bin", "/tmp/.sbx-repl-checkpoint.bin")

def _read_exact(n):
    chunks = []
    rem = n
    while rem > 0:
        b = _STDIN.read(rem)
        if not b:
            raise EOFError("unexpected eof")
        chunks.append(b)
        rem -= len(b)
    return b"".join(chunks)

def _write_resp(rc, out_s, err_s, msg_s):
    ob = out_s.encode("utf-8", "replace")
    eb = err_s.encode("utf-8", "replace")
    mb = msg_s.encode("utf-8", "replace")
    hdr = f"RESP {rc} {len(ob)} {len(eb)} {len(mb)}\n".encode("ascii")
    _PROTO_OUT.write(hdr)
    if ob:
        _PROTO_OUT.write(ob)
    if eb:
        _PROTO_OUT.write(eb)
    if mb:
        _PROTO_OUT.write(mb)
    _PROTO_OUT.flush()

ns = {"__name__": "__main__"}

def __sbx_save_state__(path="/tmp/.sbx-repl-checkpoint.bin"):
    vals = {}
    mods = {}
    for k, v in list(ns.items()):
        if k.startswith("__sbx_") or k == "__builtins__":
            continue
        if isinstance(v, types.ModuleType):
            mods[k] = v.__name__
            continue
        try:
            pickle.dumps(v)
            vals[k] = v
        except Exception:
            pass
    payload = {"vals": vals, "mods": mods}
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        pickle.dump(payload, f)
    os.replace(tmp, path)
    return len(vals)

def __sbx_load_state__(path="/tmp/.sbx-repl-checkpoint.bin"):
    if not os.path.exists(path):
        return 0
    with open(path, "rb") as f:
        payload = pickle.load(f)
    for k, mod_name in payload.get("mods", {}).items():
        try:
            ns[k] = importlib.import_module(mod_name)
        except Exception:
            pass
    vals = payload.get("vals", {})
    for k, v in vals.items():
        ns[k] = v
    return len(vals)

ns["__sbx_save_state__"] = __sbx_save_state__
ns["__sbx_load_state__"] = __sbx_load_state__

for _p in _CKPT_PATHS:
    if os.path.exists(_p):
        try:
            __sbx_load_state__(_p)
            break
        except Exception:
            pass

while True:
    line = _STDIN.readline()
    if not line:
        break
    parts = line.decode("ascii", "replace").strip().split()
    if len(parts) != 2:
        _write_resp(1, "", "", "malformed repl command")
        continue
    op, raw_len = parts[0], parts[1]
    try:
        n = int(raw_len)
    except ValueError:
        _write_resp(1, "", "", "invalid length")
        continue
    data = _read_exact(n).decode("utf-8", "replace")
    if op == "SAVE":
        try:
            cnt = __sbx_save_state__(data)
            _write_resp(0, str(cnt), "", "")
        except Exception:
            _write_resp(1, "", traceback.format_exc(), "save failed")
        continue
    if op == "LOAD":
        try:
            cnt = __sbx_load_state__(data)
            _write_resp(0, str(cnt), "", "")
        except Exception:
            _write_resp(1, "", traceback.format_exc(), "load failed")
        continue
    if op != "EXEC":
        _write_resp(1, "", "", f"unknown op {op}")
        continue

    out_buf = io.StringIO()
    err_buf = io.StringIO()
    rc = 0
    err_msg = ""
    with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
        try:
            tree = ast.parse(data, "<sbx-repl>", "exec")
            if tree.body and isinstance(tree.body[-1], ast.Expr):
                last = tree.body.pop()
                if tree.body:
                    exec(compile(tree, "<sbx-repl>", "exec"), ns)
                val = eval(compile(ast.Expression(last.value), "<sbx-repl>", "eval"), ns)
                if val is not None:
                    print(repr(val))
            else:
                exec(compile(tree, "<sbx-repl>", "exec"), ns)
        except SystemExit as se:
            rc = se.code if isinstance(se.code, int) else 1
        except Exception:
            rc = 1
            traceback.print_exc(file=err_buf)
            err_msg = "python exception"
    _write_resp(rc, out_buf.getvalue(), err_buf.getvalue(), err_msg)
"#;

const NODE_REPL_DRIVER: &str = r#"
const fs = require("fs");
const vm = require("vm");
const util = require("util");
const origWrite = process.stdout.write.bind(process.stdout);

let outCap = "";
let errCap = "";
const fakeOut = (chunk) => { outCap += String(chunk); return true; };
const fakeErr = (chunk) => { errCap += String(chunk); return true; };

const sandboxConsole = {
  log: (...a) => { outCap += util.format(...a) + "\n"; },
  info: (...a) => { outCap += util.format(...a) + "\n"; },
  warn: (...a) => { errCap += util.format(...a) + "\n"; },
  error: (...a) => { errCap += util.format(...a) + "\n"; },
};

const ctx = vm.createContext({
  console: sandboxConsole,
  require,
  Buffer,
  process,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
});

let buf = Buffer.alloc(0);
function readMore() {
  const tmp = Buffer.alloc(4096);
  while (true) {
    try {
      const n = fs.readSync(0, tmp, 0, tmp.length, null);
      if (n <= 0) return false;
      buf = Buffer.concat([buf, tmp.subarray(0, n)]);
      return true;
    } catch (e) {
      if (e.code === "EAGAIN") continue;
      return false;
    }
  }
}

function readLine() {
  while (true) {
    const idx = buf.indexOf(10);
    if (idx !== -1) {
      const line = buf.subarray(0, idx).toString("utf8");
      buf = buf.subarray(idx + 1);
      return line;
    }
    if (!readMore()) return null;
  }
}

function readExact(n) {
  while (buf.length < n) {
    if (!readMore()) throw new Error("unexpected eof");
  }
  const out = buf.subarray(0, n);
  buf = buf.subarray(n);
  return out.toString("utf8");
}

function writeResp(rc, outS, errS, msgS) {
  const ob = Buffer.from(outS, "utf8");
  const eb = Buffer.from(errS, "utf8");
  const mb = Buffer.from(msgS, "utf8");
  origWrite(`RESP ${rc} ${ob.length} ${eb.length} ${mb.length}\n`);
  if (ob.length) origWrite(ob);
  if (eb.length) origWrite(eb);
  if (mb.length) origWrite(mb);
}

while (true) {
  const line = readLine();
  if (line === null) break;
  const parts = line.trim().split(/\s+/);
  if (parts.length !== 2) {
    writeResp(1, "", "", "malformed repl command");
    continue;
  }
  const op = parts[0];
  const n = parseInt(parts[1], 10);
  const code = readExact(n);
  if (op !== "EXEC") {
    writeResp(1, "", "", `unknown op ${op}`);
    continue;
  }
  outCap = "";
  errCap = "";
  let rc = 0;
  let errMsg = "";
  const prevOut = process.stdout.write;
  const prevErr = process.stderr.write;
  process.stdout.write = fakeOut;
  process.stderr.write = fakeErr;
  try {
    const res = vm.runInContext(code, ctx);
    if (res !== undefined) {
      outCap += util.inspect(res) + "\n";
    }
  } catch (e) {
    rc = 1;
    errCap += (e && e.stack ? e.stack : String(e)) + "\n";
    errMsg = "node exception";
  } finally {
    process.stdout.write = prevOut;
    process.stderr.write = prevErr;
  }
  writeResp(rc, outCap, errCap, errMsg);
}
"#;

struct WorkerProcess {
    pid: libc::pid_t,
    stdin_fd: RawFd,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    stdout_buf: Vec<u8>,
    stderr_buf: Vec<u8>,
}

impl WorkerProcess {
    fn spawn(argv: &[&str]) -> Result<Self, String> {
        let env_path = std::env::var("PATH").unwrap_or_else(|_| String::from(DEFAULT_PATH));
        let exec_cstr = resolve_executable(argv[0], &env_path)?;
        let mut argv_cstrs = Vec::with_capacity(argv.len());
        for a in argv {
            argv_cstrs.push(CString::new(*a).map_err(|_| String::from("NUL byte in repl argv"))?);
        }
        let mut argv_ptrs: Vec<*const libc::c_char> =
            argv_cstrs.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(ptr::null());

        let mut env_cstrs = Vec::new();
        for (k, v) in std::env::vars() {
            if let Ok(cs) = CString::new(format!("{k}={v}")) {
                env_cstrs.push(cs);
            }
        }
        if !std::env::vars_os().any(|(k, _)| k == "PATH") {
            if let Ok(cs) = CString::new(format!("PATH={DEFAULT_PATH}")) {
                env_cstrs.push(cs);
            }
        }
        let mut envp_ptrs: Vec<*const libc::c_char> =
            env_cstrs.iter().map(|s| s.as_ptr()).collect();
        envp_ptrs.push(ptr::null());

        let stdin_pipe = create_cloexec_pipe().map_err(|e| format!("pipe stdin: {e}"))?;
        let stdout_pipe = create_cloexec_pipe().map_err(|e| {
            close_fd_quiet(stdin_pipe[0]);
            close_fd_quiet(stdin_pipe[1]);
            format!("pipe stdout: {e}")
        })?;
        let stderr_pipe = create_cloexec_pipe().map_err(|e| {
            close_fd_quiet(stdin_pipe[0]);
            close_fd_quiet(stdin_pipe[1]);
            close_fd_quiet(stdout_pipe[0]);
            close_fd_quiet(stdout_pipe[1]);
            format!("pipe stderr: {e}")
        })?;

        let pid = match spawn_via_clone3() {
            Ok(p) => p,
            Err(e) => {
                close_fd_quiet(stdin_pipe[0]);
                close_fd_quiet(stdin_pipe[1]);
                close_fd_quiet(stdout_pipe[0]);
                close_fd_quiet(stdout_pipe[1]);
                close_fd_quiet(stderr_pipe[0]);
                close_fd_quiet(stderr_pipe[1]);
                return Err(format!("clone3 repl worker failed: {e}"));
            }
        };

        if pid == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                libc::dup2(stdin_pipe[0], libc::STDIN_FILENO);
                libc::dup2(stdout_pipe[1], libc::STDOUT_FILENO);
                libc::dup2(stderr_pipe[1], libc::STDERR_FILENO);

                let rc = libc::syscall(
                    libc::SYS_close_range,
                    3 as libc::c_uint,
                    libc::c_uint::MAX,
                    0 as libc::c_uint,
                );
                if rc != 0 {
                    close_fd_quiet(stdin_pipe[0]);
                    close_fd_quiet(stdin_pipe[1]);
                    close_fd_quiet(stdout_pipe[0]);
                    close_fd_quiet(stdout_pipe[1]);
                    close_fd_quiet(stderr_pipe[0]);
                    close_fd_quiet(stderr_pipe[1]);
                }

                let work_dir = if Path::new("/workspace").is_dir() {
                    c"/workspace".as_ptr()
                } else {
                    c"/tmp".as_ptr()
                };
                let _ = libc::chdir(work_dir);

                libc::execve(exec_cstr.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
                libc::_exit(127);
            }
        }

        close_fd_quiet(stdin_pipe[0]);
        close_fd_quiet(stdout_pipe[1]);
        close_fd_quiet(stderr_pipe[1]);
        set_nonblocking(stdout_pipe[0]);
        set_nonblocking(stderr_pipe[0]);

        Ok(Self {
            pid,
            stdin_fd: stdin_pipe[1],
            stdout_fd: stdout_pipe[0],
            stderr_fd: stderr_pipe[0],
            stdout_buf: Vec::with_capacity(4096),
            stderr_buf: Vec::with_capacity(1024),
        })
    }

    fn is_alive(&self) -> bool {
        if self.pid <= 0 {
            return false;
        }
        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        rc == 0
    }

    fn terminate(&mut self) {
        close_fd_quiet(self.stdin_fd);
        close_fd_quiet(self.stdout_fd);
        close_fd_quiet(self.stderr_fd);
        self.stdin_fd = -1;
        self.stdout_fd = -1;
        self.stderr_fd = -1;
        if self.pid > 0 {
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                let mut status = 0;
                loop {
                    let rc = libc::waitpid(self.pid, &mut status, 0);
                    if rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    break;
                }
            }
            self.pid = -1;
            reap_zombies();
        }
    }

    fn poll_once(&mut self, deadline_ns: Option<u64>) -> Result<(bool, bool), String> {
        let mut fds = [
            libc::pollfd {
                fd: self.stdout_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.stderr_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let timeout_ms: libc::c_int = if let Some(dl) = deadline_ns {
            let now = monotonic_ns();
            if now >= dl {
                return Err(String::from("REPL execution timed out"));
            }
            (((dl - now) / 1_000_000).clamp(1, i32::MAX as u64)) as libc::c_int
        } else {
            -1
        };

        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok((false, false));
            }
            return Err(format!("poll failed: {err}"));
        }
        if ready == 0 && deadline_ns.is_some_and(|dl| monotonic_ns() >= dl) {
            return Err(String::from("REPL execution timed out"));
        }

        let mut eof_out = false;
        let mut eof_err = false;
        if (fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            eof_out = !drain_into(self.stdout_fd, &mut self.stdout_buf);
        }
        if (fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            eof_err = !drain_into(self.stderr_fd, &mut self.stderr_buf);
        }
        Ok((eof_out, eof_err))
    }

    fn run_framed(
        &mut self,
        op: &str,
        payload: &[u8],
        timeout_ms: u64,
    ) -> Result<(i32, String, String, Option<String>), String> {
        let hdr = format!("{op} {}\n", payload.len());
        write_all_fd(self.stdin_fd, hdr.as_bytes())
            .map_err(|e| format!("failed writing REPL header: {e}"))?;
        if !payload.is_empty() {
            write_all_fd(self.stdin_fd, payload)
                .map_err(|e| format!("failed writing REPL payload: {e}"))?;
        }

        let deadline_ns = if timeout_ms > 0 {
            Some(monotonic_ns().saturating_add(timeout_ms.saturating_mul(1_000_000)))
        } else {
            None
        };

        loop {
            if let Some(parsed) = try_consume_framed_response(&mut self.stdout_buf) {
                // Drain any pending asynchronous stderr into err output.
                let _ = drain_into(self.stderr_fd, &mut self.stderr_buf);
                let mut err_str = parsed.2;
                if !self.stderr_buf.is_empty() {
                    let extra = String::from_utf8_lossy(&self.stderr_buf);
                    if !err_str.is_empty() && !err_str.ends_with('\n') {
                        err_str.push('\n');
                    }
                    err_str.push_str(&extra);
                    self.stderr_buf.clear();
                }
                return Ok((parsed.0, parsed.1, err_str, parsed.3));
            }

            let (eof_out, _) = self.poll_once(deadline_ns)?;
            if eof_out {
                let extra_err = String::from_utf8_lossy(&self.stderr_buf).into_owned();
                let extra_out = String::from_utf8_lossy(&self.stdout_buf).into_owned();
                return Err(format!(
                    "REPL worker exited unexpectedly (stdout={extra_out:?}, stderr={extra_err:?})"
                ));
            }
        }
    }

    fn run_shell(
        &mut self,
        code: &str,
        marker: &str,
        timeout_ms: u64,
    ) -> Result<(i32, String, String, Option<String>), String> {
        let script = format!(
            "{code}\n__sbx_rc=$?\nprintf '\\n{marker}:%d\\n' \"$__sbx_rc\"\nprintf '\\n{marker}_ERR\\n' >&2\n"
        );
        write_all_fd(self.stdin_fd, script.as_bytes())
            .map_err(|e| format!("failed writing shell script: {e}"))?;

        let deadline_ns = if timeout_ms > 0 {
            Some(monotonic_ns().saturating_add(timeout_ms.saturating_mul(1_000_000)))
        } else {
            None
        };

        let mut eof_seen = false;
        let out_prefix = format!("{marker}:");
        let err_marker = format!("{marker}_ERR\n");

        loop {
            let has_out = find_shell_out_marker(&self.stdout_buf, &out_prefix);
            let has_err = find_bytes(&self.stderr_buf, err_marker.as_bytes());
            if let (Some((out_end, rc_start, rc_end, line_end)), Some(err_pos)) = (has_out, has_err)
            {
                let mut stdout_str =
                    String::from_utf8_lossy(&self.stdout_buf[..out_end]).into_owned();
                if stdout_str.ends_with('\n') && out_end > 0 {
                    // Trim the synthetic leading newline before the marker only if code produced output.
                    let _ = stdout_str.pop();
                }
                let rc_str = String::from_utf8_lossy(&self.stdout_buf[rc_start..rc_end]);
                let rc = rc_str.trim().parse::<i32>().unwrap_or(0);
                self.stdout_buf.drain(..line_end);

                let mut stderr_str =
                    String::from_utf8_lossy(&self.stderr_buf[..err_pos]).into_owned();
                if stderr_str.ends_with('\n') && err_pos > 0 {
                    let _ = stderr_str.pop();
                }
                self.stderr_buf.drain(..err_pos + err_marker.len());
                return Ok((rc, stdout_str, stderr_str, None));
            }

            if eof_seen {
                let out_str = String::from_utf8_lossy(&self.stdout_buf).into_owned();
                let err_str = String::from_utf8_lossy(&self.stderr_buf).into_owned();
                self.stdout_buf.clear();
                self.stderr_buf.clear();
                return Err(format!("shell exited: stdout={out_str:?} stderr={err_str:?}"));
            }

            let (eo, ee) = self.poll_once(deadline_ns)?;
            if eo && ee {
                eof_seen = true;
            }
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Manages persistent in-sandbox Stateful REPL workers (`python`, `node`, `sh`).
pub struct ReplManager {
    python: Option<WorkerProcess>,
    node: Option<WorkerProcess>,
    shell: Option<WorkerProcess>,
    seq: u64,
}

impl ReplManager {
    pub fn new() -> Self {
        Self {
            python: None,
            node: None,
            shell: None,
            seq: 0,
        }
    }

    pub fn execute(&mut self, request_id: u32, req: &ReplExecRequest) -> ReplExecResponse {
        let start_ns = monotonic_ns();
        self.seq = self.seq.saturating_add(1);
        let lang = req.language.trim().to_ascii_lowercase();

        let res = match lang.as_str() {
            "python" | "python3" | "py" => self.exec_python(req),
            "node" | "nodejs" | "javascript" | "js" => self.exec_node(req),
            "sh" | "bash" | "shell" => self.exec_shell(&lang, request_id, req),
            other => Err(format!("unsupported REPL language: {other}")),
        };

        let elapsed_us = (monotonic_ns().saturating_sub(start_ns)) / 1000;
        match res {
            Ok((exit_code, stdout, stderr, error)) => ReplExecResponse {
                exit_code,
                stdout,
                stderr,
                elapsed_us,
                error,
            },
            Err(err_msg) => {
                let timed_out = err_msg.contains("timed out");
                ReplExecResponse {
                    exit_code: if timed_out { 137 } else { 1 },
                    stdout: String::new(),
                    stderr: err_msg.clone(),
                    elapsed_us,
                    error: Some(err_msg),
                }
            }
        }
    }

    /// Flush live Python REPL namespace state to disk before filesystem snapshot/checkpoint.
    pub fn save_checkpoint(&mut self) {
        if let Some(worker) = self.python.as_mut() {
            if worker.is_alive() {
                if worker
                    .run_framed("SAVE", b"/tmp/.sbx-repl-checkpoint.bin", 3000)
                    .is_err()
                {
                    self.python = None;
                    return;
                }
                // Also try root checkpoint path; harmless if root is read-only under Landlock.
                let _ = worker.run_framed("SAVE", b"/.sbx-repl-checkpoint.bin", 1000);
            } else {
                self.python = None;
            }
        }
    }

    fn exec_python(
        &mut self,
        req: &ReplExecRequest,
    ) -> Result<(i32, String, String, Option<String>), String> {
        if self.python.as_ref().is_some_and(|w| !w.is_alive()) {
            self.python = None;
        }
        if self.python.is_none() {
            let worker = WorkerProcess::spawn(&["python3", "-u", "-c", PYTHON_REPL_DRIVER])?;
            self.python = Some(worker);
        }
        let worker = self.python.as_mut().unwrap();
        match worker.run_framed("EXEC", req.code.as_bytes(), req.timeout_ms) {
            Ok(out) => Ok(out),
            Err(e) => {
                self.python = None;
                Err(e)
            }
        }
    }

    fn exec_node(
        &mut self,
        req: &ReplExecRequest,
    ) -> Result<(i32, String, String, Option<String>), String> {
        if self.node.as_ref().is_some_and(|w| !w.is_alive()) {
            self.node = None;
        }
        if self.node.is_none() {
            let worker = WorkerProcess::spawn(&["node", "-e", NODE_REPL_DRIVER])?;
            self.node = Some(worker);
        }
        let worker = self.node.as_mut().unwrap();
        match worker.run_framed("EXEC", req.code.as_bytes(), req.timeout_ms) {
            Ok(out) => Ok(out),
            Err(e) => {
                self.node = None;
                Err(e)
            }
        }
    }

    fn exec_shell(
        &mut self,
        lang: &str,
        request_id: u32,
        req: &ReplExecRequest,
    ) -> Result<(i32, String, String, Option<String>), String> {
        if self.shell.as_ref().is_some_and(|w| !w.is_alive()) {
            self.shell = None;
        }
        if self.shell.is_none() {
            let bin = if lang == "bash" && Path::new("/bin/bash").exists() {
                "/bin/bash"
            } else {
                "/bin/sh"
            };
            let worker = WorkerProcess::spawn(&[bin])?;
            self.shell = Some(worker);
        }
        let marker = format!("__SBX_DONE_{}_{}__", request_id, self.seq);
        let worker = self.shell.as_mut().unwrap();
        match worker.run_shell(&req.code, &marker, req.timeout_ms) {
            Ok(out) => Ok(out),
            Err(e) => {
                // Check exit status if shell exited cleanly via `exit N`.
                let exit_code = if let Some(mut w) = self.shell.take() {
                    let pid = w.pid;
                    let mut status = 0;
                    let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                    if rc == pid && libc::WIFEXITED(status) {
                        w.pid = -1;
                        Some(libc::WEXITSTATUS(status))
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(code) = exit_code {
                    return Ok((code, String::new(), String::new(), None));
                }
                Err(e)
            }
        }
    }
}

fn drain_into(fd: RawFd, buf: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n > 0 {
            buf.extend_from_slice(&chunk[..n as usize]);
        } else if n == 0 {
            return false;
        } else {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) => return true,
                Some(libc::EINTR) => continue,
                _ => return false,
            }
        }
    }
}

fn try_consume_framed_response(
    buf: &mut Vec<u8>,
) -> Option<(i32, String, String, Option<String>)> {
    let nl = buf.iter().position(|&b| b == b'\n')?;
    let header_line = core::str::from_utf8(&buf[..nl]).ok()?;
    let mut parts = header_line.split_ascii_whitespace();
    if parts.next()? != "RESP" {
        return None;
    }
    let rc: i32 = parts.next()?.parse().ok()?;
    let out_len: usize = parts.next()?.parse().ok()?;
    let err_len: usize = parts.next()?.parse().ok()?;
    let msg_len: usize = parts.next()?.parse().ok()?;

    let total = nl + 1 + out_len + err_len + msg_len;
    if buf.len() < total {
        return None;
    }

    let mut pos = nl + 1;
    let out_str = String::from_utf8_lossy(&buf[pos..pos + out_len]).into_owned();
    pos += out_len;
    let err_str = String::from_utf8_lossy(&buf[pos..pos + err_len]).into_owned();
    pos += err_len;
    let msg_str = if msg_len > 0 {
        Some(String::from_utf8_lossy(&buf[pos..pos + msg_len]).into_owned())
    } else {
        None
    };

    buf.drain(..total);
    Some((rc, out_str, err_str, msg_str))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_shell_out_marker(buf: &[u8], prefix: &str) -> Option<(usize, usize, usize, usize)> {
    let pos = find_bytes(buf, prefix.as_bytes())?;
    let rc_start = pos + prefix.len();
    let rel_nl = buf[rc_start..].iter().position(|&b| b == b'\n')?;
    let rc_end = rc_start + rel_nl;
    let line_end = rc_end + 1;
    Some((pos, rc_start, rc_end, line_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_framed_response_and_leaves_trailing_bytes() {
        let mut buf = b"RESP 0 6 4 0\nhello\nerr\nRESP 1".to_vec();
        let parsed = try_consume_framed_response(&mut buf).expect("should parse frame");
        assert_eq!(parsed.0, 0);
        assert_eq!(parsed.1, "hello\n");
        assert_eq!(parsed.2, "err\n");
        assert_eq!(parsed.3, None);
        assert_eq!(buf, b"RESP 1");
    }

    #[test]
    fn python_repl_preserves_state_and_expression_values() {
        if !Path::new("/usr/bin/python3").exists() {
            return;
        }
        let mut mgr = ReplManager::new();
        let r1 = mgr.execute(
            1,
            &ReplExecRequest {
                language: String::from("python"),
                code: String::from("import math\nx = 21\nx * 2"),
                timeout_ms: 5000,
            },
        );
        assert_eq!(r1.exit_code, 0, "stderr={}", r1.stderr);
        assert_eq!(r1.stdout, "42\n");

        let r2 = mgr.execute(
            2,
            &ReplExecRequest {
                language: String::from("python"),
                code: String::from("int(math.sqrt(x + 4))"),
                timeout_ms: 5000,
            },
        );
        assert_eq!(r2.exit_code, 0, "stderr={}", r2.stderr);
        assert_eq!(r2.stdout, "5\n");
    }

    #[test]
    fn shell_repl_preserves_env_and_cwd() {
        let mut mgr = ReplManager::new();
        let r1 = mgr.execute(
            1,
            &ReplExecRequest {
                language: String::from("sh"),
                code: String::from("MY_SBX_VAR=hello_repl && cd /tmp"),
                timeout_ms: 5000,
            },
        );
        assert_eq!(r1.exit_code, 0, "stderr={}", r1.stderr);

        let r2 = mgr.execute(
            2,
            &ReplExecRequest {
                language: String::from("sh"),
                code: String::from("printf '%s:%s' \"$MY_SBX_VAR\" \"$(pwd)\""),
                timeout_ms: 5000,
            },
        );
        assert_eq!(r2.exit_code, 0, "stderr={}", r2.stderr);
        assert_eq!(r2.stdout, "hello_repl:/tmp");
    }
}
