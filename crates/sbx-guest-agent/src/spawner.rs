use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::path::Path;
use std::ptr;

use sbx_proto::{
    encode_postcard_frame, encode_raw_frame, ExecExitPayload, ExecRequest, OpCode, FLAG_NONE,
    HEADER_LEN,
};

use crate::init::reap_zombies;
use crate::transport::write_all_fd;

const STREAM_CHUNK_SIZE: usize = 65536;

/// Linux `struct clone_args` layout for `SYS_clone3`.
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

#[inline]
pub(crate) fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[inline]
fn timeval_to_us(tv: libc::timeval) -> u64 {
    (tv.tv_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add(tv.tv_usec as u64)
}

fn is_executable_file(c_path: &CString) -> bool {
    let mut st: libc::stat = unsafe { mem::zeroed() };
    let rc = unsafe { libc::stat(c_path.as_ptr(), &mut st) };
    if rc != 0 {
        return false;
    }
    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    if is_dir {
        return false;
    }
    unsafe { libc::access(c_path.as_ptr(), libc::X_OK) == 0 }
}

pub(crate) fn resolve_executable(program: &str, path_env: &str) -> Result<CString, String> {
    if program.contains('/') {
        return CString::new(program).map_err(|_| String::from("invalid NUL byte in argv[0]"));
    }
    for dir in path_env.split(':') {
        let base = if dir.is_empty() { "." } else { dir };
        let candidate = Path::new(base).join(program);
        if let Some(s) = candidate.to_str() {
            if let Ok(c_str) = CString::new(s) {
                if is_executable_file(&c_str) {
                    return Ok(c_str);
                }
            }
        }
    }
    // Fallback to raw program name so execve sets ENOENT if absent.
    CString::new(program).map_err(|_| String::from("invalid NUL byte in argv[0]"))
}

pub(crate) fn spawn_via_clone3() -> io::Result<libc::pid_t> {
    let args = CloneArgs {
        flags: 0,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            mem::size_of::<CloneArgs>(),
        )
    };
    if pid >= 0 {
        return Ok(pid as libc::pid_t);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOSYS) {
        let fpid = unsafe { libc::fork() };
        if fpid < 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(fpid);
    }
    Err(err)
}

pub(crate) fn create_cloexec_pipe() -> io::Result<[RawFd; 2]> {
    let mut fds = [-1 as RawFd; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fds)
}

pub(crate) fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

pub(crate) fn close_fd_quiet(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

/// Spawn and stream execution for an `ExecRequest` directly via `clone3`.
pub fn execute_streaming(conn_fd: RawFd, request_id: u32, req: &ExecRequest) {
    let start_ns = monotonic_ns();
    let mut frame_buf = vec![0u8; HEADER_LEN + STREAM_CHUNK_SIZE];

    if req.argv.is_empty() {
        let payload = ExecExitPayload {
            exit_code: 127,
            term_signal: None,
            user_cpu_us: 0,
            sys_cpu_us: 0,
            max_rss_kb: 0,
            elapsed_us: 0,
            error: Some(String::from("empty argv")),
        };
        send_exit_frame(conn_fd, request_id, &payload, &mut frame_buf);
        return;
    }

    // Prepare all CStrings before clone3 so the child performs zero heap allocations.
    let mut has_path = false;
    let mut effective_path = String::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    let mut env_cstrings: Vec<CString> = Vec::with_capacity(req.env.len() + 1);
    for (k, v) in &req.env {
        if k == "PATH" {
            has_path = true;
            effective_path = v.clone();
        }
        if let Ok(cs) = CString::new(format!("{k}={v}")) {
            env_cstrings.push(cs);
        }
    }
    if !has_path {
        if let Ok(cs) = CString::new(format!("PATH={effective_path}")) {
            env_cstrings.push(cs);
        }
    }

    let exec_cstring = match resolve_executable(&req.argv[0], &effective_path) {
        Ok(c) => c,
        Err(msg) => {
            let payload = ExecExitPayload {
                exit_code: 127,
                term_signal: None,
                user_cpu_us: 0,
                sys_cpu_us: 0,
                max_rss_kb: 0,
                elapsed_us: (monotonic_ns() - start_ns) / 1000,
                error: Some(msg),
            };
            send_exit_frame(conn_fd, request_id, &payload, &mut frame_buf);
            return;
        }
    };

    let mut argv_cstrings: Vec<CString> = Vec::with_capacity(req.argv.len());
    for arg in &req.argv {
        match CString::new(arg.as_str()) {
            Ok(c) => argv_cstrings.push(c),
            Err(_) => {
                let payload = ExecExitPayload {
                    exit_code: 127,
                    term_signal: None,
                    user_cpu_us: 0,
                    sys_cpu_us: 0,
                    max_rss_kb: 0,
                    elapsed_us: (monotonic_ns() - start_ns) / 1000,
                    error: Some(String::from("NUL byte in argv")),
                };
                send_exit_frame(conn_fd, request_id, &payload, &mut frame_buf);
                return;
            }
        }
    }

    let cwd_cstring = match CString::new(req.cwd.as_deref().unwrap_or("/")) {
        Ok(c) => c,
        Err(_) => {
            let payload = ExecExitPayload {
                exit_code: 127,
                term_signal: None,
                user_cpu_us: 0,
                sys_cpu_us: 0,
                max_rss_kb: 0,
                elapsed_us: (monotonic_ns() - start_ns) / 1000,
                error: Some(String::from("NUL byte in cwd")),
            };
            send_exit_frame(conn_fd, request_id, &payload, &mut frame_buf);
            return;
        }
    };

    let mut argv_ptrs: Vec<*const libc::c_char> =
        argv_cstrings.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(ptr::null());

    let mut envp_ptrs: Vec<*const libc::c_char> =
        env_cstrings.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(ptr::null());

    let stdout_pipe = match create_cloexec_pipe() {
        Ok(p) => p,
        Err(e) => {
            let payload = ExecExitPayload {
                exit_code: 127,
                term_signal: None,
                user_cpu_us: 0,
                sys_cpu_us: 0,
                max_rss_kb: 0,
                elapsed_us: (monotonic_ns() - start_ns) / 1000,
                error: Some(format!("pipe failed: {e}")),
            };
            send_exit_frame(conn_fd, request_id, &payload, &mut frame_buf);
            return;
        }
    };
    let stderr_pipe = match create_cloexec_pipe() {
        Ok(p) => p,
        Err(e) => {
            close_fd_quiet(stdout_pipe[0]);
            close_fd_quiet(stdout_pipe[1]);
            let payload = ExecExitPayload {
                exit_code: 127,
                term_signal: None,
                user_cpu_us: 0,
                sys_cpu_us: 0,
                max_rss_kb: 0,
                elapsed_us: (monotonic_ns() - start_ns) / 1000,
                error: Some(format!("pipe failed: {e}")),
            };
            send_exit_frame(conn_fd, request_id, &payload, &mut frame_buf);
            return;
        }
    };

    let child_pid = match spawn_via_clone3() {
        Ok(pid) => pid,
        Err(e) => {
            close_fd_quiet(stdout_pipe[0]);
            close_fd_quiet(stdout_pipe[1]);
            close_fd_quiet(stderr_pipe[0]);
            close_fd_quiet(stderr_pipe[1]);
            let payload = ExecExitPayload {
                exit_code: 127,
                term_signal: None,
                user_cpu_us: 0,
                sys_cpu_us: 0,
                max_rss_kb: 0,
                elapsed_us: (monotonic_ns() - start_ns) / 1000,
                error: Some(format!("clone3 failed: {e}")),
            };
            send_exit_frame(conn_fd, request_id, &payload, &mut frame_buf);
            return;
        }
    };

    if child_pid == 0 {
        unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

            // Reset SIGPIPE to default for the spawned workload.
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);

            let dev_null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            if dev_null >= 0 {
                libc::dup2(dev_null, libc::STDIN_FILENO);
                if dev_null > libc::STDERR_FILENO {
                    libc::close(dev_null);
                }
            } else {
                libc::close(libc::STDIN_FILENO);
            }

            libc::dup2(stdout_pipe[1], libc::STDOUT_FILENO);
            libc::dup2(stderr_pipe[1], libc::STDERR_FILENO);

            // Close all inherited fds >= 3 (including pipe ends and agent sockets).
            let rc = libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                0 as libc::c_uint,
            );
            if rc != 0 {
                libc::close(stdout_pipe[0]);
                libc::close(stdout_pipe[1]);
                libc::close(stderr_pipe[0]);
                libc::close(stderr_pipe[1]);
            }

            if libc::chdir(cwd_cstring.as_ptr()) != 0 {
                let msg = b"sbx-guest-agent: chdir failed\n";
                libc::write(
                    libc::STDERR_FILENO,
                    msg.as_ptr().cast(),
                    msg.len(),
                );
                libc::_exit(127);
            }

            if let Some(gid) = req.gid {
                if libc::setgid(gid as libc::gid_t) != 0 {
                    let msg = b"sbx-guest-agent: setgid failed\n";
                    libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
                    libc::_exit(127);
                }
            }

            if let Some(uid) = req.uid {
                if libc::setuid(uid as libc::uid_t) != 0 {
                    let msg = b"sbx-guest-agent: setuid failed\n";
                    libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
                    libc::_exit(127);
                }
            }

            libc::execve(
                exec_cstring.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            );

            let errno_val = *libc::__errno_location();
            let err_msg = match errno_val {
                libc::ENOENT => b"sbx-guest-agent: execve failed: ENOENT (file not found)\n".as_slice(),
                libc::EACCES => b"sbx-guest-agent: execve failed: EACCES (permission denied)\n".as_slice(),
                libc::ENOEXEC => b"sbx-guest-agent: execve failed: ENOEXEC (exec format error)\n".as_slice(),
                _ => b"sbx-guest-agent: execve failed\n".as_slice(),
            };
            libc::write(libc::STDERR_FILENO, err_msg.as_ptr().cast(), err_msg.len());
            libc::_exit(127);
        }
    }

    // Parent: close child write ends, set non-blocking on read ends.
    close_fd_quiet(stdout_pipe[1]);
    close_fd_quiet(stderr_pipe[1]);
    set_nonblocking(stdout_pipe[0]);
    set_nonblocking(stderr_pipe[0]);

    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut timed_out = false;
    let deadline_ns = if req.timeout_ms > 0 {
        Some(start_ns.saturating_add(req.timeout_ms.saturating_mul(1_000_000)))
    } else {
        None
    };

    while stdout_open || stderr_open {
        let mut fds = [
            libc::pollfd {
                fd: if stdout_open { stdout_pipe[0] } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if stderr_open { stderr_pipe[0] } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let poll_timeout_ms: libc::c_int = if let Some(deadline) = deadline_ns {
            let now = monotonic_ns();
            if now >= deadline {
                if !timed_out {
                    timed_out = true;
                    unsafe {
                        libc::kill(child_pid, libc::SIGKILL);
                    }
                }
                50
            } else {
                let rem_ms = ((deadline - now) / 1_000_000).clamp(1, i32::MAX as u64);
                rem_ms as libc::c_int
            }
        } else {
            -1
        };

        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, poll_timeout_ms) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        if stdout_open && (fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            if !drain_pipe_to_frames(
                stdout_pipe[0],
                conn_fd,
                request_id,
                OpCode::StdoutData,
                &mut frame_buf,
            ) {
                close_fd_quiet(stdout_pipe[0]);
                stdout_open = false;
            }
        }

        if stderr_open && (fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            if !drain_pipe_to_frames(
                stderr_pipe[0],
                conn_fd,
                request_id,
                OpCode::StderrData,
                &mut frame_buf,
            ) {
                close_fd_quiet(stderr_pipe[0]);
                stderr_open = false;
            }
        }
    }

    if stdout_open {
        close_fd_quiet(stdout_pipe[0]);
    }
    if stderr_open {
        close_fd_quiet(stderr_pipe[0]);
    }

    let mut status: libc::c_int = 0;
    let mut rusage: libc::rusage = unsafe { mem::zeroed() };
    loop {
        let rc = unsafe { libc::wait4(child_pid, &mut status, 0, &mut rusage) };
        if rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }

    reap_zombies();

    let elapsed_us = (monotonic_ns().saturating_sub(start_ns)) / 1000;
    let (exit_code, term_signal) = if libc::WIFEXITED(status) {
        (libc::WEXITSTATUS(status), None)
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        (128 + sig, Some(sig))
    } else {
        (1, None)
    };

    let payload = ExecExitPayload {
        exit_code,
        term_signal,
        user_cpu_us: timeval_to_us(rusage.ru_utime),
        sys_cpu_us: timeval_to_us(rusage.ru_stime),
        max_rss_kb: rusage.ru_maxrss.max(0) as u64,
        elapsed_us,
        error: if timed_out {
            Some(format!("command timed out after {} ms", req.timeout_ms))
        } else {
            None
        },
    };
    send_exit_frame(conn_fd, request_id, &payload, &mut frame_buf);
}

/// Drain non-blocking pipe `pipe_fd` and send `OpCode::StdoutData`/`StderrData` frames.
/// Returns `false` when EOF or fatal error is reached.
fn drain_pipe_to_frames(
    pipe_fd: RawFd,
    conn_fd: RawFd,
    request_id: u32,
    opcode: OpCode,
    frame_buf: &mut [u8],
) -> bool {
    loop {
        let n = unsafe {
            libc::read(
                pipe_fd,
                frame_buf[HEADER_LEN..].as_mut_ptr().cast(),
                STREAM_CHUNK_SIZE,
            )
        };
        if n > 0 {
            let len = n as usize;
            let mut hdr = [0u8; HEADER_LEN];
            sbx_proto::VsockFrameHeader::new(opcode, request_id, len as u32, FLAG_NONE)
                .write_to(&mut hdr);
            frame_buf[..HEADER_LEN].copy_from_slice(&hdr);
            if write_all_fd(conn_fd, &frame_buf[..HEADER_LEN + len]).is_err() {
                return false;
            }
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

fn send_exit_frame(
    conn_fd: RawFd,
    request_id: u32,
    payload: &ExecExitPayload,
    frame_buf: &mut [u8],
) {
    if let Ok(total) = encode_postcard_frame(OpCode::ExecExit, request_id, FLAG_NONE, payload, frame_buf)
    {
        let _ = write_all_fd(conn_fd, &frame_buf[..total]);
    } else {
        let mut fallback = [0u8; 256];
        let _ = encode_raw_frame(OpCode::ExecExit, request_id, FLAG_NONE, &[], &mut fallback);
        let _ = write_all_fd(conn_fd, &fallback[..HEADER_LEN]);
    }
}
