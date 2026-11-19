use std::ffi::CString;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::ptr;

use sbx_proto::{
    decode_postcard_payload, encode_postcard_frame, ExecRequest, FileGetRequest, FileGetResponse,
    FilePutRequest, FilePutResponse, OpCode, PingPayload, PongPayload, ReplExecRequest,
    SignalRequest, VsockFrameHeader, FLAG_NONE, FLAG_PONG, HEADER_LEN, MAX_PAYLOAD_LEN,
};

use crate::init::reap_zombies;
use crate::repl::ReplManager;
use crate::spawner::execute_streaming;

const AF_VSOCK: libc::c_int = 40;
const VMADDR_CID_ANY: u32 = u32::MAX;

#[repr(C)]
struct SockAddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

pub enum TransportMode {
    ListenFd(RawFd),
    UnixSocket(String),
    VsockPort(u32),
}

pub fn run_transport_loop(mode: TransportMode) -> io::Result<()> {
    let listen_fd = match mode {
        TransportMode::ListenFd(fd) => {
            set_cloexec(fd);
            fd
        }
        TransportMode::UnixSocket(ref path) => bind_unix_socket(path)?,
        TransportMode::VsockPort(port) => bind_vsock(port)?,
    };

    let mut payload_buf = vec![0u8; 64 * 1024];
    let mut tx_buf = vec![0u8; 64 * 1024];
    let mut repl_mgr = ReplManager::new();

    loop {
        reap_zombies();
        let conn_fd = unsafe { libc::accept(listen_fd, ptr::null_mut(), ptr::null_mut()) };
        if conn_fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        set_cloexec(conn_fd);
        handle_connection(conn_fd, &mut payload_buf, &mut tx_buf, &mut repl_mgr);
        unsafe {
            libc::close(conn_fd);
        }
        reap_zombies();
    }
}

fn handle_connection(
    conn_fd: RawFd,
    payload_buf: &mut Vec<u8>,
    tx_buf: &mut Vec<u8>,
    repl_mgr: &mut ReplManager,
) {
    let mut hdr_buf = [0u8; HEADER_LEN];
    loop {
        match read_exact_fd(conn_fd, &mut hdr_buf) {
            Ok(true) => {}
            Ok(false) | Err(_) => break,
        }

        let hdr = match VsockFrameHeader::from_bytes(&hdr_buf) {
            Ok(h) => h,
            Err(_) => break,
        };

        if hdr.payload_len > MAX_PAYLOAD_LEN {
            break;
        }
        let plen = hdr.payload_len as usize;
        if payload_buf.len() < plen {
            payload_buf.resize(plen, 0);
        }
        if plen > 0 {
            match read_exact_fd(conn_fd, &mut payload_buf[..plen]) {
                Ok(true) => {}
                Ok(false) | Err(_) => break,
            }
        }

        match hdr.opcode {
            OpCode::Ping => {
                let ts = if plen > 0 {
                    decode_postcard_payload::<PingPayload>(&payload_buf[..plen])
                        .map(|p| p.timestamp_ns)
                        .unwrap_or(0)
                } else {
                    0
                };
                let pong = PongPayload {
                    timestamp_ns: ts,
                    agent_pid: std::process::id(),
                };
                if let Ok(n) =
                    encode_postcard_frame(OpCode::Ping, hdr.request_id, FLAG_PONG, &pong, tx_buf)
                {
                    if write_all_fd(conn_fd, &tx_buf[..n]).is_err() {
                        break;
                    }
                }
            }
            OpCode::ExecReq => {
                if let Ok(req) = decode_postcard_payload::<ExecRequest>(&payload_buf[..plen]) {
                    execute_streaming(conn_fd, hdr.request_id, &req);
                } else {
                    break;
                }
            }
            OpCode::Signal => {
                if let Ok(sig) = decode_postcard_payload::<SignalRequest>(&payload_buf[..plen]) {
                    if sig.target_request_id > 0 {
                        unsafe {
                            libc::kill(-(sig.target_request_id as libc::pid_t), sig.signal);
                        }
                    }
                }
            }
            OpCode::FilePut => {
                if let Ok(req) = decode_postcard_payload::<FilePutRequest>(&payload_buf[..plen]) {
                    let resp = handle_file_put(&req);
                    let needed = HEADER_LEN + 512;
                    if tx_buf.len() < needed {
                        tx_buf.resize(needed, 0);
                    }
                    if let Ok(n) = encode_postcard_frame(
                        OpCode::FilePut,
                        hdr.request_id,
                        FLAG_PONG,
                        &resp,
                        tx_buf,
                    ) {
                        if write_all_fd(conn_fd, &tx_buf[..n]).is_err() {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            OpCode::FileGet => {
                if let Ok(req) = decode_postcard_payload::<FileGetRequest>(&payload_buf[..plen]) {
                    let resp = handle_file_get(&req);
                    let needed = HEADER_LEN + resp.data.len() + 512;
                    if tx_buf.len() < needed {
                        tx_buf.resize(needed.min(HEADER_LEN + MAX_PAYLOAD_LEN as usize), 0);
                    }
                    if let Ok(n) = encode_postcard_frame(
                        OpCode::FileGet,
                        hdr.request_id,
                        FLAG_PONG,
                        &resp,
                        tx_buf,
                    ) {
                        if write_all_fd(conn_fd, &tx_buf[..n]).is_err() {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            OpCode::Freeze => {
                repl_mgr.save_checkpoint();
                unsafe {
                    libc::sync();
                }
                let ack = VsockFrameHeader::new(OpCode::Freeze, hdr.request_id, 0, FLAG_PONG);
                if write_all_fd(conn_fd, &ack.to_bytes()).is_err() {
                    break;
                }
            }
            OpCode::Thaw => {
                let ack = VsockFrameHeader::new(OpCode::Thaw, hdr.request_id, 0, FLAG_PONG);
                if write_all_fd(conn_fd, &ack.to_bytes()).is_err() {
                    break;
                }
            }
            OpCode::ReplExec => {
                if let Ok(req) = decode_postcard_payload::<ReplExecRequest>(&payload_buf[..plen]) {
                    let resp = repl_mgr.execute(hdr.request_id, &req);
                    let needed = HEADER_LEN + resp.stdout.len() + resp.stderr.len() + 512;
                    if tx_buf.len() < needed {
                        tx_buf.resize(needed.min(HEADER_LEN + MAX_PAYLOAD_LEN as usize), 0);
                    }
                    if let Ok(n) = encode_postcard_frame(
                        OpCode::ReplExec,
                        hdr.request_id,
                        FLAG_PONG,
                        &resp,
                        tx_buf,
                    ) {
                        if write_all_fd(conn_fd, &tx_buf[..n]).is_err() {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            OpCode::StdinData
            | OpCode::StdoutData
            | OpCode::StderrData
            | OpCode::ExecExit => {
                // Reserved / client-bound opcodes ignored.
                let ack = VsockFrameHeader::new(hdr.opcode, hdr.request_id, 0, FLAG_NONE);
                let _ = write_all_fd(conn_fd, &ack.to_bytes());
            }
        }
    }
}

fn handle_file_put(req: &FilePutRequest) -> FilePutResponse {
    let path = Path::new(&req.path);
    if req.path.is_empty() {
        return FilePutResponse {
            ok: false,
            bytes_written: 0,
            error: Some(String::from("empty destination path")),
        };
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = fs::create_dir_all(parent) {
                return FilePutResponse {
                    ok: false,
                    bytes_written: 0,
                    error: Some(format!("create_dir_all failed: {e}")),
                };
            }
        }
    }
    if let Err(e) = fs::write(path, &req.data) {
        return FilePutResponse {
            ok: false,
            bytes_written: 0,
            error: Some(format!("write failed: {e}")),
        };
    }
    if req.mode != 0 {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(req.mode));
    }
    FilePutResponse {
        ok: true,
        bytes_written: req.data.len() as u64,
        error: None,
    }
}

fn handle_file_get(req: &FileGetRequest) -> FileGetResponse {
    if req.path.is_empty() {
        return FileGetResponse {
            ok: false,
            mode: 0,
            data: Vec::new(),
            error: Some(String::from("empty source path")),
        };
    }
    let meta = match fs::metadata(&req.path) {
        Ok(m) => m,
        Err(e) => {
            return FileGetResponse {
                ok: false,
                mode: 0,
                data: Vec::new(),
                error: Some(format!("stat failed: {e}")),
            };
        }
    };
    let max_allowed = if req.max_bytes > 0 {
        req.max_bytes.min((MAX_PAYLOAD_LEN as u64).saturating_sub(512))
    } else {
        (MAX_PAYLOAD_LEN as u64).saturating_sub(512)
    };
    if meta.len() > max_allowed {
        return FileGetResponse {
            ok: false,
            mode: 0,
            data: Vec::new(),
            error: Some(format!(
                "file size {} exceeds max frame limit {max_allowed}",
                meta.len()
            )),
        };
    }
    match fs::read(&req.path) {
        Ok(data) => FileGetResponse {
            ok: true,
            mode: meta.permissions().mode(),
            data,
            error: None,
        },
        Err(e) => FileGetResponse {
            ok: false,
            mode: 0,
            data: Vec::new(),
            error: Some(format!("read failed: {e}")),
        },
    }
}

fn set_cloexec(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

fn bind_unix_socket(path: &str) -> io::Result<RawFd> {
    if Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    let c_path = CString::new(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = c_path.as_bytes_with_nul();
    if bytes.len() > addr.sun_path.len() {
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unix socket path too long",
        ));
    }
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }

    let len = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), len) } != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    if unsafe { libc::listen(fd, 64) } != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    Ok(fd)
}

fn bind_vsock(port: u32) -> io::Result<RawFd> {
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let addr = SockAddrVm {
        svm_family: AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    let len = mem::size_of::<SockAddrVm>() as libc::socklen_t;
    if unsafe { libc::bind(fd, (&addr as *const SockAddrVm).cast(), len) } != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    if unsafe { libc::listen(fd, 64) } != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    Ok(fd)
}

/// Read exact `buf.len()` bytes from `fd`. Returns `Ok(false)` on clean EOF at offset 0.
pub fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<bool> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf[offset..].as_mut_ptr().cast(),
                buf.len() - offset,
            )
        };
        if n > 0 {
            offset += n as usize;
        } else if n == 0 {
            if offset == 0 {
                return Ok(false);
            }
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
    }
    Ok(true)
}

pub fn write_all_fd(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = unsafe { libc::write(fd, buf[offset..].as_ptr().cast(), buf.len() - offset) };
        if n > 0 {
            offset += n as usize;
        } else if n == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
    }
    Ok(())
}
