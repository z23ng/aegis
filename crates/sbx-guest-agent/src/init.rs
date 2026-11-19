use std::ffi::CStr;
use std::path::Path;
use std::ptr;

/// Initialize PID 1 / subreaper environment inside the sandbox.
pub fn init_pid1_env() {
    unsafe {
        // Ensure we reap any orphaned grandchild processes even if not running as literal PID 1.
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
        // Never terminate the agent on broken client pipes or sockets.
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    if unsafe { libc::getpid() } == 1 {
        ensure_proc_mounted();
        ensure_dir_mode("/tmp", 0o1777);
    }
}

fn ensure_proc_mounted() {
    if Path::new("/proc/self/stat").exists() {
        return;
    }
    ensure_dir_mode("/proc", 0o555);
    let source: &CStr = c"proc";
    let target: &CStr = c"/proc";
    let fstype: &CStr = c"proc";
    let flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;
    unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            ptr::null(),
        );
    }
}

fn ensure_dir_mode(path: &str, mode: u32) {
    if !Path::new(path).exists() {
        let _ = std::fs::create_dir_all(path);
    }
    if let Ok(c_path) = std::ffi::CString::new(path) {
        unsafe {
            libc::chmod(c_path.as_ptr(), mode as libc::mode_t);
        }
    }
}

/// Reap any terminated child/grandchild processes without blocking.
pub fn reap_zombies() {
    loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::wait4(-1, &mut status, libc::WNOHANG, ptr::null_mut()) };
        if pid > 0 {
            continue;
        }
        if pid == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
}
