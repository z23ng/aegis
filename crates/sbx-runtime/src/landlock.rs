use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::path::Path;
use std::ptr;

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

const ABI1_ALL_FS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

const READ_EXEC_FS: u64 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Probe the running Linux kernel's Landlock ABI version (returns `None` if unavailable/disabled).
pub fn landlock_abi_version() -> Option<i32> {
    let ver = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ver >= 1 {
        Some(ver as i32)
    } else {
        None
    }
}

/// Pre-allocated Landlock configuration ready to apply inside a `clone3` child before `execve`.
pub struct PreparedLandlock {
    read_only_root: CString,
    writable_paths: Vec<CString>,
    ro_protect_dirs: Vec<CString>,
}

impl PreparedLandlock {
    /// Build pre-allocated `CString` path lists from `writable_paths` (`policy.writable_paths`).
    pub fn new(writable_paths: &[String], enforce_ro_system_dirs: bool) -> Self {
        let mut rw = vec![
            CString::new("/dev").unwrap(),
            CString::new("/proc").unwrap(),
            CString::new("/tmp").unwrap(),
            CString::new("/workspace").unwrap(),
        ];
        for p in writable_paths {
            let trimmed = p.trim();
            if !trimmed.is_empty() {
                if let Ok(cs) = CString::new(trimmed) {
                    if !rw.iter().any(|existing| existing == &cs) {
                        rw.push(cs);
                    }
                }
            }
        }

        let mut ro_protect_dirs = Vec::new();
        if enforce_ro_system_dirs {
            for sys_dir in ["/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64"] {
                let c_sys = CString::new(sys_dir).unwrap();
                let overridden_rw = writable_paths
                    .iter()
                    .any(|p| p.trim() == "/" || p.trim() == sys_dir);
                if !overridden_rw {
                    ro_protect_dirs.push(c_sys);
                }
            }
        }

        Self {
            read_only_root: CString::new("/").unwrap(),
            writable_paths: rw,
            ro_protect_dirs,
        }
    }

    /// Apply read-only system directory bind remounts + Landlock LSM rules inside the sandbox rootfs.
    /// Degrades gracefully if Landlock is disabled in the host kernel (`ENOSYS`/`EOPNOTSUPP`).
    ///
    /// # Safety
    /// Must only be invoked inside the isolated sandbox child after `pivot_root`.
    pub unsafe fn apply_in_child(&self) {
        // Ensure /workspace exists before enforcing read-only protections.
        let ws = c"/workspace";
        libc::mkdir(ws.as_ptr(), 0o777);
        libc::chmod(ws.as_ptr(), 0o1777);

        // 1. Mount-level read-only enforcement on immutable system directories so protection
        //    holds even if the kernel was booted without `lsm=landlock`.
        for dir in &self.ro_protect_dirs {
            let mut st: libc::stat = mem::zeroed();
            if libc::lstat(dir.as_ptr(), &mut st) != 0 {
                continue;
            }
            // Only bind-remount real directories (skip symlinks like /bin -> /usr/bin).
            if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                continue;
            }
            if libc::mount(
                dir.as_ptr(),
                dir.as_ptr(),
                ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                ptr::null(),
            ) == 0
            {
                let _ = libc::mount(
                    ptr::null(),
                    dir.as_ptr(),
                    ptr::null(),
                    libc::MS_BIND | libc::MS_REC | libc::MS_REMOUNT | libc::MS_RDONLY,
                    ptr::null(),
                );
            }
        }

        // 2. Kernel Landlock LSM path-beneath ruleset (if kernel supports Landlock).
        let _ = apply_landlock_rules(&self.read_only_root, &self.writable_paths);
    }
}

/// Apply Landlock path restrictions in the current process for a custom `read_root` + `rw_paths`.
/// Returns `Ok(true)` if Landlock was enforced, `Ok(false)` if kernel does not support Landlock.
pub fn apply_landlock_for_paths(read_root: &Path, rw_paths: &[&Path]) -> io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let c_root = CString::new(read_root.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in read_root"))?;
    let mut c_rw = Vec::with_capacity(rw_paths.len());
    for p in rw_paths {
        c_rw.push(
            CString::new(p.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in rw_path"))?,
        );
    }
    unsafe { apply_landlock_rules(&c_root, &c_rw) }
}

unsafe fn apply_landlock_rules(read_root: &CString, rw_paths: &[CString]) -> io::Result<bool> {
    let Some(abi) = landlock_abi_version() else {
        return Ok(false);
    };

    let mut handled_fs = ABI1_ALL_FS;
    if abi >= 2 {
        handled_fs |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        handled_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs,
    };
    let ruleset_fd = libc::syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        &attr as *const LandlockRulesetAttr,
        mem::size_of::<LandlockRulesetAttr>(),
        0u32,
    ) as RawFd;
    if ruleset_fd < 0 {
        let err = io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
        ) {
            return Ok(false);
        }
        return Err(err);
    }

    let add_res: io::Result<()> = (|| {
        add_path_rule(ruleset_fd, read_root, READ_EXEC_FS & handled_fs)?;
        for p in rw_paths {
            let _ = add_path_rule(ruleset_fd, p, handled_fs);
        }

        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();

    libc::close(ruleset_fd);
    add_res?;
    Ok(true)
}

unsafe fn add_path_rule(ruleset_fd: RawFd, path: &CString, allowed_access: u64) -> io::Result<()> {
    let fd = libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let rule = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: fd,
    };
    let rc = libc::syscall(
        SYS_LANDLOCK_ADD_RULE,
        ruleset_fd,
        LANDLOCK_RULE_PATH_BENEATH,
        &rule as *const LandlockPathBeneathAttr,
        0u32,
    );
    let err = io::Error::last_os_error();
    libc::close(fd);
    if rc != 0 {
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn landlock_probe_and_graceful_fallback_works() {
        // Must never panic regardless of whether host kernel enabled Landlock LSM.
        let abi = landlock_abi_version();
        let prep = PreparedLandlock::new(&[String::from("/workspace")], true);
        assert!(prep.writable_paths.iter().any(|p| p.as_bytes() == b"/tmp"));
        assert!(prep.writable_paths.iter().any(|p| p.as_bytes() == b"/workspace"));
        assert!(!prep.ro_protect_dirs.is_empty());

        if abi.is_some() {
            let tmp = std::env::temp_dir().join(format!("sbx-ll-test-{}", std::process::id()));
            let rw = tmp.join("rw");
            let ro = tmp.join("ro");
            let _ = fs::create_dir_all(&rw);
            let _ = fs::create_dir_all(&ro);

            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let applied = apply_landlock_for_paths(&tmp, &[rw.as_path()]).unwrap_or(false);
                if !applied {
                    unsafe { libc::_exit(0) };
                }
                let ok_rw = fs::write(rw.join("ok.txt"), b"hello").is_ok();
                let denied_ro = fs::write(ro.join("blocked.txt"), b"nope").is_err();
                unsafe { libc::_exit(if ok_rw && denied_ro { 0 } else { 1 }) };
            }
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            let _ = fs::remove_dir_all(&tmp);
            assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        }
    }
}
