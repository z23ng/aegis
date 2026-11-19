use std::io;

use anyhow::Result;
use sbx_proto::SeccompMode;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[cfg(target_arch = "x86_64")]
const EXPECTED_AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const EXPECTED_AUDIT_ARCH: u32 = 0xC000_00B7;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *const SockFilter,
}

#[inline]
const fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[inline]
const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Return the list of blocked syscall numbers for the requested `SeccompMode`.
pub fn blocked_syscalls(mode: SeccompMode) -> Vec<u32> {
    let mut blocked = vec![
        libc::SYS_ptrace as u32,
        libc::SYS_mount as u32,
        libc::SYS_umount2 as u32,
        libc::SYS_pivot_root as u32,
        libc::SYS_bpf as u32,
        libc::SYS_keyctl as u32,
        libc::SYS_add_key as u32,
        libc::SYS_request_key as u32,
        425, // io_uring_setup
        426, // io_uring_enter
        427, // io_uring_register
        libc::SYS_kexec_load as u32,
        libc::SYS_kexec_file_load as u32,
        libc::SYS_reboot as u32,
        libc::SYS_init_module as u32,
        libc::SYS_finit_module as u32,
        libc::SYS_delete_module as u32,
        libc::SYS_acct as u32,
        libc::SYS_swapon as u32,
        libc::SYS_swapoff as u32,
        libc::SYS_open_by_handle_at as u32,
        libc::SYS_perf_event_open as u32,
        libc::SYS_userfaultfd as u32,
        libc::SYS_quotactl as u32,
        libc::SYS_syslog as u32,
        libc::SYS_process_vm_readv as u32,
        libc::SYS_process_vm_writev as u32,
    ];

    if matches!(mode, SeccompMode::Strict) {
        blocked.extend_from_slice(&[
            libc::SYS_unshare as u32,
            libc::SYS_setns as u32,
            libc::SYS_chroot as u32,
            libc::SYS_sethostname as u32,
            libc::SYS_mknodat as u32,
        ]);
        #[cfg(target_arch = "x86_64")]
        blocked.push(libc::SYS_mknod as u32);
    }

    blocked
}

/// Build a Classic BPF Seccomp filter blocking dangerous syscalls with `EPERM`.
pub fn build_seccomp_bpf(mode: SeccompMode) -> Vec<SockFilter> {
    let blocked = blocked_syscalls(mode);
    // Filter layout:
    // 0: ld [4] (arch)
    // 1: jeq EXPECTED_AUDIT_ARCH -> jt=1, jf=0
    // 2: ret KILL_PROCESS
    // 3: ld [0] (nr)
    // 4 (x86_64): jset X32_SYSCALL_BIT -> jt -> deny, jf=0
    // ... blocked checks: jeq sys_nr -> jt -> deny, jf=0
    // allow: ret ALLOW
    // deny: ret ERRNO | EPERM
    let mut prog = Vec::with_capacity(blocked.len() + 10);

    // Verify architecture
    prog.push(bpf_stmt(BPF_LD_W_ABS, 4));
    prog.push(bpf_jump(BPF_JMP_JEQ_K, EXPECTED_AUDIT_ARCH, 1, 0));
    prog.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));

    // Load syscall number
    prog.push(bpf_stmt(BPF_LD_W_ABS, 0));

    let has_x32_check = cfg!(target_arch = "x86_64");
    let total_checks = blocked.len() + usize::from(has_x32_check);

    if has_x32_check {
        let remaining_to_deny = total_checks as u8; // lands on deny instruction after allow
        prog.push(bpf_jump(BPF_JMP_JSET_K, X32_SYSCALL_BIT, remaining_to_deny, 0));
    }

    for (idx, &nr) in blocked.iter().enumerate() {
        let remaining = (blocked.len() - idx) as u8;
        prog.push(bpf_jump(BPF_JMP_JEQ_K, nr, remaining, 0));
    }

    // Allow
    prog.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    // Deny with EPERM
    prog.push(bpf_stmt(
        BPF_RET_K,
        SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xFFFF),
    ));

    prog
}

/// Apply `PR_SET_NO_NEW_PRIVS` and install the Seccomp-BPF filter on the calling thread/process.
/// Safe to invoke inside `clone3` child right before `execve` (uses pre-built slice, zero locks).
pub unsafe fn install_prebuilt_seccomp(filter: &[SockFilter]) -> io::Result<()> {
    if filter.is_empty() {
        return Ok(());
    }
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return Err(io::Error::last_os_error());
    }

    let prog = SockFprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr(),
    };

    let rc = libc::syscall(
        libc::SYS_seccomp,
        SECCOMP_SET_MODE_FILTER,
        0 as libc::c_ulong,
        &prog as *const SockFprog,
    );
    if rc == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOSYS) {
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &prog as *const SockFprog,
        ) == 0
        {
            return Ok(());
        }
        return Err(io::Error::last_os_error());
    }

    Err(err)
}

/// Convenience wrapper for building and installing Seccomp-BPF on the current process.
pub fn install_seccomp_filter(mode: SeccompMode) -> Result<()> {
    let filter = build_seccomp_bpf(mode);
    unsafe { install_prebuilt_seccomp(&filter) }?;
    Ok(())
}

/// Opaque pre-built filter handle usable across `clone3` without allocating in child.
pub struct PreparedSeccomp {
    filter: Vec<SockFilter>,
}

impl PreparedSeccomp {
    pub fn new(mode: SeccompMode) -> Self {
        Self {
            filter: build_seccomp_bpf(mode),
        }
    }

    /// # Safety
    /// Must only be called in single-threaded / pre-execve child context.
    pub unsafe fn install(&self) -> io::Result<()> {
        install_prebuilt_seccomp(&self.filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_blocks_forbidden_syscalls_with_eperm_and_allows_normal_syscalls() {
        let prepared = PreparedSeccomp::new(SeccompMode::Strict);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            unsafe {
                if prepared.install().is_err() {
                    libc::_exit(20);
                }
                // Normal syscall must continue to succeed
                if libc::getpid() <= 0 {
                    libc::_exit(21);
                }
                // Blocked syscall: ptrace must return -1 with EPERM
                let rc_ptrace = libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0);
                if rc_ptrace != -1 || *libc::__errno_location() != libc::EPERM {
                    libc::_exit(22);
                }
                // Blocked syscall: bpf must return -1 with EPERM
                let rc_bpf = libc::syscall(libc::SYS_bpf, 0, 0, 0);
                if rc_bpf != -1 || *libc::__errno_location() != libc::EPERM {
                    libc::_exit(23);
                }
                // Blocked syscall: mount must return -1 with EPERM
                let rc_mount = libc::syscall(libc::SYS_mount, 0, 0, 0, 0, 0);
                if rc_mount != -1 || *libc::__errno_location() != libc::EPERM {
                    libc::_exit(24);
                }
                // Strict-only syscall: unshare must return -1 with EPERM
                let rc_unshare = libc::syscall(libc::SYS_unshare, 0);
                if rc_unshare != -1 || *libc::__errno_location() != libc::EPERM {
                    libc::_exit(25);
                }
                libc::_exit(0);
            }
        }

        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(rc, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child exited with status={status:#x} code={}",
            libc::WEXITSTATUS(status)
        );
    }
}
