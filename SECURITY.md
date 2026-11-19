# Security Policy (`Aegis`)

## 1. Threat Model & Security Guarantees

**Aegis (`sbx`)** is designed to execute untrusted, LLM-generated, or prompt-injection-compromised code while protecting host confidentiality, integrity, and availability.

### Core Security Boundaries

1. **Compute & Syscall Isolation (`sbx-runtime`)**
   - **Native Mode**: Linux `clone3` namespaces (`CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWIPC`, `CLONE_NEWUTS`, `CLONE_NEWNET`, and `CLONE_NEWUSER` when rootless), `pivot_root` rootfs isolation, `cgroup v2` hard quotas (`cpu.max`, `memory.max`, `pids.max`), Classic **Seccomp-BPF** syscall filtering (`EPERM` on `ptrace`, `mount`, `umount2`, `pivot_root`, `bpf`, `keyctl`, `add_key`, `request_key`, `io_uring_*`, `kexec_*`, `reboot`, `*_module`, etc.), and **Landlock LSM** + read-only bind-remount enforcement restricting writes to `/workspace` and `/tmp`.
   - **gVisor Mode (`--backend gvisor`)**: User-space kernel syscall interception via `runsc` for hostile multi-tenant workloads without nested KVM.
   - **MicroVM Mode (`--backend microvm`)**: Hardware-virtualized KVM isolation (Firecracker / QEMU) booting a minimal ~10MB Linux kernel + static `sbx-guest-agent` initramfs over `AF_VSOCK`.

2. **Zero-Trust Network Boundary (`sbx-net`)**
   - **Default Deny**: Sandboxes default to `NetworkPolicy::Disabled` (`CLONE_NEWNET` with loopback `lo` only).
   - **Allowlist Egress Proxy**: In `AllowlistProxy` mode, sandbox traffic routes exclusively through an in-namespace loopback listener handed off via `SCM_RIGHTS` to the host `EgressProxy`.
   - **SSRF / Metadata / Rebinding Defense**: Blocks cloud metadata (`169.254.0.0/16`, including `169.254.169.254`), host loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`), IPv6 ULA (`fc00::/7`), and TLS `ClientHello` SNI spoofing.

3. **Zero-Trust Credential Isolation (`SecretVault` + `SecretRule`)**
   - Real API keys and tokens never enter sandbox environment variables, memory, or OverlayFS layers.
   - Only placeholder tokens (e.g., `sbx_placeholder_gh_1`) exist inside the sandbox; the host proxy replaces placeholders **only** in outbound HTTP headers bound to explicitly allowlisted target hosts.

---

## 2. Degraded Execution Notice

When `sbx` is invoked inside a nested container or outer sandbox that blocks `SYS_clone3` namespace creation (`ENOSYS`/`EPERM`) or lacks `/dev/kvm` / `runsc`, `sbx` logs an explicit `WARN` diagnostic and falls back gracefully (preserving Seccomp-BPF and Egress Proxy boundaries where permitted). Production multi-tenant deployments must run directly on a Linux host with namespaces, `cgroup v2`, Landlock LSM (or `gvisor` / `microvm`), and `sbx doctor` verification.

---

## 3. Reporting a Vulnerability

Please **do not** open public GitHub issues for suspected sandbox escapes, privilege escalation, or secret-leakage vulnerabilities.

- Use **GitHub Private Vulnerability Reporting** (`Security -> Advisories -> Report a vulnerability`) on `https://github.com/z23ng/aegis`, or email `xk@kxkxmer.com`.
- Include reproduction steps, kernel version (`uname -a`), `sbx doctor` output, and the isolation backend used (`native` / `gvisor` / `microvm`).
