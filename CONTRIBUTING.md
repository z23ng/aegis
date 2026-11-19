# Contributing to Aegis (`aegis`)

Thank you for contributing to **Aegis**! Before opening a pull request, please review our architectural invariants and development workflow.

---

## 1. Architectural Invariants (Must Not Break)

1. **Zero-Trust Credential Boundary**: Real secrets/tokens must remain strictly inside host memory (`sbx-net::SecretVault` / `sbx-daemon`). Sandboxes only receive placeholders, replaced in outbound HTTP headers after target domain verification.
2. **Zero `runc` on the Hot Path**: All command executions (`OP_EXEC_REQ`) and stateful REPL evaluations (`OP_REPL_EXEC`) must execute through the resident PID 1 `sbx-guest-agent` over binary `postcard` frames and `clone3`.
3. **Minimal Static `sbx-guest-agent`**: `crates/sbx-guest-agent` must remain dependency-light (only `libc` and `no_std` `sbx-proto` — **never** add `tokio`, `regex`, `serde_json`, or OpenSSL) and stay **< 1.5 MiB** (target **< 1 MiB**) when compiled for `x86_64-unknown-linux-musl`.
4. **Lease & Reaper Hygiene**: Every `containerd` snapshot, cgroup directory, network namespace/socket, and warm pool slot must be tied to a sandbox ID and lease/TTL so crashed runs are reaped idempotently.
5. **No Agent Memory Coupling**: Keep Aegis strictly focused on compute isolation, lifecycle scheduling, controlled egress, secret injection, and filesystem/memory snapshots.

---

## 2. Crate Layering

```text
sbx-cli / sbx-mcp / sbx-shim
         │
     sbx-daemon
      /      \
sbx-runtime  sbx-containerd
   /   \         │
sbx-net  sbx-guest-agent
      \      /
      sbx-proto (no_std, zero internal dependencies)
```

---

## 3. Development & Verification Commands

```bash
# 1. Verify no_std protocol crate
cargo check --no-default-features -p sbx-proto

# 2. Build static musl Guest Agent and check binary size (< 1 MiB)
cargo build --release --target x86_64-unknown-linux-musl -p sbx-guest-agent
ls -lh target/x86_64-unknown-linux-musl/release/sbx-guest-agent

# 3. Build entire workspace & run all tests
cargo build --release --workspace
cargo test --workspace

# 4. Verify host health & SDK syntax
./target/release/sbx doctor
python3 -m py_compile sdks/python/sbx_client.py
bash -n deploy/kernel/build-kernel-initramfs.sh
```
