#!/usr/bin/env bash
set -euo pipefail

# Build minimal initramfs packing static musl `sbx-guest-agent` as `/init`
# and optionally build the ~10MB MicroVM Linux kernel using `deploy/kernel/microvm-kernel.config`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SBX_KERNEL_OUT:-${REPO_ROOT}/target/microvm}"
AGENT_BIN="${SBX_GUEST_AGENT_BIN:-${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/sbx-guest-agent}"

mkdir -p "${OUT_DIR}"

if [[ ! -x "${AGENT_BIN}" ]]; then
  echo "[sbx] Building static musl sbx-guest-agent..."
  cargo build --offline --release --target x86_64-unknown-linux-musl -p sbx-guest-agent --manifest-path "${REPO_ROOT}/Cargo.toml"
fi

INITRAMFS_DIR="$(mktemp -d)"
trap 'rm -rf "${INITRAMFS_DIR}"' EXIT
mkdir -p "${INITRAMFS_DIR}"/{dev,proc,sys,tmp,workspace,run}
cp "${AGENT_BIN}" "${INITRAMFS_DIR}/init"
chmod 0755 "${INITRAMFS_DIR}/init"

(cd "${INITRAMFS_DIR}" && find . -print0 | cpio --null -ov --format=newc > "${OUT_DIR}/initramfs.cpio" 2>/dev/null)
echo "[sbx] Built minimal initramfs: ${OUT_DIR}/initramfs.cpio ($(du -h "${OUT_DIR}/initramfs.cpio" | cut -f1))"

if [[ -n "${LINUX_SRC_DIR:-}" && -d "${LINUX_SRC_DIR}" ]]; then
  echo "[sbx] Building minimal ~10MB vmlinux from ${LINUX_SRC_DIR}..."
  cp "${SCRIPT_DIR}/microvm-kernel.config" "${LINUX_SRC_DIR}/.config"
  make -C "${LINUX_SRC_DIR}" olddefconfig
  make -C "${LINUX_SRC_DIR}" -j"$(nproc)" vmlinux bzImage
  cp "${LINUX_SRC_DIR}/vmlinux" "${OUT_DIR}/vmlinux"
  cp "${LINUX_SRC_DIR}/arch/x86/boot/bzImage" "${OUT_DIR}/bzImage"
  echo "[sbx] Kernel ready: ${OUT_DIR}/vmlinux"
else
  echo "[sbx] Tip: pass LINUX_SRC_DIR=/path/to/linux-6.x to compile vmlinux (~10MB)."
fi
