# AGENTS.md — AI Sandbox (`sbx`) 开发协作指南

本目录是 **AI Sandbox (`sbx`)** 独立项目的开发工作区。请在后续所有开发工作中严格遵循本文档的架构边界、技术选型与工程不变量。

---

## 1. 项目定位与边界

- **一句话定位**：基于 `containerd` 镜像与快照底座、借鉴 `libracoder/kiri` 极简运行时理念构建的 **Rust 高性能、强受控 AI 沙箱引擎**。
- **独立性原则**：本项目专注于**计算隔离、生命周期调度、受控网络出口、凭证注入与文件/内存快照**。**不要**在此仓库中耦合任何 Agent Memory（向量检索、对话记忆、记忆图谱）逻辑。

---

## 2. 强制技术栈选型

| 层级 | 选型 | 说明 |
| :--- | :--- | :--- |
| **核心语言** | Rust (Edition 2021/2024) | 统一采用 Cargo Workspace 管理所有 crate |
| **异步运行时** | `tokio` | 仅用于宿主机控制面 (`sbx-daemon`, `sbx-net`, `sbx-mcp`)；Guest Agent 优先使用轻量级事件循环 (`mio` / 同步 epoll) 以极致压缩体积 |
| **containerd 对接** | `containerd-client` + `tonic` | 通过标准 gRPC API 对接宿主机 `containerd.sock` |
| **Linux 底层系统调用** | `rustix` / `nix` + `libc` | 直接操作 `clone3`、`unshare`、`pivot_root`、`prctl`、`cgroup v2`、`AF_VSOCK` |
| **安全隔离组件** | `seccompiler` + `landlock` | 构造 Seccomp-BPF 过滤规则与 Landlock LSM 目录访问控制 |
| **序列化协议** | `postcard` (Host <-> Guest) / `prost` (gRPC) | `vsock` 热路径禁用 JSON 序列化 |
| **Guest 编译目标** | `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl` | `sbx-guest-agent` 必须静态链接，零外部 `.so` 依赖 |

---

## 3. 核心架构不变量（Invariants）

1. **绝不绕过隔离边界投递敏感凭证**：真实 API Keys / Tokens 永远只能存在于宿主机 `sbx-daemon` / `sbx-net` 内存中，沙箱内部只能获得占位符，通过出站代理在域名白名单校验通过后替换。
2. **禁止在热路径上每次调用外部 `runc` 进程**：单次 `exec` 必须经由常驻的 `sbx-guest-agent`（PID 1）直接通过 `clone3` 完成派生，保证毫秒级延迟。
3. **Guest Agent 保持极简与零动态依赖**：`crates/sbx-guest-agent` 不允许引入 `tokio` 全家桶、正则重型库或 OpenSSL 等动态链接库，二进制体积目标始终保持在 **< 1.5MB**（理想 < 1MB）。
4. **所有资源绑定 Lease 与 Reaper**：向 `containerd` 申请的 Snapshot、创建的 NetNS / veth、cgroup 目录必须关联沙箱 ID 与 TTL，进程异常崩溃退出时控制面启动自检必须能幂等清理残留资源。

---

## 4. 新会话起步指令

当你在本目录下开启开发时，请按以下顺序推进（参考 [docs/ROADMAP.md](./docs/ROADMAP.md)）：

1. 先阅读 [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) 与 [docs/DIRECTORY_STRUCTURE.md](./docs/DIRECTORY_STRUCTURE.md) 确认接口与目录结构。
2. 检查本地环境前置依赖：`rustc --version`、`cargo --version`、`containerd --version`、内核版本（确认 `cgroup v2`、`clone3`、Landlock 与 KVM/vsock 可用性）。
3. 从 **Milestone 1** 开始：
   - 初始化根目录 `Cargo.toml` Workspace。
   - 先实现 `crates/sbx-proto`（`vsock` 帧协议）与 `crates/sbx-guest-agent`（最小化 PID 1 + 进程派生）。
   - 再实现 `crates/sbx-containerd`（连接本地 `containerd.sock` 拉取镜像与准备 OverlayFS Rootfs）与 `crates/sbx-runtime`（Native Namespaces + `cgroup v2` 驱动）。
   - 用 `sbx-cli` 跑通第一条端到端命令执行与毫秒级耗时基准测试。
