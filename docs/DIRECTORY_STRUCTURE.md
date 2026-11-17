# AI Sandbox (`sbx`) 目录结构与核心模块规划

本项目采用单一 **Rust Cargo Workspace** 组织所有组件，统一共享协议定义与核心类型，同时保证 `sbx-guest-agent` 能够独立交叉编译为静态 `musl` 极简二进制。

---

## 1. Cargo Workspace 目录树

```text
ai-sandbox/
├── Cargo.toml                  # Workspace 定义、统一依赖版本与 release profile 优化 (LTO + strip)
├── Cargo.lock
├── rust-toolchain.toml         # 锁定 Rust 工具链与 musl 编译目标
├── AGENTS.md                   # AI 开发会话协作指南
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DIRECTORY_STRUCTURE.md
│   └── ROADMAP.md
├── deploy/
│   ├── systemd/
│   │   └── sbx-daemon.service  # 宿主机常驻服务配置
│   ├── config/
│   │   └── default-policy.toml # 默认 AI 沙箱安全策略（Seccomp/Landlock/Net）
│   └── kernel/                 # MicroVM 极简内核构建脚本与配置 (~10MB bzImage/vmlinux)
├── crates/
│   ├── sbx-proto/              # 协议层：vsock 二进制帧协议、gRPC/Protobuf 定义与错误码
│   ├── sbx-containerd/         # 底座适配层：containerd gRPC 封装（镜像、Lease、Snapshotter）
│   ├── sbx-runtime/            # 隔离执行层：多后端驱动抽象（Native clone3 / gVisor / MicroVM）
│   ├── sbx-guest-agent/        # 沙箱内 PID 1 Agent：极简 Rust 静态二进制（vsock + clone3 + REPL）
│   ├── sbx-shim/               # containerd-shim-sbx-v2 标准运行时垫片实现
│   ├── sbx-net/                # 网络与安全网关：NetNS 配置、DNS/SNI 白名单、Secret 注入代理
│   ├── sbx-daemon/             # 宿主机控制面：生命周期、Warm Pool 调度、快照与 Fork 编排
│   ├── sbx-cli/                # 命令行工具：sbx run / exec / snapshot / fork / rollback / policy
│   └── sbx-mcp/                # AI 集成层：Model Context Protocol Server
├── sdks/                       # 后续扩展的客户端 SDK（Python / TypeScript）
└── tests/
    ├── integration/            # 端到端沙箱生命周期、隔离逃逸检测、网络策略测试
    └── benchmarks/             # 冷/热启动延迟、clone3 派生耗时、并发密度压测
```

---

## 2. 各 Crate 核心职责与关键接口

### 2.1 `crates/sbx-proto`
- **职责**：全系统零环依赖的基础协议包，支持 `no_std`（供 `sbx-guest-agent` 使用）与 `std`（供控制面使用）。
- **包含内容**：
  - `VsockFrameHeader` 与编解码器（零堆分配解析）。
  - `GuestRequest` / `GuestResponse`（基于 `postcard` 序列化）。
  - `SandboxSpec`、`SecurityPolicy`、`SnapshotMeta`、`SandboxState` 核心结构体。
  - `proto/sbx.v1.proto`（control plane gRPC 服务定义）。

### 2.2 `crates/sbx-containerd`
- **职责**：封装 `containerd-client`（Tonic gRPC），屏蔽底层繁琐的 Namespace、Lease 和 Snapshotter 协议细节。
- **核心能力**：
  - 镜像解析与自动拉取（`Images` + `Transfer` / `Content` Service）。
  - 基于 `Lease` 的垃圾回收防误删保护。
  - Snapshot 生命周期操作：`prepare_rw_layer`、`commit_snapshot`、`fork_from_snapshot`、`diff_layers`、`remove_snapshot`。

### 2.3 `crates/sbx-runtime`
- **职责**：定义统一的隔离后端接口，屏蔽不同底层隔离机制的差异。
- **核心 Trait**：

```rust
#[async_trait]
pub trait IsolationBackend: Send + Sync {
    /// 启动隔离环境并在其中拉起 sbx-guest-agent，返回通信通道句柄
    async fn start(&self, cfg: &SandboxRuntimeConfig) -> Result<Box<dyn SandboxHandle>>;

    /// 休眠沙箱（MicroVM 内存挂起 / cgroup freezer）
    async fn sleep(&self, id: &SandboxId) -> Result<()>;

    /// 唤醒沙箱
    async fn wake(&self, id: &SandboxId) -> Result<()>;

    /// 内存级快照（若后端支持 CRIU / VM Snapshot）
    async fn checkpoint(&self, id: &SandboxId, dest: &Path) -> Result<()>;

    /// 从内存快照恢复
    async fn restore(&self, src: &Path, cfg: &SandboxRuntimeConfig) -> Result<Box<dyn SandboxHandle>>;

    /// 彻底销毁并清理 cgroups/namespaces/tap 设备
    async fn destroy(&self, id: &SandboxId) -> Result<()>;
}
```

- **内含后端实现**：
  - `native`：基于 `rustix` / `nix` 直接调度 Linux `clone3`、User/PID/Mount/Net/IPC/UTS Namespaces、`pivot_root`、`cgroup v2`、`seccompiler`（Seccomp-BPF）及 `landlock`。
  - `gvisor`：对接 `runsc` 命令行/API，适合不可信高危代码在普通云主机运行。
  - `microvm`：对接轻量级 VMM（`libkrun` 或自研极简 KVM 启动器 / Firecracker），加载定制内核与 initramfs/virtiofs。

### 2.4 `crates/sbx-guest-agent`
- **职责**：运行在沙箱内部作为 PID 1 的极简守护进程，直接决定单沙箱的内存底座与执行响应延迟。
- **编译策略**：
  - `Cargo.toml` 独立配置 `opt-level = "z"`、`lto = true`、`panic = "abort"`、`strip = true`。
  - 编译目标：`x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl`，目标体积 **< 1MB**。
- **核心模块**：
  - `init.rs`：PID 1 挂载基础伪文件系统（`/proc`, `/sys`, `/dev/pts`）、设置信号处理与僵尸进程自动收割循环（`waitpid(-1, WNOHANG)`）。
  - `transport.rs`：同时支持 `AF_VSOCK`（MicroVM 模式）与 `AF_UNIX`（Native Namespace 模式）的复用事件循环。
  - `spawner.rs`：直接调用 `clone3` / `execve` 派生业务进程，配置 `RLIMIT_*` 与非特权用户切换，支持流式管道输出。
  - `repl.rs`：长驻有状态语言执行器桥接（通过本地管道维持 Python/Node 上下文状态）。

### 2.5 `crates/sbx-shim`
- **职责**：输出二进制文件 `containerd-shim-sbx-v2`。
- **核心能力**：
  - 实现 containerd Shim v2 (`ttrpc`) 接口，使 `ctr run --runtime io.containerd.sbx.v2` 可直接工作。
  - 托管 Sandbox 实例的 `vsock` / Unix Socket 长连接，将 containerd `Create`/`Start`/`Exec`/`Kill`/`Delete` 映射至 `sbx-runtime` 与 `sbx-guest-agent`。

### 2.6 `crates/sbx-net`
- **职责**：构建沙箱的零信任网络边界。
- **核心模块**：
  - `netns.rs`：通过 Netlink 创建隔离 `veth` 对、配置独立网段与防火墙规则（禁止沙箱访问宿主机局域网与元数据 IP）。
  - `dns_guard.rs`：轻量内置 DNS 拦截器，仅响应白名单域名解析，并动态同步允许的 IP 列表。
  - `egress_proxy.rs`：支持 HTTP Proxy 与透明 TLS SNI 检查；内置 **Secret Vault Binding**，按目标域名匹配并替换请求头中的占位符为真实凭证。

### 2.7 `crates/sbx-daemon`
- **职责**：宿主机常驻控制面，面向 AI Agent 编排层提供高层次能力。
- **核心模块**：
  - `pool.rs`：Warm Pool 调度器，维护热池水位线（min/max warm count）与快速回收重置策略。
  - `snapshot_mgr.rs`：协调 Guest `OP_FREEZE` 与 `sbx-containerd` 的快照提交，提供 `diff` 列表导出与毫秒级 `fork` / `rollback`。
  - `reaper.rs`：TTL 到期自动清理与空闲检测触发 `sleep()`。
  - `server.rs`：gRPC 与 HTTP/JSON API 服务端。

### 2.8 `crates/sbx-cli` & `crates/sbx-mcp`
- **`sbx-cli`**：用户友好的命令行客户端，输出延迟统计、文件系统 Diff 视图与实时日志流。
- **`sbx-mcp`**：基于 MCP 协议将 `create_sandbox`、`exec_command`、`run_python`、`snapshot`、`rollback`、`fork_sandbox` 暴露给 Claude Code、Cursor 等 Agent 客户端。

---

## 3. 核心数据结构草案

```rust
/// 沙箱实例状态机
pub enum SandboxState {
    Creating,
    Warm,        // 已预热在池中待命
    Running,     // 正在被任务占用
    Sleeping,    // MicroVM 休眠态或 cgroup 冻结态
    Snapshotted, // 已固化为只读快照
    Destroyed,
}

/// 沙箱安全策略定义
pub struct SecurityPolicy {
    pub backend: BackendKind,            // Native | Gvisor | MicroVm
    pub cpu_cores: f32,
    pub memory_limit_mb: u64,
    pub pids_limit: u32,
    pub disk_quota_mb: u64,
    pub seccomp_mode: SeccompMode,       // Strict | Standard | Custom
    pub writable_paths: Vec<PathBuf>,    // Landlock 可写路径白名单
    pub network: NetworkPolicy,          // Disabled | AllowlistProxy
    pub secret_bindings: Vec<SecretRule>,
}

/// 零信任 Secret 注入规则
pub struct SecretRule {
    pub placeholder: String,             // 注入沙箱 env 的假值，如 "sbx_sec_xxx"
    pub allowed_hosts: Vec<String>,      // 仅允许发往这些域名时才进行替换
    pub secret_ref: String,              // 宿主机 Vault 中的密钥 ID
}
```
