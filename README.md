# AI Sandbox (`sbx`)

基于 `containerd` 生态底座、吸收 `libracoder/kiri` 极简运行时理念构建的高性能、强受控 Rust AI 沙箱引擎与管理工具。

---

## 项目定位

传统的容器栈（`dockerd -> containerd -> containerd-shim -> runc`）在 AI Agent 场景下面临两个核心瓶颈：
1. **启动与调度链路过重**：每次执行任务都要拉起完整的 Go Shim 与 `runc` 进程，冷启动和进程派生延迟高，高密度并发下内存开销大。
2. **安全与状态能力与 AI 需求错配**：AI 代码执行既需要严格隔离与防凭证泄露（防止 Prompt Injection 拖库/外泄 Secret），又需要步骤级文件系统回滚、运行中分叉（Fork）以及持久化有状态 REPL。

**AI Sandbox (`sbx`)** 采用 **“控制面复用 `containerd` + 执行面自研 `Kiri` 级极简 Rust Shim & PID 1 Agent”** 的架构：
- **控制面 & 镜像生态**：复用 `containerd` 成熟的 OCI 镜像拉取、Content Store 去重与 OverlayFS/EroFS Snapshotter，兼容云原生与 K8s 生态。
- **执行面极简重构**：绕过笨重的逐容器 `runc` 调用，通过自定义 `containerd-shim-sbx-v2` 托管极速沙箱与 <1MB 静态编译的 Rust Guest Agent（PID 1），经由 `vsock` + `clone3` 实现毫秒级命令派生与挂起唤醒。

---

## 核心设计目标

### 1. 极速启停与分叉（Extreme Speed）
- **Warm Pool + `vsock` + `clone3`**：通过预热沙箱池、零拷贝 `vsock` 通信与底层 `clone3` 系统调用，实现 **~2.5ms 级别的进程执行与命令派生**。
- **MicroVM 自动休眠与唤醒**：针对空闲沙箱自动挂起（参考 Kiri 思路，内存常驻 ~15MB），请求到达时 ~150ms 内唤醒恢复。
- **状态快照与 CoW 分叉（Forking）**：支持内存 Checkpoint/Restore 与基于 Snapshotter 的毫秒级 Copy-on-Write 分叉，满足多路径 Agent 并行试错需求。

### 2. 严格受控环境（Strictly Controlled Environment）
- **纵深计算与文件隔离**：支持多隔离驱动切换——Linux 原生强受控沙箱（Namespaces + `cgroup v2` + Seccomp-BPF + Landlock LSM）、gVisor（`runsc`）及轻量级 MicroVM（KVM/Firecracker）。
- **零信任出口网关（Zero-Trust Egress Proxy）**：沙箱默认无直接外网访问权限，所有出站流量经过宿主机 `sbx-net-guard` 代理：
  - 基于 DNS 与 TLS SNI 的域名白名单控制。
  - **宿主机侧 Secret 动态注入**：沙箱内部仅持有占位符凭证，真实 API Key/Token 由宿主机网关在出站转发时注入 HTTP Header，确保敏感凭证永不进入沙箱磁盘、内存或环境变量。

### 3. 云原生生态兼容（Cloud-Native Compatibility）
- 原生集成 `containerd` gRPC API（基于 `containerd-client`），直接消费标准 Docker/OCI 镜像。
- 提供符合标准规范的 `containerd-shim-sbx-v2`，既可作为独立 CLI/Daemon 工具运行，也可无缝接入 Kubernetes / containerd 基础设施。

---

## 文档导航

| 文档 | 说明 |
| :--- | :--- |
| [系统架构设计 (docs/ARCHITECTURE.md)](./docs/ARCHITECTURE.md) | 总体分层架构、核心组件职责、关键时序图、数据模型与 `vsock` 帧协议设计 |
| [目录结构与模块规划 (docs/DIRECTORY_STRUCTURE.md)](./docs/DIRECTORY_STRUCTURE.md) | Rust Cargo Workspace 规划、各 Crate 职责边界及核心 Trait/Struct 签名 |
| [开发路线图与里程碑 (docs/ROADMAP.md)](./docs/ROADMAP.md) | M1 至 M4 阶段拆分、工程任务清单与可量化验收标准 |
| [Agent 开发协作指南 (AGENTS.md)](./AGENTS.md) | 供新开 AI 开发 Session 快速接手的架构不变量、技术栈约束与起步指引 |
