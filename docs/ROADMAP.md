# AI Sandbox (`sbx`) 开发路线图与里程碑

本项目采用**“先跑通极简核心执行链路，再加固受控安全边界，最后接入完整 containerd Shim v2 与 MicroVM”**的渐进式演进策略，确保每个阶段都有可运行、可测量的工程交付物。

---

## Milestone 1: 核心执行原型与 containerd 对接（Core Prototype）

**阶段目标**：跑通 Rust Workspace，打通从 `containerd` 拉取镜像与准备 OverlayFS 到拉起极简 `sbx-guest-agent` 执行命令的完整链路。

### 核心任务
- [x] **1.1 初始化 Rust Workspace**
  - 建立 `Cargo.toml` Workspace 结构，配置 `sbx-proto`、`sbx-containerd`、`sbx-runtime`、`sbx-guest-agent`、`sbx-cli`。
  - 配置交叉编译链，确保 `sbx-guest-agent` 可编译出独立的 `musl` 静态二进制且体积 < 1.5MB。
- [x] **1.2 `sbx-containerd` 镜像与快照基础适配**
  - 通过 `containerd-client` 连接宿主机 `/run/containerd/containerd.sock`。
  - 实现 `pull_image(ref)`、`create_lease()` 及基于 OverlayFS 的 `prepare_rootfs(sandbox_id, image_ref)`。
- [x] **1.3 `sbx-guest-agent` PID 1 与极速通信循环**
  - 实现帧头 + `postcard` 的 `vsock` / Unix Socket 通信协议。
  - 实现 `clone3` 进程派生、流式 `stdout`/`stderr` 回传、退出码上报及僵尸进程回收。
- [x] **1.4 Native 隔离原型（Namespaces + cgroup v2）**
  - 在 `sbx-runtime` 实现独立 Mount/PID/IPC/UTS/User Namespaces、`pivot_root` 切换至 containerd 准备好的 Rootfs，并挂载 `cgroup v2` 限制 CPU/内存/PIDs。
  - 通过 `sbx run alpine -- echo hello` 完成首次端到端跑通。

### 验收标准（Exit Criteria）
1. 能够直接使用标准 OCI 镜像（如 `python:3.12-slim`）拉起沙箱并执行任意命令。
2. 沙箱进程启动至首次 `OP_EXEC` 响应的延迟（本地已缓存镜像）**< 20ms**；单沙箱内部后续 `clone3` 派生执行延迟 **< 5ms**。
3. 沙箱退出后无残留僵尸进程、无残留 `cgroup` 或泄漏挂载点。

---

## Milestone 2: 严格受控环境与零信任网络（Security & Controlled Env）

**阶段目标**：补齐 AI 场景最关键的防逃逸、防内网探测与防 API Key 泄露能力。

### 核心任务
- [x] **2.1 Seccomp-BPF 与 Landlock 纵深防护**
  - 在 `sbx-runtime` 集成 Seccomp-BPF，制定面向 AI 代码执行场景的严格系统调用策略（拦截 `ptrace`、`mount`、`bpf`、`keyctl`、`io_uring` 等高危系统调用）。
  - 集成 Linux **Landlock LSM**（支持内核版本探测与降级），限制沙箱内进程仅能修改授权目录（如 `/workspace`、`/tmp`），其余系统路径只读。
- [x] **2.2 `sbx-net` 独立网络命名空间与出网防火墙**
  - 实现 `NetMode::Disabled`（纯 loopback，完全断网）与 `NetMode::AllowlistProxy`。
  - 构建宿主机端 `egress_proxy`，屏蔽所有 RFC1918 内网段、`127.0.0.0/8` 宿主机服务及 `169.254.169.254` 云元数据接口。
  - 实现 DNS 查询拦截与 TLS SNI 域名白名单校验。
- [x] **2.3 Zero-Trust Secret Injector**
  - 实现沙箱环境变量占位符自动注入，以及宿主机代理侧在转发 HTTPS 请求时校验域名绑定关系并动态替换为真实 Token 的机制。

### 验收标准（Exit Criteria）
1. 沙箱内部无法读取宿主机敏感文件、无法扫描宿主机局域网或元数据 IP、无法触发 Fork 炸弹打垮宿主机。
2. 沙箱内部执行 `env` 或打印环境变量只能看到占位符字符串；仅当向绑定域名发送请求时，外部真实服务端能收到有效鉴权 Header。
3. 未列入白名单的外网域名连接请求在宿主机层被 100% 拦截并返回明确策略错误。

---

## Milestone 3: Shim v2 标准化、Warm Pool 与状态时间旅行（Lifecycle & Snapshots）

**阶段目标**：将沙箱封装为标准 `containerd-shim-sbx-v2`，并落地预热池、步骤级文件系统回滚及 CoW 分叉能力。

### 核心任务
- [x] **3.1 实现 `containerd-shim-sbx-v2`**
  - 实现 containerd Runtime v2 `TaskService` (`ttrpc`) 协议，支持通过 `ctr` 或标准 CRI 调用。
- [x] **3.2 `sbx-daemon` 与 Warm Pool 调度**
  - 实现常驻守护进程，支持基于策略模板维持热沙箱池（Pre-warmed Pool），实现 **< 5ms 领取可用沙箱**。
  - 实现空闲检测、TTL 自动回收与一键重置复用。
- [x] **3.3 步骤级快照（Snapshot）、Diff 与回滚（Rollback / Fork）**
  - 联动 `OP_FREEZE` / `OP_THAW` 与 `containerd` Snapshotter，实现毫秒级文件层提交与新层挂载。
  - 实现 `sbx diff <id>`（导出某次执行修改的文件列表与变更摘要）和 `sbx rollback <id> <snap>`。
  - 实现 `sbx fork <snap> -n 4`，瞬间基于同一快照分叉出多个并发子沙箱。
- [x] **3.4 内存级 Checkpoint / Restore 原型**
  - 集成 CRIU 与 REPL 状态持久化，实现运行中 Python 解释器状态的内存固化与百毫秒内热恢复。

### 验收标准（Exit Criteria）
1. `ctr run --runtime io.containerd.sbx.v2` 可正常创建并执行容器任务。
2. 从 Warm Pool 申请沙箱并开始执行 Python 命令的端到端耗时 **< 10ms**。
3. 支持在运行过程中打快照、执行破坏性命令后一键回滚恢复文件状态，以及从快照并发 Fork 出 10 个独立可写子沙箱。

---

## Milestone 4: MicroVM 强隔离后端、有状态 REPL 与 MCP 集成（MicroVM & AI Integration）

**阶段目标**：引入硬件级虚拟化隔离后端（参照 Kiri 休眠唤醒模型），并完善面向 AI Agent 的原生集成界面。

### 核心任务
- [x] **4.1 MicroVM Driver (`Firecracker / QEMU` + 极简内核)**
  - 构建 ~10MB 极简 Linux 内核配置/脚本与仅包含 `sbx-guest-agent` 的 initramfs，支持通过 `AF_VSOCK` 零分配通信。
  - 实现无请求超时自动休眠（Idle Sleep）与新请求到达时自动唤醒。
  - 同步接入 `gVisor (runsc)` Driver 作为无 KVM 宿主机环境下的强隔离备选方案。
- [x] **4.2 Stateful REPL Worker**
  - 在 `sbx-guest-agent` 中增加常驻 Python / Node / Shell REPL 通道支持，支持跨多次 `exec` 调用保持内存变量与导入模块。
- [x] **4.3 `sbx-mcp` 与客户端 SDK**
  - 实现 MCP Server（`stdio` / HTTP+SSE），暴露完整的沙箱操作工具。
  - 提供 Python 客户端 SDK (`sdks/python/sbx_client.py`) 与完整集成测试套件。

### 验收标准（Exit Criteria）
1. 单宿主机支持同一套控制面 API 无缝切换 `native`、`gvisor`、`microvm` 三种隔离等级。
2. MicroVM 空闲休眠后单实例宿主机内存占用 **< 25MB**，再次唤醒执行延迟 **< 200ms**。
3. 主流 Coding Agent（如 Claude Code / Cursor）可通过 `sbx-mcp` 直接调用沙箱完成代码执行、查看 Diff 并在报错时自主回滚快照。
