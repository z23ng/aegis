# AI Sandbox (`sbx`) 系统架构设计

本文档描述 `ai-sandbox` 的分层架构、核心子系统职责、关键交互时序以及核心数据与通信协议模型。

---

## 1. 总体分层架构

`sbx` 将**云原生资源管理（containerd）**与**极速受控执行（Kiri 风格 Guest Agent + 安全网关）**清晰解耦：

```mermaid
flowchart TB
    subgraph Interface["接口接入层 (Interface Layer)"]
        CLI["sbx CLI"]
        API["gRPC / HTTP Control API"]
        MCP["sbx-mcp Server"]
    end

    subgraph Control["控制面 (Control Plane - sbx-daemon)"]
        Lifecycle["Sandbox Lifecycle Manager"]
        WarmPool["Warm Pool Scheduler"]
        PolicyMgr["Policy & Secret Manager"]
        CTRDAdapter["containerd Client Adapter"]
    end

    subgraph External["云原生底座 (containerd)"]
        CTRD["containerd Daemon"]
        ContentStore["Content Store / Images"]
        Snapshotter["OverlayFS / EroFS Snapshotter"]
    end

    subgraph Runtime["运行时与隔离层 (Runtime Plane - containerd-shim-sbx-v2)"]
        Shim["containerd-shim-sbx-v2"]
        NativeDrv["Fast Native Driver (clone3 / Seccomp / Landlock)"]
        GvisorDrv["gVisor Driver (runsc)"]
        MicroVMDrv["MicroVM Driver (10MB Kernel / KVM)"]
    end

    subgraph Guest["沙箱内部执行面 (Guest Plane)"]
        GuestAgent["sbx-guest-agent (PID 1 ~900KB Static Rust)"]
        REPL["Stateful REPL Worker (Python / Node)"]
        Workload["Isolated Child Processes"]
    end

    subgraph SecurityNet["安全与网络层 (sbx-net-guard)"]
        NetNS["Network Namespace / veth / tap"]
        EgressFilter["DNS & TLS SNI Allowlist Filter"]
        SecretProxy["Zero-Trust Secret Injector Proxy"]
    end

    subgraph Storage["存储快照层 (sbx-snapshot)"]
        StepSnap["Step-level CoW Snapshots"]
        DiffEngine["Filesystem Diff & Rollback"]
    end

    CLI --> Lifecycle
    API --> Lifecycle
    MCP --> Lifecycle

    Lifecycle --> WarmPool
    Lifecycle --> PolicyMgr
    Lifecycle --> CTRDAdapter
    Lifecycle --> Shim

    CTRDAdapter --> CTRD
    CTRD --> ContentStore
    CTRD --> Snapshotter
    Snapshotter --> StepSnap
    StepSnap --> DiffEngine

    Shim --> NativeDrv
    Shim --> GvisorDrv
    Shim --> MicroVMDrv

    Shim <-->|"Zero-Alloc vsock / Unix Socket"| GuestAgent
    GuestAgent --> REPL
    GuestAgent --> Workload

    PolicyMgr --> EgressFilter
    PolicyMgr --> SecretProxy
    NativeDrv --> NetNS
    MicroVMDrv --> NetNS
    NetNS --> EgressFilter
    EgressFilter --> SecretProxy
```

---

## 2. 核心平面与模块职责

### 2.1 接口接入层（Interface Layer）
- **`sbx` CLI (`sbx-cli`)**：面向开发者与运维人员的命令行工具，提供 `run`、`exec`、`fork`、`snapshot`、`rollback`、`policy`、`ps`、`inspect` 等指令。
- **gRPC / REST API**：供上层 Agent 编排平台或 SDK（Python/TS/Go）调用，支持同步执行、流式输出（SSE/gRPC Stream）及事件订阅。
- **MCP Server (`sbx-mcp`)**：直接将沙箱生命周期、命令执行、有状态 REPL、快照回滚暴露为标准的 Model Context Protocol 工具集。

### 2.2 控制面（Control Plane - `sbx-daemon`）
- **Sandbox Lifecycle Manager**：统一状态机管理（`Creating -> Warm -> Running -> Sleeping -> Snapshotted -> Destroyed`），负责沙箱配额与超时回收（TTL / Idle Timeout）。
- **Warm Pool Scheduler**：按镜像标签与安全策略模板维护预热沙箱池（预先拉起 Guest Agent 与常用 Python/Node REPL 运行时），请求到达时亚毫秒级分配，用后按策略重置或销毁。
- **Policy & Secret Manager**：管理每个沙箱的资源配额（CPU/RAM/PIDs/Disk）、系统调用白名单、目录只读/读写权限、出网域名白名单与 Secret 映射表。
- **`containerd` Client Adapter**：通过 `containerd` gRPC 接口完成 OCI 镜像拉取、解包、Lease 管理以及 Snapshot Prepare/View/Commit/Remove。

### 2.3 运行时平面（Runtime Plane - `containerd-shim-sbx-v2`）
实现标准 containerd Runtime v2 (`TaskService`) 协议，同时通过内置 Driver 抽象支持三种隔离级别按场景切换：
1. **Fast Native/Sandboxed Driver（快速受控模式）**：
   - 不调用重型 `runc`，由 Shim 直接准备 Rootfs 与网络命名空间，在目标空间内拉起 `sbx-guest-agent`。
   - 配合 **Seccomp-BPF**（拦截危险系统调用如 `ptrace`、`mount`、`kexec_load`）、**Landlock LSM**（内核级路径访问控制）、**Capabilities Drop** 与 **`cgroup v2`** 硬限额。
2. **gVisor Driver（用户态内核模式）**：
   - 对需要极强系统调用拦截但宿主机无 KVM 嵌套虚拟化权限的云主机环境，通过 `runsc` 提供用户态内核隔离，并复用 `runsc checkpoint/restore` 能力。
3. **MicroVM Driver（硬件级虚拟化模式）**：
   - 参考 `libracoder/kiri` 架构，采用极简定制 Linux 内核（~10MB）配合 KVM/Firecracker（或 `libkrun`）。
   - 支持空闲超时自动休眠（保留极低内存占用的挂起态）与请求触发时的百毫秒级唤醒。

### 2.4 沙箱执行面（Guest Plane - `sbx-guest-agent`）
- **极致精简的 PID 1 二进制**：采用 Rust 静态编译（`musl` target，剥离调试符号，体积控制在 ~900KB 左右），无外部动态库依赖，启动耗时微秒级。
- **原生 `clone3` 进程派生**：收到宿主机指令后，不经过 `/bin/sh` 额外套壳（除非显式请求 Shell），直接通过 `clone3` 派生子进程并精准绑定环境变量、工作目录、cgroup 子分组与 `PR_SET_NO_NEW_PRIVS`，负责僵尸进程回收（Zombie Reaping）。
- **零分配 `vsock` 通信循环**：基于预分配环形缓冲区与二进制帧协议处理宿主机指令，支持多路复用流式 `stdout`/`stderr` 回传、信号投递（`SIGINT`/`SIGKILL`）、小文件快速读写及 Freeze/Thaw 控制。
- **内置 Stateful REPL Worker**：可选常驻轻量 Worker（如 Python Jupyter/IPython Core 或 Node VM），避免每次 `exec` 都重新 `import numpy/pandas`。

### 2.5 安全与网络层（Security & Network Plane - `sbx-net-guard`）
- **默认断网（Default Deny）**：未配置网络策略的沙箱仅拥有 Loopback 接口，无法触达宿主机内网（禁止访问 RFC1918 / `169.254.169.254` 云元数据服务）与公网。
- **DNS & TLS SNI 白名单过滤**：对于授权联网的沙箱，宿主机侧拦截 DNS 解析并校验出站连接的 SNI / IP，防止通过直接 IP 绕过域名白名单。
- **Zero-Trust Secret Injector**：所有需要携带 API Token 访问外部服务的 HTTP/HTTPS 请求，必须经过宿主机代理。沙箱内代码只需使用占位符（如 `Authorization: Bearer sbx_secret_github_token`），代理校验目标域名符合该 Secret 的绑定域名白名单后，在出口处替换为真实密钥。

### 2.6 存储快照层（Storage Plane - `sbx-snapshot`）
- **基于 `containerd` Snapshotter 的时间旅行**：
  - 基础镜像层（只读）通过 OverlayFS/EroFS 在所有沙箱间零拷贝共享。
  - Agent 每执行一个关键步骤前后，控制面可触发 Step-level Snapshot（利用 containerd `Commit` + 新建 `Prepare` 上层视图，或结合文件系统 CoW），直接计算 `Upperdir` 变更生成 **Filesystem Diff**。
  - 若 Agent 执行破坏性命令失败，可在毫秒级丢弃当前活跃层并回滚（Rollback）至上一健康 Snapshot，或从某 Snapshot **Fork** 出多个并行子沙箱尝试不同修复路径。

---

## 3. 核心交互时序图

### 3.1 沙箱获取与 `vsock` 极速执行流程

```mermaid
sequenceDiagram
    autonumber
    actor Agent as AI Agent / Client
    participant Daemon as sbx-daemon
    participant CTRD as containerd
    participant Pool as Warm Pool
    participant Shim as containerd-shim-sbx-v2
    participant Guest as sbx-guest-agent (PID 1)

    Agent->>Daemon: CreateSandbox(image, policy)
    alt Warm Pool Hit
        Daemon->>Pool: Acquire pre-warmed sandbox
        Pool-->>Daemon: sandbox_id (already booted)
    else Cold Start
        Daemon->>CTRD: PrepareSnapshot(image_ref, lease_id)
        CTRD-->>Daemon: Mounts (OverlayFS upper/lower)
        Daemon->>Shim: StartTask(rootfs, policy, vsock_cid)
        Shim->>Guest: Boot PID 1 in isolated env
        Guest-->>Shim: Ready Heartbeat via vsock
        Shim-->>Daemon: Sandbox Ready
    end
    Daemon-->>Agent: sandbox_id

    Agent->>Daemon: Exec(sandbox_id, cmd, stream=true)
    Daemon->>Shim: Forward ExecReq
    Shim->>Guest: Write vsock Frame (OP_EXEC)
    Guest->>Guest: clone3() spawn target process
    loop Streaming Output
        Guest-->>Shim: vsock Frame (OP_STDOUT / OP_STDERR)
        Shim-->>Daemon: Stream chunk
        Daemon-->>Agent: Stream chunk
    end
    Guest-->>Shim: vsock Frame (OP_EXIT, code)
    Shim-->>Daemon: ExecResult(exit_code, rusage)
    Daemon-->>Agent: ExecResult
```

### 3.2 步骤级快照（Snapshot）、分叉（Fork）与回滚（Rollback）

```mermaid
sequenceDiagram
    autonumber
    actor Agent as AI Agent
    participant Daemon as sbx-daemon
    participant Guest as sbx-guest-agent
    participant Snap as sbx-snapshot / containerd

    Agent->>Daemon: Snapshot(sbx_1, label="before_refactor")
    Daemon->>Guest: Freeze & SyncFS (vsock OP_FREEZE)
    Guest-->>Daemon: Filesystem quiesced
    Daemon->>Snap: Commit active upper layer -> snap_A
    Daemon->>Snap: Prepare new active layer from snap_A
    Daemon->>Guest: Thaw (vsock OP_THAW)
    Daemon-->>Agent: snapshot_id = snap_A

    Agent->>Daemon: Exec(sbx_1, "rm -rf src/ && bad_script")
    Daemon-->>Agent: Exit 1 / Broken state

    Agent->>Daemon: Rollback(sbx_1, snap_A)
    Daemon->>Snap: Discard dirty layer, mount new layer on snap_A
    Daemon-->>Agent: sbx_1 restored to snap_A

    Agent->>Daemon: Fork(snap_A, count=2)
    Daemon->>Snap: Prepare layer_B1 & layer_B2 from snap_A (CoW)
    Daemon-->>Agent: [sbx_2, sbx_3] ready for parallel trials
```

### 3.3 零信任出口代理与 Secret 注入流程

```mermaid
sequenceDiagram
    autonumber
    participant Proc as Sandbox Process
    participant NetGuard as sbx-net-guard (Host Proxy)
    participant Policy as Policy & Secret Store
    participant Upstream as Target API (api.github.com)

    Note over Proc: Env only has GH_TOKEN="sbx_placeholder_gh_1"
    Proc->>NetGuard: HTTPS Request via Proxy (CONNECT api.github.com:443)
    NetGuard->>Policy: Check Egress Allowlist("api.github.com")
    alt Domain Denied or Internal IP
        Policy-->>NetGuard: DENY
        NetGuard-->>Proc: 403 Forbidden (Blocked by Policy)
    else Domain Allowed
        Policy-->>NetGuard: ALLOW + Secret Binding Rule
        NetGuard->>Upstream: TLS Handshake + Forward Request
        Note over NetGuard: Inspect Header: replace "sbx_placeholder_gh_1" with real token (only for api.github.com)
        Upstream-->>NetGuard: 200 OK (API Response)
        NetGuard-->>Proc: 200 OK (No real secret ever enters sandbox)
    end
```

---

## 4. 核心协议与数据模型设计

### 4.1 Host <-> Guest `vsock` 二进制帧协议

借鉴 `kiri` 的低分配、高吞吐思路，Host Shim 与 Guest Agent 之间采用紧凑的定长帧头 + 变长载荷二进制协议（无需在热路径解析 JSON）：

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Magic (0x5342)            |   Version (1) |   OpCode      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Stream / Request ID                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload Length                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |                  Reserved                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload (Postcard / Raw Bytes)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **核心 OpCode 定义**：
  - `0x01 OP_PING / OP_PONG`：健康检查与启动就绪探针。
  - `0x02 OP_EXEC_REQ`：携带 `argv`、`env`、`cwd`、timeout、uid/gid 与 tty 标志（`postcard` 二进制序列化，极低反序列化开销）。
  - `0x03 OP_STDIN_DATA` / `0x04 OP_STDOUT_DATA` / `0x05 OP_STDERR_DATA`：原始字节流，零拷贝直传。
  - `0x06 OP_EXEC_EXIT`：返回退出码与进程资源统计（CPU time、Max RSS）。
  - `0x07 OP_SIGNAL`：向指定 Request ID 进程树投递 POSIX 信号。
  - `0x08 OP_FILE_PUT` / `0x09 OP_FILE_GET`：宿主机与沙箱内部之间绕过宿主机路径穿透的安全文件传输。
  - `0x0A OP_FREEZE` / `0x0B OP_THAW`：触发 cgroup freezer 与 `syncfs`，保障快照一致性。
  - `0x0C OP_REPL_EXEC`：向沙箱内常驻 REPL Worker 发送代码片段并获取结构化执行结果。

### 4.2 安全策略模型（SecurityPolicy）

每个沙箱在创建时绑定不可变的最小权限策略：

| 字段类别 | 配置项 | 默认受控策略 |
| :--- | :--- | :--- |
| **隔离后端** | `backend` | `native` / `gvisor` / `microvm`（按宿主机能力与隔离等级选择） |
| **计算配额** | `cpu_quota_us`, `memory_max_bytes`, `pids_max` | 默认强制开启 `cgroup v2` 限制（如 2 vCPU, 1GB RAM, 128 PIDs 防 Fork 炸弹） |
| **系统调用** | `seccomp_profile` | 默认启用 AI Sandbox 精简白名单（禁用 `bpf`, `ptrace`, `mount`, `reboot`, `init_module` 等） |
| **文件系统** | `readonly_rootfs`, `writable_paths`, `disk_quota_mb` | Rootfs 默认只读或受 Landlock 限制，仅允许 `/workspace` 与 `/tmp` 写入 |
| **网络出口** | `net_mode`, `egress_allowlist`, `block_private_cidrs` | 默认 `none`（完全断网）；开启 `proxy` 模式时强制屏蔽私网与元数据 IP |
| **凭证注入** | `secret_bindings` | `[{ placeholder, target_domains, header_name, secret_ref }]` |
| **生命周期** | `max_ttl_sec`, `idle_sleep_sec`, `auto_destroy` | 防止僵尸沙箱长期占用计算与内存资源 |
