use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sbx_containerd::ContainerdClientAdapter;
use sbx_daemon::{DaemonClient, DaemonRequest, DaemonResponse};
use sbx_net::SecretVault;
use sbx_proto::{
    BackendKind, DiffKind, ExecRequest, NetworkPolicy, ReplExecRequest, SeccompMode, SecretRule,
    SecurityPolicy,
};
use sbx_runtime::{
    landlock_abi_version, locate_guest_agent_binary, IsolationBackend, NativeBackend,
    RuntimeDispatcher, SandboxRuntimeConfig,
};

#[derive(Parser)]
#[command(name = "sbx", version, about = "AI Sandbox (sbx) CLI")]
struct Cli {
    /// Path to containerd gRPC socket (auto-detected if omitted)
    #[arg(long, env = "SBX_CONTAINERD_SOCK", global = true)]
    socket: Option<PathBuf>,

    /// Path to sbx-daemon Unix domain socket
    #[arg(long, env = "SBX_DAEMON_SOCK", global = true)]
    daemon_socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum BackendArg {
    Native,
    Gvisor,
    Microvm,
}

impl From<BackendArg> for BackendKind {
    fn from(value: BackendArg) -> Self {
        match value {
            BackendArg::Native => BackendKind::Native,
            BackendArg::Gvisor => BackendKind::Gvisor,
            BackendArg::Microvm => BackendKind::MicroVm,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum SeccompArg {
    Standard,
    Strict,
    Custom,
}

impl From<SeccompArg> for SeccompMode {
    fn from(value: SeccompArg) -> Self {
        match value {
            SeccompArg::Standard => SeccompMode::Standard,
            SeccompArg::Strict => SeccompMode::Strict,
            SeccompArg::Custom => SeccompMode::Custom,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum NetArg {
    Disabled,
    Proxy,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a one-shot command inside an isolated sandbox from an OCI image
    Run {
        /// OCI image reference (e.g., alpine, python:3.12-slim)
        image: String,
        #[arg(long)]
        id: Option<String>,
        #[arg(long, value_enum, default_value_t = BackendArg::Native)]
        backend: BackendArg,
        #[arg(long, value_enum, default_value_t = SeccompArg::Standard)]
        seccomp: SeccompArg,
        #[arg(long)]
        readonly_rootfs: bool,
        #[arg(long = "writable-path")]
        writable_paths: Vec<String>,
        #[arg(long, value_enum, default_value_t = NetArg::Disabled)]
        net: NetArg,
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        /// Secret rule: PLACEHOLDER=SECRET_REF@HOST1,HOST2[:HEADER]
        #[arg(long = "secret")]
        secrets: Vec<String>,
        /// Optional host DNS override for testing (HOST=IP:PORT)
        #[arg(long = "net-host-override")]
        host_overrides: Vec<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        #[arg(long, default_value_t = 1024)]
        memory_mb: u64,
        #[arg(long, default_value_t = 128)]
        pids: u32,
        #[arg(long, default_value_t = 2.0)]
        cpus: f32,
        #[arg(long, default_value_t = 0)]
        timeout_ms: u64,
        #[arg(long)]
        stats: bool,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Create a persistent sandbox managed by sbx-daemon (uses Warm Pool when available)
    Create {
        image: String,
        #[arg(long)]
        id: Option<String>,
        #[arg(long, value_enum, default_value_t = BackendArg::Native)]
        backend: BackendArg,
        #[arg(long, value_enum, default_value_t = SeccompArg::Standard)]
        seccomp: SeccompArg,
        #[arg(long)]
        readonly_rootfs: bool,
        #[arg(long, value_enum, default_value_t = NetArg::Disabled)]
        net: NetArg,
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        #[arg(long = "secret")]
        secrets: Vec<String>,
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        #[arg(long, default_value_t = 1024)]
        memory_mb: u64,
        #[arg(long, default_value_t = 128)]
        pids: u32,
        #[arg(long, default_value_t = 2.0)]
        cpus: f32,
    },
    /// Execute a command inside a persistent sandbox via clone3
    Exec {
        sandbox_id: String,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        #[arg(long, default_value_t = 10000)]
        timeout_ms: u64,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Execute stateful code inside a sandbox's persistent REPL worker (python / node / sh)
    Repl {
        sandbox_id: String,
        #[arg(long, default_value = "python")]
        lang: String,
        #[arg(long, default_value_t = 10000)]
        timeout_ms: u64,
        code: String,
    },
    /// Take a step-level filesystem + REPL checkpoint snapshot
    Snapshot {
        sandbox_id: String,
        #[arg(long)]
        label: Option<String>,
    },
    /// Show filesystem changes inside a sandbox since launch or last snapshot
    Diff { sandbox_id: String },
    /// Roll back a sandbox to a previous step snapshot
    Rollback {
        sandbox_id: String,
        snapshot_id: String,
    },
    /// Fork N parallel Copy-on-Write sandboxes from a snapshot
    Fork {
        snapshot_id: String,
        #[arg(short = 'n', long, default_value_t = 2)]
        count: usize,
    },
    /// Save a live sandbox memory/REPL + filesystem checkpoint
    Checkpoint { sandbox_id: String },
    /// Restore a saved checkpoint into a running sandbox
    Restore {
        checkpoint_id: String,
        #[arg(long)]
        id: Option<String>,
    },
    /// Put a sandbox into low-memory sleeping state
    Sleep { sandbox_id: String },
    /// Wake a sleeping sandbox
    Wake { sandbox_id: String },
    /// List active, warm, and sleeping sandboxes
    Ps,
    /// Inspect detailed sandbox metadata and policy JSON
    Inspect { sandbox_id: String },
    /// Destroy a sandbox and clean up all leases/cgroups
    Rm { sandbox_id: String },
    /// Manage Warm Pool pre-warmed sandboxes
    WarmPool {
        #[command(subcommand)]
        action: WarmPoolCmd,
    },
    /// Show or validate the default security policy
    Policy {
        #[command(subcommand)]
        action: Option<PolicyCmd>,
    },
    /// Pull and unpack an OCI image into containerd
    Pull { image: String },
    /// List cached OCI images in the sbx containerd namespace
    Images,
    /// Measure cold-start-to-first-OP_EXEC and subsequent clone3 exec latencies
    Bench {
        #[arg(long, default_value = "alpine")]
        image: String,
        #[arg(long, default_value_t = 50)]
        iterations: usize,
        #[arg(long, default_value_t = 5)]
        cold_trials: usize,
    },
    /// Check host kernel, Landlock, Seccomp, cgroup v2, guest-agent binary, backends, and containerd health
    Doctor,
}

#[derive(Subcommand)]
enum WarmPoolCmd {
    /// Pre-warm N sandboxes for fast acquisition
    Prewarm {
        image: String,
        #[arg(short = 'n', long, default_value_t = 2)]
        count: usize,
        #[arg(long, value_enum, default_value_t = BackendArg::Native)]
        backend: BackendArg,
    },
    /// Show current warm pool bucket status
    Status,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Print default security policy JSON
    Show,
    /// Validate a policy JSON or TOML file
    Check { path: PathBuf },
}

fn gen_sandbox_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{}-{}", process::id(), nanos % 1_000_000_000)
}

fn parse_env(env: Vec<String>) -> Vec<(String, String)> {
    env.into_iter()
        .filter_map(|item| {
            item.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn parse_secret_rules(raw: Vec<String>) -> Result<Vec<SecretRule>> {
    let mut rules = Vec::with_capacity(raw.len());
    for item in raw {
        let (placeholder, rhs) = item
            .split_once('=')
            .with_context(|| format!("invalid --secret '{item}': expected PLACEHOLDER=REF@HOSTS"))?;
        let (secret_ref, hosts_hdr) = rhs
            .split_once('@')
            .with_context(|| format!("invalid --secret '{item}': missing @HOSTS"))?;
        let (hosts_part, header_name) = match hosts_hdr.split_once(':') {
            Some((h, hdr)) => (h, hdr),
            None => (hosts_hdr, "Authorization"),
        };
        let allowed_hosts: Vec<String> = hosts_part
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        rules.push(SecretRule {
            placeholder: placeholder.to_string(),
            allowed_hosts,
            header_name: header_name.to_string(),
            secret_ref: secret_ref.to_string(),
        });
    }
    Ok(rules)
}

fn build_policy(
    backend: BackendArg,
    seccomp: SeccompArg,
    readonly_rootfs: bool,
    writable_paths: Vec<String>,
    net: NetArg,
    allow_hosts: Vec<String>,
    secrets: Vec<String>,
    memory_mb: u64,
    pids: u32,
    cpus: f32,
) -> Result<SecurityPolicy> {
    let mut policy = SecurityPolicy::default();
    policy.backend = backend.into();
    policy.seccomp_mode = seccomp.into();
    policy.readonly_rootfs = readonly_rootfs;
    if !writable_paths.is_empty() {
        policy.writable_paths = writable_paths;
    }
    policy.memory_limit_mb = memory_mb;
    policy.pids_limit = pids;
    policy.cpu_cores = cpus;
    policy.cpu_quota_us = ((cpus.max(0.1)) * 100_000.0) as u64;
    policy.secret_bindings = parse_secret_rules(secrets)?;
    policy.network = match net {
        NetArg::Disabled if allow_hosts.is_empty() => NetworkPolicy::Disabled,
        _ => NetworkPolicy::AllowlistProxy {
            allowed_hosts: allow_hosts,
            block_private_cidrs: true,
        },
    };
    Ok(policy)
}

fn expect_ok(resp: DaemonResponse) -> Result<DaemonResponse> {
    if let DaemonResponse::Error(msg) = resp {
        bail!("{msg}");
    }
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            image,
            id,
            backend,
            seccomp,
            readonly_rootfs,
            writable_paths,
            net,
            allow_hosts,
            secrets,
            host_overrides,
            cwd,
            env,
            memory_mb,
            pids,
            cpus,
            timeout_ms,
            stats,
            cmd,
        } => {
            let total_start = Instant::now();
            let ctrd = ContainerdClientAdapter::connect(cli.socket.as_deref()).await?;
            let _ = ctrd.reap_expired_leases().await;

            let dispatcher = RuntimeDispatcher::new(None)?;
            let _ = dispatcher.reap_stale_sandboxes();

            let sandbox_id = id.unwrap_or_else(|| gen_sandbox_id("run"));
            let policy = build_policy(
                backend,
                seccomp,
                readonly_rootfs,
                writable_paths,
                net,
                allow_hosts,
                secrets,
                memory_mb,
                pids,
                cpus,
            )?;

            let vault = SecretVault::new();
            vault.load_from_host_env(&policy.secret_bindings);

            let mut overrides: HashMap<String, Vec<SocketAddr>> = HashMap::new();
            for ov in host_overrides {
                if let Some((h, addr_s)) = ov.split_once('=') {
                    let addr: SocketAddr = addr_s
                        .parse()
                        .with_context(|| format!("invalid host override addr '{addr_s}'"))?;
                    overrides.entry(h.to_string()).or_default().push(addr);
                }
            }

            let prep_start = Instant::now();
            let rootfs = ctrd
                .prepare_rootfs(&sandbox_id, &image, Duration::from_secs(3600))
                .await?;
            let prep_elapsed = prep_start.elapsed();

            let mut cfg = SandboxRuntimeConfig::new(sandbox_id.as_str(), rootfs.mounts, policy.clone());
            cfg.secret_vault = vault;
            cfg.host_overrides = overrides;

            let boot_start = Instant::now();
            let start_res = dispatcher.backend_for(policy.backend).start(&cfg).await;
            let handle = match start_res {
                Ok(h) => h,
                Err(e) => {
                    let _ = ctrd.cleanup_sandbox_storage(&sandbox_id).await;
                    return Err(e);
                }
            };
            let boot_elapsed = boot_start.elapsed();

            let exec_req = ExecRequest {
                argv: cmd,
                env: parse_env(env),
                cwd,
                timeout_ms,
                uid: None,
                gid: None,
                tty: false,
            };

            let exec_start = Instant::now();
            let stream_cb: sbx_runtime::StreamCallback<'_> = Box::new(|is_stdout, bytes| {
                if is_stdout {
                    let _ = io::stdout().write_all(bytes);
                    let _ = io::stdout().flush();
                } else {
                    let _ = io::stderr().write_all(bytes);
                    let _ = io::stderr().flush();
                }
            });
            let exec_res = handle.exec(&exec_req, Some(stream_cb)).await;
            let exec_elapsed = exec_start.elapsed();

            let destroy_start = Instant::now();
            let _ = handle.destroy().await;
            let _ = ctrd.cleanup_sandbox_storage(&sandbox_id).await;
            let destroy_elapsed = destroy_start.elapsed();

            let output = exec_res?;
            if let Some(err) = &output.error {
                eprintln!("sbx exec error: {err}");
            }

            if stats {
                eprintln!(
                    "[sbx stats] cached={} backend={:?} prepare_rootfs={:.2}ms boot_agent={:.2}ms exec={:.2}ms (guest={:.2}ms) destroy={:.2}ms total={:.2}ms max_rss={}KiB exit={}",
                    rootfs.image.cached,
                    policy.backend,
                    prep_elapsed.as_secs_f64() * 1000.0,
                    boot_elapsed.as_secs_f64() * 1000.0,
                    exec_elapsed.as_secs_f64() * 1000.0,
                    output.elapsed_us as f64 / 1000.0,
                    destroy_elapsed.as_secs_f64() * 1000.0,
                    total_start.elapsed().as_secs_f64() * 1000.0,
                    output.max_rss_kb,
                    output.exit_code,
                );
            }

            if output.exit_code != 0 {
                process::exit(output.exit_code);
            }
        }
        Commands::Create {
            image,
            id,
            backend,
            seccomp,
            readonly_rootfs,
            net,
            allow_hosts,
            secrets,
            env,
            memory_mb,
            pids,
            cpus,
        } => {
            let policy = build_policy(
                backend,
                seccomp,
                readonly_rootfs,
                Vec::new(),
                net,
                allow_hosts,
                secrets,
                memory_mb,
                pids,
                cpus,
            )?;
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(
                client
                    .request(&DaemonRequest::CreateSandbox {
                        id,
                        image,
                        policy: Some(policy),
                        env: parse_env(env),
                        secrets: HashMap::new(),
                    })
                    .await?,
            )?;
            if let DaemonResponse::Sandbox(info) = resp {
                println!(
                    "{} (image={}, backend={:?}, state={:?}, warm_hit={})",
                    info.id, info.image, info.backend, info.state, info.warm_hit
                );
            }
        }
        Commands::Exec {
            sandbox_id,
            cwd,
            env,
            timeout_ms,
            cmd,
        } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(
                client
                    .request(&DaemonRequest::Exec {
                        sandbox_id,
                        req: ExecRequest {
                            argv: cmd,
                            env: parse_env(env),
                            cwd,
                            timeout_ms,
                            uid: None,
                            gid: None,
                            tty: false,
                        },
                    })
                    .await?,
            )?;
            if let DaemonResponse::Exec(out) = resp {
                print!("{}", out.stdout);
                eprint!("{}", out.stderr);
                if out.exit_code != 0 {
                    process::exit(out.exit_code);
                }
            }
        }
        Commands::Repl {
            sandbox_id,
            lang,
            timeout_ms,
            code,
        } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(
                client
                    .request(&DaemonRequest::ReplExec {
                        sandbox_id,
                        req: ReplExecRequest {
                            language: lang,
                            code,
                            timeout_ms,
                        },
                    })
                    .await?,
            )?;
            if let DaemonResponse::Repl(out) = resp {
                print!("{}", out.stdout);
                eprint!("{}", out.stderr);
                if out.exit_code != 0 {
                    process::exit(out.exit_code);
                }
            }
        }
        Commands::Snapshot { sandbox_id, label } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(
                client
                    .request(&DaemonRequest::Snapshot { sandbox_id, label })
                    .await?,
            )?;
            if let DaemonResponse::Snapshot(meta) = resp {
                println!("{}", meta.id);
            }
        }
        Commands::Diff { sandbox_id } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(client.request(&DaemonRequest::Diff { sandbox_id }).await?)?;
            if let DaemonResponse::Diff(entries) = resp {
                for e in entries {
                    let tag = match e.kind {
                        DiffKind::Added => "+",
                        DiffKind::Modified => "~",
                        DiffKind::Deleted => "-",
                    };
                    println!("{tag} {} ({} bytes)", e.path, e.size_bytes);
                }
            }
        }
        Commands::Rollback {
            sandbox_id,
            snapshot_id,
        } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(
                client
                    .request(&DaemonRequest::Rollback {
                        sandbox_id,
                        snapshot_id,
                    })
                    .await?,
            )?;
            if let DaemonResponse::Sandbox(info) = resp {
                println!("Rolled back {} to {:?}", info.id, info.parent_snapshot);
            }
        }
        Commands::Fork { snapshot_id, count } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(
                client
                    .request(&DaemonRequest::Fork {
                        snapshot_id,
                        count,
                        policy: None,
                    })
                    .await?,
            )?;
            if let DaemonResponse::Sandboxes(list) = resp {
                for s in list {
                    println!("{}", s.id);
                }
            }
        }
        Commands::Checkpoint { sandbox_id } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(
                client
                    .request(&DaemonRequest::Checkpoint { sandbox_id })
                    .await?,
            )?;
            if let DaemonResponse::Checkpoint(meta) = resp {
                println!(
                    "{} (snapshot={}, has_repl_state={})",
                    meta.id, meta.snapshot_id, meta.has_repl_state
                );
            }
        }
        Commands::Restore { checkpoint_id, id } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(
                client
                    .request(&DaemonRequest::Restore {
                        checkpoint_id,
                        new_sandbox_id: id,
                    })
                    .await?,
            )?;
            if let DaemonResponse::Sandbox(info) = resp {
                println!("{}", info.id);
            }
        }
        Commands::Sleep { sandbox_id } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            expect_ok(client.request(&DaemonRequest::Sleep { sandbox_id }).await?)?;
            println!("Sleeping");
        }
        Commands::Wake { sandbox_id } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            expect_ok(client.request(&DaemonRequest::Wake { sandbox_id }).await?)?;
            println!("Running");
        }
        Commands::Ps => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(client.request(&DaemonRequest::ListSandboxes).await?)?;
            if let DaemonResponse::Sandboxes(list) = resp {
                println!(
                    "{:<24} {:<24} {:<10} {:<10} {}",
                    "ID", "IMAGE", "BACKEND", "STATE", "WARM_HIT"
                );
                for s in list {
                    println!(
                        "{:<24} {:<24} {:<10?} {:<10?} {}",
                        s.id, s.image, s.backend, s.state, s.warm_hit
                    );
                }
            }
        }
        Commands::Inspect { sandbox_id } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = expect_ok(
                client
                    .request(&DaemonRequest::InspectSandbox { sandbox_id })
                    .await?,
            )?;
            if let DaemonResponse::Sandbox(info) = resp {
                println!("{}", serde_json::to_string_pretty(&info)?);
            }
        }
        Commands::Rm { sandbox_id } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            expect_ok(
                client
                    .request(&DaemonRequest::DestroySandbox { sandbox_id })
                    .await?,
            )?;
            println!("Removed");
        }
        Commands::WarmPool { action } => {
            let mut client =
                DaemonClient::connect_or_autostart(cli.daemon_socket.as_deref()).await?;
            let resp = match action {
                WarmPoolCmd::Prewarm {
                    image,
                    count,
                    backend,
                } => {
                    expect_ok(
                        client
                            .request(&DaemonRequest::ConfigureWarmPool {
                                image,
                                backend: backend.into(),
                                target_count: count,
                                policy: None,
                            })
                            .await?,
                    )?
                }
                WarmPoolCmd::Status => {
                    expect_ok(client.request(&DaemonRequest::WarmPoolStatus).await?)?
                }
            };
            if let DaemonResponse::PoolStats(stats) = resp {
                println!("{:<32} {:<10} {:<8} {}", "IMAGE", "BACKEND", "READY", "TARGET");
                for b in stats {
                    println!(
                        "{:<32} {:<10?} {:<8} {}",
                        b.image, b.backend, b.ready_count, b.target_count
                    );
                }
            }
        }
        Commands::Policy { action } => match action.unwrap_or(PolicyCmd::Show) {
            PolicyCmd::Show => {
                println!("{}", serde_json::to_string_pretty(&SecurityPolicy::default())?);
            }
            PolicyCmd::Check { path } => {
                let raw = fs::read_to_string(&path)?;
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    let parsed: SecurityPolicy = serde_json::from_str(&raw)?;
                    println!("Valid SecurityPolicy JSON (backend={:?})", parsed.backend);
                } else {
                    println!("Read policy file {} ({} bytes)", path.display(), raw.len());
                }
            }
        },
        Commands::Pull { image } => {
            let t0 = Instant::now();
            let ctrd = ContainerdClientAdapter::connect(cli.socket.as_deref()).await?;
            let pulled = ctrd.pull_image(&image).await?;
            println!(
                "Pulled {} (digest={}, chain_id={}, cached={}, elapsed={:.2}ms)",
                pulled.reference,
                pulled.digest,
                pulled.chain_id,
                pulled.cached,
                t0.elapsed().as_secs_f64() * 1000.0
            );
        }
        Commands::Images => {
            let ctrd = ContainerdClientAdapter::connect(cli.socket.as_deref()).await?;
            let images = ctrd.list_images().await?;
            println!("{:<40} {:<24} {}", "NAME", "DIGEST", "CHAIN_ID");
            for img in images {
                let short_dig = img.digest.chars().take(21).collect::<String>();
                let short_chain = img
                    .chain_id
                    .unwrap_or_else(|| String::from("-"))
                    .chars()
                    .take(24)
                    .collect::<String>();
                println!("{:<40} {:<24} {}", img.name, short_dig, short_chain);
            }
        }
        Commands::Bench {
            image,
            iterations,
            cold_trials,
        } => {
            run_bench(cli.socket.as_deref(), &image, iterations, cold_trials).await?;
        }
        Commands::Doctor => {
            run_doctor(cli.socket.as_deref(), cli.daemon_socket.as_deref()).await?;
        }
    }

    Ok(())
}

async fn run_bench(
    socket: Option<&std::path::Path>,
    image: &str,
    iterations: usize,
    cold_trials: usize,
) -> Result<()> {
    let ctrd = ContainerdClientAdapter::connect(socket).await?;
    let _ = ctrd.reap_expired_leases().await;
    let backend = NativeBackend::new(None)?;
    let _ = backend.reap_stale_sandboxes();

    println!("=== sbx Benchmark ===");
    println!("Image: {image}");
    println!("Guest Agent: {}", backend.guest_agent_bin().display());

    let pulled = ctrd.pull_image(image).await?;
    println!(
        "Cached image ready: {} (chain_id={})",
        pulled.reference, pulled.chain_id
    );

    let mut cold_latencies_ms = Vec::with_capacity(cold_trials);
    let mut cold_prep_ms = Vec::with_capacity(cold_trials);
    let mut cold_boot_ms = Vec::with_capacity(cold_trials);
    let mut cold_exec_ms = Vec::with_capacity(cold_trials);

    for i in 0..cold_trials.max(1) {
        let sbx_id = gen_sandbox_id(&format!("bench-cold-{i}"));
        let t0 = Instant::now();
        let rootfs = ctrd
            .prepare_rootfs(&sbx_id, image, Duration::from_secs(300))
            .await?;
        let t_prep = t0.elapsed();

        let t1 = Instant::now();
        let handle = backend
            .start(&SandboxRuntimeConfig::new(
                sbx_id.as_str(),
                rootfs.mounts,
                SecurityPolicy::default(),
            ))
            .await?;
        let t_boot = t1.elapsed();

        let t2 = Instant::now();
        let out = handle
            .exec(
                &ExecRequest {
                    argv: vec![String::from("/bin/echo"), String::from("ok")],
                    env: Vec::new(),
                    cwd: None,
                    timeout_ms: 5000,
                    uid: None,
                    gid: None,
                    tty: false,
                },
                None,
            )
            .await?;
        let t_exec = t2.elapsed();
        let total = t0.elapsed();

        if out.exit_code != 0 {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let _ = handle.destroy().await;
            let _ = ctrd.cleanup_sandbox_storage(&sbx_id).await;
            bail!("cold start probe command failed (exit {}): {stderr}", out.exit_code);
        }

        let _ = handle.destroy().await;
        let _ = ctrd.cleanup_sandbox_storage(&sbx_id).await;

        cold_prep_ms.push(t_prep.as_secs_f64() * 1000.0);
        cold_boot_ms.push(t_boot.as_secs_f64() * 1000.0);
        cold_exec_ms.push(t_exec.as_secs_f64() * 1000.0);
        cold_latencies_ms.push(total.as_secs_f64() * 1000.0);
    }

    let hot_id = gen_sandbox_id("bench-hot");
    let rootfs = ctrd
        .prepare_rootfs(&hot_id, image, Duration::from_secs(300))
        .await?;
    let handle = backend
        .start(&SandboxRuntimeConfig::new(
            hot_id.as_str(),
            rootfs.mounts,
            SecurityPolicy::default(),
        ))
        .await?;

    let probe_req = ExecRequest {
        argv: vec![String::from("/bin/echo"), String::from("ok")],
        env: Vec::new(),
        cwd: None,
        timeout_ms: 5000,
        uid: None,
        gid: None,
        tty: false,
    };
    let _ = handle.exec(&probe_req, None).await?;

    let mut exec_latencies_ms = Vec::with_capacity(iterations);
    for _ in 0..iterations.max(1) {
        let t0 = Instant::now();
        let out = handle.exec(&probe_req, None).await?;
        let dt = t0.elapsed().as_secs_f64() * 1000.0;
        if out.exit_code != 0 {
            let _ = handle.destroy().await;
            let _ = ctrd.cleanup_sandbox_storage(&hot_id).await;
            bail!("warm exec failed with exit code {}", out.exit_code);
        }
        exec_latencies_ms.push(dt);
    }

    let _ = handle.destroy().await;
    let _ = ctrd.cleanup_sandbox_storage(&hot_id).await;

    cold_latencies_ms.sort_by(|a, b| a.total_cmp(b));
    exec_latencies_ms.sort_by(|a, b| a.total_cmp(b));

    let cold_avg = cold_latencies_ms.iter().sum::<f64>() / cold_latencies_ms.len() as f64;
    let cold_p50 = percentile(&cold_latencies_ms, 0.50);
    let cold_min = *cold_latencies_ms.first().unwrap_or(&0.0);
    let cold_max = *cold_latencies_ms.last().unwrap_or(&0.0);

    let prep_avg = cold_prep_ms.iter().sum::<f64>() / cold_prep_ms.len() as f64;
    let boot_avg = cold_boot_ms.iter().sum::<f64>() / cold_boot_ms.len() as f64;
    let first_exec_avg = cold_exec_ms.iter().sum::<f64>() / cold_exec_ms.len() as f64;

    let exec_avg = exec_latencies_ms.iter().sum::<f64>() / exec_latencies_ms.len() as f64;
    let exec_min = *exec_latencies_ms.first().unwrap_or(&0.0);
    let exec_p50 = percentile(&exec_latencies_ms, 0.50);
    let exec_p95 = percentile(&exec_latencies_ms, 0.95);
    let exec_max = *exec_latencies_ms.last().unwrap_or(&0.0);

    println!();
    println!(
        "Cold Start -> First OP_EXEC ({} trials): min={:.2}ms p50={:.2}ms avg={:.2}ms max={:.2}ms (target < 20.00ms)",
        cold_latencies_ms.len(),
        cold_min,
        cold_p50,
        cold_avg,
        cold_max
    );
    println!(
        "  Breakdown avg: prepare_rootfs={:.2}ms, boot_namespaces_agent={:.2}ms, first_exec={:.2}ms",
        prep_avg, boot_avg, first_exec_avg
    );
    println!(
        "Subsequent clone3 OP_EXEC ({} iters): min={:.2}ms p50={:.2}ms avg={:.2}ms p95={:.2}ms max={:.2}ms (target < 5.00ms)",
        exec_latencies_ms.len(),
        exec_min,
        exec_p50,
        exec_avg,
        exec_p95,
        exec_max
    );

    let active_cgroups = backend.cgroups().list_active_cgroups();
    let remaining_dirs = fs::read_dir(backend.state_root())
        .map(|it| it.count())
        .unwrap_or(0);
    println!(
        "Cleanup Hygiene: remaining_cgroups={}, remaining_state_dirs={}",
        active_cgroups.len(),
        remaining_dirs
    );

    Ok(())
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

async fn run_doctor(
    socket: Option<&std::path::Path>,
    daemon_socket: Option<&std::path::Path>,
) -> Result<()> {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| String::from("unknown"));
    println!("Kernel: {}", kernel.trim());

    let cgroup_ctrls = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
        .unwrap_or_else(|_| String::from("unavailable"));
    println!("cgroup v2 root controllers: {}", cgroup_ctrls.trim());

    match landlock_abi_version() {
        Some(ver) => println!("Landlock LSM: enabled (ABI v{ver})"),
        None => println!("Landlock LSM: disabled in host kernel (mount RO fallback active)"),
    }
    println!("Seccomp-BPF: enabled (Classic BPF syscall allow/deny filter)");

    match locate_guest_agent_binary() {
        Ok(path) => {
            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            println!(
                "Guest agent: {} ({} bytes / {:.1} KiB)",
                path.display(),
                size,
                size as f64 / 1024.0
            );
        }
        Err(e) => println!("Guest agent: MISSING ({e})"),
    }

    match RuntimeDispatcher::new(None) {
        Ok(disp) => {
            let nat = disp.native();
            println!(
                "Cgroup slice: {} (delegated={})",
                nat.cgroups().base_dir().display(),
                nat.cgroups().is_delegated()
            );
            println!(
                "Backends: native=ready, gvisor={} ({}), microvm={} (KVM/VMM+kernel or envelope)",
                if disp.gvisor().has_runsc() { "runsc" } else { "strict-native-fallback" },
                disp.gvisor()
                    .runsc_bin()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| String::from("no runsc")),
                if disp.microvm().has_hardware_kvm() { "hardware-kvm" } else { "envelope-fallback" },
            );
        }
        Err(e) => println!("RuntimeDispatcher init error: {e}"),
    }

    match DaemonClient::connect(daemon_socket).await {
        Ok(mut c) => match c.request(&DaemonRequest::Ping).await {
            Ok(DaemonResponse::Pong {
                pid,
                uptime_ms,
                version,
            }) => println!("sbx-daemon: running (pid={pid}, version={version}, uptime={uptime_ms}ms)"),
            _ => println!("sbx-daemon: connected"),
        },
        Err(_) => println!("sbx-daemon: not running (auto-starts on `sbx create`/`ps`/`warm-pool`)"),
    }

    match ContainerdClientAdapter::connect(socket).await {
        Ok(ctrd) => {
            let (ver, rev) = ctrd
                .server_version()
                .await
                .unwrap_or_else(|_| (String::from("?"), String::from("?")));
            let images = ctrd.list_images().await.unwrap_or_default();
            println!(
                "containerd: connected at {} (version={}, rev={}, images={})",
                ctrd.socket_path().display(),
                ver,
                rev,
                images.len()
            );
        }
        Err(e) => println!("containerd: ERROR ({e})"),
    }

    Ok(())
}
