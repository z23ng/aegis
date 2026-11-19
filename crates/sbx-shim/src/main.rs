use std::env;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use anyhow::{bail, Result};
use sbx_runtime::RuntimeDispatcher;
use sbx_shim::{serve_ttrpc, ShimTaskService};
use tracing_subscriber::EnvFilter;

#[derive(Default)]
struct ShimArgs {
    namespace: String,
    id: String,
    address: String,
    publish_binary: String,
    bundle: String,
    socket: Option<PathBuf>,
    debug: bool,
    show_version: bool,
    action: String,
}

fn parse_shim_args() -> ShimArgs {
    let mut out = ShimArgs {
        namespace: String::from("default"),
        ..Default::default()
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-namespace" | "--namespace" => {
                if let Some(v) = args.next() {
                    out.namespace = v;
                }
            }
            "-id" | "--id" => {
                if let Some(v) = args.next() {
                    out.id = v;
                }
            }
            "-address" | "--address" => {
                if let Some(v) = args.next() {
                    out.address = v;
                }
            }
            "-publish-binary" | "--publish-binary" => {
                if let Some(v) = args.next() {
                    out.publish_binary = v;
                }
            }
            "-bundle" | "--bundle" => {
                if let Some(v) = args.next() {
                    out.bundle = v;
                }
            }
            "-socket" | "--socket" => {
                if let Some(v) = args.next() {
                    out.socket = Some(PathBuf::from(v));
                }
            }
            "-debug" | "--debug" => out.debug = true,
            "-v" | "--version" => out.show_version = true,
            other if !other.starts_with('-') => {
                out.action = other.to_string();
            }
            _ => {}
        }
    }
    out
}

fn default_shim_socket(namespace: &str, id: &str) -> PathBuf {
    let base = std::env::temp_dir().join("sbx-shim");
    let safe_id = if id.is_empty() { "default" } else { id };
    base.join(format!("{namespace}-{safe_id}.sock"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_shim_args();
    if args.show_version {
        println!(
            "containerd-shim-sbx-v2 v{} (proto v{})",
            env!("CARGO_PKG_VERSION"),
            sbx_proto::FRAME_VERSION
        );
        return Ok(());
    }

    let filter = if args.debug { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_writer(io::stderr)
        .init();

    let sock_path = args
        .socket
        .clone()
        .unwrap_or_else(|| default_shim_socket(&args.namespace, &args.id));

    match args.action.as_str() {
        "start" => {
            // Spawn detached foreground `serve` instance and return unix://<path> to containerd.
            let exe = env::current_exe()?;
            let mut cmd = Command::new(exe);
            cmd.args([
                "-namespace",
                &args.namespace,
                "-id",
                &args.id,
                "-address",
                &args.address,
                "-publish-binary",
                &args.publish_binary,
                "-bundle",
                &args.bundle,
                "-socket",
                &sock_path.to_string_lossy(),
                "serve",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
            let _child = cmd.spawn()?;
            for _ in 0..50 {
                if sock_path.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            println!("unix://{}", sock_path.display());
            Ok(())
        }
        "delete" => {
            if sock_path.exists() {
                let _ = std::fs::remove_file(&sock_path);
            }
            println!(
                "{{\"exit_status\":0,\"exited_at\":\"1970-01-01T00:00:00Z\",\"pid\":0}}"
            );
            Ok(())
        }
        "serve" | "" => {
            let dispatcher = Arc::new(RuntimeDispatcher::new(None)?);
            let (svc, rx) = ShimTaskService::new(dispatcher);
            serve_ttrpc(&sock_path, svc, rx).await
        }
        other => bail!("unknown containerd shim v2 action: {other}"),
    }
}
