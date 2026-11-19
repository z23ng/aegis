use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use sbx_daemon::reaper::spawn_reaper_loop;
use sbx_daemon::server::{default_daemon_socket_path, serve_http, serve_uds};
use sbx_daemon::ControlPlane;
use sbx_proto::BackendKind;
use sbx_proto::SecurityPolicy;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "sbx-daemon", version, about = "AI Sandbox (sbx) Control Plane Daemon")]
struct Args {
    /// Path to control plane Unix domain socket
    #[arg(long, env = "SBX_DAEMON_SOCK")]
    socket: Option<PathBuf>,

    /// Path to containerd gRPC Unix socket
    #[arg(long, env = "SBX_CONTAINERD_SOCK")]
    containerd_socket: Option<PathBuf>,

    /// Optional HTTP REST API bind address (e.g., 127.0.0.1:8090)
    #[arg(long, env = "SBX_HTTP_ADDR")]
    http_addr: Option<SocketAddr>,

    /// Optional warm pool image to pre-warm on startup (format: image[:count])
    #[arg(long)]
    warm_image: Option<String>,

    /// Number of pre-warmed sandboxes when --warm-image is set
    #[arg(long, default_value_t = 2)]
    warm_count: usize,

    /// Daemon state & snapshot directory
    #[arg(long)]
    data_root: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(io::stderr)
        .init();

    let args = Args::parse();
    let sock_path = args.socket.unwrap_or_else(default_daemon_socket_path);
    let cp = ControlPlane::connect(args.containerd_socket.as_deref(), args.data_root).await?;

    if let Some(ref img) = args.warm_image {
        cp.configure_warm_pool(
            img,
            BackendKind::Native,
            args.warm_count,
            SecurityPolicy::default(),
        )
        .await?;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let reaper_handle = spawn_reaper_loop(
        Arc::clone(&cp),
        Duration::from_secs(5),
        shutdown_rx.clone(),
    );

    let http_task = if let Some(addr) = args.http_addr {
        let cp_http = Arc::clone(&cp);
        let rx_http = shutdown_rx.clone();
        Some(tokio::spawn(async move {
            let _ = serve_http(addr, cp_http, rx_http).await;
        }))
    } else {
        None
    };

    let uds_cp = Arc::clone(&cp);
    let uds_rx = shutdown_rx.clone();
    let uds_task = tokio::spawn(async move { serve_uds(&sock_path, uds_cp, uds_rx).await });

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(true);
    let _ = uds_task.await;
    if let Some(ht) = http_task {
        let _ = ht.await;
    }
    let _ = reaper_handle.await;
    cp.shutdown().await;
    Ok(())
}
