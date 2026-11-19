use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use sbx_daemon::ControlPlane;
use sbx_mcp::{serve_http_sse, serve_stdio, McpServer};
use tokio::io::BufReader;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "sbx-mcp", version, about = "Model Context Protocol (MCP) server for AI Sandbox")]
struct Args {
    /// Connect to an existing sbx-daemon socket instead of running an in-process ControlPlane
    #[arg(long, env = "SBX_DAEMON_SOCK")]
    daemon_socket: Option<PathBuf>,

    /// Path to containerd gRPC socket (used when running in-process ControlPlane)
    #[arg(long, env = "SBX_CONTAINERD_SOCK")]
    containerd_socket: Option<PathBuf>,

    /// Serve over HTTP/SSE instead of stdio (e.g., 127.0.0.1:8091)
    #[arg(long)]
    http_addr: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(io::stderr)
        .init();

    let args = Args::parse();
    let server = if let Some(sock) = args.daemon_socket {
        McpServer::with_daemon_socket(sock)
    } else {
        let cp = ControlPlane::connect(args.containerd_socket.as_deref(), None).await?;
        McpServer::with_control_plane(cp)
    };

    if let Some(addr) = args.http_addr {
        serve_http_sse(addr, server).await
    } else {
        let stdin = BufReader::new(tokio::io::stdin());
        let stdout = tokio::io::stdout();
        serve_stdio(server, stdin, stdout).await
    }
}
