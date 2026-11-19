mod init;
mod repl;
mod spawner;
mod transport;

use std::env;
use std::os::fd::RawFd;
use std::process;

use transport::{run_transport_loop, TransportMode};

fn parse_args() -> Result<TransportMode, String> {
    let mut args = env::args().skip(1);
    let mut mode: Option<TransportMode> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen-fd" => {
                let val = args
                    .next()
                    .ok_or_else(|| String::from("missing value for --listen-fd"))?;
                let fd: RawFd = val
                    .parse()
                    .map_err(|_| format!("invalid fd for --listen-fd: {val}"))?;
                mode = Some(TransportMode::ListenFd(fd));
            }
            "--socket" => {
                let path = args
                    .next()
                    .ok_or_else(|| String::from("missing value for --socket"))?;
                mode = Some(TransportMode::UnixSocket(path));
            }
            "--vsock-port" => {
                let val = args
                    .next()
                    .ok_or_else(|| String::from("missing value for --vsock-port"))?;
                let port: u32 = val
                    .parse()
                    .map_err(|_| format!("invalid port for --vsock-port: {val}"))?;
                mode = Some(TransportMode::VsockPort(port));
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
    }

    Ok(mode.unwrap_or_else(|| TransportMode::UnixSocket(String::from("/run/sbx-agent.sock"))))
}

fn main() {
    init::init_pid1_env();

    let mode = match parse_args() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("sbx-guest-agent: {e}");
            process::exit(2);
        }
    };

    if let Err(e) = run_transport_loop(mode) {
        eprintln!("sbx-guest-agent: transport loop exited with error: {e}");
        process::exit(1);
    }
}
