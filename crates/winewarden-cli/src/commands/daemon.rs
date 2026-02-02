use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

use winewarden_core::ipc::{
    resolve_pid_path, resolve_socket_path, send_request, WineWardenRequest, WineWardenResponse,
};

#[derive(Debug)]
pub enum DaemonAction {
    Start {
        socket: Option<PathBuf>,
        pid: Option<PathBuf>,
    },
    Stop {
        pid: Option<PathBuf>,
    },
    Ping {
        socket: Option<PathBuf>,
    },
    Status {
        socket: Option<PathBuf>,
    },
    SocketPath,
    PidPath,
}

pub fn execute(action: DaemonAction) -> Result<()> {
    match action {
        DaemonAction::Start { socket, pid } => start_daemon(socket, pid),
        DaemonAction::Stop { pid } => stop_daemon(pid),
        DaemonAction::Ping { socket } => ping(socket),
        DaemonAction::Status { socket } => status(socket),
        DaemonAction::SocketPath => {
            println!("{}", resolve_socket_path().display());
            Ok(())
        }
        DaemonAction::PidPath => {
            println!("{}", resolve_pid_path().display());
            Ok(())
        }
    }
}

fn start_daemon(socket: Option<PathBuf>, pid: Option<PathBuf>) -> Result<()> {
    let mut cmd = Command::new("winewarden-daemon");
    if let Some(socket) = socket {
        cmd.env("WINEWARDEN_SOCKET", socket);
    }
    if let Some(pid) = pid {
        cmd.env("WINEWARDEN_PID", pid);
    }
    cmd.spawn().context("start winewarden-daemon")?;
    println!("WineWarden daemon started.");
    Ok(())
}

fn stop_daemon(pid_override: Option<PathBuf>) -> Result<()> {
    let pid_path = pid_override.unwrap_or_else(resolve_pid_path);
    let pid_text = std::fs::read_to_string(&pid_path)
        .with_context(|| format!("read pid file {}", pid_path.display()))?;
    let pid: i32 = pid_text.trim().parse().context("parse pid")?;
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc != 0 {
        return Err(anyhow::anyhow!("failed to stop daemon with pid {pid}"));
    }
    println!("WineWarden daemon stopped.");
    Ok(())
}

fn ping(socket_override: Option<PathBuf>) -> Result<()> {
    let socket = socket_override.unwrap_or_else(resolve_socket_path);
    let response = send_request(&socket, &WineWardenRequest::Ping)?;
    match response {
        WineWardenResponse::Pong => {
            println!("WineWarden daemon is healthy.");
            Ok(())
        }
        WineWardenResponse::Error(error) => Err(anyhow::anyhow!(error.message)),
        other => Err(anyhow::anyhow!("unexpected response: {other:?}")),
    }
}

fn status(socket_override: Option<PathBuf>) -> Result<()> {
    let socket = socket_override.unwrap_or_else(resolve_socket_path);
    let response = send_request(&socket, &WineWardenRequest::Status)?;
    match response {
        WineWardenResponse::Status(payload) => {
            println!("WineWarden daemon is running.");
            println!("Uptime: {}s", payload.uptime_seconds);
            if let Some(summary) = payload.last_summary {
                println!("Last session: {}", summary);
            }
            Ok(())
        }
        WineWardenResponse::Error(error) => Err(anyhow::anyhow!(error.message)),
        other => Err(anyhow::anyhow!("unexpected response: {other:?}")),
    }
}
