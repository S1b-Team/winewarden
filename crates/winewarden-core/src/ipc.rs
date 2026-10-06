use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::trust::TrustTier;
use crate::types::LiveMonitorConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequestPayload {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub prefix_root: Option<PathBuf>,
    pub event_log: Option<PathBuf>,
    pub trust_override: Option<TrustTier>,
    pub no_run: bool,
    pub pirate_safe: bool,
    pub config_path: Option<PathBuf>,
    #[serde(default)]
    pub live_monitor: LiveMonitorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusPayload {
    pub started_at: OffsetDateTime,
    pub uptime_seconds: u64,
    pub active_sessions: u32,
    pub last_session_id: Option<Uuid>,
    pub last_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub session_id: Uuid,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum WineWardenRequest {
    Ping,
    Status,
    Run(RunRequestPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum WineWardenResponse {
    Pong,
    Status(StatusPayload),
    RunResult(RunResult),
    Error(ErrorPayload),
}

fn runtime_dir() -> Result<PathBuf> {
    let runtime = std::env::var("XDG_RUNTIME_DIR").context(
        "XDG_RUNTIME_DIR is not set; refusing to use /tmp for the daemon socket. \
         Set XDG_RUNTIME_DIR (or WINEWARDEN_SOCKET/WINEWARDEN_PID) explicitly.",
    )?;
    if runtime.trim().is_empty() {
        anyhow::bail!(
            "XDG_RUNTIME_DIR is empty; refusing to use /tmp for the daemon socket. \
             Set XDG_RUNTIME_DIR (or WINEWARDEN_SOCKET/WINEWARDEN_PID) explicitly."
        );
    }
    Ok(PathBuf::from(runtime))
}

pub fn default_socket_path() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("winewarden").join("winewarden.sock"))
}

pub fn default_pid_path() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("winewarden").join("winewarden.pid"))
}

pub fn resolve_socket_path() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("WINEWARDEN_SOCKET") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    default_socket_path()
}

pub fn resolve_pid_path() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("WINEWARDEN_PID") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    default_pid_path()
}

pub fn send_request(socket_path: &Path, request: &WineWardenRequest) -> Result<WineWardenResponse> {
    let stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connect to daemon at {}", socket_path.display()))?;
    let mut writer = BufWriter::new(stream.try_clone()?);
    let payload = serde_json::to_string(request).context("serialize request")?;
    writer.write_all(payload.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = serde_json::from_str(&line).context("parse response")?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn missing_runtime_dir_fails_closed() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("XDG_RUNTIME_DIR");
        std::env::remove_var("WINEWARDEN_SOCKET");
        std::env::remove_var("WINEWARDEN_PID");
        let socket_err = default_socket_path().unwrap_err().to_string();
        assert!(socket_err.contains("XDG_RUNTIME_DIR"), "{socket_err}");
        let pid_err = default_pid_path().unwrap_err().to_string();
        assert!(pid_err.contains("XDG_RUNTIME_DIR"), "{pid_err}");
        assert!(resolve_socket_path().is_err());
        assert!(resolve_pid_path().is_err());
    }

    #[test]
    fn socket_override_bypasses_runtime_dir() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("XDG_RUNTIME_DIR");
        std::env::set_var("WINEWARDEN_SOCKET", "/custom/winewarden.sock");
        std::env::set_var("WINEWARDEN_PID", "/custom/winewarden.pid");
        assert_eq!(
            resolve_socket_path().unwrap(),
            PathBuf::from("/custom/winewarden.sock")
        );
        assert_eq!(
            resolve_pid_path().unwrap(),
            PathBuf::from("/custom/winewarden.pid")
        );
        std::env::remove_var("WINEWARDEN_SOCKET");
        std::env::remove_var("WINEWARDEN_PID");
    }

    #[test]
    fn runtime_dir_provides_paths() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        std::env::remove_var("WINEWARDEN_SOCKET");
        std::env::remove_var("WINEWARDEN_PID");
        assert_eq!(
            default_socket_path().unwrap(),
            PathBuf::from("/run/user/1000/winewarden/winewarden.sock")
        );
        assert_eq!(
            resolve_pid_path().unwrap(),
            PathBuf::from("/run/user/1000/winewarden/winewarden.pid")
        );
        std::env::remove_var("XDG_RUNTIME_DIR");
    }
}
