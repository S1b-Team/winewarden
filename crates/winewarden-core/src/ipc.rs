use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::os::unix::net::UnixStream;

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

pub fn default_socket_path() -> PathBuf {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("winewarden").join("winewarden.sock");
    }
    PathBuf::from("/tmp").join("winewarden.sock")
}

pub fn default_pid_path() -> PathBuf {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("winewarden").join("winewarden.pid");
    }
    PathBuf::from("/tmp").join("winewarden.pid")
}

pub fn resolve_socket_path() -> PathBuf {
    if let Ok(value) = std::env::var("WINEWARDEN_SOCKET") {
        return PathBuf::from(value);
    }
    default_socket_path()
}

pub fn resolve_pid_path() -> PathBuf {
    if let Ok(value) = std::env::var("WINEWARDEN_PID") {
        return PathBuf::from(value);
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
