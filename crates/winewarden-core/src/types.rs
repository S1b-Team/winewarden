use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::trust::TrustTier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    pub session_id: Uuid,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub started_at: OffsetDateTime,
    pub ended_at: Option<OffsetDateTime>,
    pub trust_tier: TrustTier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessAttempt {
    pub timestamp: OffsetDateTime,
    pub kind: AccessKind,
    pub target: AccessTarget,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessKind {
    Read,
    Write,
    Execute,
    Network,
    Device,
    SystemSocket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessTarget {
    Path(PathBuf),
    Network(NetworkTarget),
    Device(String),
    Socket(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTarget {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveMonitorConfig {
    pub fs: bool,
    pub proc: bool,
    pub net: bool,
    pub poll_interval_ms: u64,
}

impl LiveMonitorConfig {
    pub fn enabled(&self) -> bool {
        self.fs || self.proc || self.net
    }
}

impl Default for LiveMonitorConfig {
    fn default() -> Self {
        Self {
            fs: false,
            proc: false,
            net: false,
            poll_interval_ms: 250,
        }
    }
}
