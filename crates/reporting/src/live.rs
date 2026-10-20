//! Live session log: one JSON event per line, written while a session runs.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use policy_engine::TrustScore;
use serde::{Deserialize, Serialize};
use winewarden_core::config::ConfigPaths;
use winewarden_core::types::{PrefixDiffSummary, RunMetadata};

use crate::{ReportEvent, ReportStats};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveEvent {
    Session {
        metadata: RunMetadata,
    },
    Access(ReportEvent),
    Process {
        pid: u32,
        exe: PathBuf,
        state: ProcessState,
    },
    Trust(TrustScore),
    End {
        stats: ReportStats,
        /// Why the session stopped early; absent when it finished normally
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// Prefix changes since the baseline snapshot; absent without one
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix_diff: Option<PrefixDiffSummary>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Started,
    Exited,
}

/// Directory for live session logs: `<data_dir>/sessions`, next to the
/// reports. It stays outside the sandbox's writable paths (`/run` and `/tmp`
/// are writable there), so the monitored app can't rewrite its own log.
pub fn default_live_dir(paths: &ConfigPaths) -> PathBuf {
    paths.data_dir.join("sessions")
}

/// Appends live events to a JSONL file. A failed write is reported once and
/// disables the log so the session keeps running.
#[derive(Debug)]
pub struct LiveLog {
    file: Option<File>,
    path: PathBuf,
}

impl LiveLog {
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .with_context(|| format!("create live log dir {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create live log {}", path.display()))?;
        Ok(Self {
            file: Some(file),
            path: path.to_path_buf(),
        })
    }

    pub fn disabled() -> Self {
        Self {
            file: None,
            path: PathBuf::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.file.is_some()
    }

    pub fn write(&mut self, event: &LiveEvent) {
        let Some(file) = self.file.as_mut() else {
            return;
        };
        let result = serde_json::to_string(event)
            .map_err(anyhow::Error::from)
            .and_then(|mut line| {
                line.push('\n');
                file.write_all(line.as_bytes())?;
                Ok(())
            });
        if let Err(e) = result {
            eprintln!("Warning: live log {} disabled: {e}", self.path.display());
            self.file = None;
        }
    }
}

/// Reads every event from a live log.
pub fn read_live_log(path: &Path) -> Result<Vec<LiveEvent>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("read live log {}", path.display()))?;
    contents
        .lines()
        .map(|line| serde_json::from_str(line).context("parse live event"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_engine::{DecisionAction, PolicyDecision};
    use std::os::unix::fs::PermissionsExt;
    use time::OffsetDateTime;
    use winewarden_core::trust::TrustTier;
    use winewarden_core::types::{AccessAttempt, AccessKind, AccessTarget};

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("winewarden-live-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn roundtrip() {
        let dir = temp_dir();
        let path = dir.join("sessions").join("s.jsonl");
        let metadata = RunMetadata {
            session_id: uuid::Uuid::new_v4(),
            executable: PathBuf::from("/games/game.exe"),
            args: vec!["-windowed".to_string()],
            started_at: OffsetDateTime::now_utc(),
            ended_at: None,
            trust_tier: TrustTier::Yellow,
        };
        let access = ReportEvent {
            attempt: AccessAttempt {
                timestamp: OffsetDateTime::now_utc(),
                kind: AccessKind::Read,
                target: AccessTarget::Path(PathBuf::from("/etc/passwd")),
                note: None,
            },
            decision: PolicyDecision {
                action: DecisionAction::Deny,
                reason: "sacred".to_string(),
                zone_label: None,
                systemic_risk: true,
            },
        };

        let mut log = LiveLog::create(&path).unwrap();
        log.write(&LiveEvent::Session { metadata });
        log.write(&LiveEvent::Access(access.clone()));
        log.write(&LiveEvent::Process {
            pid: 42,
            exe: PathBuf::from("/games/game.exe"),
            state: ProcessState::Started,
        });
        log.write(&LiveEvent::Trust(TrustScore::new(80, vec![])));
        log.write(&LiveEvent::End {
            stats: ReportStats::from_events(&[access]),
            error: None,
            prefix_diff: None,
        });

        let events = read_live_log(&path).unwrap();
        assert_eq!(events.len(), 5);
        assert!(matches!(events[0], LiveEvent::Session { .. }));
        assert!(matches!(
            &events[1],
            LiveEvent::Access(e) if matches!(e.decision.action, DecisionAction::Deny)
        ));
        assert!(matches!(
            events[2],
            LiveEvent::Process {
                pid: 42,
                state: ProcessState::Started,
                ..
            }
        ));
        assert!(matches!(
            &events[3],
            LiveEvent::Trust(score) if score.score == 80 && score.recommended_tier == TrustTier::Green
        ));
        assert!(matches!(
            &events[4],
            LiveEvent::End { stats, error: None, prefix_diff: None } if stats.denied == 1
        ));
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("\"error\""));
        assert!(!raw.contains("prefix_diff"));

        let mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn end_line_without_error_still_parses() {
        let line = r#"{"type":"end","stats":{"total_attempts":0,"denied":0,"redirected":0,"virtualized":0,"allowed":0,"systemic_risks":0}}"#;
        let event: LiveEvent = serde_json::from_str(line).unwrap();
        assert!(matches!(
            event,
            LiveEvent::End {
                error: None,
                prefix_diff: None,
                ..
            }
        ));
    }

    #[test]
    fn write_failure_disables_log() {
        let mut log = LiveLog::create(Path::new("/dev/full")).unwrap();
        let event = LiveEvent::Trust(TrustScore::new(50, vec![]));
        log.write(&event);
        assert!(!log.is_enabled());
        log.write(&event);
    }
}
