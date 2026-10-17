//! Feeds session data from the monitor into the TUI state.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use policy_engine::DecisionAction;
use reporting::{ReportEvent, SessionReport};
use winewarden_core::types::{AccessKind, AccessTarget};

use crate::tui::app::{App, ProcessStatus};

/// Reads a finished session report written by `winewarden run`.
pub fn read_report(path: &Path) -> Result<SessionReport> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("read report {}", path.display()))?;
    serde_json::from_str(&contents).context("parse report JSON")
}

/// Loads a finished session into the app.
pub fn load_report(app: &mut App, report: SessionReport) {
    app.set_session(&report.metadata);
    for event in report.events {
        apply_event(app, event);
    }
    if report.metadata.ended_at.is_some() {
        for process in &mut app.processes {
            process.status = ProcessStatus::Terminated;
        }
    }
}

/// Applies a single evaluated access attempt to the app.
pub fn apply_event(app: &mut App, event: ReportEvent) {
    let ReportEvent { attempt, decision } = event;
    match (&attempt.kind, &attempt.target) {
        (_, AccessTarget::Network(target)) => {
            app.add_connection(target.host.clone(), target.port, target.protocol.clone());
        }
        (AccessKind::Execute, AccessTarget::Path(path)) => {
            let name = path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .into_owned();
            let pid = attempt.note.as_deref().and_then(parse_pid).unwrap_or(0);
            app.add_process(name, pid);
        }
        _ => {}
    }
    let denied = matches!(decision.action, DecisionAction::Deny);
    app.add_event(attempt, denied);
}

/// Extracts the pid from process watcher notes ("child process pid 1234").
fn parse_pid(note: &str) -> Option<u32> {
    note.strip_prefix("child process pid ")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_engine::PolicyDecision;
    use std::path::PathBuf;
    use time::OffsetDateTime;
    use winewarden_core::trust::{TrustSignal, TrustTier};
    use winewarden_core::types::{AccessAttempt, NetworkTarget, RunMetadata};

    fn event(
        kind: AccessKind,
        target: AccessTarget,
        note: &str,
        action: DecisionAction,
    ) -> ReportEvent {
        ReportEvent {
            attempt: AccessAttempt {
                timestamp: OffsetDateTime::now_utc(),
                kind,
                target,
                note: Some(note.to_string()),
            },
            decision: PolicyDecision {
                action,
                reason: String::new(),
                zone_label: None,
                systemic_risk: false,
            },
        }
    }

    fn path(p: &str) -> AccessTarget {
        AccessTarget::Path(PathBuf::from(p))
    }

    #[test]
    fn counts_denied_events() {
        let mut app = App::new();
        apply_event(
            &mut app,
            event(AccessKind::Read, path("/a"), "", DecisionAction::Allow),
        );
        apply_event(
            &mut app,
            event(AccessKind::Read, path("/b"), "", DecisionAction::Deny),
        );
        let redirect = DecisionAction::Redirect(PathBuf::from("/c"));
        apply_event(&mut app, event(AccessKind::Write, path("/c"), "", redirect));

        assert_eq!(app.total_events, 3);
        assert_eq!(app.denied_events, 1);
        assert!(app.connections.is_empty());
        assert!(app.processes.is_empty());
    }

    #[test]
    fn network_target_becomes_connection() {
        let mut app = App::new();
        let target = AccessTarget::Network(NetworkTarget {
            host: "10.0.0.1".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
        });
        for _ in 0..2 {
            let event = event(
                AccessKind::Network,
                target.clone(),
                "",
                DecisionAction::Allow,
            );
            apply_event(&mut app, event);
        }

        assert_eq!(app.connections.len(), 1);
        assert_eq!(app.connections[0].host, "10.0.0.1");
        assert_eq!(app.connections[0].port, 443);
        assert_eq!(app.connections[0].connection_count, 2);
        assert_eq!(app.total_events, 2);
    }

    #[test]
    fn exec_events_become_processes() {
        let mut app = App::new();
        let watched = event(
            AccessKind::Execute,
            path("/usr/bin/wineserver"),
            "child process pid 4242",
            DecisionAction::Allow,
        );
        let spawned = event(
            AccessKind::Execute,
            path("C:/game/launcher.exe"),
            "Process spawn: launcher.exe",
            DecisionAction::Deny,
        );
        apply_event(&mut app, watched);
        apply_event(&mut app, spawned);

        assert_eq!(app.processes.len(), 2);
        assert_eq!(app.processes[0].name, "wineserver");
        assert_eq!(app.processes[0].pid, 4242);
        assert_eq!(app.processes[1].name, "launcher.exe");
        assert_eq!(app.processes[1].pid, 0);
        assert_eq!(app.denied_events, 1);
    }

    #[test]
    fn load_report_sets_session() {
        let ended_at = OffsetDateTime::now_utc() - time::Duration::minutes(5);
        let metadata = RunMetadata {
            session_id: uuid::Uuid::new_v4(),
            executable: PathBuf::from("/games/game.exe"),
            args: Vec::new(),
            started_at: ended_at - time::Duration::seconds(90),
            ended_at: Some(ended_at),
            trust_tier: TrustTier::Red,
        };
        let events = vec![event(
            AccessKind::Execute,
            path("/usr/bin/wine"),
            "child process pid 7",
            DecisionAction::Allow,
        )];
        let report = SessionReport::new(metadata, TrustSignal::from_tier(TrustTier::Red), events);

        let mut app = App::new();
        load_report(&mut app, report);

        assert_eq!(app.trust_tier, TrustTier::Red);
        assert_eq!(app.session_duration(), "00:01:30");
        assert_eq!(app.processes[0].status, ProcessStatus::Terminated);
        assert_eq!(app.total_events, 1);
    }
}
