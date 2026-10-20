use std::fs;
use std::path::{Path, PathBuf};

use monitor::{Monitor, RunRequest};
use policy_engine::{DecisionAction, PolicyEngine};
use reporting::live::{read_live_log, LiveEvent};
use time::OffsetDateTime;
use winewarden_core::config::{Config, ConfigPaths};
use winewarden_core::trust::TrustTier;
use winewarden_core::types::{AccessAttempt, AccessKind, AccessTarget};

fn test_paths(root: &Path) -> ConfigPaths {
    ConfigPaths {
        config_path: root.join("config.toml"),
        data_dir: root.join("data"),
        report_dir: root.join("reports"),
        trust_db_path: root.join("trust.json"),
        snapshot_dir: root.join("snapshots"),
    }
}

#[test]
fn event_log_run_writes_live_log() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let paths = test_paths(root);
    let prefix_root = root.join("prefix");
    let attempts = [
        prefix_root.join("drive_c/game.cfg"),
        PathBuf::from("/etc/shadow"),
    ];
    let event_log = root.join("events.jsonl");
    let lines: Vec<String> = attempts
        .iter()
        .map(|path| {
            serde_json::to_string(&AccessAttempt {
                timestamp: OffsetDateTime::now_utc(),
                kind: AccessKind::Read,
                target: AccessTarget::Path(path.clone()),
                note: None,
            })
            .unwrap()
        })
        .collect();
    fs::write(&event_log, lines.join("\n") + "\n").unwrap();

    let policy = PolicyEngine::from_config(Config::default_config(), &paths).unwrap();
    let live_dir = root.join("sessions");
    let report = Monitor::new(policy)
        .run(RunRequest {
            executable: PathBuf::from("/bin/true"),
            args: Vec::new(),
            prefix_root,
            trust_tier: TrustTier::Yellow,
            event_log: Some(event_log),
            no_run: true,
            live_monitor: None,
            live_log_dir: Some(live_dir.clone()),
            prefix_baseline: None,
        })
        .unwrap();

    let path = live_dir.join(format!("{}.jsonl", report.session_id));
    let events = read_live_log(&path).unwrap();
    assert_eq!(events.len(), 5, "{events:?}");
    assert!(
        matches!(&events[0], LiveEvent::Session { metadata } if metadata.session_id == report.session_id)
    );
    for (event, expected) in events[1..3].iter().zip(&report.events) {
        let LiveEvent::Access(event) = event else {
            panic!("expected access event, got {event:?}");
        };
        assert_eq!(
            format!("{:?}", event.attempt.target),
            format!("{:?}", expected.attempt.target)
        );
        assert_eq!(
            matches!(event.decision.action, DecisionAction::Allow),
            matches!(expected.decision.action, DecisionAction::Allow)
        );
    }
    assert!(matches!(events[3], LiveEvent::Trust(_)));
    assert!(
        matches!(&events[4], LiveEvent::End { stats, error: None, prefix_diff: None } if stats.total_attempts == report.stats.total_attempts)
    );
}

#[test]
fn failed_run_still_ends_live_log() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let policy = PolicyEngine::from_config(Config::default_config(), &test_paths(root)).unwrap();
    let live_dir = root.join("sessions");
    let result = Monitor::new(policy).run(RunRequest {
        executable: PathBuf::from("/bin/true"),
        args: Vec::new(),
        prefix_root: root.join("prefix"),
        trust_tier: TrustTier::Yellow,
        event_log: Some(root.join("missing.jsonl")),
        no_run: true,
        live_monitor: None,
        live_log_dir: Some(live_dir.clone()),
        prefix_baseline: None,
    });
    let error = result.unwrap_err().to_string();

    let log = fs::read_dir(&live_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let events = read_live_log(&log).unwrap();
    assert!(matches!(events.first(), Some(LiveEvent::Session { .. })));
    assert!(
        matches!(events.last(), Some(LiveEvent::End { error: Some(e), .. }) if e.contains(&error)),
        "{events:?}"
    );
}
