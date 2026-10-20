use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use monitor::{Monitor, RunRequest};
use policy_engine::PolicyEngine;
use prefix_manager::PrefixManager;
use reporting::live::{read_live_log, LiveEvent};
use reporting::SessionReport;
use winewarden_core::config::{Config, ConfigPaths};
use winewarden_core::trust::TrustTier;
use winewarden_core::types::PrefixChangeKind;

fn test_paths(root: &Path) -> ConfigPaths {
    ConfigPaths {
        config_path: root.join("config.toml"),
        data_dir: root.join("data"),
        report_dir: root.join("reports"),
        trust_db_path: root.join("trust.json"),
        snapshot_dir: root.join("snapshots"),
    }
}

fn write(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

#[test]
fn run_reports_files_added_modified_and_removed_since_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let paths = test_paths(root);
    let prefix_root = root.join("prefix");
    let kept = prefix_root.join("drive_c/windows/system32/kernel32.dll");
    let modified = prefix_root.join("drive_c/users/steam/save.dat");
    let removed = prefix_root.join("drive_c/users/steam/old.log");
    let added = prefix_root.join("drive_c/users/steam/new.cfg");
    write(&kept, "kernel");
    write(&modified, "slot1");
    write(&removed, "bye");

    let manager = PrefixManager::new(prefix_root.clone(), &paths);
    let snapshot = manager.create_snapshot().unwrap();
    let baseline = manager.latest_snapshot_path().unwrap().unwrap();

    // What a game session would leave behind.
    write(&added, "fullscreen=1");
    write(&modified, "slot1+slot2");
    fs::File::options()
        .write(true)
        .open(&modified)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(60))
        .unwrap();
    fs::remove_file(&removed).unwrap();

    let event_log = root.join("events.jsonl");
    fs::write(&event_log, "").unwrap();
    let live_dir = root.join("sessions");
    let policy = PolicyEngine::from_config(Config::default_config(), &paths).unwrap();
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
            prefix_baseline: Some(baseline),
        })
        .unwrap();

    let diff = report.prefix_diff.clone().expect("prefix diff in report");
    assert_eq!(diff.baseline_id, Some(snapshot.id));
    assert_eq!((diff.added, diff.removed, diff.modified), (1, 1, 1));
    assert!(!diff.truncated);
    let changes: Vec<_> = diff
        .changes
        .iter()
        .map(|c| (c.path.clone(), c.kind))
        .collect();
    // The listed changes come sorted by path.
    let expected = vec![
        (added.clone(), PrefixChangeKind::Added),
        (removed.clone(), PrefixChangeKind::Removed),
        (modified.clone(), PrefixChangeKind::Modified),
    ];
    assert_eq!(changes, expected);

    let summary = report.human_summary();
    assert!(
        summary.contains("1 added, 1 removed, 1 modified"),
        "{summary}"
    );
    assert!(summary.contains(&format!("+ {}", added.display())));
    assert!(summary.contains(&format!("~ {}", modified.display())));
    assert!(summary.contains(&format!("- {}", removed.display())));
    assert!(!summary.contains(&kept.display().to_string()));

    report.write_to(&paths.report_dir).unwrap();
    let stored: SessionReport = serde_json::from_str(
        &fs::read_to_string(paths.report_dir.join(format!("{}.json", report.session_id))).unwrap(),
    )
    .unwrap();
    assert_eq!(stored.prefix_diff, Some(diff.clone()));

    let events = read_live_log(&live_dir.join(format!("{}.jsonl", report.session_id))).unwrap();
    assert!(
        matches!(events.last(), Some(LiveEvent::End { prefix_diff: Some(d), .. }) if *d == diff),
        "{events:?}"
    );
}

#[test]
fn missing_baseline_leaves_diff_out_without_failing_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let paths = test_paths(root);
    let event_log = root.join("events.jsonl");
    fs::write(&event_log, "").unwrap();
    let policy = PolicyEngine::from_config(Config::default_config(), &paths).unwrap();
    let report = Monitor::new(policy)
        .run(RunRequest {
            executable: PathBuf::from("/bin/true"),
            args: Vec::new(),
            prefix_root: root.join("prefix"),
            trust_tier: TrustTier::Yellow,
            event_log: Some(event_log),
            no_run: true,
            live_monitor: None,
            live_log_dir: None,
            prefix_baseline: Some(root.join("snapshots/missing.json")),
        })
        .unwrap();
    assert!(report.prefix_diff.is_none());
}
