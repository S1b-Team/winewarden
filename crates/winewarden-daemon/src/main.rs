use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use time::OffsetDateTime;

use winewarden_core::config::{Config, ConfigPaths};
use winewarden_core::ipc::{WineWardenRequest, WineWardenResponse, RunRequestPayload, RunResult, StatusPayload, resolve_pid_path, resolve_socket_path};
use winewarden_core::store::{ExecutableIdentity, TrustStore};
use winewarden_core::trust::TrustTier;

use monitor::{Monitor, RunRequest};
use policy_engine::PolicyEngine;
use prefix_manager::PrefixManager;
use reporting::SessionReport;
use runner::{Runner, RunnerRequest};

mod ipc;
mod scheduler;
mod store;

use ipc::DaemonState;
use store::EventStore;

fn main() -> Result<()> {
    let socket_path = resolve_socket_path();
    let pid_path = resolve_pid_path();
    let state = Arc::new(Mutex::new(DaemonState {
        started_at: OffsetDateTime::now_utc(),
        active_sessions: 0,
        last_session_id: None,
        last_summary: None,
        store: EventStore { location: socket_path.display().to_string() },
    }));

    write_pid_file(&pid_path)?;
    println!("WineWarden daemon listening on {}", socket_path.display());
    ipc::serve(&socket_path, state, handle_request)?;
    Ok(())
}

fn handle_request(request: WineWardenRequest, state: &Arc<Mutex<DaemonState>>) -> Result<WineWardenResponse> {
    match request {
        WineWardenRequest::Ping => Ok(WineWardenResponse::Pong),
        WineWardenRequest::Status => Ok(WineWardenResponse::Status(build_status(state))),
        WineWardenRequest::Run(payload) => handle_run(payload, state),
    }
}

fn build_status(state: &Arc<Mutex<DaemonState>>) -> StatusPayload {
    let guard = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let uptime = OffsetDateTime::now_utc() - guard.started_at;
    StatusPayload {
        started_at: guard.started_at,
        uptime_seconds: uptime.whole_seconds().max(0) as u64,
        active_sessions: guard.active_sessions,
        last_session_id: guard.last_session_id,
        last_summary: guard.last_summary.clone(),
    }
}

fn handle_run(payload: RunRequestPayload, state: &Arc<Mutex<DaemonState>>) -> Result<WineWardenResponse> {
    let report = execute_run(payload)?;
    let summary = report.human_summary();
    let result = RunResult {
        session_id: report.session_id,
        summary,
    };

    let mut guard = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.active_sessions = guard.active_sessions.saturating_add(1);
    guard.last_session_id = Some(result.session_id);
    guard.last_summary = Some(result.summary.clone());

    Ok(WineWardenResponse::RunResult(result))
}

fn execute_run(payload: RunRequestPayload) -> Result<SessionReport> {
    let paths = ConfigPaths::resolve()?;
    let config = load_config(payload.config_path.as_ref(), &paths)?;

    let mut trust_store = TrustStore::load(&paths.trust_db_path)?;
    let identity = ExecutableIdentity::from_path(&payload.executable)?;
    let base_tier = payload.trust_override
        .or_else(|| trust_store.get_tier(&identity))
        .unwrap_or(config.trust.default_tier);

    let mut trust_tier = base_tier;
    if config.trust.pirate_safe || payload.pirate_safe {
        trust_tier = downgrade_tier(trust_tier);
    }

    let prefix_root = payload.prefix_root.unwrap_or_else(|| default_prefix_path(&paths, trust_tier));

    if config.prefix.snapshot_before_first_run && !trust_store.records.contains_key(&identity.sha256) {
        let manager = PrefixManager::new(prefix_root.clone(), &paths);
        let _snapshot = manager.create_snapshot()?;
    }

    if config.prefix.hygiene_scan_on_run {
        let manager = PrefixManager::new(prefix_root.clone(), &paths);
        let findings = manager.scan_hygiene()?;
        if !findings.is_empty() {
            println!("Prefix hygiene findings detected: {}", findings.len());
        }
    }

    let runner = Runner::new();
    let runner_request = RunnerRequest {
        executable: payload.executable.clone(),
        args: payload.args.clone(),
        prefix_root: prefix_root.clone(),
        env: Default::default(),
    };
    let _command = runner.dry_run(&runner_request)?;

    let policy = PolicyEngine::from_config(config.clone(), &paths)?;
    let monitor = Monitor::new(policy);

    let live = if payload.live_monitor.enabled() {
        Some(payload.live_monitor)
    } else {
        None
    };

    let request = RunRequest {
        executable: payload.executable.clone(),
        args: payload.args.clone(),
        prefix_root: prefix_root.clone(),
        trust_tier,
        event_log: payload.event_log,
        no_run: payload.no_run,
        live_monitor: live,
    };

    let report = monitor.run(request)?;

    trust_store.record_run(identity, trust_tier);
    trust_store.save(&paths.trust_db_path)?;

    store_report(&paths, &config, &report)?;
    Ok(report)
}

fn store_report(paths: &ConfigPaths, config: &Config, report: &SessionReport) -> Result<()> {
    if !config.reporting.store_reports {
        return Ok(());
    }
    std::fs::create_dir_all(&paths.report_dir)
        .with_context(|| format!("create report dir {}", paths.report_dir.display()))?;

    let report_path = paths.report_dir.join(format!("{}.json", report.session_id));
    let contents = serde_json::to_string_pretty(report).context("render report JSON")?;
    std::fs::write(&report_path, contents)
        .with_context(|| format!("write report {}", report_path.display()))?;
    Ok(())
}

fn load_config(path: Option<&PathBuf>, paths: &ConfigPaths) -> Result<Config> {
    match path {
        Some(path) => Config::load(path),
        None => Config::load(&paths.config_path).or_else(|_| Ok(Config::default_config())),
    }
}

fn downgrade_tier(tier: TrustTier) -> TrustTier {
    match tier {
        TrustTier::Green => TrustTier::Yellow,
        TrustTier::Yellow => TrustTier::Red,
        TrustTier::Red => TrustTier::Red,
    }
}

fn default_prefix_path(paths: &ConfigPaths, tier: TrustTier) -> PathBuf {
    let tier_name = match tier {
        TrustTier::Green => "green",
        TrustTier::Yellow => "yellow",
        TrustTier::Red => "red",
    };
    paths.data_dir.join("prefixes").join(tier_name)
}

fn write_pid_file(path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create pid dir {}", parent.display()))?;
    }
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("write pid file {}", path.display()))?;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("set pid permissions {}", path.display()))?;
    Ok(())
}
