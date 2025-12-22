use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

use winewarden_core::config::{Config, ConfigPaths};
use winewarden_core::store::{ExecutableIdentity, TrustStore};
use winewarden_core::trust::TrustTier;
use winewarden_core::types::LiveMonitorConfig;
use winewarden_core::ipc::{WineWardenRequest, WineWardenResponse, RunRequestPayload, resolve_socket_path, send_request};
use monitor::{Monitor, RunRequest};
use policy_engine::PolicyEngine;
use prefix_manager::PrefixManager;
use reporting::SessionReport;
use runner::{Runner, RunnerRequest};

pub struct RunInputs {
    pub config_path: Option<PathBuf>,
    pub prefix: Option<PathBuf>,
    pub event_log: Option<PathBuf>,
    pub trust_override: Option<TrustTier>,
    pub no_run: bool,
    pub pirate_safe: bool,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub live_monitor: Option<LiveMonitorConfig>,
    pub use_daemon: bool,
}

pub fn execute(inputs: RunInputs) -> Result<()> {
    if inputs.use_daemon {
        return run_via_daemon(inputs);
    }
    let paths = ConfigPaths::resolve()?;
    let config_path = inputs.config_path.clone().unwrap_or(paths.config_path.clone());
    let config = Config::load(&config_path).with_context(|| {
        format!(
            "load config at {} (run `winewarden init` if missing)",
            config_path.display()
        )
    })?;

    let mut trust_store = TrustStore::load(&paths.trust_db_path)?;
    let identity = ExecutableIdentity::from_path(&inputs.executable)?;
    let base_tier = inputs.trust_override
        .or_else(|| trust_store.get_tier(&identity))
        .unwrap_or(config.trust.default_tier);

    let mut trust_tier = base_tier;
    if config.trust.pirate_safe || inputs.pirate_safe {
        trust_tier = downgrade_tier(trust_tier);
    }

    let prefix_root = inputs.prefix.unwrap_or_else(|| default_prefix_path(&paths, trust_tier));

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
        executable: inputs.executable.clone(),
        args: inputs.args.clone(),
        prefix_root: prefix_root.clone(),
        env: HashMap::new(),
    };
    let _command = runner.dry_run(&runner_request)?;

    let policy = PolicyEngine::from_config(config.clone(), &paths)?;
    let monitor = Monitor::new(policy);

    let request = RunRequest {
        executable: inputs.executable.clone(),
        args: inputs.args.clone(),
        prefix_root: prefix_root.clone(),
        trust_tier,
        event_log: inputs.event_log,
        no_run: inputs.no_run,
        live_monitor: inputs.live_monitor.clone(),
    };

    let report = monitor.run(request)?;

    trust_store.record_run(identity, trust_tier);
    trust_store.save(&paths.trust_db_path)?;

    store_report(&paths, &config, &report)?;
    println!("{}", report.human_summary());
    Ok(())
}

fn run_via_daemon(inputs: RunInputs) -> Result<()> {
    let socket_path = resolve_socket_path();
    let payload = RunRequestPayload {
        executable: inputs.executable,
        args: inputs.args,
        prefix_root: inputs.prefix,
        event_log: inputs.event_log,
        trust_override: inputs.trust_override,
        no_run: inputs.no_run,
        pirate_safe: inputs.pirate_safe,
        config_path: inputs.config_path,
        live_monitor: inputs.live_monitor.unwrap_or_default(),
    };
    let response = send_request(&socket_path, &WineWardenRequest::Run(payload))?;
    match response {
        WineWardenResponse::RunResult(result) => {
            println!("{}", result.summary);
            Ok(())
        }
        WineWardenResponse::Error(error) => Err(anyhow::anyhow!(error.message)),
        other => Err(anyhow::anyhow!("unexpected response: {other:?}")),
    }
}

fn store_report(paths: &ConfigPaths, config: &Config, report: &SessionReport) -> Result<()> {
    if !config.reporting.store_reports {
        return Ok(());
    }
    fs::create_dir_all(&paths.report_dir)
        .with_context(|| format!("create report dir {}", paths.report_dir.display()))?;

    let report_path = paths.report_dir.join(format!("{}.json", report.session_id));
    let contents = serde_json::to_string_pretty(report).context("render report JSON")?;
    fs::write(&report_path, contents)
        .with_context(|| format!("write report {}", report_path.display()))?;
    Ok(())
}

fn downgrade_tier(tier: TrustTier) -> TrustTier {
    match tier {
        TrustTier::Green => TrustTier::Yellow,
        TrustTier::Yellow => TrustTier::Red,
        TrustTier::Red => TrustTier::Red,
    }
}

fn default_prefix_path(paths: &ConfigPaths, tier: TrustTier) -> PathBuf {
    let tier_name = tier_string(tier);
    paths.data_dir.join("prefixes").join(tier_name)
}

fn tier_string(tier: TrustTier) -> &'static str {
    match tier {
        TrustTier::Green => "green",
        TrustTier::Yellow => "yellow",
        TrustTier::Red => "red",
    }
}
