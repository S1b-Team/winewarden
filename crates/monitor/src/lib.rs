use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use winewarden_core::trust::TrustTier;
use winewarden_core::types::{AccessAttempt, LiveMonitorConfig, RunMetadata};
use policy_engine::{PolicyContext, PolicyEngine};
use reporting::{ReportEvent, SessionReport, trust_signal_for_tier};

pub mod fs_watch;
pub mod net_watch;
pub mod proc_watch;
pub mod signals;

pub trait EventSource {
    fn next_event(&mut self) -> Result<Option<AccessAttempt>>;
}

pub struct NoopEventSource;

impl EventSource for NoopEventSource {
    fn next_event(&mut self) -> Result<Option<AccessAttempt>> {
        Ok(None)
    }
}

pub struct JsonlEventSource {
    reader: BufReader<File>,
}

impl JsonlEventSource {
    pub fn from_path(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("open event log {}", path.display()))?;
        Ok(Self {
            reader: BufReader::new(file),
        })
    }
}

impl EventSource for JsonlEventSource {
    fn next_event(&mut self) -> Result<Option<AccessAttempt>> {
        let mut line = String::new();
        let bytes = self.reader.read_line(&mut line)?;
        if bytes == 0 {
            return Ok(None);
        }
        let event: AccessAttempt = serde_json::from_str(&line).context("parse event JSON")?;
        Ok(Some(event))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub prefix_root: PathBuf,
    pub trust_tier: TrustTier,
    pub event_log: Option<PathBuf>,
    pub no_run: bool,
    pub live_monitor: Option<LiveMonitorConfig>,
}

pub struct Monitor {
    policy: PolicyEngine,
}

impl Monitor {
    pub fn new(policy: PolicyEngine) -> Self {
        Self { policy }
    }

    pub fn run(&self, request: RunRequest) -> Result<SessionReport> {
        let session_id = Uuid::new_v4();
        let started_at = OffsetDateTime::now_utc();
        let mut metadata = RunMetadata {
            session_id,
            executable: request.executable.clone(),
            args: request.args.clone(),
            started_at,
            ended_at: None,
            trust_tier: request.trust_tier,
        };

        let mut child = None;
        if !request.no_run {
            child = Some(self.spawn_process(&request.executable, &request.args)?);
        }

        let policy_context = PolicyContext {
            prefix_root: request.prefix_root.clone(),
            trust_tier: request.trust_tier,
        };

        let mut evaluated = Vec::new();
        if let Some(mut child) = child {
            let live_config = request.live_monitor.clone().unwrap_or_default();
            let mut fs_watcher = if live_config.fs {
                Some(fs_watch::FsWatcher::new(&request.prefix_root)?)
            } else {
                None
            };
            let mut seen_pids = HashSet::new();
            let mut seen_net = HashSet::new();
            seen_pids.insert(child.id());

            while child.try_wait()?.is_none() {
                if let Some(watcher) = fs_watcher.as_mut() {
                    for event in watcher.drain() {
                        let decision = self.policy.evaluate(&event, &policy_context);
                        evaluated.push(ReportEvent { attempt: event, decision });
                    }
                }
                if live_config.proc {
                    for event in proc_watch::collect_process_events(child.id(), &mut seen_pids) {
                        let decision = self.policy.evaluate(&event, &policy_context);
                        evaluated.push(ReportEvent { attempt: event, decision });
                    }
                }
                if live_config.net {
                    for event in net_watch::collect_network_events(child.id(), &mut seen_net) {
                        let decision = self.policy.evaluate(&event, &policy_context);
                        evaluated.push(ReportEvent { attempt: event, decision });
                    }
                }
                if live_config.enabled() {
                    sleep(Duration::from_millis(live_config.poll_interval_ms));
                } else {
                    child.wait()?;
                    break;
                }
            }
        }

        let mut source: Box<dyn EventSource> = match &request.event_log {
            Some(path) => Box::new(JsonlEventSource::from_path(path)?),
            None => Box::new(NoopEventSource),
        };

        while let Some(event) = source.next_event()? {
            let decision = self.policy.evaluate(&event, &policy_context);
            evaluated.push(ReportEvent { attempt: event, decision });
        }

        metadata.ended_at = Some(OffsetDateTime::now_utc());
        let trust_signal = trust_signal_for_tier(request.trust_tier);
        Ok(SessionReport::new(metadata, trust_signal, evaluated))
    }

    fn spawn_process(&self, executable: &Path, args: &[String]) -> Result<std::process::Child> {
        let child = Command::new(executable)
            .args(args)
            .spawn()
            .with_context(|| format!("launch {}", executable.display()))?;

        Ok(child)
    }
}
