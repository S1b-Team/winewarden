use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::Duration;
use uuid::Uuid;

use policy_engine::{DecisionAction, PolicyDecision};
use winewarden_core::trust::{TrustSignal, TrustTier};
use winewarden_core::types::{AccessAttempt, PrefixChangeKind, PrefixDiffSummary, RunMetadata};

pub mod live;

pub use live::{LiveEvent, LiveLog};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEvent {
    pub attempt: AccessAttempt,
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStats {
    pub total_attempts: u32,
    pub denied: u32,
    pub redirected: u32,
    pub virtualized: u32,
    pub allowed: u32,
    pub systemic_risks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    pub session_id: Uuid,
    pub metadata: RunMetadata,
    pub trust_signal: TrustSignal,
    pub events: Vec<ReportEvent>,
    pub stats: ReportStats,
    /// Prefix changes since the baseline snapshot; absent when no baseline
    /// was available or the comparison failed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_diff: Option<PrefixDiffSummary>,
}

impl SessionReport {
    pub fn new(metadata: RunMetadata, trust_signal: TrustSignal, events: Vec<ReportEvent>) -> Self {
        let stats = ReportStats::from_events(&events);
        let session_id = metadata.session_id;
        Self {
            session_id,
            metadata,
            trust_signal,
            events,
            stats,
            prefix_diff: None,
        }
    }

    pub fn duration(&self) -> Option<Duration> {
        let end = self.metadata.ended_at?;
        Some(end - self.metadata.started_at)
    }

    /// Writes the report as `<session_id>.json` under `dir`.
    pub fn write_to(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).with_context(|| format!("create report dir {}", dir.display()))?;
        let path = dir.join(format!("{}.json", self.session_id));
        let contents = serde_json::to_string_pretty(self).context("render report JSON")?;
        fs::write(&path, contents).with_context(|| format!("write report {}", path.display()))
    }

    pub fn human_summary(&self) -> String {
        let duration = self
            .duration()
            .map(format_duration)
            .unwrap_or_else(|| "unknown".to_string());
        let dangerous = self.stats.denied + self.stats.redirected + self.stats.virtualized;
        let safe_line = if dangerous == 0 {
            "No dangerous access attempts succeeded.".to_string()
        } else {
            format!("{dangerous} dangerous access attempts were blocked or redirected.")
        };

        let mut summary = format!(
            "You played for {duration}.\n{safe_line}\nYour system remains intact.\n{signal}",
            signal = self.trust_signal.message
        );
        if let Some(diff) = &self.prefix_diff {
            summary.push('\n');
            summary.push_str(&format_prefix_diff(diff));
        }
        summary
    }
}

impl ReportStats {
    pub fn from_events(events: &[ReportEvent]) -> Self {
        let mut stats = ReportStats {
            total_attempts: 0,
            denied: 0,
            redirected: 0,
            virtualized: 0,
            allowed: 0,
            systemic_risks: 0,
        };

        for event in events {
            stats.total_attempts = stats.total_attempts.saturating_add(1);
            if event.decision.systemic_risk {
                stats.systemic_risks = stats.systemic_risks.saturating_add(1);
            }
            match event.decision.action {
                DecisionAction::Allow => stats.allowed = stats.allowed.saturating_add(1),
                DecisionAction::Deny => stats.denied = stats.denied.saturating_add(1),
                DecisionAction::Redirect(_) => {
                    stats.redirected = stats.redirected.saturating_add(1)
                }
                DecisionAction::Virtualize(_) => {
                    stats.virtualized = stats.virtualized.saturating_add(1)
                }
            }
        }

        stats
    }
}

/// Human-readable prefix diff: one count line, then the listed changes.
pub fn format_prefix_diff(diff: &PrefixDiffSummary) -> String {
    if diff.is_empty() {
        return "Prefix unchanged since baseline snapshot.".to_string();
    }
    let mut out = format!(
        "Prefix changes since baseline snapshot: {} added, {} removed, {} modified.",
        diff.added, diff.removed, diff.modified
    );
    for change in &diff.changes {
        let marker = match change.kind {
            PrefixChangeKind::Added => '+',
            PrefixChangeKind::Removed => '-',
            PrefixChangeKind::Modified => '~',
        };
        out.push_str(&format!("\n  {marker} {}", change.path.display()));
    }
    if diff.truncated {
        let hidden = diff.total().saturating_sub(diff.changes.len() as u64);
        out.push_str(&format!("\n  ... and {hidden} more"));
    }
    out
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_seconds_f64().max(0.0) as i64;
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

pub fn trust_signal_for_tier(tier: TrustTier) -> TrustSignal {
    TrustSignal::from_tier(tier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use time::OffsetDateTime;
    use winewarden_core::types::PrefixChange;

    fn report() -> SessionReport {
        let metadata = RunMetadata {
            session_id: Uuid::new_v4(),
            executable: PathBuf::from("/games/game.exe"),
            args: Vec::new(),
            started_at: OffsetDateTime::now_utc(),
            ended_at: None,
            trust_tier: TrustTier::Yellow,
        };
        SessionReport::new(
            metadata,
            trust_signal_for_tier(TrustTier::Yellow),
            Vec::new(),
        )
    }

    #[test]
    fn report_without_prefix_diff_omits_field_and_old_json_parses() {
        let report = report();
        let json = serde_json::to_value(&report).unwrap();
        assert!(json.get("prefix_diff").is_none());
        let parsed: SessionReport = serde_json::from_value(json).unwrap();
        assert!(parsed.prefix_diff.is_none());
        assert!(!report.human_summary().contains("Prefix"));
    }

    #[test]
    fn summary_lists_changes_and_hidden_count() {
        let mut report = report();
        report.prefix_diff = Some(PrefixDiffSummary {
            added: 3,
            removed: 1,
            modified: 1,
            changes: vec![
                PrefixChange {
                    path: PathBuf::from("/p/a.txt"),
                    kind: PrefixChangeKind::Added,
                },
                PrefixChange {
                    path: PathBuf::from("/p/b.txt"),
                    kind: PrefixChangeKind::Removed,
                },
            ],
            truncated: true,
            ..PrefixDiffSummary::default()
        });
        let summary = report.human_summary();
        assert!(
            summary.contains("3 added, 1 removed, 1 modified"),
            "{summary}"
        );
        assert!(summary.contains("+ /p/a.txt"));
        assert!(summary.contains("- /p/b.txt"));
        assert!(summary.contains("... and 3 more"));

        let json = serde_json::to_string(&report).unwrap();
        let parsed: SessionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.prefix_diff, report.prefix_diff);
    }

    #[test]
    fn empty_diff_says_unchanged() {
        let mut report = report();
        report.prefix_diff = Some(PrefixDiffSummary::default());
        assert!(report.human_summary().contains("Prefix unchanged"));
    }
}
