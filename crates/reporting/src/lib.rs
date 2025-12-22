use serde::{Deserialize, Serialize};
use time::Duration;
use uuid::Uuid;

use winewarden_core::trust::{TrustSignal, TrustTier};
use winewarden_core::types::{AccessAttempt, RunMetadata};
use policy_engine::{DecisionAction, PolicyDecision};

pub mod human;
pub mod json;
pub mod timeline;
pub mod redact;

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
        }
    }

    pub fn duration(&self) -> Option<Duration> {
        let end = self.metadata.ended_at?;
        Some(end - self.metadata.started_at)
    }

    pub fn human_summary(&self) -> String {
        let duration = self.duration().map(|d| format_duration(d)).unwrap_or_else(|| "unknown".to_string());
        let dangerous = self.stats.denied + self.stats.redirected + self.stats.virtualized;
        let safe_line = if dangerous == 0 {
            "No dangerous access attempts succeeded.".to_string()
        } else {
            format!("{dangerous} dangerous access attempts were blocked or redirected.")
        };

        format!(
            "You played for {duration}.\n{safe_line}\nYour system remains intact.\n{signal}",
            signal = self.trust_signal.message
        )
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
                DecisionAction::Redirect(_) => stats.redirected = stats.redirected.saturating_add(1),
                DecisionAction::Virtualize(_) => stats.virtualized = stats.virtualized.saturating_add(1),
            }
        }

        stats
    }
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
