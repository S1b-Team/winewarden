use crate::decision::{DecisionAction, PolicyDecision};

pub fn evaluate_process_spawn(process: &str) -> PolicyDecision {
    PolicyDecision {
        action: DecisionAction::Allow,
        reason: format!("Process allowed: {process}"),
        zone_label: Some("Process".to_string()),
        systemic_risk: false,
    }
}
