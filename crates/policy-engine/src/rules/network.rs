use winewarden_core::config::{Config, NetworkMode};
use winewarden_core::trust::TrustTier;

use crate::decision::{DecisionAction, PolicyDecision};

pub fn evaluate_network(config: &Config, trust_tier: TrustTier) -> PolicyDecision {
    let reason = match config.network.mode {
        NetworkMode::Observe => "Network observed (no interference)",
        NetworkMode::Permissive => "Network allowed (permissive mode)",
    };

    let systemic_risk = matches!(trust_tier, TrustTier::Red) && config.network.block_on_malicious;
    let action = if systemic_risk {
        DecisionAction::Deny
    } else {
        DecisionAction::Allow
    };

    let final_reason = if systemic_risk {
        "Network denied due to high risk".to_string()
    } else {
        reason.to_string()
    };

    PolicyDecision {
        action,
        reason: final_reason,
        zone_label: Some("Network".to_string()),
        systemic_risk,
    }
}
