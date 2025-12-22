use std::path::Path;

use winewarden_core::paths::{PathAction, SacredZone};

use crate::decision::{DecisionAction, PolicyDecision};
use crate::zones::redirects::fallback_redirect;

pub fn evaluate_path(path: &Path, prefix_root: &Path, zones: &[SacredZone]) -> PolicyDecision {
    for zone in zones {
        if zone.matches(path) {
            return apply_zone_rule(zone);
        }
    }

    if !path.starts_with(prefix_root) {
        return PolicyDecision {
            action: DecisionAction::Deny,
            reason: "Access outside prefix blocked".to_string(),
            zone_label: Some("Prefix boundary".to_string()),
            systemic_risk: true,
        };
    }

    PolicyDecision {
        action: DecisionAction::Allow,
        reason: "Access within prefix allowed".to_string(),
        zone_label: None,
        systemic_risk: false,
    }
}

fn apply_zone_rule(zone: &SacredZone) -> PolicyDecision {
    match zone.action {
        PathAction::Allow => PolicyDecision {
            action: DecisionAction::Allow,
            reason: format!("Access allowed: {}", zone.label),
            zone_label: Some(zone.label.clone()),
            systemic_risk: false,
        },
        PathAction::Deny => PolicyDecision {
            action: DecisionAction::Deny,
            reason: format!("Access denied: {}", zone.label),
            zone_label: Some(zone.label.clone()),
            systemic_risk: true,
        },
        PathAction::Redirect => {
            let redirect_to = zone.redirect_to.clone().unwrap_or_else(fallback_redirect);
            PolicyDecision {
                action: DecisionAction::Redirect(redirect_to),
                reason: format!("Access redirected: {}", zone.label),
                zone_label: Some(zone.label.clone()),
                systemic_risk: true,
            }
        }
        PathAction::Virtualize => {
            let redirect_to = zone.redirect_to.clone().unwrap_or_else(fallback_redirect);
            PolicyDecision {
                action: DecisionAction::Virtualize(redirect_to),
                reason: format!("Access virtualized: {}", zone.label),
                zone_label: Some(zone.label.clone()),
                systemic_risk: true,
            }
        }
    }
}
