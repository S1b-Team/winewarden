use std::path::{PathBuf};

use anyhow::Result;

use winewarden_core::config::{Config, ConfigPaths};
use winewarden_core::trust::TrustTier;
use winewarden_core::types::{AccessAttempt, AccessTarget};

mod decision;
pub mod rules;
pub mod trust;
pub mod zones;

pub use decision::{DecisionAction, PolicyDecision};

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    config: Config,
    sacred_zones: Vec<winewarden_core::paths::SacredZone>,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub prefix_root: PathBuf,
    pub trust_tier: TrustTier,
}

impl PolicyEngine {
    pub fn from_config(config: Config, paths: &ConfigPaths) -> Result<Self> {
        let sacred_zones = zones::sacred::load_sacred_zones(&config, paths)?;
        Ok(Self { config, sacred_zones })
    }

    pub fn evaluate(&self, attempt: &AccessAttempt, context: &PolicyContext) -> PolicyDecision {
        match &attempt.target {
            AccessTarget::Path(path) => rules::filesystem::evaluate_path(path, &context.prefix_root, &self.sacred_zones),
            AccessTarget::Network(_target) => rules::network::evaluate_network(&self.config, context.trust_tier),
            AccessTarget::Device(name) => PolicyDecision {
                action: DecisionAction::Deny,
                reason: format!("Device access blocked: {name}"),
                zone_label: Some("Sacred devices".to_string()),
                systemic_risk: true,
            },
            AccessTarget::Socket(name) => PolicyDecision {
                action: DecisionAction::Deny,
                reason: format!("System socket access blocked: {name}"),
                zone_label: Some("System sockets".to_string()),
                systemic_risk: true,
            },
        }
    }
}
