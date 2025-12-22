use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub action: DecisionAction,
    pub reason: String,
    pub zone_label: Option<String>,
    pub systemic_risk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionAction {
    Allow,
    Deny,
    Redirect(PathBuf),
    Virtualize(PathBuf),
}
