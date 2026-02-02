use std::cell::RefCell;
use std::path::PathBuf;

use anyhow::Result;

use winewarden_core::config::{Config, ConfigPaths};
use winewarden_core::trust::TrustTier;
use winewarden_core::types::{AccessAttempt, AccessTarget};

mod decision;
pub mod rules;
pub mod trust;
pub mod zones;

pub use decision::{DecisionAction, PolicyDecision};
pub use trust::scoring::{calculate_trust_score, BehaviorProfile, TrustScore, TrustScoringConfig};

/// Policy engine for evaluating access attempts and making security decisions.
#[derive(Debug)]
pub struct PolicyEngine {
    config: Config,
    sacred_zones: Vec<winewarden_core::paths::SacredZone>,
    /// Tracks process execution statistics
    process_tracker: RefCell<rules::process::ProcessTracker>,
    /// Tracks behavior profile for trust scoring
    behavior_profile: RefCell<BehaviorProfile>,
}

/// Context for policy evaluation
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub prefix_root: PathBuf,
    pub trust_tier: TrustTier,
}

impl PolicyEngine {
    /// Creates a new PolicyEngine from configuration
    pub fn from_config(config: Config, paths: &ConfigPaths) -> Result<Self> {
        let sacred_zones = zones::sacred::load_sacred_zones(&config, paths)?;
        Ok(Self {
            config,
            sacred_zones,
            process_tracker: RefCell::new(rules::process::ProcessTracker::new()),
            behavior_profile: RefCell::new(BehaviorProfile::new()),
        })
    }

    /// Evaluates an access attempt against the policy
    pub fn evaluate(&self, attempt: &AccessAttempt, context: &PolicyContext) -> PolicyDecision {
        // Update behavior profile based on attempt
        self.update_behavior_profile(attempt);

        let decision = match &attempt.target {
            AccessTarget::Path(path) => {
                rules::filesystem::evaluate_path(path, &context.prefix_root, &self.sacred_zones)
            }
            AccessTarget::Network(target) => {
                // Track network destinations
                self.behavior_profile
                    .borrow_mut()
                    .record_outbound_connection(&target.host);
                rules::network::evaluate_network(&self.config, context.trust_tier)
            }
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
        };

        // Track denied attempts
        if matches!(decision.action, DecisionAction::Deny) {
            self.behavior_profile
                .borrow_mut()
                .record_denied_attempt(&decision.reason);
        }

        decision
    }

    /// Evaluates a process spawn attempt
    pub fn evaluate_process_spawn(
        &self,
        process: &str,
        _context: &PolicyContext,
    ) -> PolicyDecision {
        let decision = rules::process::evaluate_process_spawn(
            process,
            &self.config.process,
            &mut self.process_tracker.borrow_mut(),
        );

        // Update behavior profile
        if matches!(decision.action, DecisionAction::Allow) {
            self.behavior_profile
                .borrow_mut()
                .record_child_process(process);
        } else {
            self.behavior_profile
                .borrow_mut()
                .record_denied_attempt(&decision.reason);
        }

        decision
    }

    /// Calculates current trust score based on observed behavior
    pub fn calculate_trust_score(&self, current_tier: TrustTier) -> TrustScore {
        let config = TrustScoringConfig::default();
        calculate_trust_score(current_tier, &self.behavior_profile.borrow(), &config)
    }

    /// Returns the current behavior profile
    pub fn behavior_profile(&self) -> std::cell::Ref<'_, BehaviorProfile> {
        self.behavior_profile.borrow()
    }

    /// Returns process tracking statistics
    pub fn process_tracker(&self) -> std::cell::Ref<'_, rules::process::ProcessTracker> {
        self.process_tracker.borrow()
    }

    /// Updates behavior profile based on an access attempt
    fn update_behavior_profile(&self, attempt: &AccessAttempt) {
        match attempt.kind {
            winewarden_core::types::AccessKind::Write => {
                if let AccessTarget::Path(path) = &attempt.target {
                    if let Some(path_str) = path.to_str() {
                        self.behavior_profile
                            .borrow_mut()
                            .record_file_modification(path_str);
                    }
                }
            }
            _ => {}
        }
    }

    /// Resets all tracking data
    pub fn reset_tracking(&self) {
        *self.process_tracker.borrow_mut() = rules::process::ProcessTracker::new();
        *self.behavior_profile.borrow_mut() = BehaviorProfile::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winewarden_core::types::AccessKind;

    fn create_test_engine() -> PolicyEngine {
        let config = Config::default_config();
        let paths = ConfigPaths {
            config_path: PathBuf::from("/tmp/config.toml"),
            data_dir: PathBuf::from("/tmp/data"),
            report_dir: PathBuf::from("/tmp/reports"),
            trust_db_path: PathBuf::from("/tmp/trust.json"),
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
        };
        PolicyEngine::from_config(config, &paths).unwrap()
    }

    #[test]
    fn test_evaluate_filesystem() {
        let engine = create_test_engine();
        let context = PolicyContext {
            prefix_root: PathBuf::from("/tmp/prefix"),
            trust_tier: TrustTier::Yellow,
        };

        let attempt = AccessAttempt {
            timestamp: time::OffsetDateTime::now_utc(),
            kind: AccessKind::Read,
            target: AccessTarget::Path(PathBuf::from("/tmp/prefix/file.txt")),
            note: None,
        };

        let decision = engine.evaluate(&attempt, &context);
        assert!(matches!(decision.action, DecisionAction::Allow));
    }

    #[test]
    fn test_evaluate_process() {
        let engine = create_test_engine();
        let context = PolicyContext {
            prefix_root: PathBuf::from("/tmp/prefix"),
            trust_tier: TrustTier::Yellow,
        };

        // Wine should be allowed
        let decision = engine.evaluate_process_spawn("wine64", &context);
        assert!(matches!(decision.action, DecisionAction::Allow));

        // Shell should be blocked
        let decision = engine.evaluate_process_spawn("bash", &context);
        assert!(matches!(decision.action, DecisionAction::Deny));
    }

    #[test]
    fn test_trust_score() {
        let engine = create_test_engine();

        // Initial score should be decent
        let score = engine.calculate_trust_score(TrustTier::Yellow);
        assert!(score.score > 50);

        // Add some suspicious behavior
        let context = PolicyContext {
            prefix_root: PathBuf::from("/tmp/prefix"),
            trust_tier: TrustTier::Yellow,
        };

        // Try to spawn a shell (will be denied)
        engine.evaluate_process_spawn("bash", &context);

        // Score should decrease
        let new_score = engine.calculate_trust_score(TrustTier::Yellow);
        assert!(new_score.score <= score.score);
    }
}
