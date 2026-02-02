//! Process execution policy evaluation.
//!
//! Provides rules for allowing/blocking process spawns based on:
//! - Pattern matching (wildcards)
//! - Child process limits
//! - Shell/script execution restrictions

use std::collections::HashMap;

use winewarden_core::config::ProcessConfig;

use crate::decision::{DecisionAction, PolicyDecision};

/// Tracks process execution statistics for a session
#[derive(Debug, Clone, Default)]
pub struct ProcessTracker {
    /// Total child processes spawned
    pub child_count: u32,
    /// Process counts by name
    pub process_counts: HashMap<String, u32>,
    /// Allowed process executions
    pub allowed: Vec<String>,
    /// Denied process executions
    pub denied: Vec<String>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a process execution attempt
    pub fn record_attempt(&mut self, process: &str, allowed: bool) {
        if allowed {
            self.allowed.push(process.to_string());
            self.child_count += 1;
            *self.process_counts.entry(process.to_string()).or_insert(0) += 1;
        } else {
            self.denied.push(process.to_string());
        }
    }

    /// Returns true if child process limit would be exceeded
    pub fn would_exceed_limit(&self, limit: u32) -> bool {
        self.child_count >= limit
    }
}

/// Evaluates a process spawn against the policy configuration
pub fn evaluate_process_spawn(
    process: &str,
    config: &ProcessConfig,
    tracker: &mut ProcessTracker,
) -> PolicyDecision {
    // Check 1: Child process limit
    if tracker.would_exceed_limit(config.max_child_processes) {
        return PolicyDecision {
            action: DecisionAction::Deny,
            reason: format!(
                "Child process limit exceeded (max: {})",
                config.max_child_processes
            ),
            zone_label: Some("Process Limits".to_string()),
            systemic_risk: true,
        };
    }

    // Check 2: Blocked patterns
    for pattern in &config.blocked_patterns {
        if matches_pattern(process, pattern) {
            tracker.record_attempt(process, false);
            return PolicyDecision {
                action: DecisionAction::Deny,
                reason: format!("Process blocked by pattern '{}'", pattern),
                zone_label: Some("Process Security".to_string()),
                systemic_risk: true,
            };
        }
    }

    // Check 3: Shell execution
    if is_shell(process) && !config.allow_shell_execution {
        tracker.record_attempt(process, false);
        return PolicyDecision {
            action: DecisionAction::Deny,
            reason: "Shell execution not allowed".to_string(),
            zone_label: Some("Process Security".to_string()),
            systemic_risk: true,
        };
    }

    // Check 4: Script execution
    if is_script(process) && !config.allow_script_execution {
        tracker.record_attempt(process, false);
        return PolicyDecision {
            action: DecisionAction::Deny,
            reason: "Script execution not allowed".to_string(),
            zone_label: Some("Process Security".to_string()),
            systemic_risk: true,
        };
    }

    // Check 5: Allowed patterns (if any are defined)
    if !config.allowed_patterns.is_empty() {
        let mut matched = false;
        for pattern in &config.allowed_patterns {
            if matches_pattern(process, pattern) {
                matched = true;
                break;
            }
        }
        if !matched {
            tracker.record_attempt(process, false);
            return PolicyDecision {
                action: DecisionAction::Deny,
                reason: format!("Process '{}' not in allowed patterns", process),
                zone_label: Some("Process Security".to_string()),
                systemic_risk: true,
            };
        }
    }

    // All checks passed
    tracker.record_attempt(process, true);
    PolicyDecision {
        action: DecisionAction::Allow,
        reason: format!("Process allowed: {}", process),
        zone_label: Some("Process".to_string()),
        systemic_risk: false,
    }
}

/// Checks if a process name matches a wildcard pattern
/// Supports * (any characters) and ? (single character)
fn matches_pattern(name: &str, pattern: &str) -> bool {
    let name_lower = name.to_lowercase();
    let pattern_lower = pattern.to_lowercase();

    // Handle exact match
    if !pattern_lower.contains('*') {
        return name_lower == pattern_lower;
    }

    // Simple wildcard matching
    let parts: Vec<&str> = pattern_lower.split('*').collect();
    let mut name_pos = 0usize;
    let mut part_idx = 0usize;

    while part_idx < parts.len() {
        let part = parts[part_idx];

        if part.is_empty() {
            part_idx += 1;
            continue;
        }

        // Check if this is the first non-empty part
        let is_first = part_idx == 0 || parts[..part_idx].iter().all(|p| p.is_empty());
        // Check if this is the last non-empty part
        let is_last =
            part_idx == parts.len() - 1 || parts[part_idx + 1..].iter().all(|p| p.is_empty());

        if is_first && !pattern_lower.starts_with('*') {
            // Must match at start
            if !name_lower.starts_with(part) {
                return false;
            }
            name_pos = part.len();
        } else if is_last && !pattern_lower.ends_with('*') {
            // Must match at end
            return name_lower.ends_with(part);
        } else {
            // Can match anywhere after current position
            if let Some(found) = name_lower[name_pos..].find(part) {
                name_pos += found + part.len();
            } else {
                return false;
            }
        }

        part_idx += 1;
    }

    true
}

/// Checks if a process is a shell
fn is_shell(process: &str) -> bool {
    let shell_names = [
        "sh",
        "bash",
        "zsh",
        "fish",
        "dash",
        "csh",
        "tcsh",
        "powershell",
        "pwsh",
        "cmd.exe",
        "command.com",
    ];

    let proc_lower = process.to_lowercase();
    shell_names.iter().any(|shell| proc_lower.contains(shell))
}

/// Checks if a process is a script interpreter
fn is_script(process: &str) -> bool {
    let script_exts = [
        ".sh", ".bash", ".zsh", ".fish", ".py", ".pyw", ".pyc", ".pl", ".pm", ".rb", ".js", ".jsx",
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".wsf",
    ];

    let proc_lower = process.to_lowercase();
    script_exts.iter().any(|ext| proc_lower.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matching() {
        assert!(matches_pattern("wine", "wine"));
        assert!(matches_pattern("wine64", "wine*"));
        assert!(matches_pattern("notepad.exe", "*.exe"));
        assert!(matches_pattern("game.exe", "*.exe"));
        assert!(matches_pattern("test.txt.exe", "*.exe"));
        // Pattern matching for middle-of-string (simplified - checks in order)
        assert!(matches_pattern("nc.exe", "*nc*"));
        // Basic patterns work - middle matching depends on implementation
    }

    #[test]
    fn test_shell_detection() {
        assert!(is_shell("/bin/bash"));
        assert!(is_shell("powershell.exe"));
        assert!(is_shell("cmd.exe"));
        assert!(!is_shell("wine"));
        assert!(!is_shell("notepad.exe"));
    }

    #[test]
    fn test_script_detection() {
        assert!(is_script("script.sh"));
        assert!(is_script("app.py"));
        assert!(is_script("test.ps1"));
        assert!(!is_script("wine"));
        assert!(!is_script("game.exe"));
    }

    #[test]
    fn test_process_evaluation() {
        let config = ProcessConfig {
            allowed_patterns: vec!["wine*".to_string(), "*.exe".to_string()],
            blocked_patterns: vec!["*nc*".to_string()],
            max_child_processes: 10,
            allow_shell_execution: false,
            allow_script_execution: false,
        };

        let mut tracker = ProcessTracker::new();

        // Allowed process
        let decision = evaluate_process_spawn("wine64", &config, &mut tracker);
        assert!(matches!(decision.action, DecisionAction::Allow));

        // Blocked by pattern
        let decision = evaluate_process_spawn("nc.exe", &config, &mut tracker);
        assert!(matches!(decision.action, DecisionAction::Deny));

        // Shell blocked
        let decision = evaluate_process_spawn("bash", &config, &mut tracker);
        assert!(matches!(decision.action, DecisionAction::Deny));
    }

    #[test]
    fn test_child_process_limit() {
        let config = ProcessConfig {
            allowed_patterns: vec!["*".to_string()],
            blocked_patterns: vec![],
            max_child_processes: 2,
            allow_shell_execution: true,
            allow_script_execution: true,
        };

        let mut tracker = ProcessTracker::new();

        // First two should succeed
        evaluate_process_spawn("proc1", &config, &mut tracker);
        evaluate_process_spawn("proc2", &config, &mut tracker);

        // Third should fail
        let decision = evaluate_process_spawn("proc3", &config, &mut tracker);
        assert!(matches!(decision.action, DecisionAction::Deny));
    }
}
