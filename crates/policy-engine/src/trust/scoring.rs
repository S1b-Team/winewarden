//! Trust scoring algorithm for dynamic risk assessment.
//!
//! Calculates trust scores based on observed behavior patterns during execution.
//! Scores can trigger trust tier adjustments and policy enforcement changes.

use winewarden_core::trust::TrustTier;

/// Trust scoring configuration
#[derive(Debug, Clone)]
pub struct TrustScoringConfig {
    /// Threshold for considering behavior suspicious (0-100)
    pub suspicion_threshold: u32,
    /// Weight for network activity in scoring
    pub network_activity_weight: f32,
    /// Weight for file system activity in scoring
    pub filesystem_activity_weight: f32,
    /// Weight for process activity in scoring
    pub process_activity_weight: f32,
    /// Penalty for accessing sensitive paths
    pub sensitive_path_penalty: i32,
    /// Penalty for outbound network connections
    pub outbound_connection_penalty: i32,
    /// Penalty for spawning many child processes
    pub child_process_penalty: i32,
    /// Bonus for consistent behavior
    pub consistency_bonus: i32,
}

impl Default for TrustScoringConfig {
    fn default() -> Self {
        Self {
            suspicion_threshold: 50,
            network_activity_weight: 0.4,
            filesystem_activity_weight: 0.3,
            process_activity_weight: 0.3,
            sensitive_path_penalty: -10,
            outbound_connection_penalty: -5,
            child_process_penalty: -3,
            consistency_bonus: 5,
        }
    }
}

/// Observed behavior patterns for scoring
#[derive(Debug, Clone, Default)]
pub struct BehaviorProfile {
    /// Number of sensitive path access attempts
    pub sensitive_path_attempts: u32,
    /// Number of unique outbound network destinations
    pub unique_destinations: u32,
    /// Number of DNS queries made
    pub dns_query_count: u32,
    /// Number of child processes spawned
    pub child_process_count: u32,
    /// Number of file modifications
    pub file_modifications: u32,
    /// Number of denied access attempts
    pub denied_attempts: u32,
    /// Suspicious patterns detected
    pub suspicious_patterns: Vec<String>,
}

impl BehaviorProfile {
    /// Creates a new empty behavior profile
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a sensitive path access attempt
    pub fn record_sensitive_path(&mut self, path: &str) {
        self.sensitive_path_attempts += 1;
        self.suspicious_patterns.push(format!("Accessed: {}", path));
    }

    /// Records an outbound connection
    pub fn record_outbound_connection(&mut self, host: &str) {
        self.unique_destinations += 1;
        if self.unique_destinations > 10 {
            self.suspicious_patterns
                .push(format!("Many connections: {}", host));
        }
    }

    /// Records a child process spawn
    pub fn record_child_process(&mut self, process: &str) {
        self.child_process_count += 1;
        if self.child_process_count > 20 {
            self.suspicious_patterns
                .push(format!("Process spawning: {}", process));
        }
    }

    /// Records a denied access attempt
    pub fn record_denied_attempt(&mut self, reason: &str) {
        self.denied_attempts += 1;
        self.suspicious_patterns
            .push(format!("Blocked: {}", reason));
    }

    /// Records file modification
    pub fn record_file_modification(&mut self, _path: &str) {
        self.file_modifications += 1;
    }

    /// Returns true if profile shows suspicious activity
    pub fn is_suspicious(&self) -> bool {
        self.sensitive_path_attempts > 0
            || self.denied_attempts > 5
            || !self.suspicious_patterns.is_empty()
    }
}

/// Calculated trust score with details
#[derive(Debug, Clone)]
pub struct TrustScore {
    /// Numerical score (0-100, higher is more trustworthy)
    pub score: u32,
    /// Recommended trust tier based on score
    pub recommended_tier: TrustTier,
    /// Human-readable assessment
    pub assessment: String,
    /// Detailed notes on scoring factors
    pub notes: Vec<String>,
    /// Whether score indicates suspicious behavior
    pub is_suspicious: bool,
}

impl TrustScore {
    /// Creates a new trust score
    pub fn new(score: u32, notes: Vec<String>) -> Self {
        let clamped_score = score.clamp(0, 100);
        let recommended_tier = Self::tier_from_score(clamped_score);
        let assessment = Self::assessment_from_score(clamped_score);
        let is_suspicious = clamped_score < 50;

        Self {
            score: clamped_score,
            recommended_tier,
            assessment,
            notes,
            is_suspicious,
        }
    }

    /// Converts score to trust tier
    fn tier_from_score(score: u32) -> TrustTier {
        match score {
            0..=25 => TrustTier::Red,
            26..=75 => TrustTier::Yellow,
            76..=100 => TrustTier::Green,
            _ => TrustTier::Yellow, // Shouldn't happen due to clamping
        }
    }

    /// Generates human-readable assessment
    fn assessment_from_score(score: u32) -> String {
        match score {
            90..=100 => "Excellent - Consistent trustworthy behavior".to_string(),
            75..=89 => "Good - Normal behavior patterns".to_string(),
            50..=74 => "Fair - Some unusual activity detected".to_string(),
            25..=49 => "Poor - Suspicious behavior observed".to_string(),
            0..=24 => "Critical - High risk activity detected".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}

/// Calculates trust score based on behavior profile and current tier
pub fn calculate_trust_score(
    current_tier: TrustTier,
    profile: &BehaviorProfile,
    config: &TrustScoringConfig,
) -> TrustScore {
    let mut score: i32 = 75; // Start at neutral (Yellow tier midpoint)
    let mut notes = Vec::new();

    // Apply base score based on current tier
    score += match current_tier {
        TrustTier::Green => 15, // Bonus for already being trusted
        TrustTier::Yellow => 0, // Neutral
        TrustTier::Red => -15,  // Penalty for being restricted
    };

    // Apply network activity scoring
    let network_score = calculate_network_score(profile, config);
    score += (network_score * config.network_activity_weight) as i32;
    if network_score < 0.0 {
        notes.push(format!("Network activity penalty: {:.1}", network_score));
    }

    // Apply filesystem activity scoring
    let fs_score = calculate_filesystem_score(profile, config);
    score += (fs_score * config.filesystem_activity_weight) as i32;
    if fs_score < 0.0 {
        notes.push(format!("Filesystem activity penalty: {:.1}", fs_score));
    }

    // Apply process activity scoring
    let process_score = calculate_process_score(profile, config);
    score += (process_score * config.process_activity_weight) as i32;
    // Apply denied attempts penalty
    if profile.denied_attempts > 0 {
        let denied_penalty = -(profile.denied_attempts as i32 * 3);
        score += denied_penalty;
        notes.push(format!(
            "Denied access attempts ({}): {}",
            profile.denied_attempts, denied_penalty
        ));
    }

    // Apply consistency bonus if no suspicious activity
    if !profile.is_suspicious() && profile.denied_attempts == 0 {
        score += config.consistency_bonus;
        notes.push(format!("Consistency bonus: +{}", config.consistency_bonus));
    }

    // Add suspicious patterns to notes
    for pattern in &profile.suspicious_patterns {
        notes.push(format!("Suspicious: {}", pattern));
    }

    TrustScore::new(score as u32, notes)
}

/// Calculates network activity score
fn calculate_network_score(profile: &BehaviorProfile, config: &TrustScoringConfig) -> f32 {
    let mut score = 0.0;

    // Penalty for many outbound connections
    if profile.unique_destinations > 10 {
        score +=
            config.outbound_connection_penalty as f32 * (profile.unique_destinations as f32 / 10.0);
    }

    // Penalty for excessive DNS queries
    if profile.dns_query_count > 50 {
        score -= (profile.dns_query_count - 50) as f32 / 5.0;
    }

    score
}

/// Calculates filesystem activity score
fn calculate_filesystem_score(profile: &BehaviorProfile, config: &TrustScoringConfig) -> f32 {
    let mut score = 0.0;

    // Heavy penalty for sensitive path access
    if profile.sensitive_path_attempts > 0 {
        score += config.sensitive_path_penalty as f32 * profile.sensitive_path_attempts as f32;
    }

    // Slight concern for many file modifications
    if profile.file_modifications > 100 {
        score -= (profile.file_modifications - 100) as f32 / 20.0;
    }

    score
}

/// Calculates process activity score
fn calculate_process_score(profile: &BehaviorProfile, config: &TrustScoringConfig) -> f32 {
    let mut score = 0.0;

    // Penalty for many child processes
    if profile.child_process_count > 10 {
        score += config.child_process_penalty as f32 * (profile.child_process_count as f32 / 10.0);
    }

    score
}

/// Tracks trust scores over time for trend analysis
#[derive(Debug, Clone, Default)]
pub struct TrustScoreHistory {
    /// Score history entries
    pub entries: Vec<TrustScore>,
    /// Maximum history size
    max_size: usize,
}

impl TrustScoreHistory {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_size: 100,
        }
    }

    /// Records a new trust score
    pub fn record(&mut self, score: TrustScore) {
        if self.entries.len() >= self.max_size {
            self.entries.remove(0);
        }
        self.entries.push(score);
    }

    /// Calculates average score from history
    pub fn average_score(&self) -> Option<f32> {
        if self.entries.is_empty() {
            return None;
        }
        let sum: u32 = self.entries.iter().map(|e| e.score).sum();
        Some(sum as f32 / self.entries.len() as f32)
    }

    /// Detects if trust is declining
    pub fn is_declining(&self) -> bool {
        if self.entries.len() < 3 {
            return false;
        }

        let recent: u32 = self.entries.iter().rev().take(3).map(|e| e.score).sum();
        let previous: u32 = self
            .entries
            .iter()
            .rev()
            .skip(3)
            .take(3)
            .map(|e| e.score)
            .sum();

        recent < previous
    }

    /// Returns trend direction
    pub fn trend(&self) -> TrustTrend {
        if self.entries.len() < 2 {
            return TrustTrend::Stable;
        }

        let first = self.entries.first().unwrap().score;
        let last = self.entries.last().unwrap().score;
        let diff = last as i32 - first as i32;

        match diff {
            d if d > 10 => TrustTrend::Improving,
            d if d < -10 => TrustTrend::Declining,
            _ => TrustTrend::Stable,
        }
    }
}

/// Trust score trend direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTrend {
    Improving,
    Stable,
    Declining,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_score_calculation() {
        let config = TrustScoringConfig::default();

        // Clean profile should get good score
        let clean_profile = BehaviorProfile::new();
        let score = calculate_trust_score(TrustTier::Yellow, &clean_profile, &config);
        assert!(score.score >= 70);
        assert!(!score.is_suspicious);

        // Suspicious profile should get lower score and have notes
        let mut suspicious_profile = BehaviorProfile::new();
        suspicious_profile.record_sensitive_path("/home/user/.ssh");
        suspicious_profile.record_outbound_connection("suspicious.com");
        let score = calculate_trust_score(TrustTier::Yellow, &suspicious_profile, &config);
        // Score should have notes explaining the issues
        assert!(!score.notes.is_empty());
        // Profile should be marked as suspicious
        assert!(suspicious_profile.is_suspicious());
    }

    #[test]
    fn test_tier_from_score() {
        assert_eq!(TrustScore::tier_from_score(90), TrustTier::Green);
        assert_eq!(TrustScore::tier_from_score(60), TrustTier::Yellow);
        assert_eq!(TrustScore::tier_from_score(20), TrustTier::Red);
    }

    #[test]
    fn test_behavior_profile() {
        let mut profile = BehaviorProfile::new();

        profile.record_sensitive_path("/home/user/.ssh");
        profile.record_outbound_connection("example.com");
        profile.record_child_process("child.exe");

        assert_eq!(profile.sensitive_path_attempts, 1);
        assert_eq!(profile.unique_destinations, 1);
        assert_eq!(profile.child_process_count, 1);
        assert!(profile.is_suspicious());
    }

    #[test]
    fn test_trust_history() {
        let mut history = TrustScoreHistory::new();

        // Add 6 entries to test declining detection
        history.record(TrustScore::new(90, vec![]));
        history.record(TrustScore::new(85, vec![]));
        history.record(TrustScore::new(80, vec![]));
        history.record(TrustScore::new(75, vec![]));
        history.record(TrustScore::new(70, vec![]));
        history.record(TrustScore::new(60, vec![]));

        assert!(history.is_declining());
        assert_eq!(history.trend(), TrustTrend::Declining);
    }
}
