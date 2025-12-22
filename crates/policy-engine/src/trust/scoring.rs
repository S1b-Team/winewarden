use winewarden_core::trust::TrustTier;

#[derive(Debug, Clone)]
pub struct TrustScore {
    pub tier: TrustTier,
    pub notes: Vec<String>,
}

pub fn score_trust(current: TrustTier, observations: &[String]) -> TrustScore {
    let notes = observations.to_vec();
    TrustScore { tier: current, notes }
}
