use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrustTier {
    Green,
    Yellow,
    Red,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSignal {
    pub tier: TrustTier,
    pub message: String,
}

impl TrustTier {
    pub fn calm_label(&self) -> &'static str {
        match self {
            TrustTier::Green => "trusted",
            TrustTier::Yellow => "partial",
            TrustTier::Red => "restricted",
        }
    }
}

impl TrustSignal {
    pub fn from_tier(tier: TrustTier) -> Self {
        let message = match tier {
            TrustTier::Green => "This game ran with full trust.",
            TrustTier::Yellow => "This game ran with partial trust.",
            TrustTier::Red => "This game ran with strict protection.",
        };
        Self {
            tier,
            message: message.to_string(),
        }
    }
}

impl FromStr for TrustTier {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "green" => Ok(TrustTier::Green),
            "yellow" => Ok(TrustTier::Yellow),
            "red" => Ok(TrustTier::Red),
            _ => Err(format!("unknown trust tier: {value}")),
        }
    }
}

impl fmt::Display for TrustTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            TrustTier::Green => "green",
            TrustTier::Yellow => "yellow",
            TrustTier::Red => "red",
        };
        write!(f, "{value}")
    }
}
