use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::trust::TrustTier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableIdentity {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecord {
    pub identity: ExecutableIdentity,
    pub tier: TrustTier,
    pub runs: u32,
    pub last_seen: OffsetDateTime,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    pub records: HashMap<String, TrustRecord>,
}

impl ExecutableIdentity {
    pub fn from_path(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("read executable {}", path.display()))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hasher.finalize();
        let sha256 = hex::encode(hash);
        Ok(Self {
            path: path.to_path_buf(),
            sha256,
        })
    }
}

impl TrustStore {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read trust store {}", path.display()))?;
        let store = serde_json::from_str(&contents).context("parse trust store JSON")?;
        Ok(store)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create trust dir {}", parent.display()))?;
        }
        let contents = serde_json::to_string_pretty(self).context("render trust store JSON")?;
        fs::write(path, contents)
            .with_context(|| format!("write trust store {}", path.display()))?;
        Ok(())
    }

    pub fn record_run(&mut self, identity: ExecutableIdentity, tier: TrustTier) {
        let now = OffsetDateTime::now_utc();
        let entry = self.records.entry(identity.sha256.clone()).or_insert(TrustRecord {
            identity: identity.clone(),
            tier,
            runs: 0,
            last_seen: now,
        });
        entry.runs = entry.runs.saturating_add(1);
        entry.last_seen = now;
        entry.tier = tier;
        entry.identity.path = identity.path;
    }

    pub fn get_tier(&self, identity: &ExecutableIdentity) -> Option<TrustTier> {
        self.records.get(&identity.sha256).map(|record| record.tier)
    }

    pub fn set_tier(&mut self, identity: ExecutableIdentity, tier: TrustTier) {
        let now = OffsetDateTime::now_utc();
        let entry = self.records.entry(identity.sha256.clone()).or_insert(TrustRecord {
            identity: identity.clone(),
            tier,
            runs: 0,
            last_seen: now,
        });
        entry.tier = tier;
        entry.identity.path = identity.path;
        entry.last_seen = now;
    }
}
