use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub id: Uuid,
    pub created_at: OffsetDateTime,
    pub prefix_root: PathBuf,
}

impl SnapshotMetadata {
    pub fn new(prefix_root: PathBuf) -> Self {
        Self {
            id: Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc(),
            prefix_root,
        }
    }
}
