use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrefixId(pub Uuid);

impl RunId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl ExecId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl PrefixId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}
