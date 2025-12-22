use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct QuarantinePlan {
    pub prefix_root: PathBuf,
    pub reason: String,
}

impl QuarantinePlan {
    pub fn new(prefix_root: PathBuf, reason: String) -> Self {
        Self { prefix_root, reason }
    }
}
