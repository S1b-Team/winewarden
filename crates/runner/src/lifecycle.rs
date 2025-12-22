use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct LifecyclePlan {
    pub prefix_root: PathBuf,
}

impl LifecyclePlan {
    pub fn new(prefix_root: PathBuf) -> Self {
        Self { prefix_root }
    }
}
