use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct PrefixLayout {
    pub root: PathBuf,
}

impl PrefixLayout {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}
