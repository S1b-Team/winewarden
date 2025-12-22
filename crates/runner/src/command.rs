use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RunnerCommand {
    pub executable: PathBuf,
    pub args: Vec<String>,
}

impl RunnerCommand {
    pub fn new(executable: PathBuf, args: Vec<String>) -> Self {
        Self { executable, args }
    }
}
