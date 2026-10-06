use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub mod command;

use command::RunnerCommand;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerRequest {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub prefix_root: PathBuf,
    pub env: HashMap<String, String>,
}

pub struct Runner;

impl Default for Runner {
    fn default() -> Self {
        Self
    }
}

impl Runner {
    pub fn new() -> Self {
        Self
    }

    pub fn build_command(&self, request: &RunnerRequest) -> RunnerCommand {
        RunnerCommand::new(request.executable.clone(), request.args.clone())
    }

    pub fn dry_run(&self, request: &RunnerRequest) -> Result<RunnerCommand> {
        Ok(self.build_command(request))
    }
}
