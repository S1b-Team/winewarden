use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub mod command;
pub mod detect;
pub mod env;
pub mod lifecycle;

use command::RunnerCommand;
use detect::RunnerHint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerRequest {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub prefix_root: PathBuf,
    pub env: HashMap<String, String>,
}

pub struct Runner;

impl Runner {
    pub fn new() -> Self {
        Self
    }

    pub fn build_command(&self, request: &RunnerRequest) -> RunnerCommand {
        RunnerCommand::new(request.executable.clone(), request.args.clone())
    }

    pub fn detect(&self, request: &RunnerRequest) -> RunnerHint {
        detect::detect_hint(&request.executable)
    }

    pub fn prepare_env(&self, request: &RunnerRequest) -> HashMap<String, String> {
        env::sanitize_env(&request.env)
    }

    pub fn dry_run(&self, request: &RunnerRequest) -> Result<RunnerCommand> {
        Ok(self.build_command(request))
    }
}
