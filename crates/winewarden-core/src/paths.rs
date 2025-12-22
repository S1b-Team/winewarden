use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::{ConfigPaths, SacredZoneConfig};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PathAction {
    Allow,
    Deny,
    Redirect,
    Virtualize,
}

#[derive(Debug, Clone)]
pub struct SacredZone {
    pub label: String,
    pub path: PathBuf,
    pub action: PathAction,
    pub redirect_to: Option<PathBuf>,
}

impl SacredZone {
    pub fn from_config(config: &SacredZoneConfig, paths: &ConfigPaths) -> Result<Self> {
        let base_path = expand_path_template(&config.path, paths)?;
        let redirect_to = match &config.redirect_to {
            Some(value) => Some(expand_path_template(value, paths)?),
            None => None,
        };
        Ok(Self {
            label: config.label.clone(),
            path: base_path,
            action: config.action,
            redirect_to,
        })
    }

    pub fn matches(&self, candidate: &Path) -> bool {
        candidate.starts_with(&self.path)
    }
}

pub fn expand_path_template(template: &str, paths: &ConfigPaths) -> Result<PathBuf> {
    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    let replaced = template
        .replace("${HOME}", &home_dir)
        .replace("${DATA_DIR}", &paths.data_dir.to_string_lossy())
        .replace("${CONFIG_DIR}", &paths.config_path.parent().unwrap_or(&paths.data_dir).to_string_lossy());
    let path = PathBuf::from(replaced);
    Ok(path)
}
