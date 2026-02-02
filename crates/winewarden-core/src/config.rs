use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::paths::PathAction;
use crate::trust::TrustTier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub winewarden: WineWardenConfig,
    pub trust: TrustConfig,
    pub process: ProcessConfig,
    pub sacred_zones: Vec<SacredZoneConfig>,
    pub network: NetworkConfig,
    pub prefix: PrefixConfig,
    pub reporting: ReportConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WineWardenConfig {
    pub enabled: bool,
    pub no_prompts_during_gameplay: bool,
    pub emergency_only: bool,
    pub systemic_risk_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    pub default_tier: TrustTier,
    pub pirate_safe: bool,
    pub auto_promote: bool,
    pub promotion_after_runs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub allowed_patterns: Vec<String>,
    pub blocked_patterns: Vec<String>,
    pub max_child_processes: u32,
    pub allow_shell_execution: bool,
    pub allow_script_execution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SacredZoneConfig {
    pub label: String,
    pub path: String,
    pub action: PathAction,
    pub redirect_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub mode: NetworkMode,
    pub dns_awareness: bool,
    pub destination_monitoring: bool,
    pub block_on_malicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    Observe,
    Permissive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixConfig {
    pub separate_by_trust: bool,
    pub snapshot_before_first_run: bool,
    pub hygiene_scan_on_run: bool,
    pub disposable_prefix_for_untrusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    pub store_reports: bool,
    pub human_summary: bool,
    pub structured_json: bool,
}

#[derive(Debug, Clone)]
pub struct ConfigPaths {
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
    pub report_dir: PathBuf,
    pub trust_db_path: PathBuf,
    pub snapshot_dir: PathBuf,
}

impl Config {
    pub fn default_config() -> Self {
        Self {
            winewarden: WineWardenConfig {
                enabled: true,
                no_prompts_during_gameplay: true,
                emergency_only: true,
                systemic_risk_only: true,
            },
            trust: TrustConfig {
                default_tier: TrustTier::Yellow,
                pirate_safe: false,
                auto_promote: true,
                promotion_after_runs: 3,
            },
            process: ProcessConfig {
                allowed_patterns: vec![
                    "wine*".to_string(),
                    "wineserver".to_string(),
                    "*.exe".to_string(),
                ],
                blocked_patterns: vec![
                    "*nc*".to_string(),
                    "*netcat*".to_string(),
                    "*powershell*".to_string(),
                    "*cmd.exe*".to_string(),
                ],
                max_child_processes: 50,
                allow_shell_execution: false,
                allow_script_execution: false,
            },
            sacred_zones: vec![
                SacredZoneConfig {
                    label: "Home outside prefix".to_string(),
                    path: "${HOME}".to_string(),
                    action: PathAction::Redirect,
                    redirect_to: Some("${DATA_DIR}/virtual/home".to_string()),
                },
                SacredZoneConfig {
                    label: "SSH keys".to_string(),
                    path: "${HOME}/.ssh".to_string(),
                    action: PathAction::Deny,
                    redirect_to: None,
                },
                SacredZoneConfig {
                    label: "GPG keys".to_string(),
                    path: "${HOME}/.gnupg".to_string(),
                    action: PathAction::Deny,
                    redirect_to: None,
                },
                SacredZoneConfig {
                    label: "User config".to_string(),
                    path: "${HOME}/.config".to_string(),
                    action: PathAction::Redirect,
                    redirect_to: Some("${DATA_DIR}/virtual/config".to_string()),
                },
            ],
            network: NetworkConfig {
                mode: NetworkMode::Observe,
                dns_awareness: true,
                destination_monitoring: true,
                block_on_malicious: true,
            },
            prefix: PrefixConfig {
                separate_by_trust: true,
                snapshot_before_first_run: true,
                hygiene_scan_on_run: true,
                disposable_prefix_for_untrusted: true,
            },
            reporting: ReportConfig {
                store_reports: true,
                human_summary: true,
                structured_json: true,
            },
        }
    }

    pub fn from_toml_str(contents: &str) -> Result<Self> {
        let config: Config = toml::from_str(contents).context("parse config TOML")?;
        Ok(config)
    }

    pub fn to_toml_string(&self) -> Result<String> {
        let output = toml::to_string_pretty(self).context("render config TOML")?;
        Ok(output)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read config at {}", path.display()))?;
        Self::from_toml_str(&contents)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create config dir {}", parent.display()))?;
        }
        let contents = self.to_toml_string()?;
        fs::write(path, contents).with_context(|| format!("write config at {}", path.display()))?;
        Ok(())
    }
}

impl ConfigPaths {
    pub fn resolve() -> Result<Self> {
        let project_dirs = ProjectDirs::from("io", "winewarden", "winewarden")
            .ok_or_else(|| anyhow::anyhow!("unable to determine project directories"))?;
        let config_dir = project_dirs.config_dir();
        let data_dir = project_dirs.data_dir();
        let report_dir = data_dir.join("reports");
        let trust_db_path = data_dir.join("trust.json");
        let snapshot_dir = data_dir.join("snapshots");
        Ok(Self {
            config_path: config_dir.join("config.toml"),
            data_dir: data_dir.to_path_buf(),
            report_dir,
            trust_db_path,
            snapshot_dir,
        })
    }
}
