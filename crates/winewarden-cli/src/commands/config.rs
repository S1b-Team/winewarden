use std::path::PathBuf;

use anyhow::{Context, Result};

use winewarden_core::config::{Config, ConfigPaths};

pub fn print_effective(config_path: Option<PathBuf>) -> Result<()> {
    let paths = ConfigPaths::resolve()?;
    let config_path = config_path.unwrap_or(paths.config_path);
    let config = Config::load(&config_path)
        .with_context(|| format!("load config {}", config_path.display()))?;
    let output = config.to_toml_string()?;
    println!("{}", output);
    Ok(())
}
