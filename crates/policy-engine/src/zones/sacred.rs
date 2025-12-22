use anyhow::Result;

use winewarden_core::config::{Config, ConfigPaths};
use winewarden_core::paths::SacredZone;

pub fn load_sacred_zones(config: &Config, paths: &ConfigPaths) -> Result<Vec<SacredZone>> {
    let mut zones = Vec::new();
    for zone in &config.sacred_zones {
        zones.push(SacredZone::from_config(zone, paths)?);
    }
    Ok(zones)
}
