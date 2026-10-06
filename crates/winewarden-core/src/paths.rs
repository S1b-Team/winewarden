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
        lexical_absolute(candidate).starts_with(lexical_absolute(&self.path))
    }
}

/// Lexically normalizes a path: resolves `.` and `..` components without
/// following symlinks (an explicit no-follow policy). Paths that do not
/// exist on disk normalize identically to existing ones.
pub fn lexical_absolute(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop();
            }
            other => components.push(other.as_os_str()),
        }
    }
    let mut result = PathBuf::new();
    if path.is_absolute() {
        result.push(std::path::Component::RootDir.as_os_str());
    }
    for component in components {
        result.push(component);
    }
    result
}

pub fn expand_path_template(template: &str, paths: &ConfigPaths) -> Result<PathBuf> {
    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    let replaced = template
        .replace("${HOME}", &home_dir)
        .replace("${DATA_DIR}", &paths.data_dir.to_string_lossy())
        .replace(
            "${CONFIG_DIR}",
            &paths
                .config_path
                .parent()
                .unwrap_or(&paths.data_dir)
                .to_string_lossy(),
        );
    let path = PathBuf::from(replaced);
    Ok(path)
}

#[cfg(test)]
mod canonicalization_tests {
    use super::*;

    fn zone(path: &str) -> SacredZone {
        SacredZone {
            label: "test".to_string(),
            path: PathBuf::from(path),
            action: PathAction::Deny,
            redirect_to: None,
        }
    }

    #[test]
    fn zone_match_normalizes_dot_dot() {
        let z = zone("/home/user/.ssh");
        assert!(z.matches(Path::new("/home/user/docs/../.ssh/id_rsa")));
        assert!(!z.matches(Path::new("/home/user/../other/.ssh/id_rsa")));
    }

    #[test]
    fn zone_match_normalizes_dot_components() {
        let z = zone("/etc/secrets");
        assert!(z.matches(Path::new("/etc/./secrets/./key")));
    }

    #[test]
    fn zone_match_ignores_trailing_separator() {
        let z = zone("/home/user/.ssh/");
        assert!(z.matches(Path::new("/home/user/.ssh/id_rsa")));
    }

    #[test]
    fn lexical_absolute_resolves_relative_components() {
        assert_eq!(
            lexical_absolute(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
        assert_eq!(
            lexical_absolute(Path::new("/a/../../x")),
            PathBuf::from("/x")
        );
    }
}
