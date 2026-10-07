use std::path::{Path, PathBuf};

use anyhow::Result;

/// Maps original paths to virtual paths based on prefix replacement rules.
#[derive(Debug, Clone)]
pub struct PathMapper {
    /// Maps source prefixes to destination prefixes
    /// e.g., "/home/user" -> "/tmp/winewarden/virtual/home"
    mappings: Vec<(PathBuf, PathBuf)>,
}

impl PathMapper {
    /// Creates a new PathMapper from raw mappings.
    /// Mappings will be sorted by longest prefix first.
    pub fn with_mappings(mappings: Vec<(PathBuf, PathBuf)>) -> Self {
        let mut mapper = Self { mappings };
        mapper.sort_mappings();
        mapper
    }

    /// Creates a new PathMapper from environment-based configuration.
    /// Uses WINEWARDEN_REDIRECT_MAP if set, otherwise uses sensible defaults.
    pub fn from_env_or_default(data_dir: &Path) -> Result<Self> {
        let mappings = if let Ok(env_map) = std::env::var("WINEWARDEN_REDIRECT_MAP") {
            Self::parse_mapping_string(&env_map)?
        } else {
            Self::default_mappings(data_dir)
        };

        Ok(Self::with_mappings(mappings))
    }

    /// Sorts mappings by longest source prefix first for proper matching order.
    fn sort_mappings(&mut self) {
        self.mappings
            .sort_by_key(|m| std::cmp::Reverse(m.0.as_os_str().len()));
    }

    /// Parses a mapping string like "${HOME}:/virtual/home,/tmp:/virtual/tmp"
    fn parse_mapping_string(map_str: &str) -> Result<Vec<(PathBuf, PathBuf)>> {
        let mut mappings = Vec::new();

        for entry in map_str.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }

            let parts: Vec<&str> = entry.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!(
                    "Invalid mapping format: '{}'. Expected 'source:dest'",
                    entry
                ));
            }

            let source = Self::expand_env_vars(parts[0])?;
            let dest = Self::expand_env_vars(parts[1])?;
            mappings.push((source, dest));
        }

        Ok(mappings)
    }

    /// Returns default mappings for common sensitive paths
    fn default_mappings(data_dir: &Path) -> Vec<(PathBuf, PathBuf)> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
        let virtual_base = data_dir.join("virtual");

        vec![
            (PathBuf::from(&home), virtual_base.join("home")),
            (PathBuf::from("/tmp"), virtual_base.join("tmp")),
            // Note: /root is unusual for games but included for completeness
            (PathBuf::from("/root"), virtual_base.join("root")),
        ]
    }

    /// Expands environment variables like ${HOME} or ~ in paths
    fn expand_env_vars(path: &str) -> Result<PathBuf> {
        let expanded = if path.starts_with("~/") {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
            path.replacen("~", &home, 1)
        } else {
            // Simple ${VAR} expansion
            let mut result = path.to_string();
            for (key, value) in std::env::vars() {
                let pattern = format!("${{{}}}", key);
                result = result.replace(&pattern, &value);
            }
            result
        };

        Ok(PathBuf::from(expanded))
    }

    /// Maps an original path to its redirected/virtualized destination.
    /// Returns None if no mapping applies.
    pub fn map_path(&self, original: &Path) -> Option<PathBuf> {
        // Lexical normalization (explicit no-follow symlink policy) so `..`
        // and `.` components cannot dodge or accidentally hit a mapping.
        let original = winewarden_core::paths::lexical_absolute(original);
        for (source, dest) in &self.mappings {
            let source = winewarden_core::paths::lexical_absolute(source);
            if let Ok(relative) = original.strip_prefix(&source) {
                return Some(dest.join(relative));
            }
        }
        None
    }

    /// Returns all configured mappings
    pub fn mappings(&self) -> &[(PathBuf, PathBuf)] {
        &self.mappings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_path_mapper_prefix_replacement() {
        let mapper = PathMapper::with_mappings(vec![
            (PathBuf::from("/home/user"), PathBuf::from("/virtual/home")),
            (PathBuf::from("/tmp"), PathBuf::from("/virtual/tmp")),
        ]);

        // Test basic mapping
        assert_eq!(
            mapper.map_path(Path::new("/home/user/.ssh/id_rsa")),
            Some(PathBuf::from("/virtual/home/.ssh/id_rsa"))
        );

        // Test /tmp mapping
        assert_eq!(
            mapper.map_path(Path::new("/tmp/cache/file.txt")),
            Some(PathBuf::from("/virtual/tmp/cache/file.txt"))
        );

        // Test no mapping
        assert_eq!(mapper.map_path(Path::new("/opt/some/path")), None);
    }

    #[test]
    fn test_path_mapper_longest_prefix_wins() {
        let mapper = PathMapper::with_mappings(vec![
            (PathBuf::from("/home"), PathBuf::from("/virtual/all_homes")),
            (
                PathBuf::from("/home/user"),
                PathBuf::from("/virtual/specific_user"),
            ),
        ]);

        // More specific prefix should win
        assert_eq!(
            mapper.map_path(Path::new("/home/user/file.txt")),
            Some(PathBuf::from("/virtual/specific_user/file.txt"))
        );

        // Less specific prefix used for other users
        assert_eq!(
            mapper.map_path(Path::new("/home/other/file.txt")),
            Some(PathBuf::from("/virtual/all_homes/other/file.txt"))
        );
    }

    #[test]
    fn test_map_path_normalizes_dot_dot() {
        let mapper = PathMapper::with_mappings(vec![(
            PathBuf::from("/home/user"),
            PathBuf::from("/virtual/home"),
        )]);
        // `..` inside the candidate must not dodge the mapping
        let mapped = mapper.map_path(Path::new("/home/user/docs/../notes.txt"));
        assert_eq!(mapped, Some(PathBuf::from("/virtual/home/notes.txt")));
        // `..` escaping the source prefix must not map
        let mapped = mapper.map_path(Path::new("/home/other/../user/x.txt"));
        assert_eq!(mapped, Some(PathBuf::from("/virtual/home/x.txt")));
        let mapped = mapper.map_path(Path::new("/etc/../home/user/y.txt"));
        assert_eq!(mapped, Some(PathBuf::from("/virtual/home/y.txt")));
        // Truly outside the prefix stays unmapped
        let mapped = mapper.map_path(Path::new("/opt/data/file.txt"));
        assert_eq!(mapped, None);
    }

    #[test]
    fn test_map_path_no_follow_symlink_policy() {
        let temp = TempDir::new().unwrap();
        let real = temp.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = temp.path().join("linked");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mapper =
            PathMapper::with_mappings(vec![(real.clone(), PathBuf::from("/virtual/real"))]);
        // Policy: symlinks are NOT resolved; the lexical path via the symlink
        // does not match the real-dir mapping.
        let mapped = mapper.map_path(&link);
        assert_eq!(mapped, None);
    }

    #[test]
    fn test_map_path_dot_components() {
        let mapper = PathMapper::with_mappings(vec![(
            PathBuf::from("/tmp/cache"),
            PathBuf::from("/virtual/tmp"),
        )]);
        let mapped = mapper.map_path(Path::new("/tmp/./cache/./item.bin"));
        assert_eq!(mapped, Some(PathBuf::from("/virtual/tmp/item.bin")));
    }

    #[test]
    fn test_parse_mapping_string() {
        let mappings =
            PathMapper::parse_mapping_string("/home/user:/virtual/home,/tmp:/virtual/tmp").unwrap();

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].0, PathBuf::from("/home/user"));
        assert_eq!(mappings[0].1, PathBuf::from("/virtual/home"));
    }
}
