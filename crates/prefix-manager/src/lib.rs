use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use walkdir::WalkDir;

use winewarden_core::config::ConfigPaths;
use winewarden_core::types::{PrefixChange, PrefixChangeKind, PrefixDiffSummary};

/// Default cap on the number of individual changes kept in a diff summary.
pub const DEFAULT_DIFF_LIST_CAP: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixSnapshot {
    pub id: Uuid,
    pub created_at: OffsetDateTime,
    pub prefix_root: PathBuf,
    pub entries: Vec<SnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub path: PathBuf,
    pub size: u64,
    pub modified_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotChange {
    pub path: PathBuf,
    pub change: SnapshotChangeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HygieneFinding {
    pub kind: HygieneFindingKind,
    pub path: PathBuf,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HygieneFindingKind {
    OrphanedDll,
    OverrideConflict,
    UnexpectedDllLocation,
}

pub struct PrefixManager {
    pub prefix_root: PathBuf,
    pub snapshot_dir: PathBuf,
}

impl PrefixManager {
    pub fn new(prefix_root: PathBuf, paths: &ConfigPaths) -> Self {
        Self {
            prefix_root,
            snapshot_dir: paths.snapshot_dir.clone(),
        }
    }

    pub fn scan_hygiene(&self) -> Result<Vec<HygieneFinding>> {
        let mut findings = Vec::new();

        let dll_locations = self.collect_dll_locations()?;
        for (name, paths) in &dll_locations {
            if paths.len() > 1 {
                let sizes: Vec<u64> = paths
                    .iter()
                    .filter_map(|path| fs::metadata(path).ok().map(|meta| meta.len()))
                    .collect();
                if sizes.windows(2).any(|pair| pair[0] != pair[1]) {
                    findings.push(HygieneFinding {
                        kind: HygieneFindingKind::OverrideConflict,
                        path: paths[0].clone(),
                        note: format!("Duplicate DLL with mismatched size: {name}"),
                    });
                }
            }

            for path in paths {
                if is_unexpected_dll_location(path) {
                    findings.push(HygieneFinding {
                        kind: HygieneFindingKind::UnexpectedDllLocation,
                        path: path.clone(),
                        note: "DLL is stored outside standard Windows directories".to_string(),
                    });
                }
            }
        }

        for path in self.find_orphaned_dlls()? {
            findings.push(HygieneFinding {
                kind: HygieneFindingKind::OrphanedDll,
                path,
                note: "DLL found in user content without a nearby executable".to_string(),
            });
        }

        Ok(findings)
    }

    pub fn create_snapshot(&self) -> Result<PrefixSnapshot> {
        fs::create_dir_all(&self.snapshot_dir)
            .with_context(|| format!("create snapshot dir {}", self.snapshot_dir.display()))?;

        let mut entries = Vec::new();
        for entry in WalkDir::new(&self.prefix_root) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let metadata = entry.metadata()?;
                let modified_at = metadata.modified().ok().map(OffsetDateTime::from);
                entries.push(SnapshotEntry {
                    path: entry.path().to_path_buf(),
                    size: metadata.len(),
                    modified_at,
                });
            }
        }

        let snapshot = PrefixSnapshot {
            id: Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc(),
            prefix_root: self.prefix_root.clone(),
            entries,
        };

        let snapshot_path = self.snapshot_dir.join(format!("{}.json", snapshot.id));
        let contents = serde_json::to_string_pretty(&snapshot).context("render snapshot JSON")?;
        fs::write(&snapshot_path, contents)
            .with_context(|| format!("write snapshot {}", snapshot_path.display()))?;

        Ok(snapshot)
    }

    pub fn diff_snapshot(&self, snapshot: &PrefixSnapshot) -> Result<Vec<SnapshotChange>> {
        let mut changes = Vec::new();
        let mut current_map = HashMap::new();
        for entry in WalkDir::new(&self.prefix_root) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let metadata = entry.metadata()?;
                let modified_at = metadata.modified().ok().map(OffsetDateTime::from);
                current_map.insert(entry.path().to_path_buf(), (metadata.len(), modified_at));
            }
        }

        let mut snapshot_map = HashMap::new();
        for entry in &snapshot.entries {
            snapshot_map.insert(entry.path.clone(), (entry.size, entry.modified_at));
        }

        for (path, (size, modified_at)) in &current_map {
            match snapshot_map.get(path) {
                None => changes.push(SnapshotChange {
                    path: path.clone(),
                    change: SnapshotChangeKind::Added,
                }),
                Some((old_size, old_modified)) => {
                    // A rewrite that keeps the size still moves the mtime.
                    let mtime_changed = matches!(
                        (old_modified, modified_at),
                        (Some(old), Some(new)) if old != new
                    );
                    if old_size != size || mtime_changed {
                        changes.push(SnapshotChange {
                            path: path.clone(),
                            change: SnapshotChangeKind::Modified,
                        });
                    }
                }
            }
        }

        for path in snapshot_map.keys() {
            if !current_map.contains_key(path) {
                changes.push(SnapshotChange {
                    path: path.clone(),
                    change: SnapshotChangeKind::Removed,
                });
            }
        }

        Ok(changes)
    }

    /// Diffs the prefix against `snapshot` and condenses the result: full
    /// counts, plus at most `cap` changes sorted by path.
    pub fn diff_summary(&self, snapshot: &PrefixSnapshot, cap: usize) -> Result<PrefixDiffSummary> {
        let mut changes = self.diff_snapshot(snapshot)?;
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        let mut summary = PrefixDiffSummary {
            baseline_id: Some(snapshot.id),
            baseline_created_at: Some(snapshot.created_at),
            ..PrefixDiffSummary::default()
        };
        for change in &changes {
            match change.change {
                SnapshotChangeKind::Added => summary.added += 1,
                SnapshotChangeKind::Removed => summary.removed += 1,
                SnapshotChangeKind::Modified => summary.modified += 1,
            }
        }
        summary.truncated = changes.len() > cap;
        summary.changes = changes
            .into_iter()
            .take(cap)
            .map(|change| PrefixChange {
                path: change.path,
                kind: match change.change {
                    SnapshotChangeKind::Added => PrefixChangeKind::Added,
                    SnapshotChangeKind::Removed => PrefixChangeKind::Removed,
                    SnapshotChangeKind::Modified => PrefixChangeKind::Modified,
                },
            })
            .collect();
        Ok(summary)
    }

    pub fn load_snapshot(path: &Path) -> Result<PrefixSnapshot> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read snapshot {}", path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("parse snapshot {}", path.display()))
    }

    /// Path of the newest stored snapshot taken of this prefix, if any.
    /// Unreadable or foreign snapshot files are skipped.
    pub fn latest_snapshot_path(&self) -> Result<Option<PathBuf>> {
        let dir = match fs::read_dir(&self.snapshot_dir) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("read snapshot dir {}", self.snapshot_dir.display()))
            }
        };
        let mut latest: Option<(OffsetDateTime, PathBuf)> = None;
        for entry in dir {
            let path = entry?.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let Ok(snapshot) = Self::load_snapshot(&path) else {
                continue;
            };
            if snapshot.prefix_root != self.prefix_root {
                continue;
            }
            if latest
                .as_ref()
                .is_none_or(|(created_at, _)| snapshot.created_at > *created_at)
            {
                latest = Some((snapshot.created_at, path));
            }
        }
        Ok(latest.map(|(_, path)| path))
    }

    fn collect_dll_locations(&self) -> Result<HashMap<String, Vec<PathBuf>>> {
        let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for entry in WalkDir::new(&self.prefix_root) {
            let entry = entry?;
            if entry.file_type().is_file() {
                if let Some(extension) = entry.path().extension() {
                    if extension.to_string_lossy().eq_ignore_ascii_case("dll") {
                        let name = entry
                            .path()
                            .file_name()
                            .map(|value| value.to_string_lossy().to_string())
                            .unwrap_or_else(|| "unknown.dll".to_string());
                        map.entry(name)
                            .or_default()
                            .push(entry.path().to_path_buf());
                    }
                }
            }
        }
        Ok(map)
    }

    fn find_orphaned_dlls(&self) -> Result<Vec<PathBuf>> {
        let mut orphaned = Vec::new();
        for entry in WalkDir::new(&self.prefix_root) {
            let entry = entry?;
            if entry.file_type().is_file() {
                if let Some(extension) = entry.path().extension() {
                    if extension.to_string_lossy().eq_ignore_ascii_case("dll") {
                        if let Some(parent) = entry.path().parent() {
                            if is_user_content(parent) && !has_executable_neighbor(parent)? {
                                orphaned.push(entry.path().to_path_buf());
                            }
                        }
                    }
                }
            }
        }
        Ok(orphaned)
    }
}

fn is_user_content(path: &Path) -> bool {
    path.to_string_lossy().contains("drive_c/users")
}

fn is_unexpected_dll_location(path: &Path) -> bool {
    let value = path.to_string_lossy();
    !(value.contains("drive_c/windows/system32") || value.contains("drive_c/windows/syswow64"))
}

fn has_executable_neighbor(path: &Path) -> Result<bool> {
    if !path.is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension.to_string_lossy().eq_ignore_ascii_case("exe") {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(root: &Path) -> PrefixManager {
        PrefixManager {
            prefix_root: root.join("prefix"),
            snapshot_dir: root.join("snapshots"),
        }
    }

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn summary_counts_everything_but_caps_the_list() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        write(&manager.prefix_root.join("keep.txt"), "x");
        let snapshot = manager.create_snapshot().unwrap();
        for i in 0..10 {
            write(&manager.prefix_root.join(format!("new{i:02}.txt")), "y");
        }

        let summary = manager.diff_summary(&snapshot, 3).unwrap();
        assert_eq!(summary.added, 10);
        assert_eq!(summary.total(), 10);
        assert!(summary.truncated);
        let listed: Vec<_> = summary.changes.iter().map(|c| c.path.clone()).collect();
        assert_eq!(
            listed,
            vec![
                manager.prefix_root.join("new00.txt"),
                manager.prefix_root.join("new01.txt"),
                manager.prefix_root.join("new02.txt"),
            ]
        );
        assert_eq!(summary.baseline_id, Some(snapshot.id));
    }

    #[test]
    fn same_size_rewrite_counts_as_modified() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        let file = manager.prefix_root.join("save.dat");
        write(&file, "aaaa");
        let snapshot = manager.create_snapshot().unwrap();
        write(&file, "bbbb");
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(later)
            .unwrap();

        let summary = manager.diff_summary(&snapshot, 10).unwrap();
        assert_eq!(summary.modified, 1);
        assert_eq!(summary.changes[0].kind, PrefixChangeKind::Modified);
    }

    #[test]
    fn untouched_prefix_has_empty_diff() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        write(&manager.prefix_root.join("a.txt"), "a");
        let snapshot = manager.create_snapshot().unwrap();
        let summary = manager.diff_summary(&snapshot, 10).unwrap();
        assert!(summary.is_empty());
        assert!(!summary.truncated);
    }

    #[test]
    fn latest_snapshot_picks_newest_for_this_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        assert!(manager.latest_snapshot_path().unwrap().is_none());
        fs::create_dir_all(&manager.prefix_root).unwrap();
        let first = manager.create_snapshot().unwrap();
        let second = manager.create_snapshot().unwrap();
        let other = PrefixManager {
            prefix_root: dir.path().join("other"),
            snapshot_dir: manager.snapshot_dir.clone(),
        };
        fs::create_dir_all(&other.prefix_root).unwrap();
        other.create_snapshot().unwrap();
        fs::write(manager.snapshot_dir.join("broken.json"), "{").unwrap();

        let path = manager.latest_snapshot_path().unwrap().unwrap();
        let loaded = PrefixManager::load_snapshot(&path).unwrap();
        assert_ne!(loaded.id, first.id);
        assert_eq!(loaded.id, second.id);
    }
}
