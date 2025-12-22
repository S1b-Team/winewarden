use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use walkdir::WalkDir;

use winewarden_core::config::ConfigPaths;
use reporting::ReportStats;
pub mod layout;
pub mod snapshots;
pub mod lint;
pub mod quarantine;
pub mod repair;

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
                let modified_at = metadata
                    .modified()
                    .ok()
                    .and_then(|time| OffsetDateTime::try_from(time).ok());
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
                current_map.insert(entry.path().to_path_buf(), metadata.len());
            }
        }

        let mut snapshot_map = HashMap::new();
        for entry in &snapshot.entries {
            snapshot_map.insert(entry.path.clone(), entry.size);
        }

        for (path, size) in &current_map {
            match snapshot_map.get(path) {
                None => changes.push(SnapshotChange {
                    path: path.clone(),
                    change: SnapshotChangeKind::Added,
                }),
                Some(old_size) if old_size != size => changes.push(SnapshotChange {
                    path: path.clone(),
                    change: SnapshotChangeKind::Modified,
                }),
                _ => {}
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
                        map.entry(name).or_default().push(entry.path().to_path_buf());
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

pub fn summarize_findings(findings: &[HygieneFinding]) -> ReportStats {
    let mut stats = ReportStats {
        total_attempts: 0,
        denied: 0,
        redirected: 0,
        virtualized: 0,
        allowed: 0,
        systemic_risks: 0,
    };

    stats.total_attempts = findings.len() as u32;
    stats
}
