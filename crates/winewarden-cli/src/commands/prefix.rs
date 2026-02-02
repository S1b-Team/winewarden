use std::path::PathBuf;

use anyhow::Result;

use prefix_manager::PrefixManager;
use winewarden_core::config::ConfigPaths;

#[derive(Debug)]
pub enum PrefixAction {
    Scan { prefix: PathBuf },
    Snapshot { prefix: PathBuf },
}

pub fn execute(action: PrefixAction) -> Result<()> {
    let paths = ConfigPaths::resolve()?;
    match action {
        PrefixAction::Scan { prefix } => {
            let manager = PrefixManager::new(prefix, &paths);
            let findings = manager.scan_hygiene()?;
            if findings.is_empty() {
                println!("Prefix hygiene looks clean.");
            } else {
                println!("Hygiene findings: {}", findings.len());
                for finding in findings {
                    println!("- {}: {}", finding.note, finding.path.display());
                }
            }
        }
        PrefixAction::Snapshot { prefix } => {
            let manager = PrefixManager::new(prefix, &paths);
            let snapshot = manager.create_snapshot()?;
            println!("Snapshot created: {}", snapshot.id);
        }
    }
    Ok(())
}
