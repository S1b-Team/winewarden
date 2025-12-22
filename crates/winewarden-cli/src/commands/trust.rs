use std::path::PathBuf;

use anyhow::Result;

use winewarden_core::config::ConfigPaths;
use winewarden_core::store::{ExecutableIdentity, TrustStore};
use winewarden_core::trust::TrustTier;

#[derive(Debug)]
pub enum TrustAction {
    Get { executable: PathBuf },
    Set { executable: PathBuf, tier: TrustTier },
}

pub fn execute(action: TrustAction) -> Result<()> {
    let paths = ConfigPaths::resolve()?;
    let mut store = TrustStore::load(&paths.trust_db_path)?;

    match action {
        TrustAction::Get { executable } => {
            let identity = ExecutableIdentity::from_path(&executable)?;
            let tier = store.get_tier(&identity).unwrap_or(TrustTier::Yellow);
            println!("Trust: {} ({})", tier, executable.display());
        }
        TrustAction::Set { executable, tier } => {
            let identity = ExecutableIdentity::from_path(&executable)?;
            store.set_tier(identity, tier);
            store.save(&paths.trust_db_path)?;
            println!("Trust updated to {}", tier);
        }
    }
    Ok(())
}
