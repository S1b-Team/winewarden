use std::path::PathBuf;

use anyhow::Result;

use winewarden_core::config::ConfigPaths;
use winewarden_core::ipc::{
    resolve_socket_path, send_request, WineWardenRequest, WineWardenResponse,
};
use winewarden_core::store::{ExecutableIdentity, TrustStore};
use winewarden_core::trust::TrustTier;

pub fn execute(executable: Option<PathBuf>, use_daemon: bool) -> Result<()> {
    if use_daemon {
        return status_via_daemon();
    }

    let paths = ConfigPaths::resolve()?;
    let store = TrustStore::load(&paths.trust_db_path)?;

    if let Some(exe) = executable {
        let identity = ExecutableIdentity::from_path(&exe)?;
        let tier = store.get_tier(&identity).unwrap_or(TrustTier::Yellow);
        println!("Trust: {} ({})", tier, exe.display());
        return Ok(());
    }

    println!("Trusted executables: {}", store.records.len());
    Ok(())
}

fn status_via_daemon() -> Result<()> {
    let socket_path = resolve_socket_path();
    let response = send_request(&socket_path, &WineWardenRequest::Status)?;
    match response {
        WineWardenResponse::Status(payload) => {
            println!("WineWarden daemon is running.");
            println!("Uptime: {}s", payload.uptime_seconds);
            if let Some(summary) = payload.last_summary {
                println!("Last session: {}", summary);
            }
            Ok(())
        }
        WineWardenResponse::Error(error) => Err(anyhow::anyhow!(error.message)),
        other => Err(anyhow::anyhow!("unexpected response: {other:?}")),
    }
}
