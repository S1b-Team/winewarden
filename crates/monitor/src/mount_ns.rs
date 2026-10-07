use std::ffi::CStr;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};

use crate::path_redirect::PathMapper;

/// Manages mount namespace for filesystem virtualization.
///
/// This creates a private mount namespace where we can bind-mount virtual directories
/// over sensitive paths, providing defense-in-depth even if seccomp is bypassed.
pub struct MountNamespace {
    /// The path mapper containing redirect rules
    mapper: PathMapper,
}

impl MountNamespace {
    /// Creates a new MountNamespace with the given path mapper.
    pub fn new(mapper: PathMapper) -> Self {
        Self { mapper }
    }

    /// Sets up the mount namespace for the current process.
    ///
    /// Must run in the child before it executes the target binary (pre_exec).
    pub fn setup(&self) -> Result<()> {
        unshare(CloneFlags::CLONE_NEWNS).context("Failed to create new mount namespace")?;

        // Make all mounts private so our bind mounts don't propagate to the host
        mount(
            Some(c"none"),
            c"/",
            None::<&CStr>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&CStr>,
        )
        .context("Failed to make mounts private")?;

        for (source, dest) in self.mapper.mappings() {
            self.setup_bind_mount(source, dest)?;
        }

        Ok(())
    }

    /// Bind-mounts `dest` over `source`, creating either directory if missing.
    /// Only directory sources are mounted.
    fn setup_bind_mount(&self, source: &Path, dest: &Path) -> Result<()> {
        Self::ensure_dir_all(dest)?;

        if !source.exists() {
            Self::ensure_dir_all(source)?;
        }

        if source.is_dir() {
            let source_c = std::ffi::CString::new(source.as_os_str().as_encoded_bytes())
                .map_err(|e| anyhow::anyhow!("Invalid source path: {}", e))?;
            let dest_c = std::ffi::CString::new(dest.as_os_str().as_encoded_bytes())
                .map_err(|e| anyhow::anyhow!("Invalid dest path: {}", e))?;

            mount(
                Some(dest_c.as_c_str()),
                source_c.as_c_str(),
                None::<&CStr>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&CStr>,
            )
            .with_context(|| {
                format!(
                    "Failed to bind mount {} over {}",
                    dest.display(),
                    source.display()
                )
            })?;
        }

        Ok(())
    }

    /// Ensures a directory and all its parents exist.
    fn ensure_dir_all(path: &Path) -> Result<()> {
        if path.exists() {
            return Ok(());
        }

        fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_ensure_dir_all() {
        let temp = TempDir::new().unwrap();
        let nested = temp.path().join("a/b/c/d");

        MountNamespace::ensure_dir_all(&nested).unwrap();

        assert!(nested.exists());
        assert!(nested.is_dir());
    }
}
