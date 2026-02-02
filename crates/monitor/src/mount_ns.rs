use std::ffi::CStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};

use crate::path_redirect::PathMapper;

/// Manages mount namespace for filesystem virtualization.
///
/// This creates a private mount namespace where we can bind-mount virtual directories
/// over sensitive paths, providing defense-in-depth even if seccomp is bypassed.
pub struct MountNamespace {
    /// The path mapper containing redirect rules
    mapper: PathMapper,
    /// Root of the virtual filesystem (old root is moved here after pivot_root)
    old_root: PathBuf,
}

impl MountNamespace {
    /// Creates a new MountNamespace with the given path mapper.
    pub fn new(mapper: PathMapper) -> Self {
        // Use a hidden directory in /tmp for the old root after pivot
        let old_root = PathBuf::from(format!("/tmp/.winewarden_old_root_{}", std::process::id()));
        Self { mapper, old_root }
    }

    /// Sets up the mount namespace for the current process.
    ///
    /// This must be called BEFORE the process starts executing the target binary.
    /// Typically called from a pre_exec hook.
    ///
    /// # Safety
    ///
    /// This function uses unsafe FFI calls to Linux kernel interfaces.
    /// It must only be called in the child process context (pre_exec).
    pub fn setup(&self, _prefix_root: &Path) -> Result<()> {
        // Step 1: Create a new mount namespace
        // This gives us a private copy of the mount table
        unshare(CloneFlags::CLONE_NEWNS).context("Failed to create new mount namespace")?;

        // Step 2: Make all mounts private to prevent propagation
        // This ensures our bind mounts don't affect the host
        mount(
            Some(CStr::from_bytes_with_nul(b"none\0").unwrap()),
            CStr::from_bytes_with_nul(b"/\0").unwrap(),
            None::<&CStr>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&CStr>,
        )
        .context("Failed to make mounts private")?;

        // Step 3: Set up bind mounts for each redirect mapping
        for (source, dest) in self.mapper.mappings() {
            self.setup_bind_mount(source, dest)?;
        }

        Ok(())
    }

    /// Sets up a single bind mount for redirect/virtualize.
    ///
    /// The strategy depends on whether the source path exists:
    /// - If source exists: bind-mount dest over source (hide original)
    /// - If source doesn't exist: just ensure dest exists
    fn setup_bind_mount(&self, source: &Path, dest: &Path) -> Result<()> {
        // Ensure the destination directory exists
        Self::ensure_dir_all(dest)?;

        // Ensure the source directory exists (needed for bind mount)
        if !source.exists() {
            // Source doesn't exist, nothing to bind over
            // Just create it as a placeholder so future accesses work
            Self::ensure_dir_all(source)?;
        }

        // If source is a file, we need different handling
        // For now, we focus on directories (most common case for redirects)
        if source.is_dir() {
            // Create the bind mount
            // Convert paths to CString for nix mount API
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

            // Remount as read-only if needed (optional, can be configured)
            // For now, we allow writes to the virtual location
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

    /// Creates necessary parent directories for a path.
    pub fn ensure_parent_dirs(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            Self::ensure_dir_all(parent)?;
        }
        Ok(())
    }

    /// Cleans up the mount namespace on process exit.
    ///
    /// Note: In most cases, this happens automatically when the process exits.
    /// This is mainly useful for explicit cleanup in tests.
    pub fn cleanup(&self) -> Result<()> {
        // Unmount the old root if we did a pivot_root
        if self.old_root.exists() {
            let _ = umount2(&self.old_root, MntFlags::MNT_DETACH);
            let _ = fs::remove_dir(&self.old_root);
        }
        Ok(())
    }
}

/// Builder for mount namespace configuration.
#[derive(Debug, Clone)]
pub struct MountNamespaceBuilder {
    mappings: Vec<(PathBuf, PathBuf)>,
    data_dir: PathBuf,
}

impl MountNamespaceBuilder {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            mappings: Vec::new(),
            data_dir,
        }
    }

    /// Adds a path mapping.
    pub fn add_mapping(mut self, source: PathBuf, dest: PathBuf) -> Self {
        self.mappings.push((source, dest));
        self
    }

    /// Adds default mappings for common sensitive paths.
    pub fn with_default_mappings(mut self) -> Result<Self> {
        let mapper = PathMapper::from_env_or_default(&self.data_dir)?;
        for (source, dest) in mapper.mappings() {
            self.mappings.push((source.clone(), dest.clone()));
        }
        Ok(self)
    }

    /// Builds the MountNamespace.
    pub fn build(self) -> MountNamespace {
        MountNamespace::new(PathMapper::with_mappings(self.mappings))
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

    #[test]
    fn test_ensure_parent_dirs() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("a/b/c/file.txt");

        MountNamespace::ensure_parent_dirs(&path).unwrap();

        let parent = temp.path().join("a/b/c");
        assert!(parent.exists());
        assert!(parent.is_dir());
    }
}
