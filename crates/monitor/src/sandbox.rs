use std::fs::File;
use std::path::Path;

use anyhow::Result;
use landlock::{
    Access, AccessFs, BitFlags, PathBeneath, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetError, ABI,
};

use crate::mount_ns::MountNamespace;
use crate::path_redirect::PathMapper;
use winewarden_core::ConfigPaths;

/// Applies a complete sandbox (Landlock + Mount Namespace) to the current process.
/// This MUST be called before executing the untrusted code (e.g. in pre_exec).
pub fn apply_sandbox(prefix_root: &Path) -> Result<()> {
    setup_mount_namespace()?;
    apply_landlock_sandbox(prefix_root)?;
    Ok(())
}

/// Bind-mounts the redirect targets under the user's XDG data dir instead of a
/// world-readable /tmp tree shared across sessions.
fn setup_mount_namespace() -> Result<()> {
    let paths = ConfigPaths::resolve()?;
    let mapper = PathMapper::from_env_or_default(&paths.data_dir.join("virtual-mounts"))?;
    MountNamespace::new(mapper).setup()
}

/// Applies Landlock sandbox for filesystem access control.
fn apply_landlock_sandbox(prefix_root: &Path) -> Result<()> {
    // Define access rights
    let read_dirs = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;
    let read_write_dirs = read_dirs
        | AccessFs::WriteFile
        | AccessFs::RemoveDir
        | AccessFs::RemoveFile
        | AccessFs::MakeChar
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeBlock
        | AccessFs::MakeSym;

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1))?
        .create()
        .map_err(|e| anyhow::anyhow!("Failed to create Landlock ruleset: {}", e))?;

    // 1. System Basic Access (Read-Only)
    // Necessary for Wine binary, libraries, etc.
    let system_paths = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/opt"];
    for path in system_paths {
        let path = Path::new(path);
        // We only add rules for paths that exist and can be opened
        if path.exists() {
            add_rule(&mut ruleset, path, read_dirs)?;
        }
    }

    // 2. Devices (Read-Write or Read-Only depending on device)
    // Simplified: Allow RW to common safe devices if they exist.
    // In strict mode, we might want to be more granular.
    // /dev/null, /dev/zero, /dev/urandom are essential.
    let common_devs = [
        "/dev/null",
        "/dev/zero",
        "/dev/urandom",
        "/dev/full",
        "/dev/ptmx",
        "/dev/tty",
    ];
    for dev in common_devs {
        let path = Path::new(dev);
        if path.exists() {
            // Some of these might be char devices, landlock handles directory/file access.
            // For files, ReadFile/WriteFile usually covers it.
            add_rule(&mut ruleset, path, AccessFs::ReadFile | AccessFs::WriteFile)?;
        }
    }
    // GPU access
    if Path::new("/dev/dri").exists() {
        add_rule(&mut ruleset, Path::new("/dev/dri"), read_dirs)?;
    }
    // Shared Memory / TMP (Read-Write)
    // /dev/shm is crucial for performance
    if Path::new("/dev/shm").exists() {
        add_rule(&mut ruleset, Path::new("/dev/shm"), read_write_dirs)?;
    }

    // 3. Runtime / Temp (Read-Write)
    // X11 sockets, Wayland sockets often live in /run/user/UID or /tmp
    let tmp_paths = ["/tmp", "/run", "/var/run"];
    for path in tmp_paths {
        let path = Path::new(path);
        if path.exists() {
            add_rule(&mut ruleset, path, read_write_dirs)?;
        }
    }

    // 4. The Prefix (Read-Write)
    // This is the core: allow the game to do whatever it wants inside its jail.
    if prefix_root.exists() {
        add_rule(&mut ruleset, prefix_root, read_write_dirs)?;
    }

    ruleset
        .restrict_self()
        .map_err(|e| anyhow::anyhow!("Failed to enforce Landlock ruleset: {}", e))?;

    Ok(())
}

fn add_rule(ruleset: &mut RulesetCreated, path: &Path, access: BitFlags<AccessFs>) -> Result<()> {
    // Landlock needs an open fd; a path we cannot open is simply not allowed.
    let Ok(file) = File::open(path) else {
        return Ok(());
    };

    match ruleset.add_rule(PathBeneath::new(&file, access)) {
        Ok(_) => Ok(()),
        // Skip rules the running kernel rejects rather than failing startup.
        Err(RulesetError::AddRules(_)) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Landlock error: {:?}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_virtualization_base_is_xdg_data_dir() {
        let paths = ConfigPaths::resolve().unwrap();
        let base = paths.data_dir.join("virtual-mounts");
        let mapper = PathMapper::from_env_or_default(&base).unwrap();
        for (source, dest) in mapper.mappings() {
            assert!(
                dest.starts_with(&base),
                "mapping {source:?} -> {dest:?} escapes virtualization base"
            );
        }
    }
}
