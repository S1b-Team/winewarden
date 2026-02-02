use std::fs::File;
use std::path::Path;

use anyhow::Result;
use landlock::{
    Access, AccessFs, BitFlags, PathBeneath, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetError, ABI,
};

use crate::mount_ns::MountNamespaceBuilder;
use winewarden_core::trust::TrustTier;

/// Applies a complete sandbox (Landlock + Mount Namespace) to the current process.
/// This MUST be called before executing the untrusted code (e.g. in pre_exec).
pub fn apply_sandbox(prefix_root: &Path, tier: TrustTier) -> Result<()> {
    // Step 1: Set up mount namespace for path virtualization
    // This creates bind mounts that redirect sensitive paths to virtual locations
    setup_mount_namespace(prefix_root)?;

    // Step 2: Apply Landlock sandbox for additional restrictions
    apply_landlock_sandbox(prefix_root, tier)?;

    Ok(())
}

/// Sets up the mount namespace for path virtualization.
fn setup_mount_namespace(_prefix_root: &Path) -> Result<()> {
    // Create mount namespace with default mappings
    let data_dir = Path::new("/tmp/winewarden");
    let builder = MountNamespaceBuilder::new(data_dir.to_path_buf()).with_default_mappings()?;

    let mount_ns = builder.build();
    mount_ns.setup(_prefix_root)?;

    Ok(())
}

/// Applies Landlock sandbox for filesystem access control.
fn apply_landlock_sandbox(prefix_root: &Path, tier: TrustTier) -> Result<()> {
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

    // Build the ruleset
    let ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1))?
        .create()
        .map_err(|e| anyhow::anyhow!("Failed to create Landlock ruleset: {}", e))?;

    // We need a mutable ruleset to add rules
    let mut ruleset = ruleset;

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

    // 5. Special handling based on TrustTier
    match tier {
        TrustTier::Red => {
            // Strictly confined. The defaults above are already quite "Red"
            // (no access to home/Documents etc).
        }
        TrustTier::Yellow => {
            // Yellow might allow some extra integrations if defined?
            // For now, keep it same as Red for safety.
        }
        TrustTier::Green => {
            // Green might allow access to specific "My Documents" if configured?
            // But even green games shouldn't read .ssh.
            // Keeping the safe defaults is better.
        }
    }

    // Apply the ruleset
    let status = ruleset
        .restrict_self()
        .map_err(|e| anyhow::anyhow!("Failed to enforce Landlock ruleset: {}", e))?;

    if status.ruleset == landlock::RulesetStatus::FullyEnforced {
        // Success
    } else {
        // Partially enforced (maybe some fs features missing?)
        // Proceeding, but noting could be useful.
    }

    Ok(())
}

fn add_rule(ruleset: &mut RulesetCreated, path: &Path, access: BitFlags<AccessFs>) -> Result<()> {
    // Landlock requires an open file descriptor.

    let file = match File::open(path) {
        Ok(f) => f,

        Err(_) => return Ok(()), // If we can't open it, we can't allow it. Skip.
    };

    match ruleset.add_rule(PathBeneath::new(&file, access)) {
        Ok(_) => Ok(()),

        Err(RulesetError::AddRules(_e)) => {
            // Log warning?

            // "Failed to add rule for path: {:?} - {}", path, e

            // For now, ignore minor errors to avoid crashing start.

            Ok(())
        }

        Err(e) => Err(anyhow::anyhow!("Landlock error: {:?}", e)),
    }
}
