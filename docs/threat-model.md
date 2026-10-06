# Threat Model

## In Scope

- Windows executables attempting to escape Wine/Proton prefixes
- Access to sensitive host paths outside the prefix
- Unwanted access to system sockets or devices
- Prefix degradation over time
- Sandbox escape attempts against WineWarden's own enforcement layers:
  - **Landlock LSM** — filesystem access control (kernel-enforced)
  - **Seccomp user notification** — syscall interception and policy decisions
  - **Mount namespaces** — path virtualization and redirect of sensitive paths

## Sandbox Enforcement Layers

WineWarden's isolation stack, in order of application to a monitored child:

1. **Mount namespace** (created before exec): bind mounts remap sensitive paths
   (e.g. `$HOME`, `~/.config`) to per-user virtual locations under the XDG data
   dir. This is the **authoritative redirect mechanism** (see "Path Redirect
   Mechanism" below).
2. **Landlock ruleset**: kernel-enforced allowlist for filesystem access,
   scoped to the prefix and explicitly allowed device/socket paths. Acts as
   defense in depth for accesses that bypass syscall interception.
3. **Seccomp user notification** (`SECCOMP_FILTER_FLAG_NEW_LISTENER`): the
   handler intercepts network (`connect`, `bind`), filesystem (`open*`, `stat*`,
   `access*`, `mkdir*`), and process spawn (`execve`, `execveat`) syscalls,
   evaluates policy, and allows or denies each call.

## Known Gaps (tracked)

- **Seccomp path rewrite**: seccomp notify cannot rewrite path arguments.
  Redirect/virtualize decisions rely entirely on mount-namespace mappings;
  without coverage the syscall is denied (fail closed), not silently continued.
- **TOCTOU**: between the handler reading a path from process memory and the
  kernel executing the syscall, the target process may swap the memory contents.
  Landlock and the mount namespace bound the damage; seccomp decisions are
  best-effort for path-based syscalls.
- **Unprivileged user namespaces / Landlock availability**: some distros
  restrict unprivileged `CLONE_NEWNS` or ship kernels without Landlock.
  WineWarden requires both; without them a run fails closed rather than
  silently continuing unsandboxed.
- **Network policy is observe-first**: `connect`/`bind` are evaluated and may be
  denied, but DNS-level and per-host enforcement is limited to what the
  notifier sees.

## Out of Scope

- Malware removal or signature-based detection
- Anti-cheat bypass or interference
- Policing software provenance
- **AppArmor/SELinux integration** — planned, not currently implemented;
  WineWarden ships profiles under `system/` as reference material only

## Path Redirect Mechanism

The mount namespace is the **authoritative** mechanism for path redirect and
virtualization. Seccomp user notification evaluates policy, but it cannot
rewrite path arguments; it only decides allow/deny.

Consequently:

- If policy says `redirect`/`virtualize` **and** the mount namespace map covers
  the path, the syscall continues (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) and the
  bind mount remaps it to the virtual location.
- If policy says `redirect`/`virtualize` but the mount map does **not** cover
  the path, the syscall is **denied** (EPERM). It is never allowed to proceed
  against the original host path.
- Path comparisons (sacred zones and redirect mappings) are normalized
  lexically (`.`/`..` resolved, symlinks **not** followed).
- Landlock remains defense in depth for filesystem accesses that bypass
  notification.
