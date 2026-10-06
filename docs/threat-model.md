# Threat Model

## In Scope
- Windows executables attempting to escape Wine/Proton prefixes
- Access to sensitive host paths outside the prefix
- Unwanted access to system sockets or devices
- Prefix degradation over time

## Out of Scope
- Malware removal or signature-based detection
- Kernel-level protection
- Anti-cheat bypass or interference
- Policing software provenance

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
- Landlock remains defense in depth for filesystem accesses that bypass
  notification.
