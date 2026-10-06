# Security Policy

## Reporting a Vulnerability

If you discover a security issue in WineWarden, please report it privately:

- **Open a private security advisory** on GitHub:
  `Security` tab → `Report a vulnerability`
- Do **not** open a public issue, PR, or discussion for vulnerabilities
- Include reproduction steps, affected component (Landlock, seccomp handler,
  mount namespace, policy engine), and expected impact
- Allow reasonable time for response and coordinated disclosure before
  publishing anything

## Scope

WineWarden's security scope covers its **isolation stack**:

- **Landlock LSM** filesystem sandboxing
- **Seccomp user-notification** syscall interception and policy enforcement
- **Mount namespace** path virtualization and redirect
- Policy evaluation (sacred zones, redirects, process rules)
- Prefix hygiene and trust-store integrity

It does **not** attempt to detect or remove malware, bypass anti-cheat, or
police software provenance. See [docs/threat-model.md](docs/threat-model.md)
for the full threat model, including known gaps such as the seccomp
path-rewrite limitation and TOCTOU considerations.

## Sandboxing Requirements

WineWarden fails closed when its kernel prerequisites are unavailable:
unprivileged user namespaces (for the mount namespace) and Landlock (kernel
5.13+ recommended). A run that cannot set up the sandbox does not proceed
unsandboxed.

## Not Yet Implemented

- AppArmor / SELinux integration (profiles under `system/` are reference
  material only)

## Supported Versions

Only the most recent main branch is supported for security fixes.
