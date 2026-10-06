use anyhow::{Context, Result};
use byteorder::{BigEndian, ByteOrder, NativeEndian};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;
use time::OffsetDateTime;

use crate::memory;
use crate::path_redirect::{CopyOnWrite, PathMapper};
use policy_engine::{DecisionAction, PolicyContext, PolicyDecision, PolicyEngine};
use winewarden_core::types::{AccessAttempt, AccessKind, AccessTarget, NetworkTarget};

// -- Linux Seccomp Userspace Notification ABI --

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

// Define ioctls using nix macros
// nix 0.27+ uses `ioctl_readwrite!`
nix::ioctl_readwrite!(seccomp_notif_recv, b'!', 0, SeccompNotif);
nix::ioctl_readwrite!(seccomp_notif_send, b'!', 1, SeccompNotifResp);

// Syscall numbers (x86_64)
const SYS_CONNECT: i32 = 42;
const SYS_BIND: i32 = 49;
// Process spawn syscalls
const SYS_EXECVE: i32 = 59;
const SYS_EXECVEAT: i32 = 322;

// Filesystem syscalls
const SYS_OPEN: i32 = 2;
const SYS_OPENAT: i32 = 257;
const SYS_OPENAT2: i32 = 437;
const SYS_STAT: i32 = 4;
const SYS_LSTAT: i32 = 6;
const SYS_FSTATAT: i32 = 262;
const SYS_ACCESS: i32 = 21;
const SYS_FACCESSAT: i32 = 269;
const SYS_FACCESSAT2: i32 = 439;
const SYS_MKDIR: i32 = 83;
const SYS_MKDIRAT: i32 = 258;

// Address Families
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Maximum path length to read from process memory
const MAX_PATH_LEN: usize = 4096;

/// Context for handling seccomp notifications
pub struct HandlerContext {
    /// Path mapper for redirect/virtualize operations
    pub mapper: PathMapper,
}

impl HandlerContext {
    pub fn new(data_dir: std::path::PathBuf) -> Result<Self> {
        let mapper = PathMapper::from_env_or_default(&data_dir)?;
        Ok(Self { mapper })
    }
}

pub fn handle_notification(
    seccomp_fd: RawFd,
    policy: &PolicyEngine,
    context: &PolicyContext,
    handler_ctx: &mut HandlerContext,
) -> Result<Option<(AccessAttempt, PolicyDecision)>> {
    // 1. Receive Notification
    let mut req = SeccompNotif::default();
    unsafe {
        seccomp_notif_recv(seccomp_fd, &mut req)
            .context("ioctl SECCOMP_IOCTL_NOTIF_RECV failed")?;
    }

    // 2. Analyze Syscall
    let syscall = req.data.nr;
    let mut decision_action = DecisionAction::Allow;
    let mut event_data = None;
    let mut path_redirect: Option<std::path::PathBuf> = None;

    // Handle network syscalls
    if syscall == SYS_CONNECT || syscall == SYS_BIND {
        event_data = handle_network_syscall(&req, policy, context, &mut decision_action)?;
    }
    // Handle process spawn syscalls (execve/execveat) via process policy
    else if syscall == SYS_EXECVE || syscall == SYS_EXECVEAT {
        event_data = handle_process_syscall(&req, syscall, policy, context, &mut decision_action)?;
    }
    // Handle filesystem syscalls
    else if is_filesystem_syscall(syscall) {
        event_data = handle_filesystem_syscall(
            &req,
            syscall,
            policy,
            context,
            handler_ctx,
            &mut decision_action,
            &mut path_redirect,
        )?;
    } else {
        eprintln!("Intercepted unexpected syscall nr: {}", syscall);
    }

    // 6. Send Response
    let mut resp = SeccompNotifResp {
        id: req.id,
        val: 0,
        error: 0,
        flags: 0,
    };

    // Set error code based on decision
    if matches!(decision_action, DecisionAction::Deny) {
        resp.error = 1; // EPERM
    }

    // A redirect/virtualize decision only reaches this point when the mount
    // namespace covers the path (mapper produced a mapping). The mount NS is
    // the authoritative redirect mechanism; the syscall continues and the
    // bind mount remaps it to the virtual location. Without a mapping the
    // decision was already downgraded to Deny (fail closed).
    if path_redirect.is_some() && matches!(decision_action, DecisionAction::Allow) {
        resp.error = 0;
        resp.flags = 1; // SECCOMP_USER_NOTIF_FLAG_CONTINUE
    } else if matches!(decision_action, DecisionAction::Allow) {
        resp.flags = 1; // SECCOMP_USER_NOTIF_FLAG_CONTINUE
    }

    unsafe {
        seccomp_notif_send(seccomp_fd, &mut resp)
            .context("ioctl SECCOMP_IOCTL_NOTIF_SEND failed")?;
    }

    Ok(event_data)
}

/// Handles execve/execveat by evaluating the process spawn policy.
fn handle_process_syscall(
    req: &SeccompNotif,
    syscall: i32,
    policy: &PolicyEngine,
    context: &PolicyContext,
    decision_action: &mut DecisionAction,
) -> Result<Option<(AccessAttempt, PolicyDecision)>> {
    let pid = req.pid as i32;
    // execve(filename, argv, envp): args[0] = filename
    // execveat(dirfd, pathname, argv, envp, flags): args[1] = pathname
    let path_ptr = if syscall == SYS_EXECVE {
        req.data.args[0]
    } else {
        req.data.args[1]
    };
    let path = match read_null_terminated_string(pid, path_ptr, MAX_PATH_LEN) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Failed to read exec path from process {}: {}", req.pid, e);
            // Fail closed: unreadable exec path is denied
            *decision_action = DecisionAction::Deny;
            return Ok(None);
        }
    };
    let process_name = std::path::Path::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or(path.clone());
    let policy_decision = policy.evaluate_process_spawn(&process_name, context);
    *decision_action = policy_decision.action.clone();
    let attempt = AccessAttempt {
        timestamp: OffsetDateTime::now_utc(),
        kind: AccessKind::Execute,
        target: AccessTarget::Path(std::path::PathBuf::from(&path)),
        note: Some(format!("Process spawn: {}", process_name)),
    };
    Ok(Some((attempt, policy_decision)))
}

fn is_filesystem_syscall(syscall: i32) -> bool {
    matches!(
        syscall,
        SYS_OPEN
            | SYS_OPENAT
            | SYS_OPENAT2
            | SYS_STAT
            | SYS_LSTAT
            | SYS_FSTATAT
            | SYS_ACCESS
            | SYS_FACCESSAT
            | SYS_FACCESSAT2
            | SYS_MKDIR
            | SYS_MKDIRAT
    )
}

fn handle_network_syscall(
    req: &SeccompNotif,
    policy: &PolicyEngine,
    context: &PolicyContext,
    decision_action: &mut DecisionAction,
) -> Result<Option<(AccessAttempt, PolicyDecision)>> {
    // connect(fd, addr, addrlen)
    // args[0] = fd, args[1] = addr (ptr), args[2] = addrlen
    let remote_addr_ptr = req.data.args[1];
    let addrlen = req.data.args[2] as usize;

    if addrlen == 0 {
        return Ok(None);
    }

    // 3. Read Memory (Address)
    match memory::read_remote_memory(req.pid as i32, remote_addr_ptr, addrlen) {
        Ok(bytes) => {
            // 4. Parse IP/Port
            if let Some(target) = parse_sockaddr(&bytes) {
                // 5. Evaluate Policy
                let attempt = AccessAttempt {
                    timestamp: OffsetDateTime::now_utc(),
                    kind: AccessKind::Network,
                    target: AccessTarget::Network(target),
                    note: Some(format!("Syscall: {}", req.data.nr)),
                };

                let policy_decision = policy.evaluate(&attempt, context);

                let result = Some((attempt.clone(), policy_decision.clone()));

                if let DecisionAction::Deny = policy_decision.action {
                    *decision_action = DecisionAction::Deny;
                }

                return Ok(result);
            }
        }
        Err(e) => {
            eprintln!("Failed to read syscall arguments: {}", e);
        }
    }

    Ok(None)
}

fn handle_filesystem_syscall(
    req: &SeccompNotif,
    syscall: i32,
    policy: &PolicyEngine,
    context: &PolicyContext,
    handler_ctx: &mut HandlerContext,
    decision_action: &mut DecisionAction,
    path_redirect: &mut Option<std::path::PathBuf>,
) -> Result<Option<(AccessAttempt, PolicyDecision)>> {
    // Read the path argument from process memory
    let path_result = read_path_argument(req, syscall);

    let path_str = match path_result {
        Some(Ok(path)) => path,
        Some(Err(e)) => {
            eprintln!("Failed to read path from process {}: {}", req.pid, e);
            return Ok(None);
        }
        None => {
            // Unknown syscall or no path to read
            return Ok(None);
        }
    };

    let path = std::path::PathBuf::from(&path_str);

    // Evaluate policy
    let attempt = AccessAttempt {
        timestamp: OffsetDateTime::now_utc(),
        kind: AccessKind::Read, // Will be refined based on syscall
        target: AccessTarget::Path(path.clone()),
        note: Some(format!("Syscall: {}", syscall)),
    };

    let policy_decision = policy.evaluate(&attempt, context);
    let result = Some((attempt.clone(), policy_decision.clone()));

    // Handle the decision
    match &policy_decision.action {
        DecisionAction::Deny => {
            *decision_action = DecisionAction::Deny;
        }
        DecisionAction::Redirect(_target) => {
            // The mount namespace is the only mechanism that actually remaps
            // paths. If the mount map does not cover this path, the syscall
            // would continue against the original host path: fail closed.
            match handler_ctx.mapper.map_path(&path) {
                Some(mapped) => {
                    *path_redirect = Some(mapped);
                    *decision_action = DecisionAction::Allow;
                }
                None => {
                    eprintln!(
                        "Redirect policy for {} has no mount mapping; denying",
                        path.display()
                    );
                    *decision_action = DecisionAction::Deny;
                }
            }
        }
        DecisionAction::Virtualize(_target) => {
            // Same fail-closed rule as Redirect: without a mount mapping the
            // syscall would hit the original host path.
            match handler_ctx.mapper.map_path(&path) {
                Some(mapped) => {
                    if let Some(parent) = mapped.parent() {
                        let _ = CopyOnWrite::ensure_dir_exists(parent);
                    }
                    *path_redirect = Some(mapped);
                    *decision_action = DecisionAction::Allow;
                }
                None => {
                    eprintln!(
                        "Virtualize policy for {} has no mount mapping; denying",
                        path.display()
                    );
                    *decision_action = DecisionAction::Deny;
                }
            }
        }
        DecisionAction::Allow => {
            *decision_action = DecisionAction::Allow;
        }
    }

    Ok(result)
}

/// Reads the path argument from a filesystem syscall
fn read_path_argument(req: &SeccompNotif, syscall: i32) -> Option<Result<String>> {
    let pid = req.pid as i32;

    match syscall {
        // open(pathname, flags, mode)
        // args[0] = pathname (const char *)
        SYS_OPEN | SYS_ACCESS | SYS_STAT | SYS_LSTAT | SYS_MKDIR => {
            let path_ptr = req.data.args[0];
            Some(read_null_terminated_string(pid, path_ptr, MAX_PATH_LEN))
        }

        // openat(dirfd, pathname, flags, mode)
        // args[0] = dirfd, args[1] = pathname
        SYS_OPENAT | SYS_MKDIRAT | SYS_FACCESSAT => {
            let dirfd = req.data.args[0] as i32;
            let path_ptr = req.data.args[1];

            Some(read_dirfd_path(pid, dirfd, path_ptr))
        }

        // fstatat(dirfd, pathname, statbuf, flags)
        // args[0] = dirfd, args[1] = pathname
        SYS_FSTATAT => {
            let dirfd = req.data.args[0] as i32;
            let path_ptr = req.data.args[1];

            Some(read_dirfd_path(pid, dirfd, path_ptr))
        }

        // openat2(dirfd, pathname, open_how, size)
        // args[0] = dirfd, args[1] = pathname
        SYS_OPENAT2 => {
            let dirfd = req.data.args[0] as i32;
            let path_ptr = req.data.args[1];
            Some(read_dirfd_path(pid, dirfd, path_ptr))
        }

        // faccessat2(dirfd, pathname, mode, flags)
        SYS_FACCESSAT2 => {
            let dirfd = req.data.args[0] as i32;
            let path_ptr = req.data.args[1];

            Some(read_dirfd_path(pid, dirfd, path_ptr))
        }

        _ => None,
    }
}

/// Resolves a dirfd-relative path to an absolute path via /proc/<pid>/fd/<dirfd>.
/// Returns Ok(None) when dirfd is AT_FDCWD or the path is absolute.
/// Returns Err when the dirfd cannot be resolved (fail closed).
fn resolve_dirfd_path(pid: i32, dirfd: i32, path: &str) -> Result<Option<String>> {
    const AT_FDCWD: i32 = -100;
    if dirfd == AT_FDCWD || path.starts_with('/') {
        return Ok(None);
    }
    let link = format!("/proc/{pid}/fd/{dirfd}");
    let target = std::fs::read_link(&link)
        .map_err(|e| anyhow::anyhow!("resolve dirfd {dirfd} of pid {pid}: {e}"))?;
    let base = target.to_string_lossy();
    let joined = if base.ends_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    };
    Ok(Some(joined))
}

/// Reads a path argument and resolves dirfd-relative paths (fail closed).
fn read_dirfd_path(pid: i32, dirfd: i32, path_ptr: u64) -> Result<String> {
    let path = read_null_terminated_string(pid, path_ptr, MAX_PATH_LEN)?;
    match resolve_dirfd_path(pid, dirfd, &path)? {
        Some(resolved) => Ok(resolved),
        None => Ok(path),
    }
}
/// Reads a null-terminated string from remote process memory
fn read_null_terminated_string(pid: i32, addr: u64, max_len: usize) -> Result<String> {
    // Read in chunks to find the null terminator
    let chunk_size = 256;
    let mut result = Vec::new();
    let mut offset = 0;

    while offset < max_len {
        let to_read = chunk_size.min(max_len - offset);
        let chunk = memory::read_remote_memory(pid, addr + offset as u64, to_read)?;

        // Look for null terminator
        if let Some(null_pos) = chunk.iter().position(|&b| b == 0) {
            result.extend_from_slice(&chunk[..null_pos]);
            break;
        }

        result.extend_from_slice(&chunk);
        offset += to_read;

        // If we hit max_len without finding null, truncate
        if offset >= max_len {
            break;
        }
    }

    String::from_utf8(result).context("Path is not valid UTF-8")
}

fn parse_sockaddr(data: &[u8]) -> Option<NetworkTarget> {
    if data.len() < 2 {
        return None;
    }

    let family = NativeEndian::read_u16(&data[0..2]);

    match family {
        AF_INET if data.len() >= 8 => {
            // struct sockaddr_in { short sin_family; u16 sin_port; struct in_addr sin_addr; ... }
            let port = BigEndian::read_u16(&data[2..4]);
            let ip_bytes = &data[4..8];
            let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            Some(NetworkTarget {
                host: ip.to_string(),
                port,
                protocol: "tcp/udp".to_string(),
            })
        }
        AF_INET6 if data.len() >= 24 => {
            // struct sockaddr_in6
            let port = BigEndian::read_u16(&data[2..4]);
            // flowinfo 4..8
            let ip_u16s: Vec<u16> = (0..8)
                .map(|i| BigEndian::read_u16(&data[8 + i * 2..10 + i * 2]))
                .collect();
            let ip = Ipv6Addr::new(
                ip_u16s[0], ip_u16s[1], ip_u16s[2], ip_u16s[3], ip_u16s[4], ip_u16s[5], ip_u16s[6],
                ip_u16s[7],
            );
            Some(NetworkTarget {
                host: ip.to_string(),
                port,
                protocol: "tcp/udp".to_string(),
            })
        }
        _ => None, // Unix sockets, etc.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_fdcwd_and_absolute_paths_pass_through() {
        let pid = std::process::id() as i32;
        assert_eq!(resolve_dirfd_path(pid, -100, "relative.txt").unwrap(), None);
        assert_eq!(
            resolve_dirfd_path(pid, 3, "/absolute/path.txt").unwrap(),
            None
        );
    }

    #[test]
    fn unresolvable_dirfd_fails_closed() {
        let pid = std::process::id() as i32;
        let bogus = i32::MAX;
        let result = resolve_dirfd_path(pid, bogus, "relative.txt");
        assert!(result.is_err(), "expected error for unresolvable dirfd");
    }

    #[test]
    fn dirfd_resolves_via_proc_fd() {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::open(dir.path()).unwrap();
        use std::os::unix::io::AsRawFd;
        let dirfd = file.as_raw_fd();
        let pid = std::process::id() as i32;
        let resolved = resolve_dirfd_path(pid, dirfd, "game.cfg")
            .unwrap()
            .expect("expected resolved path");
        assert!(resolved.ends_with("game.cfg"), "{resolved}");
        assert!(resolved.starts_with('/'), "{resolved}");
    }
}
