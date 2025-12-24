use std::os::unix::io::RawFd;
use std::net::{Ipv4Addr, Ipv6Addr};
use anyhow::{Context, Result};
use byteorder::{BigEndian, ByteOrder, NativeEndian};
use time::OffsetDateTime;

use winewarden_core::types::{AccessAttempt, AccessKind, AccessTarget, NetworkTarget};
use policy_engine::{PolicyEngine, PolicyContext, PolicyDecision, DecisionAction};
use crate::memory;

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

// Address Families
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

pub fn handle_notification(
    seccomp_fd: RawFd,
    policy: &PolicyEngine,
    context: &PolicyContext,
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

    if syscall == SYS_CONNECT || syscall == SYS_BIND {
        // connect(fd, addr, addrlen)
        // args[0] = fd, args[1] = addr (ptr), args[2] = addrlen
        let remote_addr_ptr = req.data.args[1];
        let addrlen = req.data.args[2] as usize;

        if addrlen > 0 {
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
                            note: Some(format!("Syscall: {}", syscall)),
                        };

                        let policy_decision = policy.evaluate(&attempt, context);
                        
                        event_data = Some((attempt, policy_decision.clone()));
                        
                        match policy_decision.action {
                            DecisionAction::Deny => {
                                decision_action = DecisionAction::Deny;
                            }
                            _ => {} // Allow, Redirect (Treat as Allow for net for now), etc.
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read syscall arguments: {}", e);
                }
            }
        }
    } else {
        eprintln!("Intercepted unexpected syscall nr: {}", syscall);
    }

    // 6. Send Response
    let resp = SeccompNotifResp {
        id: req.id,
        val: 0,
        error: if matches!(decision_action, DecisionAction::Deny) { 
            1 // EPERM 
        } else { 
            0 
        },
        flags: 0, 
    };
    
    // Fix flags based on decision
    let mut final_resp = resp;
    if matches!(decision_action, DecisionAction::Allow) {
        final_resp.flags = 1; // SECCOMP_USER_NOTIF_FLAG_CONTINUE
        final_resp.error = 0;
        final_resp.val = 0;
    }
    
    // The send ioctl is also IOWR, so passing &mut is correct for ioctl_read_write!
    // But resp is input-only for us. We pass &mut because the macro signature requires it.
    unsafe {
        seccomp_notif_send(seccomp_fd, &mut final_resp)
             .context("ioctl SECCOMP_IOCTL_NOTIF_SEND failed")?;
    }

    Ok(event_data)
}

fn parse_sockaddr(data: &[u8]) -> Option<NetworkTarget> {
    if data.len() < 2 { return None; }
    
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
            let ip_u16s: Vec<u16> = (0..8).map(|i| BigEndian::read_u16(&data[8 + i*2 .. 10 + i*2])).collect();
            let ip = Ipv6Addr::new(
                ip_u16s[0], ip_u16s[1], ip_u16s[2], ip_u16s[3],
                ip_u16s[4], ip_u16s[5], ip_u16s[6], ip_u16s[7]
            );
            Some(NetworkTarget {
                host: ip.to_string(),
                port,
                protocol: "tcp/udp".to_string(),
            })
        }
        _ => None // Unix sockets, etc.
    }
}