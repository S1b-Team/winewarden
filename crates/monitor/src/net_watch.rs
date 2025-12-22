use std::collections::HashSet;
use std::fs;

use time::OffsetDateTime;

use winewarden_core::types::{AccessAttempt, AccessKind, AccessTarget, NetworkTarget};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NetKey {
    pub protocol: String,
    pub host: String,
    pub port: u16,
}

pub fn collect_network_events(pid: u32, seen: &mut HashSet<NetKey>) -> Vec<AccessAttempt> {
    let mut events = Vec::new();
    events.extend(collect_from_table(pid, "tcp", seen));
    events.extend(collect_from_table(pid, "udp", seen));
    events
}

fn collect_from_table(pid: u32, protocol: &str, seen: &mut HashSet<NetKey>) -> Vec<AccessAttempt> {
    let path = format!("/proc/{pid}/net/{protocol}");
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };

    let mut events = Vec::new();
    for line in contents.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let remote = parts[2];
        if let Some((host, port)) = parse_remote(remote) {
            if host == "0.0.0.0" && port == 0 {
                continue;
            }
            let key = NetKey {
                protocol: protocol.to_string(),
                host: host.clone(),
                port,
            };
            if seen.insert(key.clone()) {
                events.push(AccessAttempt {
                    timestamp: OffsetDateTime::now_utc(),
                    kind: AccessKind::Network,
                    target: AccessTarget::Network(NetworkTarget {
                        host,
                        port,
                        protocol: protocol.to_string(),
                    }),
                    note: Some("connection observed".to_string()),
                });
            }
        }
    }

    events
}

fn parse_remote(value: &str) -> Option<(String, u16)> {
    let mut parts = value.split(':');
    let addr = parts.next()?;
    let port = parts.next()?;
    let port = u16::from_str_radix(port, 16).ok()?;

    if addr.len() == 8 {
        let host = ipv4_from_hex(addr)?;
        return Some((host, port));
    }
    None
}

fn ipv4_from_hex(value: &str) -> Option<String> {
    let raw = u32::from_str_radix(value, 16).ok()?;
    let bytes = raw.to_le_bytes();
    Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
}
