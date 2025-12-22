use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use time::OffsetDateTime;

use winewarden_core::types::{AccessAttempt, AccessKind, AccessTarget};

pub fn collect_process_events(root_pid: u32, seen: &mut HashSet<u32>) -> Vec<AccessAttempt> {
    let mut new_events = Vec::new();
    let mut queue = vec![root_pid];

    while let Some(pid) = queue.pop() {
        for child in read_children(pid) {
            if seen.insert(child) {
                if let Some(exe_path) = read_exe(child) {
                    new_events.push(AccessAttempt {
                        timestamp: OffsetDateTime::now_utc(),
                        kind: AccessKind::Execute,
                        target: AccessTarget::Path(exe_path),
                        note: Some(format!("child process pid {child}")),
                    });
                }
                queue.push(child);
            }
        }
    }

    new_events
}

fn read_children(pid: u32) -> Vec<u32> {
    let path = format!("/proc/{pid}/task/{pid}/children");
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };
    contents
        .split_whitespace()
        .filter_map(|value| value.parse::<u32>().ok())
        .collect()
}

fn read_exe(pid: u32) -> Option<PathBuf> {
    let path = format!("/proc/{pid}/exe");
    fs::read_link(path).ok()
}
