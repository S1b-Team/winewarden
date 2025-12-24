use std::io::IoSliceMut;
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::Pid;
use anyhow::{Context, Result};

/// Reads memory from a remote process.
pub fn read_remote_memory(pid: i32, remote_addr: u64, len: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; len];
    // process_vm_readv requires IoSliceMut for local buffer
    let mut local_iov = [IoSliceMut::new(&mut buffer)];
    let remote_iov = [RemoteIoVec {
        base: remote_addr as usize,
        len,
    }];

    // process_vm_readv returns the number of bytes read
    let bytes_read = process_vm_readv(Pid::from_raw(pid), &mut local_iov, &remote_iov)
        .with_context(|| format!("Failed to read remote memory from PID {}", pid))?;

    if bytes_read != len {
        // It's possible to read less if we hit unmapped memory, but for a sockaddr it shouldn't happen
        // unless the game is buggy or malicious.
        return Err(anyhow::anyhow!("Partial read: expected {} bytes, got {}", len, bytes_read));
    }

    Ok(buffer)
}