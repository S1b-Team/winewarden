use std::os::unix::io::RawFd;
use anyhow::{Context, Result};
use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall};
use nix::sys::socket::{sendmsg, recvmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{OwnedFd, FromRawFd};

/// Installs a Seccomp filter that notifies on network and execution syscalls.
/// Returns the notification file descriptor.
pub fn install_seccomp_filter() -> Result<RawFd> {
    // Default action: Allow everything. We only want to intercept specific calls.
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)
        .context("Failed to create Seccomp context")?;

    // We want to intercept: connect, bind
    // And potentially execve if we want to track child processes.
    let syscalls = [
        "connect",
        "bind",
    ];

    for syscall_name in syscalls {
        let syscall = ScmpSyscall::from_name(syscall_name)
            .with_context(|| format!("Failed to resolve syscall {}", syscall_name))?;
        
        ctx.add_rule(ScmpAction::Notify, syscall)
            .with_context(|| format!("Failed to add rule for {}", syscall_name))?;
    }

    // Load the filter
    ctx.load().context("Failed to load Seccomp filter")?;

    // Get the notification FD
    let fd = ctx.get_notify_fd()
        .context("Failed to get Seccomp notification FD. Is your kernel new enough?")?;

    Ok(fd)
}

/// Sends a file descriptor over a Unix socket.
pub fn send_fd(socket: RawFd, fd_to_send: RawFd) -> Result<()> {
    let iov = [IoSlice::new(b"x")];
    let fds = [fd_to_send];
    let cmsgs = [ControlMessage::ScmRights(&fds)];
    
    sendmsg::<()>(socket, &iov, &cmsgs, MsgFlags::empty(), None)
        .context("Failed to send FD over socket")?;
    
    Ok(())
}

/// Receives a file descriptor from a Unix socket.
pub fn recv_fd(socket: RawFd) -> Result<OwnedFd> {
    let mut iov_buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut iov_buf)];
    let mut cmsg_buf = nix::cmsg_space!(RawFd);
    
    let msg = recvmsg::<()>(socket, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
        .context("Failed to receive FD from socket")?;
    
    for cmsg in msg.cmsgs()? {
        match cmsg {
            ControlMessageOwned::ScmRights(fds) => {
                if let Some(&fd) = fds.first() {
                    // Safety: We just received this FD from recvmsg, so we own it now.
                    return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
            _ => {}
        }
    }
    
    Err(anyhow::anyhow!("No FD received"))
}
