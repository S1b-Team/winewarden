use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::unistd::close;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use policy_engine::{PolicyContext, PolicyEngine};
use reporting::{trust_signal_for_tier, ReportEvent, SessionReport};
use winewarden_core::trust::TrustTier;
use winewarden_core::types::{AccessAttempt, LiveMonitorConfig, RunMetadata};

pub mod fs_watch;
pub mod memory;
pub mod mount_ns;
pub mod net_watch;
pub mod path_redirect;
pub mod proc_watch;
pub mod sandbox;
pub mod seccomp_handler;
pub mod signals;
pub mod syscalls;

pub trait EventSource {
    fn next_event(&mut self) -> Result<Option<AccessAttempt>>;
}

pub struct NoopEventSource;

impl EventSource for NoopEventSource {
    fn next_event(&mut self) -> Result<Option<AccessAttempt>> {
        Ok(None)
    }
}

pub struct JsonlEventSource {
    reader: BufReader<File>,
}

impl JsonlEventSource {
    pub fn from_path(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("open event log {}", path.display()))?;
        Ok(Self {
            reader: BufReader::new(file),
        })
    }
}

impl EventSource for JsonlEventSource {
    fn next_event(&mut self) -> Result<Option<AccessAttempt>> {
        let mut line = String::new();
        let bytes = self.reader.read_line(&mut line)?;
        if bytes == 0 {
            return Ok(None);
        }
        let event: AccessAttempt = serde_json::from_str(&line).context("parse event JSON")?;
        Ok(Some(event))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub prefix_root: PathBuf,
    pub trust_tier: TrustTier,
    pub event_log: Option<PathBuf>,
    pub no_run: bool,
    pub live_monitor: Option<LiveMonitorConfig>,
}

pub struct Monitor {
    policy: PolicyEngine,
}

impl Monitor {
    pub fn new(policy: PolicyEngine) -> Self {
        Self { policy }
    }

    pub fn run(&self, request: RunRequest) -> Result<SessionReport> {
        let session_id = Uuid::new_v4();
        let started_at = OffsetDateTime::now_utc();
        let mut metadata = RunMetadata {
            session_id,
            executable: request.executable.clone(),
            args: request.args.clone(),
            started_at,
            ended_at: None,
            trust_tier: request.trust_tier,
        };

        let mut child_process = None;
        let mut seccomp_fd: Option<OwnedFd> = None;

        if !request.no_run {
            let (child, rx_fd) = self.spawn_process(
                &request.executable,
                &request.args,
                &request.prefix_root,
                request.trust_tier,
            )?;
            child_process = Some(child);

            if let Some(rx) = rx_fd {
                // Try to receive the seccomp notify FD from the child
                // We use the raw fd of rx to receive
                match syscalls::recv_fd(rx.as_raw_fd()) {
                    Ok(fd) => {
                        // println!("Seccomp active. Notification FD: {}", fd.as_raw_fd());
                        seccomp_fd = Some(fd);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to receive Seccomp FD: {}", e);
                    }
                }
                // rx is OwnedFd, drops here and closes socket
            }
        }

        let policy_context = PolicyContext {
            prefix_root: request.prefix_root.clone(),
            trust_tier: request.trust_tier,
        };

        // Create handler context for seccomp filesystem operations
        let data_dir = request.prefix_root.join(".winewarden");
        let mut handler_ctx = seccomp_handler::HandlerContext::new(data_dir)?;

        let mut evaluated = Vec::new();
        if let Some(mut child) = child_process {
            let live_config = request.live_monitor.clone().unwrap_or_default();
            let mut fs_watcher = if live_config.fs {
                Some(fs_watch::FsWatcher::new(&request.prefix_root)?)
            } else {
                None
            };
            let mut seen_pids = HashSet::new();
            let mut seen_net = HashSet::new();
            seen_pids.insert(child.id());

            while child.try_wait()?.is_none() {
                // Handle Seccomp Notifications
                if let Some(fd) = &seccomp_fd {
                    let mut poll_fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];

                    let timeout_ms = if live_config.enabled() {
                        live_config.poll_interval_ms as i32
                    } else {
                        100
                    };

                    // PollTimeout::try_from is available for i32
                    let timeout = PollTimeout::try_from(timeout_ms).unwrap_or(PollTimeout::NONE);

                    match poll(&mut poll_fds, timeout) {
                        Ok(_) => {
                            if poll_fds[0]
                                .revents()
                                .unwrap_or(PollFlags::empty())
                                .contains(PollFlags::POLLIN)
                            {
                                match seccomp_handler::handle_notification(
                                    fd.as_raw_fd(),
                                    &self.policy,
                                    &policy_context,
                                    &mut handler_ctx,
                                ) {
                                    Ok(Some((attempt, decision))) => {
                                        evaluated.push(ReportEvent { attempt, decision });
                                    }
                                    Ok(None) => {} // Notification handled (e.g. unknown syscall or ignored)
                                    Err(e) => eprintln!("Seccomp handler error: {}", e),
                                }
                            }
                        }
                        Err(e) => {
                            if e != nix::errno::Errno::EINTR {
                                eprintln!("Poll error: {}", e);
                            }
                        }
                    }
                } else {
                    // Fallback to sleep if no seccomp
                    if live_config.enabled() {
                        sleep(Duration::from_millis(live_config.poll_interval_ms));
                    } else {
                        // Wait for child if no monitoring and no seccomp?
                        // Just wait briefly to avoid busy loop
                        sleep(Duration::from_millis(100));
                    }
                }

                if live_config.fs {
                    if let Some(watcher) = fs_watcher.as_mut() {
                        for event in watcher.drain() {
                            let decision = self.policy.evaluate(&event, &policy_context);
                            evaluated.push(ReportEvent {
                                attempt: event,
                                decision,
                            });
                        }
                    }
                }
                if live_config.proc {
                    for event in proc_watch::collect_process_events(child.id(), &mut seen_pids) {
                        let decision = self.policy.evaluate(&event, &policy_context);
                        evaluated.push(ReportEvent {
                            attempt: event,
                            decision,
                        });
                    }
                }
                if live_config.net {
                    for event in net_watch::collect_network_events(child.id(), &mut seen_net) {
                        let decision = self.policy.evaluate(&event, &policy_context);
                        evaluated.push(ReportEvent {
                            attempt: event,
                            decision,
                        });
                    }
                }
            }

            // seccomp_fd drops here
        }

        let mut source: Box<dyn EventSource> = match &request.event_log {
            Some(path) => Box::new(JsonlEventSource::from_path(path)?),
            None => Box::new(NoopEventSource),
        };

        while let Some(event) = source.next_event()? {
            let decision = self.policy.evaluate(&event, &policy_context);
            evaluated.push(ReportEvent {
                attempt: event,
                decision,
            });
        }

        metadata.ended_at = Some(OffsetDateTime::now_utc());
        let trust_signal = trust_signal_for_tier(request.trust_tier);
        Ok(SessionReport::new(metadata, trust_signal, evaluated))
    }

    fn spawn_process(
        &self,
        executable: &Path,
        args: &[String],
        prefix: &Path,
        tier: TrustTier,
    ) -> Result<(std::process::Child, Option<OwnedFd>)> {
        let mut cmd = Command::new(executable);
        cmd.args(args);

        // Create socket pair for Seccomp FD passing
        let (rx, tx) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::empty(),
        )
        .context("socketpair failed")?;

        // Apply Landlock sandbox
        // We clone the path/tier because the closure needs to own them or move them
        let prefix = prefix.to_path_buf();
        unsafe {
            cmd.pre_exec(move || {
                // 1. Landlock
                sandbox::apply_sandbox(&prefix, tier)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                // 2. Seccomp (Install filter and send FD)
                let notify_fd = syscalls::install_seccomp_filter()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                syscalls::send_fd(tx.as_raw_fd(), notify_fd)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                // Close the notify FD in the child (parent has it now via socket, or will have it)
                let _ = close(notify_fd);
                // tx drops and closes here

                Ok(())
            });
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("launch {}", executable.display()))?;

        // tx drops and closes in parent (Wait, tx was moved to closure? No, only in closure scope)
        // Actually, if we use `move ||`, `tx` is moved into closure. It is NOT available in parent anymore?
        // Ah, `socketpair` returns objects. If I move `tx` into closure, parent doesn't have it.
        // BUT, `pre_exec` runs in child.
        // Wait, `Command::pre_exec` closure is run in the child process.
        // But the closure definition happens in the parent.
        // So `tx` is moved into the closure structure.
        // Does the parent still own `tx`? No.
        // So `tx` is dropped in the parent when the closure is dropped?
        // `cmd` owns the closure. `cmd` is dropped after `spawn`? No, `spawn` consumes `&mut cmd`? No.
        // `spawn` creates the child.
        // IMPORTANT: We need to ensure `tx` is closed in the PARENT so the child sees EOF/closure if needed?
        // Actually, `socketpair` creates FDs. If we move `tx` into closure, it's owned by the closure.
        // When `cmd` is dropped (at end of `spawn_process`), the closure is dropped, and `tx` is closed in the parent process.
        // This is correct. We don't need to manually close `tx` in parent.

        Ok((child, Some(rx)))
    }
}
