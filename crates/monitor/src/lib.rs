use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::unistd::close;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use policy_engine::{PolicyContext, PolicyEngine};
use reporting::live::{LiveEvent, LiveLog, ProcessState};
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
    /// Directory for the live `<session_id>.jsonl` log; no log when unset
    #[serde(default)]
    pub live_log_dir: Option<PathBuf>,
}

const TRUST_INTERVAL: Duration = Duration::from_secs(1);

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

        let mut live = open_live_log(request.live_log_dir.as_deref(), session_id);
        live.write(&LiveEvent::Session {
            metadata: metadata.clone(),
        });

        let mut child_process = None;
        let mut seccomp_fd: Option<OwnedFd> = None;

        if !request.no_run {
            let (child, rx_fd) =
                self.spawn_process(&request.executable, &request.args, &request.prefix_root)?;
            live.write(&LiveEvent::Process {
                pid: child.id(),
                exe: request.executable.clone(),
                state: ProcessState::Started,
            });
            child_process = Some(child);

            if let Some(rx) = rx_fd {
                // Try to receive the seccomp notify FD from the child
                // We use the raw fd of rx to receive
                match syscalls::recv_fd(rx.as_raw_fd()) {
                    Ok(fd) => seccomp_fd = Some(fd),
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
            let mut last_trust = Instant::now();

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
                                    Ok(Some((attempt, decision))) => record(
                                        &mut evaluated,
                                        &mut live,
                                        ReportEvent { attempt, decision },
                                    ),
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
                            let event = ReportEvent {
                                attempt: event,
                                decision,
                            };
                            record(&mut evaluated, &mut live, event);
                        }
                    }
                }
                if live_config.proc {
                    for event in proc_watch::collect_process_events(child.id(), &mut seen_pids) {
                        let decision = self.policy.evaluate(&event, &policy_context);
                        let event = ReportEvent {
                            attempt: event,
                            decision,
                        };
                        record(&mut evaluated, &mut live, event);
                    }
                }
                if live_config.net {
                    for event in net_watch::collect_network_events(child.id(), &mut seen_net) {
                        let decision = self.policy.evaluate(&event, &policy_context);
                        let event = ReportEvent {
                            attempt: event,
                            decision,
                        };
                        record(&mut evaluated, &mut live, event);
                    }
                }
                if last_trust.elapsed() >= TRUST_INTERVAL {
                    let score = self.policy.calculate_trust_score(request.trust_tier);
                    live.write(&LiveEvent::Trust(score));
                    last_trust = Instant::now();
                }
            }

            live.write(&LiveEvent::Process {
                pid: child.id(),
                exe: request.executable.clone(),
                state: ProcessState::Exited,
            });
            // seccomp_fd drops here
        }

        let mut source: Box<dyn EventSource> = match &request.event_log {
            Some(path) => Box::new(JsonlEventSource::from_path(path)?),
            None => Box::new(NoopEventSource),
        };

        while let Some(event) = source.next_event()? {
            let decision = self.policy.evaluate(&event, &policy_context);
            let event = ReportEvent {
                attempt: event,
                decision,
            };
            record(&mut evaluated, &mut live, event);
        }

        metadata.ended_at = Some(OffsetDateTime::now_utc());
        let trust_signal = trust_signal_for_tier(request.trust_tier);
        let report = SessionReport::new(metadata, trust_signal, evaluated);
        let score = self.policy.calculate_trust_score(request.trust_tier);
        live.write(&LiveEvent::Trust(score));
        live.write(&LiveEvent::End {
            stats: report.stats.clone(),
        });
        Ok(report)
    }

    fn spawn_process(
        &self,
        executable: &Path,
        args: &[String],
        prefix: &Path,
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

        // `tx` moves into the pre_exec closure; the parent's copy closes when
        // `cmd` is dropped at the end of this function.
        let prefix = prefix.to_path_buf();
        unsafe {
            cmd.pre_exec(move || {
                sandbox::apply_sandbox(&prefix).map_err(|e| io::Error::other(e.to_string()))?;

                let notify_fd = syscalls::install_seccomp_filter()
                    .map_err(|e| io::Error::other(e.to_string()))?;

                syscalls::send_fd(tx.as_raw_fd(), notify_fd)
                    .map_err(|e| io::Error::other(e.to_string()))?;

                // Close the notify FD in the child (parent has it now via socket, or will have it)
                let _ = close(notify_fd);
                // tx drops and closes here

                Ok(())
            });
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("launch {}", executable.display()))?;

        Ok((child, Some(rx)))
    }
}

fn open_live_log(dir: Option<&Path>, session_id: Uuid) -> LiveLog {
    let Some(dir) = dir else {
        return LiveLog::disabled();
    };
    LiveLog::create(&dir.join(format!("{session_id}.jsonl"))).unwrap_or_else(|e| {
        eprintln!("Warning: live log unavailable: {e:#}");
        LiveLog::disabled()
    })
}

fn record(evaluated: &mut Vec<ReportEvent>, live: &mut LiveLog, event: ReportEvent) {
    live.write(&LiveEvent::Access(event.clone()));
    evaluated.push(event);
}
