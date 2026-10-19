//! Follows a live session log while the monitor writes it.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use anyhow::{anyhow, Context, Result};
use reporting::live::{LiveEvent, ProcessState};

use crate::tui::app::{App, ProcessStatus};
use crate::tui::feed;

/// Reads new lines from a live log on each poll, keeping any partial line
/// until the rest of it arrives.
pub struct LiveTail {
    file: File,
    path: PathBuf,
    pending: Vec<u8>,
}

impl LiveTail {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open live log {}", path.display()))?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            pending: Vec::new(),
        })
    }

    /// Applies every complete line written since the last poll.
    pub fn poll(&mut self, app: &mut App) -> Result<()> {
        self.file
            .read_to_end(&mut self.pending)
            .with_context(|| format!("read live log {}", self.path.display()))?;
        let Some(end) = self.pending.iter().rposition(|&b| b == b'\n') else {
            return Ok(());
        };
        let complete: Vec<u8> = self.pending.drain(..=end).collect();
        for line in complete.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            // The monitor writes whole lines, so a line that doesn't parse is
            // skipped rather than ending the dashboard.
            if let Ok(event) = serde_json::from_slice::<LiveEvent>(line) {
                self.apply(app, event);
            }
        }
        Ok(())
    }

    fn apply(&self, app: &mut App, event: LiveEvent) {
        match event {
            LiveEvent::Session { metadata } => app.set_session(&metadata),
            LiveEvent::Access(event) => feed::apply_event(app, event),
            LiveEvent::Process { pid, exe, state } => match state {
                ProcessState::Started => {
                    let name = exe
                        .file_name()
                        .unwrap_or(exe.as_os_str())
                        .to_string_lossy()
                        .into_owned();
                    app.add_process(name, pid);
                }
                ProcessState::Exited => app.update_process_status(pid, ProcessStatus::Terminated),
            },
            LiveEvent::Trust(score) => app.update_trust_score(score),
            LiveEvent::End { .. } => {
                // The end event is the last write, so the file's mtime is
                // when the session finished, even if we read it much later.
                let since_end = fs::metadata(&self.path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| SystemTime::now().duration_since(t).ok())
                    .unwrap_or_default();
                let now = Instant::now();
                app.session_end = Some(now.checked_sub(since_end).unwrap_or(now));
                for process in &mut app.processes {
                    process.status = ProcessStatus::Terminated;
                }
            }
        }
    }
}

/// Path of the live log for `session`, or the newest log in `dir` when no
/// session is given.
pub fn session_log(dir: &Path, session: Option<&str>) -> Result<PathBuf> {
    if let Some(id) = session {
        let id = uuid::Uuid::parse_str(id).with_context(|| format!("invalid session id {id}"))?;
        return Ok(dir.join(format!("{id}.jsonl")));
    }
    let entries =
        fs::read_dir(dir).with_context(|| format!("no live sessions in {}", dir.display()))?;
    entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "jsonl"))
        .filter_map(|entry| Some((entry.metadata().ok()?.modified().ok()?, entry.path())))
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
        .ok_or_else(|| anyhow!("no live sessions in {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_engine::TrustScore;
    use reporting::live::LiveLog;
    use std::io::Write;
    use time::OffsetDateTime;
    use winewarden_core::trust::TrustTier;
    use winewarden_core::types::RunMetadata;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("winewarden-tail-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn metadata() -> RunMetadata {
        RunMetadata {
            session_id: uuid::Uuid::new_v4(),
            executable: PathBuf::from("/games/game.exe"),
            args: Vec::new(),
            started_at: OffsetDateTime::now_utc(),
            ended_at: None,
            trust_tier: TrustTier::Green,
        }
    }

    #[test]
    fn follows_a_growing_log() {
        let dir = temp_dir();
        let path = dir.join("s.jsonl");
        let mut log = LiveLog::create(&path).unwrap();
        log.write(&LiveEvent::Session {
            metadata: metadata(),
        });
        log.write(&LiveEvent::Process {
            pid: 42,
            exe: PathBuf::from("/games/game.exe"),
            state: ProcessState::Started,
        });

        let mut app = App::new();
        let mut tail = LiveTail::open(&path).unwrap();
        tail.poll(&mut app).unwrap();
        assert_eq!(app.trust_tier, TrustTier::Green);
        assert_eq!(app.processes[0].name, "game.exe");
        assert_eq!(app.processes[0].status, ProcessStatus::Running);
        assert!(app.trust_score.is_none());

        log.write(&LiveEvent::Trust(TrustScore::new(64, vec![])));
        tail.poll(&mut app).unwrap();
        assert_eq!(app.trust_score.as_ref().unwrap().score, 64);

        log.write(&LiveEvent::Process {
            pid: 42,
            exe: PathBuf::from("/games/game.exe"),
            state: ProcessState::Exited,
        });
        tail.poll(&mut app).unwrap();
        assert_eq!(app.processes[0].status, ProcessStatus::Terminated);
        assert!(app.session_end.is_none());

        log.write(&LiveEvent::End {
            stats: reporting::ReportStats::from_events(&[]),
            error: None,
        });
        tail.poll(&mut app).unwrap();
        assert!(app.session_end.is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn session_that_stopped_early_shows_as_ended() {
        let dir = temp_dir();
        let path = dir.join("s.jsonl");
        let mut log = LiveLog::create(&path).unwrap();
        log.write(&LiveEvent::Session {
            metadata: metadata(),
        });
        log.write(&LiveEvent::End {
            stats: reporting::ReportStats::from_events(&[]),
            error: Some("launch /games/game.exe: Invalid argument".to_string()),
        });

        let mut app = App::new();
        LiveTail::open(&path).unwrap().poll(&mut app).unwrap();
        assert!(app.session_end.is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn waits_for_the_rest_of_a_partial_line() {
        let dir = temp_dir();
        let path = dir.join("s.jsonl");
        let line = serde_json::to_string(&LiveEvent::Trust(TrustScore::new(30, vec![]))).unwrap();
        let (head, rest) = line.split_at(line.len() / 2);
        let mut file = File::create(&path).unwrap();
        file.write_all(head.as_bytes()).unwrap();

        let mut app = App::new();
        let mut tail = LiveTail::open(&path).unwrap();
        tail.poll(&mut app).unwrap();
        assert!(app.trust_score.is_none());

        writeln!(file, "{rest}").unwrap();
        tail.poll(&mut app).unwrap();
        assert_eq!(app.trust_score.as_ref().unwrap().score, 30);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn picks_named_or_newest_session() {
        let dir = temp_dir();
        assert!(session_log(&dir, None).is_err());
        assert!(session_log(&dir, Some("../../etc/passwd")).is_err());

        let id = uuid::Uuid::new_v4();
        assert_eq!(
            session_log(&dir, Some(&id.to_string())).unwrap(),
            dir.join(format!("{id}.jsonl"))
        );

        let older = dir.join("a.jsonl");
        let newer = dir.join("b.jsonl");
        fs::write(&older, "").unwrap();
        fs::write(&newer, "").unwrap();
        fs::write(dir.join("c.json"), "").unwrap();
        let earlier = SystemTime::now() - std::time::Duration::from_secs(60);
        File::options()
            .write(true)
            .open(&older)
            .unwrap()
            .set_modified(earlier)
            .unwrap();
        assert_eq!(session_log(&dir, None).unwrap(), newer);
        fs::remove_dir_all(dir).unwrap();
    }
}
