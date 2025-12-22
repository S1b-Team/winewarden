use std::path::Path;
use std::sync::mpsc::{Receiver, channel};

use anyhow::{Context, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use time::OffsetDateTime;

use winewarden_core::types::{AccessAttempt, AccessKind, AccessTarget};

pub struct FsWatcher {
    _watcher: RecommendedWatcher,
    receiver: Receiver<notify::Result<Event>>,
}

impl FsWatcher {
    pub fn new(path: &Path) -> Result<Self> {
        let (sender, receiver) = channel();
        let mut watcher = RecommendedWatcher::new(sender, notify::Config::default())
            .context("create filesystem watcher")?;
        watcher
            .watch(path, RecursiveMode::Recursive)
            .with_context(|| format!("watch {}", path.display()))?;
        Ok(Self { _watcher: watcher, receiver })
    }

    pub fn drain(&mut self) -> Vec<AccessAttempt> {
        let mut events = Vec::new();
        while let Ok(event) = self.receiver.try_recv() {
            if let Ok(event) = event {
                events.extend(convert_event(event));
            }
        }
        events
    }
}

fn convert_event(event: Event) -> Vec<AccessAttempt> {
    let kind = map_kind(&event.kind);
    let timestamp = OffsetDateTime::now_utc();
    event
        .paths
        .into_iter()
        .map(|path| AccessAttempt {
            timestamp,
            kind: kind.clone(),
            target: AccessTarget::Path(path),
            note: Some(format!("fs:{:?}", event.kind)),
        })
        .collect()
}

fn map_kind(kind: &EventKind) -> AccessKind {
    match kind {
        EventKind::Create(_) => AccessKind::Write,
        EventKind::Modify(_) => AccessKind::Write,
        EventKind::Remove(_) => AccessKind::Write,
        EventKind::Access(_) => AccessKind::Read,
        _ => AccessKind::Read,
    }
}
