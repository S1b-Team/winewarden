use crate::ReportEvent;

pub fn timeline(events: &[ReportEvent]) -> Vec<String> {
    events
        .iter()
        .map(|event| format!("{:?}: {}", event.attempt.timestamp, event.decision.reason))
        .collect()
}
