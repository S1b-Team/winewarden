use time::OffsetDateTime;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ScheduledJob {
    pub name: String,
    pub next_run: OffsetDateTime,
}
