use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct NetTelemetry {
    pub captured_at: OffsetDateTime,
    pub summary: String,
}
