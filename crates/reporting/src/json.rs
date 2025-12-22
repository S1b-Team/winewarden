use crate::SessionReport;

pub fn render_json(report: &SessionReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}
