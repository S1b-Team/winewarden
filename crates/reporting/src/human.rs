use crate::SessionReport;

pub fn render_human(report: &SessionReport) -> String {
    report.human_summary()
}
