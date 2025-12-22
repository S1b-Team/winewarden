use super::HygieneFinding;

pub fn summarize(findings: &[HygieneFinding]) -> String {
    if findings.is_empty() {
        return "Prefix hygiene looks clean.".to_string();
    }
    format!("Prefix hygiene findings: {}", findings.len())
}
