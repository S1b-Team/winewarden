use std::path::Path;

#[derive(Debug, Clone)]
pub enum RunnerHint {
    Steam,
    Lutris,
    Heroic,
    Manual,
}

pub fn detect_hint(executable: &Path) -> RunnerHint {
    let value = executable.to_string_lossy();
    if value.contains("steam") {
        RunnerHint::Steam
    } else if value.contains("lutris") {
        RunnerHint::Lutris
    } else if value.contains("heroic") {
        RunnerHint::Heroic
    } else {
        RunnerHint::Manual
    }
}
