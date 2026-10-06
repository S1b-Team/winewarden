use std::path::Path;

pub fn redact_path(path: &Path) -> String {
    let display = path.display().to_string();
    if let Ok(home) = std::env::var("HOME") {
        return display.replace(&home, "~");
    }
    display
}
