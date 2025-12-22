use std::path::Path;

pub fn redact_path(path: &Path) -> String {
    let display = path.display().to_string();
    if let Some(home) = std::env::var("HOME").ok() {
        return display.replace(&home, "~");
    }
    display
}
