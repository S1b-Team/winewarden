use std::path::PathBuf;

pub fn fallback_redirect() -> PathBuf {
    PathBuf::from("/dev/null")
}
