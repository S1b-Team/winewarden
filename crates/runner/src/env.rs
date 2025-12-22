use std::collections::HashMap;

pub fn sanitize_env(env: &HashMap<String, String>) -> HashMap<String, String> {
    let mut sanitized = env.clone();
    sanitized.remove("LD_PRELOAD");
    sanitized.remove("DYLD_INSERT_LIBRARIES");
    sanitized
}
