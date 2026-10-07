use std::fs;
use std::path::Path;

fn repo_config_files() -> Vec<std::path::PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let mut files = vec![
        root.join("config/default.toml"),
        root.join("config/pirate-safe.toml"),
        root.join("config/relaxed.toml"),
    ];
    let examples = root.join("config/examples");
    let mut example_files: Vec<_> = fs::read_dir(&examples)
        .expect("config/examples directory exists")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    example_files.sort();
    files.extend(example_files);
    files
}

#[test]
fn example_configs_parse_into_config() {
    for path in repo_config_files() {
        let contents =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        winewarden_core::config::Config::from_toml_str(&contents)
            .unwrap_or_else(|e| panic!("config {} failed to load: {}", path.display(), e));
    }
}
