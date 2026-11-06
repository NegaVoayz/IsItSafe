pub fn default_download_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Downloads")
}

pub fn default_quarantine_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("IsItSafe")
        .join("quarantine")
}

fn development_config_file_from(executable: &Path) -> Option<PathBuf> {
    for directory in executable.ancestors().skip(1).take(6) {
        let manifest = directory.join("Cargo.toml");
        let config = directory.join("config.toml");
        if !manifest.is_file() || !config.is_file() {
            continue;
        }
        let is_this_project = fs::read_to_string(&manifest).is_ok_and(|contents| {
            contents
                .lines()
                .any(|line| line.trim() == "name = \"isitsafe\"")
        });
        if is_this_project {
            return Some(config);
        }
    }
    None
}

