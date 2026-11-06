/// User-editable runtime settings persisted without rewriting the rest of the
/// configuration file. This preserves local API keys and unrelated options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSettings {
    pub download_dir: PathBuf,
    pub quarantine_dir: PathBuf,
    pub monitor_enabled: bool,
    pub start_at_login: bool,
}

impl RuntimeSettings {
    pub fn from_config(config: &Config) -> Self {
        Self {
            download_dir: config.download_dir.clone(),
            quarantine_dir: config.storage.quarantine_dir.clone(),
            monitor_enabled: config.runtime.monitor_enabled,
            start_at_login: config.runtime.start_at_login,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_directory(&self.download_dir, "download directory")?;
        if !self.quarantine_dir.is_absolute() {
            bail!("quarantine location must be an absolute path");
        }
        if self.quarantine_dir.parent().is_none() {
            bail!("quarantine location cannot be a filesystem root");
        }
        validate_ancestors(&self.quarantine_dir, "quarantine location")?;
        if path_is_within(&self.quarantine_dir, &self.download_dir) {
            bail!("quarantine location must be outside the download directory");
        }
        Ok(())
    }
}

pub fn save_runtime_settings(path: &Path, settings: &RuntimeSettings) -> Result<()> {
    settings.validate()?;
    let contents = if path.exists() {
        fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?
    } else {
        String::new()
    };
    let mut document = contents
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("failed to parse config {}", path.display()))?;

    document["download_dir"] = toml_edit::value(path_text(&settings.download_dir));
    document["storage"]["quarantine_dir"] = toml_edit::value(path_text(&settings.quarantine_dir));
    document["runtime"]["monitor_enabled"] = toml_edit::value(settings.monitor_enabled);
    document["runtime"]["start_at_login"] = toml_edit::value(settings.start_at_login);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("toml.tmp");
    let backup = path.with_extension("toml.bak");
    fs::write(&temporary, document.to_string())
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    if backup.exists() {
        fs::remove_file(&backup)
            .with_context(|| format!("failed to clear stale backup {}", backup.display()))?;
    }
    if path.exists() {
        fs::rename(path, &backup)
            .with_context(|| format!("failed to back up config {}", path.display()))?;
    }
    if let Err(error) = fs::rename(&temporary, path) {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err(error).with_context(|| format!("failed to install config {}", path.display()));
    }
    if backup.exists() {
        fs::remove_file(&backup)
            .with_context(|| format!("failed to remove config backup {}", backup.display()))?;
    }
    Ok(())
}

fn validate_directory(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{label} must be an absolute path");
    }
    if !path.is_dir() {
        bail!("{label} does not exist or is not a directory: {}", path.display());
    }
    validate_ancestors(path, label)
}

fn validate_ancestors(path: &Path, label: &str) -> Result<()> {
    for ancestor in path.ancestors().filter(|ancestor| ancestor.exists()) {
        let metadata = fs::symlink_metadata(ancestor)
            .with_context(|| format!("failed to inspect {label} {}", ancestor.display()))?;
        if is_reparse_point(&metadata) {
            bail!("{label} cannot contain a symbolic link or directory junction");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn path_is_within(candidate: &Path, root: &Path) -> bool {
    let normalize = |path: &Path| path.to_string_lossy().replace('/', "\\").to_lowercase();
    let candidate = normalize(candidate);
    let root = normalize(root).trim_end_matches('\\').to_owned();
    candidate == root || candidate.starts_with(&format!("{root}\\"))
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

