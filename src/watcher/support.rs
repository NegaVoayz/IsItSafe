fn strip_temp_extension(path: &Path) -> Option<PathBuf> {
    let text = path.to_string_lossy();
    let dot = text.rfind('.')?;
    Some(PathBuf::from(&text[..dot]))
}

fn is_reparse(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & 0x400 != 0
            }
            #[cfg(not(windows))]
            {
                metadata.file_type().is_symlink()
            }
        })
        .unwrap_or(true)
}

fn system_time_ns(value: SystemTime) -> Option<i64> {
    value
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
}

