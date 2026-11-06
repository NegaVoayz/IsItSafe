use anyhow::{Context, Result, bail};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::config::AppPaths;

const DETAILS_EXTENSION: &str = "request";
const SCAN_EXTENSION: &str = "scan";
const MAX_SCAN_REQUEST_BYTES: u64 = 32 * 1024;

pub fn open_details(paths: &AppPaths, report_id: Uuid) -> Result<()> {
    write_request(paths, DETAILS_EXTENSION, &report_id.to_string())
}

pub fn open_scan(paths: &AppPaths, path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("selected path is not a file: {}", path.display());
    }
    write_request(paths, SCAN_EXTENSION, &path.to_string_lossy())
}

pub(crate) fn take_requested_details(paths: &AppPaths) -> Result<Option<Uuid>> {
    Ok(take_latest(paths, DETAILS_EXTENSION)?.and_then(|value| value.trim().parse::<Uuid>().ok()))
}

pub(crate) fn take_requested_scan(paths: &AppPaths) -> Result<Option<PathBuf>> {
    let Some(value) = take_latest(paths, SCAN_EXTENSION)? else {
        return Ok(None);
    };
    let path = PathBuf::from(value.trim());
    Ok(path.is_file().then_some(path))
}

fn write_request(paths: &AppPaths, extension: &str, contents: &str) -> Result<()> {
    let requests = request_directory(paths);
    fs::create_dir_all(&requests)
        .with_context(|| format!("failed to create {}", requests.display()))?;
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let request = requests.join(format!("{timestamp:039}.{extension}"));
    fs::write(&request, contents)
        .with_context(|| format!("failed to queue request in {}", request.display()))
}

fn take_latest(paths: &AppPaths, extension: &str) -> Result<Option<String>> {
    let requests = request_directory(paths);
    if !requests.exists() {
        return Ok(None);
    }
    let mut matching = fs::read_dir(&requests)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|value| value == extension))
        .collect::<Vec<_>>();
    matching.sort_by(|left, right| right.file_name().cmp(&left.file_name()));

    let mut selected = None;
    for request in matching {
        if selected.is_none()
            && request
                .metadata()
                .is_ok_and(|metadata| metadata.len() <= MAX_SCAN_REQUEST_BYTES)
            && let Ok(value) = fs::read_to_string(&request)
        {
            selected = Some(value);
        }
        let _ = fs::remove_file(request);
    }
    Ok(selected)
}

fn request_directory(paths: &AppPaths) -> PathBuf {
    paths.data_dir.join("ui-requests")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_paths(root: &Path) -> AppPaths {
        AppPaths {
            config_file: root.join("config.toml"),
            data_dir: root.to_path_buf(),
            database: root.join("state.db"),
            reports_dir: root.join("reports"),
            logs_dir: root.join("logs"),
            rules_dir: root.join("rules"),
        }
    }

    #[test]
    fn detail_requests_are_consumed_once() {
        let root = tempfile::tempdir().unwrap();
        let paths = app_paths(root.path());
        let report_id = Uuid::new_v4();

        open_details(&paths, report_id).unwrap();
        assert_eq!(take_requested_details(&paths).unwrap(), Some(report_id));
        assert_eq!(take_requested_details(&paths).unwrap(), None);
    }

    #[test]
    fn scan_requests_require_an_existing_file() {
        let root = tempfile::tempdir().unwrap();
        let paths = app_paths(root.path());
        let file = root.path().join("sample.bin");
        fs::write(&file, b"sample").unwrap();

        open_scan(&paths, &file).unwrap();
        assert_eq!(take_requested_scan(&paths).unwrap(), Some(file));
        assert!(open_scan(&paths, &root.path().join("missing.bin")).is_err());
    }
}
