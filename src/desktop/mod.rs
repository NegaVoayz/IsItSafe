mod actions;
mod app;
mod data;

use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use uuid::Uuid;

use crate::config::{AppPaths, Config};
use crate::db::Database;
use crate::interaction::register_notification_identity;
use crate::security::ensure_download_execution_barrier;
use crate::watcher::Watcher;

use app::DesktopApp;

const MONITOR_MUTEX: &str = "Local\\IsItSafe.Monitor.v1";
const GUI_MUTEX: &str = "Local\\IsItSafe.Desktop.v1";
const WINDOW_TITLE: &str = "IsItSafe";
const DETAIL_REQUEST_EXTENSION: &str = "request";

/// Queues a report for the running desktop process and wakes the native UI.
/// Unique request files avoid partial reads and races between concurrent clicks.
pub fn open_details(paths: &AppPaths, report_id: Uuid) -> Result<()> {
    let requests = paths.data_dir.join("ui-requests");
    fs::create_dir_all(&requests)
        .with_context(|| format!("failed to create {}", requests.display()))?;
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let request = requests.join(format!("{timestamp:039}-{report_id}.request"));
    fs::write(&request, report_id.to_string())
        .with_context(|| format!("failed to queue report details in {}", request.display()))
}

pub(crate) fn take_requested_details(paths: &AppPaths) -> Result<Option<Uuid>> {
    let requests = paths.data_dir.join("ui-requests");
    if !requests.exists() {
        return Ok(None);
    }
    let mut paths_to_requests = fs::read_dir(&requests)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|value| value == DETAIL_REQUEST_EXTENSION)
        })
        .collect::<Vec<_>>();
    paths_to_requests.sort_by(|left, right| right.file_name().cmp(&left.file_name()));

    let mut selected = None;
    for request in paths_to_requests {
        if selected.is_none()
            && let Ok(value) = fs::read_to_string(&request)
            && let Ok(report_id) = value.trim().parse::<Uuid>()
        {
            selected = Some(report_id);
        }
        let _ = fs::remove_file(request);
    }
    Ok(selected)
}

/// Launches the native desktop workspace or the headless download monitor.
pub fn run(config: Config, paths: AppPaths, show_window: bool) -> Result<()> {
    if !show_window {
        return run_monitor(config, paths);
    }

    let Some(_gui_lease) = NamedMutex::acquire(GUI_MUTEX)? else {
        focus_existing_window();
        return Ok(());
    };

    ensure_background_monitor()?;
    initialize_download_security(&config)?;
    let database = Arc::new(Database::open_with_recovery(&paths.database)?);
    let config = Arc::new(config);
    let paths = Arc::new(paths);
    run_egui(config, database, paths)
}

fn run_monitor(config: Config, paths: AppPaths) -> Result<()> {
    let Some(_monitor_lease) = NamedMutex::acquire(MONITOR_MUTEX)? else {
        return Ok(());
    };
    initialize_download_security(&config)?;
    let database = Database::open_with_recovery(&paths.database)?;
    let watcher = Watcher::new(config, database, paths);
    watcher.run_with_prompt(true)
}

fn initialize_download_security(config: &Config) -> Result<()> {
    if config.security.block_execution_in_download_dir {
        ensure_download_execution_barrier(&config.download_dir)?;
    }
    if config.interaction.enabled {
        register_notification_identity()?;
    }
    Ok(())
}

fn ensure_background_monitor() -> Result<()> {
    if monitor_is_running() {
        return Ok(());
    }
    let executable = std::env::current_exe().context("cannot locate the IsItSafe executable")?;
    let mut command = Command::new(&executable);
    if executable
        .file_stem()
        .is_some_and(|value| value.eq_ignore_ascii_case("isitsafe"))
    {
        command.arg("ui").arg("--background");
    } else {
        command.arg("--background");
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {}", executable.display()))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if monitor_is_running() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            if !monitor_is_running() {
                bail!("the background monitor exited during startup ({status})");
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    bail!("the background monitor did not become ready within 5 seconds")
}

fn run_egui(config: Arc<Config>, database: Arc<Database>, paths: Arc<AppPaths>) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title(WINDOW_TITLE)
            .with_inner_size([1000.0, 720.0])
            .with_min_inner_size([900.0, 560.0])
            .with_decorations(false),
        ..Default::default()
    };
    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(move |creation| Ok(Box::new(DesktopApp::new(creation, config, database, paths)))),
    )
    .map_err(|error| anyhow::anyhow!("native desktop UI failed: {error}"))
}

#[cfg(windows)]
fn monitor_is_running() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};

    let name = wide(MONITOR_MUTEX);
    let handle = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr()) };
    if handle.is_null() {
        false
    } else {
        unsafe {
            CloseHandle(handle);
        }
        true
    }
}

#[cfg(not(windows))]
fn monitor_is_running() -> bool {
    false
}

#[cfg(windows)]
fn focus_existing_window() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SW_RESTORE, SetForegroundWindow, ShowWindow,
    };

    let title = wide(WINDOW_TITLE);
    let window = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
    if !window.is_null() {
        unsafe {
            ShowWindow(window, SW_RESTORE);
            SetForegroundWindow(window);
        }
    }
}

#[cfg(not(windows))]
fn focus_existing_window() {}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
struct NamedMutex {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl NamedMutex {
    fn acquire(name: &str) -> Result<Option<Self>> {
        use std::ptr;
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, SetLastError,
        };
        use windows_sys::Win32::System::Threading::CreateMutexW;

        let name = wide(name);
        unsafe {
            SetLastError(0);
        }
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error()).context("CreateMutexW failed");
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe {
                CloseHandle(handle);
            }
            Ok(None)
        } else {
            Ok(Some(Self { handle }))
        }
    }
}

#[cfg(windows)]
impl Drop for NamedMutex {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(not(windows))]
struct NamedMutex;

#[cfg(not(windows))]
impl NamedMutex {
    fn acquire(_name: &str) -> Result<Option<Self>> {
        Ok(Some(Self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_paths(root: &std::path::Path) -> AppPaths {
        AppPaths {
            config_file: root.join("config.toml"),
            data_dir: root.to_path_buf(),
            database: root.join("state.db"),
            reports_dir: root.join("reports"),
            logs_dir: root.join("logs"),
            quarantine_dir: root.join("quarantine"),
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
}
