mod actions;
mod app;
mod data;

use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::config::{AppPaths, Config};
use crate::db::Database;
use crate::interaction::register_notification_identity;
use crate::security::ensure_download_execution_barrier;
use crate::watcher::Watcher;

use app::DesktopApp;

const MONITOR_MUTEX: &str = "Local\\IsItSafe.Monitor.v1";
const GUI_MUTEX: &str = "Local\\IsItSafe.Desktop.v1";
const WINDOW_TITLE: &str = "IsItSafe";

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
