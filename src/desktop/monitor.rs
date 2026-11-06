use anyhow::{Context, Result, bail};
use std::thread;
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(8);

pub fn is_running() -> bool {
    platform_is_running()
}

pub fn ensure_running() -> Result<()> {
    if is_running() {
        reset_stop_request()?;
        return Ok(());
    }
    start()
}

pub fn start() -> Result<()> {
    reset_stop_request()?;
    let mut child = crate::startup::launch_background_monitor()?;
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if is_running() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            if !is_running() {
                bail!("the background monitor exited during startup ({status})");
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    bail!("the background monitor did not become ready within 5 seconds")
}

pub fn stop() -> Result<()> {
    if !is_running() {
        reset_stop_request()?;
        return Ok(());
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if !is_running() {
            return Ok(());
        }
        request_stop()?;
        thread::sleep(Duration::from_millis(50));
    }
    bail!("the background monitor did not stop within 8 seconds")
}

#[cfg(windows)]
pub fn reset_stop_request() -> Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, GetLastError};
    use windows_sys::Win32::System::Threading::{OpenEventW, ResetEvent};

    let name = super::wide(super::MONITOR_STOP_EVENT);
    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
    if event.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        return Err(std::io::Error::from_raw_os_error(error as i32))
            .context("failed to open monitor stop event");
    }
    let reset = unsafe { ResetEvent(event) };
    unsafe {
        CloseHandle(event);
    }
    if reset == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to reset monitor stop event");
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn reset_stop_request() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn request_stop() -> Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, GetLastError};
    use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent};

    let name = super::wide(super::MONITOR_STOP_EVENT);
    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
    if event.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        return Err(std::io::Error::from_raw_os_error(error as i32))
            .context("failed to open monitor stop event");
    }
    let signaled = unsafe { SetEvent(event) };
    unsafe {
        CloseHandle(event);
    }
    if signaled == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to stop the monitor");
    }
    Ok(())
}

#[cfg(not(windows))]
fn request_stop() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub struct MonitorStop {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl MonitorStop {
    pub fn create() -> Result<Self> {
        use std::ptr;
        use windows_sys::Win32::System::Threading::CreateEventW;

        let name = super::wide(super::MONITOR_STOP_EVENT);
        let handle = unsafe { CreateEventW(ptr::null(), 1, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("failed to create monitor stop event");
        }
        Ok(Self { handle })
    }

    pub fn is_requested(&self) -> bool {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        unsafe { WaitForSingleObject(self.handle, 0) == WAIT_OBJECT_0 }
    }
}

#[cfg(windows)]
impl Drop for MonitorStop {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(not(windows))]
pub struct MonitorStop;

#[cfg(not(windows))]
impl MonitorStop {
    pub fn create() -> Result<Self> {
        Ok(Self)
    }

    pub fn is_requested(&self) -> bool {
        false
    }
}

const EVENT_MODIFY_STATE: u32 = 0x0002;

#[cfg(windows)]
fn platform_is_running() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};

    let name = super::wide(super::MONITOR_MUTEX);
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
fn platform_is_running() -> bool {
    false
}
