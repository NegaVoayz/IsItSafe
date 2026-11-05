use std::ffi::OsStr;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{FreeSid, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
};

#[derive(Clone, Copy)]
struct AppContainerPipes {
    stdin_read: HANDLE,
    stdin_write: HANDLE,
    stdout_read: HANDLE,
    stdout_write: HANDLE,
    stderr_read: HANDLE,
    stderr_write: HANDLE,
}

impl AppContainerPipes {
    fn close_child_ends(self) {
        close_handles(&[self.stdin_read, self.stdout_write, self.stderr_write]);
    }

    fn close_parent_ends(self) {
        close_handles(&[self.stdin_write, self.stdout_read, self.stderr_read]);
    }

    fn close_all(self) {
        close_handles(&[
            self.stdin_read,
            self.stdin_write,
            self.stdout_read,
            self.stdout_write,
            self.stderr_read,
            self.stderr_write,
        ]);
    }
}

fn close_handles(handles: &[HANDLE]) {
    for handle in handles {
        unsafe {
            CloseHandle(*handle);
        }
    }
}

fn pipe_pair() -> Result<(HANDLE, HANDLE)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create child pipe");
    }
    Ok((read, write))
}

fn create_app_container_pipes() -> Result<AppContainerPipes> {
    let (stdin_read, stdin_write) = pipe_pair()?;
    let (stdout_read, stdout_write) = match pipe_pair() {
        Ok(pair) => pair,
        Err(error) => {
            close_handles(&[stdin_read, stdin_write]);
            return Err(error);
        }
    };
    let (stderr_read, stderr_write) = match pipe_pair() {
        Ok(pair) => pair,
        Err(error) => {
            close_handles(&[stdin_read, stdin_write, stdout_read, stdout_write]);
            return Err(error);
        }
    };
    for handle in [stdin_write, stdout_read, stderr_read] {
        unsafe {
            SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
        }
    }
    Ok(AppContainerPipes {
        stdin_read,
        stdin_write,
        stdout_read,
        stdout_write,
        stderr_read,
        stderr_write,
    })
}

fn create_app_container_sid() -> Result<HANDLE> {
    let mut app_name: Vec<u16> = "IsItSafe.Analysis.v1"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut display_name: Vec<u16> = "IsItSafe Analysis Sandbox"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut description: Vec<u16> =
        "Parses untrusted downloads without network or user-file access"
            .encode_utf16()
            .chain(Some(0))
            .collect();
    let mut app_sid = std::ptr::null_mut();
    let hr = unsafe {
        CreateAppContainerProfile(
            app_name.as_mut_ptr(),
            display_name.as_mut_ptr(),
            description.as_mut_ptr(),
            std::ptr::null(),
            0,
            &mut app_sid,
        )
    };
    const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;
    if app_sid.is_null() && (hr == HRESULT_ALREADY_EXISTS || hr >= 0) {
        let derive_hr = unsafe {
            DeriveAppContainerSidFromAppContainerName(app_name.as_mut_ptr(), &mut app_sid)
        };
        if derive_hr < 0 {
            bail!(
                "failed to derive AppContainer SID after profile creation: HRESULT {derive_hr:#x}"
            );
        }
    }
    if hr < 0 && hr != HRESULT_ALREADY_EXISTS {
        bail!("failed to create AppContainer profile: HRESULT {hr:#x}");
    }
    if app_sid.is_null() {
        bail!("AppContainer profile returned a null SID");
    }
    Ok(app_sid)
}

fn create_suspended_app_container(
    executable: &Path,
    pipes: AppContainerPipes,
) -> Result<PROCESS_INFORMATION> {
    let app_sid = match create_app_container_sid() {
        Ok(sid) => sid,
        Err(error) => {
            pipes.close_all();
            return Err(error);
        }
    };
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: app_sid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };

    let mut attribute_size = 0usize;
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut attribute_size);
    }
    let mut attribute_storage = vec![0usize; attribute_size.div_ceil(size_of::<usize>())];
    let attribute_list = attribute_storage.as_mut_ptr().cast();
    if unsafe { InitializeProcThreadAttributeList(attribute_list, 2, 0, &mut attribute_size) } == 0
    {
        let error = std::io::Error::last_os_error();
        unsafe { FreeSid(app_sid) };
        pipes.close_all();
        return Err(error).context("failed to initialize process attribute list");
    }
    let security_ok = unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            (&capabilities as *const SECURITY_CAPABILITIES).cast(),
            size_of::<SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    let inherited_handles = [pipes.stdin_read, pipes.stdout_write, pipes.stderr_write];
    let handles_ok = unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited_handles.as_ptr().cast(),
            size_of::<HANDLE>() * inherited_handles.len(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    if security_ok == 0 || handles_ok == 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            DeleteProcThreadAttributeList(attribute_list);
            FreeSid(app_sid);
        }
        pipes.close_all();
        return Err(error).context("failed to configure AppContainer process attributes");
    }

    let mut startup = unsafe { zeroed::<STARTUPINFOEXW>() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = pipes.stdin_read;
    startup.StartupInfo.hStdOutput = pipes.stdout_write;
    startup.StartupInfo.hStdError = pipes.stderr_write;
    startup.lpAttributeList = attribute_list;
    let application_wide: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let command = format!(
        "\"{}\" {}",
        executable.as_os_str().to_string_lossy(),
        INTERNAL_CHILD_ARGUMENT
    );
    let mut command_wide: Vec<u16> = OsStr::new(&command).encode_wide().chain(Some(0)).collect();
    let mut process_info = unsafe { zeroed::<PROCESS_INFORMATION>() };
    let created = unsafe {
        CreateProcessW(
            application_wide.as_ptr(),
            command_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    unsafe {
        DeleteProcThreadAttributeList(attribute_list);
        FreeSid(app_sid);
    }
    pipes.close_child_ends();
    if created == 0 {
        let error = std::io::Error::last_os_error();
        pipes.close_parent_ends();
        return Err(error).context("failed to launch zero-capability AppContainer child");
    }
    Ok(process_info)
}
