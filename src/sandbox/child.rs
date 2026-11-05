fn probe_child_sandbox() -> ChildSandboxProof {
    #[cfg(windows)]
    {
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenIntegrityLevel,
            TokenIsAppContainer,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = std::ptr::null_mut();
        let token_open = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        let mut app_container = 0u32;
        let mut returned = 0u32;
        let is_app_container = token_open != 0
            && unsafe {
                GetTokenInformation(
                    token,
                    TokenIsAppContainer,
                    (&mut app_container as *mut u32).cast(),
                    size_of::<u32>() as u32,
                    &mut returned,
                )
            } != 0
            && app_container != 0;
        let mut integrity_level_rid = None;
        if token_open != 0 {
            let mut label = unsafe { zeroed::<TOKEN_MANDATORY_LABEL>() };
            let ok = unsafe {
                GetTokenInformation(
                    token,
                    TokenIntegrityLevel,
                    (&mut label as *mut TOKEN_MANDATORY_LABEL).cast(),
                    size_of::<TOKEN_MANDATORY_LABEL>() as u32,
                    &mut returned,
                )
            };
            if ok != 0 && !label.Label.Sid.is_null() {
                let rid = unsafe {
                    windows_sys::Win32::Security::GetSidSubAuthority(
                        label.Label.Sid,
                        (*windows_sys::Win32::Security::GetSidSubAuthorityCount(label.Label.Sid))
                            .saturating_sub(1) as u32,
                    )
                };
                if !rid.is_null() {
                    integrity_level_rid = Some(unsafe { *rid });
                }
                unsafe {
                    windows_sys::Win32::Foundation::LocalFree(label.Label.Sid.cast());
                }
            }
            unsafe {
                CloseHandle(token);
            }
        }
        let network_connect = if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([1, 1, 1, 1], 443)),
            Duration::from_millis(300),
        )
        .is_ok()
        {
            SandboxSelfTest::Allowed
        } else {
            SandboxSelfTest::Denied
        };
        let process_create = if let Ok(mut probe) = Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/c", "exit 0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let _ = probe.kill();
            let _ = probe.wait();
            SandboxSelfTest::Allowed
        } else {
            SandboxSelfTest::Denied
        };
        ChildSandboxProof {
            is_app_container,
            integrity_level_rid,
            network_connect,
            process_create,
        }
    }
    #[cfg(not(windows))]
    {
        ChildSandboxProof {
            network_connect: SandboxSelfTest::NotRun,
            process_create: SandboxSelfTest::NotRun,
            ..ChildSandboxProof::default()
        }
    }
}

