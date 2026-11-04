use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use wait_timeout::ChildExt;

use crate::analysis::{AnalysisLimits, ChildAnalysis, ChildSandboxProof, analyze_bytes_with_rules};
use crate::config::Config;
use crate::report::{Boundary, BoundaryKind, ChildExecution, SandboxCapability, SandboxSelfTest};

pub const INTERNAL_CHILD_ARGUMENT: &str = "__isitsafe_analysis_child";
const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct ChildRequest {
    protocol_version: u32,
    display_path: String,
    limits: AnalysisLimits,
    output_max_bytes: u64,
    yara_enabled: bool,
    yara_source: Option<String>,
}

#[derive(Debug)]
pub struct SandboxResult {
    pub analysis: Option<ChildAnalysis>,
    pub execution: ChildExecution,
    pub boundaries: Vec<Boundary>,
    pub error: Option<String>,
}

pub fn is_internal_child_invocation() -> bool {
    std::env::args().nth(1).as_deref() == Some(INTERNAL_CHILD_ARGUMENT)
}

pub fn run_child_main() -> Result<()> {
    let mut stdin = std::io::stdin().lock();
    let request_len = read_u64(&mut stdin)?;
    if request_len > 32 * 1024 * 1024 {
        bail!("analysis request header is too large");
    }
    let mut request_bytes = vec![0; request_len as usize];
    stdin.read_exact(&mut request_bytes)?;
    let request: ChildRequest = serde_json::from_slice(&request_bytes)?;
    if request.protocol_version != PROTOCOL_VERSION {
        bail!(
            "child protocol mismatch: expected {PROTOCOL_VERSION}, got {}",
            request.protocol_version
        );
    }
    let data_len = read_u64(&mut stdin)?;
    if data_len > request.limits.total_output_max_bytes.saturating_mul(2) {
        bail!("child input exceeds configured protocol limit");
    }
    let mut data = vec![0; data_len as usize];
    stdin.read_exact(&mut data)?;
    let mut analysis = analyze_bytes_with_rules(
        Path::new(&request.display_path),
        &data,
        &request.limits,
        request.yara_enabled,
        request.yara_source.as_deref(),
    );
    analysis.sandbox_proof = Some(probe_child_sandbox());
    let output = serialize_bounded(analysis, request.output_max_bytes as usize)?;
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}

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

pub fn run_sandboxed(
    config: &Config,
    path: &Path,
    data: &[u8],
    custom_yara_rules: Option<&str>,
) -> Result<SandboxResult> {
    let executable = config
        .child
        .executable
        .clone()
        .unwrap_or(std::env::current_exe()?);
    let limits = AnalysisLimits::from(config);
    let request = ChildRequest {
        protocol_version: PROTOCOL_VERSION,
        display_path: path.to_string_lossy().into_owned(),
        limits,
        output_max_bytes: config.limits.child_output_max_bytes,
        yara_enabled: config.yara.enabled,
        yara_source: custom_yara_rules.map(str::to_owned),
    };
    let header = serde_json::to_vec(&request)?;

    let started = Instant::now();
    #[cfg(windows)]
    {
        run_windows_child(config, &executable, &header, data, started)
    }
    #[cfg(not(windows))]
    {
        run_portable_child(config, &executable, &header, data, started)
    }
}

#[cfg(not(windows))]
fn run_portable_child(
    config: &Config,
    executable: &Path,
    header: &[u8],
    data: &[u8],
    started: Instant,
) -> Result<SandboxResult> {
    let mut command = Command::new(executable);
    command
        .arg(INTERNAL_CHILD_ARGUMENT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    feed_child(&mut child, header, data)?;
    wait_and_collect(config, child, started)
}

fn feed_child(child: &mut Child, header: &[u8], data: &[u8]) -> Result<()> {
    let mut stdin = child.stdin.take().context("child stdin unavailable")?;
    write_u64(&mut stdin, header.len() as u64)?;
    stdin.write_all(header)?;
    write_u64(&mut stdin, data.len() as u64)?;
    stdin.write_all(data)?;
    stdin.flush()?;
    Ok(())
}

fn wait_and_collect(config: &Config, mut child: Child, started: Instant) -> Result<SandboxResult> {
    let wall_limit = Duration::from_millis(config.limits.child_wall_time_ms);
    let output_limit = config.limits.child_output_max_bytes as usize;
    let mut stdout = child.stdout.take().context("child stdout unavailable")?;
    let stdout_reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        let _ = stdout
            .by_ref()
            .take(output_limit.saturating_add(1) as u64)
            .read_to_end(&mut output);
        output
    });
    let mut stderr = child.stderr.take().context("child stderr unavailable")?;
    let stderr_reader = std::thread::spawn(move || {
        let mut output = String::new();
        let _ = stderr.by_ref().take(128 * 1024).read_to_string(&mut output);
        output
    });
    let status = match child.wait_timeout(wall_limit)? {
        Some(status) => status,
        None => {
            #[cfg(windows)]
            terminate_job(&child);
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Ok(SandboxResult {
                analysis: None,
                execution: ChildExecution {
                    launched: true,
                    exit_code: None,
                    job_terminated: true,
                    peak_memory_bytes: None,
                    cpu_time_ms: None,
                    wall_time_ms: started.elapsed().as_millis() as u64,
                    output_bytes: 0,
                    output_truncated: false,
                    process_creation_limit: Some(1),
                    network_capability: SandboxCapability::Unknown,
                    filesystem_capability: SandboxCapability::Unknown,
                    sandbox_self_tests: BTreeMap::new(),
                },
                boundaries: vec![Boundary {
                    kind: BoundaryKind::ChildTimedOut,
                    detail: "analysis child exceeded the wall-clock limit".into(),
                }],
                error: Some("analysis child timed out".into()),
            });
        }
    };
    let mut output = stdout_reader.join().unwrap_or_default();
    let truncated_by_parent = output.len() > output_limit;
    if truncated_by_parent {
        output.truncate(output_limit);
    }
    let stderr = stderr_reader.join().unwrap_or_default();
    let exit_code = status.code();
    let analysis_result = serde_json::from_slice::<ChildAnalysis>(&output);
    let mut boundaries = Vec::new();
    let analysis = match analysis_result {
        Ok(value) => Some(value),
        Err(error) => {
            boundaries.push(Boundary {
                kind: if truncated_by_parent {
                    BoundaryKind::OutputTruncated
                } else if status.success() {
                    BoundaryKind::UnsupportedFormat
                } else {
                    BoundaryKind::ChildCrashed
                },
                detail: format!(
                    "child output could not be parsed: {error}; stderr={}",
                    crate::capture::escape_controls(&stderr)
                ),
            });
            None
        }
    };
    if analysis
        .as_ref()
        .is_some_and(|value| value.output_truncated)
        || truncated_by_parent
    {
        boundaries.push(Boundary {
            kind: BoundaryKind::OutputTruncated,
            detail: "child output exceeded the configured limit and is incomplete".into(),
        });
    }
    if !status.success() && analysis.is_none() {
        boundaries.push(Boundary {
            kind: BoundaryKind::ChildCrashed,
            detail: format!(
                "child exited with {:?}; stderr={}",
                exit_code,
                crate::capture::escape_controls(&stderr)
            ),
        });
    }
    let mut execution = ChildExecution {
        launched: true,
        exit_code,
        job_terminated: false,
        peak_memory_bytes: None,
        cpu_time_ms: None,
        wall_time_ms: started.elapsed().as_millis() as u64,
        output_bytes: output.len() as u64,
        output_truncated: truncated_by_parent,
        process_creation_limit: Some(1),
        network_capability: SandboxCapability::Unknown,
        filesystem_capability: SandboxCapability::Unknown,
        sandbox_self_tests: BTreeMap::from([
            ("network_connect".into(), SandboxSelfTest::NotRun),
            ("process_create".into(), SandboxSelfTest::NotRun),
        ]),
    };
    apply_child_sandbox_proof(&mut execution, analysis.as_ref());
    Ok(SandboxResult {
        analysis,
        execution,
        boundaries,
        error: if status.success() {
            None
        } else {
            Some(format!("analysis child exited with {status}"))
        },
    })
}

fn serialize_bounded(mut analysis: ChildAnalysis, max_bytes: usize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&analysis)?;
    if bytes.len() <= max_bytes {
        return Ok(bytes);
    }
    analysis.components.clear();
    bytes = serde_json::to_vec(&analysis)?;
    if bytes.len() <= max_bytes {
        analysis.output_truncated = true;
        return Ok(serde_json::to_vec(&analysis)?);
    }
    for evidence in analysis
        .facts
        .iter_mut()
        .chain(analysis.inference.iter_mut())
    {
        evidence.detail = None;
    }
    bytes = serde_json::to_vec(&analysis)?;
    if bytes.len() <= max_bytes {
        analysis.output_truncated = true;
        return Ok(serde_json::to_vec(&analysis)?);
    }
    for certificate in &mut analysis.certificates {
        certificate.subject = truncate(&certificate.subject, 128);
        certificate.issuer = truncate(&certificate.issuer, 128);
        certificate.ocsp_urls.clear();
        certificate.crl_urls.clear();
    }
    analysis.output_truncated = true;
    bytes = serde_json::to_vec(&analysis)?;
    if bytes.len() <= max_bytes {
        return Ok(bytes);
    }
    let minimal = ChildAnalysis {
        classification: analysis.classification,
        output_truncated: true,
        boundaries: vec![Boundary {
            kind: BoundaryKind::OutputTruncated,
            detail: "child output exceeded the hard cap".into(),
        }],
        ..ChildAnalysis::default()
    };
    let bytes = serde_json::to_vec(&minimal)?;
    if bytes.len() > max_bytes {
        bail!("minimal child report exceeds configured output cap");
    }
    Ok(bytes)
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(windows)]
fn run_windows_child(
    config: &Config,
    executable: &Path,
    header: &[u8],
    data: &[u8],
    started: Instant,
) -> Result<SandboxResult> {
    if config.child.use_app_container {
        return run_app_container_child(config, executable, header, data, started);
    }
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut command = Command::new(executable);
    command
        .arg(INTERNAL_CHILD_ARGUMENT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to launch analysis child {}", executable.display()))?;
    let job = attach_job(&child, config)?;
    feed_child(&mut child, header, data)?;
    let mut result = wait_and_collect(config, child, started)?;
    if let Some(job) = job {
        let metrics = query_job_metrics(job);
        result.execution.peak_memory_bytes = metrics.peak_memory_bytes;
        result.execution.cpu_time_ms = metrics.cpu_time_ms;
        result.execution.network_capability = SandboxCapability::Unknown;
        result.execution.filesystem_capability = SandboxCapability::Unknown;
        result
            .execution
            .sandbox_self_tests
            .insert("job_object".into(), SandboxSelfTest::Allowed);
        close_job(job);
    }
    Ok(result)
}

#[cfg(windows)]
fn run_app_container_child(
    config: &Config,
    executable: &Path,
    header: &[u8],
    data: &[u8],
    started: Instant,
) -> Result<SandboxResult> {
    use std::ffi::OsStr;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    };
    use windows_sys::Win32::Security::{FreeSid, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        UpdateProcThreadAttribute, WaitForSingleObject,
    };

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

    let (stdin_read, stdin_write) = pipe_pair()?;
    let (stdout_read, stdout_write) = pipe_pair()?;
    let (stderr_read, stderr_write) = pipe_pair()?;
    // Only the child ends remain inheritable.
    for handle in [stdin_write, stdout_read, stderr_read] {
        unsafe {
            SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
        }
    }

    let mut app_name: Vec<u16> = "IsItSafe.Analysis.v1"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut app_sid = std::ptr::null_mut();
    let mut display_name: Vec<u16> = "IsItSafe Analysis Sandbox"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut description: Vec<u16> =
        "Parses untrusted downloads without network or user-file access"
            .encode_utf16()
            .chain(Some(0))
            .collect();
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
            anyhow::bail!(
                "failed to derive AppContainer SID after profile creation: HRESULT {derive_hr:#x}"
            );
        }
    }
    if hr < 0 && hr != HRESULT_ALREADY_EXISTS {
        for handle in [
            stdin_read,
            stdin_write,
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
        ] {
            unsafe {
                CloseHandle(handle);
            }
        }
        anyhow::bail!("failed to create AppContainer profile: HRESULT {hr:#x}");
    }
    if app_sid.is_null() {
        anyhow::bail!("AppContainer profile returned a null SID");
    }

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
        unsafe {
            for handle in [
                stdin_read,
                stdin_write,
                stdout_read,
                stdout_write,
                stderr_read,
                stderr_write,
            ] {
                CloseHandle(handle);
            }
            FreeSid(app_sid);
        }
        return Err(std::io::Error::last_os_error())
            .context("failed to initialize process attribute list");
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
    let inherited_handles = [stdin_read, stdout_write, stderr_write];
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
            for handle in [
                stdin_read,
                stdin_write,
                stdout_read,
                stdout_write,
                stderr_read,
                stderr_write,
            ] {
                CloseHandle(handle);
            }
            FreeSid(app_sid);
        }
        return Err(error).context("failed to configure AppContainer process attributes");
    }

    let mut startup = unsafe { zeroed::<STARTUPINFOEXW>() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin_read;
    startup.StartupInfo.hStdOutput = stdout_write;
    startup.StartupInfo.hStdError = stderr_write;
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
        CloseHandle(stdin_read);
        CloseHandle(stdout_write);
        CloseHandle(stderr_write);
    }
    if created == 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            CloseHandle(stdin_write);
            CloseHandle(stdout_read);
            CloseHandle(stderr_read);
        }
        return Err(error).context("failed to launch zero-capability AppContainer child");
    }

    let job = match attach_job_handle(process_info.hProcess, config) {
        Ok(job) => job,
        Err(error) => {
            unsafe {
                CloseHandle(stdin_write);
                CloseHandle(stdout_read);
                CloseHandle(stderr_read);
                CloseHandle(process_info.hThread);
                CloseHandle(process_info.hProcess);
            }
            return Err(error);
        }
    };
    if unsafe { ResumeThread(process_info.hThread) } == u32::MAX {
        let error = std::io::Error::last_os_error();
        unsafe {
            CloseHandle(stdin_write);
            CloseHandle(stdout_read);
            CloseHandle(stderr_read);
            CloseHandle(process_info.hThread);
            CloseHandle(process_info.hProcess);
            CloseHandle(job);
        }
        return Err(error).context("failed to resume AppContainer child");
    }
    unsafe {
        CloseHandle(process_info.hThread);
    }

    let output_limit = config.limits.child_output_max_bytes as usize;
    let stdout_reader = {
        let mut stdout = unsafe { std::fs::File::from_raw_handle(stdout_read as RawHandle) };
        std::thread::spawn(move || {
            let mut output = Vec::new();
            let _ = std::io::Read::by_ref(&mut stdout)
                .take(output_limit.saturating_add(1) as u64)
                .read_to_end(&mut output);
            output
        })
    };
    let stderr_reader = {
        let mut stderr = unsafe { std::fs::File::from_raw_handle(stderr_read as RawHandle) };
        std::thread::spawn(move || {
            let mut output = Vec::new();
            let _ = std::io::Read::by_ref(&mut stderr)
                .take(128 * 1024)
                .read_to_end(&mut output);
            output
        })
    };
    {
        let mut stdin = unsafe { std::fs::File::from_raw_handle(stdin_write as RawHandle) };
        write_u64(&mut stdin, header.len() as u64)?;
        stdin.write_all(header)?;
        write_u64(&mut stdin, data.len() as u64)?;
        stdin.write_all(data)?;
        stdin.flush()?;
    }

    let wait = unsafe {
        WaitForSingleObject(
            process_info.hProcess,
            config.limits.child_wall_time_ms.min(u32::MAX as u64) as u32,
        )
    };
    let timed_out = wait == WAIT_TIMEOUT;
    if timed_out || wait != WAIT_OBJECT_0 {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(job, 1);
        }
    }
    let mut exit_code = u32::MAX;
    unsafe {
        GetExitCodeProcess(process_info.hProcess, &mut exit_code);
    }
    let metrics = query_job_metrics(job);
    unsafe {
        CloseHandle(process_info.hProcess);
        CloseHandle(job);
    }
    let output = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    let truncated_by_parent = output.len() > output_limit;
    let output = if truncated_by_parent {
        &output[..output_limit]
    } else {
        &output[..]
    };
    let mut boundaries = Vec::new();
    let analysis = if timed_out {
        boundaries.push(Boundary {
            kind: BoundaryKind::ChildTimedOut,
            detail: "AppContainer analysis child exceeded the wall-clock limit".into(),
        });
        None
    } else {
        match serde_json::from_slice::<ChildAnalysis>(output) {
            Ok(value) => Some(value),
            Err(error) => {
                boundaries.push(Boundary {
                    kind: if exit_code == 0 {
                        BoundaryKind::UnsupportedFormat
                    } else {
                        BoundaryKind::ChildCrashed
                    },
                    detail: format!(
                        "AppContainer child output is invalid: {error}; stderr={}",
                        crate::capture::escape_controls(&String::from_utf8_lossy(&stderr))
                    ),
                });
                None
            }
        }
    };
    if truncated_by_parent
        || analysis
            .as_ref()
            .is_some_and(|value| value.output_truncated)
    {
        boundaries.push(Boundary {
            kind: BoundaryKind::OutputTruncated,
            detail: "child output exceeded the configured cap".into(),
        });
    }
    let mut execution = ChildExecution {
        launched: true,
        exit_code: if timed_out {
            None
        } else {
            Some(exit_code as i32)
        },
        job_terminated: timed_out,
        peak_memory_bytes: metrics.peak_memory_bytes,
        cpu_time_ms: metrics.cpu_time_ms,
        wall_time_ms: started.elapsed().as_millis() as u64,
        output_bytes: output.len() as u64,
        output_truncated: truncated_by_parent,
        process_creation_limit: Some(1),
        network_capability: SandboxCapability::None,
        filesystem_capability: SandboxCapability::Restricted,
        sandbox_self_tests: BTreeMap::from([
            ("app_container".into(), SandboxSelfTest::Allowed),
            ("network_connect".into(), SandboxSelfTest::Denied),
            ("process_create".into(), SandboxSelfTest::NotRun),
        ]),
    };
    apply_child_sandbox_proof(&mut execution, analysis.as_ref());
    Ok(SandboxResult {
        analysis,
        execution,
        boundaries,
        error: if timed_out {
            Some("AppContainer analysis child timed out".into())
        } else if exit_code != 0 {
            Some(format!("AppContainer child exited with code {exit_code}"))
        } else {
            None
        },
    })
}

fn apply_child_sandbox_proof(execution: &mut ChildExecution, analysis: Option<&ChildAnalysis>) {
    let Some(proof) = analysis.and_then(|analysis| analysis.sandbox_proof.as_ref()) else {
        return;
    };
    execution.network_capability = if proof.is_app_container {
        SandboxCapability::None
    } else {
        SandboxCapability::Unknown
    };
    execution.filesystem_capability = if proof.is_app_container {
        SandboxCapability::Restricted
    } else {
        SandboxCapability::Unknown
    };
    execution
        .sandbox_self_tests
        .insert("network_connect".into(), proof.network_connect);
    execution
        .sandbox_self_tests
        .insert("process_create".into(), proof.process_create);
    execution.sandbox_self_tests.insert(
        "app_container".into(),
        if proof.is_app_container {
            SandboxSelfTest::Allowed
        } else {
            SandboxSelfTest::Unknown
        },
    );
}

#[cfg(windows)]
#[derive(Default)]
struct JobMetrics {
    peak_memory_bytes: Option<u64>,
    cpu_time_ms: Option<u64>,
}

#[cfg(windows)]
type JobHandle = windows_sys::Win32::Foundation::HANDLE;

#[cfg(windows)]
fn attach_job(child: &Child, config: &Config) -> Result<Option<JobHandle>> {
    use std::os::windows::io::AsRawHandle;
    Ok(Some(attach_job_handle(child.as_raw_handle() as _, config)?))
}

#[cfg(windows)]
fn attach_job_handle(process: JobHandle, config: &Config) -> Result<JobHandle> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        JOB_OBJECT_LIMIT_PROCESS_TIME, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("failed to create analysis Job Object");
    }
    let mut info = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    info.BasicLimitInformation.ActiveProcessLimit = 1;
    info.BasicLimitInformation.PerProcessUserTimeLimit =
        config.limits.child_cpu_time_ms.saturating_mul(10_000) as i64;
    info.ProcessMemoryLimit = config.limits.child_committed_memory_bytes as usize;
    info.JobMemoryLimit = config.limits.child_committed_memory_bytes as usize;
    let set_ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if set_ok == 0 {
        close_job(job);
        return Err(std::io::Error::last_os_error()).context("failed to configure Job Object");
    }
    let assign_ok = unsafe { AssignProcessToJobObject(job, process) };
    if assign_ok == 0 {
        close_job(job);
        return Err(std::io::Error::last_os_error())
            .context("failed to assign child to Job Object");
    }
    Ok(job)
}

#[cfg(windows)]
fn query_job_metrics(job: JobHandle) -> JobMetrics {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::System::JobObjects::{
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject,
    };
    let mut extended = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    let mut accounting = unsafe { zeroed::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() };
    let ext_ok = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&mut extended as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    let acct_ok = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    JobMetrics {
        peak_memory_bytes: (ext_ok != 0).then_some(extended.PeakProcessMemoryUsed as u64),
        cpu_time_ms: (acct_ok != 0).then_some(
            (accounting.TotalUserTime as u64 + accounting.TotalKernelTime as u64) / 10_000,
        ),
    }
}

#[cfg(windows)]
fn terminate_job(child: &Child) {
    // The wait timeout path kills the process directly. Kill-on-close in the
    // Job Object ensures any descendant that might exist is also terminated
    // when the job handle is closed.
    let _ = child.id();
}

#[cfg(windows)]
fn close_job(job: JobHandle) {
    use windows_sys::Win32::Foundation::CloseHandle;
    unsafe {
        CloseHandle(job);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Confidence, Evidence, Severity};

    #[test]
    fn oversized_output_remains_valid_json_and_is_incomplete() {
        let mut analysis = ChildAnalysis::default();
        for index in 0..200 {
            analysis.facts.push(Evidence {
                id: format!("fact:{index}"),
                category: "test".into(),
                severity: Severity::Low,
                summary: "x".repeat(200),
                detail: Some("detail".repeat(100)),
                provenance: "test".into(),
                confidence: Confidence::Inferred,
            });
        }
        let bytes = serialize_bounded(analysis, 4096).unwrap();
        assert!(bytes.len() <= 4096);
        let decoded: ChildAnalysis = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.output_truncated);
        assert!(decoded.facts.is_empty() || decoded.facts.iter().all(|item| item.detail.is_none()));
    }
}
