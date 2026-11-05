use std::os::windows::io::{FromRawHandle, RawHandle};
use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, ResumeThread, WaitForSingleObject,
};

fn run_app_container_child(
    config: &Config,
    executable: &Path,
    header: &[u8],
    data: &[u8],
    started: Instant,
) -> Result<SandboxResult> {
    let pipes = create_app_container_pipes()?;
    let process_info = create_suspended_app_container(executable, pipes)?;
    let job = match attach_job_handle(process_info.hProcess, config) {
        Ok(job) => job,
        Err(error) => {
            unsafe {
                pipes.close_parent_ends();
                CloseHandle(process_info.hThread);
                CloseHandle(process_info.hProcess);
            }
            return Err(error);
        }
    };
    if unsafe { ResumeThread(process_info.hThread) } == u32::MAX {
        let error = std::io::Error::last_os_error();
        unsafe {
            pipes.close_parent_ends();
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
        let mut stdout =
            unsafe { std::fs::File::from_raw_handle(pipes.stdout_read as RawHandle) };
        std::thread::spawn(move || {
            let mut output = Vec::new();
            let _ = std::io::Read::by_ref(&mut stdout)
                .take(output_limit.saturating_add(1) as u64)
                .read_to_end(&mut output);
            output
        })
    };
    let stderr_reader = {
        let mut stderr =
            unsafe { std::fs::File::from_raw_handle(pipes.stderr_read as RawHandle) };
        std::thread::spawn(move || {
            let mut output = Vec::new();
            let _ = std::io::Read::by_ref(&mut stderr)
                .take(128 * 1024)
                .read_to_end(&mut output);
            output
        })
    };
    {
        let mut stdin =
            unsafe { std::fs::File::from_raw_handle(pipes.stdin_write as RawHandle) };
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
