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
