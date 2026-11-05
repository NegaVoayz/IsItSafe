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

