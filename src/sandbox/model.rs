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

