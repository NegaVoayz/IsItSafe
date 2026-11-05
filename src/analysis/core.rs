#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisLimits {
    pub entry_max_bytes: u64,
    pub total_output_max_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
    pub compression_ratio_warning: u64,
}

impl From<&LimitsConfig> for AnalysisLimits {
    fn from(value: &LimitsConfig) -> Self {
        Self {
            entry_max_bytes: value.entry_max_bytes,
            total_output_max_bytes: value.total_output_max_bytes,
            max_entries: value.max_entries,
            max_depth: value.max_depth,
            compression_ratio_warning: value.compression_ratio_warning,
        }
    }
}

impl From<&Config> for AnalysisLimits {
    fn from(value: &Config) -> Self {
        Self::from(&value.limits)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChildAnalysis {
    pub classification: Classification,
    pub facts: Vec<Evidence>,
    pub inference: Vec<Evidence>,
    pub boundaries: Vec<Boundary>,
    pub components: Vec<ComponentEvidence>,
    pub products: Vec<ProductIdentityEvidence>,
    pub certificates: Vec<CertificateChainEvidence>,
    pub authenticity: Option<AuthenticityEvidence>,
    pub sandbox_proof: Option<ChildSandboxProof>,
    pub output_truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChildSandboxProof {
    pub is_app_container: bool,
    pub integrity_level_rid: Option<u32>,
    pub network_connect: SandboxSelfTest,
    pub process_create: SandboxSelfTest,
}

pub fn analyze_bytes(path: &Path, data: &[u8], limits: &AnalysisLimits) -> ChildAnalysis {
    analyze_bytes_with_rules(path, data, limits, false, None)
}

pub fn analyze_bytes_with_rules(
    path: &Path,
    data: &[u8],
    limits: &AnalysisLimits,
    yara_enabled: bool,
    custom_rules: Option<&str>,
) -> ChildAnalysis {
    let head_end = data.len().min(64 * 1024);
    let tail_start = data.len().saturating_sub(1024 * 1024);
    let sniff = detect::sniff(
        path,
        &data[..head_end],
        &data[tail_start..],
        data.len() as u64,
    );
    let mut analysis = ChildAnalysis {
        classification: sniff.classification,
        facts: sniff.evidence,
        ..ChildAnalysis::default()
    };
    let mut budget = Budget {
        limits,
        entries_seen: 0,
        total_output: 0,
    };

    let classification = analysis.classification.clone();
    inspect_document_features(data, &classification, &mut analysis);
    inspect_scripts(path, data, &mut analysis);
    if analysis
        .classification
        .formats
        .iter()
        .any(|format| format.kind == "pe")
    {
        analyze_pe(path, data, limits, &mut analysis);
    }
    inspect_magic_polyglots(data, &mut analysis);
    analyze_containers(path, data, "", 0, &mut budget, &mut analysis);
    #[cfg(feature = "yara")]
    if yara_enabled {
        inspect_yara(data, custom_rules, &mut analysis);
    }
    #[cfg(not(feature = "yara"))]
    {
        let _ = (yara_enabled, custom_rules);
    }
    analysis
}

#[cfg(feature = "yara")]
fn inspect_yara(data: &[u8], custom_rules: Option<&str>, analysis: &mut ChildAnalysis) {
    const BUILTIN_RULES: &str = include_str!("../../rules/default.yar");
    let mut source = String::from(BUILTIN_RULES);
    if let Some(custom) = custom_rules {
        source.push('\n');
        source.push_str(custom);
    }
    let digest = hex::encode(Sha256::digest(source.as_bytes()));
    let mut compiler = yara_x::Compiler::new();
    if let Err(error) = compiler.add_source(source.as_str()) {
        analysis.boundaries.push(Boundary {
            kind: BoundaryKind::UnsupportedFormat,
            detail: format!("YARA rules could not be compiled: {error}"),
        });
        return;
    }
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = match scanner.scan(data) {
        Ok(results) => results,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("YARA scan failed: {error}"),
            });
            return;
        }
    };
    for rule in results.matching_rules() {
        let identifier = rule.identifier().to_string();
        analysis.facts.push(evidence(
            format!("yara:{identifier}"),
            "yara_match",
            if identifier.contains("remote") || identifier.contains("powershell") {
                Severity::High
            } else {
                Severity::Medium
            },
            format!("YARA rule matched: {identifier}"),
            &format!("yara-x rules sha256={digest}"),
            Confidence::Inferred,
        ));
    }
}

