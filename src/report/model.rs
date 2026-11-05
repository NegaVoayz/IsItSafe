pub const SCHEMA_VERSION: &str = "1.2";
pub const REPORT_SUMMARY_SCHEMA_VERSION: &str = "1.1";
pub const LIMITATION_NOTICE: &str =
    "Static analysis found no high-risk content; this does not prove runtime safety.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReportV1 {
    pub schema_version: String,
    pub report_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub file: FileEvidence,
    pub origin: OriginEvidence,
    pub classification: Classification,
    pub facts: Vec<Evidence>,
    pub inference: Vec<Evidence>,
    pub boundaries: Vec<Boundary>,
    pub threshold_decisions: ThresholdDecisions,
    pub lock_acquisition: LockAcquisitionEvidence,
    pub motw: MotwEvidence,
    pub alternate_streams: Vec<AlternateStream>,
    pub child_execution: Option<ChildExecution>,
    pub certificates: Vec<CertificateChainEvidence>,
    pub components: Vec<ComponentEvidence>,
    #[serde(default)]
    pub products: Vec<ProductIdentityEvidence>,
    pub authenticity: Option<AuthenticityEvidence>,
    pub reputation: Vec<ReputationEvidence>,
    pub policy: PolicyDecision,
    pub verdict: Verdict,
    pub limitations_notice: String,
    #[serde(skip, default)]
    pub source_path: Option<std::path::PathBuf>,
}

impl AnalysisReportV1 {
    pub fn new(file: FileEvidence) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            report_id: Uuid::new_v4(),
            observed_at: Utc::now(),
            file,
            origin: OriginEvidence::default(),
            classification: Classification::default(),
            facts: Vec::new(),
            inference: Vec::new(),
            boundaries: Vec::new(),
            threshold_decisions: ThresholdDecisions::default(),
            lock_acquisition: LockAcquisitionEvidence::default(),
            motw: MotwEvidence::default(),
            alternate_streams: Vec::new(),
            child_execution: None,
            certificates: Vec::new(),
            components: Vec::new(),
            products: Vec::new(),
            authenticity: None,
            reputation: Vec::new(),
            policy: PolicyDecision::default(),
            verdict: Verdict::Incomplete,
            limitations_notice: LIMITATION_NOTICE.into(),
            source_path: None,
        }
    }

    pub fn add_boundary(&mut self, kind: BoundaryKind, detail: impl Into<String>) {
        self.boundaries.push(Boundary {
            kind,
            detail: detail.into(),
        });
    }

    pub fn has_boundary(&self, kind: BoundaryKind) -> bool {
        self.boundaries.iter().any(|b| b.kind == kind)
    }

    pub fn request_quarantine(&mut self) {
        self.policy.quarantine_requested = true;
    }

    pub fn certificate_state_reason(&self) -> Option<&'static str> {
        if self
            .certificates
            .iter()
            .any(|certificate| certificate.revocation.state == RevocationState::Revoked)
        {
            return Some("Certificate is revoked");
        }
        let authenticity = self.authenticity.as_ref()?;
        if authenticity.signature_digest_valid == Some(false) {
            return Some("Signature digest is invalid");
        }
        if authenticity.chain_valid == Some(false) {
            return if authenticity.timestamp_state == TimestampState::Invalid {
                Some("Certificate has expired")
            } else {
                Some("Certificate chain is invalid")
            };
        }
        if authenticity.timestamp_state == TimestampState::Invalid {
            return Some("Signature timestamp is invalid");
        }
        let now = Utc::now();
        if self.certificates.iter().any(|certificate| {
            certificate.role != CertificateRole::Root
                && certificate.not_after.is_some_and(|value| now > value)
        }) {
            return Some("Certificate has expired");
        }
        self.certificates
            .iter()
            .any(|certificate| {
                certificate.role != CertificateRole::Root
                    && certificate.not_before.is_some_and(|value| now < value)
            })
            .then_some("Certificate is not yet valid")
    }

    pub fn certificate_problem_reason(&self) -> Option<&'static str> {
        self.certificate_state_reason().filter(|reason| {
            !matches!(
                *reason,
                "Certificate has expired" | "Certificate is not yet valid"
            )
        })
    }

    pub fn summary(&self) -> ReportSummary {
        ReportSummary {
            schema_version: REPORT_SUMMARY_SCHEMA_VERSION.into(),
            report_id: self.report_id,
            path: self.file.display_path.clone(),
            file_name: std::path::Path::new(&self.file.display_path)
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| self.file.display_path.clone()),
            sha256: self.file.sha256.clone(),
            size: self.file.size,
            verdict: self.verdict,
            observed_at: self.observed_at,
            reasons: concise_reasons(self),
            user_decision: self.policy.user_decision,
        }
    }
}

/// Compact report data used by the desktop lists. The complete report remains
/// available separately and is loaded only when its details are requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub schema_version: String,
    pub report_id: Uuid,
    pub path: String,
    pub file_name: String,
    pub sha256: Option<String>,
    pub size: u64,
    pub verdict: Verdict,
    pub observed_at: DateTime<Utc>,
    pub reasons: Vec<String>,
    pub user_decision: Option<UserDecision>,
}

fn concise_reasons(report: &AnalysisReportV1) -> Vec<String> {
    let mut reasons = Vec::new();
    for reason in &report.policy.reasons {
        if reason.starts_with("Waiting for a Keep, Quarantine, or Remove")
            || reason.starts_with("The user ")
        {
            continue;
        }
        push_unique(&mut reasons, reason.clone());
    }

    if let Some(reason) = report.certificate_state_reason() {
        push_unique(&mut reasons, reason.into());
    }

    let mut facts: Vec<&Evidence> = report
        .facts
        .iter()
        .filter(|evidence| evidence.severity >= Severity::Medium)
        .collect();
    facts.sort_by_key(|evidence| std::cmp::Reverse(evidence.severity));
    for evidence in facts {
        push_unique(&mut reasons, evidence.summary.clone());
        if reasons.len() >= 4 {
            break;
        }
    }

    for reputation in &report.reputation {
        if matches!(
            reputation.state,
            ReputationState::Malicious
                | ReputationState::Suspicious
                | ReputationState::RateLimited
                | ReputationState::Unavailable
        ) {
            let detail = match (reputation.detections, reputation.engines_total) {
                (Some(detections), Some(engines)) => {
                    format!("VirusTotal: {detections}/{engines} engines flagged this file")
                }
                _ => reputation
                    .detail
                    .clone()
                    .unwrap_or_else(|| format!("VirusTotal state: {:?}", reputation.state)),
            };
            push_unique(&mut reasons, detail);
        }
    }

    if reasons.len() < 2 {
        for boundary in &report.boundaries {
            push_unique(&mut reasons, boundary.detail.clone());
            if reasons.len() >= 4 {
                break;
            }
        }
    }

    if reasons.is_empty() {
        reasons.push(format!(
            "{:?} verdict; no concise reason was recorded",
            report.verdict
        ));
    }
    reasons.truncate(4);
    reasons
        .into_iter()
        .map(|reason| sanitize_visible_text(&reason))
        .collect()
}

fn push_unique(reasons: &mut Vec<String>, value: String) {
    let value = value.trim();
    if value.is_empty()
        || reasons
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(value))
    {
        return;
    }
    reasons.push(value.to_string());
}

fn sanitize_visible_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            value if value.is_control() => format!("\\u{{{:x}}}", value as u32).chars().collect(),
            value => vec![value],
        })
        .collect()
}

