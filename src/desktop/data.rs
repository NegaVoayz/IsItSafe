use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::capture::escape_controls;
use crate::config::{AppPaths, Config};
use crate::db::{Database, normalize_path};
use crate::report::{
    AnalysisReportV1, CertificateRole, ProductIdentityEvidence, ReportSummary, Severity, Verdict,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskGroup {
    Critical,
    High,
    Review,
    Limited,
    Unknown,
}

impl RiskGroup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Review => "Needs review",
            Self::Limited => "Limited visibility",
            Self::Unknown => "Unknown",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Critical => "Known malicious evidence",
            Self::High => "Suspicious structure or behavior",
            Self::Review => "Unresolved or incomplete checks",
            Self::Limited => "Only shallow checks were possible",
            Self::Unknown => "The original report is unavailable",
        }
    }

    pub fn from_verdict(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Malicious => Self::Critical,
            Verdict::Suspicious => Self::High,
            Verdict::ReviewRequired | Verdict::Unverified | Verdict::Incomplete => Self::Review,
            Verdict::Limited | Verdict::BasicCheckOnly => Self::Limited,
            Verdict::NoHighRiskFound => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuestionableFile {
    pub summary: ReportSummary,
    pub group: RiskGroup,
}

#[derive(Debug, Clone)]
pub struct QuarantineItem {
    pub sha256: String,
    pub path: PathBuf,
    pub moved_at: DateTime<Utc>,
    pub summary: Option<ReportSummary>,
    pub display_name: String,
    pub reasons: Vec<String>,
    pub group: RiskGroup,
}

impl QuarantineItem {
    pub fn suggested_download_name(&self) -> String {
        self.summary
            .as_ref()
            .map(|summary| summary.file_name.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| quarantine_original_name(&self.path))
    }
}

#[derive(Debug, Clone, Default)]
pub struct DesktopSnapshot {
    pub questionable: Vec<QuestionableFile>,
    pub quarantine: Vec<QuarantineItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    Invalid,
    Revoked,
    Expired,
    NotYetValid,
    Unsigned,
    Unknown,
    Unverified,
    Valid,
}

impl SignatureState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Invalid => "Invalid",
            Self::Revoked => "Revoked",
            Self::Expired => "Expired",
            Self::NotYetValid => "Not Yet Valid",
            Self::Unsigned => "Unsigned",
            Self::Unknown => "Unknown",
            Self::Unverified => "Unverified",
            Self::Valid => "Valid",
        }
    }

    pub fn risk_rank(self) -> u8 {
        match self {
            Self::Invalid => 0,
            Self::Revoked => 1,
            Self::Unsigned => 2,
            Self::Expired => 3,
            Self::NotYetValid => 4,
            Self::Unknown => 5,
            Self::Unverified => 6,
            Self::Valid => 7,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SoftwareIdentityGroup {
    pub product_name: String,
    pub manufacturer: Option<String>,
    pub product_version: Option<String>,
    pub certificates: Vec<SignatureGroup>,
}

impl SoftwareIdentityGroup {
    pub fn risk_state(&self) -> SignatureState {
        self.certificates
            .iter()
            .map(|certificate| certificate.state)
            .min_by_key(|state| state.risk_rank())
            .unwrap_or(SignatureState::Unknown)
    }

    pub fn starts_expanded(&self) -> bool {
        self.risk_state() != SignatureState::Valid
    }
}

#[derive(Debug, Clone)]
pub struct SignatureGroup {
    pub signer: String,
    pub certificate_sha256: Option<String>,
    pub state: SignatureState,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub products: Vec<ProductIdentityEvidence>,
}

pub fn group_products_by_software(report: &AnalysisReportV1) -> Vec<SoftwareIdentityGroup> {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<String, SoftwareIdentityGroup> = BTreeMap::new();
    for product in &report.products {
        let product_name = display_product_name(product);
        let key = software_identity_key(product, &product_name);
        let certificate = signature_group_for_product(report, product);
        let group = groups.entry(key).or_insert_with(|| SoftwareIdentityGroup {
            product_name,
            manufacturer: nonempty(product.manufacturer.as_deref()).map(str::to_string),
            product_version: nonempty(product.product_version.as_deref()).map(str::to_string),
            certificates: Vec::new(),
        });
        if let Some(existing) = group.certificates.iter_mut().find(|existing| {
            existing.state == certificate.state
                && existing.certificate_sha256 == certificate.certificate_sha256
                && existing.signer == certificate.signer
        }) {
            existing.products.extend(certificate.products);
        } else {
            group.certificates.push(certificate);
        }
    }

    for group in groups.values_mut() {
        for certificate in &mut group.certificates {
            certificate.products.sort_by(|left, right| {
                carrier_name(left)
                    .to_ascii_lowercase()
                    .cmp(&carrier_name(right).to_ascii_lowercase())
                    .then_with(|| left.nesting_path.cmp(&right.nesting_path))
            });
        }
        group.certificates.sort_by(|left, right| {
            left.state
                .risk_rank()
                .cmp(&right.state.risk_rank())
                .then_with(|| {
                    left.signer
                        .to_ascii_lowercase()
                        .cmp(&right.signer.to_ascii_lowercase())
                })
        });
    }

    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by(|left, right| {
        left.risk_state()
            .risk_rank()
            .cmp(&right.risk_state().risk_rank())
            .then_with(|| {
                left.product_name
                    .to_ascii_lowercase()
                    .cmp(&right.product_name.to_ascii_lowercase())
            })
            .then_with(|| {
                left.product_version
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(right.product_version.as_deref().unwrap_or_default())
            })
    });
    groups
}

fn signature_group_for_product(
    report: &AnalysisReportV1,
    product: &ProductIdentityEvidence,
) -> SignatureGroup {
    let top_level_fingerprint = report
        .certificates
        .iter()
        .find(|certificate| certificate.role == CertificateRole::Leaf)
        .map(|certificate| certificate.sha256_fingerprint.clone());
    let component = product.nesting_path.as_deref().and_then(|path| {
        report
            .components
            .iter()
            .find(|component| component.nesting_path == path)
    });
    let top_level = product.nesting_path.is_none();
    let authenticity = top_level.then_some(report.authenticity.as_ref()).flatten();
    let signer = product
        .signer_identity
        .clone()
        .or_else(|| authenticity.and_then(|value| value.publisher_identity.clone()));
    let fingerprint = product
        .signer_sha256
        .clone()
        .or_else(|| top_level.then_some(top_level_fingerprint.clone()).flatten());
    let digest_valid = product
        .signature_digest_valid
        .or_else(|| authenticity.and_then(|value| value.signature_digest_valid));
    let certificate = fingerprint.as_deref().and_then(|fingerprint| {
        report.certificates.iter().find(|certificate| {
            certificate
                .sha256_fingerprint
                .eq_ignore_ascii_case(fingerprint)
        })
    });
    let not_before = product
        .signature_not_before
        .or_else(|| certificate.and_then(|value| value.not_before));
    let not_after = product
        .signature_not_after
        .or_else(|| certificate.and_then(|value| value.not_after));
    let signed = component.and_then(|value| value.signed).or_else(|| {
        (top_level
            && authenticity.is_some_and(|value| {
                value.publisher_identity.is_some() || value.signature_digest_valid.is_some()
            }))
        .then_some(true)
    });
    let now = Utc::now();
    let state = if digest_valid == Some(false) {
        SignatureState::Invalid
    } else if certificate
        .is_some_and(|value| value.revocation.state == crate::report::RevocationState::Revoked)
    {
        SignatureState::Revoked
    } else if signed == Some(false) {
        SignatureState::Unsigned
    } else if not_after.is_some_and(|value| now > value) {
        SignatureState::Expired
    } else if not_before.is_some_and(|value| now < value) {
        SignatureState::NotYetValid
    } else if digest_valid == Some(true) {
        SignatureState::Valid
    } else if signer.is_some() || signed == Some(true) {
        SignatureState::Unverified
    } else {
        SignatureState::Unknown
    };
    let signer = signer
        .as_deref()
        .map(compact_signer_name)
        .unwrap_or_else(|| match state {
            SignatureState::Invalid => "Invalid signature".into(),
            SignatureState::Unsigned => "No signature".into(),
            SignatureState::Unknown => "Signer unknown".into(),
            SignatureState::Unverified => "Signer unavailable".into(),
            SignatureState::Valid => "Verified signer".into(),
            SignatureState::Revoked => "Revoked certificate".into(),
            SignatureState::Expired => "Expired certificate".into(),
            SignatureState::NotYetValid => "Certificate not yet valid".into(),
        });
    SignatureGroup {
        signer,
        certificate_sha256: fingerprint,
        state,
        not_before,
        not_after,
        products: vec![product.clone()],
    }
}

fn software_identity_key(product: &ProductIdentityEvidence, product_name: &str) -> String {
    [
        product_name,
        product.manufacturer.as_deref().unwrap_or_default(),
        product.product_version.as_deref().unwrap_or_default(),
        product.product_code.as_deref().unwrap_or_default(),
        product.upgrade_code.as_deref().unwrap_or_default(),
    ]
    .join("\0")
    .to_ascii_lowercase()
}

fn display_product_name(product: &ProductIdentityEvidence) -> String {
    nonempty(product.product_name.as_deref())
        .or_else(|| nonempty(product.file_description.as_deref()))
        .or_else(|| nonempty(product.original_filename.as_deref()))
        .map(str::to_string)
        .or_else(|| {
            product
                .nesting_path
                .as_deref()
                .and_then(|path| Path::new(path).file_name())
                .map(|value| value.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "<unnamed software>".into())
}

fn carrier_name(product: &ProductIdentityEvidence) -> &str {
    product
        .original_filename
        .as_deref()
        .or(product.nesting_path.as_deref())
        .unwrap_or_default()
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn format_certificate_date(value: Option<DateTime<Utc>>) -> Option<String> {
    value.map(|date| date.format("%Y-%m-%d %H:%M UTC").to_string())
}

impl SignatureGroup {
    pub fn validity_label(&self) -> Option<String> {
        match (
            format_certificate_date(self.not_before),
            format_certificate_date(self.not_after),
        ) {
            (Some(not_before), Some(not_after)) => Some(format!("{not_before} to {not_after}")),
            (Some(not_before), None) => Some(format!("From {not_before}")),
            (None, Some(not_after)) => Some(format!("Until {not_after}")),
            (None, None) => None,
        }
    }
}

fn compact_signer_name(identity: &str) -> String {
    for attribute in ["CN=", "O="] {
        if let Some(start) = identity.find(attribute) {
            let value = &identity[start + attribute.len()..];
            let value = value.split(',').next().unwrap_or(value).trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    identity.to_string()
}

impl DesktopSnapshot {
    pub fn review_count(&self, group: RiskGroup) -> usize {
        self.questionable
            .iter()
            .filter(|entry| entry.group == group)
            .count()
    }

    pub fn quarantine_count(&self, group: RiskGroup) -> usize {
        self.quarantine
            .iter()
            .filter(|entry| entry.group == group)
            .count()
    }
}

pub fn load_snapshot(
    config: &Config,
    database: &Database,
    _paths: &AppPaths,
) -> Result<DesktopSnapshot> {
    let summaries = database.latest_report_summaries()?;
    let mut questionable = Vec::new();
    for mut summary in summaries {
        summary.reasons = summary
            .reasons
            .into_iter()
            .map(|reason| escape_controls(&reason))
            .collect();
        if summary.user_decision.is_some() || summary.verdict == Verdict::NoHighRiskFound {
            continue;
        }
        if !is_current_download(&summary.path, &config.download_dir) {
            continue;
        }
        let group = RiskGroup::from_verdict(summary.verdict);
        questionable.push(QuestionableFile { summary, group });
    }
    questionable.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then_with(|| right.summary.observed_at.cmp(&left.summary.observed_at))
            .then_with(|| {
                left.summary
                    .file_name
                    .to_ascii_lowercase()
                    .cmp(&right.summary.file_name.to_ascii_lowercase())
            })
    });

    let mut quarantine = Vec::new();
    for entry in database.list_quarantine_entries()? {
        let (display_name, reasons, group) = if let Some(summary) = &entry.summary {
            (
                summary.file_name.clone(),
                summary.reasons.clone(),
                RiskGroup::from_verdict(summary.verdict),
            )
        } else {
            (
                quarantine_original_name(&entry.path),
                vec!["The original analysis report is unavailable".into()],
                RiskGroup::Unknown,
            )
        };
        quarantine.push(QuarantineItem {
            sha256: entry.sha256,
            path: entry.path,
            moved_at: entry.moved_at,
            summary: entry.summary,
            display_name,
            reasons,
            group,
        });
    }
    quarantine.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then_with(|| right.moved_at.cmp(&left.moved_at))
    });

    Ok(DesktopSnapshot {
        questionable,
        quarantine,
    })
}

pub fn most_risky_component_first(components: &mut [crate::report::ComponentEvidence]) {
    components.sort_by(|left, right| {
        std::cmp::Reverse(left.severity)
            .cmp(&std::cmp::Reverse(right.severity))
            .then_with(|| left.nesting_path.cmp(&right.nesting_path))
    });
}

pub fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

pub fn reputation_subject(report: &AnalysisReportV1, sha256: &str) -> String {
    if report
        .file
        .sha256
        .as_deref()
        .is_some_and(|hash| hash.eq_ignore_ascii_case(sha256))
    {
        return format!(
            "Download file: {}",
            Path::new(&report.file.display_path)
                .file_name()
                .map_or_else(
                    || report.file.display_path.clone(),
                    |name| name.to_string_lossy().into_owned()
                )
        );
    }
    if let Some(component) = report.components.iter().find(|component| {
        component
            .sha256
            .as_deref()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(sha256))
    }) {
        return format!("Inside: {}", component.nesting_path);
    }
    format!("Hash: {}...", &sha256[..sha256.len().min(12)])
}

pub fn compact_reason(reason: &str) -> String {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("virustotal") {
        if lower.contains("reported one or more malicious") {
            return "VirusTotal: malicious".into();
        }
        if lower.contains("reported suspicious") {
            return "VirusTotal: suspicious".into();
        }
        let detections = reason
            .split_whitespace()
            .find(|part| {
                part.split_once('/').is_some_and(|(found, total)| {
                    found.chars().all(|character| character.is_ascii_digit())
                        && total
                            .trim_end_matches(|character: char| !character.is_ascii_digit())
                            .chars()
                            .all(|character| character.is_ascii_digit())
                })
            })
            .map(|part| {
                part.trim_end_matches(|character: char| !character.is_ascii_digit())
                    .to_string()
            });
        return detections.map_or_else(
            || "VirusTotal finding".into(),
            |count| format!("VirusTotal {count}"),
        );
    }
    if lower.contains("downloaded file name") && lower.contains("embedded original filename") {
        return "Name differs from embedded file".into();
    }
    if lower.contains("multiple file formats") {
        return "Multiple embedded formats".into();
    }
    if lower.contains("extension") && lower.contains("does not match") {
        return "Extension does not match content".into();
    }
    if lower.contains("pdf") && lower.contains("active") {
        return "Active PDF content".into();
    }
    if lower.contains("script references endpoint") {
        return "Embedded endpoint".into();
    }
    if lower.contains("executable has no authenticode signature") {
        return "Unsigned executable".into();
    }
    if lower.contains("certificate is revoked")
        || lower.contains("authenticity evidence is invalid or revoked")
    {
        return "Revoked certificate".into();
    }
    if lower.contains("signature digest is invalid") {
        return "Invalid signature".into();
    }
    if lower.contains("certificate has expired")
        || lower.contains("certificate is expired or invalid")
    {
        return "Expired certificate".into();
    }
    if lower.contains("certificate chain is invalid") {
        return "Invalid certificate chain".into();
    }
    if lower.contains("signature timestamp is invalid") {
        return "Invalid signature timestamp".into();
    }
    if lower.contains(" is an exe disguised as .") || lower.contains(" is a dll disguised as .") {
        let kind = if lower.contains(" is an exe disguised as .") {
            "EXE"
        } else {
            "DLL"
        };
        let extension = reason
            .split_once(" disguised as .")
            .map_or("other", |(_, extension)| {
                extension.split_whitespace().next().unwrap_or("other")
            });
        return format!("{kind} hidden as .{extension}");
    }
    // Preserve the concise label for reports written before the PE wording change.
    if lower.contains("pe executable disguised with the .") {
        let extension = reason
            .split("with the .")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or("other");
        return format!("Executable hidden as .{extension}");
    }
    if lower.contains("uses a .dll extension") && lower.contains("marks it as an exe") {
        return "EXE hidden as .dll".into();
    }
    if lower.contains("uses a .exe extension") && lower.contains("marks it as a dll") {
        return "DLL hidden as .exe".into();
    }
    if lower.contains("has no file extension but is an exe")
        || lower.contains("has no file extension but is a dll")
    {
        return if lower.contains("but is an exe") {
            "EXE without extension".into()
        } else {
            "DLL without extension".into()
        };
    }
    if lower.contains("pe executable with no file extension") {
        return "EXE without extension".into();
    }
    if lower.contains("decompression bomb") {
        return "Possible zip bomb".into();
    }
    if lower.contains("exceeded") && lower.contains("threshold") {
        return "Too large for deep scan".into();
    }
    if lower.contains("snapshot_max_bytes") || lower.contains("basic_check_threshold_bytes") {
        return String::new();
    }
    if lower.contains("temporary download") {
        return "Incomplete download".into();
    }
    if lower.contains("network reputation") {
        return "Online reputation incomplete".into();
    }
    if lower.contains("structural evidence") {
        return "Structural risk".into();
    }
    if lower.contains("user chose to keep") {
        return "Kept by user".into();
    }

    let first_clause = reason.split([';', '•']).next().unwrap_or(reason).trim();
    let mut compact = first_clause.chars().take(42).collect::<String>();
    if first_clause.chars().count() > 42 {
        compact.push('…');
    }
    compact
}

pub fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

fn is_current_download(path: &str, download_dir: &Path) -> bool {
    let path = Path::new(path);
    let parent_matches = path.parent().is_some_and(|parent| {
        normalize_path(&parent.to_string_lossy()) == normalize_path(&download_dir.to_string_lossy())
    });
    if !parent_matches {
        return false;
    }
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_file() && {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & 0x400 == 0
            }
            #[cfg(not(windows))]
            {
                !metadata.file_type().is_symlink()
            }
        }
    })
}

fn quarantine_original_name(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".into());
    let Some(stem) = name.strip_suffix(".quarantined") else {
        return name;
    };
    let Some((original, hash_segment)) = stem.rsplit_once('.') else {
        return stem.to_string();
    };
    let hash = hash_segment
        .split_once('-')
        .map_or(hash_segment, |(hash, _)| hash);
    if hash.len() == 12 && hash.chars().all(|character| character.is_ascii_hexdigit()) {
        original.to_string()
    } else {
        stem.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interaction::{
        DecisionSource, execute_user_decision, restore_quarantine_from_desktop,
    };
    use crate::report::{AnalysisReportV1, FileEvidence, PolicyAction, UserDecision};
    use sha2::{Digest, Sha256};

    #[test]
    fn risk_groups_cover_every_review_verdict() {
        assert_eq!(
            RiskGroup::from_verdict(Verdict::Malicious),
            RiskGroup::Critical
        );
        assert_eq!(
            RiskGroup::from_verdict(Verdict::Suspicious),
            RiskGroup::High
        );
        assert_eq!(
            RiskGroup::from_verdict(Verdict::Incomplete),
            RiskGroup::Review
        );
        assert_eq!(
            RiskGroup::from_verdict(Verdict::BasicCheckOnly),
            RiskGroup::Limited
        );
    }

    #[test]
    fn quarantine_name_recovers_the_searchable_original_name() {
        assert_eq!(
            quarantine_original_name(Path::new(
                r"C:\data\quarantine\setup.exe.abcdef123456.quarantined"
            )),
            "setup.exe"
        );
        assert_eq!(
            quarantine_original_name(Path::new(
                r"C:\data\quarantine\setup.exe.abcdef123456-2.quarantined"
            )),
            "setup.exe"
        );
    }

    #[test]
    fn review_reasons_are_short_labels() {
        assert_eq!(
            compact_reason("VirusTotal: 3/93 engines flagged this file"),
            "VirusTotal 3/93"
        );
        assert_eq!(
            compact_reason("VirusTotal reported one or more malicious detections"),
            "VirusTotal: malicious"
        );
        assert_eq!(
            compact_reason(
                "Downloaded file name ddu.exe differs from embedded original filename SqlSetupBootstrapper.exe"
            ),
            "Name differs from embedded file"
        );
        assert_eq!(
            compact_reason("File extension .jpg does not match its contents (detected: pe)"),
            "Extension does not match content"
        );
        assert_eq!(
            compact_reason("The file exceeded a deep-analysis resource threshold"),
            "Too large for deep scan"
        );
        assert_eq!(
            compact_reason(
                "Potential decompression bomb: payload.dat, ratio 1026:1, 6731776 bytes declared"
            ),
            "Possible zip bomb"
        );
        assert_eq!(
            compact_reason(
                "vcomp140.dll uses a .dll extension but its PE header marks it as an EXE"
            ),
            "EXE hidden as .dll"
        );
        assert_eq!(
            compact_reason("patch.dat is a PE executable disguised with the .dat extension"),
            "Executable hidden as .dat"
        );
        assert_eq!(
            compact_reason("SqlSetupBootstrapper.dll is an EXE disguised as .dll"),
            "EXE hidden as .dll"
        );
        assert_eq!(
            compact_reason("metadata.dat is a DLL disguised as .dat"),
            "DLL hidden as .dat"
        );
        assert_eq!(
            compact_reason("payload.metadata has no file extension but is an EXE"),
            "EXE without extension"
        );
        assert_eq!(
            compact_reason("Certificate is expired or invalid"),
            "Expired certificate"
        );
        assert_eq!(
            compact_reason("Certificate has expired"),
            "Expired certificate"
        );
        assert_eq!(
            compact_reason("Certificate chain is invalid"),
            "Invalid certificate chain"
        );
        assert_eq!(
            compact_reason("Certificate is revoked"),
            "Revoked certificate"
        );
        assert_eq!(
            compact_reason("file exceeds snapshot_max_bytes (536870912)"),
            ""
        );
    }

    #[test]
    fn reputation_subjects_name_the_download_or_embedded_file() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\bundle.zip".into(),
            sha256: Some("a".repeat(64)),
            ..FileEvidence::default()
        });
        report.components.push(crate::report::ComponentEvidence {
            nesting_path: "bundle/tool.exe".into(),
            name: "bundle/tool.exe".into(),
            size: 1,
            sha256: Some("b".repeat(64)),
            formats: Vec::new(),
            severity: Severity::Info,
            signed: None,
            evidence: Vec::new(),
        });

        assert_eq!(
            reputation_subject(&report, &"a".repeat(64)),
            "Download file: bundle.zip"
        );
        assert_eq!(
            reputation_subject(&report, &"B".repeat(64)),
            "Inside: bundle/tool.exe"
        );
        assert_eq!(
            reputation_subject(&report, &"c".repeat(64)),
            "Hash: cccccccccccc..."
        );
    }

    #[test]
    fn software_identities_group_carriers_before_certificates() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\bundle.zip".into(),
            sha256: Some("a".repeat(64)),
            ..FileEvidence::default()
        });
        let signed_product = |name: &str, path: &str| ProductIdentityEvidence {
            product_name: Some(name.into()),
            signer_identity: Some("C=US, O=Example Corp, CN=Example Corp Code Signing".into()),
            signer_sha256: Some("b".repeat(64)),
            signature_digest_valid: Some(true),
            nesting_path: Some(path.into()),
            ..ProductIdentityEvidence::default()
        };
        report
            .products
            .push(signed_product("Example App", "Example.exe"));
        report
            .products
            .push(signed_product("Example App", "Example.dll"));
        report.products.push(ProductIdentityEvidence {
            product_name: Some("Hidden Payload".into()),
            nesting_path: Some("payload.dll".into()),
            ..ProductIdentityEvidence::default()
        });
        report.components.push(crate::report::ComponentEvidence {
            nesting_path: "Example.exe".into(),
            name: "Example.exe".into(),
            size: 1,
            sha256: Some("c".repeat(64)),
            formats: Vec::new(),
            severity: Severity::Info,
            signed: Some(true),
            evidence: Vec::new(),
        });
        report.components.push(crate::report::ComponentEvidence {
            nesting_path: "payload.dll".into(),
            name: "payload.dll".into(),
            size: 1,
            sha256: Some("d".repeat(64)),
            formats: Vec::new(),
            severity: Severity::High,
            signed: Some(false),
            evidence: Vec::new(),
        });

        let groups = group_products_by_software(&report);
        let signed = groups
            .iter()
            .find(|group| group.product_name == "Example App")
            .expect("signed software");
        assert_eq!(signed.manufacturer.as_deref(), None);
        assert_eq!(signed.certificates.len(), 1);
        assert_eq!(signed.certificates[0].signer, "Example Corp Code Signing");
        assert_eq!(signed.certificates[0].products.len(), 2);
        assert_eq!(signed.certificates[0].state, SignatureState::Valid);
        let unsigned = groups
            .iter()
            .find(|group| group.product_name == "Hidden Payload")
            .expect("unsigned software");
        assert_eq!(unsigned.certificates[0].state, SignatureState::Unsigned);
        assert_eq!(unsigned.certificates[0].products.len(), 1);
    }

    #[test]
    fn signature_status_labels_are_compact() {
        assert_eq!(SignatureState::Valid.label(), "Valid");
        assert_eq!(SignatureState::Unsigned.label(), "Unsigned");
        assert_eq!(SignatureState::Revoked.label(), "Revoked");
        assert_eq!(SignatureState::Expired.label(), "Expired");
        assert_eq!(SignatureState::NotYetValid.label(), "Not Yet Valid");
    }

    #[test]
    fn certificate_risk_orders_revoked_unsigned_then_expired() {
        assert!(SignatureState::Revoked.risk_rank() < SignatureState::Unsigned.risk_rank());
        assert!(SignatureState::Unsigned.risk_rank() < SignatureState::Expired.risk_rank());
        assert!(SignatureState::Expired.risk_rank() < SignatureState::Valid.risk_rank());

        let mut group = SoftwareIdentityGroup {
            product_name: "Example".into(),
            manufacturer: None,
            product_version: None,
            certificates: Vec::new(),
        };
        for state in [
            SignatureState::Expired,
            SignatureState::Unsigned,
            SignatureState::Revoked,
        ] {
            group.certificates.push(SignatureGroup {
                signer: format!("{state:?}"),
                certificate_sha256: None,
                state,
                not_before: None,
                not_after: None,
                products: Vec::new(),
            });
        }
        assert_eq!(group.risk_state(), SignatureState::Revoked);
    }

    #[test]
    fn one_software_identity_can_contain_multiple_certificate_groups() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\runtime.zip".into(),
            ..FileEvidence::default()
        });
        for (filename, fingerprint) in [("alpha.dll", "1"), ("beta.dll", "2")] {
            report.products.push(ProductIdentityEvidence {
                product_name: Some("Example Runtime".into()),
                manufacturer: Some("Example Corporation".into()),
                product_version: Some("14.0".into()),
                signer_identity: Some(format!("CN=Example Publisher {fingerprint}")),
                signer_sha256: Some(fingerprint.repeat(64)),
                signature_digest_valid: Some(true),
                nesting_path: Some(filename.into()),
                ..ProductIdentityEvidence::default()
            });
        }

        let groups = group_products_by_software(&report);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].product_name, "Example Runtime");
        assert_eq!(
            groups[0].manufacturer.as_deref(),
            Some("Example Corporation")
        );
        assert_eq!(groups[0].certificates.len(), 2);
    }

    #[test]
    fn software_identities_sort_by_risk_then_name() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\bundle.zip".into(),
            ..FileEvidence::default()
        });
        for (name, fingerprint, digest_valid) in [
            ("Valid Product", Some("1".repeat(64)), Some(true)),
            ("Another Valid Product", Some("4".repeat(64)), Some(true)),
            ("Unsigned Product", None, None),
            ("Unverified Product", Some("2".repeat(64)), None),
            ("Invalid Product", Some("3".repeat(64)), Some(false)),
        ] {
            report.products.push(ProductIdentityEvidence {
                product_name: Some(name.into()),
                signer_identity: fingerprint.as_ref().map(|_| format!("CN={name} Publisher")),
                signer_sha256: fingerprint,
                signature_digest_valid: digest_valid,
                nesting_path: Some(format!("{name}.exe")),
                ..ProductIdentityEvidence::default()
            });
        }
        report.components.push(crate::report::ComponentEvidence {
            nesting_path: "Unsigned Product.exe".into(),
            name: "Unsigned Product.exe".into(),
            size: 1,
            sha256: None,
            formats: Vec::new(),
            severity: Severity::High,
            signed: Some(false),
            evidence: Vec::new(),
        });

        let groups = group_products_by_software(&report);
        assert_eq!(
            groups
                .iter()
                .map(SoftwareIdentityGroup::risk_state)
                .collect::<Vec<_>>(),
            vec![
                SignatureState::Invalid,
                SignatureState::Unsigned,
                SignatureState::Unverified,
                SignatureState::Valid,
                SignatureState::Valid,
            ]
        );
        assert_eq!(
            groups[3..]
                .iter()
                .map(|group| group.product_name.as_str())
                .collect::<Vec<_>>(),
            vec!["Another Valid Product", "Valid Product"]
        );
        assert!(groups[3..].iter().all(|group| !group.starts_expanded()));
        assert!(
            groups[..3]
                .iter()
                .all(SoftwareIdentityGroup::starts_expanded)
        );
    }

    #[test]
    fn expired_signer_metadata_takes_precedence_over_a_valid_digest() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\expired.exe".into(),
            ..FileEvidence::default()
        });
        report.products.push(ProductIdentityEvidence {
            product_name: Some("Expired Product".into()),
            signer_identity: Some("CN=Expired Publisher".into()),
            signer_sha256: Some("e".repeat(64)),
            signature_digest_valid: Some(true),
            signature_not_before: Some(Utc::now() - chrono::Duration::days(30)),
            signature_not_after: Some(Utc::now() - chrono::Duration::days(1)),
            nesting_path: Some("expired.exe".into()),
            ..ProductIdentityEvidence::default()
        });

        let groups = group_products_by_software(&report);
        assert_eq!(groups[0].certificates[0].state, SignatureState::Expired);
    }

    #[test]
    fn snapshot_hides_safe_kept_and_outside_downloads() {
        let root = tempfile::tempdir().unwrap();
        let downloads = root.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let questionable = downloads.join("questionable.exe");
        let safe = downloads.join("safe.txt");
        let kept = downloads.join("kept.exe");
        fs::write(&questionable, b"x").unwrap();
        fs::write(&safe, b"x").unwrap();
        fs::write(&kept, b"x").unwrap();

        let db = Database::open(&root.path().join("state.db")).unwrap();
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: questionable.to_string_lossy().into_owned(),
            sha256: Some("a".repeat(64)),
            size: 1,
            ..FileEvidence::default()
        });
        report.verdict = Verdict::Suspicious;
        report.policy.action = PolicyAction::RequireReview;
        report
            .policy
            .reasons
            .push("Suspicious test evidence".into());
        db.store_report(&report).unwrap();

        let mut safe_report = AnalysisReportV1::new(FileEvidence {
            display_path: safe.to_string_lossy().into_owned(),
            sha256: Some("b".repeat(64)),
            size: 1,
            ..FileEvidence::default()
        });
        safe_report.verdict = Verdict::NoHighRiskFound;
        db.store_report(&safe_report).unwrap();

        let mut kept_report = AnalysisReportV1::new(FileEvidence {
            display_path: kept.to_string_lossy().into_owned(),
            sha256: Some("c".repeat(64)),
            size: 1,
            ..FileEvidence::default()
        });
        kept_report.verdict = Verdict::Malicious;
        kept_report.policy.user_decision = Some(UserDecision::Keep);
        db.store_report(&kept_report).unwrap();

        let config = Config {
            download_dir: downloads,
            ..Config::default()
        };
        let paths = AppPaths {
            config_file: root.path().join("config.toml"),
            data_dir: root.path().to_path_buf(),
            database: root.path().join("state.db"),
            reports_dir: root.path().join("reports"),
            logs_dir: root.path().join("logs"),
            quarantine_dir: root.path().join("quarantine"),
            rules_dir: root.path().join("rules"),
        };
        let snapshot = load_snapshot(&config, &db, &paths).unwrap();
        assert_eq!(snapshot.questionable.len(), 1);
        assert_eq!(
            snapshot.questionable[0].summary.file_name,
            "questionable.exe"
        );
    }

    #[test]
    fn restored_quarantine_returns_to_review() {
        let root = tempfile::tempdir().unwrap();
        let downloads = root.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let source = downloads.join("restored.exe");
        let bytes = b"restored test content";
        fs::write(&source, bytes).unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        let mut config = Config {
            download_dir: downloads,
            ..Config::default()
        };
        config.security.block_execution_in_download_dir = false;
        let paths = AppPaths {
            config_file: root.path().join("config.toml"),
            data_dir: root.path().to_path_buf(),
            database: root.path().join("state.db"),
            reports_dir: root.path().join("reports"),
            logs_dir: root.path().join("logs"),
            quarantine_dir: root.path().join("quarantine"),
            rules_dir: root.path().join("rules"),
        };
        paths.ensure().unwrap();
        let database = Database::open(&paths.database).unwrap();
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: source.to_string_lossy().into_owned(),
            sha256: Some(hash.clone()),
            size: bytes.len() as u64,
            ..FileEvidence::default()
        });
        report.verdict = Verdict::Suspicious;
        report.policy.action = PolicyAction::RequireReview;
        report
            .policy
            .reasons
            .push("Suspicious test evidence".into());
        database.store_report(&report).unwrap();

        execute_user_decision(
            report.report_id,
            UserDecision::Quarantine,
            DecisionSource::Desktop,
            &config,
            &database,
            &paths,
        )
        .unwrap();
        restore_quarantine_from_desktop(&database, &config, &paths, &hash, "restored.exe").unwrap();

        let snapshot = load_snapshot(&config, &database, &paths).unwrap();
        assert_eq!(snapshot.questionable.len(), 1);
        assert_eq!(snapshot.questionable[0].summary.file_name, "restored.exe");
        assert_eq!(snapshot.questionable[0].summary.user_decision, None);
    }
}
