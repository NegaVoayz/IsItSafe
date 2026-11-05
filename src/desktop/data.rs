use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::capture::escape_controls;
use crate::config::{AppPaths, Config};
use crate::db::{Database, normalize_path};
use crate::report::{AnalysisReportV1, ReportSummary, Severity, Verdict};

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
    if lower.contains("pe executable with no file extension") {
        return "Executable without extension".into();
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
    use crate::report::{AnalysisReportV1, FileEvidence, PolicyAction, UserDecision};

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
}
