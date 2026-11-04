use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::config::{AppPaths, Config};
use crate::db::{Database, normalize_path};
use crate::report::{ReportSummary, Severity, Verdict};

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
    for summary in summaries {
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
