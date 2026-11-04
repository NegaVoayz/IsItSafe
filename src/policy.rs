use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use chrono::Utc;

use crate::capture::{CaptureDepth, capture, remove_if_hash_matches};
use crate::config::{Config, GIB};
use crate::db::{Database, normalize_path};
use crate::report::{
    AnalysisReportV1, BoundaryKind, PolicyAction, PublisherReputation, ReputationState, Severity,
    Verdict,
};

pub fn evaluate(report: &mut AnalysisReportV1, config: &Config) {
    report.policy.reasons.clear();
    report.policy.allowlist_downgraded = allowlisted(report, config);

    let confirmed_malicious = report
        .reputation
        .iter()
        .any(|entry| entry.state == ReputationState::Malicious);
    let vt_suspicious = report
        .reputation
        .iter()
        .any(|entry| entry.state == ReputationState::Suspicious);
    let revoked = report.certificates.iter().any(|certificate| {
        matches!(
            certificate.revocation.state,
            crate::report::RevocationState::Revoked
        )
    });
    let invalid_signature = report
        .authenticity
        .as_ref()
        .is_some_and(|value| value.signature_digest_valid == Some(false));
    let high_evidence = report
        .facts
        .iter()
        .any(|evidence| evidence.severity >= Severity::High);
    let remote_access = report
        .authenticity
        .as_ref()
        .is_some_and(|value| value.publisher_reputation == PublisherReputation::RemoteAccess)
        || report.components.iter().any(|component| {
            component
                .evidence
                .iter()
                .any(|evidence| evidence.category == "remote_access")
        });
    let sensitive_endpoint = report.facts.iter().any(|evidence| {
        matches!(
            evidence.category.as_str(),
            "remote_access_endpoint" | "autostart" | "credential_material"
        )
    });
    let blocked_origin = report.origin.source_url.as_deref().is_some_and(|url| {
        config
            .policy
            .blocked_origins
            .iter()
            .any(|blocked| origin_matches(url, blocked, None))
    });
    let review_origin = report.origin.source_url.as_deref().is_some_and(|url| {
        config
            .policy
            .review_origins
            .iter()
            .any(|review| origin_matches(url, review, None))
    });
    let browser_danger = report
        .origin
        .browser_danger
        .as_deref()
        .is_some_and(|danger| {
            matches!(
                danger.to_ascii_lowercase().as_str(),
                "dangerous" | "untrusted" | "unwanted" | "uncommon"
            )
        });
    let incomplete = report.boundaries.iter().any(|boundary| {
        matches!(
            boundary.kind,
            BoundaryKind::LockAcquisitionTimeout
                | BoundaryKind::LockNotAvailable
                | BoundaryKind::ReadOnlyContent
                | BoundaryKind::FileChangedDuringRead
                | BoundaryKind::OutputTruncated
                | BoundaryKind::BudgetExceeded
                | BoundaryKind::ChildCrashed
                | BoundaryKind::ChildTimedOut
                | BoundaryKind::ChildKilledByJob
                | BoundaryKind::SandboxViolation
                | BoundaryKind::QuarantineFailed
                | BoundaryKind::RemovalFailed
        )
    });
    let downgraded = report.boundaries.iter().any(|boundary| {
        matches!(
            boundary.kind,
            BoundaryKind::BasicCheckOnly | BoundaryKind::Limited
        )
    });
    let query_pending = report.reputation.iter().any(|entry| {
        matches!(
            entry.state,
            ReputationState::Pending | ReputationState::RateLimited
        )
    });
    let reputation_unavailable = report.reputation.iter().any(|entry| {
        matches!(
            entry.state,
            ReputationState::Unavailable | ReputationState::NotQueried
        )
    });
    let high_risk_type = report.classification.extension_mismatch
        || report.classification.risky_trailing_data
        || report.classification.formats.iter().any(|format| {
            matches!(
                format.kind.as_str(),
                "pe" | "msi"
                    | "ole_cfb"
                    | "zip"
                    | "cab"
                    | "7z"
                    | "rar"
                    | "powershell"
                    | "batch"
                    | "vbscript"
                    | "javascript"
                    | "hta"
                    | "lnk"
                    | "svg"
            ) || format.kind.starts_with("installer:")
                || format.kind.starts_with("ooxml:")
        });

    if confirmed_malicious {
        report.verdict = Verdict::Malicious;
        report.policy.action = if config.policy.quarantine_enabled {
            PolicyAction::Quarantine
        } else {
            PolicyAction::Notify
        };
        report
            .policy
            .reasons
            .push("VirusTotal reported one or more malicious detections".into());
    } else if vt_suspicious {
        report.verdict = Verdict::Suspicious;
        report.policy.action = review_action(config);
        report
            .policy
            .reasons
            .push("VirusTotal reported suspicious detections".into());
    } else if revoked || invalid_signature {
        report.verdict = Verdict::Suspicious;
        report.policy.action = review_action(config);
        report
            .policy
            .reasons
            .push("Authenticity evidence is invalid or revoked".into());
    } else if high_evidence || blocked_origin || browser_danger {
        report.verdict = Verdict::Suspicious;
        report.policy.action = review_action(config);
        report
            .policy
            .reasons
            .push("High-severity structural evidence was found".into());
    } else if (remote_access && sensitive_endpoint) || review_origin {
        report.verdict = Verdict::ReviewRequired;
        report.policy.action = review_action(config);
        report
            .policy
            .reasons
            .push("The installer combines review-required origin or remote-access behavior".into());
    } else if incomplete {
        report.verdict = Verdict::Incomplete;
        report.policy.action = review_action(config);
        report
            .policy
            .reasons
            .push("One or more safety checks did not complete".into());
    } else if downgraded {
        report.verdict = if report.threshold_decisions.basic_check_only {
            Verdict::BasicCheckOnly
        } else {
            Verdict::Limited
        };
        report.policy.action = PolicyAction::Notify;
        report
            .policy
            .reasons
            .push("The file exceeded a deep-analysis resource threshold".into());
    } else if query_pending || (high_risk_type && reputation_unavailable) {
        report.verdict = Verdict::Unverified;
        report.policy.action = PolicyAction::Notify;
        report
            .policy
            .reasons
            .push("Some required network reputation checks are not complete".into());
    } else {
        report.verdict = Verdict::NoHighRiskFound;
        report.policy.action = PolicyAction::NoAction;
        report
            .policy
            .reasons
            .push("No high-risk evidence was found by completed checks".into());
    }

    if report.policy.allowlist_downgraded && report.verdict != Verdict::Malicious {
        report.policy.reasons.push(
            "A configured origin/signer allowlist downgraded the notification level; checks were not skipped"
                .into(),
        );
        if report.policy.action != PolicyAction::NoAction {
            report.policy.action = PolicyAction::Notify;
            report.policy.quarantine_requested = false;
        }
    }

    if report.policy.action == PolicyAction::Quarantine {
        report.policy.quarantine_requested = true;
    }
}

fn review_action(config: &Config) -> PolicyAction {
    if config.policy.quarantine_enabled && config.policy.quarantine_review_required {
        PolicyAction::Quarantine
    } else {
        PolicyAction::RequireReview
    }
}

pub fn apply_quarantine(
    report: &AnalysisReportV1,
    config: &Config,
    database: &Database,
    quarantine_root: &Path,
) -> Result<Option<PathBuf>> {
    if !report.policy.quarantine_requested {
        return Ok(None);
    }
    if report.file.is_reparse_point {
        bail!("refusing to quarantine a reparse point");
    }
    let source = report
        .source_path
        .clone()
        .context("refusing to quarantine without the original source path")?;
    if !source.is_absolute() {
        bail!("refusing to quarantine without an absolute source path");
    }
    let expected_hash = report
        .file
        .sha256
        .as_deref()
        .context("refusing to quarantine without a source hash")?;

    // Re-read using the same exclusive readiness contract as analysis. This
    // catches a path replacement between reporting and quarantine.
    let fresh = capture(&source, config)?;
    if fresh.sha256.as_deref() != Some(expected_hash) {
        bail!("source changed after analysis; quarantine cancelled");
    }
    if fresh.depth == CaptureDepth::BasicCheckOnly
        && fresh.file.size > config.limits.basic_check_threshold_bytes
    {
        // BasicCheckOnly already streamed the complete hash under the lock.
    }

    fs::create_dir_all(quarantine_root)?;
    let safe_name = quarantine_file_name(&source, expected_hash, 0);
    let mut destination = quarantine_root.join(&safe_name);
    let mut suffix = 0u32;
    while destination.exists() && suffix < 1000 {
        suffix += 1;
        destination = quarantine_root.join(quarantine_file_name(&source, expected_hash, suffix));
    }
    if destination.exists() {
        bail!("could not allocate a unique quarantine filename");
    }
    deny_execute_acl(&source)?;
    if let Err(error) = fs::rename(&source, &destination) {
        let _ = restore_destination_acl(&source, config);
        return Err(error).with_context(|| format!("failed to quarantine {}", source.display()));
    }
    deny_execute_acl(&destination)?;
    database.quarantine_record(expected_hash, &destination, report.report_id)?;
    Ok(Some(destination))
}

/// Removes an analyzed source only after a fresh exclusive capture reproduces
/// the exact SHA-256 that the user reviewed. This makes a permanent deletion
/// explicit while retaining the same race protection as quarantine.
pub fn remove_verified(report: &AnalysisReportV1, config: &Config) -> Result<()> {
    if report.file.is_reparse_point {
        bail!("refusing to remove a reparse point");
    }
    let source = report
        .source_path
        .clone()
        .context("refusing to remove without the original source path")?;
    if !source.is_absolute() {
        bail!("refusing to remove without an absolute source path");
    }
    let expected_hash = report
        .file
        .sha256
        .as_deref()
        .context("refusing to remove without a source hash")?;
    remove_if_hash_matches(&source, config, expected_hash)?;
    Ok(())
}

pub fn prune_quarantine(
    database: &Database,
    quarantine_root: &Path,
    retention_days: u64,
) -> Result<usize> {
    if retention_days == 0 {
        bail!("quarantine retention must be greater than zero");
    }
    let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
    let mut removed = 0usize;
    for (sha256, path, moved_at) in database.list_quarantine()? {
        if moved_at >= cutoff {
            continue;
        }
        if path.exists() {
            let canonical_root = quarantine_root.canonicalize().with_context(|| {
                format!(
                    "quarantine root is unavailable: {}",
                    quarantine_root.display()
                )
            })?;
            let canonical_path = path
                .canonicalize()
                .with_context(|| format!("quarantine entry is unavailable: {}", path.display()))?;
            if !canonical_path.starts_with(&canonical_root) {
                bail!(
                    "refusing to prune quarantine entry outside {}: {}",
                    canonical_root.display(),
                    canonical_path.display()
                );
            }
            let metadata = fs::symlink_metadata(&canonical_path)?;
            if metadata.file_type().is_symlink() {
                bail!(
                    "refusing to prune reparse-point quarantine entry: {}",
                    canonical_path.display()
                );
            }
            fs::remove_file(&canonical_path)
                .with_context(|| format!("failed to remove {}", canonical_path.display()))?;
        }
        database.remove_quarantine_record(&sha256)?;
        removed += 1;
    }
    Ok(removed)
}

pub fn restore_quarantine(
    database: &Database,
    config: &Config,
    sha256: &str,
    destination: &Path,
) -> Result<()> {
    let source = find_quarantine_path(database, sha256)?
        .with_context(|| format!("no quarantine record for {sha256}"))?;
    if destination.exists() {
        bail!(
            "restore destination already exists: {}",
            destination.display()
        );
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let fresh = capture(&source, config).context(
        "failed to verify quarantined content before restoration; the file was not moved",
    )?;
    if fresh.sha256.as_deref() != Some(sha256) {
        bail!("quarantined content no longer matches its recorded SHA-256; restore cancelled");
    }
    fs::rename(&source, destination)?;
    restore_destination_acl(destination, config)?;
    database.remove_quarantine_record(sha256)?;
    Ok(())
}

fn find_quarantine_path(database: &Database, _sha256: &str) -> Result<Option<PathBuf>> {
    // The lookup is added through a narrow database method below once the
    // connection implementation is compiled.
    database.quarantine_path(_sha256)
}

fn quarantine_file_name(source: &Path, sha256: &str, suffix: u32) -> String {
    let original = source
        .file_name()
        .map(|value| value.to_string_lossy())
        .unwrap_or_else(|| "download.bin".into());
    let mut sanitized: String = original
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
            {
                '_'
            } else {
                character
            }
        })
        .take(180)
        .collect();
    sanitized = sanitized.trim_end_matches([' ', '.']).to_string();
    if sanitized.is_empty() {
        sanitized = "download.bin".into();
    }
    let hash_prefix = &sha256[..sha256.len().min(12)];
    let collision = if suffix == 0 {
        String::new()
    } else {
        format!("-{suffix}")
    };
    format!("{sanitized}.{hash_prefix}{collision}.quarantined")
}

fn allowlisted(report: &AnalysisReportV1, config: &Config) -> bool {
    let signer = report
        .certificates
        .iter()
        .find(|certificate| certificate.role == crate::report::CertificateRole::Leaf)
        .map(|certificate| certificate.sha256_fingerprint.as_str());
    config.policy.allowlist.iter().any(|entry| {
        let origin_match = report
            .origin
            .source_url
            .as_deref()
            .or(report.origin.final_url.as_deref())
            .is_some_and(|url| origin_matches(url, &entry.origin, entry.path_prefix.as_deref()));
        let signer_match = entry
            .signer_sha256
            .as_deref()
            .zip(signer)
            .is_some_and(|(expected, actual)| expected.eq_ignore_ascii_case(actual));
        origin_match && (entry.signer_sha256.is_none() || signer_match)
    })
}

fn origin_matches(url: &str, expected: &str, path_prefix: Option<&str>) -> bool {
    let Ok(actual) = url::Url::parse(url) else {
        return false;
    };
    let Ok(expected) = url::Url::parse(expected) else {
        return false;
    };
    if actual.scheme() != expected.scheme()
        || actual.host_str() != expected.host_str()
        || actual.port_or_known_default() != expected.port_or_known_default()
    {
        return false;
    }
    path_prefix.is_none_or(|prefix| actual.path().starts_with(prefix))
}

#[cfg(windows)]
fn deny_execute_acl(path: &Path) -> Result<()> {
    let user = std::env::var("USERNAME").context("USERNAME is unavailable")?;
    let status = Command::new("icacls.exe")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:(R,W,D)"))
        .status()
        .context("failed to run icacls for quarantine ACL")?;
    if !status.success() {
        bail!("icacls failed to set quarantine ACL");
    }
    Ok(())
}

#[cfg(not(windows))]
fn deny_execute_acl(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn allow_execute_acl(path: &Path) -> Result<()> {
    let user = std::env::var("USERNAME").context("USERNAME is unavailable")?;
    let status = Command::new("icacls.exe")
        .arg(path)
        .arg("/grant")
        .arg(format!("{user}:(RX)"))
        .status()
        .context("failed to run icacls while restoring quarantine")?;
    if !status.success() {
        bail!("quarantine file was restored but its execute ACL could not be restored");
    }
    Ok(())
}

fn restore_destination_acl(path: &Path, config: &Config) -> Result<()> {
    if config.security.block_execution_in_download_dir && path_is_under(path, &config.download_dir)
    {
        deny_execute_acl(path)
    } else {
        allow_execute_acl(path)
    }
}

fn path_is_under(path: &Path, directory: &Path) -> bool {
    let path = normalize_path(&path.to_string_lossy());
    let directory = normalize_path(&directory.to_string_lossy())
        .trim_end_matches('\\')
        .to_string();
    path.starts_with(&(directory + "\\"))
}

#[cfg(not(windows))]
fn allow_execute_acl(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn sort_categories(config: &Config) -> Vec<(String, String)> {
    config
        .policy
        .signer_categories
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub fn benchmark_normalization(bytes: u64) -> f64 {
    bytes as f64 / GIB as f64
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::report::{AnalysisReportV1, FileEvidence, ReputationEvidence, VtBatch};

    #[test]
    fn vt_malicious_is_terminal() {
        let mut report = AnalysisReportV1::new(FileEvidence::default());
        report.reputation.push(ReputationEvidence {
            sha256: "a".repeat(64),
            state: ReputationState::Malicious,
            vt_batch: Some(VtBatch::PreChild),
            used_by_batch: vec![VtBatch::PreChild],
            detections: Some(12),
            engines_total: Some(70),
            checked_at: Some(Utc::now()),
            signature_info: Vec::new(),
            detail: None,
        });
        let config = Config::default();
        evaluate(&mut report, &config);
        assert_eq!(report.verdict, Verdict::Malicious);
        assert_eq!(report.policy.action, PolicyAction::Quarantine);
        assert_ne!(report.report_id, Uuid::nil());
    }

    #[test]
    fn quarantine_name_is_searchable_and_not_a_path() {
        let name = quarantine_file_name(
            Path::new(r"C:\Users\example\Downloads\setup.exe"),
            &"a".repeat(64),
            0,
        );
        assert_eq!(name, "setup.exe.aaaaaaaaaaaa.quarantined");
        assert!(!name.contains(['/', '\\']));
    }

    #[test]
    fn verified_removal_requires_the_reviewed_hash() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("sample.bin");
        fs::write(&source, b"reviewed bytes").unwrap();
        let config = Config {
            download_dir: directory.path().to_path_buf(),
            ..Config::default()
        };
        let captured = capture(&source, &config).unwrap();
        let mut report = AnalysisReportV1::new(captured.file);
        report.source_path = Some(source.clone());
        report.file.sha256 = Some("0".repeat(64));

        let error = remove_verified(&report, &config).unwrap_err();
        assert!(error.to_string().contains("source changed"));
        assert!(source.exists());
    }

    #[test]
    fn verified_removal_deletes_matching_content() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("sample.bin");
        fs::write(&source, b"reviewed bytes").unwrap();
        let config = Config {
            download_dir: directory.path().to_path_buf(),
            ..Config::default()
        };
        let captured = capture(&source, &config).unwrap();
        let mut report = AnalysisReportV1::new(captured.file);
        report.source_path = Some(source.clone());

        remove_verified(&report, &config).unwrap();
        assert!(!source.exists());
    }

    #[test]
    fn protected_destination_detection_is_case_insensitive_and_direct_child_safe() {
        assert!(path_is_under(
            Path::new(r"c:\users\me\downloads\SETUP.EXE"),
            Path::new(r"C:\Users\Me\Downloads")
        ));
        assert!(!path_is_under(
            Path::new(r"C:\Users\Me\Downloads-old\setup.exe"),
            Path::new(r"C:\Users\Me\Downloads")
        ));
    }
}
