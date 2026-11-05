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

