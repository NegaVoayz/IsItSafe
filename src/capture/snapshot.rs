#[allow(clippy::result_large_err)]
pub fn capture(path: &Path, config: &Config) -> Result<CapturedFile, CaptureError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        let mut file = file_evidence(path, &metadata);
        file.is_reparse_point = true;
        return Err(CaptureError::LockUnavailable {
            file,
            lock: LockAcquisitionEvidence::default(),
            outcome: LockAcquisitionOutcome::LockNotAvailable,
            detail: "reparse points and symbolic links are not followed".into(),
        });
    }
    let pre_size = metadata.len();
    let pre_modified = metadata.modified().ok();
    let timeout = Duration::from_millis(config.limits.lock_acquisition_timeout_ms);
    let backoff = Duration::from_millis(config.limits.lock_acquisition_retry_backoff_ms);
    let started = Instant::now();
    let mut attempts = 0u32;

    loop {
        attempts = attempts.saturating_add(1);
        match open_write_ready(path) {
            Ok(mut handle) => {
                let locked_meta = handle.metadata()?;
                let same_size = locked_meta.len() == pre_size;
                let same_time = match (pre_modified, locked_meta.modified().ok()) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                };
                if !same_size || !same_time {
                    drop(handle);
                    if started.elapsed() >= timeout {
                        let mut file = file_evidence(path, &metadata);
                        file.size = locked_meta.len();
                        return Err(CaptureError::LockTimeout {
                            file,
                            lock: LockAcquisitionEvidence {
                                attempts,
                                wait_ms: started.elapsed().as_millis() as u64,
                                outcome: LockAcquisitionOutcome::Timeout,
                                pre_lock_size: Some(pre_size),
                                locked_size: Some(locked_meta.len()),
                                final_size: Some(locked_meta.len()),
                                changed_inside_lock: true,
                            },
                        });
                    }
                    thread::sleep(backoff);
                    continue;
                }

                let identity = file_identity(&handle);
                let initial_meta = handle.metadata()?;
                let initial_size = initial_meta.len();
                let initial_modified = initial_meta.modified().ok();
                let depth = select_depth(initial_size, config);
                let mut head = vec![0; HEAD_BYTES.min(initial_size as usize)];
                read_exact_at_start(&mut handle, &mut head)?;

                let (snapshot, digest) = if depth == CaptureDepth::Deep {
                    let mut bytes = Vec::with_capacity(initial_size as usize);
                    handle.seek(SeekFrom::Start(0))?;
                    handle.read_to_end(&mut bytes)?;
                    let digest = sha256(&bytes);
                    (Some(bytes), digest)
                } else {
                    handle.seek(SeekFrom::Start(0))?;
                    let mut hasher = Sha256::new();
                    let mut buffer = vec![0u8; 1024 * 1024];
                    loop {
                        let read = handle.read(&mut buffer)?;
                        if read == 0 {
                            break;
                        }
                        hasher.update(&buffer[..read]);
                    }
                    (None, hex::encode(hasher.finalize()))
                };

                let tail_len = TAIL_BYTES.min(initial_size as usize);
                let mut tail = vec![0; tail_len];
                if tail_len > 0 {
                    handle.seek(SeekFrom::End(-(tail_len as i64)))?;
                    read_exact_len(&mut handle, &mut tail)?;
                }

                let final_meta = handle.metadata()?;
                let final_modified = final_meta.modified().ok();
                let changed =
                    final_meta.len() != initial_size || final_modified != initial_modified;
                let outcome = if changed {
                    LockAcquisitionOutcome::ReadOnlyContent
                } else {
                    LockAcquisitionOutcome::Acquired
                };
                let lock = LockAcquisitionEvidence {
                    attempts,
                    wait_ms: started.elapsed().as_millis() as u64,
                    outcome,
                    pre_lock_size: Some(pre_size),
                    locked_size: Some(initial_size),
                    final_size: Some(final_meta.len()),
                    changed_inside_lock: changed,
                };
                drop(handle);

                let file = FileEvidence {
                    display_path: safe_display_path(path),
                    full_path_redacted: redact_path(path),
                    extension: path
                        .extension()
                        .and_then(|v| v.to_str())
                        .map(|v| v.to_ascii_lowercase()),
                    size: initial_size,
                    modified_at: datetime(initial_modified),
                    sha256: Some(digest.clone()),
                    volume_identity: identity.as_ref().map(|v| v.volume.clone()),
                    file_id: identity.as_ref().map(|v| v.file_id.clone()),
                    is_reparse_point: false,
                };

                if changed {
                    return Err(CaptureError::ChangedDuringRead { file, lock });
                }

                let motw = match read_motw_with_retry(path, config, &identity) {
                    Ok(value) => value,
                    Err(error) if error.to_string().contains("file identity changed") => {
                        return Err(CaptureError::ChangedDuringRead { file, lock });
                    }
                    Err(error) => return Err(CaptureError::Io(error)),
                };
                let streams = list_alternate_streams(path).unwrap_or_default();
                if identity_changed(path, &identity) {
                    return Err(CaptureError::ChangedDuringRead { file, lock });
                }
                let mut boundaries = Vec::new();
                if motw.state == MotwState::PresentEmpty {
                    boundaries.push(Boundary {
                        kind: BoundaryKind::MotwEmptyAfterRetry,
                        detail: "Zone.Identifier remained empty until timeout".into(),
                    });
                }
                if depth == CaptureDepth::Limited {
                    boundaries.push(Boundary {
                        kind: BoundaryKind::Limited,
                        detail: format!(
                            "file exceeds snapshot_max_bytes ({})",
                            config.limits.snapshot_max_bytes
                        ),
                    });
                }
                if depth == CaptureDepth::BasicCheckOnly {
                    boundaries.push(Boundary {
                        kind: BoundaryKind::BasicCheckOnly,
                        detail: format!(
                            "file exceeds basic_check_threshold_bytes ({})",
                            config.limits.basic_check_threshold_bytes
                        ),
                    });
                }
                let thresholds = threshold_decisions(initial_size, depth, config);
                return Ok(CapturedFile {
                    path: path.to_path_buf(),
                    file,
                    sha256: Some(digest),
                    head,
                    tail,
                    snapshot,
                    lock,
                    motw,
                    alternate_streams: streams,
                    thresholds,
                    depth,
                    boundaries,
                });
            }
            Err(error) if is_sharing_violation(&error) => {
                if started.elapsed() >= timeout {
                    let file = file_evidence(path, &metadata);
                    return Err(CaptureError::LockTimeout {
                        file,
                        lock: LockAcquisitionEvidence {
                            attempts,
                            wait_ms: started.elapsed().as_millis() as u64,
                            outcome: LockAcquisitionOutcome::Timeout,
                            pre_lock_size: Some(pre_size),
                            locked_size: None,
                            final_size: None,
                            changed_inside_lock: false,
                        },
                    });
                }
                thread::sleep(backoff);
            }
            Err(error) if is_access_denied(&error) => {
                let file = file_evidence(path, &metadata);
                return Err(CaptureError::LockUnavailable {
                    file,
                    lock: LockAcquisitionEvidence {
                        attempts,
                        wait_ms: started.elapsed().as_millis() as u64,
                        outcome: LockAcquisitionOutcome::LockNotAvailable,
                        pre_lock_size: Some(pre_size),
                        locked_size: None,
                        final_size: None,
                        changed_inside_lock: false,
                    },
                    outcome: LockAcquisitionOutcome::LockNotAvailable,
                    detail: error.to_string(),
                });
            }
            Err(error) => return Err(CaptureError::Io(error)),
        }
    }
}

/// Permanently deletes `path` only if complete contents read through the
/// exclusive readiness handle still hash to `expected_sha256`. On Windows the
/// delete disposition is set on that same handle, eliminating the
/// verify-path-then-delete-path race.
pub fn remove_if_hash_matches(path: &Path, config: &Config, expected_sha256: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        bail!("refusing to remove a reparse point or symbolic link");
    }
    let timeout = Duration::from_millis(config.limits.lock_acquisition_timeout_ms);
    let backoff = Duration::from_millis(config.limits.lock_acquisition_retry_backoff_ms);
    let started = Instant::now();
    loop {
        match open_write_ready_for_delete(path) {
            Ok(mut handle) => {
                handle.seek(SeekFrom::Start(0))?;
                let mut hasher = Sha256::new();
                let mut buffer = vec![0u8; 1024 * 1024];
                loop {
                    let read = handle.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
                let digest = hex::encode(hasher.finalize());
                if digest != expected_sha256 {
                    bail!("source changed after analysis; removal cancelled");
                }
                set_delete_on_close(&handle)?;
                drop(handle);
                return Ok(());
            }
            Err(error) if is_sharing_violation(&error) => {
                if started.elapsed() >= timeout {
                    bail!("exclusive removal lock timed out");
                }
                thread::sleep(backoff);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to open {} for removal", path.display()));
            }
        }
    }
}

pub fn select_depth(size: u64, config: &Config) -> CaptureDepth {
    if size > config.limits.basic_check_threshold_bytes {
        CaptureDepth::BasicCheckOnly
    } else if size > config.limits.snapshot_max_bytes {
        CaptureDepth::Limited
    } else {
        CaptureDepth::Deep
    }
}

fn threshold_decisions(size: u64, depth: CaptureDepth, config: &Config) -> ThresholdDecisions {
    let mut triggered = Vec::new();
    if size > config.limits.snapshot_max_bytes {
        triggered.push("snapshot_max_bytes".into());
    }
    if size > config.limits.basic_check_threshold_bytes {
        triggered.push("basic_check_threshold_bytes".into());
    }
    ThresholdDecisions {
        snapshot_max_bytes: config.limits.snapshot_max_bytes,
        basic_check_threshold_bytes: config.limits.basic_check_threshold_bytes,
        deep_analysis_eligible: depth == CaptureDepth::Deep,
        basic_check_only: depth == CaptureDepth::BasicCheckOnly,
        limited: depth == CaptureDepth::Limited,
        triggered,
    }
}

