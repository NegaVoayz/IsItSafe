impl Watcher {
    fn handle_event(
        &self,
        event: Event,
        debounce: &mut HashMap<PathBuf, DebounceEntry>,
        work_tx: &Sender<PathBuf>,
        debounce_window: Duration,
    ) -> Result<()> {
        if matches!(event.kind, EventKind::Access(_)) {
            return Ok(());
        }
        if matches!(event.kind, EventKind::Remove(_)) {
            return Ok(());
        }
        let explicit_rescan = event.need_rescan() || event.paths.is_empty();
        if explicit_rescan {
            self.reconcile()?;
            self.enqueue_pending_work(work_tx)?;
            return Ok(());
        }
        if matches!(event.kind, EventKind::Other | EventKind::Any) {
            return Ok(());
        }
        if matches!(
            event.kind,
            EventKind::Modify(ModifyKind::Name(RenameMode::Both))
        ) && event.paths.len() > 1
        {
            for path in &event.paths {
                if path.exists() {
                    self.schedule_path(path, event.kind, debounce, work_tx, debounce_window)?;
                }
            }
            return Ok(());
        }
        for path in &event.paths {
            if path.exists() {
                self.schedule_path(path, event.kind, debounce, work_tx, debounce_window)?;
            }
        }
        Ok(())
    }

    fn schedule_path(
        &self,
        path: &Path,
        _kind: EventKind,
        debounce: &mut HashMap<PathBuf, DebounceEntry>,
        work_tx: &Sender<PathBuf>,
        debounce_window: Duration,
    ) -> Result<()> {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!(".{}", value.to_ascii_lowercase()))
            .unwrap_or_default();
        let is_temp = self
            .config
            .events
            .temp_extensions
            .iter()
            .any(|temp| temp.eq_ignore_ascii_case(&extension));
        if is_temp {
            let now = Instant::now();
            debounce
                .entry(path.to_path_buf())
                .and_modify(|entry| {
                    entry.last_event = now;
                    entry.temp_started.get_or_insert(now);
                })
                .or_insert(DebounceEntry {
                    last_event: now,
                    temp_started: Some(now),
                });
            if let Some(stem) = strip_temp_extension(path)
                && stem.exists()
            {
                debounce.insert(
                    stem,
                    DebounceEntry {
                        last_event: now,
                        temp_started: None,
                    },
                );
            }
            return Ok(());
        }
        debounce.retain(|candidate, entry| {
            entry.temp_started.is_none() || strip_temp_extension(candidate).as_deref() != Some(path)
        });
        let entry = debounce.entry(path.to_path_buf()).or_insert(DebounceEntry {
            last_event: Instant::now(),
            temp_started: None,
        });
        entry.last_event = Instant::now();
        entry.temp_started = None;
        // A rename event is already separated from prior temporary writes by
        // the debounce collector. Use the sender directly only after a final
        // path has remained stable in the main loop.
        let _ = (work_tx, debounce_window);
        Ok(())
    }

    fn is_temp_path(&self, path: &Path) -> bool {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!(".{}", value.to_ascii_lowercase()))
            .unwrap_or_default();
        self.config
            .events
            .temp_extensions
            .iter()
            .any(|temp| temp.eq_ignore_ascii_case(&extension))
    }

    fn record_temp_only(&self, path: &Path) -> Result<()> {
        let metadata = fs::metadata(path).ok();
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: escape_controls(&path.display().to_string()),
            full_path_redacted: path
                .file_name()
                .map(|value| escape_controls(&value.to_string_lossy())),
            extension: path
                .extension()
                .map(|value| value.to_string_lossy().to_ascii_lowercase()),
            size: metadata.as_ref().map_or(0, fs::Metadata::len),
            ..FileEvidence::default()
        });
        report.source_path = Some(path.to_path_buf());
        report.add_boundary(
            BoundaryKind::TempOnly,
            "temporary download path was not renamed into a final file before grace expiry",
        );
        report.verdict = Verdict::Incomplete;
        report.policy.action = PolicyAction::RequireReview;
        self.publish(&report)?;
        self.database.upsert_observation(&Observation {
            path: path.to_string_lossy().into_owned(),
            volume_identity: None,
            file_id: None,
            size: metadata.as_ref().map_or(0, fs::Metadata::len),
            modified_ns: metadata
                .as_ref()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(system_time_ns),
            sha256: None,
            state: "temp_only".into(),
            updated_at: Utc::now(),
        })
    }

    fn recover_state(&self) -> Result<()> {
        if let Some(backup) = &self.database.recovered_from {
            tracing::warn!(
                backup = %backup.display(),
                "corrupt state database was preserved and rebuilt"
            );
        }
        let requeued = self.database.requeue_interrupted_jobs()?;
        tracing::info!(requeued, "interrupted jobs requeued");
        self.database.checkpoint(false)?;
        Ok(())
    }

    fn prune_report_storage(&self) -> Result<()> {
        let retention = Duration::from_secs(
            self.config
                .reports
                .retention_days
                .saturating_mul(24 * 60 * 60),
        );
        let _ = self.database.prune_reports(retention)?;
        let cutoff = std::time::SystemTime::now()
            .checked_sub(retention)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mut files = Vec::new();
        for entry in fs::read_dir(&self.paths.reports_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
                continue;
            }
            let metadata = entry.metadata()?;
            if metadata.modified().is_ok_and(|modified| modified < cutoff) {
                let _ = fs::remove_file(&path);
            } else {
                files.push((
                    metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    metadata.len(),
                    path,
                ));
            }
        }
        files.sort_by_key(|(modified, _, _)| *modified);
        let mut total: u64 = files.iter().map(|(_, size, _)| *size).sum();
        for (_, size, path) in files {
            if total <= self.config.reports.max_total_bytes {
                break;
            }
            fs::remove_file(&path)?;
            total = total.saturating_sub(size);
        }
        Ok(())
    }
}
