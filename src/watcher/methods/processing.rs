impl Watcher {
    pub fn reconcile(&self) -> Result<usize> {
        let mut queued = 0;
        for entry in WalkDir::new(&self.config.download_dir)
            .follow_links(false)
            .max_depth(1)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if is_reparse(path) {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let path_string = path.to_string_lossy().into_owned();
            let previous = self.database.observation(&path_string)?;
            let modified = metadata.modified().ok();
            if self.is_temp_path(path) {
                let old_enough = modified.is_some_and(|time| {
                    time.elapsed().unwrap_or_default()
                        >= Duration::from_millis(self.config.events.temp_rename_grace_ms)
                });
                let already_reported = previous.as_ref().is_some_and(|previous| {
                    previous.state == "temp_only"
                        && previous.size == metadata.len()
                        && previous.modified_ns == modified.and_then(system_time_ns)
                });
                if old_enough && !already_reported {
                    self.record_temp_only(path)?;
                    queued += 1;
                }
                continue;
            }
            let unchanged = previous.as_ref().is_some_and(|previous| {
                let base_unchanged = previous.size == metadata.len()
                    && previous.modified_ns == modified.and_then(system_time_ns);
                (matches!(previous.state.as_str(), "complete" | "awaiting_user")
                    || (previous.state == "unverified"
                        && Utc::now().signed_duration_since(previous.updated_at)
                            < chrono::Duration::hours(1)))
                    && base_unchanged
            });
            if !unchanged {
                self.database.enqueue_job(&path_string)?;
                queued += 1;
            }
        }
        tracing::info!(queued, "download directory reconciled");
        Ok(queued)
    }

    fn enqueue_pending_work(&self, work_tx: &Sender<PathBuf>) -> Result<()> {
        for (_, path) in self.database.pending_jobs(10_000)? {
            let _ = work_tx.send(PathBuf::from(path));
        }
        Ok(())
    }

    pub fn process_path(&self, path: &Path) -> Result<AnalysisReportV1> {
        self.process_path_with_prompt(path, true)
    }

    pub fn process_path_with_prompt(
        &self,
        path: &Path,
        interactive: bool,
    ) -> Result<AnalysisReportV1> {
        self.process_path_optional(path, interactive)?
            .context("file was removed before analysis")
    }

    fn process_path_optional(
        &self,
        path: &Path,
        interactive: bool,
    ) -> Result<Option<AnalysisReportV1>> {
        if !path.exists() {
            return Ok(None);
        }
        let captured = match capture(path, &self.config) {
            Ok(value) => value,
            Err(CaptureError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => {
                let report = self.capture_error_report(path, error, &self.config)?;
                self.publish(&report)?;
                return Ok(Some(report));
            }
        };
        let mut report = self.analyze_captured(captured)?;
        report.source_path = Some(path.to_path_buf());
        evaluate(&mut report, &self.config);
        if !self.notify_or_apply_fallback(&mut report, interactive)? {
            self.publish(&report)?;
        }
        Ok(Some(report))
    }

    fn notify_or_apply_fallback(
        &self,
        report: &mut AnalysisReportV1,
        interactive: bool,
    ) -> Result<bool> {
        let notify = interactive
            && self.config.interaction.enabled
            && (report.policy.quarantine_requested || should_notify(report.verdict));
        if !notify {
            self.apply_configured_action(report)?;
            return Ok(false);
        }

        let fallback_action = report.policy.action;
        let fallback_quarantine_requested = report.policy.quarantine_requested;
        report.policy.action = PolicyAction::AwaitUserDecision;
        report.policy.quarantine_requested = false;
        report
            .policy
            .reasons
            .push("Waiting for a Keep, Quarantine, or Remove notification action".into());
        self.publish(report)?;
        if let Err(error) = show_review_notification(report) {
            tracing::warn!(%error, "could not show Windows notification; applying policy fallback");
            report.policy.reasons.pop();
            report.policy.action = fallback_action;
            report.policy.quarantine_requested = fallback_quarantine_requested;
            self.apply_configured_action(report)?;
            report.policy.reasons.push(
                "Windows notification delivery failed; the configured policy fallback was applied"
                    .into(),
            );
            return Ok(false);
        }
        Ok(true)
    }

    fn apply_configured_action(&self, report: &mut AnalysisReportV1) -> Result<()> {
        if report.policy.quarantine_requested {
            self.quarantine_or_record_failure(report)?;
        }
        Ok(())
    }

    fn quarantine_or_record_failure(&self, report: &mut AnalysisReportV1) -> Result<()> {
        match apply_quarantine(
            report,
            &self.config,
            &self.database,
            self.config.quarantine_dir(),
        ) {
            Ok(Some(destination)) => {
                report.policy.quarantine_path = Some(destination.to_string_lossy().into_owned());
            }
            Ok(None) => {}
            Err(error) => {
                report.add_boundary(BoundaryKind::QuarantineFailed, error.to_string());
                report.facts.push(crate::report::Evidence {
                    id: "policy:quarantine-failed".into(),
                    category: "policy".into(),
                    severity: Severity::High,
                    summary: "The configured quarantine action failed".into(),
                    detail: Some(error.to_string()),
                    provenance: "parent quarantine worker".into(),
                    confidence: crate::report::Confidence::Structural,
                });
                report.verdict = Verdict::Incomplete;
                report.policy.action = PolicyAction::RequireReview;
                report.policy.quarantine_requested = false;
                report
                    .policy
                    .reasons
                    .push("Quarantine failed; the file requires manual review".into());
            }
        }
        Ok(())
    }

}
