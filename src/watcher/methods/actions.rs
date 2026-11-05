impl Watcher {
    fn publish(&self, report: &AnalysisReportV1) -> Result<()> {
        let verdict = serde_json::to_string(&report.verdict)?
            .trim_matches('"')
            .to_string();
        let state = match report.verdict {
            _ if report.policy.action == PolicyAction::AwaitUserDecision => "awaiting_user",
            Verdict::Incomplete => "incomplete",
            Verdict::Unverified => "unverified",
            _ if report.policy.user_decision == Some(UserDecision::Remove) => "removed",
            _ => "complete",
        };
        self.database.upsert_observation(&Observation {
            path: report
                .source_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_else(|| report.file.display_path.clone()),
            volume_identity: report.file.volume_identity.clone(),
            file_id: report.file.file_id.clone(),
            size: report.file.size,
            modified_ns: report
                .file
                .modified_at
                .map(|time| time.timestamp_nanos_opt().unwrap_or_default()),
            sha256: report.file.sha256.clone(),
            state: state.into(),
            updated_at: Utc::now(),
        })?;
        self.database.store_report(report)?;

        let json = serde_json::to_string(report)?;
        let day = Utc::now().format("%Y-%m-%d");
        let report_path = self.paths.reports_dir.join(format!("{day}.jsonl"));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&report_path)?;
        writeln!(file, "{json}")?;
        println!("{}", human_report(report));
        tracing::info!(
            report_id = %report.report_id,
            verdict = verdict,
            file = %report.file.display_path,
            "download analysis completed"
        );
        Ok(())
    }

    fn capture_error_report(
        &self,
        path: &Path,
        error: CaptureError,
        _config: &Config,
    ) -> Result<AnalysisReportV1> {
        let (file, lock, kind, detail) = match error {
            CaptureError::LockTimeout { file, lock } => (
                file,
                lock,
                BoundaryKind::LockAcquisitionTimeout,
                "exclusive readiness lock timed out".to_string(),
            ),
            CaptureError::LockUnavailable {
                file,
                lock,
                outcome,
                detail,
            } => (
                file,
                lock,
                if outcome == LockAcquisitionOutcome::ReadOnlyContent {
                    BoundaryKind::ReadOnlyContent
                } else {
                    BoundaryKind::LockNotAvailable
                },
                detail,
            ),
            CaptureError::ChangedDuringRead { file, lock } => (
                file,
                lock,
                BoundaryKind::FileChangedDuringRead,
                "file changed during capture".into(),
            ),
            CaptureError::Io(error) => (
                FileEvidence {
                    display_path: escape_controls(&path.display().to_string()),
                    full_path_redacted: path
                        .file_name()
                        .map(|value| escape_controls(&value.to_string_lossy())),
                    extension: path
                        .extension()
                        .map(|value| value.to_string_lossy().to_ascii_lowercase()),
                    ..FileEvidence::default()
                },
                LockAcquisitionEvidence::default(),
                BoundaryKind::LockNotAvailable,
                error.to_string(),
            ),
        };
        let mut report = AnalysisReportV1::new(file);
        report.source_path = Some(path.to_path_buf());
        report.lock_acquisition = lock;
        report.boundaries.push(Boundary { kind, detail });
        report.origin = origin::correlate(&self.database, path, None, &self.config)?;
        report.verdict = Verdict::Incomplete;
        report.policy.action = PolicyAction::RequireReview;
        Ok(report)
    }

}
