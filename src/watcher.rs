use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use chrono::Utc;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};
use walkdir::WalkDir;

use crate::analysis::ChildAnalysis;
use crate::capture::{CaptureDepth, CaptureError, CapturedFile, capture, escape_controls};
use crate::config::{AppPaths, Config};
use crate::db::{Database, Observation};
use crate::detect::sniff;
use crate::interaction::{should_notify, show_review_notification};
use crate::origin;
use crate::policy::{apply_quarantine, evaluate};
use crate::report::{
    AnalysisReportV1, Boundary, BoundaryKind, FileEvidence, LockAcquisitionEvidence,
    LockAcquisitionOutcome, PolicyAction, PublisherReputation, ReputationState, Severity,
    UserDecision, Verdict, VtBatch,
};
use crate::reputation::{ReputationManager, post_child_candidates, pre_child_triggers};
use crate::revocation;
use crate::rules;
use crate::sandbox::run_sandboxed;

pub struct Watcher {
    config: Arc<Config>,
    database: Arc<Database>,
    paths: Arc<AppPaths>,
}

struct DebounceEntry {
    last_event: Instant,
    temp_started: Option<Instant>,
}

impl Watcher {
    pub fn new(config: Config, database: Database, paths: AppPaths) -> Self {
        Self {
            config: Arc::new(config),
            database: Arc::new(database),
            paths: Arc::new(paths),
        }
    }

    pub fn run(&self) -> Result<()> {
        self.run_with_prompt(true)
    }

    pub fn run_with_prompt(&self, interactive: bool) -> Result<()> {
        self.recover_state()?;
        self.prune_report_storage()?;
        let (event_tx, event_rx) = mpsc::channel();
        let mut native_watcher: RecommendedWatcher =
            notify::recommended_watcher(move |event: notify::Result<Event>| {
                let _ = event_tx.send(event);
            })?;
        native_watcher.watch(&self.config.download_dir, RecursiveMode::NonRecursive)?;

        let (work_tx, work_rx) = mpsc::channel::<PathBuf>();
        let worker = {
            let config = Arc::clone(&self.config);
            let database = Arc::clone(&self.database);
            let paths = Arc::clone(&self.paths);
            thread::spawn(move || {
                while let Ok(path) = work_rx.recv() {
                    let watcher = Watcher {
                        config: Arc::clone(&config),
                        database: Arc::clone(&database),
                        paths: Arc::clone(&paths),
                    };
                    let path_string = path.to_string_lossy().into_owned();
                    let _ = watcher.database.mark_path_running(&path_string);
                    if let Err(error) = watcher.process_path_optional(&path, interactive) {
                        let _ = watcher
                            .database
                            .mark_path_finished(&path_string, Some(&error.to_string()));
                        tracing::error!(
                            path = %escape_controls(&path.display().to_string()),
                            error = %error,
                            "analysis job failed"
                        );
                    } else {
                        let _ = watcher.database.mark_path_finished(&path_string, None);
                    }
                }
            })
        };

        self.reconcile()?;
        self.enqueue_pending_work(&work_tx)?;

        let mut debounce: HashMap<PathBuf, DebounceEntry> = HashMap::new();
        let debounce_window = Duration::from_millis(self.config.events.debounce_ms);
        let temp_grace = Duration::from_millis(self.config.events.temp_rename_grace_ms);
        let reconcile_interval =
            Duration::from_millis(self.config.events.reconciliation_interval_ms);
        let mut last_reconcile = Instant::now();
        let mut last_checkpoint = Instant::now();
        let mut last_integrity = Instant::now();
        loop {
            match event_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Ok(event)) => {
                    self.handle_event(event, &mut debounce, &work_tx, debounce_window)?
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "filesystem watcher error; scheduling reconciliation");
                    self.reconcile()?;
                    self.enqueue_pending_work(&work_tx)?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            let now = Instant::now();
            let ready: Vec<PathBuf> = debounce
                .iter()
                .filter_map(|(path, entry)| {
                    if entry.temp_started.is_none()
                        && now.duration_since(entry.last_event) >= debounce_window
                    {
                        Some(path.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for path in ready {
                debounce.remove(&path);
                let _ = work_tx.send(path);
            }
            let expired_temps: Vec<PathBuf> = debounce
                .iter()
                .filter(|(_, entry)| {
                    entry
                        .temp_started
                        .is_some_and(|started| now.duration_since(started) >= temp_grace)
                })
                .map(|(path, _)| path.clone())
                .collect();
            for path in expired_temps {
                debounce.remove(&path);
                if strip_temp_extension(&path).is_some_and(|final_path| final_path.exists()) {
                    continue;
                }
                self.record_temp_only(&path)?;
            }
            if last_reconcile.elapsed() >= reconcile_interval {
                self.reconcile()?;
                self.enqueue_pending_work(&work_tx)?;
                last_reconcile = Instant::now();
            }
            if last_checkpoint.elapsed() >= Duration::from_secs(60 * 60) {
                if let Err(error) = self.database.checkpoint(false) {
                    tracing::warn!(%error, "hourly SQLite checkpoint failed");
                }
                let wal_path = self.database.path.with_file_name("state.db-wal");
                if fs::metadata(&wal_path).is_ok_and(|metadata| metadata.len() > 256 * 1024 * 1024)
                    && let Err(error) = self.database.checkpoint(true)
                {
                    tracing::warn!(%error, "SQLite WAL truncation failed");
                }
                last_checkpoint = Instant::now();
            }
            if last_integrity.elapsed() >= Duration::from_secs(24 * 60 * 60) {
                match self.database.integrity_check() {
                    Ok(result) if result.ok => {}
                    Ok(result) => tracing::error!(
                        detail = %result.detail,
                        "SQLite integrity check failed; restart will preserve and rebuild state"
                    ),
                    Err(error) => tracing::error!(%error, "SQLite integrity check errored"),
                }
                last_integrity = Instant::now();
            }
        }
        drop(work_tx);
        let _ = worker.join();
        Ok(())
    }

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
            &self.paths.quarantine_dir,
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

    fn analyze_captured(&self, captured: CapturedFile) -> Result<AnalysisReportV1> {
        let mut report = AnalysisReportV1::new(captured.file.clone());
        report.source_path = Some(captured.path.clone());
        report.threshold_decisions = captured.thresholds.clone();
        report.lock_acquisition = captured.lock.clone();
        report.motw = captured.motw.clone();
        report.alternate_streams = captured.alternate_streams.clone();
        report.boundaries = captured.boundaries.clone();
        report.origin = origin::correlate(
            &self.database,
            &captured.path,
            captured.sha256.as_deref(),
            &self.config,
        )?;

        let sniff_result = sniff(
            &captured.path,
            &captured.head,
            &captured.tail,
            captured.file.size,
        );
        report.classification = sniff_result.classification.clone();
        report.facts.extend(sniff_result.evidence);
        let pre_triggers = pre_child_triggers(
            &report.classification,
            report.motw.state,
            captured.file.size,
            &report.origin,
            &self.config,
        );
        let reputation = ReputationManager::new(&self.config, &self.database)?;
        if let Some(hash) = &captured.sha256 {
            if !pre_triggers.is_empty() || captured.depth == CaptureDepth::BasicCheckOnly {
                let evidence = reputation.query(hash, VtBatch::PreChild)?;
                reputation.merge_result(&mut report.reputation, evidence);
            } else {
                report.reputation.push(crate::report::ReputationEvidence {
                    sha256: hash.clone(),
                    state: ReputationState::NotQueried,
                    vt_batch: None,
                    used_by_batch: Vec::new(),
                    detections: None,
                    engines_total: None,
                    checked_at: None,
                    signature_info: Vec::new(),
                    detail: Some("no pre-child VirusTotal trigger applied".into()),
                });
            }
        }
        let vt_malicious = report
            .reputation
            .iter()
            .any(|entry| entry.state == ReputationState::Malicious);
        if !vt_malicious
            && captured.depth == CaptureDepth::Deep
            && let Some(snapshot) = &captured.snapshot
        {
            let custom_rules = if self.config.yara.enabled {
                rules::load_active_rules(&self.paths, 16 * 1024 * 1024)?
            } else {
                None
            };
            let sandbox = run_sandboxed(
                &self.config,
                &captured.path,
                snapshot,
                custom_rules.as_deref(),
            )?;
            report.child_execution = Some(sandbox.execution);
            report.boundaries.extend(sandbox.boundaries);
            if let Some(child) = sandbox.analysis {
                self.merge_child(&mut report, child);
            } else if let Some(error) = sandbox.error {
                report.add_boundary(BoundaryKind::ChildCrashed, error);
            }
        }
        self.apply_signer_categories(&mut report);
        revocation::update_revocation(&mut report, &self.config)?;

        if let Some(hash) = &captured.sha256 {
            let mut candidates =
                post_child_candidates(&report.components, report.authenticity.as_ref());
            if report.authenticity.as_ref().is_some_and(|auth| {
                matches!(
                    auth.publisher_reputation,
                    PublisherReputation::RemoteAccess | PublisherReputation::BundlerOrPup
                )
            }) {
                candidates.push(hash.clone());
            }
            candidates.sort();
            candidates.dedup();
            for candidate in candidates {
                let evidence = reputation.query(&candidate, VtBatch::PostChild)?;
                reputation.merge_result(&mut report.reputation, evidence);
            }
        }
        Ok(report)
    }

    fn merge_child(&self, report: &mut AnalysisReportV1, child: ChildAnalysis) {
        if let (Some(execution), Some(proof)) = (
            report.child_execution.as_mut(),
            child.sandbox_proof.as_ref(),
        ) {
            execution.network_capability = if proof.is_app_container {
                crate::report::SandboxCapability::None
            } else {
                crate::report::SandboxCapability::Unknown
            };
            execution.filesystem_capability = if proof.is_app_container {
                crate::report::SandboxCapability::Restricted
            } else {
                crate::report::SandboxCapability::Unknown
            };
            execution
                .sandbox_self_tests
                .insert("network_connect".into(), proof.network_connect);
            execution
                .sandbox_self_tests
                .insert("process_create".into(), proof.process_create);
            if !proof.is_app_container
                || proof.network_connect == crate::report::SandboxSelfTest::Allowed
                || proof.process_create == crate::report::SandboxSelfTest::Allowed
            {
                report.add_boundary(
                    BoundaryKind::SandboxViolation,
                    "analysis child did not satisfy the expected AppContainer/network/process isolation guarantees",
                );
            }
        }
        if !child.classification.formats.is_empty() {
            report.classification = child.classification;
        }
        report.facts.extend(child.facts);
        report.inference.extend(child.inference);
        deduplicate_evidence(&mut report.facts);
        deduplicate_evidence(&mut report.inference);
        report.boundaries.extend(child.boundaries);
        report.components.extend(child.components);
        report.products.extend(child.products);
        deduplicate_products(&mut report.products);
        report.certificates.extend(child.certificates);
        if child.authenticity.is_some() {
            report.authenticity = child.authenticity;
        }
        if child.output_truncated {
            report.add_boundary(
                BoundaryKind::OutputTruncated,
                "child analysis exceeded its output limit",
            );
        }
    }

    fn apply_signer_categories(&self, report: &mut AnalysisReportV1) {
        let Some(authenticity) = report.authenticity.as_mut() else {
            return;
        };
        let leaf = report
            .certificates
            .iter()
            .find(|certificate| certificate.role == crate::report::CertificateRole::Leaf);
        if let Some(leaf) = leaf
            && let Some(category) = self
                .config
                .policy
                .signer_categories
                .get(&leaf.sha256_fingerprint.to_ascii_lowercase())
        {
            authenticity.publisher_reputation = match category.as_str() {
                "trusted" => PublisherReputation::Trusted,
                "remote_access" => PublisherReputation::RemoteAccess,
                "bundler" | "pup" => PublisherReputation::BundlerOrPup,
                "untrusted" => PublisherReputation::Untrusted,
                _ => PublisherReputation::Known,
            };
        }
        let unsigned = report
            .components
            .iter()
            .filter(|component| {
                component.formats.iter().any(|format| format.kind == "pe")
                    && component.signed == Some(false)
            })
            .count() as u32;
        authenticity.unsigned_components = unsigned;
        if unsigned > 0 {
            report.facts.push(crate::report::Evidence {
                id: "authenticode:unsigned-components".into(),
                category: "authenticode".into(),
                severity: Severity::High,
                summary: format!("{unsigned} nested executable component(s) are unsigned"),
                detail: None,
                provenance: "child component inventory".into(),
                confidence: crate::report::Confidence::Structural,
            });
        }
    }

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

fn strip_temp_extension(path: &Path) -> Option<PathBuf> {
    let text = path.to_string_lossy();
    let dot = text.rfind('.')?;
    Some(PathBuf::from(&text[..dot]))
}

fn is_reparse(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & 0x400 != 0
            }
            #[cfg(not(windows))]
            {
                metadata.file_type().is_symlink()
            }
        })
        .unwrap_or(true)
}

fn system_time_ns(value: SystemTime) -> Option<i64> {
    value
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
}

fn human_report(report: &AnalysisReportV1) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "[{}] {}\n",
        serde_json::to_string(&report.verdict)
            .unwrap_or_default()
            .trim_matches('"'),
        report.file.display_path
    ));
    if let Some(hash) = &report.file.sha256 {
        output.push_str(&format!("SHA-256: {hash}\n"));
    }
    output.push_str(&format!(
        "Origin: {}\n",
        serde_json::to_string(&report.origin.state)
            .unwrap_or_default()
            .trim_matches('"')
    ));
    for format in &report.classification.formats {
        output.push_str(&format!("  format: {} @ {}\n", format.kind, format.offset));
    }
    for boundary in &report.boundaries {
        output.push_str(&format!(
            "  boundary: {:?}: {}\n",
            boundary.kind, boundary.detail
        ));
    }
    for evidence in &report.facts {
        if evidence.severity >= Severity::Medium {
            output.push_str(&format!(
                "  {:?}: {}\n",
                evidence.severity, evidence.summary
            ));
        }
    }
    for component in &report.components {
        output.push_str(&format!(
            "  component: {} ({} bytes, {:?})\n",
            component.nesting_path, component.size, component.severity
        ));
    }
    if !report.products.is_empty() {
        output.push_str("Detected software identity (declared by the installer):\n");
        for product in report.products.iter().take(24) {
            let name = product
                .product_name
                .as_deref()
                .unwrap_or("<unnamed product>");
            let manufacturer = product
                .manufacturer
                .as_deref()
                .unwrap_or("unknown manufacturer");
            let version = product
                .product_version
                .as_deref()
                .map(|value| format!(", version {value}"))
                .unwrap_or_default();
            let source = product
                .nesting_path
                .as_deref()
                .unwrap_or(product.source.as_str());
            output.push_str(&format!(
                "  {name} ({manufacturer}{version}) from {source}\n"
            ));
        }
    }
    if let Some(owner) = report
        .authenticity
        .as_ref()
        .and_then(|authenticity| authenticity.publisher_identity.as_deref())
    {
        output.push_str(&format!("Certificate owner: {owner}\n"));
    }
    if !report.components.is_empty() {
        let names = report
            .components
            .iter()
            .take(24)
            .map(|component| component.nesting_path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "Install inventory (embedded/declared; runtime behavior is not guaranteed): {names}\n"
        ));
    }
    output.push_str(&format!(
        "Policy: {:?}; {}\n",
        report.policy.action,
        report.policy.reasons.join("; ")
    ));
    if let Some(decision) = report.policy.user_decision {
        output.push_str(&format!("User decision: {decision:?}\n"));
    }
    if let Some(path) = &report.policy.quarantine_path {
        output.push_str(&format!("Quarantine: {path}\n"));
        if let Some(hash) = &report.file.sha256 {
            output.push_str(&format!(
                "Restore: isitsafe quarantine restore {hash} <destination>\n"
            ));
        }
    }
    if matches!(
        report.verdict,
        Verdict::NoHighRiskFound | Verdict::BasicCheckOnly | Verdict::Limited
    ) {
        output.push_str(&format!("{}\n", report.limitations_notice));
    }
    output
}

fn deduplicate_evidence(evidence: &mut Vec<crate::report::Evidence>) {
    let mut seen = std::collections::HashSet::new();
    evidence.retain(|item| {
        seen.insert((
            item.id.clone(),
            item.category.clone(),
            item.summary.clone(),
            item.detail.clone(),
        ))
    });
}

fn deduplicate_products(products: &mut Vec<crate::report::ProductIdentityEvidence>) {
    let mut seen = std::collections::HashSet::new();
    products.retain(|product| {
        seen.insert((
            product.nesting_path.clone(),
            product.source.clone(),
            product.product_name.clone(),
            product.manufacturer.clone(),
            product.product_version.clone(),
            product.product_code.clone(),
        ))
    });
}

#[cfg(test)]
mod tests {
    use std::fs;

    use notify::event::CreateKind;

    use super::*;
    use crate::config::{ChildConfig, LimitsConfig, MIB};

    fn test_watcher() -> (tempfile::TempDir, Watcher) {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("data");
        let paths = AppPaths {
            config_file: directory.path().join("config.toml"),
            data_dir: data_dir.clone(),
            database: data_dir.join("state.db"),
            reports_dir: data_dir.join("reports"),
            logs_dir: data_dir.join("logs"),
            quarantine_dir: data_dir.join("quarantine"),
            rules_dir: data_dir.join("rules"),
        };
        paths.ensure().unwrap();
        let config = Config {
            download_dir: directory.path().join("downloads"),
            ..Config::default()
        };
        fs::create_dir_all(&config.download_dir).unwrap();
        let database = Database::open(&paths.database).unwrap();
        (directory, Watcher::new(config, database, paths))
    }

    #[test]
    fn final_rename_absorbs_temporary_download_entry() {
        let (directory, watcher) = test_watcher();
        let temp = directory
            .path()
            .join("downloads")
            .join("setup.exe.crdownload");
        let final_path = directory.path().join("downloads").join("setup.exe");
        fs::write(&temp, b"partial").unwrap();
        fs::write(&final_path, b"complete").unwrap();
        let (sender, _receiver) = mpsc::channel();
        let mut debounce = HashMap::new();
        watcher
            .schedule_path(
                &temp,
                EventKind::Create(CreateKind::File),
                &mut debounce,
                &sender,
                Duration::from_secs(1),
            )
            .unwrap();
        assert!(debounce.contains_key(&temp));
        watcher
            .schedule_path(
                &final_path,
                EventKind::Create(CreateKind::File),
                &mut debounce,
                &sender,
                Duration::from_secs(1),
            )
            .unwrap();
        assert!(!debounce.contains_key(&temp));
        assert!(debounce.contains_key(&final_path));
        assert_eq!(debounce.len(), 1);
    }

    #[test]
    fn disappeared_path_does_not_publish_an_incomplete_report() {
        let (directory, watcher) = test_watcher();
        let missing = directory.path().join("downloads").join("restored.zip");

        let report = watcher.process_path_optional(&missing, false).unwrap();

        assert!(report.is_none());
        assert!(
            watcher
                .database
                .latest_report_summaries()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn basic_check_never_launches_the_child() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("data");
        let paths = AppPaths {
            config_file: directory.path().join("config.toml"),
            data_dir: data_dir.clone(),
            database: data_dir.join("state.db"),
            reports_dir: data_dir.join("reports"),
            logs_dir: data_dir.join("logs"),
            quarantine_dir: data_dir.join("quarantine"),
            rules_dir: data_dir.join("rules"),
        };
        paths.ensure().unwrap();
        let config = Config {
            download_dir: directory.path().join("downloads"),
            limits: LimitsConfig {
                snapshot_max_bytes: MIB,
                basic_check_threshold_bytes: 2 * MIB,
                motw_read_timeout_ms: 0,
                ..LimitsConfig::default()
            },
            child: ChildConfig {
                executable: Some(directory.path().join("missing-child.exe")),
                use_app_container: true,
            },
            ..Config::default()
        };
        fs::create_dir_all(&config.download_dir).unwrap();
        let path = config.download_dir.join("large.bin");
        let file = fs::File::create(&path).unwrap();
        file.set_len(3 * MIB).unwrap();
        drop(file);
        let database = Database::open(&paths.database).unwrap();
        let watcher = Watcher::new(config, database, paths);
        let report = watcher.process_path(&path).unwrap();
        assert!(report.threshold_decisions.basic_check_only);
        assert!(report.child_execution.is_none());
        assert!(report.has_boundary(BoundaryKind::BasicCheckOnly));
    }
}
