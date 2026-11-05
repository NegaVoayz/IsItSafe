use std::sync::{Arc, mpsc};
use std::thread;

use uuid::Uuid;

use crate::capture::escape_controls;
use crate::config::{AppPaths, Config};
use crate::db::Database;
use crate::interaction::{DecisionSource, execute_user_decision, restore_quarantine_from_desktop};
use crate::report::{AnalysisReportV1, UserDecision};

use super::data::{DesktopSnapshot, load_snapshot, most_risky_component_first};

#[derive(Debug, Clone)]
pub enum WorkerRequest {
    Refresh,
    Quarantine(Uuid),
    Restore { sha256: String, file_name: String },
    LoadReport(Uuid),
}

#[derive(Debug)]
pub enum WorkerEvent {
    Snapshot(Result<DesktopSnapshot, String>),
    ReportLoaded {
        report_id: Uuid,
        result: Result<Option<Box<AnalysisReportV1>>, String>,
    },
    ActionFinished {
        message: Result<String, String>,
        snapshot: Result<DesktopSnapshot, String>,
    },
}

pub struct Worker {
    sender: mpsc::Sender<WorkerRequest>,
    receiver: mpsc::Receiver<WorkerEvent>,
}

impl Worker {
    pub fn start(config: Arc<Config>, database: Arc<Database>, paths: Arc<AppPaths>) -> Self {
        let (request_tx, request_rx) = mpsc::channel::<WorkerRequest>();
        let (event_tx, event_rx) = mpsc::channel::<WorkerEvent>();
        thread::Builder::new()
            .name("isitsafe-desktop-data".into())
            .spawn(move || {
                while let Ok(request) = request_rx.recv() {
                    match request {
                        WorkerRequest::Refresh => {
                            let snapshot =
                                load_snapshot(&config, &database, &paths).map_err(error_text);
                            let _ = event_tx.send(WorkerEvent::Snapshot(snapshot));
                        }
                        WorkerRequest::Quarantine(report_id) => {
                            let message = execute_user_decision(
                                report_id,
                                UserDecision::Quarantine,
                                DecisionSource::Desktop,
                                &config,
                                &database,
                                &paths,
                            )
                            .map_err(error_text);
                            let snapshot =
                                load_snapshot(&config, &database, &paths).map_err(error_text);
                            let _ =
                                event_tx.send(WorkerEvent::ActionFinished { message, snapshot });
                        }
                        WorkerRequest::Restore { sha256, file_name } => {
                            let message = restore_quarantine_from_desktop(
                                &database, &config, &paths, &sha256, &file_name,
                            )
                            .map_err(error_text);
                            let snapshot =
                                load_snapshot(&config, &database, &paths).map_err(error_text);
                            let _ =
                                event_tx.send(WorkerEvent::ActionFinished { message, snapshot });
                        }
                        WorkerRequest::LoadReport(report_id) => {
                            let result = database
                                .report_by_id(&report_id.to_string())
                                .map(|report| {
                                    report.map(|mut report| {
                                        most_risky_component_first(&mut report.components);
                                        sanitize_report_for_display(&mut report);
                                        Box::new(report)
                                    })
                                })
                                .map_err(error_text);
                            let _ = event_tx.send(WorkerEvent::ReportLoaded { report_id, result });
                        }
                    }
                }
            })
            .expect("failed to start desktop data worker");
        Self {
            sender: request_tx,
            receiver: event_rx,
        }
    }

    pub fn send(&self, request: WorkerRequest) -> Result<(), String> {
        self.sender
            .send(request)
            .map_err(|_| "the desktop data worker stopped unexpectedly".into())
    }

    pub fn try_recv(&self) -> Option<WorkerEvent> {
        self.receiver.try_recv().ok()
    }
}

fn error_text(error: anyhow::Error) -> String {
    format!("{error:#}")
}

fn sanitize_report_for_display(report: &mut AnalysisReportV1) {
    report.file.display_path = escape_controls(&report.file.display_path);
    report.policy.reasons = report
        .policy
        .reasons
        .iter()
        .filter(|value| !value.starts_with("The user "))
        .map(|value| escape_controls(value))
        .collect();
    for evidence in report.facts.iter_mut().chain(report.inference.iter_mut()) {
        evidence.id = escape_controls(&evidence.id);
        evidence.category = escape_controls(&evidence.category);
        evidence.summary = escape_controls(&evidence.summary);
        evidence.detail = evidence.detail.as_deref().map(escape_controls);
        evidence.provenance = escape_controls(&evidence.provenance);
    }
    for boundary in &mut report.boundaries {
        boundary.detail = escape_controls(&boundary.detail);
    }
    for format in &mut report.classification.formats {
        format.kind = escape_controls(&format.kind);
        format.parser = escape_controls(&format.parser);
    }
    report.classification.installer_family = report
        .classification
        .installer_family
        .as_deref()
        .map(escape_controls);
    for component in &mut report.components {
        component.nesting_path = escape_controls(&component.nesting_path);
        component.name = escape_controls(&component.name);
        for evidence in &mut component.evidence {
            evidence.summary = escape_controls(&evidence.summary);
            evidence.detail = evidence.detail.as_deref().map(escape_controls);
        }
    }
    for reputation in &mut report.reputation {
        reputation.detail = reputation.detail.as_deref().map(escape_controls);
        reputation.signature_info = reputation
            .signature_info
            .iter()
            .map(|value| escape_controls(value))
            .collect();
    }
    if let Some(authenticity) = &mut report.authenticity {
        authenticity.publisher_identity = authenticity
            .publisher_identity
            .as_deref()
            .map(escape_controls);
        authenticity.detail = authenticity.detail.as_deref().map(escape_controls);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::FileEvidence;

    #[test]
    fn user_action_history_is_not_displayed_as_policy_evidence() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: "sample.exe".into(),
            ..FileEvidence::default()
        });
        report.policy.reasons.push("Unsigned executable".into());
        report
            .policy
            .reasons
            .push("The user restored the file to Downloads as sample.exe".into());

        sanitize_report_for_display(&mut report);

        assert_eq!(report.policy.reasons, vec!["Unsigned executable"]);
    }
}
