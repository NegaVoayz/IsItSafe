use std::sync::{Arc, mpsc};
use std::thread;

use uuid::Uuid;

use crate::config::{AppPaths, Config};
use crate::db::Database;
use crate::interaction::{DecisionSource, execute_user_decision, restore_quarantine_from_desktop};
use crate::report::{AnalysisReportV1, UserDecision};

use super::data::{DesktopSnapshot, load_snapshot};

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
                                .map(|report| report.map(Box::new))
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
