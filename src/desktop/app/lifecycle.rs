impl DesktopApp {
    pub(super) fn new(
        creation: &eframe::CreationContext<'_>,
        config: Arc<Config>,
        database: Arc<Database>,
        paths: Arc<AppPaths>,
    ) -> Self {
        configure_style(&creation.egui_ctx);
        let requested_details = super::take_requested_details(&paths);
        let worker = Worker::start(Arc::clone(&config), database, Arc::clone(&paths));
        let _ = worker.send(WorkerRequest::Refresh);
        let monitor_running = super::monitor_is_running();
        let mut app = Self {
            config,
            paths,
            worker,
            snapshot: DesktopSnapshot::default(),
            page: Page::Review,
            selected_report_id: None,
            selected_report: None,
            restore_prompt: None,
            status: None,
            busy: false,
            busy_message: None,
            monitor_running,
            last_refresh: Instant::now(),
            last_monitor_check: Instant::now(),
            last_detail_request_check: Instant::now(),
            last_content_scroll: None,
        };
        match requested_details {
            Ok(Some(report_id)) => app.open_details(report_id),
            Ok(None) => {}
            Err(error) => {
                app.status = Some(StatusMessage {
                    text: format!("Could not open the requested report: {error:#}"),
                    error: true,
                });
            }
        }
        app
    }

    fn request_refresh(&mut self) {
        if let Err(error) = self.worker.send(WorkerRequest::Refresh) {
            self.status = Some(StatusMessage {
                text: error,
                error: true,
            });
        }
    }

    fn open_details(&mut self, report_id: Uuid) {
        self.page = Page::Details;
        self.selected_report_id = Some(report_id);
        self.selected_report = None;
        self.busy = true;
        self.busy_message = Some("Loading stored report…");
        if let Err(error) = self.worker.send(WorkerRequest::LoadReport(report_id)) {
            self.busy = false;
            self.busy_message = None;
            self.status = Some(StatusMessage {
                text: error,
                error: true,
            });
        }
    }

    fn quarantine(&mut self, report_id: Uuid) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.busy_message = Some("Quarantining file after SHA-256 verification…");
        self.status = None;
        if let Err(error) = self.worker.send(WorkerRequest::Quarantine(report_id)) {
            self.busy = false;
            self.busy_message = None;
            self.status = Some(StatusMessage {
                text: error,
                error: true,
            });
        }
    }

    fn start_restore(&mut self, sha256: String, original_name: String) {
        self.restore_prompt = Some(RestorePrompt {
            sha256,
            file_name: original_name,
        });
    }

    fn poll_worker(&mut self, ctx: &egui::Context) {
        while let Some(event) = self.worker.try_recv() {
            match event {
                WorkerEvent::Snapshot(result) => match result {
                    Ok(snapshot) => self.snapshot = snapshot,
                    Err(error) => {
                        self.status = Some(StatusMessage {
                            text: error,
                            error: true,
                        });
                    }
                },
                WorkerEvent::ReportLoaded { report_id, result } => {
                    if self.selected_report_id == Some(report_id) {
                        self.busy = false;
                        self.busy_message = None;
                        match result {
                            Ok(Some(report)) => {
                                self.selected_report = Some(*report);
                            }
                            Ok(None) => {
                                self.status = Some(StatusMessage {
                                    text: "The stored report is no longer available".into(),
                                    error: true,
                                });
                            }
                            Err(error) => {
                                self.status = Some(StatusMessage {
                                    text: error,
                                    error: true,
                                });
                            }
                        }
                    }
                }
                WorkerEvent::ActionFinished { message, snapshot } => {
                    self.busy = false;
                    self.busy_message = None;
                    match message {
                        Ok(text) => {
                            self.status = Some(StatusMessage { text, error: false });
                            self.selected_report = None;
                            self.selected_report_id = None;
                            self.page = Page::Review;
                        }
                        Err(text) => {
                            self.status = Some(StatusMessage { text, error: true });
                        }
                    }
                    match snapshot {
                        Ok(snapshot) => self.snapshot = snapshot,
                        Err(error) => {
                            self.status = Some(StatusMessage {
                                text: error,
                                error: true,
                            });
                        }
                    }
                    self.last_refresh = Instant::now();
                    ctx.request_repaint();
                }
            }
        }
    }

}
