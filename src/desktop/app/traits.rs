impl eframe::App for DesktopApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_worker(&ctx);
        if !self.busy && self.last_refresh.elapsed() >= Duration::from_millis(1500) {
            self.request_refresh();
            self.last_refresh = Instant::now();
        }
        if self.last_monitor_check.elapsed() >= Duration::from_secs(2) {
            self.monitor_running = super::monitor_is_running();
            self.last_monitor_check = Instant::now();
        }
        if !self.busy && self.last_detail_request_check.elapsed() >= Duration::from_millis(250) {
            self.last_detail_request_check = Instant::now();
            match super::take_requested_details(&self.paths) {
                Ok(Some(report_id))
                    if self.page != Page::Details || self.selected_report_id != Some(report_id) =>
                {
                    self.open_details(report_id);
                }
                Ok(_) => {}
                Err(error) => {
                    self.status = Some(StatusMessage {
                        text: format!("Could not open the requested report: {error:#}"),
                        error: true,
                    });
                }
            }
        }

        self.render_title_bar(ui);
        self.render_sidebar(ui);
        self.render_content(ui);
        self.render_restore_prompt(&ctx);
        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

