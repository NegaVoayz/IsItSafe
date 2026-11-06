impl DesktopApp {
    fn render_status(&self, ui: &mut egui::Ui) {
        if let Some(status) = &self.status {
            let color = if status.error { DANGER } else { ACCENT };
            Frame::new()
                .fill(color.gamma_multiply(0.12))
                .stroke(Stroke::new(1.0, color.gamma_multiply(0.45)))
                .inner_margin(egui::Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.label(RichText::new(&status.text).size(11.5).color(color));
                });
        } else if let Some(message) = self.busy_message {
            Frame::new()
                .fill(BLUE.gamma_multiply(0.10))
                .stroke(Stroke::new(1.0, BLUE.gamma_multiply(0.35)))
                .inner_margin(egui::Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new(message).size(11.5).color(BLUE));
                    });
                });
        } else {
            return;
        }
        ui.add_space(10.0);
    }

    fn render_restore_prompt(&mut self, ctx: &egui::Context) {
        let Some(mut prompt) = self.restore_prompt.take() else {
            return;
        };
        let mut open = true;
        let mut confirmed = false;
        let mut cancel = false;
        let validation = validate_download_file_name(&prompt.file_name);
        let download_dir = self.config.read().download_dir.clone();
        let destination_exists =
            validation.is_ok() && download_dir.join(&prompt.file_name).exists();

        egui::Window::new("Restore to Downloads")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .default_width(500.0)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(
                        "The stored SHA-256 will be verified before the file is moved. Downloads remains non-executable.",
                    )
                    .color(MUTED),
                );
                ui.add_space(10.0);
                ui.label(RichText::new("Filename").size(11.0).color(MUTED));
                ui.add(TextEdit::singleline(&mut prompt.file_name).desired_width(460.0));
                if let Err(error) = &validation {
                    ui.label(RichText::new(error.to_string()).size(11.0).color(DANGER));
                } else if destination_exists {
                    ui.label(
                        RichText::new("A file with this name already exists in Downloads.")
                            .size(11.0)
                            .color(DANGER),
                    );
                }
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "Destination: {}",
                        download_dir.join(&prompt.file_name).display()
                    ))
                    .size(10.5)
                    .color(MUTED),
                );
                ui.add_space(14.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add_enabled(
                            validation.is_ok() && !destination_exists && !self.busy,
                            egui::Button::new(
                                RichText::new("Restore").color(Color32::BLACK),
                            )
                            .fill(ACCENT),
                        )
                        .clicked()
                    {
                        confirmed = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if confirmed {
            self.busy = true;
            self.busy_message = Some("Restoring file to Downloads…");
            self.status = None;
            if let Err(error) = self.worker.send(WorkerRequest::Restore {
                sha256: prompt.sha256,
                file_name: prompt.file_name,
            }) {
                self.busy = false;
                self.busy_message = None;
                self.status = Some(StatusMessage {
                    text: error,
                    error: true,
                });
            }
        } else if open && !cancel {
            self.restore_prompt = Some(prompt);
        }
    }

    fn prepare_scroll_reveal(&mut self, ui: &mut egui::Ui) {
        let viewport = ui.available_rect_before_wrap();
        let pointer = ui.input(|input| input.pointer.latest_pos());
        let scrolling_here = pointer.is_some_and(|position| viewport.contains(position))
            && ui.input(|input| input.smooth_scroll_delta.y.abs() > f32::EPSILON);
        let now = Instant::now();
        if scrolling_here {
            self.last_content_scroll = Some(now);
        }

        let reveal = scrollbar_should_reveal(viewport, pointer, self.last_content_scroll, now);

        let scroll = &mut ui.style_mut().spacing.scroll;
        scroll.active_handle_opacity = if reveal { 0.55 } else { 0.0 };
        scroll.active_background_opacity = if reveal { 0.22 } else { 0.0 };
        if reveal {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
    }
}
