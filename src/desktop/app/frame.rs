impl DesktopApp {
    fn render_title_bar(&mut self, root: &mut egui::Ui) {
        let ctx = root.ctx().clone();
        egui::Panel::top("desktop_title_bar")
            .exact_size(42.0)
            .frame(Frame::new().fill(Color32::from_rgb(10, 14, 13)))
            .show(root, |ui| {
                ui.horizontal_centered(|ui| {
                    let controls_width = 138.0 + ui.spacing().item_spacing.x * 3.0;
                    let drag_width = (ui.available_width() - controls_width).max(20.0);
                    let (rect, response) = ui
                        .allocate_exact_size(Vec2::new(drag_width, 42.0), Sense::click_and_drag());
                    let dot = egui::pos2(rect.left() + 16.0, rect.center().y);
                    ui.painter().circle_filled(dot, 4.0, ACCENT);
                    ui.painter().text(
                        egui::pos2(dot.x + 12.0, rect.center().y),
                        Align2::LEFT_CENTER,
                        "IsItSafe",
                        FontId::proportional(13.0),
                        MUTED,
                    );
                    if response.double_clicked() {
                        let maximized =
                            ctx.input(|input| input.viewport().maximized.unwrap_or(false));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                    } else if response.drag_started() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                    }
                    if window_button(ui, WindowButton::Minimize, "Minimize").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    }
                    if window_button(ui, WindowButton::Maximize, "Maximize or restore").clicked() {
                        let maximized =
                            ctx.input(|input| input.viewport().maximized.unwrap_or(false));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                    }
                    if window_button(ui, WindowButton::Close, "Close").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
    }

    fn render_sidebar(&mut self, root: &mut egui::Ui) {
        egui::Panel::left("desktop_navigation")
            .resizable(false)
            .exact_size(210.0)
            .frame(
                Frame::new()
                    .fill(PANEL_ALT)
                    .stroke(Stroke::new(1.0, LINE))
                    .inner_margin(egui::Margin::symmetric(16, 20)),
            )
            .show(root, |ui| {
                ui.label(RichText::new("DOWNLOAD SAFETY").size(10.0).color(MUTED));
                ui.add_space(8.0);
                ui.label(RichText::new("IsItSafe").size(25.0).strong().color(TEXT));
                ui.label(
                    RichText::new("Static checks before execution")
                        .size(11.0)
                        .color(MUTED),
                );
                ui.add_space(28.0);

                if navigation_button(
                    ui,
                    self.page == Page::Review,
                    "Review",
                    Some(self.snapshot.questionable.len()),
                    DANGER,
                ) {
                    self.page = Page::Review;
                }
                if navigation_button(
                    ui,
                    self.page == Page::Quarantine,
                    "Quarantine",
                    Some(self.snapshot.quarantine.len()),
                    WARNING,
                ) {
                    self.page = Page::Quarantine;
                }

                ui.add_space(26.0);
                ui.label(RichText::new("RISK GROUPS").size(10.0).color(MUTED));
                ui.add_space(8.0);
                for group in [
                    RiskGroup::Critical,
                    RiskGroup::High,
                    RiskGroup::Review,
                    RiskGroup::Limited,
                    RiskGroup::Unknown,
                ] {
                    let count = if self.page == Page::Quarantine {
                        self.snapshot.quarantine_count(group)
                    } else {
                        self.snapshot.review_count(group)
                    };
                    if count == 0 && group == RiskGroup::Unknown {
                        continue;
                    }
                    ui.horizontal(|ui| {
                        let (dot, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                        ui.painter()
                            .circle_filled(dot.center(), 3.0, risk_color(group));
                        ui.label(RichText::new(group.label()).size(12.0).color(MUTED));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(count.to_string())
                                    .monospace()
                                    .size(12.0)
                                    .color(TEXT),
                            );
                        });
                    });
                }

                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    if navigation_button(
                        ui,
                        self.page == Page::Settings,
                        "Settings",
                        None,
                        MUTED,
                    ) {
                        self.page = Page::Settings;
                    }
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        let (dot, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                        ui.painter().circle_filled(
                            dot.center(),
                            3.5,
                            if self.monitor_running { ACCENT } else { DANGER },
                        );
                        ui.label(
                            RichText::new(if self.monitor_running {
                                "Monitor active"
                            } else {
                                "Monitor unavailable"
                            })
                            .size(11.0)
                            .color(MUTED),
                        );
                    });
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Static analysis does not prove runtime safety.")
                            .size(10.0)
                            .color(MUTED),
                    );
                });
            });
    }

    fn render_content(&mut self, root: &mut egui::Ui) {
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(CANVAS)
                    .inner_margin(egui::Margin::symmetric(24, 20)),
            )
            .show(root, |ui| match self.page {
                Page::Review => self.render_review(ui),
                Page::Quarantine => self.render_quarantine(ui),
                Page::Settings => self.render_settings(ui),
                Page::Details => self.render_details(ui),
            });
    }

}
