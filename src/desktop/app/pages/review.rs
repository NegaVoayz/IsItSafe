impl DesktopApp {
    fn render_review(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Review downloads",
            "Files in Downloads with unresolved or elevated risk",
            Some("Quarantine moves a file immediately after rechecking its hash."),
        );
        self.render_status(ui);

        if self.snapshot.questionable.is_empty() {
            empty_state(
                ui,
                "No questionable downloads",
                "New analysis results will appear here. Safe and already-kept files are hidden.",
            );
            return;
        }

        let entries = self.snapshot.questionable.clone();
        let mut quarantine = None;
        let mut details = None;
        self.prepare_scroll_reveal(ui);
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(ScrollBarVisibility::VisibleWhenNeeded)
            .show(ui, |ui| {
                for group in [
                    RiskGroup::Critical,
                    RiskGroup::High,
                    RiskGroup::Review,
                    RiskGroup::Limited,
                ] {
                    let grouped: Vec<_> = entries
                        .iter()
                        .filter(|entry| entry.group == group)
                        .collect();
                    if grouped.is_empty() {
                        continue;
                    }
                    group_header(ui, group, grouped.len());
                    for entry in grouped {
                        Frame::new()
                            .fill(PANEL)
                            .stroke(Stroke::new(1.0, LINE))
                            .inner_margin(egui::Margin::symmetric(14, 12))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let left_width = (ui.available_width() - 292.0).max(230.0);
                                    ui.allocate_ui_with_layout(
                                        Vec2::new(left_width, 76.0),
                                        Layout::top_down(Align::LEFT),
                                        |ui| {
                                            ui.set_max_width(left_width);
                                            if ui
                                                .add(
                                                    Label::new(
                                                        RichText::new(&entry.summary.file_name)
                                                            .size(15.0)
                                                            .strong()
                                                            .color(TEXT),
                                                    )
                                                    .sense(Sense::click()),
                                                )
                                                .clicked()
                                            {
                                                details = Some(entry.summary.report_id);
                                            }
                                            ui.horizontal_wrapped(|ui| {
                                                ui.spacing_mut().item_spacing.x = 6.0;
                                                let mut compact_reasons = Vec::new();
                                                for reason in &entry.summary.reasons {
                                                    let compact = compact_reason(reason);
                                                    if compact.is_empty()
                                                        || compact_reasons
                                                            .iter()
                                                            .any(|existing| existing == &compact)
                                                    {
                                                        continue;
                                                    }
                                                    compact_reasons.push(compact);
                                                }
                                                let shown_count = compact_reasons.len().min(3);
                                                for compact in compact_reasons.iter().take(3) {
                                                    reason_badge(
                                                        ui,
                                                        compact,
                                                        risk_color(entry.group),
                                                    );
                                                }
                                                if compact_reasons.len() > shown_count {
                                                    ui.label(
                                                        RichText::new(format!(
                                                            "+{} more",
                                                            compact_reasons.len() - shown_count
                                                        ))
                                                        .size(9.5)
                                                        .color(MUTED),
                                                    );
                                                }
                                            });
                                            ui.label(
                                                RichText::new(format!(
                                                    "{} at {}",
                                                    format_size(entry.summary.size),
                                                    format_time(entry.summary.observed_at)
                                                ))
                                                .size(10.5)
                                                .color(Color32::from_rgb(112, 127, 120)),
                                            );
                                        },
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if ui
                                            .add_enabled(
                                                !self.busy,
                                                egui::Button::new(
                                                    RichText::new("Quarantine")
                                                        .color(Color32::BLACK),
                                                )
                                                .fill(WARNING),
                                            )
                                            .clicked()
                                        {
                                            quarantine = Some(entry.summary.report_id);
                                        }
                                        if ui.button("Details").clicked() {
                                            details = Some(entry.summary.report_id);
                                        }
                                        verdict_badge(ui, entry.summary.verdict);
                                    });
                                });
                            });
                        ui.add_space(8.0);
                    }
                    ui.add_space(10.0);
                }
            });

        if let Some(report_id) = quarantine {
            self.quarantine(report_id);
        } else if let Some(report_id) = details {
            self.open_details(report_id);
        }
    }

    fn render_quarantine(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Quarantine",
            "Recoverable files kept outside the normal download flow",
            Some("Restore verifies the stored SHA-256 and never overwrites a file."),
        );
        self.render_status(ui);

        if self.snapshot.quarantine.is_empty() {
            empty_state(
                ui,
                "Quarantine is empty",
                "Files you quarantine from Review or Windows notifications will appear here.",
            );
            return;
        }

        let entries = self.snapshot.quarantine.clone();
        let mut restore = None;
        self.prepare_scroll_reveal(ui);
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(ScrollBarVisibility::VisibleWhenNeeded)
            .show(ui, |ui| {
                for group in [
                    RiskGroup::Critical,
                    RiskGroup::High,
                    RiskGroup::Review,
                    RiskGroup::Limited,
                    RiskGroup::Unknown,
                ] {
                    let grouped: Vec<_> = entries
                        .iter()
                        .filter(|entry| entry.group == group)
                        .collect();
                    if grouped.is_empty() {
                        continue;
                    }
                    group_header(ui, group, grouped.len());
                    for entry in grouped {
                        Frame::new()
                            .fill(PANEL)
                            .stroke(Stroke::new(1.0, LINE))
                            .inner_margin(egui::Margin::symmetric(14, 12))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let left_width = (ui.available_width() - 220.0).max(300.0);
                                    ui.allocate_ui_with_layout(
                                        Vec2::new(left_width, 66.0),
                                        Layout::top_down(Align::LEFT),
                                        |ui| {
                                            ui.set_max_width(left_width);
                                            ui.label(
                                                RichText::new(&entry.display_name)
                                                    .size(15.0)
                                                    .strong()
                                                    .color(TEXT),
                                            );
                                            ui.label(
                                                RichText::new(entry.reasons.join("  •  "))
                                                    .size(11.5)
                                                    .color(MUTED),
                                            );
                                            ui.label(
                                                RichText::new(format!(
                                                    "Quarantined {}  •  {}…",
                                                    format_time(entry.moved_at),
                                                    &entry.sha256[..entry.sha256.len().min(12)]
                                                ))
                                                .size(10.5)
                                                .color(Color32::from_rgb(112, 127, 120)),
                                            );
                                        },
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if ui
                                            .add_enabled(
                                                !self.busy,
                                                egui::Button::new(
                                                    RichText::new("Restore").color(Color32::BLACK),
                                                )
                                                .fill(ACCENT),
                                            )
                                            .clicked()
                                        {
                                            restore = Some((
                                                entry.sha256.clone(),
                                                entry.suggested_download_name(),
                                            ));
                                        }
                                        if let Some(summary) = &entry.summary {
                                            verdict_badge(ui, summary.verdict);
                                        } else {
                                            risk_badge(ui, entry.group);
                                        }
                                    });
                                });
                            });
                        ui.add_space(8.0);
                    }
                    ui.add_space(10.0);
                }
            });

        if let Some((sha256, name)) = restore {
            self.start_restore(sha256, name);
        }
    }

}
