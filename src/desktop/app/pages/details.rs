impl DesktopApp {
    fn render_details(&mut self, ui: &mut egui::Ui) {
        if ui.button("← Back to Review").clicked() {
            self.page = Page::Review;
            self.selected_report = None;
            self.selected_report_id = None;
        }
        ui.add_space(12.0);
        self.render_status(ui);
        self.prepare_scroll_reveal(ui);

        let Some(report) = self.selected_report.as_ref() else {
            if self.busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Loading stored report…").color(MUTED));
                });
            } else {
                empty_state(
                    ui,
                    "Report unavailable",
                    "Return to Review and select another file.",
                );
            }
            return;
        };

        ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(ScrollBarVisibility::VisibleWhenNeeded)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(file_name(&report.file.display_path))
                                .size(26.0)
                                .strong()
                                .color(TEXT),
                        );
                        ui.label(
                            RichText::new(report.file.display_path.as_str())
                                .size(11.0)
                                .color(MUTED),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        verdict_badge(ui, report.verdict);
                    });
                });
                ui.add_space(14.0);

                Frame::new()
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0, LINE))
                    .inner_margin(egui::Margin::same(14))
                    .show(ui, |ui| {
                        key_value(
                            ui,
                            "SHA-256",
                            report.file.sha256.as_deref().unwrap_or("unavailable"),
                        );
                        key_value(
                            ui,
                            "Size",
                            &format!(
                                "{} ({} bytes)",
                                format_size(report.file.size),
                                report.file.size
                            ),
                        );
                        key_value(ui, "Observed", &format_time(report.observed_at));
                        key_value(
                            ui,
                            "Formats",
                            &if report.classification.formats.is_empty() {
                                "No structural format identified".into()
                            } else {
                                report
                                    .classification
                                    .formats
                                    .iter()
                                    .map(|format| {
                                        format!("{} at offset {}", format.kind, format.offset)
                                    })
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            },
                        );
                        if let Some(family) = &report.classification.installer_family {
                            key_value(ui, "Installer", family);
                        }
                    });

                if !report.products.is_empty() {
                    ui.add_space(10.0);
                    let groups = group_products_by_software(report);
                    egui::CollapsingHeader::new(
                        RichText::new(format!("Software identities ({} groups)", groups.len()))
                            .strong()
                            .color(TEXT),
                    )
                    .default_open(true)
                    .show(ui, |ui| {
                        for (index, group) in groups.iter().enumerate() {
                            render_software_group(ui, group, index);
                        }
                    });
                }

                ui.add_space(14.0);
                egui::CollapsingHeader::new(
                    RichText::new("Reasons and policy").strong().color(TEXT),
                )
                .default_open(true)
                .show(ui, |ui| {
                    if report.policy.reasons.is_empty() {
                        ui.label(RichText::new("No policy reason was recorded.").color(MUTED));
                    }
                    for reason in &report.policy.reasons {
                        bullet(ui, reason, WARNING);
                    }
                    ui.label(
                        RichText::new(report.limitations_notice.as_str())
                            .size(11.0)
                            .color(MUTED),
                    );
                });

                if !report.facts.is_empty() {
                    ui.add_space(10.0);
                    egui::CollapsingHeader::new(
                        RichText::new("Detection evidence").strong().color(TEXT),
                    )
                    .default_open(true)
                    .show(ui, |ui| {
                        for evidence in &report.facts {
                            ui.horizontal(|ui| {
                                severity_badge(ui, evidence.severity);
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(&evidence.summary).size(12.0).color(TEXT),
                                    );
                                    if let Some(detail) = &evidence.detail {
                                        ui.label(RichText::new(detail).size(10.5).color(MUTED));
                                    }
                                });
                            });
                        }
                    });
                }

                ui.add_space(10.0);
                egui::CollapsingHeader::new(
                    RichText::new(format!("Embedded inventory ({})", report.components.len()))
                        .strong()
                        .color(TEXT),
                )
                .default_open(true)
                .show(ui, |ui| {
                    render_inventory(ui, report);
                });

                ui.add_space(10.0);
                egui::CollapsingHeader::new(
                    RichText::new("Reputation and signatures")
                        .strong()
                        .color(TEXT),
                )
                .default_open(true)
                .show(ui, |ui| {
                    render_reputation(ui, report);
                });

                if !report.boundaries.is_empty() {
                    ui.add_space(10.0);
                    egui::CollapsingHeader::new(
                        RichText::new("Check boundaries").strong().color(TEXT),
                    )
                    .default_open(false)
                    .show(ui, |ui| {
                        for boundary in &report.boundaries {
                            bullet(ui, &boundary.detail, WARNING);
                        }
                    });
                }
                ui.add_space(20.0);
            });
    }

}
