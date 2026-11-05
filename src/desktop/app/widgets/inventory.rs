fn render_inventory(ui: &mut egui::Ui, report: &AnalysisReportV1) {
    if report.components.is_empty() {
        let limited = report.boundaries.iter().any(|boundary| {
            matches!(
                boundary.kind,
                BoundaryKind::Limited | BoundaryKind::BasicCheckOnly
            )
        });
        let message = if limited {
            "No component inventory is available because deep unpacking was skipped."
        } else {
            "No embedded files or installer components were recorded in this report."
        };
        Frame::new()
            .fill(WARNING.gamma_multiply(0.08))
            .stroke(Stroke::new(1.0, WARNING.gamma_multiply(0.3)))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.label(RichText::new(message).size(11.5).color(MUTED));
            });
        return;
    }

    for component in &report.components {
        render_component(ui, component, report);
        ui.add_space(7.0);
    }
}

fn render_component(ui: &mut egui::Ui, component: &ComponentEvidence, report: &AnalysisReportV1) {
    let color = severity_color(component.severity);
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(
            1.0,
            if component.severity >= Severity::High {
                color.gamma_multiply(0.65)
            } else {
                LINE
            },
        ))
        .inner_margin(egui::Margin::same(11))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                severity_badge(ui, component.severity);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(&component.nesting_path)
                            .size(12.0)
                            .strong()
                            .color(TEXT),
                    );
                    let formats = if component.formats.is_empty() {
                        "unknown format".into()
                    } else {
                        component
                            .formats
                            .iter()
                            .map(|format| format.kind.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    let signed = match component.signed {
                        Some(true) => "signed",
                        Some(false) => "unsigned",
                        None => "signature unavailable",
                    };
                    ui.label(
                        RichText::new(format!(
                            "{}  •  {}  •  {signed}",
                            format_size(component.size),
                            formats
                        ))
                        .size(10.0)
                        .color(MUTED),
                    );
                    if let Some(hash) = &component.sha256 {
                        ui.label(
                            RichText::new(hash)
                                .monospace()
                                .size(9.0)
                                .color(Color32::from_rgb(110, 128, 119)),
                        );
                        render_matching_reputation(ui, report, hash);
                    }
                });
            });
            for evidence in &component.evidence {
                bullet(ui, &evidence.summary, severity_color(evidence.severity));
            }
        });
}

fn render_software_group(
    ui: &mut egui::Ui,
    group: &super::data::SoftwareIdentityGroup,
    index: usize,
) {
    let carrier_count: usize = group
        .certificates
        .iter()
        .map(|certificate| certificate.products.len())
        .sum();
    let risk = group.risk_state();
    let color = software_group_color(group);
    let summary = format!(
        "{}  •  {}  •  {} certificate{}, {}",
        group.product_name,
        risk.label(),
        group.certificates.len(),
        if group.certificates.len() == 1 {
            ""
        } else {
            "s"
        },
        file_count_label(carrier_count)
    );
    egui::CollapsingHeader::new(RichText::new(summary).size(13.0).strong().color(TEXT))
        .id_salt(("software-identity", index, &group.product_name))
        .default_open(group.starts_expanded())
        .show(ui, |ui| {
            Frame::new()
                .fill(PANEL_ALT)
                .stroke(Stroke::new(1.0, color.gamma_multiply(0.35)))
                .corner_radius(6.0)
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    key_value(
                        ui,
                        "Manufacturer",
                        group.manufacturer.as_deref().unwrap_or("not declared"),
                    );
                    if let Some(version) = &group.product_version {
                        key_value(ui, "Version", version);
                    }
                    if let Some(product) = group
                        .certificates
                        .iter()
                        .flat_map(|certificate| &certificate.products)
                        .next()
                    {
                        if let Some(description) = &product.file_description {
                            key_value(ui, "Description", description);
                        }
                        if let Some(copyright) = &product.legal_copyright {
                            key_value(ui, "Copyright", copyright);
                        }
                    }
                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);
                    for (certificate_index, certificate) in group.certificates.iter().enumerate() {
                        render_certificate_group(ui, certificate, (index, certificate_index));
                    }
                });
        });
}

