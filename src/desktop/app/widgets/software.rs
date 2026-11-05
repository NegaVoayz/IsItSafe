fn software_group_color(group: &super::data::SoftwareIdentityGroup) -> Color32 {
    match group.risk_state() {
        SignatureState::Invalid | SignatureState::Revoked => DANGER,
        SignatureState::Unsigned | SignatureState::NotYetValid => WARNING,
        SignatureState::Expired | SignatureState::Unknown | SignatureState::Unverified => BLUE,
        SignatureState::Valid => ACCENT,
    }
}

fn render_certificate_group(
    ui: &mut egui::Ui,
    group: &super::data::SignatureGroup,
    id: (usize, usize),
) {
    if id.1 > 0 {
        ui.separator();
        ui.add_space(4.0);
    }
    ui.horizontal(|ui| {
        ui.label(RichText::new("Certificate").size(10.0).color(MUTED));
        if !matches!(
            group.state,
            SignatureState::Unsigned | SignatureState::Unknown
        ) {
            let full_signer = group
                .products
                .iter()
                .find_map(|product| product.signer_identity.as_deref());
            let signer = ui.label(RichText::new(&group.signer).size(12.0).strong().color(TEXT));
            if let Some(full_signer) = full_signer.filter(|value| *value != group.signer) {
                signer.on_hover_text(full_signer);
            }
        }
        signature_badge(ui, group.state);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(file_count_label(group.products.len()))
                    .size(10.0)
                    .color(MUTED),
            );
        });
    });
    if let Some(fingerprint) = &group.certificate_sha256 {
        key_value(ui, "SHA-256", fingerprint);
    }
    if let Some(validity) = group.validity_label() {
        key_value(ui, "Validity", &validity);
    }
    ui.add_space(4.0);
    egui::CollapsingHeader::new(
        RichText::new(format!(
            "Evidence source  •  {}",
            file_count_label(group.products.len())
        ))
        .size(11.0)
        .color(TEXT),
    )
    .id_salt(("evidence-source", id, &group.signer))
    .default_open(false)
    .show(ui, |ui| {
        for product in &group.products {
            render_product_source(ui, product);
        }
    });
}

fn render_product_source(ui: &mut egui::Ui, product: &ProductIdentityEvidence) {
    let carrier = product
        .nesting_path
        .as_deref()
        .unwrap_or("the downloaded file");
    ui.label(
        RichText::new(
            product
                .original_filename
                .as_deref()
                .or_else(|| {
                    Path::new(carrier)
                        .file_name()
                        .and_then(|value| value.to_str())
                })
                .unwrap_or(carrier),
        )
        .size(11.0)
        .strong()
        .color(TEXT),
    );
    ui.label(RichText::new(carrier).monospace().size(9.5).color(MUTED));
    let mut source = product.source.clone();
    if let Some(original) = &product.original_filename
        && !original.eq_ignore_ascii_case(
            Path::new(carrier)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default(),
        )
    {
        source = format!("Original filename {original}  •  {source}");
    }
    ui.label(RichText::new(source).size(9.5).color(MUTED));
}

fn signature_badge(ui: &mut egui::Ui, state: SignatureState) {
    let color = signature_color(state);
    Frame::new()
        .fill(color.gamma_multiply(0.14))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.45)))
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(state.label()).size(9.5).strong().color(color));
        });
}

fn file_count_label(count: usize) -> String {
    format!("{count} file{}", if count == 1 { "" } else { "s" })
}

fn signature_color(state: SignatureState) -> Color32 {
    match state {
        SignatureState::Invalid | SignatureState::Revoked => DANGER,
        SignatureState::Unsigned | SignatureState::NotYetValid => WARNING,
        SignatureState::Expired | SignatureState::Unknown | SignatureState::Unverified => BLUE,
        SignatureState::Valid => ACCENT,
    }
}

fn render_reputation(ui: &mut egui::Ui, report: &AnalysisReportV1) {
    if report.reputation.is_empty() {
        ui.label(RichText::new("No reputation lookup was recorded.").color(MUTED));
    }
    for reputation in &report.reputation {
        let color = match reputation.state {
            ReputationState::Malicious => DANGER,
            ReputationState::Suspicious => WARNING,
            ReputationState::Undetected | ReputationState::NotFound => ACCENT,
            _ => MUTED,
        };
        ui.horizontal_top(|ui| {
            Frame::new()
                .fill(color.gamma_multiply(0.14))
                .inner_margin(egui::Margin::symmetric(7, 3))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("{:?}", reputation.state))
                            .size(9.5)
                            .strong()
                            .color(color),
                    );
                });
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(reputation_subject(report, &reputation.sha256))
                        .size(11.0)
                        .strong()
                        .color(TEXT),
                );
                let detail = reputation
                    .detail
                    .clone()
                    .unwrap_or_else(|| "VirusTotal hash lookup".into());
                ui.label(RichText::new(detail).size(10.5).color(MUTED));
            });
        });
    }
    if let Some(authenticity) = &report.authenticity {
        ui.add_space(5.0);
        key_value(
            ui,
            "Certificate owner",
            authenticity
                .publisher_identity
                .as_deref()
                .unwrap_or("not available"),
        );
        key_value(
            ui,
            "Signature",
            match authenticity.signature_digest_valid {
                Some(true) => "digest valid",
                Some(false) => "digest invalid",
                None => "not available",
            },
        );
        key_value(
            ui,
            "Chain",
            match authenticity.chain_valid {
                Some(true) => "valid",
                Some(false) => "invalid",
                None => "unknown",
            },
        );
        key_value(
            ui,
            "Unsigned",
            &format!("{} nested component(s)", authenticity.unsigned_components),
        );
    }
}

fn render_matching_reputation(ui: &mut egui::Ui, report: &AnalysisReportV1, hash: &str) {
    for reputation in report.reputation.iter().filter(|entry| {
        entry.sha256.eq_ignore_ascii_case(hash)
            && matches!(
                entry.state,
                ReputationState::Malicious
                    | ReputationState::Suspicious
                    | ReputationState::RateLimited
                    | ReputationState::Unavailable
            )
    }) {
        let color = match reputation.state {
            ReputationState::Malicious => DANGER,
            ReputationState::Suspicious => WARNING,
            _ => MUTED,
        };
        let label = match (reputation.detections, reputation.engines_total) {
            (Some(detections), Some(engines)) => {
                format!("VirusTotal {detections}/{engines}")
            }
            _ => format!("VirusTotal {:?}", reputation.state),
        };
        reason_badge(ui, &label, color);
    }
}

