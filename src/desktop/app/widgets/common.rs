fn window_button(ui: &mut egui::Ui, kind: WindowButton, tooltip: &str) -> egui::Response {
    let response = ui
        .add_sized(Vec2::new(46.0, 42.0), egui::Button::new("").frame(false))
        .on_hover_text(tooltip);
    let rect = response.rect;
    let hovered = response.hovered();
    let color = if hovered { TEXT } else { MUTED };
    if hovered {
        ui.painter().rect_filled(
            rect,
            0.0,
            if matches!(kind, WindowButton::Close) {
                Color32::from_rgb(190, 45, 38)
            } else {
                Color32::from_rgb(35, 45, 41)
            },
        );
    }
    let center = rect.center();
    let stroke = Stroke::new(1.2, color);
    match kind {
        WindowButton::Minimize => {
            ui.painter().line_segment(
                [
                    egui::pos2(center.x - 5.0, center.y + 0.5),
                    egui::pos2(center.x + 5.0, center.y + 0.5),
                ],
                stroke,
            );
        }
        WindowButton::Maximize => {
            ui.painter().rect_stroke(
                egui::Rect::from_center_size(center, Vec2::splat(9.0)),
                0.0,
                stroke,
                egui::StrokeKind::Inside,
            );
        }
        WindowButton::Close => {
            ui.painter().line_segment(
                [
                    egui::pos2(center.x - 4.5, center.y - 4.5),
                    egui::pos2(center.x + 4.5, center.y + 4.5),
                ],
                stroke,
            );
            ui.painter().line_segment(
                [
                    egui::pos2(center.x + 4.5, center.y - 4.5),
                    egui::pos2(center.x - 4.5, center.y + 4.5),
                ],
                stroke,
            );
        }
    }
    response
}

fn navigation_button(
    ui: &mut egui::Ui,
    selected: bool,
    label: &str,
    count: Option<usize>,
    color: Color32,
) -> bool {
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), 36.0),
        Sense::click(),
    );
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    let hovered = response.hovered();
    let fill = if selected {
        color.gamma_multiply(if hovered { 0.20 } else { 0.12 })
    } else if hovered {
        color.gamma_multiply(0.08)
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, 8.0, fill);
    if hovered {
        ui.painter().rect_stroke(
            rect,
            8.0,
            Stroke::new(1.0, color.gamma_multiply(0.32)),
            egui::StrokeKind::Inside,
        );
    }

    let center_y = rect.center().y;
    let dot = egui::pos2(rect.left() + 14.0, center_y);
    ui.painter().circle_filled(dot, 3.5, color);
    ui.painter().text(
        egui::pos2(rect.left() + 27.0, center_y),
        Align2::LEFT_CENTER,
        label,
        FontId::proportional(13.0),
        if selected || hovered { TEXT } else { MUTED },
    );
    if let Some(count) = count {
        ui.painter().text(
            egui::pos2(rect.right() - 14.0, center_y),
            Align2::RIGHT_CENTER,
            count,
            FontId::monospace(11.0),
            if selected { color } else { MUTED },
        );
    }
    response.clicked()
}

fn page_header(ui: &mut egui::Ui, title: &str, description: &str, note: Option<&str>) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(title).size(25.0).strong().color(TEXT));
            ui.label(RichText::new(description).size(12.0).color(MUTED));
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new("ISOLATED ANALYSIS").size(9.5).color(ACCENT));
        });
    });
    if let Some(note) = note {
        ui.add_space(8.0);
        ui.label(RichText::new(note).size(10.5).color(MUTED));
    }
    ui.add_space(16.0);
}

fn empty_state(ui: &mut egui::Ui, title: &str, detail: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(90.0);
        ui.label(RichText::new(title).size(19.0).strong().color(TEXT));
        ui.label(RichText::new(detail).size(12.0).color(MUTED));
    });
}

fn group_header(ui: &mut egui::Ui, group: RiskGroup, count: usize) {
    ui.horizontal(|ui| {
        let (dot, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
        ui.painter()
            .circle_filled(dot.center(), 4.0, risk_color(group));
        ui.label(RichText::new(group.label()).size(13.0).strong().color(TEXT));
        ui.label(
            RichText::new(format!("{count}  •  {}", group.description()))
                .size(10.5)
                .color(MUTED),
        );
    });
    ui.add_space(7.0);
}

fn verdict_badge(ui: &mut egui::Ui, verdict: Verdict) {
    let group = RiskGroup::from_verdict(verdict);
    risk_badge(ui, group);
}

fn risk_badge(ui: &mut egui::Ui, group: RiskGroup) {
    let color = risk_color(group);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(108.0, 24.0), Sense::hover());
    ui.painter()
        .rect_filled(rect, 4.0, color.gamma_multiply(0.14));
    ui.painter().rect_stroke(
        rect,
        4.0,
        Stroke::new(1.0, color.gamma_multiply(0.5)),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        group.label(),
        FontId::proportional(10.0),
        color,
    );
}

fn severity_badge(ui: &mut egui::Ui, severity: Severity) {
    let color = severity_color(severity);
    Frame::new()
        .fill(color.gamma_multiply(0.14))
        .inner_margin(egui::Margin::symmetric(6, 3))
        .show(ui, |ui| {
            ui.label(
                RichText::new(severity_label(severity))
                    .size(9.0)
                    .strong()
                    .color(color),
            );
        });
}

fn reason_badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    Frame::new()
        .fill(color.gamma_multiply(0.10))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.34)))
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(9.5).color(color));
        });
}

fn bullet(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.horizontal(|ui| {
        let (dot, _) = ui.allocate_exact_size(Vec2::splat(7.0), Sense::hover());
        ui.painter().circle_filled(dot.center(), 2.5, color);
        ui.label(RichText::new(text).size(11.5).color(MUTED));
    });
}

