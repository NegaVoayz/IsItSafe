fn key_value(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            Vec2::new(82.0, 18.0),
            Label::new(RichText::new(key).size(10.5).color(MUTED)),
        );
        ui.label(RichText::new(value).monospace().size(10.5).color(TEXT));
    });
}

