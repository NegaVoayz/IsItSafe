fn risk_color(group: RiskGroup) -> Color32 {
    match group {
        RiskGroup::Critical => DANGER,
        RiskGroup::High => Color32::from_rgb(247, 162, 92),
        RiskGroup::Review => WARNING,
        RiskGroup::Limited => BLUE,
        RiskGroup::Unknown => MUTED,
    }
}

fn severity_color(severity: Severity) -> Color32 {
    match severity {
        Severity::Critical => DANGER,
        Severity::High => Color32::from_rgb(247, 162, 92),
        Severity::Medium => WARNING,
        Severity::Low => BLUE,
        Severity::Info => MUTED,
    }
}

fn format_time(time: DateTime<Utc>) -> String {
    time.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

fn scrollbar_should_reveal(
    viewport: egui::Rect,
    pointer: Option<egui::Pos2>,
    last_scroll: Option<Instant>,
    now: Instant,
) -> bool {
    pointer.is_some_and(|position| {
        viewport.y_range().contains(position.y)
            && position.x >= viewport.right() - SCROLLBAR_REVEAL_GUTTER
    }) || last_scroll.is_some_and(|time| {
        now.checked_duration_since(time)
            .is_some_and(|elapsed| elapsed < SCROLLBAR_REVEAL_AFTER_SCROLL)
    })
}

