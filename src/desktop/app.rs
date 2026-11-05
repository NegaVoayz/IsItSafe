use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local, Utc};
use eframe::egui::containers::scroll_area::ScrollBarVisibility;
use eframe::egui::{
    self, Align, Align2, Color32, FontId, Frame, Label, Layout, RichText, ScrollArea, Sense,
    Stroke, TextEdit, TextStyle, Vec2,
};
use uuid::Uuid;

use crate::config::{AppPaths, Config};
use crate::db::Database;
use crate::interaction::validate_download_file_name;
use crate::report::{
    AnalysisReportV1, BoundaryKind, ComponentEvidence, ProductIdentityEvidence, ReputationState,
    Severity, Verdict,
};

use super::actions::Worker;
use super::actions::{WorkerEvent, WorkerRequest};
use super::data::{
    DesktopSnapshot, RiskGroup, SignatureState, compact_reason, format_size,
    group_products_by_software, reputation_subject, severity_label,
};

const CANVAS: Color32 = Color32::from_rgb(12, 16, 15);
const PANEL: Color32 = Color32::from_rgb(21, 28, 25);
const PANEL_ALT: Color32 = Color32::from_rgb(16, 22, 20);
const LINE: Color32 = Color32::from_rgb(45, 58, 52);
const TEXT: Color32 = Color32::from_rgb(240, 246, 242);
const MUTED: Color32 = Color32::from_rgb(151, 166, 159);
const ACCENT: Color32 = Color32::from_rgb(141, 226, 181);
const WARNING: Color32 = Color32::from_rgb(244, 194, 104);
const DANGER: Color32 = Color32::from_rgb(245, 123, 120);
const BLUE: Color32 = Color32::from_rgb(132, 183, 242);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Review,
    Quarantine,
    Details,
}

struct RestorePrompt {
    sha256: String,
    file_name: String,
}

struct StatusMessage {
    text: String,
    error: bool,
}

pub(super) struct DesktopApp {
    config: Arc<Config>,
    paths: Arc<AppPaths>,
    worker: Worker,
    snapshot: DesktopSnapshot,
    page: Page,
    selected_report_id: Option<Uuid>,
    selected_report: Option<AnalysisReportV1>,
    restore_prompt: Option<RestorePrompt>,
    status: Option<StatusMessage>,
    busy: bool,
    busy_message: Option<&'static str>,
    monitor_running: bool,
    last_refresh: Instant,
    last_monitor_check: Instant,
    last_detail_request_check: Instant,
}

impl DesktopApp {
    pub(super) fn new(
        creation: &eframe::CreationContext<'_>,
        config: Arc<Config>,
        database: Arc<Database>,
        paths: Arc<AppPaths>,
    ) -> Self {
        configure_style(&creation.egui_ctx);
        let requested_details = super::take_requested_details(&paths);
        let worker = Worker::start(Arc::clone(&config), database, Arc::clone(&paths));
        let _ = worker.send(WorkerRequest::Refresh);
        let monitor_running = super::monitor_is_running();
        let mut app = Self {
            config,
            paths,
            worker,
            snapshot: DesktopSnapshot::default(),
            page: Page::Review,
            selected_report_id: None,
            selected_report: None,
            restore_prompt: None,
            status: None,
            busy: false,
            busy_message: None,
            monitor_running,
            last_refresh: Instant::now(),
            last_monitor_check: Instant::now(),
            last_detail_request_check: Instant::now(),
        };
        match requested_details {
            Ok(Some(report_id)) => app.open_details(report_id),
            Ok(None) => {}
            Err(error) => {
                app.status = Some(StatusMessage {
                    text: format!("Could not open the requested report: {error:#}"),
                    error: true,
                });
            }
        }
        app
    }

    fn request_refresh(&mut self) {
        if let Err(error) = self.worker.send(WorkerRequest::Refresh) {
            self.status = Some(StatusMessage {
                text: error,
                error: true,
            });
        }
    }

    fn open_details(&mut self, report_id: Uuid) {
        self.page = Page::Details;
        self.selected_report_id = Some(report_id);
        self.selected_report = None;
        self.busy = true;
        self.busy_message = Some("Loading stored report…");
        if let Err(error) = self.worker.send(WorkerRequest::LoadReport(report_id)) {
            self.busy = false;
            self.busy_message = None;
            self.status = Some(StatusMessage {
                text: error,
                error: true,
            });
        }
    }

    fn quarantine(&mut self, report_id: Uuid) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.busy_message = Some("Quarantining file after SHA-256 verification…");
        self.status = None;
        if let Err(error) = self.worker.send(WorkerRequest::Quarantine(report_id)) {
            self.busy = false;
            self.busy_message = None;
            self.status = Some(StatusMessage {
                text: error,
                error: true,
            });
        }
    }

    fn start_restore(&mut self, sha256: String, original_name: String) {
        self.restore_prompt = Some(RestorePrompt {
            sha256,
            file_name: original_name,
        });
    }

    fn poll_worker(&mut self, ctx: &egui::Context) {
        while let Some(event) = self.worker.try_recv() {
            match event {
                WorkerEvent::Snapshot(result) => match result {
                    Ok(snapshot) => self.snapshot = snapshot,
                    Err(error) => {
                        self.status = Some(StatusMessage {
                            text: error,
                            error: true,
                        });
                    }
                },
                WorkerEvent::ReportLoaded { report_id, result } => {
                    if self.selected_report_id == Some(report_id) {
                        self.busy = false;
                        self.busy_message = None;
                        match result {
                            Ok(Some(report)) => {
                                self.selected_report = Some(*report);
                            }
                            Ok(None) => {
                                self.status = Some(StatusMessage {
                                    text: "The stored report is no longer available".into(),
                                    error: true,
                                });
                            }
                            Err(error) => {
                                self.status = Some(StatusMessage {
                                    text: error,
                                    error: true,
                                });
                            }
                        }
                    }
                }
                WorkerEvent::ActionFinished { message, snapshot } => {
                    self.busy = false;
                    self.busy_message = None;
                    match message {
                        Ok(text) => {
                            self.status = Some(StatusMessage { text, error: false });
                            self.selected_report = None;
                            self.selected_report_id = None;
                            self.page = Page::Review;
                        }
                        Err(text) => {
                            self.status = Some(StatusMessage { text, error: true });
                        }
                    }
                    match snapshot {
                        Ok(snapshot) => self.snapshot = snapshot,
                        Err(error) => {
                            self.status = Some(StatusMessage {
                                text: error,
                                error: true,
                            });
                        }
                    }
                    self.last_refresh = Instant::now();
                    ctx.request_repaint();
                }
            }
        }
    }

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
                    self.page != Page::Quarantine,
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
                    ui.label(
                        RichText::new("Static analysis does not prove runtime safety.")
                            .size(10.0)
                            .color(MUTED),
                    );
                    ui.add_space(8.0);
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
                Page::Details => self.render_details(ui),
            });
    }

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

    fn render_details(&mut self, ui: &mut egui::Ui) {
        if ui.button("← Back to Review").clicked() {
            self.page = Page::Review;
            self.selected_report = None;
            self.selected_report_id = None;
        }
        ui.add_space(12.0);
        self.render_status(ui);

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
                        if let Some(reason) = report.certificate_problem_reason() {
                            reason_badge(ui, &compact_reason(reason), DANGER);
                        }
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
        let destination_exists =
            validation.is_ok() && self.config.download_dir.join(&prompt.file_name).exists();

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
                        self.config
                            .download_dir
                            .join(&prompt.file_name)
                            .display()
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
}

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

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = CANVAS;
    visuals.window_fill = PANEL;
    visuals.extreme_bg_color = Color32::from_rgb(9, 13, 12);
    visuals.faint_bg_color = PANEL_ALT;
    visuals.selection.bg_fill = ACCENT.gamma_multiply(0.3);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, MUTED);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, TEXT);
    ctx.set_visuals(visuals);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 7.0);
        style.spacing.button_padding = Vec2::new(10.0, 6.0);
        style
            .text_styles
            .insert(TextStyle::Heading, FontId::proportional(24.0));
        style
            .text_styles
            .insert(TextStyle::Body, FontId::proportional(13.0));
    });
}

#[derive(Clone, Copy)]
enum WindowButton {
    Minimize,
    Maximize,
    Close,
}

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
    let response = Frame::new()
        .fill(if selected {
            color.gamma_multiply(0.12)
        } else {
            Color32::TRANSPARENT
        })
        .inner_margin(egui::Margin::symmetric(10, 9))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (dot, _) = ui.allocate_exact_size(Vec2::splat(7.0), Sense::hover());
                ui.painter().circle_filled(dot.center(), 3.5, color);
                ui.label(RichText::new(label).size(13.0).color(if selected {
                    TEXT
                } else {
                    MUTED
                }));
                if let Some(count) = count {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(count.to_string())
                                .monospace()
                                .size(11.0)
                                .color(if selected { color } else { MUTED }),
                        );
                    });
                }
            });
        })
        .response
        .interact(Sense::click());
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

fn key_value(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            Vec2::new(82.0, 18.0),
            Label::new(RichText::new(key).size(10.5).color(MUTED)),
        );
        ui.label(RichText::new(value).monospace().size(10.5).color(TEXT));
    });
}

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

fn software_group_color(group: &super::data::SoftwareIdentityGroup) -> Color32 {
    if group.certificates.iter().any(|certificate| {
        matches!(
            certificate.state,
            SignatureState::Invalid | SignatureState::Revoked | SignatureState::Expired
        )
    }) {
        DANGER
    } else if group.certificates.iter().any(|certificate| {
        matches!(
            certificate.state,
            SignatureState::NotYetValid | SignatureState::Unsigned
        )
    }) {
        WARNING
    } else if group.certificates.iter().any(|certificate| {
        matches!(
            certificate.state,
            SignatureState::Unknown | SignatureState::Unverified
        )
    }) {
        BLUE
    } else {
        ACCENT
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
        SignatureState::Invalid | SignatureState::Revoked | SignatureState::Expired => DANGER,
        SignatureState::NotYetValid => WARNING,
        SignatureState::Unsigned => WARNING,
        SignatureState::Unknown => MUTED,
        SignatureState::Unverified => BLUE,
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
