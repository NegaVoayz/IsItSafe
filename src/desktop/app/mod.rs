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
const SCROLLBAR_REVEAL_GUTTER: f32 = 36.0;
const SCROLLBAR_REVEAL_AFTER_SCROLL: Duration = Duration::from_millis(650);

include!("types.rs");
include!("lifecycle.rs");
include!("frame.rs");
include!("pages/review.rs");
include!("pages/details.rs");
include!("interaction.rs");
include!("traits.rs");
include!("style.rs");
include!("widgets/common.rs");
include!("widgets/primitives.rs");
include!("widgets/inventory.rs");
include!("widgets/software.rs");
include!("helpers.rs");

#[cfg(test)]
mod tests {
    include!("tests/scroll.rs");
}
