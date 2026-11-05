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
    last_content_scroll: Option<Instant>,
}
