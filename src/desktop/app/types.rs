#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Review,
    Quarantine,
    Settings,
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

struct SettingsDraft {
    download_dir: String,
    quarantine_dir: String,
    monitor_enabled: bool,
    start_at_login: bool,
    context_menu_enabled: bool,
}

pub(super) struct DesktopApp {
    config: Arc<parking_lot::RwLock<Config>>,
    paths: Arc<AppPaths>,
    worker: Worker,
    snapshot: DesktopSnapshot,
    page: Page,
    selected_report_id: Option<Uuid>,
    selected_report: Option<AnalysisReportV1>,
    restore_prompt: Option<RestorePrompt>,
    settings: SettingsDraft,
    status: Option<StatusMessage>,
    busy: bool,
    busy_message: Option<&'static str>,
    monitor_running: bool,
    last_refresh: Instant,
    last_monitor_check: Instant,
    last_detail_request_check: Instant,
    last_content_scroll: Option<Instant>,
}
