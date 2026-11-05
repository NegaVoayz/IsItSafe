#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    Notification,
    Desktop,
}

/// Returns true when a report is actionable enough to interrupt the user.
pub fn should_notify(verdict: Verdict) -> bool {
    matches!(
        verdict,
        Verdict::Malicious
            | Verdict::Suspicious
            | Verdict::ReviewRequired
            | Verdict::Unverified
            | Verdict::Incomplete
    )
}

/// Registers the unpackaged app AUMID and the URI handler used by notification
/// buttons. Both registrations are per-user and require no administrator rights.
pub fn register_notification_identity() -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::register()
    }
    #[cfg(not(windows))]
    {
        bail!("Windows notifications are supported only on Windows")
    }
}

pub fn show_review_notification(report: &AnalysisReportV1) -> Result<()> {
    register_notification_identity()?;
    #[cfg(windows)]
    {
        windows_impl::show(report)
    }
    #[cfg(not(windows))]
    {
        let _ = report;
        bail!("Windows notifications are supported only on Windows")
    }
}

pub fn action_uri(action: UserDecision, report_id: Uuid) -> String {
    let action = match action {
        UserDecision::Keep => "keep",
        UserDecision::Quarantine => "quarantine",
        UserDecision::Remove => "remove",
    };
    format!("{ACTION_SCHEME}://{action}/{report_id}")
}

pub fn detail_action_uri(report_id: Uuid) -> String {
    format!("{ACTION_SCHEME}://detail/{report_id}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationAction {
    Decision(UserDecision),
    Detail(Uuid),
}

pub fn parse_notification_action(uri: &str) -> Result<NotificationAction> {
    let parsed = Url::parse(uri).context("invalid IsItSafe action URI")?;
    if parsed.scheme() != ACTION_SCHEME && parsed.scheme() != LEGACY_ACTION_SCHEME {
        bail!("unexpected action URI scheme");
    }
    let report_id = parsed
        .path()
        .trim_matches('/')
        .parse::<Uuid>()
        .context("invalid report ID in IsItSafe action URI")?;
    let action = match parsed.host_str() {
        Some("detail") => NotificationAction::Detail(report_id),
        Some("keep") => NotificationAction::Decision(UserDecision::Keep),
        Some("quarantine") => NotificationAction::Decision(UserDecision::Quarantine),
        Some("remove") => NotificationAction::Decision(UserDecision::Remove),
        _ => bail!("unknown IsItSafe notification action"),
    };
    Ok(action)
}

/// Handles a button click forwarded by the registered custom URI scheme.
pub fn handle_action_uri(
    uri: &str,
    config: &Config,
    database: &Database,
    paths: &AppPaths,
) -> Result<String> {
    let (decision, report_id) = parse_action_uri(uri)?;
    execute_user_decision(
        report_id,
        decision,
        DecisionSource::Notification,
        config,
        database,
        paths,
    )
}

