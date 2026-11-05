pub fn execute_user_decision(
    report_id: Uuid,
    decision: UserDecision,
    source: DecisionSource,
    config: &Config,
    database: &Database,
    paths: &AppPaths,
) -> Result<String> {
    let report_id_text = report_id.to_string();
    let mut report = database
        .report_by_id(&report_id_text)?
        .with_context(|| format!("no stored report for {report_id_text}"))?;
    if let Some(existing) = report.policy.user_decision {
        let message = format!("This notification was already handled: {existing:?}");
        if source == DecisionSource::Notification {
            let _ = show_status_notification("IsItSafe", &message);
        }
        return Ok(message);
    }
    let source_path = PathBuf::from(&report.file.display_path);
    report.source_path = Some(source_path);

    match decision {
        UserDecision::Keep => {
            report.policy.user_decision = Some(UserDecision::Keep);
            report.policy.quarantine_requested = false;
            report.policy.action = PolicyAction::Notify;
        }
        UserDecision::Quarantine => {
            report.policy.user_decision = Some(UserDecision::Quarantine);
            report.policy.quarantine_requested = true;
            report.policy.action = PolicyAction::Quarantine;
            match apply_quarantine(&report, config, database, &paths.quarantine_dir) {
                Ok(Some(destination)) => {
                    report.policy.quarantine_path =
                        Some(destination.to_string_lossy().into_owned());
                }
                Ok(None) => bail!("quarantine was not performed"),
                Err(error) => {
                    if source == DecisionSource::Notification {
                        let _ = show_status_notification(
                            "IsItSafe quarantine failed",
                            &format!("{}: {error}", clean(&report.file.display_path)),
                        );
                    }
                    return Err(error);
                }
            }
        }
        UserDecision::Remove => {
            report.policy.user_decision = Some(UserDecision::Remove);
            report.policy.quarantine_requested = false;
            if let Err(error) = remove_verified(&report, config) {
                if source == DecisionSource::Notification {
                    let _ = show_status_notification(
                        "IsItSafe removal cancelled",
                        &format!("{}: {error}", clean(&report.file.display_path)),
                    );
                }
                return Err(error);
            }
            report.policy.action = PolicyAction::UserRemoved;
        }
    }

    database.store_report(&report)?;
    let state = match decision {
        UserDecision::Keep => "complete",
        UserDecision::Quarantine => "quarantined",
        UserDecision::Remove => "removed",
    };
    database.update_observation_state(&report.file.display_path, state)?;
    append_report(paths, &report)?;
    let message = match decision {
        UserDecision::Keep => "File kept. Downloads execution blocking remains active.",
        UserDecision::Quarantine => "File moved to the recoverable quarantine.",
        UserDecision::Remove => "File permanently removed after hash verification.",
    };
    if source == DecisionSource::Notification {
        let _ = show_status_notification("IsItSafe action completed", message);
    }
    Ok(message.into())
}

pub fn validate_download_file_name(name: &str) -> Result<()> {
    if name.is_empty() || name.trim() != name {
        bail!("the filename must be non-empty without leading or trailing spaces");
    }
    if name == "." || name == ".." || name.ends_with('.') || name.ends_with(' ') {
        bail!("the filename must not end with a dot or space");
    }
    if name.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
    }) {
        bail!("the filename contains a character that Windows does not allow");
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'));
    if reserved {
        bail!("the filename is reserved by Windows");
    }
    let path = Path::new(name);
    if path.components().count() != 1
        || path.file_name().and_then(|value| value.to_str()) != Some(name)
    {
        bail!("the filename must not contain a directory");
    }
    Ok(())
}

pub fn restore_quarantine_from_desktop(
    database: &Database,
    config: &Config,
    paths: &AppPaths,
    sha256: &str,
    destination_name: &str,
) -> Result<String> {
    validate_download_file_name(destination_name)?;
    let destination = config.download_dir.join(destination_name);
    if destination.exists() {
        bail!("a file named {destination_name} already exists in Downloads");
    }
    super::policy::restore_quarantine(database, config, sha256, &destination)?;

    if let Some(mut report) = database.report_by_sha256(sha256)? {
        report.file.display_path = destination.to_string_lossy().into_owned();
        report.file.full_path_redacted = Some(destination_name.to_string());
        report.source_path = Some(destination.clone());
        // Restoring is not a Keep decision. The file must return to Review so
        // the user can inspect it again while the execution barrier stays on.
        report.policy.user_decision = None;
        report.policy.quarantine_requested = false;
        report.policy.quarantine_path = None;
        report.policy.action = PolicyAction::RequireReview;
        database.store_report(&report)?;
        database.upsert_observation(&crate::db::Observation {
            path: destination.to_string_lossy().into_owned(),
            volume_identity: report.file.volume_identity.clone(),
            file_id: report.file.file_id.clone(),
            size: report.file.size,
            modified_ns: report
                .file
                .modified_at
                .map(|time| time.timestamp_nanos_opt().unwrap_or_default()),
            sha256: report.file.sha256.clone(),
            state: "complete".into(),
            updated_at: Utc::now(),
        })?;
        append_report(paths, &report)?;
    }

    Ok("File is available in Review.".into())
}

pub fn parse_action_uri(uri: &str) -> Result<(UserDecision, Uuid)> {
    match parse_notification_action(uri)? {
        NotificationAction::Decision(decision) => {
            let parsed = Url::parse(uri)?;
            let report_id = parsed
                .path()
                .trim_matches('/')
                .parse::<Uuid>()
                .context("invalid report ID in IsItSafe action URI")?;
            Ok((decision, report_id))
        }
        NotificationAction::Detail(_) => {
            bail!("the notification action does not represent a decision")
        }
    }
}

