use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use url::Url;
use uuid::Uuid;

use crate::config::{AppPaths, Config};
use crate::db::Database;
use crate::policy::{apply_quarantine, remove_verified};
use crate::report::{
    AnalysisReportV1, PolicyAction, ReputationState, Severity, UserDecision, Verdict,
};

pub const APP_USER_MODEL_ID: &str = "IsItSafe.Desktop";
pub const ACTION_SCHEME: &str = "isitsafe";
const LEGACY_ACTION_SCHEME: &str = "isitsafe-action";
#[cfg(windows)]
const LEGACY_BROKEN_ACTIVATOR_CLSID: &str = "980b8b22-b56a-4bf3-a73e-44d157f9a3b7";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    Notification,
    Desktop,
}

impl DecisionSource {
    fn phrase(self) -> &'static str {
        match self {
            Self::Notification => "the Windows notification",
            Self::Desktop => "the desktop review workspace",
        }
    }
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
            report
                .policy
                .reasons
                .push(format!("The user kept the file from {}", source.phrase()));
        }
        UserDecision::Quarantine => {
            report.policy.user_decision = Some(UserDecision::Quarantine);
            report.policy.quarantine_requested = true;
            report.policy.action = PolicyAction::Quarantine;
            report.policy.reasons.push(format!(
                "The user quarantined the file from {}",
                source.phrase()
            ));
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
            report.policy.reasons.push(format!(
                "The user removed the file from {}",
                source.phrase()
            ));
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
        report.policy.reasons.push(format!(
            "The user restored the file to Downloads as {destination_name}; execution remains blocked"
        ));
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

fn show_status_notification(title: &str, message: &str) -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::show_status(title, message)
    }
    #[cfg(not(windows))]
    {
        let _ = (title, message);
        Ok(())
    }
}

fn append_report(paths: &AppPaths, report: &AnalysisReportV1) -> Result<()> {
    let json = serde_json::to_string(report)?;
    let day = Utc::now().format("%Y-%m-%d");
    let report_path = paths.reports_dir.join(format!("{day}.jsonl"));
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&report_path)
        .with_context(|| format!("failed to open {}", report_path.display()))?;
    writeln!(file, "{json}")?;
    Ok(())
}

fn display_name(report: &AnalysisReportV1) -> String {
    report
        .source_path
        .as_deref()
        .and_then(Path::file_name)
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            Path::new(&report.file.display_path)
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| report.file.display_path.clone())
        })
}

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(windows)]
mod windows_impl {
    use std::mem::{ManuallyDrop, zeroed};
    use std::path::Path;
    use std::thread;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{
        NotificationSetting, ToastNotification, ToastNotificationManager,
    };
    use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, S_OK};
    use windows::Win32::Storage::EnhancedStorage::{
        PKEY_AppUserModel_ID, PKEY_AppUserModel_ToastActivatorCLSID,
    };
    use windows::Win32::System::Com::StructuredStorage::{
        PROPVARIANT, PROPVARIANT_0_0, PROPVARIANT_0_0_0, PropVariantClear,
    };
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoTaskMemAlloc, CoUninitialize, IPersistFile,
    };
    use windows::Win32::System::Variant::VT_LPWSTR;
    use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::core::{HSTRING, IUnknown, Interface, PWSTR};
    use windows_registry::CURRENT_USER;
    use windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;

    use super::{
        ACTION_SCHEME, APP_USER_MODEL_ID, AnalysisReportV1, LEGACY_ACTION_SCHEME,
        LEGACY_BROKEN_ACTIVATOR_CLSID, ReputationState, Severity, UserDecision, Verdict,
        action_uri, clean, detail_action_uri, display_name,
    };

    pub(super) fn register() -> Result<()> {
        let executable =
            std::env::current_exe().context("failed to locate the IsItSafe executable")?;
        let app_id: Vec<u16> = APP_USER_MODEL_ID
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let result = unsafe { SetCurrentProcessExplicitAppUserModelID(app_id.as_ptr()) };
        if result < 0 {
            anyhow::bail!(
                "SetCurrentProcessExplicitAppUserModelID failed with HRESULT 0x{:08x}",
                result as u32
            );
        }
        let aumid = format!(r"SOFTWARE\Classes\AppUserModelId\{APP_USER_MODEL_ID}");
        let key = CURRENT_USER.create(&aumid)?;
        key.set_string("DisplayName", "IsItSafe")?;
        key.set_string("IconUri", executable.display().to_string())?;
        key.set_string("IconBackgroundColor", "0")?;

        register_action_scheme(ACTION_SCHEME, &executable)?;
        // Existing toasts may still point at the original scheme name.
        register_action_scheme(LEGACY_ACTION_SCHEME, &executable)?;
        let _ = CURRENT_USER.remove_tree(format!(
            r"SOFTWARE\Classes\CLSID\{{{LEGACY_BROKEN_ACTIVATOR_CLSID}}}"
        ));
        create_start_menu_shortcut(&executable)?;
        Ok(())
    }

    fn register_action_scheme(scheme_name: &str, executable: &Path) -> Result<()> {
        let scheme = CURRENT_USER.create(format!(r"SOFTWARE\Classes\{scheme_name}"))?;
        scheme.set_string("", "URL:IsItSafe notification action")?;
        scheme.set_string("URL Protocol", "")?;
        let command = CURRENT_USER.create(format!(
            r"SOFTWARE\Classes\{scheme_name}\shell\open\command"
        ))?;
        command.set_string(
            "",
            format!("\"{}\" handle-action \"%1\"", executable.display()),
        )?;
        Ok(())
    }

    fn create_start_menu_shortcut(executable: &Path) -> Result<()> {
        let appdata = std::env::var_os("APPDATA").context("APPDATA is unavailable")?;
        let shortcut_path = Path::new(&appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("IsItSafe.lnk");
        if let Some(parent) = shortcut_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if initialized.is_err() && initialized != RPC_E_CHANGED_MODE {
            anyhow::bail!("CoInitializeEx failed with HRESULT 0x{:08x}", initialized.0);
        }
        let result = (|| {
            let link: IShellLinkW =
                unsafe { CoCreateInstance(&ShellLink, None::<&IUnknown>, CLSCTX_INPROC_SERVER)? };
            let executable_text = HSTRING::from(executable.as_os_str());
            let shortcut_text = HSTRING::from(shortcut_path.as_os_str());
            unsafe {
                link.SetPath(&executable_text)?;
                link.SetArguments(&HSTRING::from("watch"))?;
                link.SetDescription(&HSTRING::from("IsItSafe download safety checker"))?;
                link.SetIconLocation(&executable_text, 0)?;
            }

            let store: IPropertyStore = link.cast()?;
            let mut app_id = prop_variant_string(APP_USER_MODEL_ID)?;
            let no_activator = PROPVARIANT::default();
            let property_result: Result<()> = (|| {
                unsafe {
                    store.SetValue(&PKEY_AppUserModel_ID, &app_id)?;
                    store.SetValue(&PKEY_AppUserModel_ToastActivatorCLSID, &no_activator)?;
                    store.Commit()?;
                }
                Ok(())
            })();
            unsafe {
                PropVariantClear(&mut app_id)?;
            }
            property_result?;

            let persist: IPersistFile = link.cast()?;
            unsafe {
                persist.Save(&shortcut_text, true)?;
            }
            Ok(())
        })();
        if initialized == S_OK {
            unsafe {
                CoUninitialize();
            }
        }
        result
    }

    fn prop_variant_string(value: &str) -> Result<PROPVARIANT> {
        let utf16: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = utf16.len() * std::mem::size_of::<u16>();
        let memory = unsafe { CoTaskMemAlloc(bytes) };
        if memory.is_null() {
            anyhow::bail!("CoTaskMemAlloc failed while setting the AppUserModelID");
        }
        unsafe {
            std::ptr::copy_nonoverlapping(utf16.as_ptr().cast::<u8>(), memory.cast::<u8>(), bytes);
        }
        let mut inner: PROPVARIANT_0_0 = unsafe { zeroed() };
        inner.vt = VT_LPWSTR;
        inner.Anonymous = PROPVARIANT_0_0_0 {
            pwszVal: PWSTR(memory.cast()),
        };
        let mut variant = PROPVARIANT::default();
        variant.Anonymous.Anonymous = ManuallyDrop::new(inner);
        Ok(variant)
    }

    pub(super) fn show(report: &AnalysisReportV1) -> Result<()> {
        let verdict = verdict_label(report.verdict);
        let filename = display_name(report);
        let title = format!("{verdict}: {filename}");
        let mut facts = Vec::new();
        if !report.classification.formats.is_empty() {
            facts.push(
                report
                    .classification
                    .formats
                    .iter()
                    .map(|format| format.kind.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        if let Some(reputation) = report
            .reputation
            .iter()
            .find(|entry| entry.state == ReputationState::Malicious)
        {
            facts.push(match (reputation.detections, reputation.engines_total) {
                (Some(detections), Some(total)) => {
                    format!("VirusTotal {detections}/{total}")
                }
                _ => "VirusTotal: malicious".into(),
            });
        }
        facts.push(format!("{} components", report.components.len()));
        let detail = report
            .file
            .sha256
            .as_deref()
            .map(|hash| format!("SHA-256 {}", &hash[..hash.len().min(24)]))
            .unwrap_or_else(|| "No complete hash available".into());
        let reason = report
            .facts
            .iter()
            .find(|evidence| evidence.severity >= Severity::Medium)
            .map(|evidence| clean(&evidence.summary))
            .or_else(|| report.policy.reasons.first().cloned())
            .unwrap_or_else(|| "Review required".into());

        let xml = format!(
            r#"<toast duration="long" scenario="reminder">
<visual><binding template="ToastGeneric">
<text id="1">{}</text>
<text id="2">{}</text>
<text id="3">{}</text>
<text id="4">{}</text>
</binding></visual>
<actions>
<action content="Detail" arguments="{}" activationType="foreground" />
<action content="Quarantine" arguments="{}" activationType="foreground" />
<action content="Remove" arguments="{}" activationType="foreground" />
</actions>
</toast>"#,
            xml_text(&title),
            xml_text(&facts.join("  •  ")),
            xml_text(&detail),
            xml_text(&reason),
            xml_attribute(&detail_action_uri(report.report_id)),
            xml_attribute(&action_uri(UserDecision::Quarantine, report.report_id)),
            xml_attribute(&action_uri(UserDecision::Remove, report.report_id)),
        );
        show_xml(&xml, Some(&report.report_id.to_string()[..16]))
    }

    pub(super) fn show_status(title: &str, message: &str) -> Result<()> {
        let xml = format!(
            r#"<toast duration="short"><visual><binding template="ToastGeneric">
<text id="1">{}</text><text id="2">{}</text>
</binding></visual></toast>"#,
            xml_text(title),
            xml_text(message),
        );
        show_xml(&xml, None)
    }

    fn show_xml(xml: &str, tag: Option<&str>) -> Result<()> {
        let document = XmlDocument::new()?;
        document.LoadXml(&HSTRING::from(xml))?;
        let notification = ToastNotification::CreateToastNotification(&document)?;
        if let Some(tag) = tag {
            notification.SetTag(&HSTRING::from(tag))?;
            crate::notification_activator::attach(&notification)?;
        }
        let notifier =
            ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_USER_MODEL_ID))?;
        let setting = notifier.Setting()?;
        if setting != NotificationSetting::Enabled {
            anyhow::bail!(
                "Windows notifications are disabled for {APP_USER_MODEL_ID} (setting {})",
                setting.0
            );
        }
        notifier.Show(&notification)?;
        // Windows may silently drop a toast when the posting process exits
        // immediately after Show returns.
        thread::sleep(Duration::from_millis(50));
        let history = ToastNotificationManager::History()?
            .GetHistoryWithId(&HSTRING::from(APP_USER_MODEL_ID))?;
        if history.Size()? == 0 {
            anyhow::bail!(
                "Windows Show() returned success, but no notification was recorded for {APP_USER_MODEL_ID}"
            );
        }
        Ok(())
    }

    fn verdict_label(verdict: Verdict) -> &'static str {
        match verdict {
            Verdict::Malicious => "Malicious",
            Verdict::Suspicious => "Suspicious",
            Verdict::ReviewRequired => "Review required",
            Verdict::Unverified => "Unverified",
            Verdict::Limited => "Limited check",
            Verdict::Incomplete => "Incomplete check",
            Verdict::BasicCheckOnly => "Basic check only",
            Verdict::NoHighRiskFound => "No high-risk evidence found",
        }
    }

    fn xml_text(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn xml_attribute(value: &str) -> String {
        xml_text(value)
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppPaths, Config};
    use crate::db::Database;
    use crate::report::{AnalysisReportV1, FileEvidence};
    use sha2::{Digest, Sha256};

    #[test]
    fn notification_action_uri_round_trips() {
        let report_id = Uuid::new_v4();
        let uri = action_uri(UserDecision::Quarantine, report_id);
        assert_eq!(
            parse_action_uri(&uri).unwrap(),
            (UserDecision::Quarantine, report_id)
        );
    }

    #[test]
    fn notification_detail_uri_round_trips() {
        let report_id = Uuid::new_v4();
        let uri = detail_action_uri(report_id);
        assert_eq!(uri, format!("isitsafe://detail/{report_id}"));
        assert_eq!(
            parse_notification_action(&uri).unwrap(),
            NotificationAction::Detail(report_id)
        );
    }

    #[test]
    fn legacy_notification_actions_remain_compatible() {
        let report_id = Uuid::new_v4();
        let uri = format!("isitsafe-action://keep/{report_id}");
        assert_eq!(
            parse_notification_action(&uri).unwrap(),
            NotificationAction::Decision(UserDecision::Keep)
        );
    }

    #[test]
    fn only_actionable_verdicts_raise_notifications() {
        assert!(should_notify(Verdict::Malicious));
        assert!(should_notify(Verdict::ReviewRequired));
        assert!(!should_notify(Verdict::NoHighRiskFound));
        assert!(!should_notify(Verdict::BasicCheckOnly));
    }

    #[test]
    fn restore_filename_is_a_single_safe_windows_name() {
        assert!(validate_download_file_name("setup (restored).exe").is_ok());
        for invalid in [
            "",
            "..\\outside.exe",
            "folder/file.exe",
            "CON.txt",
            "LPT1.log",
            "bad:name.exe",
            "trailing.exe.",
            " padded.exe",
        ] {
            assert!(
                validate_download_file_name(invalid).is_err(),
                "{invalid:?} should be rejected"
            );
        }
    }

    #[test]
    fn desktop_quarantine_and_restore_round_trip_through_verified_paths() {
        let root = tempfile::tempdir().unwrap();
        let downloads = root.path().join("Downloads");
        let quarantine = root.path().join("quarantine");
        std::fs::create_dir_all(&downloads).unwrap();
        let source = downloads.join("sample.exe");
        let bytes = b"verified test content";
        std::fs::write(&source, bytes).unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        let mut config = Config {
            download_dir: downloads.clone(),
            ..Config::default()
        };
        config.security.block_execution_in_download_dir = false;
        let paths = AppPaths {
            config_file: root.path().join("config.toml"),
            data_dir: root.path().to_path_buf(),
            database: root.path().join("state.db"),
            reports_dir: root.path().join("reports"),
            logs_dir: root.path().join("logs"),
            quarantine_dir: quarantine.clone(),
            rules_dir: root.path().join("rules"),
        };
        paths.ensure().unwrap();
        let database = Database::open(&paths.database).unwrap();
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: source.to_string_lossy().into_owned(),
            extension: Some("exe".into()),
            size: bytes.len() as u64,
            sha256: Some(hash.clone()),
            ..FileEvidence::default()
        });
        report.verdict = Verdict::Malicious;
        report.policy.action = PolicyAction::AwaitUserDecision;
        report.policy.reasons.push("test quarantine reason".into());
        database.store_report(&report).unwrap();

        execute_user_decision(
            report.report_id,
            UserDecision::Quarantine,
            DecisionSource::Desktop,
            &config,
            &database,
            &paths,
        )
        .unwrap();
        assert!(!source.exists());
        assert_eq!(database.list_quarantine().unwrap().len(), 1);

        restore_quarantine_from_desktop(&database, &config, &paths, &hash, "sample.exe").unwrap();
        assert!(source.exists());
        assert!(database.list_quarantine().unwrap().is_empty());
        let restored = database.report_by_sha256(&hash).unwrap().unwrap();
        assert_eq!(restored.policy.user_decision, None);
        assert!(
            restored
                .policy
                .reasons
                .iter()
                .any(|reason| { reason.contains("restored the file to Downloads as sample.exe") })
        );
    }
}
