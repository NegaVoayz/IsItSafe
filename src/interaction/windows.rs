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

