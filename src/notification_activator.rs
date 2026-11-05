use anyhow::{Context, Result, bail};

#[cfg(windows)]
pub fn attach(notification: &windows::UI::Notifications::ToastNotification) -> Result<()> {
    windows_impl::attach(notification)
}

#[cfg(not(windows))]
pub fn attach(_notification: &()) -> Result<()> {
    bail!("Windows notification activation is supported only on Windows")
}

pub fn handle_activation_arguments(arguments: &str) -> Result<()> {
    use crate::config::{AppPaths, Config};
    use crate::db::Database;
    use crate::desktop;
    use crate::interaction::{NotificationAction, handle_action_uri, parse_notification_action};

    if !arguments.trim().is_empty() {
        match parse_notification_action(arguments)
            .with_context(|| format!("invalid notification arguments: {arguments}"))?
        {
            NotificationAction::Decision(_) => {
                let paths = AppPaths::discover()?;
                paths.ensure()?;
                let config = Config::load_or_create(&paths.config_file)?;
                config.validate()?;
                let database = Database::open_with_recovery(&paths.database)?;
                handle_action_uri(arguments, &config, &database, &paths)?;
                return Ok(());
            }
            NotificationAction::Detail(report_id) => {
                let paths = AppPaths::discover()?;
                paths.ensure()?;
                let database = Database::open_with_recovery(&paths.database)?;
                if database.report_by_id(&report_id.to_string())?.is_none() {
                    bail!("the stored report for {report_id} is unavailable");
                }
                desktop::open_details(&paths, report_id)?;
            }
        }
    }

    let executable = std::env::current_exe().context("cannot locate the IsItSafe executable")?;
    std::process::Command::new(executable)
        .spawn()
        .context("failed to open the IsItSafe desktop workspace")?;
    Ok(())
}

#[cfg(windows)]
mod windows_impl {
    use std::collections::VecDeque;
    use std::sync::{Mutex, OnceLock};

    use anyhow::Result;
    use windows::Foundation::TypedEventHandler;
    use windows::UI::Notifications::{ToastActivatedEventArgs, ToastNotification};
    use windows::core::{IInspectable, Interface};

    use super::handle_activation_arguments;

    const RETAINED_TOASTS: usize = 64;
    static ACTIVE_TOASTS: OnceLock<Mutex<VecDeque<ToastNotification>>> = OnceLock::new();

    pub(super) fn attach(notification: &ToastNotification) -> Result<()> {
        let handler = TypedEventHandler::<ToastNotification, IInspectable>::new(|_, args| {
            let arguments = args
                .as_ref()
                .and_then(|value| value.cast::<ToastActivatedEventArgs>().ok())
                .and_then(|value| value.Arguments().ok())
                .map(|value| value.to_string())
                .unwrap_or_default();
            let _ = handle_activation_arguments(&arguments);
            Ok(())
        });
        notification.Activated(&handler)?;

        let mut active = ACTIVE_TOASTS
            .get_or_init(|| Mutex::new(VecDeque::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while active.len() >= RETAINED_TOASTS {
            active.pop_front();
        }
        active.push_back(notification.clone());
        Ok(())
    }
}
