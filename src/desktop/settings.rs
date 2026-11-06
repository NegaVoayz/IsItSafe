use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::fs;

use crate::config::{AppPaths, Config, RuntimeSettings, save_runtime_settings};
use crate::context_menu;
use crate::security::ensure_download_execution_barrier;
use crate::startup;

use super::monitor;

pub fn apply_runtime_settings(
    config: &RwLock<Config>,
    paths: &AppPaths,
    desired: RuntimeSettings,
) -> Result<String> {
    desired.validate()?;
    fs::create_dir_all(&desired.quarantine_dir).with_context(|| {
        format!(
            "failed to create quarantine directory {}",
            desired.quarantine_dir.display()
        )
    })?;

    let previous = config.read().clone();
    let location_changed = previous.download_dir != desired.download_dir
        || previous.storage.quarantine_dir != desired.quarantine_dir;
    if previous.security.block_execution_in_download_dir {
        ensure_download_execution_barrier(&desired.download_dir)?;
    }
    let startup_was_enabled = startup::is_enabled();
    let context_menu_was_enabled = context_menu::is_enabled();
    let registration = startup::set_enabled(desired.start_at_login)
        .and_then(|_| context_menu::set_enabled(desired.context_menu_enabled));
    if let Err(error) = registration {
        let _ = context_menu::set_enabled(context_menu_was_enabled);
        let _ = startup::set_enabled(startup_was_enabled);
        return Err(error);
    }
    if let Err(error) = save_runtime_settings(&paths.config_file, &desired) {
        let _ = startup::set_enabled(startup_was_enabled);
        let _ = context_menu::set_enabled(context_menu_was_enabled);
        return Err(error);
    }

    {
        let mut live = config.write();
        live.download_dir = desired.download_dir;
        live.storage.quarantine_dir = desired.quarantine_dir;
        live.runtime.monitor_enabled = desired.monitor_enabled;
        live.runtime.start_at_login = desired.start_at_login;
        live.runtime.context_menu_enabled = desired.context_menu_enabled;
    }

    let restart_monitor = location_changed && monitor::is_running();
    if restart_monitor || !desired.monitor_enabled {
        monitor::stop()?;
    }
    if desired.monitor_enabled {
        monitor::ensure_running()?;
    }

    Ok(if location_changed {
        "Settings saved. The monitor is using the new locations.".into()
    } else {
        "Settings saved.".into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuntimeSettings;

    #[test]
    fn settings_file_round_trip_uses_new_paths() {
        let directory = tempfile::tempdir().unwrap();
        let downloads = directory.path().join("downloads");
        let quarantine = directory.path().join("quarantine");
        fs::create_dir_all(&downloads).unwrap();
        let config_file = directory.path().join("config.toml");
        let settings = RuntimeSettings {
            download_dir: downloads.clone(),
            quarantine_dir: quarantine.clone(),
            monitor_enabled: false,
            start_at_login: false,
            context_menu_enabled: false,
        };

        save_runtime_settings(&config_file, &settings).unwrap();
        let loaded = Config::load(&config_file).unwrap();

        assert_eq!(loaded.download_dir, downloads);
        assert_eq!(loaded.storage.quarantine_dir, quarantine);
        assert!(!loaded.runtime.monitor_enabled);
        assert!(!loaded.runtime.context_menu_enabled);
    }
}
