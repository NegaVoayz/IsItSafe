use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "IsItSafe";
const LEGACY_STARTUP_NAME: &str = "IsItSafe Monitor.lnk";
const HRESULT_FROM_WIN32_FILE_NOT_FOUND: i32 = -2_147_024_894;

pub fn is_enabled() -> bool {
    registry_is_enabled() || legacy_shortcut_path().is_some_and(|path| path.is_file())
}

pub fn set_enabled(enabled: bool) -> Result<()> {
    if enabled {
        enable_registration()?;
        remove_legacy_shortcut()?;
    } else {
        disable_registration()?;
        remove_legacy_shortcut()?;
    }
    Ok(())
}

pub fn launch_background_monitor() -> Result<std::process::Child> {
    let executable = std::env::current_exe().context("cannot locate the IsItSafe executable")?;
    background_command(&executable)
        .spawn()
        .with_context(|| format!("failed to start {}", executable.display()))
}

pub fn background_command(executable: &Path) -> Command {
    let mut command = Command::new(executable);
    if executable
        .file_stem()
        .is_some_and(|value| value.eq_ignore_ascii_case("isitsafe"))
    {
        command.arg("ui").arg("--background");
    } else {
        command.arg("--background");
    }
    command
}

fn startup_command(executable: &Path) -> String {
    let arguments = if executable
        .file_stem()
        .is_some_and(|value| value.eq_ignore_ascii_case("isitsafe"))
    {
        "ui --background"
    } else {
        "--background"
    };
    format!("\"{}\" {arguments}", executable.display())
}

fn legacy_shortcut_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|appdata| {
        PathBuf::from(appdata)
            .join(r"Microsoft\Windows\Start Menu\Programs\Startup")
            .join(LEGACY_STARTUP_NAME)
    })
}

fn remove_legacy_shortcut() -> Result<()> {
    let Some(path) = legacy_shortcut_path() else {
        return Ok(());
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

#[cfg(windows)]
fn registry_is_enabled() -> bool {
    use windows_registry::CURRENT_USER;

    CURRENT_USER
        .open(RUN_KEY)
        .and_then(|key| key.get_string(VALUE_NAME))
        .is_ok()
}

#[cfg(not(windows))]
fn registry_is_enabled() -> bool {
    false
}

#[cfg(windows)]
fn enable_registration() -> Result<()> {
    use windows_registry::CURRENT_USER;

    let executable = std::env::current_exe().context("cannot locate the IsItSafe executable")?;
    let key = CURRENT_USER
        .create(RUN_KEY)
        .context("failed to open the per-user startup registry key")?;
    key.set_string(VALUE_NAME, startup_command(&executable))
        .context("failed to register IsItSafe at sign-in")
}

#[cfg(not(windows))]
fn enable_registration() -> Result<()> {
    anyhow::bail!("sign-in startup is supported only on Windows")
}

#[cfg(windows)]
fn disable_registration() -> Result<()> {
    use windows_registry::CURRENT_USER;

    let Ok(key) = CURRENT_USER.options().read().write().open(RUN_KEY) else {
        return Ok(());
    };
    match key.remove_value(VALUE_NAME) {
        Ok(()) => Ok(()),
        Err(error) => {
            // Removing a missing registration is already the desired state.
            if error.code().0 == HRESULT_FROM_WIN32_FILE_NOT_FOUND {
                return Ok(());
            }
            Err(error).context("failed to remove the IsItSafe sign-in registration")
        }
    }
}

#[cfg(not(windows))]
fn disable_registration() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_command_quotes_paths_and_uses_the_ui_flag() {
        let command = startup_command(Path::new(r"C:\Program Files\IsItSafe\isitsafe-ui.exe"));
        assert_eq!(
            command,
            r#""C:\Program Files\IsItSafe\isitsafe-ui.exe" --background"#
        );
    }

    #[test]
    fn console_binary_starts_the_ui_subcommand() {
        let command = startup_command(Path::new(r"C:\Tools\isitsafe.exe"));
        assert_eq!(command, r#""C:\Tools\isitsafe.exe" ui --background"#);
    }
}
