use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const MENU_KEY: &str = r"Software\Classes\*\shell\IsItSafe";
const COMMAND_KEY: &str = r"Software\Classes\*\shell\IsItSafe\command";

pub fn is_enabled() -> bool {
    registry_is_enabled()
}

pub fn set_enabled(enabled: bool) -> Result<()> {
    if enabled {
        enable_registration()
    } else {
        disable_registration()
    }
}

fn desktop_executable(current: &Path) -> Result<PathBuf> {
    if current
        .file_stem()
        .is_some_and(|value| value.eq_ignore_ascii_case("isitsafe"))
    {
        let desktop = current.with_file_name("isitsafe-ui.exe");
        if !desktop.is_file() {
            anyhow::bail!("desktop executable not found at {}", desktop.display());
        }
        Ok(desktop)
    } else {
        Ok(current.to_path_buf())
    }
}

fn scan_file_command(executable: &Path) -> String {
    format!("\"{}\" --scan-file \"%1\"", executable.display())
}

#[cfg(windows)]
fn registry_is_enabled() -> bool {
    use windows_registry::CURRENT_USER;

    CURRENT_USER
        .open(COMMAND_KEY)
        .and_then(|key| key.get_string(""))
        .is_ok_and(|command| !command.trim().is_empty())
}

#[cfg(not(windows))]
fn registry_is_enabled() -> bool {
    false
}

#[cfg(windows)]
fn enable_registration() -> Result<()> {
    use windows_registry::CURRENT_USER;

    let current = std::env::current_exe().context("cannot locate the IsItSafe executable")?;
    let executable = desktop_executable(&current)?;
    let menu = CURRENT_USER
        .create(MENU_KEY)
        .context("failed to open the Explorer context-menu registry key")?;
    menu.set_string("", "Is It Safe?")
        .context("failed to label the Explorer context-menu action")?;
    menu.set_string("Icon", executable.display().to_string())
        .context("failed to set the Explorer context-menu icon")?;
    let command = CURRENT_USER
        .create(COMMAND_KEY)
        .context("failed to open the Explorer context-menu command key")?;
    command
        .set_string("", scan_file_command(&executable))
        .context("failed to register the Explorer context-menu command")
}

#[cfg(not(windows))]
fn enable_registration() -> Result<()> {
    anyhow::bail!("Explorer context-menu integration is supported only on Windows")
}

#[cfg(windows)]
fn disable_registration() -> Result<()> {
    use windows_registry::CURRENT_USER;

    if CURRENT_USER.open(MENU_KEY).is_err() {
        return Ok(());
    }
    CURRENT_USER
        .remove_tree(MENU_KEY)
        .context("failed to remove the IsItSafe Explorer context-menu action")
}

#[cfg(not(windows))]
fn disable_registration() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_command_quotes_the_executable_and_selected_file() {
        assert_eq!(
            scan_file_command(Path::new(r"C:\Program Files\IsItSafe\isitsafe-ui.exe")),
            r#""C:\Program Files\IsItSafe\isitsafe-ui.exe" --scan-file "%1""#
        );
    }

    #[test]
    fn console_installations_use_the_sibling_desktop_binary() {
        let directory = tempfile::tempdir().unwrap();
        let desktop = directory.path().join("isitsafe-ui.exe");
        std::fs::write(&desktop, []).unwrap();
        let console = directory.path().join("isitsafe.exe");

        assert_eq!(desktop_executable(&console).unwrap(), desktop);
    }
}
