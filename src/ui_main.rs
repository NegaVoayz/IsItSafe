#![windows_subsystem = "windows"]

use anyhow::{Result, anyhow};
use isitsafe::config::{AppPaths, Config};
use isitsafe::db::Database;
use isitsafe::interaction::handle_action_uri;
use isitsafe::sandbox::{is_internal_child_invocation, run_child_main};
use std::io::Write;

fn main() {
    if let Err(error) = run()
        && let Ok(paths) = AppPaths::discover()
        && let Ok(()) = paths.ensure()
        && let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(paths.logs_dir.join("ui-errors.log"))
    {
        let _ = writeln!(file, "{}: {error:#}", chrono::Utc::now().to_rfc3339());
    }
}

fn run() -> Result<()> {
    if is_internal_child_invocation() {
        return run_child_main();
    }
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|value| value == "handle-action")
    {
        let uri = arguments
            .get(1)
            .ok_or_else(|| anyhow!("notification action URI is missing"))?;
        let paths = AppPaths::discover()?;
        paths.ensure()?;
        let config = Config::load_or_create(&paths.config_file)?;
        config.validate()?;
        isitsafe::logging::initialize(&paths, &config)?;
        let database = Database::open_with_recovery(&paths.database)?;
        handle_action_uri(uri, &config, &database, &paths)?;
        return Ok(());
    }
    let background = arguments.iter().any(|argument| argument == "--background");
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config = Config::load_or_create(&paths.config_file)?;
    config.validate()?;
    isitsafe::logging::initialize(&paths, &config)?;
    isitsafe::desktop::run(config, paths, !background)
}
