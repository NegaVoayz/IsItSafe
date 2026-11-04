#![windows_subsystem = "windows"]

use anyhow::Result;
use isitsafe::config::{AppPaths, Config};
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
    let background = std::env::args().any(|argument| argument == "--background");
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config = Config::load_or_create(&paths.config_file)?;
    config.validate()?;
    isitsafe::logging::initialize(&paths, &config)?;
    isitsafe::desktop::run(config, paths, !background)
}
