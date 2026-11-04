#![windows_subsystem = "windows"]

use anyhow::Result;
use isitsafe::config::{AppPaths, Config};
use isitsafe::db::Database;
use std::io::Write;

fn main() {
    if let Err(error) = run() {
        if let Ok(paths) = AppPaths::discover()
            && let Ok(()) = paths.ensure()
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(paths.logs_dir.join("native-host-errors.log"))
        {
            let _ = writeln!(file, "{}: {error:#}", chrono::Utc::now().to_rfc3339());
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config = Config::load_or_create(&paths.config_file)?;
    config.validate()?;
    let database = Database::open_with_recovery(&paths.database)?;
    isitsafe::origin::run_native_host(&config, &database)
}
