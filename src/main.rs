use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use isitsafe::Watcher;
use isitsafe::config::{AppPaths, Config};
use isitsafe::db::Database;
use isitsafe::interaction::{NotificationAction, parse_notification_action};
use isitsafe::policy::{prune_quarantine, restore_quarantine};
use isitsafe::sandbox::{is_internal_child_invocation, run_child_main};
use isitsafe::secrets::store_virus_total_api_key;
use isitsafe::security::ensure_download_execution_barrier;

#[derive(Parser)]
#[command(name = "isitsafe", version, about)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize download-directory protections and verify the security configuration.
    #[command(name = "init", alias = "setup")]
    Init,
    /// Watch the configured download directory.
    Watch {
        /// Do not post interactive Windows review notifications.
        #[arg(long)]
        no_prompt: bool,
    },
    /// Open the native desktop workspace and ensure the download monitor is running.
    #[command(alias = "open")]
    Ui {
        /// Keep the monitor and UI server running without opening a browser window.
        #[arg(long)]
        background: bool,
    },
    /// Analyze one or more files immediately.
    Scan {
        paths: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Do not post interactive Windows review notifications.
        #[arg(long)]
        no_prompt: bool,
    },
    /// Run the browser Native Messaging host.
    #[command(name = "native-host")]
    NativeHost,
    /// Install Native Messaging manifests for configured browser extension IDs.
    #[command(name = "install-host")]
    InstallHost,
    /// Manage quarantined files.
    Quarantine {
        #[command(subcommand)]
        command: QuarantineCommand,
    },
    /// Prune expired JSONL reports and report records.
    Reports {
        #[command(subcommand)]
        command: ReportsCommand,
    },
    /// Update signed YARA rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Validate the effective configuration.
    #[command(name = "config")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Store the VirusTotal API key in Windows Credential Manager.
    #[command(name = "set-vt-key", hide = true)]
    SetVtKey { value: Option<String> },
    /// Internal Windows notification button handler.
    #[command(name = "handle-action", hide = true)]
    HandleAction { uri: String },
    /// Internal sandbox entry point.
    #[command(name = "__isitsafe_analysis_child", hide = true)]
    InternalChild,
}

#[derive(Subcommand)]
enum QuarantineCommand {
    List {
        #[arg(long)]
        search: Option<String>,
    },
    Restore {
        sha256: String,
        destination: PathBuf,
    },
    Prune,
}

#[derive(Subcommand)]
enum ReportsCommand {
    Prune,
}

#[derive(Subcommand)]
enum RulesCommand {
    Update,
}

#[derive(Subcommand)]
enum ConfigCommand {
    Validate,
    Path,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("isitsafe: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    if is_internal_child_invocation() {
        return run_child_main();
    }
    if std::env::args().nth(1).is_some_and(|value| {
        value.starts_with("chrome-extension://") || value.starts_with("moz-extension://")
    }) {
        let paths = AppPaths::discover()?;
        paths.ensure()?;
        let config = Config::load_or_create(&paths.config_file)?;
        config.validate()?;
        isitsafe::logging::initialize(&paths, &config)?;
        let database = Database::open_with_recovery(&paths.database)?;
        return isitsafe::origin::run_native_host(&config, &database);
    }
    let cli = Cli::parse();
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config = match &cli.config {
        Some(path) => Config::load(path)?,
        None => Config::load_or_create(&paths.config_file)?,
    };
    config.validate()?;
    isitsafe::logging::initialize(&paths, &config)?;

    match cli.command {
        Commands::Init => {
            initialize_download_security(&config)?;
            println!("initialization complete");
            Ok(())
        }
        Commands::Watch { no_prompt } => {
            initialize_download_security(&config)?;
            let database = Database::open_with_recovery(&paths.database)?;
            let removed = prune_quarantine(
                &database,
                &paths.quarantine_dir,
                config.policy.quarantine_retention_days,
            )?;
            if removed > 0 {
                tracing::info!(removed, "expired quarantine entries removed");
            }
            let watcher = Watcher::new(config, database, paths);
            watcher.run_with_prompt(!no_prompt)
        }
        Commands::Ui { background } => isitsafe::desktop::run(config, paths, !background),
        Commands::Scan {
            paths: files,
            json,
            no_prompt,
        } => {
            if files.is_empty() {
                bail!("scan requires at least one file path");
            }
            let database = Database::open_with_recovery(&paths.database)?;
            let watcher = Watcher::new(config, database, paths);
            for file in files {
                let report = watcher.process_path_with_prompt(&file, !json && !no_prompt)?;
                if json {
                    println!("{}", serde_json::to_string(&report)?);
                }
            }
            Ok(())
        }
        Commands::NativeHost => {
            let database = Database::open_with_recovery(&paths.database)?;
            isitsafe::origin::run_native_host(&config, &database)
        }
        Commands::InstallHost => {
            for path in isitsafe::origin::install_native_host(&config, &paths)? {
                println!("installed {}", path.display());
            }
            Ok(())
        }
        Commands::Quarantine { command } => {
            let database = Database::open_with_recovery(&paths.database)?;
            match command {
                QuarantineCommand::List { search } => {
                    let search = search.map(|value| value.to_ascii_lowercase());
                    for (hash, path, moved_at) in database.list_quarantine()? {
                        let path_text = path.display().to_string();
                        if search.as_ref().is_some_and(|needle| {
                            !hash.to_ascii_lowercase().contains(needle)
                                && !path_text.to_ascii_lowercase().contains(needle)
                        }) {
                            continue;
                        }
                        let file_name = path
                            .file_name()
                            .map(|value| value.to_string_lossy())
                            .unwrap_or_else(|| "unknown".into());
                        println!(
                            "{}\t{}\t{hash}\t{path_text}",
                            moved_at.to_rfc3339(),
                            file_name
                        );
                    }
                }
                QuarantineCommand::Restore {
                    sha256,
                    destination,
                } => restore_quarantine(&database, &config, &sha256, &destination)?,
                QuarantineCommand::Prune => {
                    let removed = prune_quarantine(
                        &database,
                        &paths.quarantine_dir,
                        config.policy.quarantine_retention_days,
                    )?;
                    tracing::info!(removed, "expired quarantine entries removed");
                    println!("pruned {removed} expired quarantine entries");
                }
            }
            Ok(())
        }
        Commands::Reports {
            command: ReportsCommand::Prune,
        } => {
            let database = Database::open_with_recovery(&paths.database)?;
            let retention = Duration::from_secs(config.reports.retention_days * 24 * 60 * 60);
            let removed = database.prune_reports(retention)?;
            prune_jsonl(
                &paths.reports_dir,
                config.reports.retention_days,
                config.reports.max_total_bytes,
            )?;
            println!("pruned {removed} report records");
            Ok(())
        }
        Commands::Rules {
            command: RulesCommand::Update,
        } => {
            let path = isitsafe::rules::update_rules(&config, &paths)?;
            println!("YARA rules updated: {}", path.display());
            Ok(())
        }
        Commands::Config { command } => {
            match command {
                ConfigCommand::Validate => println!("configuration is valid"),
                ConfigCommand::Path => println!("{}", paths.config_file.display()),
            }
            Ok(())
        }
        Commands::SetVtKey { value } => {
            let value = match value {
                Some(value) => value,
                None => {
                    eprint!("VirusTotal API key: ");
                    std::io::Write::flush(&mut std::io::stderr())?;
                    let mut value = String::new();
                    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut value)?;
                    value
                }
            };
            store_virus_total_api_key(value.trim())?;
            println!("VirusTotal API key stored in Windows Credential Manager");
            Ok(())
        }
        Commands::HandleAction { uri } => {
            let database = Database::open_with_recovery(&paths.database)?;
            match parse_notification_action(&uri)? {
                NotificationAction::Decision(_) => {
                    let result =
                        isitsafe::interaction::handle_action_uri(&uri, &config, &database, &paths)?;
                    println!("{result}");
                }
                NotificationAction::Detail(report_id) => {
                    if database.report_by_id(&report_id.to_string())?.is_none() {
                        bail!("the stored report for {report_id} is unavailable");
                    }
                    isitsafe::desktop::open_details(&paths, report_id)?;
                    return isitsafe::desktop::run(config, paths, true);
                }
            }
            Ok(())
        }
        Commands::InternalChild => run_child_main(),
    }
}

fn initialize_download_security(config: &Config) -> Result<()> {
    if config.security.block_execution_in_download_dir {
        let status = ensure_download_execution_barrier(&config.download_dir)?;
        println!(
            "download execution blocked: {} (SID {}, inherited deny-execute ACE verified)",
            status.download_dir.display(),
            status.user_sid
        );
    } else {
        println!("download execution barrier disabled by configuration");
    }
    if config.interaction.enabled {
        isitsafe::interaction::register_notification_identity()?;
        println!("Windows notification identity and action handler registered");
    }
    Ok(())
}

fn prune_jsonl(
    directory: &std::path::Path,
    retention_days: u64,
    max_total_bytes: u64,
) -> Result<()> {
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
    let mut retained = Vec::new();
    let mut total = 0u64;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
            continue;
        }
        let stale = entry
            .metadata()?
            .modified()
            .ok()
            .map(chrono::DateTime::<chrono::Utc>::from)
            .is_some_and(|modified| modified < cutoff);
        if stale {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        } else {
            let metadata = entry.metadata()?;
            retained.push((
                metadata
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                metadata.len(),
                path,
            ));
            total = total.saturating_add(metadata.len());
        }
    }
    retained.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in retained {
        if total <= max_total_bytes {
            break;
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to remove {}", path.display()))?;
        total = total.saturating_sub(size);
    }
    Ok(())
}
