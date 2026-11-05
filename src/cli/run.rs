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
