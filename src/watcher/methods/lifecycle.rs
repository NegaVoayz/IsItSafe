impl Watcher {
    pub fn new(config: Config, database: Database, paths: AppPaths) -> Self {
        Self {
            config: Arc::new(config),
            database: Arc::new(database),
            paths: Arc::new(paths),
        }
    }

    pub fn run(&self) -> Result<()> {
        self.run_with_prompt(true)
    }

    pub fn run_with_prompt(&self, interactive: bool) -> Result<()> {
        self.run_with_prompt_and_stop(interactive, || false)
    }

    pub fn run_with_prompt_and_stop<F>(&self, interactive: bool, should_stop: F) -> Result<()>
    where
        F: Fn() -> bool,
    {
        if should_stop() {
            return Ok(());
        }
        self.recover_state()?;
        self.prune_report_storage()?;
        let (event_tx, event_rx) = mpsc::channel();
        let mut native_watcher: RecommendedWatcher =
            notify::recommended_watcher(move |event: notify::Result<Event>| {
                let _ = event_tx.send(event);
            })?;
        native_watcher.watch(&self.config.download_dir, RecursiveMode::NonRecursive)?;

        let (work_tx, work_rx) = mpsc::channel::<PathBuf>();
        let worker = {
            let config = Arc::clone(&self.config);
            let database = Arc::clone(&self.database);
            let paths = Arc::clone(&self.paths);
            thread::spawn(move || {
                while let Ok(path) = work_rx.recv() {
                    let watcher = Watcher {
                        config: Arc::clone(&config),
                        database: Arc::clone(&database),
                        paths: Arc::clone(&paths),
                    };
                    let path_string = path.to_string_lossy().into_owned();
                    let _ = watcher.database.mark_path_running(&path_string);
                    if let Err(error) = watcher.process_path_optional(&path, interactive) {
                        let _ = watcher
                            .database
                            .mark_path_finished(&path_string, Some(&error.to_string()));
                        tracing::error!(
                            path = %escape_controls(&path.display().to_string()),
                            error = %error,
                            "analysis job failed"
                        );
                    } else {
                        let _ = watcher.database.mark_path_finished(&path_string, None);
                    }
                }
            })
        };

        self.reconcile()?;
        self.enqueue_pending_work(&work_tx)?;

        let mut debounce: HashMap<PathBuf, DebounceEntry> = HashMap::new();
        let debounce_window = Duration::from_millis(self.config.events.debounce_ms);
        let temp_grace = Duration::from_millis(self.config.events.temp_rename_grace_ms);
        let reconcile_interval =
            Duration::from_millis(self.config.events.reconciliation_interval_ms);
        let mut last_reconcile = Instant::now();
        let mut last_checkpoint = Instant::now();
        let mut last_integrity = Instant::now();
        loop {
            if should_stop() {
                break;
            }
            match event_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Ok(event)) => {
                    self.handle_event(event, &mut debounce, &work_tx, debounce_window)?
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "filesystem watcher error; scheduling reconciliation");
                    self.reconcile()?;
                    self.enqueue_pending_work(&work_tx)?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            let now = Instant::now();
            let ready: Vec<PathBuf> = debounce
                .iter()
                .filter_map(|(path, entry)| {
                    if entry.temp_started.is_none()
                        && now.duration_since(entry.last_event) >= debounce_window
                    {
                        Some(path.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for path in ready {
                debounce.remove(&path);
                let _ = work_tx.send(path);
            }
            let expired_temps: Vec<PathBuf> = debounce
                .iter()
                .filter(|(_, entry)| {
                    entry
                        .temp_started
                        .is_some_and(|started| now.duration_since(started) >= temp_grace)
                })
                .map(|(path, _)| path.clone())
                .collect();
            for path in expired_temps {
                debounce.remove(&path);
                if strip_temp_extension(&path).is_some_and(|final_path| final_path.exists()) {
                    continue;
                }
                self.record_temp_only(&path)?;
            }
            if last_reconcile.elapsed() >= reconcile_interval {
                self.reconcile()?;
                self.enqueue_pending_work(&work_tx)?;
                last_reconcile = Instant::now();
            }
            if last_checkpoint.elapsed() >= Duration::from_secs(60 * 60) {
                if let Err(error) = self.database.checkpoint(false) {
                    tracing::warn!(%error, "hourly SQLite checkpoint failed");
                }
                let wal_path = self.database.path.with_file_name("state.db-wal");
                if fs::metadata(&wal_path).is_ok_and(|metadata| metadata.len() > 256 * 1024 * 1024)
                    && let Err(error) = self.database.checkpoint(true)
                {
                    tracing::warn!(%error, "SQLite WAL truncation failed");
                }
                last_checkpoint = Instant::now();
            }
            if last_integrity.elapsed() >= Duration::from_secs(24 * 60 * 60) {
                match self.database.integrity_check() {
                    Ok(result) if result.ok => {}
                    Ok(result) => tracing::error!(
                        detail = %result.detail,
                        "SQLite integrity check failed; restart will preserve and rebuild state"
                    ),
                    Err(error) => tracing::error!(%error, "SQLite integrity check errored"),
                }
                last_integrity = Instant::now();
            }
        }
        let stopped = should_stop();
        drop(work_tx);
        if !stopped {
            let _ = worker.join();
        }
        Ok(())
    }

}
