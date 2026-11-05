fn initialize_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS observations (
          path TEXT PRIMARY KEY,
          volume_identity TEXT,
          file_id TEXT,
          size INTEGER NOT NULL,
          modified_ns INTEGER,
          sha256 TEXT,
          state TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jobs (
          id TEXT PRIMARY KEY,
          path TEXT NOT NULL UNIQUE,
          state TEXT NOT NULL,
          created_at TEXT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          last_error TEXT
        );
        CREATE TABLE IF NOT EXISTS origins (
          download_id TEXT PRIMARY KEY,
          normalized_path TEXT NOT NULL,
          source_url TEXT NOT NULL,
          final_url TEXT,
          referrer TEXT,
          timestamp TEXT NOT NULL,
          expected_size INTEGER,
          browser_danger TEXT,
          final_path TEXT NOT NULL,
          resolved_sha256 TEXT
        );
        CREATE INDEX IF NOT EXISTS origins_path_time
          ON origins(normalized_path, timestamp);
        CREATE TABLE IF NOT EXISTS reputation_cache (
          sha256 TEXT PRIMARY KEY,
          body TEXT NOT NULL,
          checked_at TEXT NOT NULL,
          query_batch TEXT
        );
        CREATE TABLE IF NOT EXISTS rate_limits (
          key TEXT PRIMARY KEY,
          last_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
          report_id TEXT PRIMARY KEY,
          sha256 TEXT,
          path TEXT NOT NULL,
          verdict TEXT NOT NULL,
          created_at TEXT NOT NULL,
          json TEXT NOT NULL,
          summary_json TEXT
        );
        CREATE TABLE IF NOT EXISTS quarantine (
          sha256 TEXT PRIMARY KEY,
          path TEXT NOT NULL,
          moved_at TEXT NOT NULL,
          report_id TEXT
        );
        ",
    )?;
    let has_sha_column = connection
        .prepare("PRAGMA table_info(origins)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == "resolved_sha256");
    if !has_sha_column {
        connection.execute("ALTER TABLE origins ADD COLUMN resolved_sha256 TEXT", [])?;
    }
    let has_batch_column = connection
        .prepare("PRAGMA table_info(reputation_cache)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == "query_batch");
    if !has_batch_column {
        connection.execute(
            "ALTER TABLE reputation_cache ADD COLUMN query_batch TEXT",
            [],
        )?;
    }
    let has_summary_column = connection
        .prepare("PRAGMA table_info(reports)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == "summary_json");
    if !has_summary_column {
        connection.execute("ALTER TABLE reports ADD COLUMN summary_json TEXT", [])?;
    }
    let has_quarantine_report_column = connection
        .prepare("PRAGMA table_info(quarantine)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == "report_id");
    if !has_quarantine_report_column {
        connection.execute("ALTER TABLE quarantine ADD COLUMN report_id TEXT", [])?;
    }
    connection.execute_batch(
        "CREATE INDEX IF NOT EXISTS origins_hash_time
           ON origins(resolved_sha256, timestamp);
         CREATE INDEX IF NOT EXISTS reports_path_time
           ON reports(path, created_at);
         CREATE INDEX IF NOT EXISTS reports_sha_time
           ON reports(sha256, created_at);",
    )?;
    backfill_report_summaries(connection)?;
    Ok(())
}

fn backfill_report_summaries(connection: &Connection) -> Result<()> {
    loop {
        let rows = {
            let mut statement = connection
                .prepare("SELECT rowid, json FROM reports WHERE summary_json IS NULL LIMIT 100")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.filter_map(Result::ok).collect::<Vec<_>>()
        };
        if rows.is_empty() {
            break;
        }
        for (rowid, json) in rows {
            let report: AnalysisReportV1 = serde_json::from_str(&json)
                .context("stored report cannot be summarized during migration")?;
            connection.execute(
                "UPDATE reports SET summary_json=?2 WHERE rowid=?1",
                params![rowid, serde_json::to_string(&report.summary())?],
            )?;
        }
    }
    Ok(())
}

fn backup_corrupt(path: &Path, detail: &str) -> Result<PathBuf> {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let backup = path.with_file_name(format!("state.corrupt.{timestamp}.db"));
    fs::copy(path, &backup)?;
    fs::write(
        backup.with_extension("corruption.txt"),
        format!("corruption detail: {detail}\n"),
    )?;
    fs::remove_file(path)?;
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", path.display()));
    }
    Ok(backup)
}

