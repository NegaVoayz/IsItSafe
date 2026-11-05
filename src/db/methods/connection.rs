impl Database {
    pub fn open_with_recovery(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        match Self::open(path) {
            Ok(db) => {
                let integrity = db.integrity_check()?;
                if integrity.ok {
                    Ok(db)
                } else {
                    drop(db);
                    let backup = backup_corrupt(path, &integrity.detail)?;
                    let db = Self::open(path)?;
                    Ok(Self {
                        recovered_from: Some(backup),
                        ..db
                    })
                }
            }
            Err(error) => {
                let backup = backup_corrupt(path, &error.to_string())?;
                let db = Self::open(path)?;
                Ok(Self {
                    recovered_from: Some(backup),
                    ..db
                })
            }
        }
    }

    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open database {}", path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1000)?;
        initialize_schema(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            path: path.to_path_buf(),
            recovered_from: None,
        })
    }

    pub fn integrity_check(&self) -> Result<IntegrityResult> {
        let connection = self.connection.lock().unwrap();
        let detail: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(IntegrityResult {
            ok: detail == "ok",
            detail,
        })
    }

    pub fn checkpoint(&self, truncate: bool) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        let mode = if truncate { "TRUNCATE" } else { "PASSIVE" };
        connection.execute_batch(&format!("PRAGMA wal_checkpoint({mode});"))?;
        Ok(())
    }

}
