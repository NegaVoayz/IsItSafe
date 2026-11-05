impl Database {
    pub fn quarantine_record(&self, sha256: &str, path: &Path, report_id: Uuid) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO quarantine (sha256, path, moved_at, report_id)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                sha256,
                path.to_string_lossy(),
                Utc::now().to_rfc3339(),
                report_id.to_string()
            ],
        )?;
        Ok(())
    }

    pub fn remove_quarantine_record(&self, sha256: &str) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute("DELETE FROM quarantine WHERE sha256=?1", [sha256])?;
        Ok(())
    }

    pub fn quarantine_path(&self, sha256: &str) -> Result<Option<PathBuf>> {
        let connection = self.connection.lock().unwrap();
        connection
            .query_row(
                "SELECT path FROM quarantine WHERE sha256=?1",
                [sha256],
                |row| Ok(PathBuf::from(row.get::<_, String>(0)?)),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_quarantine(&self) -> Result<Vec<(String, PathBuf, DateTime<Utc>)>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection
            .prepare("SELECT sha256, path, moved_at FROM quarantine ORDER BY moved_at DESC")?;
        let rows = statement.query_map([], |row| {
            let timestamp: String = row.get(2)?;
            Ok((
                row.get::<_, String>(0)?,
                PathBuf::from(row.get::<_, String>(1)?),
                DateTime::parse_from_rfc3339(&timestamp)
                    .map(|value| value.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            ))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn list_quarantine_entries(&self) -> Result<Vec<QuarantineEntry>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "SELECT q.sha256, q.path, q.moved_at, q.report_id,
                    COALESCE(
                      (SELECT r.summary_json FROM reports r
                       WHERE r.report_id=q.report_id),
                      (SELECT r.summary_json FROM reports r
                       WHERE r.sha256=q.sha256
                       ORDER BY r.created_at DESC LIMIT 1)
                    )
             FROM quarantine q
             ORDER BY q.moved_at DESC",
        )?;
        let rows = statement.query_map([], |row| {
            let moved_at: String = row.get(2)?;
            let report_id: Option<String> = row.get(3)?;
            let summary_json: Option<String> = row.get(4)?;
            let summary = summary_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            Ok(QuarantineEntry {
                sha256: row.get(0)?,
                path: PathBuf::from(row.get::<_, String>(1)?),
                moved_at: DateTime::parse_from_rfc3339(&moved_at)
                    .map(|value| value.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                report_id: report_id.and_then(|value| Uuid::parse_str(&value).ok()),
                summary,
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }
}
