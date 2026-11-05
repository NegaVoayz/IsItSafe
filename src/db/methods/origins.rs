impl Database {
    pub fn insert_origin(&self, origin: &DownloadOrigin) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        let normalized_path = normalize_path(&origin.final_path);
        connection.execute(
            "INSERT INTO origins
             (download_id, normalized_path, source_url, final_url, referrer, timestamp,
              expected_size, browser_danger, final_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(download_id) DO UPDATE SET
               normalized_path=excluded.normalized_path,
               source_url=excluded.source_url,
               final_url=excluded.final_url,
               referrer=excluded.referrer,
               timestamp=excluded.timestamp,
               expected_size=excluded.expected_size,
               browser_danger=excluded.browser_danger,
               final_path=excluded.final_path",
            params![
                origin.download_id,
                normalized_path,
                origin.source_url,
                origin.final_url,
                origin.referrer,
                origin.timestamp.to_rfc3339(),
                origin.expected_size.map(|value| value as i64),
                origin.browser_danger,
                origin.final_path,
            ],
        )?;
        Ok(())
    }

    pub fn find_origin(
        &self,
        final_path: &str,
        window: Duration,
    ) -> Result<Option<DownloadOrigin>> {
        let connection = self.connection.lock().unwrap();
        let normalized = normalize_path(final_path);
        let threshold = Utc::now() - chrono::Duration::from_std(window).unwrap_or_default();
        connection
            .query_row(
                "SELECT download_id, source_url, final_url, referrer, timestamp,
                        expected_size, browser_danger, final_path
                 FROM origins
                 WHERE normalized_path=?1 AND timestamp>=?2
                 ORDER BY timestamp DESC LIMIT 1",
                params![normalized, threshold.to_rfc3339()],
                |row| {
                    let timestamp: String = row.get(4)?;
                    Ok(DownloadOrigin {
                        schema_version: 1,
                        download_id: row.get(0)?,
                        source_url: row.get(1)?,
                        final_url: row.get(2)?,
                        referrer: row.get(3)?,
                        timestamp: DateTime::parse_from_rfc3339(&timestamp)
                            .map(|value| value.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        expected_size: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
                        browser_danger: row.get(6)?,
                        final_path: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn bind_origin_hash(&self, final_path: &str, sha256: &str) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE origins SET resolved_sha256=?2
             WHERE normalized_path=?1 AND resolved_sha256 IS NULL",
            params![normalize_path(final_path), sha256],
        )?;
        Ok(())
    }

    pub fn find_origin_by_hash(
        &self,
        sha256: &str,
        window: Duration,
    ) -> Result<Option<DownloadOrigin>> {
        let connection = self.connection.lock().unwrap();
        let threshold = Utc::now() - chrono::Duration::from_std(window).unwrap_or_default();
        connection
            .query_row(
                "SELECT download_id, source_url, final_url, referrer, timestamp,
                        expected_size, browser_danger, final_path
                 FROM origins
                 WHERE resolved_sha256=?1 AND timestamp>=?2
                 ORDER BY timestamp DESC LIMIT 1",
                params![sha256, threshold.to_rfc3339()],
                |row| {
                    let timestamp: String = row.get(4)?;
                    Ok(DownloadOrigin {
                        schema_version: 1,
                        download_id: row.get(0)?,
                        source_url: row.get(1)?,
                        final_url: row.get(2)?,
                        referrer: row.get(3)?,
                        timestamp: DateTime::parse_from_rfc3339(&timestamp)
                            .map(|value| value.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        expected_size: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
                        browser_danger: row.get(6)?,
                        final_path: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

}
