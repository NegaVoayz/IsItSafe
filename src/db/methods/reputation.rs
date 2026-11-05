impl Database {
    pub fn cached_reputation(
        &self,
        sha256: &str,
        ttl: Duration,
    ) -> Result<Option<CachedReputation>> {
        let connection = self.connection.lock().unwrap();
        connection
            .query_row(
                "SELECT body, checked_at, query_batch FROM reputation_cache WHERE sha256=?1",
                [sha256],
                |row| {
                    let body: String = row.get(0)?;
                    let checked: String = row.get(1)?;
                    Ok(CachedReputation {
                        body: serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
                        checked_at: DateTime::parse_from_rfc3339(&checked)
                            .map(|value| value.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        query_batch: row.get(2)?,
                    })
                },
            )
            .optional()
            .map(|value| {
                value.filter(|entry| {
                    Utc::now()
                        .signed_duration_since(entry.checked_at)
                        .to_std()
                        .unwrap_or(Duration::MAX)
                        <= ttl
                })
            })
            .map_err(Into::into)
    }

    pub fn claim_rate_slot(&self, key: &str, requests_per_minute: u32) -> Result<bool> {
        let interval_ms = 60_000u64 / u64::from(requests_per_minute.max(1));
        loop {
            let now_ms = Utc::now().timestamp_millis() as u64;
            let connection = self.connection.lock().unwrap();
            let last_ms: Option<u64> = connection
                .query_row(
                    "SELECT last_at_ms FROM rate_limits WHERE key=?1",
                    [key],
                    |row| row.get::<_, i64>(0).map(|value| value as u64),
                )
                .optional()?;
            if last_ms.is_none_or(|last| now_ms.saturating_sub(last) >= interval_ms) {
                connection.execute(
                    "INSERT INTO rate_limits (key, last_at_ms) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET last_at_ms=excluded.last_at_ms",
                    params![key, now_ms as i64],
                )?;
                return Ok(true);
            }
            drop(connection);
            let wait = interval_ms.saturating_sub(now_ms.saturating_sub(last_ms.unwrap_or(0)));
            std::thread::sleep(Duration::from_millis(wait.min(1_000)));
        }
    }

    pub fn cache_reputation(
        &self,
        sha256: &str,
        body: &serde_json::Value,
        checked_at: DateTime<Utc>,
        query_batch: Option<&str>,
    ) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO reputation_cache (sha256, body, checked_at, query_batch)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(sha256) DO UPDATE SET
               body=excluded.body,
               checked_at=excluded.checked_at,
               query_batch=excluded.query_batch",
            params![
                sha256,
                serde_json::to_string(body)?,
                checked_at.to_rfc3339(),
                query_batch
            ],
        )?;
        Ok(())
    }

}
