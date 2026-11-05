impl Database {
    pub fn upsert_observation(&self, observation: &Observation) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO observations
             (path, volume_identity, file_id, size, modified_ns, sha256, state, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(path) DO UPDATE SET
               volume_identity=excluded.volume_identity,
               file_id=excluded.file_id,
               size=excluded.size,
               modified_ns=excluded.modified_ns,
               sha256=excluded.sha256,
               state=excluded.state,
               updated_at=excluded.updated_at",
            params![
                observation.path,
                observation.volume_identity,
                observation.file_id,
                observation.size as i64,
                observation.modified_ns,
                observation.sha256,
                observation.state,
                observation.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn observation(&self, path: &str) -> Result<Option<Observation>> {
        let connection = self.connection.lock().unwrap();
        connection
            .query_row(
                "SELECT path, volume_identity, file_id, size, modified_ns, sha256, state, updated_at
                 FROM observations WHERE path=?1",
                [path],
                |row| {
                    let updated: String = row.get(7)?;
                    Ok(Observation {
                        path: row.get(0)?,
                        volume_identity: row.get(1)?,
                        file_id: row.get(2)?,
                        size: row.get::<_, i64>(3)? as u64,
                        modified_ns: row.get(4)?,
                        sha256: row.get(5)?,
                        state: row.get(6)?,
                        updated_at: DateTime::parse_from_rfc3339(&updated)
                            .map(|value| value.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn update_observation_state(&self, path: &str, state: &str) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE observations SET state=?2, updated_at=?3 WHERE path=?1",
            params![path, state, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn enqueue_job(&self, path: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO jobs (id, path, state, created_at, attempts)
             VALUES (?1, ?2, 'pending', ?3, 0)
             ON CONFLICT(path) DO UPDATE SET
               state='pending',
               created_at=excluded.created_at",
            params![id.to_string(), path, Utc::now().to_rfc3339()],
        )?;
        Ok(id)
    }

    pub fn pending_jobs(&self, limit: usize) -> Result<Vec<(Uuid, String)>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "SELECT id, path FROM jobs WHERE state='pending' ORDER BY created_at LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            let id: String = row.get(0)?;
            Ok((
                Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::new_v4()),
                row.get(1)?,
            ))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn job_started(&self, id: Uuid) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE jobs SET state='running', attempts=attempts+1 WHERE id=?1",
            [id.to_string()],
        )?;
        Ok(())
    }

    pub fn job_finished(&self, id: Uuid, error: Option<&str>) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE jobs SET state=?2, last_error=?3 WHERE id=?1",
            params![
                id.to_string(),
                if error.is_some() { "failed" } else { "done" },
                error
            ],
        )?;
        Ok(())
    }

    pub fn requeue_interrupted_jobs(&self) -> Result<usize> {
        let connection = self.connection.lock().unwrap();
        Ok(connection.execute("UPDATE jobs SET state='pending' WHERE state='running'", [])?)
    }

    pub fn mark_path_running(&self, path: &str) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE jobs SET state='running', attempts=attempts+1 WHERE path=?1",
            [path],
        )?;
        Ok(())
    }

    pub fn mark_path_finished(&self, path: &str, error: Option<&str>) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE jobs SET state=?2, last_error=?3 WHERE path=?1",
            params![path, if error.is_some() { "failed" } else { "done" }, error],
        )?;
        Ok(())
    }

}
