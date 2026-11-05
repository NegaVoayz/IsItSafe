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
