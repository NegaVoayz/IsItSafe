pub struct Watcher {
    config: Arc<Config>,
    database: Arc<Database>,
    paths: Arc<AppPaths>,
}

struct DebounceEntry {
    last_event: Instant,
    temp_started: Option<Instant>,
}

