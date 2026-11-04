use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::Utc;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
pub struct SizeRotatingWriter {
    state: Arc<Mutex<State>>,
}

struct State {
    directory: PathBuf,
    current: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
    retain: usize,
}

impl SizeRotatingWriter {
    pub fn new(directory: &Path, max_bytes: u64, retain: usize) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let current = directory.join("isitsafe.log");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&current)?;
        let size = file.metadata()?.len();
        let writer = Self {
            state: Arc::new(Mutex::new(State {
                directory: directory.to_path_buf(),
                current,
                file,
                size,
                max_bytes: max_bytes.max(1024),
                retain: retain.max(1),
            })),
        };
        writer.rotate_retention(false);
        Ok(writer)
    }

    fn rotate_retention(&self, force: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if !force && state.size < state.max_bytes {
            return;
        }
        let rotated = state.directory.join(format!(
            "isitsafe-{}.log",
            Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
        ));
        let _ = state.file.flush();
        if fs::rename(&state.current, &rotated).is_ok()
            && let Ok(file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&state.current)
        {
            state.file = file;
            state.size = 0;
        }
        let mut logs = fs::read_dir(&state.directory)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("isitsafe-"))
            .filter_map(|entry| {
                let modified = entry.metadata().ok()?.modified().ok()?;
                Some((modified, entry.path()))
            })
            .collect::<Vec<_>>();
        logs.sort_by_key(|(modified, _)| *modified);
        let excess = logs.len().saturating_sub(state.retain.saturating_sub(1));
        for (_, path) in logs.into_iter().take(excess) {
            let _ = fs::remove_file(path);
        }
    }
}

impl Write for SizeRotatingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("log writer lock poisoned"))?;
        if state.size.saturating_add(buffer.len() as u64) > state.max_bytes {
            drop(state);
            self.rotate_retention(true);
            state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("log writer lock poisoned"))?;
        }
        let written = state.file.write(buffer)?;
        state.size = state.size.saturating_add(written as u64);
        state.file.flush()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("log writer lock poisoned"))?
            .file
            .flush()
    }
}

impl<'a> MakeWriter<'a> for SizeRotatingWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

pub fn initialize(paths: &crate::config::AppPaths, config: &crate::config::Config) -> Result<()> {
    let writer = SizeRotatingWriter::new(
        &paths.logs_dir,
        config.reports.log_max_bytes,
        config.reports.log_retained_files,
    )?;
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("isitsafe=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .try_init()
        .ok();
    Ok(())
}
