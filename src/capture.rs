use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::report::{
    AlternateStream, Boundary, BoundaryKind, FileEvidence, LockAcquisitionEvidence,
    LockAcquisitionOutcome, MotwEvidence, MotwState, ThresholdDecisions,
};

const HEAD_BYTES: usize = 64 * 1024;
const TAIL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureDepth {
    Deep,
    Limited,
    BasicCheckOnly,
}

#[derive(Debug)]
pub struct CapturedFile {
    pub path: PathBuf,
    pub file: FileEvidence,
    pub sha256: Option<String>,
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
    pub snapshot: Option<Vec<u8>>,
    pub lock: LockAcquisitionEvidence,
    pub motw: MotwEvidence,
    pub alternate_streams: Vec<AlternateStream>,
    pub thresholds: ThresholdDecisions,
    pub depth: CaptureDepth,
    pub boundaries: Vec<Boundary>,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("exclusive readiness lock timed out")]
    LockTimeout {
        file: FileEvidence,
        lock: LockAcquisitionEvidence,
    },
    #[error("exclusive readiness lock is unavailable: {detail}")]
    LockUnavailable {
        file: FileEvidence,
        lock: LockAcquisitionEvidence,
        outcome: LockAcquisitionOutcome,
        detail: String,
    },
    #[error("file changed while held under the readiness lock")]
    ChangedDuringRead {
        file: FileEvidence,
        lock: LockAcquisitionEvidence,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[allow(clippy::result_large_err)]
pub fn capture(path: &Path, config: &Config) -> Result<CapturedFile, CaptureError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        let mut file = file_evidence(path, &metadata);
        file.is_reparse_point = true;
        return Err(CaptureError::LockUnavailable {
            file,
            lock: LockAcquisitionEvidence::default(),
            outcome: LockAcquisitionOutcome::LockNotAvailable,
            detail: "reparse points and symbolic links are not followed".into(),
        });
    }
    let pre_size = metadata.len();
    let pre_modified = metadata.modified().ok();
    let timeout = Duration::from_millis(config.limits.lock_acquisition_timeout_ms);
    let backoff = Duration::from_millis(config.limits.lock_acquisition_retry_backoff_ms);
    let started = Instant::now();
    let mut attempts = 0u32;

    loop {
        attempts = attempts.saturating_add(1);
        match open_write_ready(path) {
            Ok(mut handle) => {
                let locked_meta = handle.metadata()?;
                let same_size = locked_meta.len() == pre_size;
                let same_time = match (pre_modified, locked_meta.modified().ok()) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                };
                if !same_size || !same_time {
                    drop(handle);
                    if started.elapsed() >= timeout {
                        let mut file = file_evidence(path, &metadata);
                        file.size = locked_meta.len();
                        return Err(CaptureError::LockTimeout {
                            file,
                            lock: LockAcquisitionEvidence {
                                attempts,
                                wait_ms: started.elapsed().as_millis() as u64,
                                outcome: LockAcquisitionOutcome::Timeout,
                                pre_lock_size: Some(pre_size),
                                locked_size: Some(locked_meta.len()),
                                final_size: Some(locked_meta.len()),
                                changed_inside_lock: true,
                            },
                        });
                    }
                    thread::sleep(backoff);
                    continue;
                }

                let identity = file_identity(&handle);
                let initial_meta = handle.metadata()?;
                let initial_size = initial_meta.len();
                let initial_modified = initial_meta.modified().ok();
                let depth = select_depth(initial_size, config);
                let mut head = vec![0; HEAD_BYTES.min(initial_size as usize)];
                read_exact_at_start(&mut handle, &mut head)?;

                let (snapshot, digest) = if depth == CaptureDepth::Deep {
                    let mut bytes = Vec::with_capacity(initial_size as usize);
                    handle.seek(SeekFrom::Start(0))?;
                    handle.read_to_end(&mut bytes)?;
                    let digest = sha256(&bytes);
                    (Some(bytes), digest)
                } else {
                    handle.seek(SeekFrom::Start(0))?;
                    let mut hasher = Sha256::new();
                    let mut buffer = vec![0u8; 1024 * 1024];
                    loop {
                        let read = handle.read(&mut buffer)?;
                        if read == 0 {
                            break;
                        }
                        hasher.update(&buffer[..read]);
                    }
                    (None, hex::encode(hasher.finalize()))
                };

                let tail_len = TAIL_BYTES.min(initial_size as usize);
                let mut tail = vec![0; tail_len];
                if tail_len > 0 {
                    handle.seek(SeekFrom::End(-(tail_len as i64)))?;
                    read_exact_len(&mut handle, &mut tail)?;
                }

                let final_meta = handle.metadata()?;
                let final_modified = final_meta.modified().ok();
                let changed =
                    final_meta.len() != initial_size || final_modified != initial_modified;
                let outcome = if changed {
                    LockAcquisitionOutcome::ReadOnlyContent
                } else {
                    LockAcquisitionOutcome::Acquired
                };
                let lock = LockAcquisitionEvidence {
                    attempts,
                    wait_ms: started.elapsed().as_millis() as u64,
                    outcome,
                    pre_lock_size: Some(pre_size),
                    locked_size: Some(initial_size),
                    final_size: Some(final_meta.len()),
                    changed_inside_lock: changed,
                };
                drop(handle);

                let file = FileEvidence {
                    display_path: safe_display_path(path),
                    full_path_redacted: redact_path(path),
                    extension: path
                        .extension()
                        .and_then(|v| v.to_str())
                        .map(|v| v.to_ascii_lowercase()),
                    size: initial_size,
                    modified_at: datetime(initial_modified),
                    sha256: Some(digest.clone()),
                    volume_identity: identity.as_ref().map(|v| v.volume.clone()),
                    file_id: identity.as_ref().map(|v| v.file_id.clone()),
                    is_reparse_point: false,
                };

                if changed {
                    return Err(CaptureError::ChangedDuringRead { file, lock });
                }

                let motw = match read_motw_with_retry(path, config, &identity) {
                    Ok(value) => value,
                    Err(error) if error.to_string().contains("file identity changed") => {
                        return Err(CaptureError::ChangedDuringRead { file, lock });
                    }
                    Err(error) => return Err(CaptureError::Io(error)),
                };
                let streams = list_alternate_streams(path).unwrap_or_default();
                if identity_changed(path, &identity) {
                    return Err(CaptureError::ChangedDuringRead { file, lock });
                }
                let mut boundaries = Vec::new();
                if motw.state == MotwState::PresentEmpty {
                    boundaries.push(Boundary {
                        kind: BoundaryKind::MotwEmptyAfterRetry,
                        detail: "Zone.Identifier remained empty until timeout".into(),
                    });
                }
                if depth == CaptureDepth::Limited {
                    boundaries.push(Boundary {
                        kind: BoundaryKind::Limited,
                        detail: format!(
                            "file exceeds snapshot_max_bytes ({})",
                            config.limits.snapshot_max_bytes
                        ),
                    });
                }
                if depth == CaptureDepth::BasicCheckOnly {
                    boundaries.push(Boundary {
                        kind: BoundaryKind::BasicCheckOnly,
                        detail: format!(
                            "file exceeds basic_check_threshold_bytes ({})",
                            config.limits.basic_check_threshold_bytes
                        ),
                    });
                }
                let thresholds = threshold_decisions(initial_size, depth, config);
                return Ok(CapturedFile {
                    path: path.to_path_buf(),
                    file,
                    sha256: Some(digest),
                    head,
                    tail,
                    snapshot,
                    lock,
                    motw,
                    alternate_streams: streams,
                    thresholds,
                    depth,
                    boundaries,
                });
            }
            Err(error) if is_sharing_violation(&error) => {
                if started.elapsed() >= timeout {
                    let file = file_evidence(path, &metadata);
                    return Err(CaptureError::LockTimeout {
                        file,
                        lock: LockAcquisitionEvidence {
                            attempts,
                            wait_ms: started.elapsed().as_millis() as u64,
                            outcome: LockAcquisitionOutcome::Timeout,
                            pre_lock_size: Some(pre_size),
                            locked_size: None,
                            final_size: None,
                            changed_inside_lock: false,
                        },
                    });
                }
                thread::sleep(backoff);
            }
            Err(error) if is_access_denied(&error) => {
                let file = file_evidence(path, &metadata);
                return Err(CaptureError::LockUnavailable {
                    file,
                    lock: LockAcquisitionEvidence {
                        attempts,
                        wait_ms: started.elapsed().as_millis() as u64,
                        outcome: LockAcquisitionOutcome::LockNotAvailable,
                        pre_lock_size: Some(pre_size),
                        locked_size: None,
                        final_size: None,
                        changed_inside_lock: false,
                    },
                    outcome: LockAcquisitionOutcome::LockNotAvailable,
                    detail: error.to_string(),
                });
            }
            Err(error) => return Err(CaptureError::Io(error)),
        }
    }
}

/// Permanently deletes `path` only if complete contents read through the
/// exclusive readiness handle still hash to `expected_sha256`. On Windows the
/// delete disposition is set on that same handle, eliminating the
/// verify-path-then-delete-path race.
pub fn remove_if_hash_matches(path: &Path, config: &Config, expected_sha256: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        bail!("refusing to remove a reparse point or symbolic link");
    }
    let timeout = Duration::from_millis(config.limits.lock_acquisition_timeout_ms);
    let backoff = Duration::from_millis(config.limits.lock_acquisition_retry_backoff_ms);
    let started = Instant::now();
    loop {
        match open_write_ready_for_delete(path) {
            Ok(mut handle) => {
                handle.seek(SeekFrom::Start(0))?;
                let mut hasher = Sha256::new();
                let mut buffer = vec![0u8; 1024 * 1024];
                loop {
                    let read = handle.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
                let digest = hex::encode(hasher.finalize());
                if digest != expected_sha256 {
                    bail!("source changed after analysis; removal cancelled");
                }
                set_delete_on_close(&handle)?;
                drop(handle);
                return Ok(());
            }
            Err(error) if is_sharing_violation(&error) => {
                if started.elapsed() >= timeout {
                    bail!("exclusive removal lock timed out");
                }
                thread::sleep(backoff);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to open {} for removal", path.display()));
            }
        }
    }
}

pub fn select_depth(size: u64, config: &Config) -> CaptureDepth {
    if size > config.limits.basic_check_threshold_bytes {
        CaptureDepth::BasicCheckOnly
    } else if size > config.limits.snapshot_max_bytes {
        CaptureDepth::Limited
    } else {
        CaptureDepth::Deep
    }
}

fn threshold_decisions(size: u64, depth: CaptureDepth, config: &Config) -> ThresholdDecisions {
    let mut triggered = Vec::new();
    if size > config.limits.snapshot_max_bytes {
        triggered.push("snapshot_max_bytes".into());
    }
    if size > config.limits.basic_check_threshold_bytes {
        triggered.push("basic_check_threshold_bytes".into());
    }
    ThresholdDecisions {
        snapshot_max_bytes: config.limits.snapshot_max_bytes,
        basic_check_threshold_bytes: config.limits.basic_check_threshold_bytes,
        deep_analysis_eligible: depth == CaptureDepth::Deep,
        basic_check_only: depth == CaptureDepth::BasicCheckOnly,
        limited: depth == CaptureDepth::Limited,
        triggered,
    }
}

fn open_write_ready(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
    }
    options.open(path)
}

#[cfg(windows)]
fn open_write_ready_for_delete(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_SHARE_DELETE, FILE_SHARE_READ};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
    options.open(path)
}

#[cfg(not(windows))]
fn open_write_ready_for_delete(path: &Path) -> std::io::Result<File> {
    open_write_ready(path)
}

#[cfg(windows)]
fn set_delete_on_close(handle: &File) -> Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let result = unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle().cast(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to mark the open file for deletion");
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_delete_on_close(handle: &File) -> Result<()> {
    let _ = handle;
    Ok(())
}

fn read_exact_at_start(handle: &mut File, buffer: &mut [u8]) -> std::io::Result<()> {
    handle.seek(SeekFrom::Start(0))?;
    read_exact_len(handle, buffer)
}

fn read_exact_len(handle: &mut File, mut buffer: &mut [u8]) -> std::io::Result<()> {
    while !buffer.is_empty() {
        let read = handle.read(buffer)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected end of file",
            ));
        }
        buffer = &mut buffer[read..];
    }
    Ok(())
}

fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn file_evidence(path: &Path, metadata: &fs::Metadata) -> FileEvidence {
    FileEvidence {
        display_path: safe_display_path(path),
        full_path_redacted: redact_path(path),
        extension: path
            .extension()
            .and_then(|v| v.to_str())
            .map(|v| v.to_ascii_lowercase()),
        size: metadata.len(),
        modified_at: metadata.modified().ok().and_then(|v| datetime(Some(v))),
        sha256: None,
        volume_identity: None,
        file_id: None,
        is_reparse_point: false,
    }
}

fn datetime(value: Option<std::time::SystemTime>) -> Option<DateTime<Utc>> {
    value.map(DateTime::<Utc>::from)
}

fn is_sharing_violation(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(32 | 33))
}

fn is_access_denied(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(error.raw_os_error(), Some(5 | 19))
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[derive(Debug)]
struct Identity {
    volume: String,
    file_id: String,
}

#[cfg(windows)]
fn file_identity(file: &File) -> Option<Identity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    if ok == 0 {
        return None;
    }
    let file_index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    Some(Identity {
        volume: format!("{:08x}", info.dwVolumeSerialNumber),
        file_id: format!("{file_index:016x}"),
    })
}

#[cfg(not(windows))]
fn file_identity(_file: &File) -> Option<Identity> {
    None
}

fn read_motw_with_retry(
    path: &Path,
    config: &Config,
    expected_identity: &Option<Identity>,
) -> std::io::Result<MotwEvidence> {
    let timeout = Duration::from_millis(config.limits.motw_read_timeout_ms);
    let backoff = Duration::from_millis(config.limits.motw_retry_backoff_ms);
    let started = Instant::now();
    let mut stream_name = path.as_os_str().to_os_string();
    stream_name.push(":Zone.Identifier");
    let stream_path = PathBuf::from(stream_name);
    let mut ever_present = false;
    loop {
        if identity_changed(path, expected_identity) {
            return Err(std::io::Error::other(
                "file identity changed while reading MOTW",
            ));
        }
        match fs::read(&stream_path) {
            Ok(bytes) => {
                ever_present = true;
                if !bytes.is_empty() {
                    return Ok(parse_motw(&bytes));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // Some filesystems expose ADS names but deny direct reads. Treat
                // the state as unknown rather than absent.
                return Ok(MotwEvidence {
                    state: MotwState::Unknown,
                    ..MotwEvidence::default()
                });
            }
            Err(error) => return Err(error),
        }
        if started.elapsed() >= timeout {
            return Ok(MotwEvidence {
                state: if ever_present {
                    MotwState::PresentEmpty
                } else {
                    MotwState::Absent
                },
                ..MotwEvidence::default()
            });
        }
        thread::sleep(backoff);
    }
}

fn identity_changed(path: &Path, expected: &Option<Identity>) -> bool {
    let Some(expected) = expected else {
        return fs::metadata(path).is_err();
    };
    let Ok(file) = File::open(path) else {
        return true;
    };
    file_identity(&file).is_none_or(|current| {
        current.volume != expected.volume || current.file_id != expected.file_id
    })
}

fn parse_motw(bytes: &[u8]) -> MotwEvidence {
    let raw = String::from_utf8_lossy(bytes).replace('\r', "");
    let mut zone_id = None;
    let mut referrer_url = None;
    let mut host_url = None;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("ZoneId=") {
            zone_id = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("ReferrerUrl=") {
            referrer_url = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("HostUrl=") {
            host_url = Some(value.trim().to_string());
        }
    }
    MotwEvidence {
        state: MotwState::Present,
        zone_id,
        referrer_url,
        host_url,
        raw: Some(raw.chars().take(16_384).collect()),
    }
}

#[cfg(windows)]
fn list_alternate_streams(path: &Path) -> Result<Vec<AlternateStream>> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        WIN32_FIND_STREAM_DATA,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut data = unsafe { std::mem::zeroed::<WIN32_FIND_STREAM_DATA>() };
    let handle = unsafe {
        FindFirstStreamW(
            wide.as_ptr(),
            FindStreamInfoStandard,
            (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    loop {
        let name_len = data
            .cStreamName
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(data.cStreamName.len());
        let name = OsString::from_wide(&data.cStreamName[..name_len])
            .to_string_lossy()
            .to_string();
        if name != "::$DATA" && !name.eq_ignore_ascii_case(":Zone.Identifier:$DATA") {
            result.push(AlternateStream {
                name,
                size: data.StreamSize.max(0) as u64,
            });
        }
        if unsafe { FindNextStreamW(handle, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast()) }
            == 0
        {
            break;
        }
    }
    unsafe {
        FindClose(handle);
    }
    Ok(result)
}

#[cfg(not(windows))]
fn list_alternate_streams(_path: &Path) -> Result<Vec<AlternateStream>> {
    Ok(Vec::new())
}

#[cfg(windows)]
fn safe_display_path(path: &Path) -> String {
    escape_controls(&path.display().to_string())
}

#[cfg(not(windows))]
fn safe_display_path(path: &Path) -> String {
    escape_controls(&path.display().to_string())
}

pub fn escape_controls(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            c if c.is_control() => format!("\\u{{{:x}}}", c as u32).chars().collect(),
            c => vec![c],
        })
        .collect()
}

fn redact_path(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|v| v.to_str())
        .map(escape_controls)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn depth_matrix_requires_both_gates() {
        let mut config = Config::default();
        config.limits.snapshot_max_bytes = 10;
        config.limits.basic_check_threshold_bytes = 20;
        assert_eq!(select_depth(10, &config), CaptureDepth::Deep);
        assert_eq!(select_depth(15, &config), CaptureDepth::Limited);
        assert_eq!(select_depth(21, &config), CaptureDepth::BasicCheckOnly);
    }

    #[test]
    fn captures_and_hashes_snapshot() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"MZ").unwrap();
        temp.flush().unwrap();
        let temp_path = temp.into_temp_path();
        let mut config = Config::default();
        config.limits.lock_acquisition_retry_backoff_ms = 1;
        let captured = capture(&temp_path, &config).unwrap();
        assert_eq!(captured.lock.outcome, LockAcquisitionOutcome::Acquired);
        assert!(captured.sha256.is_some());
        assert_eq!(captured.head, b"MZ");
    }

    #[test]
    fn escapes_control_characters() {
        assert_eq!(escape_controls("a\nb\r\t"), "a\\nb\\r\\t");
    }

    #[test]
    fn basic_check_uses_two_gate_matrix_and_streams() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.bin");
        let file = File::create(&path).unwrap();
        file.set_len(3 * 1024 * 1024).unwrap();
        drop(file);
        let mut config = Config::default();
        config.limits.snapshot_max_bytes = 1024 * 1024;
        config.limits.basic_check_threshold_bytes = 2 * 1024 * 1024;
        config.limits.lock_acquisition_retry_backoff_ms = 1;
        config.limits.motw_read_timeout_ms = 0;
        let captured = capture(&path, &config).unwrap();
        assert_eq!(captured.depth, CaptureDepth::BasicCheckOnly);
        assert!(captured.snapshot.is_none());
        assert!(captured.thresholds.basic_check_only);
        assert!(!captured.thresholds.deep_analysis_eligible);
        assert_eq!(captured.sha256.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn active_writer_prevents_readiness_until_timeout() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("writing.bin");
        let writer = File::create(&path).unwrap();
        let mut config = Config::default();
        config.limits.lock_acquisition_timeout_ms = 30;
        config.limits.lock_acquisition_retry_backoff_ms = 5;
        config.limits.motw_read_timeout_ms = 0;
        let result = capture(&path, &config);
        assert!(matches!(result, Err(CaptureError::LockTimeout { .. })));
        drop(writer);
    }

    #[test]
    #[ignore = "creates and hashes an 8 GiB sparse fixture; run explicitly for the BasicCheckOnly benchmark"]
    fn basic_check_benchmark_eight_gibibytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.bin");
        let file = File::create(&path).unwrap();
        let size = 8 * 1024 * 1024 * 1024u64;
        file.set_len(size).unwrap();
        drop(file);
        let mut config = Config::default();
        config.limits.snapshot_max_bytes = 512 * 1024 * 1024;
        config.limits.basic_check_threshold_bytes = 2 * 1024 * 1024 * 1024;
        config.limits.motw_read_timeout_ms = 0;
        let started = Instant::now();
        let captured = capture(&path, &config).unwrap();
        assert_eq!(captured.depth, CaptureDepth::BasicCheckOnly);
        // 100 Mbps transfer time is about 11 minutes for 8 GiB; 20% is 132 seconds.
        assert!(started.elapsed() < Duration::from_secs(132));
    }
}
