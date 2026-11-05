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

