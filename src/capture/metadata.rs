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

