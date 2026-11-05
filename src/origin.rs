use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::{AppPaths, Config};
use crate::db::{
    Database, DownloadOrigin, normalize_path, read_native_message, write_native_message,
};
use crate::process::hidden_command;
use crate::report::{FieldState, OriginEvidence, OriginState};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserDownload {
    pub schema_version: u32,
    pub download_id: String,
    pub source_url: String,
    pub final_url: Option<String>,
    pub referrer: Option<String>,
    pub final_path: String,
    pub timestamp: DateTime<Utc>,
    pub expected_size: Option<u64>,
    pub browser_danger: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeResponse {
    pub ok: bool,
    pub message: String,
}

pub fn validate_sender_origin(arg: Option<&str>, config: &Config) -> Result<()> {
    if !config.origin.enabled {
        return Ok(());
    }
    let sender = arg.unwrap_or_default();
    let mut allowed = HashSet::new();
    for id in &config.origin.chrome_extension_ids {
        allowed.insert(format!("chrome-extension://{id}/"));
    }
    for id in &config.origin.firefox_extension_ids {
        allowed.insert(format!("moz-extension://{id}/"));
    }
    if allowed.is_empty() {
        bail!(
            "no extension IDs are configured in origin.chrome_extension_ids or origin.firefox_extension_ids"
        );
    }
    if !allowed.contains(sender) {
        bail!("native message sender is not allowlisted: {sender}");
    }
    Ok(())
}

pub fn run_native_host(config: &Config, database: &Database) -> Result<()> {
    let sender = std::env::args().nth(1);
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let result = (|| -> Result<()> {
        validate_sender_origin(sender.as_deref(), config)?;
        let bytes = read_native_message(&mut stdin, config.origin.max_message_bytes as usize)?;
        let download: BrowserDownload = serde_json::from_slice(&bytes)?;
        if download.schema_version != 1 {
            bail!(
                "unsupported origin schema version {}",
                download.schema_version
            );
        }
        validate_url(&download.source_url)?;
        if let Some(url) = &download.final_url {
            validate_url(url)?;
        }
        let final_path = if Path::new(&download.final_path).is_absolute() {
            download.final_path.clone()
        } else {
            config
                .download_dir
                .join(&download.final_path)
                .to_string_lossy()
                .into_owned()
        };
        let origin = DownloadOrigin {
            schema_version: 1,
            download_id: download.download_id,
            source_url: download.source_url,
            final_url: download.final_url,
            referrer: download.referrer,
            final_path,
            timestamp: download.timestamp,
            expected_size: download.expected_size,
            browser_danger: download.browser_danger,
        };
        database.insert_origin(&origin)?;
        Ok(())
    })();
    match result {
        Ok(()) => write_native_message(
            &mut stdout,
            &serde_json::to_vec(&NativeResponse {
                ok: true,
                message: "origin recorded".into(),
            })?,
        ),
        Err(error) => {
            write_native_message(
                &mut stdout,
                &serde_json::to_vec(&NativeResponse {
                    ok: false,
                    message: error.to_string(),
                })?,
            )?;
            Err(error)
        }
    }
}

pub fn install_native_host(config: &Config, paths: &AppPaths) -> Result<Vec<PathBuf>> {
    if config.origin.chrome_extension_ids.is_empty()
        && config.origin.firefox_extension_ids.is_empty()
    {
        bail!(
            "configure at least one browser extension ID before installing the Native Messaging host"
        );
    }
    let current = std::env::current_exe()?;
    let executable = current
        .parent()
        .map(|parent| parent.join("isitsafe-native-host.exe"))
        .filter(|candidate| candidate.exists())
        .unwrap_or(current);
    let host_dir = paths.data_dir.join("native-messaging");
    fs::create_dir_all(&host_dir)?;
    let chrome_manifest_path = host_dir.join("com.isitsafe.origin.json");
    let chrome = serde_json::json!({
        "name": "com.isitsafe.origin",
        "description": "IsItSafe download origin host",
        "path": executable.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": config.origin.chrome_extension_ids.iter()
            .map(|id| format!("chrome-extension://{id}/"))
            .collect::<Vec<_>>()
    });
    fs::write(&chrome_manifest_path, serde_json::to_vec_pretty(&chrome)?)?;
    let mut installed = vec![chrome_manifest_path.clone()];

    for (browser, registry) in [
        (
            "Chrome",
            "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.isitsafe.origin",
        ),
        (
            "Edge",
            "HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.isitsafe.origin",
        ),
    ] {
        if !config.origin.chrome_extension_ids.is_empty() {
            let output = hidden_command("reg.exe")
                .args([
                    "add",
                    registry,
                    "/ve",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &chrome_manifest_path.to_string_lossy(),
                    "/f",
                ])
                .output()?;
            if !output.status.success() {
                bail!("failed to register the {browser} Native Messaging host");
            }
        }
    }

    if !config.origin.firefox_extension_ids.is_empty() {
        let appdata = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("APPDATA is unavailable"))?;
        let firefox_dir = appdata.join("Mozilla").join("NativeMessagingHosts");
        fs::create_dir_all(&firefox_dir)?;
        let firefox_path = firefox_dir.join("com.isitsafe.origin.json");
        let firefox = serde_json::json!({
            "name": "com.isitsafe.origin",
            "description": "IsItSafe download origin host",
            "path": executable.to_string_lossy(),
            "type": "stdio",
            "allowed_extensions": config.origin.firefox_extension_ids
        });
        fs::write(&firefox_path, serde_json::to_vec_pretty(&firefox)?)?;
        installed.push(firefox_path);
    }
    Ok(installed)
}

pub fn correlate(
    database: &Database,
    path: &Path,
    sha256: Option<&str>,
    config: &Config,
) -> Result<OriginEvidence> {
    if !config.origin.enabled {
        return Ok(OriginEvidence {
            state: OriginState::TrackingDisabled,
            ..OriginEvidence::default()
        });
    }
    let path = path.to_string_lossy();
    let window = std::time::Duration::from_millis(config.events.origin_correlation_window_ms);
    let origin = match database.find_origin(&path, window)? {
        Some(origin) => Some(origin),
        None => match sha256 {
            Some(hash) => database.find_origin_by_hash(hash, window)?,
            None => None,
        },
    };
    if let (Some(origin), Some(hash)) = (&origin, sha256) {
        database.bind_origin_hash(&origin.final_path, hash)?;
    }
    match origin {
        Some(origin) => Ok(OriginEvidence {
            state: OriginState::Matched,
            download_id: Some(origin.download_id),
            source_url: Some(origin.source_url),
            final_url: origin.final_url,
            referrer: origin.referrer.clone(),
            referrer_state: if origin.referrer.is_some() {
                FieldState::Present
            } else {
                FieldState::Unavailable
            },
            browser_danger: origin.browser_danger,
            observed_at: Some(origin.timestamp),
            correlation: Some(format!(
                "path+time or sha256; normalized={}",
                normalize_path(&origin.final_path)
            )),
        }),
        None => Ok(OriginEvidence {
            state: OriginState::Unknown,
            referrer_state: FieldState::Unavailable,
            ..OriginEvidence::default()
        }),
    }
}

pub fn receive_for_test<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    max_bytes: usize,
) -> Result<BrowserDownload> {
    let body = read_native_message(reader, max_bytes)?;
    let message: BrowserDownload = serde_json::from_slice(&body)?;
    write_native_message(writer, b"{\"ok\":true}")?;
    Ok(message)
}

fn validate_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value)?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("download URL must use http or https");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_messaging_rejects_oversize_length() {
        let bytes = u32::MAX.to_le_bytes().to_vec();
        let mut reader = std::io::Cursor::new(bytes);
        assert!(read_native_message(&mut reader, 1024).is_err());
    }

    #[test]
    fn native_message_frame_round_trip() {
        let body = br#"{"schema_version":1}"#;
        let mut encoded = Vec::new();
        write_native_message(&mut encoded, body).unwrap();
        let mut reader = std::io::Cursor::new(encoded);
        assert_eq!(
            read_native_message(&mut reader, 1024).unwrap(),
            body.to_vec()
        );
    }
}
