use anyhow::{Context, Result, bail};

use crate::config::Config;

pub const VIRUSTOTAL_TARGET: &str = "IsItSafe/VirusTotal";

pub fn virus_total_api_key(config: &Config) -> Result<Option<String>> {
    if let Ok(value) = std::env::var("VIRUSTOTAL_API_KEY")
        && !value.trim().is_empty()
    {
        return Ok(Some(value));
    }
    if let Some(value) = &config.virus_total.api_key {
        let value = value.as_str().trim();
        if !value.is_empty() {
            return Ok(Some(value.to_owned()));
        }
    }
    credential_read(VIRUSTOTAL_TARGET)
}

pub fn store_virus_total_api_key(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("API key cannot be empty");
    }
    credential_write(VIRUSTOTAL_TARGET, value)
}

#[cfg(windows)]
fn credential_read(target: &str) -> Result<Option<String>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
    use windows_sys::Win32::Security::Credentials::{
        CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
    };
    let target: Vec<u16> = target.encode_utf16().chain(Some(0)).collect();
    let mut credential = ptr::null_mut::<CREDENTIALW>();
    let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
    if ok == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
            return Ok(None);
        }
        return Err(error).context("failed to read VirusTotal key from Credential Manager");
    }
    let value = unsafe {
        let credential = &*credential;
        let len = credential.CredentialBlobSize as usize / 2;
        let pointer = credential.CredentialBlob as *const u16;
        let slice = std::slice::from_raw_parts(pointer, len);
        String::from_utf16(slice)
    };
    unsafe { CredFree(credential.cast()) };
    value.map(Some).map_err(Into::into)
}

#[cfg(windows)]
fn credential_write(target: &str, value: &str) -> Result<()> {
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
    };
    let mut target_wide: Vec<u16> = target.encode_utf16().chain(Some(0)).collect();
    let mut blob: Vec<u16> = value.encode_utf16().collect();
    let credential = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target_wide.as_mut_ptr(),
        Comment: std::ptr::null_mut(),
        LastWritten: Default::default(),
        CredentialBlobSize: u32::try_from(blob.len() * 2)?,
        CredentialBlob: blob.as_mut_ptr().cast(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: std::ptr::null_mut(),
        UserName: std::ptr::null_mut(),
    };
    let ok = unsafe { CredWriteW(&credential, 0) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to write VirusTotal key to Credential Manager");
    }
    Ok(())
}

#[cfg(not(windows))]
fn credential_read(_target: &str) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(not(windows))]
fn credential_write(_target: &str, _value: &str) -> Result<()> {
    bail!("Windows Credential Manager is only available on Windows")
}
