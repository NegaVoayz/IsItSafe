use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone)]
pub struct ExecutionBarrierStatus {
    pub download_dir: PathBuf,
    pub user_sid: String,
    pub inherited_deny_execute: bool,
}

/// Applies and verifies the inheritance-only deny-execute ACE for the current
/// user on the download directory. This prevents Win32 images from executing
/// while they remain under that directory, including in new subdirectories.
pub fn ensure_download_execution_barrier(download_dir: &Path) -> Result<ExecutionBarrierStatus> {
    if !download_dir.is_absolute() {
        bail!(
            "download directory must be an absolute path: {}",
            download_dir.display()
        );
    }
    if !download_dir.is_dir() {
        bail!(
            "download directory does not exist or is not a directory: {}",
            download_dir.display()
        );
    }
    let metadata = fs::symlink_metadata(download_dir)
        .with_context(|| format!("failed to inspect {}", download_dir.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing to apply an execution barrier through a link: {}",
            download_dir.display()
        );
    }

    #[cfg(windows)]
    {
        windows::ensure(download_dir)
    }
    #[cfg(not(windows))]
    {
        bail!("the download execution barrier is supported only on Windows")
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{addr_of, null_mut};

    use anyhow::{Context, Result, bail};
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_DENIED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_EXECUTE;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::ExecutionBarrierStatus;
    use crate::process::hidden_command;

    pub(super) fn ensure(download_dir: &Path) -> Result<ExecutionBarrierStatus> {
        let user_sid = current_user_sid()?;
        let path = wide(download_dir.as_os_str().encode_wide().collect());
        let sid_utf16 = wide(user_sid.encode_utf16().collect());
        if has_inherited_deny_execute(&path, &sid_utf16)? {
            return Ok(ExecutionBarrierStatus {
                download_dir: download_dir.to_path_buf(),
                user_sid,
                inherited_deny_execute: true,
            });
        }
        let deny_ace = format!("*{user_sid}:(OI)(IO)(X)");

        let output = hidden_command("icacls.exe")
            .arg(download_dir)
            .arg("/deny")
            .arg(&deny_ace)
            .output()
            .context("failed to run icacls for the download execution barrier")?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let detail = detail.trim();
            bail!(
                "icacls could not apply the download execution barrier{}",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            );
        }

        let inherited_deny_execute = has_inherited_deny_execute(&path, &sid_utf16)?;
        if !inherited_deny_execute {
            bail!(
                "icacls reported success, but the inherited DENY EXECUTE ACE for {user_sid} was not found"
            );
        }
        Ok(ExecutionBarrierStatus {
            download_dir: download_dir.to_path_buf(),
            user_sid,
            inherited_deny_execute,
        })
    }

    fn current_user_sid() -> Result<String> {
        let mut token = null_mut();
        // SAFETY: token is a valid out-pointer and the pseudo-handle belongs to
        // the current process for the duration of this call.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            bail!("OpenProcessToken failed while reading the current user SID");
        }

        let result = (|| {
            let mut needed = 0u32;
            // The first call intentionally has no buffer so Windows returns the
            // required size and ERROR_INSUFFICIENT_BUFFER.
            unsafe {
                GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
            }
            if needed == 0 {
                bail!("GetTokenInformation returned an empty user SID buffer size");
            }
            let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
            let ok = unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            };
            if ok == 0 {
                bail!("GetTokenInformation failed while reading the current user SID");
            }

            // SAFETY: the buffer is pointer-aligned and Windows initialized the
            // TOKEN_USER prefix. Its SID remains valid until the token is closed.
            let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
            let mut sid_text = null_mut();
            let converted = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) };
            if converted == 0 || sid_text.is_null() {
                bail!("ConvertSidToStringSidW failed for the current user SID");
            }
            let length = unsafe { (0..).take_while(|index| *sid_text.add(*index) != 0).count() };
            let text =
                String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_text, length) });
            unsafe {
                LocalFree(sid_text.cast());
            }
            Ok(text)
        })();

        // SAFETY: token was opened successfully above and is no longer needed.
        unsafe {
            CloseHandle(token);
        }
        result
    }

    fn has_inherited_deny_execute(path: &[u16], sid_text: &[u16]) -> Result<bool> {
        let mut user_sid = null_mut();
        // SAFETY: sid_text is NUL-terminated and user_sid is a valid out-pointer.
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut user_sid) } == 0 {
            bail!("ConvertStringSidToSidW failed while verifying the execution barrier");
        }

        let mut security_descriptor = null_mut();
        let result = (|| {
            let mut dacl = null_mut();
            // SAFETY: path is NUL-terminated and all out-pointers are valid.
            let status = unsafe {
                GetNamedSecurityInfoW(
                    path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut dacl,
                    null_mut(),
                    &mut security_descriptor,
                )
            };
            if status != ERROR_SUCCESS {
                bail!("GetNamedSecurityInfoW failed with Win32 error {status}");
            }
            if dacl.is_null() {
                return Ok(false);
            }

            let mut info: ACL_SIZE_INFORMATION = unsafe { zeroed() };
            // SAFETY: dacl points into the allocated security descriptor and
            // info has the size required by AclSizeInformation.
            let ok = unsafe {
                GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            };
            if ok == 0 {
                bail!("GetAclInformation failed while verifying the execution barrier");
            }

            for index in 0..info.AceCount {
                let mut raw_ace = null_mut::<c_void>();
                // SAFETY: index is below AceCount and raw_ace is a valid out-pointer.
                if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
                    continue;
                }
                // ACCESS_DENIED_ACE_TYPE is 1. Keeping the numeric check avoids
                // pulling in the broad SystemServices feature only for this value.
                let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
                if header.AceType != 1 {
                    continue;
                }
                let ace = unsafe { &*raw_ace.cast::<ACCESS_DENIED_ACE>() };
                if ace.Mask & FILE_EXECUTE == 0 {
                    continue;
                }
                let required_flags = (OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE) as u8;
                if ace.Header.AceFlags & required_flags != required_flags {
                    continue;
                }
                let ace_sid = addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
                if unsafe { EqualSid(ace_sid, user_sid) } != 0 {
                    return Ok(true);
                }
            }
            Ok(false)
        })();

        // SAFETY: both allocations were created by Windows and are local.
        unsafe {
            if !user_sid.is_null() {
                LocalFree(user_sid.cast());
            }
            if !security_descriptor.is_null() {
                LocalFree(security_descriptor.cast());
            }
        }
        result
    }

    fn wide(value: Vec<u16>) -> Vec<u16> {
        let mut value = value;
        value.push(0);
        value
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn initialization_applies_and_verifies_the_deny_execute_ace() {
        let directory = tempfile::tempdir().unwrap();
        let status = ensure_download_execution_barrier(directory.path()).unwrap();
        assert!(status.user_sid.starts_with("S-1-"));
        assert!(status.inherited_deny_execute);
        let second = ensure_download_execution_barrier(directory.path()).unwrap();
        assert!(second.inherited_deny_execute);
    }
}
