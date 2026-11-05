use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use reqwest::blocking::Client;
use std::io::Read;

use crate::config::Config;
use crate::report::{AnalysisReportV1, RevocationState};

pub fn update_revocation(report: &mut AnalysisReportV1, config: &Config) -> Result<()> {
    if report.certificates.is_empty() {
        return Ok(());
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_millis(
            config.virus_total.request_timeout_ms,
        ))
        .user_agent(concat!("isitsafe/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    for certificate in &mut report.certificates {
        let mut checked = false;
        for url in certificate.crl_urls.iter().take(3) {
            let parsed = match url::Url::parse(url) {
                Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => parsed,
                _ => continue,
            };
            if !public_revocation_host(&parsed) {
                certificate.revocation.state = RevocationState::Unknown;
                certificate.revocation.detail =
                    Some("revocation endpoint resolved to a local/private host".into());
                continue;
            }
            let response = match client.get(parsed).send() {
                Ok(response) if response.status().is_success() => response,
                _ => continue,
            };
            let mut bytes = Vec::new();
            if response
                .take(config.limits.max_network_response_bytes)
                .read_to_end(&mut bytes)
                .is_err()
            {
                continue;
            }
            // Cryptographic verification of CRL/OCSP signatures is mandatory.
            // Until a response can be verified against its issuer, its presence
            // is not evidence that the certificate is valid.
            certificate.revocation.state = RevocationState::Unknown;
            certificate.revocation.source = Some(url.clone());
            certificate.revocation.detail = Some(
                "revocation response was fetched but could not be cryptographically verified"
                    .into(),
            );
            checked = true;
            break;
        }
        if !checked && !certificate.ocsp_urls.is_empty() {
            certificate.revocation.state = RevocationState::Unknown;
            certificate.revocation.detail = Some(
                "OCSP responder is configured but response verification is unavailable".into(),
            );
        }
    }
    apply_windows_chain_result(report);
    Ok(())
}

fn public_revocation_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_private()
                || address.is_link_local()
                || address.is_broadcast())
        }
        Some(url::Host::Ipv6(address)) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local())
        }
        Some(url::Host::Domain(domain)) => {
            !domain.eq_ignore_ascii_case("localhost") && !domain.ends_with(".localhost")
        }
        None => false,
    }
}

pub fn fresh(now: DateTime<Utc>, this_update: DateTime<Utc>, next_update: DateTime<Utc>) -> bool {
    now >= this_update - Duration::minutes(5) && now <= next_update
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_and_future_revocation_windows_are_not_fresh() {
        let now = Utc::now();
        assert!(!fresh(
            now,
            now - Duration::days(2),
            now - Duration::days(1)
        ));
        assert!(!fresh(
            now,
            now + Duration::days(1),
            now + Duration::days(2)
        ));
        assert!(fresh(
            now,
            now - Duration::hours(1),
            now + Duration::hours(1)
        ));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainResult {
    Valid,
    Revoked,
    RevocationUnknown,
    Expired,
    Invalid,
    Unsigned,
    Unavailable,
}

#[cfg(windows)]
fn verify_windows_chain(path: &std::path::Path) -> ChainResult {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{
        CERT_E_EXPIRED, CERT_E_REVOKED, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WinVerifyTrust,
    };
    let wide: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(Some(0))
        .collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = unsafe { zeroed::<WINTRUST_DATA>() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
    }
    if status == 0 {
        ChainResult::Valid
    } else if status == CERT_E_REVOKED {
        ChainResult::Revoked
    } else if status == CERT_E_EXPIRED {
        ChainResult::Expired
    } else if status == TRUST_E_NOSIGNATURE {
        ChainResult::Unsigned
    } else if status == TRUST_E_EXPLICIT_DISTRUST {
        ChainResult::Invalid
    } else if (status as u32) == 0x800B_010Eu32
        || (status as u32) == 0x8009_2006u32
        || (status as u32) == 0x800C_000Cu32
    {
        ChainResult::RevocationUnknown
    } else {
        ChainResult::Unavailable
    }
}

#[cfg(not(windows))]
fn verify_windows_chain(_path: &std::path::Path) -> ChainResult {
    ChainResult::Unavailable
}

fn apply_windows_chain_result(report: &mut AnalysisReportV1) {
    let Some(path) = report.source_path.as_deref() else {
        return;
    };
    if std::fs::metadata(path).map_or(true, |metadata| metadata.len() != report.file.size) {
        if let Some(authenticity) = report.authenticity.as_mut() {
            authenticity.detail = Some(
                "source changed before Windows chain verification; authenticity remains unverified"
                    .into(),
            );
        }
        return;
    }
    let result = verify_windows_chain(path);
    if result == ChainResult::Unavailable || result == ChainResult::Unsigned {
        return;
    }
    if let Some(authenticity) = report.authenticity.as_mut() {
        authenticity.chain_valid = Some(result == ChainResult::Valid);
        if result == ChainResult::Expired {
            authenticity.timestamp_state = crate::report::TimestampState::Invalid;
        }
    }
    for certificate in &mut report.certificates {
        if certificate.role == crate::report::CertificateRole::Root {
            certificate.root_trusted = Some(matches!(
                result,
                ChainResult::Valid
                    | ChainResult::Revoked
                    | ChainResult::Expired
                    | ChainResult::RevocationUnknown
            ));
            continue;
        }
        certificate.root_trusted = Some(matches!(
            result,
            ChainResult::Valid
                | ChainResult::Revoked
                | ChainResult::Expired
                | ChainResult::RevocationUnknown
        ));
        certificate.revocation.state = match result {
            ChainResult::Valid => RevocationState::Valid,
            ChainResult::Revoked => RevocationState::Revoked,
            _ => RevocationState::Unknown,
        };
        certificate.revocation.source = Some("Windows WinVerifyTrust".into());
        certificate.revocation.detail = Some(match result {
            ChainResult::Valid => {
                "Windows authenticated the chain and completed configured revocation checks".into()
            }
            ChainResult::Revoked => "Windows reported a revoked certificate".into(),
            ChainResult::Expired => "Windows reported an expired certificate".into(),
            ChainResult::Invalid => "Windows rejected the certificate chain".into(),
            ChainResult::RevocationUnknown => {
                "Windows could not conclusively check revocation".into()
            }
            ChainResult::Unsigned | ChainResult::Unavailable => {
                "Windows authenticity result is unavailable".into()
            }
        });
    }
}
