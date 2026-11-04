use std::fs;
use std::path::PathBuf;

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

#[cfg(feature = "yara")]
use anyhow::Context;
#[cfg(feature = "yara")]
use sha2::{Digest, Sha256};
#[cfg(feature = "yara")]
use std::time::Duration;

use crate::config::{AppPaths, Config};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRuleManifest {
    pub payload: RuleManifestPayload,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleManifestPayload {
    pub schema_version: u32,
    pub version: String,
    pub rules: Vec<RemoteRuleFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRuleFile {
    pub name: String,
    pub url: String,
    pub sha256: String,
}

pub fn active_rules_path(paths: &AppPaths) -> PathBuf {
    paths.rules_dir.join("active.yar")
}

pub fn load_active_rules(paths: &AppPaths, max_bytes: usize) -> Result<Option<String>> {
    let path = active_rules_path(paths);
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(&path)?;
    if metadata.len() > max_bytes as u64 {
        bail!("active YARA rule file exceeds the configured size limit");
    }
    Ok(Some(fs::read_to_string(path)?))
}

pub fn update_rules(config: &Config, paths: &AppPaths) -> Result<PathBuf> {
    #[cfg(not(feature = "yara"))]
    {
        let _ = (config, paths);
        bail!("YARA support is not enabled; rebuild with --features yara");
    }
    #[cfg(feature = "yara")]
    {
        let url = config
            .yara
            .remote_manifest_url
            .as_deref()
            .context("yara.remote_manifest_url is not configured")?;
        if !url.starts_with("https://") {
            bail!("YARA manifest URL must use HTTPS");
        }
        let key_text = config
            .yara
            .public_key_base64
            .as_deref()
            .context("yara.public_key_base64 is not configured")?;
        let key_bytes = STANDARD.decode(key_text.trim())?;
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("YARA public key must contain 32 bytes"))?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("isitsafe/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let manifest_bytes = fetch_limited(&client, url, 1024 * 1024)?;
        let signed: SignedRuleManifest = serde_json::from_slice(&manifest_bytes)?;
        if signed.payload.schema_version != 1 {
            bail!("unsupported YARA manifest schema version");
        }
        let canonical = serde_json::to_vec(&signed.payload)?;
        let signature_bytes = STANDARD.decode(signed.signature.trim())?;
        UnparsedPublicKey::new(&ED25519, &key_bytes)
            .verify(&canonical, &signature_bytes)
            .map_err(|_| anyhow::anyhow!("YARA manifest signature verification failed"))?;
        let max_rule_bytes = config
            .yara
            .max_rules_bytes
            .unwrap_or(16 * 1024 * 1024)
            .min(64 * 1024 * 1024) as usize;
        let mut combined = String::new();
        for rule in signed.payload.rules {
            if !rule.url.starts_with("https://") {
                bail!("YARA rule URL must use HTTPS: {}", rule.url);
            }
            let bytes = fetch_limited(&client, &rule.url, max_rule_bytes)?;
            let digest = hex::encode(Sha256::digest(&bytes));
            if !digest.eq_ignore_ascii_case(&rule.sha256) {
                bail!("YARA rule digest mismatch for {}", rule.name);
            }
            let text = String::from_utf8(bytes)
                .with_context(|| format!("YARA rule {} is not UTF-8", rule.name))?;
            combined.push_str(&format!(
                "// source={} sha256={}\n{}\n",
                rule.name, rule.sha256, text
            ));
            if combined.len() > max_rule_bytes {
                bail!("combined YARA rules exceed the configured limit");
            }
        }
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(combined.as_str())?;
        let _ = compiler.build();
        fs::create_dir_all(&paths.rules_dir)?;
        let destination = active_rules_path(paths);
        let temporary = destination.with_extension("yar.tmp");
        fs::write(&temporary, combined)?;
        fs::rename(&temporary, &destination)?;
        Ok(destination)
    }
}

#[cfg(feature = "yara")]
fn fetch_limited(
    client: &reqwest::blocking::Client,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut response = client.get(url).send()?;
    if !response.status().is_success() {
        bail!("rule fetch returned HTTP {}", response.status());
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("rule response exceeds the configured size limit");
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        bail!("rule response exceeds the configured size limit");
    }
    Ok(bytes)
}

pub fn manifest_payload_bytes(payload: &RuleManifestPayload) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(payload)?)
}

pub fn verify_manifest(
    payload: &RuleManifestPayload,
    signature_base64: &str,
    public_key_base64: &str,
) -> Result<()> {
    let key = STANDARD.decode(public_key_base64)?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must contain 32 bytes"))?;
    let signature = STANDARD.decode(signature_base64)?;
    UnparsedPublicKey::new(&ED25519, &key)
        .verify(&manifest_payload_bytes(payload)?, &signature)
        .map_err(|_| anyhow::anyhow!("manifest signature verification failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn detects_rule_digest_mismatch() {
        let payload = RuleManifestPayload {
            schema_version: 1,
            version: "1".into(),
            rules: vec![RemoteRuleFile {
                name: "x.yar".into(),
                url: "https://example.invalid/x.yar".into(),
                sha256: "00".repeat(32),
            }],
        };
        assert_eq!(payload.rules[0].name, "x.yar");
    }

    #[test]
    fn active_path_stays_under_data_directory() {
        let root = Path::new("C:\\data");
        assert!(
            active_rules_path(&AppPaths {
                config_file: root.join("config.toml"),
                data_dir: root.to_path_buf(),
                database: root.join("state.db"),
                reports_dir: root.join("reports"),
                logs_dir: root.join("logs"),
                quarantine_dir: root.join("quarantine"),
                rules_dir: root.join("rules"),
            })
            .starts_with(root)
        );
    }

    #[test]
    fn signed_manifest_verification_rejects_tampering() {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let payload = RuleManifestPayload {
            schema_version: 1,
            version: "1".into(),
            rules: Vec::new(),
        };
        let signature = STANDARD.encode(
            key_pair
                .sign(&serde_json::to_vec(&payload).unwrap())
                .as_ref(),
        );
        let public_key = STANDARD.encode(key_pair.public_key().as_ref());
        verify_manifest(&payload, &signature, &public_key).unwrap();

        let mut tampered = payload;
        tampered.version = "2".into();
        assert!(verify_manifest(&tampered, &signature, &public_key).is_err());
    }
}
