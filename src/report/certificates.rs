#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChainEvidence {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub sha256_fingerprint: String,
    pub ocsp_urls: Vec<String>,
    pub crl_urls: Vec<String>,
    pub role: CertificateRole,
    pub root_trusted: Option<bool>,
    pub timestamp_present: bool,
    pub timestamp_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
    pub revocation: RevocationEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateRole {
    Leaf,
    Intermediate,
    Root,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevocationEvidence {
    pub state: RevocationState,
    pub source: Option<String>,
    pub this_update: Option<DateTime<Utc>>,
    pub next_update: Option<DateTime<Utc>>,
    pub detail: Option<String>,
}

impl Default for RevocationState {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationState {
    Valid,
    Revoked,
    Unknown,
    NotChecked,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthenticityEvidence {
    pub signature_digest_valid: Option<bool>,
    pub chain_valid: Option<bool>,
    pub timestamp_state: TimestampState,
    pub publisher_identity: Option<String>,
    pub publisher_reputation: PublisherReputation,
    pub unsigned_components: u32,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampState {
    Valid,
    Missing,
    Invalid,
    Unknown,
}

impl Default for TimestampState {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherReputation {
    Trusted,
    Known,
    RemoteAccess,
    BundlerOrPup,
    Untrusted,
    Unknown,
}

impl Default for PublisherReputation {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentEvidence {
    pub nesting_path: String,
    pub name: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub formats: Vec<DetectedFormat>,
    pub severity: Severity,
    pub signed: Option<bool>,
    pub evidence: Vec<Evidence>,
}

/// Product metadata declared by an executable or installer package. This is
/// what the file claims it will install; it is not proof of runtime behavior.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProductIdentityEvidence {
    pub product_name: Option<String>,
    pub manufacturer: Option<String>,
    pub product_version: Option<String>,
    pub product_code: Option<String>,
    pub upgrade_code: Option<String>,
    pub original_filename: Option<String>,
    pub file_description: Option<String>,
    pub legal_copyright: Option<String>,
    #[serde(default)]
    pub signer_identity: Option<String>,
    #[serde(default)]
    pub signer_sha256: Option<String>,
    #[serde(default)]
    pub signature_digest_valid: Option<bool>,
    #[serde(default)]
    pub signature_not_before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub signature_not_after: Option<DateTime<Utc>>,
    pub source: String,
    pub nesting_path: Option<String>,
}

