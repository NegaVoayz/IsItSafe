#[derive(Debug, Clone)]
pub struct QuestionableFile {
    pub summary: ReportSummary,
    pub group: RiskGroup,
}

#[derive(Debug, Clone)]
pub struct QuarantineItem {
    pub sha256: String,
    pub path: PathBuf,
    pub moved_at: DateTime<Utc>,
    pub summary: Option<ReportSummary>,
    pub display_name: String,
    pub reasons: Vec<String>,
    pub group: RiskGroup,
}

impl QuarantineItem {
    pub fn suggested_download_name(&self) -> String {
        self.summary
            .as_ref()
            .map(|summary| summary.file_name.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| quarantine_original_name(&self.path))
    }
}

#[derive(Debug, Clone, Default)]
pub struct DesktopSnapshot {
    pub questionable: Vec<QuestionableFile>,
    pub quarantine: Vec<QuarantineItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    Invalid,
    Revoked,
    Expired,
    NotYetValid,
    Unsigned,
    Unknown,
    Unverified,
    Valid,
}

impl SignatureState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Invalid => "Invalid",
            Self::Revoked => "Revoked",
            Self::Expired => "Expired",
            Self::NotYetValid => "Not Yet Valid",
            Self::Unsigned => "Unsigned",
            Self::Unknown => "Unknown",
            Self::Unverified => "Unverified",
            Self::Valid => "Valid",
        }
    }

    pub fn risk_rank(self) -> u8 {
        match self {
            Self::Invalid => 0,
            Self::Revoked => 1,
            Self::Unsigned => 2,
            Self::Expired => 3,
            Self::NotYetValid => 4,
            Self::Unknown => 5,
            Self::Unverified => 6,
            Self::Valid => 7,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SoftwareIdentityGroup {
    pub product_name: String,
    pub manufacturer: Option<String>,
    pub product_version: Option<String>,
    pub certificates: Vec<SignatureGroup>,
}

impl SoftwareIdentityGroup {
    pub fn risk_state(&self) -> SignatureState {
        self.certificates
            .iter()
            .map(|certificate| certificate.state)
            .min_by_key(|state| state.risk_rank())
            .unwrap_or(SignatureState::Unknown)
    }

    pub fn starts_expanded(&self) -> bool {
        self.risk_state() != SignatureState::Valid
    }
}

#[derive(Debug, Clone)]
pub struct SignatureGroup {
    pub signer: String,
    pub certificate_sha256: Option<String>,
    pub state: SignatureState,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub products: Vec<ProductIdentityEvidence>,
}

