#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskGroup {
    Critical,
    High,
    Review,
    Limited,
    Unknown,
}

impl RiskGroup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Review => "Needs review",
            Self::Limited => "Limited visibility",
            Self::Unknown => "Unknown",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Critical => "Known malicious evidence",
            Self::High => "Suspicious structure or behavior",
            Self::Review => "Unresolved or incomplete checks",
            Self::Limited => "Only shallow checks were possible",
            Self::Unknown => "The original report is unavailable",
        }
    }

    pub fn from_verdict(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Malicious => Self::Critical,
            Verdict::Suspicious => Self::High,
            Verdict::ReviewRequired | Verdict::Unverified | Verdict::Incomplete => Self::Review,
            Verdict::Limited | Verdict::BasicCheckOnly => Self::Limited,
            Verdict::NoHighRiskFound => Self::Unknown,
        }
    }
}

