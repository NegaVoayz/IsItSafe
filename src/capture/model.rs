const HEAD_BYTES: usize = 64 * 1024;
const TAIL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureDepth {
    Deep,
    Limited,
    BasicCheckOnly,
}

#[derive(Debug)]
pub struct CapturedFile {
    pub path: PathBuf,
    pub file: FileEvidence,
    pub sha256: Option<String>,
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
    pub snapshot: Option<Vec<u8>>,
    pub lock: LockAcquisitionEvidence,
    pub motw: MotwEvidence,
    pub alternate_streams: Vec<AlternateStream>,
    pub thresholds: ThresholdDecisions,
    pub depth: CaptureDepth,
    pub boundaries: Vec<Boundary>,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("exclusive readiness lock timed out")]
    LockTimeout {
        file: FileEvidence,
        lock: LockAcquisitionEvidence,
    },
    #[error("exclusive readiness lock is unavailable: {detail}")]
    LockUnavailable {
        file: FileEvidence,
        lock: LockAcquisitionEvidence,
        outcome: LockAcquisitionOutcome,
        detail: String,
    },
    #[error("file changed while held under the readiness lock")]
    ChangedDuringRead {
        file: FileEvidence,
        lock: LockAcquisitionEvidence,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

