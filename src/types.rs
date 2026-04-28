use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        (s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| Self(s.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn short(&self) -> &str {
        &self.0[..12.min(self.0.len())]
    }
}

impl std::fmt::Display for CommitSha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpgStatusCode {
    Good,
    Bad,
    GoodUntrusted,
    NoSignature,
    GoodKeyExpiredAtSigning,
    GoodKeyExpired,
    GoodKeyRevoked,
    CannotCheck,
}

impl GpgStatusCode {
    pub fn from_char(c: char) -> Option<Self> {
        Some(match c {
            'G' => Self::Good,
            'B' => Self::Bad,
            'U' => Self::GoodUntrusted,
            'N' => Self::NoSignature,
            'X' => Self::GoodKeyExpiredAtSigning,
            'Y' => Self::GoodKeyExpired,
            'R' => Self::GoodKeyRevoked,
            'E' => Self::CannotCheck,
            _ => return None,
        })
    }

    pub fn as_char(self) -> char {
        match self {
            Self::Good => 'G',
            Self::Bad => 'B',
            Self::GoodUntrusted => 'U',
            Self::NoSignature => 'N',
            Self::GoodKeyExpiredAtSigning => 'X',
            Self::GoodKeyExpired => 'Y',
            Self::GoodKeyRevoked => 'R',
            Self::CannotCheck => 'E',
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommitRecord {
    pub sha: CommitSha,
    pub gpg_status: GpgStatusCode,
    pub committer_email: Option<String>,
    pub signer_name: Option<String>,
    pub signing_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    Unsigned,
    SignatureInvalid,
    PrincipalNotInAllowedSigners,
    KeyPrincipalMismatch,
}

impl FailureReason {
    pub fn rule_id(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::SignatureInvalid => "signature-invalid",
            Self::PrincipalNotInAllowedSigners => "principal-not-in-allowed-signers",
            Self::KeyPrincipalMismatch => "key-principal-mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail(FailureReason),
}

#[derive(Debug, Clone)]
pub enum FindingArtifact {
    Commit(CommitSha),
    Tag(String),
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub artifact: FindingArtifact,
    pub reason: FailureReason,
    pub committer_email: Option<String>,
    pub signer_name: Option<String>,
    pub signing_key: Option<String>,
    pub raw_gpg_status: Option<char>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedSignersSource {
    Flag,
    GitConfig,
}

impl AllowedSignersSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::GitConfig => "git-config",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AllowedSignersPath {
    pub path: PathBuf,
    pub source: AllowedSignersSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagVerificationStatus {
    Good,
    NoSignature,
    SignatureInvalid,
    PrincipalNotInAllowedSigners,
    KeyPrincipalMismatch,
}

impl TagVerificationStatus {
    pub fn to_failure_reason(self) -> Option<FailureReason> {
        Some(match self {
            Self::Good => return None,
            Self::NoSignature => FailureReason::Unsigned,
            Self::SignatureInvalid => FailureReason::SignatureInvalid,
            Self::PrincipalNotInAllowedSigners => FailureReason::PrincipalNotInAllowedSigners,
            Self::KeyPrincipalMismatch => FailureReason::KeyPrincipalMismatch,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TagRecord {
    pub name: String,
    pub status: TagVerificationStatus,
    pub committer_email: Option<String>,
    pub signer_name: Option<String>,
    pub signing_key: Option<String>,
}

#[derive(Debug, Default)]
pub struct AuditReport {
    pub commits_seen: u64,
    pub tags_seen: u64,
    pub exemptions_applied: u64,
    pub findings: Vec<Finding>,
    pub repo_was_shallow: bool,
    pub repo_was_empty: bool,
}

impl AuditReport {
    pub fn has_violation(&self) -> bool {
        !self.findings.is_empty()
    }
}
