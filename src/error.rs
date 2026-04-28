use std::path::PathBuf;

use thiserror::Error;

use crate::exit::ExitCode;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not a git repository: {0}")]
    NotARepo(PathBuf),

    #[error(
        "no allowed-signers source: pass --allowed-signers <path> or set git config \
         gpg.ssh.allowedSignersFile (neither is set)"
    )]
    BothSourcesMissing,

    #[error("allowed-signers file not found or not readable: {0}")]
    AllowedSignersUnreadable(PathBuf),

    #[error("could not resolve revision range '{0}'")]
    BadRange(String),

    #[error("--exempt sha cannot be resolved in this repository: {0}")]
    BadExemptSha(String),

    #[error("git invocation failed (exit {code}): {stderr}")]
    GitInvocationFailed { code: i32, stderr: String },

    #[error("git output unparsable: {0}")]
    GitOutputUnparsable(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Error::NotARepo(_)
            | Error::BothSourcesMissing
            | Error::AllowedSignersUnreadable(_)
            | Error::BadRange(_)
            | Error::BadExemptSha(_) => ExitCode::UsageError,
            Error::GitInvocationFailed { .. } | Error::GitOutputUnparsable(_) | Error::Io(_) => {
                ExitCode::RuntimeError
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
