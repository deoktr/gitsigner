//! Exit code contract.
//!
//! 0/1 are reserved for completed audits.
//! 2/3 indicate the tool could not perform a meaningful audit.

use std::process::ExitCode as ProcExitCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Ok = 0,
    PolicyViolation = 1,
    UsageError = 2,
    RuntimeError = 3,
}

impl From<ExitCode> for ProcExitCode {
    fn from(value: ExitCode) -> Self {
        ProcExitCode::from(value as u8)
    }
}

impl ExitCode {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
