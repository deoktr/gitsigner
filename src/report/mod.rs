pub mod human;
pub mod sarif;

use crate::audit::RunContext;
use crate::error::Result;
use crate::types::{AuditReport, Finding};

pub trait Emitter {
    fn prologue(&mut self, ctx: &RunContext<'_>, report: &AuditReport) -> Result<()>;
    fn finding(&mut self, ctx: &RunContext<'_>, finding: &Finding) -> Result<()>;
    fn epilogue(&mut self, ctx: &RunContext<'_>, report: &AuditReport) -> Result<()>;
}
