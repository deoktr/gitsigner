use std::io::Write;

use crate::audit::RunContext;
use crate::error::Result;
use crate::report::Emitter;
use crate::types::{AuditReport, Finding, FindingArtifact};

pub struct HumanEmitter<O: Write, E: Write> {
    pub out: O,
    pub err: E,
}

impl<O: Write, E: Write> Emitter for HumanEmitter<O, E> {
    fn prologue(&mut self, _ctx: &RunContext<'_>, report: &AuditReport) -> Result<()> {
        if report.repo_was_shallow {
            writeln!(
                self.err,
                "warning: shallow clone, audit scope is limited to fetched history"
            )?;
        }
        Ok(())
    }

    fn finding(&mut self, _ctx: &RunContext<'_>, finding: &Finding) -> Result<()> {
        let (kind, name) = match &finding.artifact {
            FindingArtifact::Commit(sha) => ("commit", sha.short().to_string()),
            FindingArtifact::Tag(name) => ("tag", name.clone()),
        };
        let email = finding.committer_email.as_deref().unwrap_or("-");
        writeln!(
            self.out,
            "{kind} {name}\t{reason}\t{email}",
            reason = finding.reason.rule_id(),
        )?;
        Ok(())
    }

    fn epilogue(&mut self, _ctx: &RunContext<'_>, report: &AuditReport) -> Result<()> {
        if report.repo_was_empty {
            writeln!(self.err, "no commits to audit")?;
            return Ok(());
        }
        let summary = format!(
            "audited {commits} commits, {tags} tags, {viol} violation(s){exempt}",
            commits = report.commits_seen,
            tags = report.tags_seen,
            viol = report.findings.len(),
            exempt = if report.exemptions_applied > 0 {
                format!(", {} exempt", report.exemptions_applied)
            } else {
                String::new()
            },
        );
        writeln!(self.err, "{summary}")?;
        Ok(())
    }
}
