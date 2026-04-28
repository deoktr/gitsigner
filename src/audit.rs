use std::collections::HashSet;
use std::path::PathBuf;

use crate::config;
use crate::error::Result;
use crate::git;
use crate::report::Emitter;
use crate::types::{
    AllowedSignersPath, AuditReport, CommitRecord, Finding, FindingArtifact, Outcome,
};

#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub repo: PathBuf,
    pub allowed_signers: AllowedSignersPath,
    pub range: String,
    pub include_commits: bool,
    pub include_tags: bool,
    pub exempt: HashSet<String>,
}

pub struct RunContext<'a> {
    pub cfg: &'a AuditConfig,
    pub allowed_principals: &'a HashSet<String>,
}

/// Run the audit. Streams findings through `emitter` as produced. Returns the
/// report.
pub fn run<E: Emitter>(cfg: &AuditConfig, emitter: &mut E) -> Result<AuditReport> {
    let mut report = AuditReport::default();

    git::ensure_repo(&cfg.repo)?;
    report.repo_was_shallow = git::is_shallow(&cfg.repo).unwrap_or(false);
    let has_head = git::has_head(&cfg.repo)?;
    report.repo_was_empty = !has_head;

    let allowed_principals = config::load_allowed_principals(&cfg.allowed_signers.path)?;
    let ctx = RunContext {
        cfg,
        allowed_principals: &allowed_principals,
    };

    emitter.prologue(&ctx, &report)?;

    if !has_head {
        emitter.epilogue(&ctx, &report)?;
        return Ok(report);
    }

    if cfg.include_commits {
        let mut stream = git::enumerate_commits(&cfg.repo, &cfg.range, &cfg.allowed_signers)?;
        for item in stream.by_ref() {
            let record = item?;
            report.commits_seen += 1;
            if ctx.cfg.exempt.contains(record.sha.as_str()) {
                report.exemptions_applied += 1;
                continue;
            }
            if let Some(finding) = classify_record(&record, &ctx) {
                emitter.finding(&ctx, &finding)?;
                report.findings.push(finding);
            }
        }
        stream.finish()?;
    }

    if cfg.include_tags {
        let tags = git::enumerate_tags(&cfg.repo, &cfg.allowed_signers)?;
        for tag in tags {
            report.tags_seen += 1;
            if let Some(finding) = classify_tag(&tag, &ctx) {
                emitter.finding(&ctx, &finding)?;
                report.findings.push(finding);
            }
        }
    }

    emitter.epilogue(&ctx, &report)?;
    Ok(report)
}

fn classify_tag(tag: &crate::types::TagRecord, ctx: &RunContext<'_>) -> Option<Finding> {
    use crate::types::{FailureReason, TagVerificationStatus};
    let mut reason = tag.status.to_failure_reason()?;
    // git's verify-tag failure messaging conflates `principal-not-in-allowed-
    // signers` and `key-principal-mismatch`, disambiguate by looking up the
    // tagger email in the loaded allowed-principals set, mirroring the commit-
    // side logic.
    if matches!(
        tag.status,
        TagVerificationStatus::PrincipalNotInAllowedSigners
    ) {
        if let Some(email) = tag.committer_email.as_deref() {
            if ctx.allowed_principals.contains(&email.to_ascii_lowercase()) {
                reason = FailureReason::KeyPrincipalMismatch;
            }
        }
    }
    Some(Finding {
        artifact: FindingArtifact::Tag(tag.name.clone()),
        reason,
        committer_email: tag.committer_email.clone(),
        signer_name: tag.signer_name.clone(),
        signing_key: tag.signing_key.clone(),
        raw_gpg_status: None,
    })
}

fn classify_record(record: &CommitRecord, ctx: &RunContext<'_>) -> Option<Finding> {
    match crate::classify::classify(record, ctx.allowed_principals) {
        Outcome::Pass => None,
        Outcome::Fail(reason) => Some(Finding {
            artifact: FindingArtifact::Commit(record.sha.clone()),
            reason,
            committer_email: record.committer_email.clone(),
            signer_name: record.signer_name.clone(),
            signing_key: record.signing_key.clone(),
            raw_gpg_status: Some(record.gpg_status.as_char()),
        }),
    }
}
