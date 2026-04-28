//! SARIF v2.1.0 emitter.
//!
//! Buffers all results and emits the run as a single JSON object in `epilogue`.
//! SARIF consumers (GitHub Code Scanning, etc.) ingest the file whole, so the
//! partial-output benefit of streaming did not apply.

use std::io::Write;

use serde_json::{json, Value};

use crate::audit::RunContext;
use crate::error::Result;
use crate::report::Emitter;
use crate::types::{AuditReport, FailureReason, Finding, FindingArtifact};

pub struct SarifEmitter<W: Write> {
    pub out: W,
    results: Vec<Value>,
}

impl<W: Write> SarifEmitter<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            results: Vec::new(),
        }
    }
}

fn rules() -> Vec<Value> {
    fn rule(id: &str, name: &str, desc: &str) -> Value {
        json!({
            "id": id,
            "name": name,
            "shortDescription": { "text": desc },
            "defaultConfiguration": { "level": "error" }
        })
    }
    vec![
        rule(
            "unsigned",
            "Unsigned",
            "Commit or tag has no cryptographic signature.",
        ),
        rule(
            "signature-invalid",
            "SignatureInvalid",
            "Cryptographic signature failed verification.",
        ),
        rule(
            "principal-not-in-allowed-signers",
            "PrincipalNotInAllowedSigners",
            "Committer email is not authorized in the allowed-signers file.",
        ),
        rule(
            "key-principal-mismatch",
            "KeyPrincipalMismatch",
            "Signature is valid and key is in allowed-signers, but the key is not bound to the committer's email.",
        ),
    ]
}

impl<W: Write> Emitter for SarifEmitter<W> {
    fn prologue(&mut self, _ctx: &RunContext<'_>, _report: &AuditReport) -> Result<()> {
        Ok(())
    }

    fn finding(&mut self, _ctx: &RunContext<'_>, finding: &Finding) -> Result<()> {
        self.results.push(build_result_json(finding));
        Ok(())
    }

    fn epilogue(&mut self, ctx: &RunContext<'_>, report: &AuditReport) -> Result<()> {
        let invocation = json!({
            "executionSuccessful": true,
            "exitCode": if report.has_violation() { 1 } else { 0 },
            "exitCodeDescription": if report.has_violation() {
                "policy-violation"
            } else {
                "ok"
            },
            "commandLine": std::env::args().collect::<Vec<_>>().join(" "),
        });
        let props = json!({
            "repoPath": ctx.cfg.repo.display().to_string(),
            "range": ctx.cfg.range,
            "allowedSignersPath": ctx.cfg.allowed_signers.path.display().to_string(),
            "allowedSignersSource": ctx.cfg.allowed_signers.source.as_str(),
            "tagsAudited": ctx.cfg.include_tags,
            "exemptionsApplied": report.exemptions_applied,
            "shallow": report.repo_was_shallow,
            "commitsAudited": report.commits_seen,
            "tagsSeen": report.tags_seen,
        });
        let doc = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "gitsigner",
                        "informationUri": "https://github.com/deoktr/gitsigner",
                        "version": env!("CARGO_PKG_VERSION"),
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "rules": rules(),
                    }
                },
                "results": std::mem::take(&mut self.results),
                "invocations": [invocation],
                "properties": props,
            }]
        });
        serde_json::to_writer(&mut self.out, &doc)
            .map_err(|e| crate::error::Error::Io(std::io::Error::other(e)))?;
        writeln!(self.out)?;
        Ok(())
    }
}

fn build_result_json(finding: &Finding) -> Value {
    let (artifact_kind, name, full_name, commit_sha_v, tag_name) = match &finding.artifact {
        FindingArtifact::Commit(sha) => (
            "commit",
            sha.short().to_string(),
            sha.to_string(),
            json!(sha.to_string()),
            Value::Null,
        ),
        FindingArtifact::Tag(name) => ("tag", name.clone(), name.clone(), Value::Null, json!(name)),
    };
    let message_text = format_message(finding);
    json!({
        "ruleId": finding.reason.rule_id(),
        "level": "error",
        "message": { "text": message_text },
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": name,
                        "fullyQualifiedName": full_name,
                        "kind": "module"
                    }
                ]
            }
        ],
        "properties": {
            "artifactKind": artifact_kind,
            "commitSha": commit_sha_v,
            "tagName": tag_name,
            "committerEmail": finding.committer_email.clone().map(Value::String).unwrap_or(Value::Null),
            "signerName": finding.signer_name.clone().map(Value::String).unwrap_or(Value::Null),
            "signingKey": finding.signing_key.clone().map(Value::String).unwrap_or(Value::Null),
            "gpgStatus": finding.raw_gpg_status.map(|c| Value::String(c.to_string())).unwrap_or(Value::Null)
        }
    })
}

fn format_message(finding: &Finding) -> String {
    let target = match &finding.artifact {
        FindingArtifact::Commit(sha) => format!("Commit {}", sha.short()),
        FindingArtifact::Tag(name) => format!("Tag {}", name),
    };
    let by = match &finding.committer_email {
        Some(e) => format!(" by {e}"),
        None => String::new(),
    };
    match finding.reason {
        FailureReason::Unsigned => format!("{target}{by} has no signature."),
        FailureReason::SignatureInvalid => format!("{target}{by} has an invalid signature."),
        FailureReason::PrincipalNotInAllowedSigners => format!(
            "{target}{by} was signed by an identity not present in the allowed-signers file."
        ),
        FailureReason::KeyPrincipalMismatch => format!(
            "{target}{by} was signed by a key not bound to the committer's email in the allowed-signers file."
        ),
    }
}
