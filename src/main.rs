use std::collections::HashSet;
use std::io::{self};
use std::process::ExitCode as ProcExitCode;

use clap::Parser;

use gitsigner::audit::{self, AuditConfig};
use gitsigner::cli::{Args, OutputFormat};
use gitsigner::config;
use gitsigner::error::{Error, Result};
use gitsigner::exit::ExitCode;
use gitsigner::report::{human::HumanEmitter, sarif::SarifEmitter};
use gitsigner::types::AuditReport;

fn main() -> ProcExitCode {
    let args = Args::parse();
    match real_main(args) {
        Ok(code) => code.into(),
        Err(e) => {
            eprintln!("gitsigner: {e}");
            e.exit_code().into()
        }
    }
}

fn real_main(args: Args) -> Result<ExitCode> {
    let repo = args
        .repo
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let repo = std::fs::canonicalize(&repo).map_err(|_| Error::NotARepo(repo.clone()))?;

    let allowed_signers = config::resolve_allowed_signers(args.allowed_signers.as_deref(), &repo)?;

    let mut range = args.range.clone().unwrap_or_else(|| "HEAD".to_string());
    if let Some(since) = &args.since {
        range = format!(
            "{}..{}",
            since,
            args.range.clone().unwrap_or_else(|| "HEAD".to_string())
        );
    }
    // Pre-push hook "new branch" pattern: <all-zeros>..<tip> means audit
    // everything reachable from <tip>. Rewrite to just <tip>.
    if let Some(rest) = range.strip_prefix("0000000000000000000000000000000000000000..") {
        range = rest.to_string();
    }

    let exempt = resolve_exemptions(&repo, &args.exempt)?;

    let cfg = AuditConfig {
        repo,
        allowed_signers,
        range,
        include_commits: !args.tags_only,
        include_tags: !args.no_tags,
        exempt,
    };

    let report = match args.format {
        OutputFormat::Human => {
            let stdout = io::stdout().lock();
            let stderr = io::stderr().lock();
            let mut emitter = HumanEmitter {
                out: stdout,
                err: stderr,
            };
            audit::run(&cfg, &mut emitter)?
        }
        OutputFormat::Sarif => {
            let mut emitter = SarifEmitter::new(io::stdout().lock());
            audit::run(&cfg, &mut emitter)?
        }
    };

    Ok(exit_from_report(&report))
}

fn exit_from_report(report: &AuditReport) -> ExitCode {
    if report.has_violation() {
        ExitCode::PolicyViolation
    } else {
        ExitCode::Ok
    }
}

fn resolve_exemptions(repo: &std::path::Path, raw: &[String]) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    for sha in raw {
        let resolved = gitsigner::git::run(
            &["rev-parse", "--verify", &format!("{sha}^{{commit}}")],
            repo,
        )
        .map_err(|_| Error::BadExemptSha(sha.clone()))?;
        let s = String::from_utf8_lossy(&resolved.stdout).trim().to_string();
        out.insert(s);
    }
    Ok(out)
}
