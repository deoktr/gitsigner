use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "gitsigner",
    version,
    about = "Audit a git repository to ensure every commit is signed by an allowed identity.",
    long_about = None,
)]
pub struct Args {
    /// Path to the git repository's working tree, defaults to the current
    /// directory.
    #[arg(short = 'C', long = "repo", value_name = "PATH")]
    pub repo: Option<PathBuf>,

    /// Path to an allowed-signers file, if omitted, falls back to git's
    /// `gpg.ssh.allowedSignersFile` configuration.
    #[arg(short = 's', long = "allowed-signers", value_name = "PATH")]
    pub allowed_signers: Option<PathBuf>,

    /// Output format.
    #[arg(short = 'f', long = "format", value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Treat all commits reachable from this commit as exempt (audit only
    /// commits introduced after)
    #[arg(long = "since", value_name = "COMMIT")]
    pub since: Option<String>,

    /// Mark a commit as exempt from the policy, repeatable
    #[arg(long = "exempt", value_name = "SHA")]
    pub exempt: Vec<String>,

    /// Skip annotated-tag auditing, by default, annotated tags reachable in the
    /// repository are audited alongside commits.
    #[arg(
        long = "no-tags",
        default_value_t = false,
        conflicts_with = "tags_only"
    )]
    pub no_tags: bool,

    /// Audit only annotated tags, skipping commit enumeration entirely.
    #[arg(long = "tags-only", default_value_t = false)]
    pub tags_only: bool,

    /// Revision range to audit (anything `git rev-list` accepts), defaults to
    /// HEAD
    #[arg(value_name = "REVISION_RANGE")]
    pub range: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Sarif,
}
