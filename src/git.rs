//! Thin wrapper over `git` subprocess invocations.
//!
//! All cryptographic verification is delegated to git itself.

use std::path::Path;
use std::process::{Command, Output};

use crate::error::{Error, Result};
use crate::types::AllowedSignersPath;

/// Build a `Command` for git with locale forced to C. We classify some failures
/// (notably `verify-tag`) by matching stderr substrings; without forcing the
/// locale, a non-English `LANG` on the host would silently miss-bucket those
/// failures.
fn git_command(cwd: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(cwd);
    cmd.env("LC_ALL", "C");
    cmd.env("LANG", "C");
    cmd
}

/// Run `git` with the given args, in the given working tree.
/// Maps non-zero exit + stderr into Error::GitInvocationFailed.
pub fn run(args: &[&str], cwd: &Path) -> Result<Output> {
    let output = git_command(cwd).args(args).output()?;
    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(Error::GitInvocationFailed { code, stderr });
    }
    Ok(output)
}

/// Build the leading `-c gpg.ssh.allowedSignersFile=<abs>` arg list to be
/// prepended to a git invocation.
pub fn allowed_signers_override(p: &AllowedSignersPath) -> String {
    format!(
        "gpg.ssh.allowedSignersFile={}",
        p.path
            .to_str()
            .expect("AllowedSignersPath must be valid UTF-8 (canonicalized at startup)")
    )
}

/// Look up `git config --get <key>` in the given repo. Returns None if the key
/// is unset (git exit code 1 with empty stdout) and Err for any other failure
/// mode.
pub fn config_get(key: &str, cwd: &Path) -> Result<Option<String>> {
    let output = git_command(cwd).args(["config", "--get", key]).output()?;
    match output.status.code() {
        Some(0) => {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if s.is_empty() {
                Ok(None)
            } else {
                Ok(Some(s))
            }
        }
        Some(1) => Ok(None),
        code => {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            Err(Error::GitInvocationFailed {
                code: code.unwrap_or(-1),
                stderr,
            })
        }
    }
}

/// Confirm that `cwd` is inside a git repository (working tree or bare repo).
pub fn ensure_repo(cwd: &Path) -> Result<()> {
    let output = git_command(cwd).args(["rev-parse", "--git-dir"]).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::NotARepo(cwd.to_path_buf()))
    }
}

/// Return true if the repository is a shallow clone.
pub fn is_shallow(cwd: &Path) -> Result<bool> {
    let output = run(&["rev-parse", "--is-shallow-repository"], cwd)?;
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(s == "true")
}

/// Return true if there is at least one commit reachable from HEAD.
pub fn has_head(cwd: &Path) -> Result<bool> {
    let output = git_command(cwd)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()?;
    Ok(output.status.success())
}

use std::io::{BufRead, BufReader};

use crate::types::{CommitRecord, CommitSha, GpgStatusCode};

const RECORD_SEPARATOR: u8 = 0x1e; // ASCII RS
const FIELD_SEPARATOR: u8 = 0x1f; // ASCII US

const COMMIT_LOG_FORMAT: &str = "%H%x1f%G?%x1f%ce%x1f%GS%x1f%GK%x1e";

/// Streaming iterator over commits in `range`, yielding (sha, signature-status,
/// committer-email, signer-name, signing-key) for each commit.
pub struct CommitStream {
    child: std::process::Child,
    reader: BufReader<std::process::ChildStdout>,
    buf: Vec<u8>,
}

impl CommitStream {
    pub fn finish(mut self) -> Result<()> {
        let status = self.child.wait()?;
        if !status.success() {
            let stderr = read_to_end(&mut self.child.stderr.take());
            let code = status.code().unwrap_or(-1);
            return Err(
                if stderr.contains("unknown revision") || stderr.contains("bad revision") {
                    Error::BadRange(stderr)
                } else {
                    Error::GitInvocationFailed { code, stderr }
                },
            );
        }
        Ok(())
    }
}

fn read_to_end(child_stderr: &mut Option<std::process::ChildStderr>) -> String {
    use std::io::Read;
    let mut s = String::new();
    if let Some(mut e) = child_stderr.take() {
        let _ = e.read_to_string(&mut s);
    }
    s
}

impl Iterator for CommitStream {
    type Item = Result<CommitRecord>;
    fn next(&mut self) -> Option<Self::Item> {
        self.buf.clear();
        match self.reader.read_until(RECORD_SEPARATOR, &mut self.buf) {
            Ok(0) => None,
            Ok(_) => {
                // Strip trailing record separator if present
                if self.buf.last() == Some(&RECORD_SEPARATOR) {
                    self.buf.pop();
                }
                if self.buf.is_empty() {
                    return self.next();
                }
                Some(parse_record(&self.buf))
            }
            Err(e) => Some(Err(Error::Io(e))),
        }
    }
}

fn parse_record(bytes: &[u8]) -> Result<CommitRecord> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| Error::GitOutputUnparsable("non-utf8 record".to_string()))?;
    let mut fields = s.split(FIELD_SEPARATOR as char);
    let sha = fields
        .next()
        .ok_or_else(|| Error::GitOutputUnparsable("missing sha".into()))?
        .trim_start_matches('\n');
    let sha = CommitSha::parse(sha)
        .ok_or_else(|| Error::GitOutputUnparsable(format!("not a 40-char hex sha: {sha:?}")))?;
    let status = fields
        .next()
        .ok_or_else(|| Error::GitOutputUnparsable("missing %G?".into()))?;
    let status = GpgStatusCode::from_char(status.chars().next().unwrap_or('?'))
        .ok_or_else(|| Error::GitOutputUnparsable(format!("unknown %G? code {status:?}")))?;
    let committer_email = fields.next().map(str::to_string).filter(|s| !s.is_empty());
    let signer_name = fields.next().map(str::to_string).filter(|s| !s.is_empty());
    let signing_key = fields.next().map(str::to_string).filter(|s| !s.is_empty());

    Ok(CommitRecord {
        sha,
        gpg_status: status,
        committer_email,
        signer_name,
        signing_key,
    })
}

/// Spawn `git log <range> --pretty=format:...` with allowed-signers override
/// and return a streaming iterator over its output.
pub fn enumerate_commits(
    repo: &Path,
    range: &str,
    allowed_signers: &AllowedSignersPath,
) -> Result<CommitStream> {
    let override_arg = allowed_signers_override(allowed_signers);
    let args = [
        "-c",
        &override_arg,
        "log",
        &format!("--pretty=format:{COMMIT_LOG_FORMAT}"),
        range,
    ];
    let mut child = git_command(repo)
        .args(args.iter().copied())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("stdout piped");
    let reader = BufReader::new(stdout);
    Ok(CommitStream {
        child,
        reader,
        buf: Vec::with_capacity(256),
    })
}

use crate::types::{TagRecord, TagVerificationStatus};

/// Enumerate annotated tags in `repo`. Lightweight tags (where `objecttype` is
/// `commit`) are filtered out. For each annotated tag, the verification is
/// performed via `git verify-tag --raw` with the allowed-signers override.
pub fn enumerate_tags(repo: &Path, allowed_signers: &AllowedSignersPath) -> Result<Vec<TagRecord>> {
    // Note: `for-each-ref --format` does NOT expand `%x1f` (unlike `git log
    // --pretty=format`), so we use a tab separator. Refnames cannot contain
    // tabs per git's refname rules; objecttype is an enum word; taggeremail is
    // `<email>`.
    let listing = run(
        &[
            "for-each-ref",
            "refs/tags",
            "--format=%(refname:short)\t%(objecttype)\t%(taggeremail)",
        ],
        repo,
    )?;
    let listing = String::from_utf8(listing.stdout)
        .map_err(|_| Error::GitOutputUnparsable("for-each-ref non-utf8".into()))?;

    let mut out = Vec::new();
    for line in listing.lines() {
        let mut fields = line.split('\t');
        let name = fields.next().unwrap_or("").trim().to_string();
        let objtype = fields.next().unwrap_or("").trim();
        if objtype != "tag" {
            // Lightweight tag, skip
            continue;
        }
        let tagger_email_raw = fields.next().unwrap_or("").trim();
        // git formats taggeremail as "<email>", strip the angle brackets
        let tagger_email = tagger_email_raw
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim()
            .to_string();
        let tagger_email = if tagger_email.is_empty() {
            None
        } else {
            Some(tagger_email)
        };

        let (status, signing_key) = verify_tag(repo, &name, allowed_signers)?;
        out.push(TagRecord {
            name,
            status,
            committer_email: tagger_email,
            signer_name: None,
            signing_key,
        });
    }
    Ok(out)
}

fn verify_tag(
    repo: &Path,
    tag: &str,
    allowed_signers: &AllowedSignersPath,
) -> Result<(TagVerificationStatus, Option<String>)> {
    let override_arg = allowed_signers_override(allowed_signers);
    let output = git_command(repo)
        .args(["-c", &override_arg, "verify-tag", "--raw", tag])
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // verify-tag exits 0 only when the signature is verified AND trusted
    if output.status.success() {
        let key = extract_signing_key(&stderr);
        return Ok((TagVerificationStatus::Good, key));
    }
    // Classify failure based on stderr signal patterns
    let s = stderr.to_ascii_lowercase();
    if s.contains("no signature found") || s.contains("error: tag") && s.contains("not signed") {
        return Ok((TagVerificationStatus::NoSignature, None));
    }
    let key = extract_signing_key(&stderr);
    if s.contains("good") && s.contains("no principal matched") {
        // Could be PrincipalNotInAllowedSigners or KeyPrincipalMismatch, caller
        // disambiguates via tagger email lookup. Default here to Principal-not-
        // in. The caller in audit.rs upgrades to KeyPrincipalMismatch when the
        // email IS present in the file.
        return Ok((TagVerificationStatus::PrincipalNotInAllowedSigners, key));
    }
    Ok((TagVerificationStatus::SignatureInvalid, key))
}

fn extract_signing_key(stderr: &str) -> Option<String> {
    // Look for "SHA256:<fingerprint>", same shape as %GK for commits.
    for token in stderr.split_whitespace() {
        if token.starts_with("SHA256:") {
            return Some(token.trim_end_matches(['.', ',']).to_string());
        }
    }
    None
}
