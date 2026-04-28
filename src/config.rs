//! Configuration resolution: allowed-signers source-of-truth and principal
//! lookup.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::git;
use crate::types::{AllowedSignersPath, AllowedSignersSource};

/// Resolve the allowed-signers file path: explicit flag -> git config fallback
/// -> error.
pub fn resolve_allowed_signers(flag: Option<&Path>, repo: &Path) -> Result<AllowedSignersPath> {
    if let Some(p) = flag {
        let abs = canonicalize_existing(p)?;
        return Ok(AllowedSignersPath {
            path: abs,
            source: AllowedSignersSource::Flag,
        });
    }
    match git::config_get("gpg.ssh.allowedSignersFile", repo)? {
        Some(s) => {
            let path = expand_tilde(&s);
            let abs = canonicalize_existing(&path)?;
            Ok(AllowedSignersPath {
                path: abs,
                source: AllowedSignersSource::GitConfig,
            })
        }
        None => Err(Error::BothSourcesMissing),
    }
}

fn canonicalize_existing(p: &Path) -> Result<PathBuf> {
    if !p.exists() {
        return Err(Error::AllowedSignersUnreadable(p.to_path_buf()));
    }
    fs::canonicalize(p).map_err(|_| Error::AllowedSignersUnreadable(p.to_path_buf()))
}

fn expand_tilde(s: &str) -> PathBuf {
    if let Some(stripped) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let mut p = PathBuf::from(home);
            p.push(stripped);
            return p;
        }
    }
    PathBuf::from(s)
}

/// Parse the allowed-signers file and return the lowercase set of email-like
/// principals.
///
/// allowed_signers format (per ssh-keygen ALLOWED SIGNERS section):
///   <principals>[ <options>] <key>
/// where `<principals>` is comma-separated. Lines beginning with `#` are
/// comments. We extract the principals list only; key contents are not parsed
/// (git itself does the cryptographic verification). Pattern matching is exact-
/// only for v1; wildcard principals (e.g. `*@example.com`) are passed through
/// verbatim and would only match if a committer's email literally contains the
/// asterisk, adequate for the common case of explicit per-person principals.
pub fn load_allowed_principals(path: &Path) -> Result<HashSet<String>> {
    let content = fs::read_to_string(path)
        .map_err(|_| Error::AllowedSignersUnreadable(path.to_path_buf()))?;
    let mut out = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let principals = match line.split_whitespace().next() {
            Some(s) => s,
            None => continue,
        };
        for p in principals.split(',') {
            let p = p.trim();
            if !p.is_empty() {
                out.insert(p.to_ascii_lowercase());
            }
        }
    }
    Ok(out)
}
