//! Test-fixture builder.
//!
//! Builds a temp git repository with controllable signing scenarios so each
//! integration test can describe the failure case it cares about declaratively.

// Each integration-test file imports `mod common;` separately; helpers used by
// only some files trigger dead_code warnings in others. Allow it at the module
// level.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

pub struct TempRepo {
    tmp: TempDir,
    keys: HashMap<String, KeyPair>,
}

#[derive(Clone)]
pub struct KeyPair {
    pub label: String,
    pub private_path: PathBuf,
    pub public_path: PathBuf,
    pub public_key_line: String, // "ssh-ed25519 AAAA... label"
}

impl TempRepo {
    pub fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path();
        run("git", &["init", "-q", "-b", "main", "."], path);
        // Isolate from user/global git config.
        // (Additionally set GIT_CONFIG_{GLOBAL,SYSTEM} on every invocation
        // below.)
        run_local_config(path, "user.name", "Test");
        run_local_config(path, "user.email", "test@example.com");
        run_local_config(path, "gpg.format", "ssh");
        run_local_config(path, "commit.gpgsign", "false");
        run_local_config(path, "tag.gpgsign", "false");
        // Required on some environments where the tempdir is owned differently.
        run_local_config(path, "safe.directory", path.to_str().unwrap());
        Self {
            tmp,
            keys: HashMap::new(),
        }
    }

    pub fn path(&self) -> &Path {
        self.tmp.path()
    }

    pub fn allowed_signers_path(&self) -> PathBuf {
        self.tmp.path().join("allowed_signers")
    }

    /// Generate an ed25519 SSH key pair labelled `label`. The key is stored
    /// under `<repo>/.keys/<label>` and `<label>.pub`.
    pub fn generate_key(&mut self, label: &str) -> KeyPair {
        let keys_dir = self.tmp.path().join(".keys");
        fs::create_dir_all(&keys_dir).unwrap();
        let private = keys_dir.join(label);
        let public = keys_dir.join(format!("{label}.pub"));
        // Remove any pre-existing key of this label so ssh-keygen does not
        // prompt
        let _ = fs::remove_file(&private);
        let _ = fs::remove_file(&public);
        let status = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                private.to_str().unwrap(),
                "-C",
                &format!("{label}-test-key"),
                "-q",
            ])
            .status()
            .expect("ssh-keygen");
        assert!(status.success(), "ssh-keygen failed for {label}");
        let public_key_line = fs::read_to_string(&public)
            .unwrap_or_else(|_| panic!("read pubkey {label}"))
            .trim()
            .to_string();
        let kp = KeyPair {
            label: label.to_string(),
            private_path: private,
            public_path: public,
            public_key_line,
        };
        self.keys.insert(label.to_string(), kp.clone());
        kp
    }

    pub fn key(&self, label: &str) -> &KeyPair {
        self.keys
            .get(label)
            .unwrap_or_else(|| panic!("no key with label {label}"))
    }

    /// Configure the repo to commit using `committer_email`, optionally
    /// signing with the named key. Returns mutable access for chaining.
    fn set_signer(&self, committer_email: &str, signing_key_label: Option<&str>) {
        let path = self.path();
        run_local_config(path, "user.email", committer_email);
        match signing_key_label {
            Some(label) => {
                let key_path = self.key(label).private_path.to_str().unwrap().to_string();
                run_local_config(path, "user.signingkey", &key_path);
                run_local_config(path, "commit.gpgsign", "true");
                run_local_config(path, "tag.gpgsign", "true");
            }
            None => {
                run_local_config(path, "commit.gpgsign", "false");
                run_local_config(path, "tag.gpgsign", "false");
                // Leave user.signingkey unset to avoid accidental signing.
                let _ = Command::new("git")
                    .envs(isolated_env())
                    .args(["config", "--local", "--unset", "user.signingkey"])
                    .current_dir(path)
                    .status();
            }
        }
    }

    /// Make a signed empty commit using the named key with the given committer
    /// email.
    pub fn commit_signed(&self, committer_email: &str, signing_key_label: &str, message: &str) {
        self.set_signer(committer_email, Some(signing_key_label));
        run(
            "git",
            &["commit", "--allow-empty", "-S", "-m", message, "-q"],
            self.path(),
        );
    }

    /// Make an unsigned empty commit with the given committer email.
    pub fn commit_unsigned(&self, committer_email: &str, message: &str) {
        self.set_signer(committer_email, None);
        run(
            "git",
            &["commit", "--allow-empty", "-m", message, "-q"],
            self.path(),
        );
    }

    /// Corrupt the signature on the current HEAD commit by mutating one byte of
    /// the gpgsig header in the commit object, writing a new commit, and
    /// updating the current branch ref. Returns the new HEAD sha.
    pub fn corrupt_head_signature(&self) -> String {
        let path = self.path();
        let raw = capture_stdout("git", &["cat-file", "commit", "HEAD"], path);
        let mut bytes = raw.into_bytes();
        // Find "gpgsig " line and flip a byte deep inside the base64 blob
        let needle = b"gpgsig ";
        let start = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("HEAD has no gpgsig, was it signed?");
        // Mutate a byte ~200 bytes into the signature blob
        let target = start + needle.len() + 200;
        if target < bytes.len() {
            bytes[target] ^= 0x01;
        } else {
            // Fallback: flip the byte right after "gpgsig "
            bytes[start + needle.len() + 8] ^= 0x01;
        }
        // Write the modified commit back via hash-object --stdin
        let new_sha = capture_stdout_with_input(
            "git",
            &["hash-object", "-w", "-t", "commit", "--stdin"],
            path,
            &bytes,
        )
        .trim()
        .to_string();
        // Move the current branch to point at the new commit
        let branch = capture_stdout("git", &["symbolic-ref", "--short", "HEAD"], path)
            .trim()
            .to_string();
        run(
            "git",
            &["update-ref", &format!("refs/heads/{branch}"), &new_sha],
            path,
        );
        new_sha
    }

    /// Create an annotated tag signed with the named key.
    pub fn create_signed_tag(&self, name: &str, signer_email: &str, signing_key_label: &str) {
        self.set_signer(signer_email, Some(signing_key_label));
        run(
            "git",
            &["tag", "-s", "-m", &format!("tag {name}"), name],
            self.path(),
        );
    }

    /// Create an unsigned annotated tag.
    pub fn create_unsigned_annotated_tag(&self, name: &str, tagger_email: &str) {
        self.set_signer(tagger_email, None);
        run(
            "git",
            &["tag", "-a", "-m", &format!("tag {name}"), name],
            self.path(),
        );
    }

    /// Create a lightweight (non-annotated) tag pointing at HEAD.
    pub fn create_lightweight_tag(&self, name: &str) {
        // Explicitly disable tag signing so a leftover `tag.gpgsign=true` from
        // a prior commit_signed call doesn't make `git tag` try to sign and
        // fail
        run_local_config(self.path(), "tag.gpgsign", "false");
        run("git", &["tag", name], self.path());
    }

    /// Write an `allowed_signers` file with the given (principal, key_label)
    /// bindings.
    pub fn write_allowed_signers(&self, bindings: &[(&str, &str)]) {
        let mut content = String::new();
        for (principal, label) in bindings {
            let key = &self.key(label).public_key_line;
            content.push_str(&format!("{principal} {key}\n"));
        }
        fs::write(self.allowed_signers_path(), content).unwrap();
    }

    /// Get the most recent commit's full sha.
    pub fn head_sha(&self) -> String {
        capture_stdout("git", &["rev-parse", "HEAD"], self.path())
            .trim()
            .to_string()
    }

    /// Build the assert_cmd::Command for the gitsigner binary, preconfigured
    /// to run against this repo and its allowed_signers file.
    pub fn gitsigner(&self) -> assert_cmd::Command {
        let mut cmd = assert_cmd::Command::cargo_bin("gitsigner").unwrap();
        cmd.current_dir(self.path());
        cmd.envs(isolated_env());
        cmd
    }

    /// Build an `assert_cmd::Command` for the gitsigner binary, set to run in
    /// `dir` (e.g. a bare clone path). Same env isolation as `gitsigner()`.
    pub fn gitsigner_in(&self, dir: &Path) -> assert_cmd::Command {
        let mut cmd = assert_cmd::Command::cargo_bin("gitsigner").unwrap();
        cmd.current_dir(dir);
        cmd.envs(isolated_env());
        cmd
    }

    /// Make a bare clone of this repo into a sibling directory under the same
    /// TempDir and return its path. Used to verify gitsigner works against bare
    /// repositories (no working tree, refs only).
    pub fn bare_clone(&self) -> PathBuf {
        let dest = self.tmp.path().join("bare-clone.git");
        let _ = fs::remove_dir_all(&dest);
        let src_url = format!("file://{}", self.tmp.path().display());
        let status = Command::new("git")
            .envs(isolated_env())
            .args(["clone", "--bare", &src_url, "bare-clone.git"])
            .current_dir(self.tmp.path())
            .status()
            .expect("git clone --bare");
        assert!(status.success(), "bare clone failed");
        dest
    }

    /// Make a shallow clone of this repo into a sibling directory under the
    /// same TempDir and return its path. Caller invokes gitsigner with
    /// `--repo <path>`.
    pub fn shallow_clone(&self, depth: u32) -> std::path::PathBuf {
        let dest = self.tmp.path().join("shallow-clone");
        let _ = fs::remove_dir_all(&dest);
        let depth_str = depth.to_string();
        let src_url = format!("file://{}", self.tmp.path().display());
        let status = Command::new("git")
            .envs(isolated_env())
            .args(["clone", "--depth", &depth_str, &src_url, "shallow-clone"])
            .current_dir(self.tmp.path())
            .status()
            .expect("git clone");
        assert!(status.success(), "shallow clone failed");
        dest
    }
}

fn run(prog: &str, args: &[&str], cwd: &Path) {
    let status = Command::new(prog)
        .envs(isolated_env())
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("spawn {prog}: {e}"));
    assert!(
        status.success(),
        "{} {} (in {}) exited {:?}",
        prog,
        args.join(" "),
        cwd.display(),
        status.code()
    );
}

fn run_local_config(path: &Path, key: &str, value: &str) {
    run("git", &["config", "--local", key, value], path);
}

fn capture_stdout(prog: &str, args: &[&str], cwd: &Path) -> String {
    let out = Command::new(prog)
        .envs(isolated_env())
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("spawn {prog}: {e}"));
    assert!(
        out.status.success(),
        "{} {} failed: {}",
        prog,
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("stdout utf8")
}

fn capture_stdout_with_input(prog: &str, args: &[&str], cwd: &Path, input: &[u8]) -> String {
    use std::io::Write;
    let mut child = Command::new(prog)
        .envs(isolated_env())
        .args(args)
        .current_dir(cwd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {prog}: {e}"));
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{} {} failed: {}",
        prog,
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("stdout utf8")
}

fn isolated_env() -> Vec<(String, String)> {
    // Note: deliberately does not set GIT_{AUTHOR,COMMITTER}_EMAIL, the per-
    // commit local config drives the email so each test can stage different
    // committers.
    vec![
        ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
        ("GIT_CONFIG_SYSTEM".into(), "/dev/null".into()),
        ("GIT_AUTHOR_NAME".into(), "Test".into()),
        ("GIT_COMMITTER_NAME".into(), "Test".into()),
        // Deterministic dates so commit shas are stable across runs
        ("GIT_AUTHOR_DATE".into(), "2026-04-27T12:00:00+00:00".into()),
        (
            "GIT_COMMITTER_DATE".into(),
            "2026-04-27T12:00:00+00:00".into(),
        ),
    ]
}
