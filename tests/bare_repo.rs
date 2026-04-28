//! Bare-repository smoke tests.
//!
//! Verifies that `gitsigner` correctly enumerates commits and tags in a bare
//! repository (no working tree). Bare clones are the typical layout on a
//! mirror/backup host and on some CI runners that fetch without checkout.

mod common;

use common::fixture::TempRepo;

#[test]
fn bare_repo_clean_history_passes() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "first");
    repo.commit_signed("alice@example.com", "alice", "second");

    let bare = repo.bare_clone();

    repo.gitsigner_in(&bare)
        .args([
            "--allowed-signers",
            repo.allowed_signers_path().to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn bare_repo_violation_exits_one() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "first");
    repo.commit_unsigned("eve@example.com", "rogue");

    let bare = repo.bare_clone();

    repo.gitsigner_in(&bare)
        .args([
            "--allowed-signers",
            repo.allowed_signers_path().to_str().unwrap(),
        ])
        .assert()
        .code(1);
}
