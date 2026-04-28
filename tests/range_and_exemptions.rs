mod common;

use common::fixture::TempRepo;

#[test]
fn range_argument_restricts_audit() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    // Commit A (signed by allowed)
    repo.commit_signed("alice@example.com", "alice", "good A");
    let a = repo.head_sha();
    // Commit B (unsigned)
    repo.commit_unsigned("alice@example.com", "bad B");
    let b = repo.head_sha();
    // Commit C (signed)
    repo.commit_signed("alice@example.com", "alice", "good C");
    let _ = b;

    // Audit only A..C, that's commits B and C; should fail because B is
    // unsigned
    let assert = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg(format!("{a}..HEAD"))
        .assert();
    assert.failure().code(1);

    // Audit just A..A, empty range, nothing to check
    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg(format!("{a}..{a}"))
        .assert()
        .success()
        .code(0);
}

#[test]
fn unresolvable_range_exits_two() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "anchor");

    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg("not-a-real-ref..HEAD")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn pre_push_new_branch_pattern_audits_everything_reachable() {
    // The pre-push hook passes <remote_oid>..<local_oid> where <remote_oid> is
    // all zeros for a brand-new branch. Treat that as "audit everything
    // reachable from <local_oid>"
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "good");
    repo.commit_unsigned("alice@example.com", "bad");

    let zeros = "0000000000000000000000000000000000000000";
    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg(format!("{zeros}..HEAD"))
        .assert()
        .failure()
        .code(1);
}

#[test]
fn since_flag_grandfathers_legacy_history() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    // Three legacy unsigned commits
    repo.commit_unsigned("alice@example.com", "legacy 1");
    repo.commit_unsigned("alice@example.com", "legacy 2");
    repo.commit_unsigned("alice@example.com", "legacy 3");
    let adoption = repo.head_sha();
    // Two signed commits after adoption
    repo.commit_signed("alice@example.com", "alice", "post-adoption 1");
    repo.commit_signed("alice@example.com", "alice", "post-adoption 2");

    // Without --since: legacy commits are violations
    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert()
        .failure()
        .code(1);

    // With --since: legacy is grandfathered
    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg("--since")
        .arg(&adoption)
        .assert()
        .success()
        .code(0);
}

#[test]
fn exempt_flag_skips_named_commits() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_unsigned("alice@example.com", "to-exempt");
    let bad = repo.head_sha();
    repo.commit_signed("alice@example.com", "alice", "good");

    // Without --exempt: fails
    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert()
        .failure()
        .code(1);

    // With --exempt <sha>: passes
    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg("--exempt")
        .arg(&bad)
        .assert()
        .success()
        .code(0);

    // Abbreviated sha works
    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg("--exempt")
        .arg(&bad[..12])
        .assert()
        .success()
        .code(0);
}

#[test]
fn shallow_clone_produces_warning_but_does_not_fail() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "good 1");
    repo.commit_signed("alice@example.com", "alice", "good 2");
    repo.commit_signed("alice@example.com", "alice", "good 3");

    let shallow = repo.shallow_clone(1);

    // Human mode: stderr contains a shallow-clone warning, exit 0
    let assert = repo
        .gitsigner()
        .arg("--repo")
        .arg(&shallow)
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert();
    assert
        .success()
        .code(0)
        .stderr(predicates::str::contains("shallow"));

    // SARIF mode: properties.shallow == true
    let out = repo
        .gitsigner()
        .arg("--repo")
        .arg(&shallow)
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg("--format")
        .arg("sarif")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(v["runs"][0]["properties"]["shallow"].as_bool(), Some(true));
}

#[test]
fn exempt_unknown_sha_exits_two() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "anchor");

    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg("--exempt")
        .arg("0000000000000000000000000000000000000000")
        .assert()
        .failure()
        .code(2);
}
