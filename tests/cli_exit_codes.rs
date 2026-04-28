mod common;

use common::fixture::TempRepo;

#[test]
fn clean_repo_exits_zero() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "good 1");
    repo.commit_signed("alice@example.com", "alice", "good 2");

    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert()
        .success()
        .code(0);
}

#[test]
fn mixed_repo_exits_one() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "good");
    repo.commit_unsigned("alice@example.com", "bad");

    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert()
        .failure()
        .code(1);
}

#[test]
fn empty_repo_exits_zero() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    // No commits

    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert()
        .success()
        .code(0);
}

#[test]
fn re_runs_are_byte_identical() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "good");
    repo.commit_unsigned("alice@example.com", "bad-1");
    repo.commit_unsigned("alice@example.com", "bad-2");

    let one = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .output()
        .expect("first run");
    let two = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .output()
        .expect("second run");
    assert_eq!(one.stdout, two.stdout, "stdout must be deterministic");
    assert_eq!(one.status.code(), two.status.code());
}
