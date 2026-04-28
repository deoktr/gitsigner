mod common;

use common::fixture::TempRepo;

#[test]
fn unsigned_commit_is_flagged() {
    let mut repo = TempRepo::new();
    let alice = repo.generate_key("alice");
    let _ = alice;
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_unsigned("alice@example.com", "an unsigned commit");

    let assert = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert();
    assert
        .failure()
        .code(1)
        .stdout(predicates::str::contains("unsigned"));
}

#[test]
fn principal_not_in_allowed_signers_is_flagged() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.generate_key("bob");
    // allowed_signers names alice, but the commit comes from bob signed with
    // bob's key
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("bob@example.com", "bob", "bob signs as bob");

    let assert = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert();
    assert.failure().code(1).stdout(predicates::str::contains(
        "principal-not-in-allowed-signers",
    ));
}

#[test]
fn key_principal_mismatch_is_flagged() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.generate_key("bob");
    // alice's email IS in the file (bound to alice's key), but the commit was
    // signed with bob's key, the realistic supply-chain attack to lock in
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "bob", "alice email but bob key");

    let assert = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert();
    assert
        .failure()
        .code(1)
        .stdout(predicates::str::contains("key-principal-mismatch"));
}

#[test]
fn signature_invalid_is_flagged() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "starts well");
    // Now corrupt the signature on HEAD
    let _new_sha = repo.corrupt_head_signature();

    let assert = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert();
    assert
        .failure()
        .code(1)
        .stdout(predicates::str::contains("signature-invalid"));
}

#[test]
fn multiple_violations_all_reported_in_one_run() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "good 1");
    repo.commit_unsigned("alice@example.com", "bad 1: unsigned");
    repo.commit_signed("alice@example.com", "alice", "good 2");
    repo.commit_unsigned("alice@example.com", "bad 2: unsigned again");

    let output = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let unsigned_count = stdout.matches("unsigned").count();
    assert_eq!(
        unsigned_count, 2,
        "expected both unsigned commits in one run; got stdout:\n{stdout}"
    );
}
