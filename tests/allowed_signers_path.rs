mod common;

use common::fixture::TempRepo;

#[test]
fn explicit_flag_works() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "good");

    repo.gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .assert()
        .success()
        .code(0);
}

#[test]
fn falls_back_to_git_config() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "good");
    // Write the allowed-signers path into the local git config; do not pass
    // --allowed-signers
    let path = repo.allowed_signers_path().to_string_lossy().to_string();
    let _ = std::process::Command::new("git")
        .envs([
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ])
        .args(["config", "--local", "gpg.ssh.allowedSignersFile", &path])
        .current_dir(repo.path())
        .status()
        .expect("git config");

    repo.gitsigner().assert().success().code(0);
}

#[test]
fn missing_both_sources_exits_two() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    // Note: don't write allowed_signers and don't set git config
    repo.commit_signed("alice@example.com", "alice", "anything");

    repo.gitsigner()
        .assert()
        .failure()
        .code(2)
        .stderr(predicates::str::contains("--allowed-signers"))
        .stderr(predicates::str::contains("gpg.ssh.allowedSignersFile"));
}
