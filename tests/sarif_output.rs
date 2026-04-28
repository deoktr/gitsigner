mod common;

use common::fixture::TempRepo;
use serde_json::Value;

#[test]
fn sarif_output_has_required_top_level_shape() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_unsigned("alice@example.com", "violation");

    let out = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg("--format")
        .arg("sarif")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));

    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not valid JSON: {e}\n{:?}",
            String::from_utf8_lossy(&out.stdout)
        )
    });

    assert_eq!(
        v["$schema"].as_str(),
        Some("https://json.schemastore.org/sarif-2.1.0.json")
    );
    assert_eq!(v["version"].as_str(), Some("2.1.0"));
    let runs = v["runs"].as_array().expect("runs[]");
    assert_eq!(runs.len(), 1);
    let run = &runs[0];

    // tool.driver.rules has all four rule IDs
    let rules = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("tool.driver.rules");
    let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    for expected in [
        "unsigned",
        "signature-invalid",
        "principal-not-in-allowed-signers",
        "key-principal-mismatch",
    ] {
        assert!(ids.contains(&expected), "missing rule {expected}: {ids:?}");
    }

    // results[0] has the right shape
    let results = run["results"].as_array().expect("results[]");
    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert_eq!(r["ruleId"].as_str(), Some("unsigned"));
    assert_eq!(r["level"].as_str(), Some("error"));
    assert!(r["message"]["text"].is_string());
    assert_eq!(
        r["locations"][0]["logicalLocations"][0]["kind"].as_str(),
        Some("module")
    );
    assert_eq!(r["properties"]["artifactKind"].as_str(), Some("commit"));
    let sha = r["properties"]["commitSha"].as_str().expect("commitSha");
    assert_eq!(sha.len(), 40);
    assert_eq!(
        r["properties"]["committerEmail"].as_str(),
        Some("alice@example.com")
    );
    assert_eq!(r["properties"]["gpgStatus"].as_str(), Some("N"));

    // run-level properties.
    let props = &run["properties"];
    assert_eq!(props["tagsAudited"].as_bool(), Some(true));
    assert_eq!(props["shallow"].as_bool(), Some(false));
    assert_eq!(props["commitsAudited"].as_u64(), Some(1));
}

#[test]
fn sarif_output_clean_repo_has_empty_results() {
    let mut repo = TempRepo::new();
    repo.generate_key("alice");
    repo.write_allowed_signers(&[("alice@example.com", "alice")]);
    repo.commit_signed("alice@example.com", "alice", "good");

    let out = repo
        .gitsigner()
        .arg("--allowed-signers")
        .arg(repo.allowed_signers_path())
        .arg("--format")
        .arg("sarif")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let results = v["runs"][0]["results"].as_array().expect("results[]");
    assert!(results.is_empty(), "expected zero results, got {results:?}");
}
