//! End-to-end CLI tests.
//!
//! Fixture secrets are constructed at runtime so no secret-shaped string
//! is ever committed to the repository.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;

fn fake_anthropic_key() -> String {
    format!("sk-ant-api03-{}", "aB3dEfGh1JkLmN0p".repeat(6))
}

fn fake_github_token() -> String {
    format!("ghp_{}", "A1b2C3d4E5f6".repeat(3))
}

fn agentleaks() -> Command {
    Command::cargo_bin("agentleaks").unwrap()
}

fn write_session(dir: &Path, key: &str) -> std::path::PathBuf {
    let file = dir.join("session.jsonl");
    let line1 = serde_json::json!({
        "type": "user",
        "message": {"role": "user", "content": "please read my .env"}
    });
    let line2 = serde_json::json!({
        "type": "user",
        "message": {
            "role": "user",
            "content": [{
                "type": "tool_result",
                "content": format!("ANTHROPIC_API_KEY={key}\nDEBUG=true")
            }]
        }
    });
    std::fs::write(&file, format!("{line1}\n{line2}\n")).unwrap();
    file
}

#[test]
fn scan_explicit_path_finds_planted_secret_and_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    let key = fake_anthropic_key();
    write_session(tmp.path(), &key);

    agentleaks()
        .args(["scan", "--no-color"])
        .arg(tmp.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Anthropic API key"))
        .stdout(predicate::str::contains("sk-ant").and(predicate::str::contains(&key).not()));
}

#[test]
fn scan_clean_directory_exits_0() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("notes.md"), "nothing secret here\n").unwrap();

    agentleaks()
        .args(["scan", "--no-color"])
        .arg(tmp.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("no secrets found"));
}

#[test]
fn scan_json_output_is_parseable_and_masked() {
    let tmp = tempfile::tempdir().unwrap();
    let key = fake_anthropic_key();
    write_session(tmp.path(), &key);

    let output = agentleaks()
        .args(["scan", "--format", "json"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["total"], 1);
    assert_eq!(report["findings"][0]["rule"], "anthropic-api-key");
    assert!(report["findings"][0].get("secret").is_none());
    assert!(
        !stdout.contains(&key),
        "full secret must not appear in masked output"
    );
}

#[test]
fn scan_unmask_reveals_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let key = fake_anthropic_key();
    write_session(tmp.path(), &key);

    agentleaks()
        .args(["scan", "--format", "json", "--unmask"])
        .arg(tmp.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains(&key));
}

#[test]
fn scrub_yes_redacts_and_keeps_jsonl_valid() {
    let tmp = tempfile::tempdir().unwrap();
    let key = fake_anthropic_key();
    let file = write_session(tmp.path(), &key);
    let original = std::fs::read_to_string(&file).unwrap();

    agentleaks()
        .args(["scrub", "--yes", "--no-color"])
        .arg(tmp.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("scrubbed"));

    let after = std::fs::read_to_string(&file).unwrap();
    assert!(!after.contains(&key));
    assert!(after.contains("[REDACTED:anthropic-api-key:"));
    for line in after.lines() {
        serde_json::from_str::<serde_json::Value>(line)
            .expect("scrubbed line must stay valid JSON");
    }

    // A backup with the original content sits next to the file.
    let backup = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().contains(".bak"))
        .expect("backup file created");
    assert_eq!(std::fs::read_to_string(backup.path()).unwrap(), original);

    // Rescan is clean.
    agentleaks().arg("scan").arg(&file).assert().code(0);
}

#[test]
fn scrub_dry_run_modifies_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let key = fake_github_token();
    let file = tmp.path().join("settings.local.json");
    std::fs::write(
        &file,
        format!("{{\"env\": {{\"GITHUB_TOKEN\": \"{key}\"}}}}"),
    )
    .unwrap();
    let before = std::fs::read_to_string(&file).unwrap();

    agentleaks()
        .args(["scrub", "--dry-run", "--no-color"])
        .arg(tmp.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("dry run"));

    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
}

#[test]
fn stdin_paths_mode_reads_file_list() {
    let tmp = tempfile::tempdir().unwrap();
    let key = fake_github_token();
    let file = tmp.path().join("mcp.json");
    std::fs::write(&file, format!("{{\"token\": \"{key}\"}}")).unwrap();

    agentleaks()
        .args(["scan", "--stdin-paths", "--no-color"])
        .write_stdin(format!("{}\n", file.display()))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("GitHub token"));
}

#[test]
fn scan_missing_path_is_an_error() {
    // A typo in a CI gate must fail loudly, not pass as "clean".
    agentleaks()
        .args(["scan", "definitely-not-a-real-path-xyz"])
        .assert()
        .code(2);
}

#[test]
fn scrub_refuses_noninteractive_without_yes() {
    let tmp = tempfile::tempdir().unwrap();
    let key = fake_anthropic_key();
    let file = write_session(tmp.path(), &key);
    let before = std::fs::read_to_string(&file).unwrap();

    // stdin is a pipe here, so scrub must refuse rather than no-op.
    agentleaks()
        .arg("scrub")
        .arg(tmp.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--yes"));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
}

#[test]
fn purge_deletes_scrub_backups() {
    let tmp = tempfile::tempdir().unwrap();
    let key = fake_anthropic_key();
    let file = write_session(tmp.path(), &key);

    agentleaks()
        .args(["scrub", "--yes", "--no-color"])
        .arg(tmp.path())
        .assert()
        .code(0);
    let has_backup = |dir: &std::path::Path| {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().ends_with(".bak"))
    };
    assert!(has_backup(tmp.path()), "scrub should have left a backup");

    agentleaks()
        .args(["purge", "--yes", "--no-color"])
        .arg(tmp.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("deleted"));

    assert!(!has_backup(tmp.path()), "purge must remove the backup");
    // The scrubbed file itself is untouched.
    let after = std::fs::read_to_string(&file).unwrap();
    assert!(after.contains("[REDACTED:anthropic-api-key:"));
}

#[test]
fn stores_command_lists_known_agents() {
    agentleaks()
        .args(["stores", "--no-color"])
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("Claude Code")
                .and(predicate::str::contains("Codex CLI"))
                .and(predicate::str::contains(".credentials.json")),
        );
}

#[test]
fn rules_command_lists_rules() {
    agentleaks()
        .args(["rules", "--no-color"])
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("anthropic-api-key")
                .and(predicate::str::contains("private-key")),
        );
}
