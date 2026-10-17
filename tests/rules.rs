//! End-to-end coverage for the code-rules engine through the binary over
//! temporary git repositories built from `tests/fixtures/rules/`
//! (code-rules spec: pinned rule set, parse-failure degradation,
//! deterministic contained engine, redaction at the engine boundary).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

mod common;

use common::{AWS_KEY, TOKEN, git, temp_repo, text_of};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("rules")
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_root().join(name))
        .unwrap_or_else(|error| panic!("cannot read fixture {name}: {error}"))
}

fn track_fixture(root: &Path, fixture: &str, repo_rel: &str) {
    std::fs::write(root.join(repo_rel), fixture_bytes(fixture)).unwrap();
    git(
        root,
        [OsStr::new("add"), OsStr::new("--"), OsStr::new(repo_rel)],
    );
}

fn scan_bin(cwd: &Path) -> AssertCommand {
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.arg("scan")
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("XDG_CONFIG_HOME", cwd)
        .env_remove("SENTINEL_CONFIG")
        .env("HOME", cwd);
    cmd
}

fn violating_repo() -> (TempDir, PathBuf) {
    let (dir, root) = temp_repo();
    track_fixture(&root, "weak_hash.js", "weak_hash.js");
    track_fixture(&root, "dynamic.ts", "dynamic.ts");
    track_fixture(&root, "shell.py", "shell.py");
    (dir, root)
}

#[test]
fn violating_js_ts_and_py_report_pinned_ids_and_exit_one() {
    let (_dir, root) = violating_repo();
    let output = scan_bin(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = text_of(&output.stdout);
    for id in [
        "RULE-weak-hash",
        "RULE-dynamic-code",
        "RULE-shell-injection-python",
    ] {
        assert!(stdout.contains(id), "missing {id} in {stdout:?}");
    }
    assert!(output.stderr.is_empty(), "stderr: {:?}", output.stderr);
}

#[test]
fn clean_fixtures_exit_zero_with_empty_stdout() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "clean.js", "clean.js");
    track_fixture(&root, "clean.py", "clean.py");
    let output = scan_bin(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn unparseable_fixture_warns_once_and_reports_nothing() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "broken.js", "broken.js");
    let output = scan_bin(&root).output().unwrap();
    // A file that does not parse is skipped rather than guessed at, and the
    // diagnostic is what keeps it from being silently dropped.
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    let stderr = text_of(&output.stderr);
    assert_eq!(
        stderr.matches("rule-fallback").count(),
        1,
        "stderr: {stderr:?}"
    );
    assert!(stderr.contains("broken.js"), "stderr: {stderr:?}");
}

#[test]
fn two_json_runs_are_byte_identical() {
    let (_dir, root) = violating_repo();
    let first = scan_bin(&root)
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();
    let second = scan_bin(&root)
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(first.stdout, second.stdout);
    assert!(!first.stdout.is_empty());
}

#[test]
fn matched_secret_never_leaves_the_engine_boundary() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "secret.js", "secret.js");
    // The second declared synthetic enters through a tracked file of its own,
    // so the redaction assertions below are live for both shapes, not vacuous.
    std::fs::write(
        root.join("aws_key.js"),
        format!("// SYNTHETIC FIXTURE\nconst key = \"{AWS_KEY}\";\n"),
    )
    .unwrap();
    git(&root, ["add", "--", "aws_key.js"]);
    let plain = scan_bin(&root).output().unwrap();
    assert_eq!(plain.status.code(), Some(1));
    let stdout = text_of(&plain.stdout);
    assert!(
        stdout.contains("RULE-shell-injection"),
        "stdout: {stdout:?}"
    );
    assert!(!stdout.contains(TOKEN), "stdout: {stdout:?}");
    assert!(!stdout.contains(AWS_KEY), "stdout: {stdout:?}");
    assert!(!text_of(&plain.stderr).contains(TOKEN));
    assert!(!text_of(&plain.stderr).contains(AWS_KEY));
    let output = scan_bin(&root)
        .arg("--output")
        .arg("json")
        .arg("--report")
        .arg("report.json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout stays empty with --report");
    let stderr = text_of(&output.stderr);
    assert!(!stderr.contains(TOKEN), "stderr: {stderr:?}");
    let report = text_of(&std::fs::read(root.join("report.json")).unwrap());
    assert!(
        report.contains("RULE-shell-injection"),
        "report: {report:?}"
    );
    assert!(!report.contains(TOKEN));
    assert!(!report.contains(AWS_KEY));
}
