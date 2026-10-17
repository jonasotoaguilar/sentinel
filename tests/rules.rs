//! End-to-end coverage for the code-rules engine through the binary over
//! temporary git repositories built from `tests/fixtures/rules/`
//! (code-rules spec: pinned rule set, parse-failure degradation,
//! deterministic contained engine, redaction at the engine boundary).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

/// The synthetic token the secret fixture embeds; it must never appear in
/// any output stream or report file.
const TOKEN: &str = "sk-synthetic-1234567890";

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

fn git<I, S>(cwd: &Path, args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git failed in {cwd:?}");
}

fn temp_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    git(&root, ["init", "-q"]);
    (dir, root)
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
    let stdout = String::from_utf8(output.stdout).unwrap();
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
fn unparseable_fixture_reports_and_warns_once() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "broken.js", "broken.js");
    let output = scan_bin(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("RULE-weak-hash"), "stdout: {stdout:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
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
    let plain = scan_bin(&root).output().unwrap();
    assert_eq!(plain.status.code(), Some(1));
    let stdout = String::from_utf8(plain.stdout).unwrap();
    assert!(
        stdout.contains("RULE-shell-injection"),
        "stdout: {stdout:?}"
    );
    assert!(!stdout.contains(TOKEN), "stdout: {stdout:?}");
    assert!(!String::from_utf8(plain.stderr).unwrap().contains(TOKEN));
    let output = scan_bin(&root)
        .arg("--output")
        .arg("json")
        .arg("--report")
        .arg("report.json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout stays empty with --report");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains(TOKEN), "stderr: {stderr:?}");
    let report = String::from_utf8(std::fs::read(root.join("report.json")).unwrap()).unwrap();
    assert!(
        report.contains("RULE-shell-injection"),
        "report: {report:?}"
    );
    assert!(!report.contains(TOKEN));
}
