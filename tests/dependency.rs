//! E2E dependency-review coverage (`sentinel-osv-dependency-engine` Phase 5):
//! offline hits/misses, corrupt entries, unpinned lines, online freshness,
//! and determinism. Each test spawns the binary with a per-command
//! `XDG_CACHE_HOME`; nothing depends on live network data.

use assert_cmd::Command as AssertCommand;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::UNIX_EPOCH;
use tempfile::TempDir;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn fixture_bytes(rel: &str) -> Vec<u8> {
    std::fs::read(fixture_root().join(rel))
        .unwrap_or_else(|error| panic!("cannot read fixture {rel}: {error}"))
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

fn track_fixture(root: &Path, fixture_rel: &str, repo_rel: &str) {
    std::fs::write(root.join(repo_rel), fixture_bytes(fixture_rel)).unwrap();
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

fn scan_with(xdg: &Path, root: &Path, args: &[&str]) -> Output {
    scan_bin(root)
        .env("XDG_CACHE_HOME", xdg)
        .args(args)
        .output()
        .unwrap()
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn snapshot_tree(root: &Path) -> Vec<(PathBuf, u64, u128)> {
    fn walk(root: &Path, dir: &Path, entries: &mut Vec<(PathBuf, u64, u128)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let meta = entry.metadata().unwrap();
            let mtime = meta
                .modified()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            if meta.is_dir() {
                walk(root, &path, entries);
            }
            entries.push((
                path.strip_prefix(root).unwrap().to_path_buf(),
                meta.len(),
                mtime,
            ));
        }
    }
    let mut entries = Vec::new();
    walk(root, root, &mut entries);
    entries.sort();
    entries
}

/// Seeds one cache record at the exact `src/cache.rs` layout
/// (`<xdg>/sentinel/osv/v1/<eco>/<pct(name)>/<pct(ver)>.json`).
fn seed_cache(xdg: &Path, eco: &str, pkg: &str, ver_enc: &str, bytes: &[u8]) -> PathBuf {
    let path = xdg
        .join("sentinel")
        .join("osv")
        .join("v1")
        .join(eco)
        .join(pkg)
        .join(format!("{ver_enc}.json"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    path
}

fn seeded_lock_repo() -> (TempDir, PathBuf, TempDir) {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "dependency/package-lock.json", "package-lock.json");
    let xdg = TempDir::new().unwrap();
    seed_cache(
        xdg.path(),
        "npm",
        "lodash",
        "4%2E17%2E20",
        &fixture_bytes("dependency/advisory.json"),
    );
    (_dir, root, xdg)
}

#[test]
fn offline_hit_reports_one_pinned_finding_and_leaves_repo_untouched() {
    let (_dir, root, xdg) = seeded_lock_repo();
    let before = snapshot_tree(&root);
    let output = scan_with(xdg.path(), &root, &["--offline"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = text_of(&output.stdout);
    assert!(stdout.contains("package-lock.json:1:1: critical OSV-GHSA-SYNTHETIC-0001"));
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("package-lock.json:"))
            .count(),
        1,
        "one dependency finding per advisory"
    );
    assert!(output.stderr.is_empty(), "a cache hit warns nothing");
    let json = scan_with(xdg.path(), &root, &["--offline", "--output", "json"]);
    assert_eq!(json.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["engine"], "dependency");
    assert_eq!(findings[0]["rule_id"], "OSV-GHSA-SYNTHETIC-0001");
    assert_eq!(findings[0]["location"]["path"], "package-lock.json");
    assert_eq!(findings[0]["location"]["line"], 1);
    assert_eq!(
        before,
        snapshot_tree(&root),
        "scan must not modify the repo"
    );
}

#[test]
fn offline_miss_warns_and_secrets_still_report() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "dependency/requirements.txt", "requirements.txt");
    track_fixture(&root, "basic/env.example", "env.example");
    let xdg = TempDir::new().unwrap();
    let before = snapshot_tree(&root);
    let output = scan_with(xdg.path(), &root, &["--offline"]);
    assert_eq!(output.status.code(), Some(1), "secret finding, never 2");
    assert!(text_of(&output.stderr).contains("osv-unavailable"));
    let stdout = text_of(&output.stdout);
    assert!(
        stdout.contains("SECRET-aws-access-key"),
        "secrets still report"
    );
    assert!(
        !stdout.contains("OSV-"),
        "a miss emits no dependency findings"
    );
    assert_eq!(before, snapshot_tree(&root));
    assert!(
        snapshot_tree(xdg.path()).is_empty(),
        "offline never writes the cache"
    );
}

#[test]
fn ci_offline_is_byte_identical_to_offline() {
    let (_dir, root, xdg) = seeded_lock_repo();
    let plain = scan_with(xdg.path(), &root, &["--offline"]);
    let ci = scan_with(xdg.path(), &root, &["--ci", "--offline"]);
    assert_eq!(
        plain.status.code(),
        Some(1),
        "--offline is accepted, not a usage error"
    );
    assert_eq!(ci.status.code(), Some(1));
    assert_eq!(
        plain.stdout, ci.stdout,
        "--ci must not change offline output"
    );
    assert_eq!(plain.stderr, ci.stderr);
}

#[test]
fn offline_corrupt_entry_warns_without_rewriting_bytes() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "dependency/package-lock.json", "package-lock.json");
    let xdg = TempDir::new().unwrap();
    let entry = seed_cache(
        xdg.path(),
        "npm",
        "lodash",
        "4%2E17%2E20",
        &fixture_bytes("dependency/corrupt-entry.json"),
    );
    let before_bytes = std::fs::read(&entry).unwrap();
    let before_tree = snapshot_tree(&root);
    let output = scan_with(xdg.path(), &root, &["--offline"]);
    assert_eq!(output.status.code(), Some(0), "miss degrades, never 2");
    assert!(text_of(&output.stderr).contains("cache-entry-corrupt"));
    assert!(output.stdout.is_empty(), "corrupt entries emit no findings");
    assert_eq!(
        std::fs::read(&entry).unwrap(),
        before_bytes,
        "offline must never rewrite the cache"
    );
    assert_eq!(before_tree, snapshot_tree(&root));
}

#[test]
fn unpinned_lines_skip_with_path_and_line_and_never_exit_two() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "dependency/requirements.txt", "requirements.txt");
    let xdg = TempDir::new().unwrap();
    let output = scan_with(xdg.path(), &root, &["--offline"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = text_of(&output.stderr);
    assert!(stderr.contains("version-unpinned-skipped") && stderr.contains("requirements.txt:3"));
    assert!(
        !text_of(&output.stdout).contains("OSV-"),
        "unpinned lines are never queried"
    );
}

#[test]
fn fresh_cache_serves_online_without_fetching_live_advisories() {
    let (_dir, root, xdg) = seeded_lock_repo();
    let before = snapshot_tree(&root);
    let output = scan_with(xdg.path(), &root, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text_of(&output.stdout).contains("OSV-GHSA-SYNTHETIC-0001"));
    let json = scan_with(xdg.path(), &root, &["--output", "json"]);
    assert_eq!(json.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert!(
        findings
            .iter()
            .all(|finding| finding["rule_id"] == "OSV-GHSA-SYNTHETIC-0001"),
        "fresh cache serves without HTTP, so no live ids appear"
    );
    assert_eq!(before, snapshot_tree(&root));
}

#[test]
fn seeded_reports_are_byte_identical_across_runs() {
    let (_dir, root, xdg) = seeded_lock_repo();
    for args in [
        &["--offline", "--output", "json"][..],
        &["--offline", "--output", "sarif"][..],
    ] {
        let first = scan_with(xdg.path(), &root, args);
        let second = scan_with(xdg.path(), &root, args);
        assert_eq!(first.status.code(), Some(1), "args {args:?}");
        assert_eq!(first.status.code(), second.status.code(), "args {args:?}");
        assert_eq!(
            first.stdout, second.stdout,
            "args {args:?} must be byte-identical"
        );
        assert_eq!(first.stderr, second.stderr, "args {args:?}");
    }
    let first = scan_with(xdg.path(), &root, &["--offline"]);
    let second = scan_with(xdg.path(), &root, &["--offline"]);
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(
        first.stdout, second.stdout,
        "terminal must be byte-identical"
    );
    assert_eq!(first.stderr, second.stderr);
}

#[test]
fn advisory_id_and_summary_are_redacted_on_every_surface() {
    // Why: the advisory id and summary are content-derived display fields.
    const RAW_ID: &str = "AKIASYNTHETICKEY1234";
    const RAW_SECRET: &str = "sk-synthetic-1234567890";
    assert!(
        sentinel::osv::is_valid_id(RAW_ID),
        "seeded id must pass validation"
    );
    let (_dir, root) = temp_repo();
    std::fs::write(root.join("requirements.txt"), b"flask==2.3.3\n").unwrap();
    git(
        &root,
        [
            OsStr::new("add"),
            OsStr::new("--"),
            OsStr::new("requirements.txt"),
        ],
    );
    let xdg = TempDir::new().unwrap();
    let advisory = serde_json::json!([{
        "id": RAW_ID,
        "summary": format!("exposes {RAW_SECRET} in summary"),
        "severity": [{"type": "CVSS_V3", "score": "9.8"}]
    }]);
    seed_cache(
        xdg.path(),
        "PyPI",
        "flask",
        "2%2E3%2E3",
        &serde_json::to_vec(&advisory).unwrap(),
    );
    let terminal = scan_with(xdg.path(), &root, &["--offline"]);
    assert_eq!(terminal.status.code(), Some(1), "the finding still reports");
    let terminal_blob = text_of(&terminal.stdout) + &text_of(&terminal.stderr);
    assert!(
        terminal_blob.contains("requirements.txt:1:1:"),
        "finding present: {terminal_blob}"
    );
    assert!(
        !terminal_blob.contains(RAW_ID),
        "raw advisory id leaked on terminal: {terminal_blob}"
    );
    assert!(
        !terminal_blob.contains(RAW_SECRET),
        "raw summary secret leaked on terminal: {terminal_blob}"
    );
    assert!(
        terminal_blob.contains("[REDACTED]"),
        "redacted marker present: {terminal_blob}"
    );
    let json = scan_with(xdg.path(), &root, &["--offline", "--output", "json"]);
    assert_eq!(json.status.code(), Some(1), "the finding still reports");
    let json_blob = text_of(&json.stdout) + &text_of(&json.stderr);
    assert!(json_blob.contains("OSV-"), "finding present: {json_blob}");
    assert!(
        !json_blob.contains(RAW_ID),
        "raw advisory id leaked in json: {json_blob}"
    );
    assert!(
        !json_blob.contains(RAW_SECRET),
        "raw summary secret leaked in json: {json_blob}"
    );
    let sarif = scan_with(xdg.path(), &root, &["--offline", "--output", "sarif"]);
    assert_eq!(sarif.status.code(), Some(1), "the finding still reports");
    let sarif_blob = text_of(&sarif.stdout) + &text_of(&sarif.stderr);
    assert!(sarif_blob.contains("OSV-"), "finding present: {sarif_blob}");
    assert!(
        !sarif_blob.contains(RAW_ID),
        "raw advisory id leaked in sarif: {sarif_blob}"
    );
    assert!(
        !sarif_blob.contains(RAW_SECRET),
        "raw summary secret leaked in sarif: {sarif_blob}"
    );
    serde_json::from_slice::<serde_json::Value>(&sarif.stdout).unwrap();
    let report = scan_with(
        xdg.path(),
        &root,
        &["--offline", "--output", "json", "--report", "out.json"],
    );
    assert_eq!(report.status.code(), Some(1), "the finding still reports");
    assert!(report.stdout.is_empty(), "stdout stays empty with --report");
    let report_blob = text_of(&std::fs::read(root.join("out.json")).unwrap());
    assert!(
        report_blob.contains("OSV-"),
        "finding present: {report_blob}"
    );
    assert!(
        !report_blob.contains(RAW_ID),
        "raw advisory id leaked in report file: {report_blob}"
    );
    assert!(
        !report_blob.contains(RAW_SECRET),
        "raw summary secret leaked in report file: {report_blob}"
    );
}

#[test]
fn degraded_scan_carries_incomplete_signal_and_clean_scan_carries_none() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "dependency/requirements.txt", "requirements.txt");
    let xdg = TempDir::new().unwrap();
    let json = scan_with(xdg.path(), &root, &["--offline", "--output", "json"]);
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        report["incomplete"], true,
        "degraded json must say incomplete"
    );
    let sarif = scan_with(xdg.path(), &root, &["--offline", "--output", "sarif"]);
    let log: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    let inv = &log["runs"][0]["invocations"];
    assert_eq!(
        inv[0]["executionSuccessful"], false,
        "sarif must say unsuccessful"
    );
    assert!(inv[0]["toolExecutionNotifications"].is_array());
    let schema: serde_json::Value =
        serde_json::from_slice(&fixture_bytes("sarif-2.1.0.schema.json")).unwrap();
    let compiled = jsonschema::draft7::new(&schema).unwrap();
    assert!(
        compiled.validate(&log).is_ok(),
        "degraded sarif stays schema-valid"
    );
    let (_dir2, clean) = temp_repo();
    std::fs::write(clean.join("ok.txt"), b"no secrets").unwrap();
    git(&clean, ["add", "--", "ok.txt"]);
    let xdg2 = TempDir::new().unwrap();
    let json = scan_with(xdg2.path(), &clean, &["--offline", "--output", "json"]);
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(
        report.get("incomplete").is_none(),
        "clean json stays absent"
    );
    let sarif = scan_with(xdg2.path(), &clean, &["--offline", "--output", "sarif"]);
    let log: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    assert!(
        log["runs"][0].get("invocations").is_none(),
        "clean sarif stays absent"
    );
}
