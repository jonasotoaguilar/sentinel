//! E2E dependency-review coverage (`sentinel-osv-dependency-engine` Phase 5):
//! offline hits/misses, corrupt entries, unpinned lines, online freshness,
//! and determinism. Each test spawns the binary with a per-command
//! `XDG_CACHE_HOME`; nothing depends on live network data.

use assert_cmd::Command as AssertCommand;
use sentinel::osv::client::{OsvApi, OsvTransportPolicy, Query, REQUEST_TIMEOUT, UreqOsvClient};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
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

// ---------------------------------------------------------------------------
// S5: the OSV transport policy is deliberate — no proxy from the
// environment, no redirects — and loopback doubles prove where each
// request goes. A double counts every request whose path carries
// `/querybatch` (a followed POST redirect arrives as GET, a proxied POST
// arrives in absolute form); anything else on loopback (ambient probers
// send `GET /`) is refused with 404 without counting, so each count pins
// this test's requests rather than machine traffic.
// ---------------------------------------------------------------------------

/// What one OSV loopback double answers a batch request with.
enum OsvRespond {
    /// One severe synthetic advisory, so the query succeeds with no detail fetch.
    BatchOk,
    /// A 302 to a second double's batch URL (the target must see nothing).
    Redirect(String),
    /// The proxy double: traps the tunnel or forwarded request so the
    /// parent can prove traffic reached the proxy instead of the endpoint.
    ProxyTrap,
}

/// The batch envelope every double answers success with: one severe
/// synthetic advisory, so the query succeeds with no detail fetch.
const BATCH_OK_BODY: &str = r#"{"results":[{"vulns":[{"id":"GHSA-TEST-0001","summary":"synthetic","severity":[{"type":"CVSS_V3","score":"9.8"}]}]}]}"#;

fn batch_ok_reply() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BATCH_OK_BODY}",
        BATCH_OK_BODY.len()
    )
}

/// Answers one connection to the proxy double: ureq tunnels every proxied
/// request through CONNECT, so the tunnel itself is the routing evidence.
/// The tunnel is established and the inner batch POST answered on the same
/// connection, so a query that honours the proxy completes *through* the
/// proxy — proving the proxy changed where the request goes instead of
/// merely breaking it. Anything else is refused without counting.
fn proxy_trap(stream: &mut TcpStream, posts: &Arc<AtomicUsize>) {
    let (method, path, _) = osv_read_request(stream);
    if method == "CONNECT" {
        posts.fetch_add(1, Ordering::SeqCst);
        let _ =
            stream.write_all(b"HTTP/1.1 200 Connection established\r\nContent-Length: 0\r\n\r\n");
        let (_, inner_path, _) = osv_read_request(stream);
        let reply = if inner_path.contains("/querybatch") {
            batch_ok_reply()
        } else {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        };
        let _ = stream.write_all(reply.as_bytes());
        return;
    }
    if method == "POST" && path.contains("/querybatch") {
        // Absolute-form forwarded POST (a client that forwards without a
        // tunnel): the same routing evidence.
        posts.fetch_add(1, Ordering::SeqCst);
        let _ = stream.write_all(batch_ok_reply().as_bytes());
        return;
    }
    let _ = stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

/// Spawns a loopback double for the OSV batch endpoint. Returns its batch
/// URL, its detail base URL, and the batch-request count (the where-it-goes
/// evidence).
fn osv_stub(respond: OsvRespond) -> (String, String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let batch = format!("http://127.0.0.1:{port}/querybatch");
    let vuln = format!("http://127.0.0.1:{port}/vulns/");
    let posts = Arc::new(AtomicUsize::new(0));
    let kept = Arc::clone(&posts);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            if matches!(respond, OsvRespond::ProxyTrap) {
                proxy_trap(&mut stream, &kept);
                continue;
            }
            let (_, path, _) = osv_read_request(&mut stream);
            if !path.contains("/querybatch") {
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                continue;
            }
            kept.fetch_add(1, Ordering::SeqCst);
            let reply = match &respond {
                OsvRespond::BatchOk => batch_ok_reply(),
                OsvRespond::Redirect(target) => format!(
                    "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
                OsvRespond::ProxyTrap => unreachable!("handled above"),
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (batch, vuln, posts)
}

/// Reads one HTTP/1.1 request: its method, path, and `Content-Length` body.
fn osv_read_request(stream: &mut TcpStream) -> (String, String, Vec<u8>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 65536 {
        let Ok(1) = stream.read(&mut byte) else { break };
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut first = text.lines().next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let length = text
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::to_string)
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length.min(1 << 20)];
    let _ = stream.read_exact(&mut body);
    (method, path, body)
}

fn osv_query() -> Query {
    Query {
        eco: "npm".into(),
        name: "lodash".into(),
        ver: "4.17.20".into(),
    }
}

fn osv_client(batch: &str, vuln: &str) -> UreqOsvClient {
    UreqOsvClient::with_policy(OsvTransportPolicy::loopback_for_test(batch, vuln))
}

#[test]
fn osv_redirect_target_is_never_contacted() {
    let (target_batch, _, target_posts) = osv_stub(OsvRespond::BatchOk);
    let (batch, vuln, batch_posts) = osv_stub(OsvRespond::Redirect(target_batch));
    let result = osv_client(&batch, &vuln).query_all(&[osv_query()]);
    assert!(
        result.is_err(),
        "a 302 degrades like any other non-success: {result:?}"
    );
    assert_eq!(
        batch_posts.load(Ordering::SeqCst),
        1,
        "the single batch POST reaches its endpoint"
    );
    assert_eq!(
        target_posts.load(Ordering::SeqCst),
        0,
        "the redirect target is never contacted"
    );
}

/// Runs inside the re-execed child (see below): the same test binary, but
/// the child owns its environment, so no parallel test can observe the
/// proxy variables. The parent asserts where the requests landed.
fn osv_proxy_child_main() {
    let batch = std::env::var("SENTINEL_OSV_TEST_BATCH").unwrap();
    let vuln = std::env::var("SENTINEL_OSV_TEST_VULN").unwrap();
    let (advisories, diagnostics) = osv_client(&batch, &vuln).query_all(&[osv_query()]).unwrap();
    assert_eq!(advisories.len(), 1);
    assert_eq!(advisories[0].len(), 1);
    assert_eq!(advisories[0][0].id, "GHSA-TEST-0001");
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
}

#[test]
fn osv_proxy_environment_is_ignored() {
    // Mutating process environment from a parallel test is a race (and
    // `std::env::set_var` is `unsafe` in this edition), so the child
    // process below owns its environment instead: the test binary re-runs
    // just this test with the proxy variables set.
    if std::env::var("SENTINEL_OSV_PROXY_CHILD").is_ok() {
        osv_proxy_child_main();
        return;
    }
    let (batch, vuln, batch_posts) = osv_stub(OsvRespond::BatchOk);
    let (proxy_batch, _, proxy_posts) = osv_stub(OsvRespond::ProxyTrap);
    let proxy_origin = proxy_batch.strip_suffix("/querybatch").unwrap().to_string();
    let exe = std::env::current_exe().unwrap();
    let output = Command::new(exe)
        .arg("--exact")
        .arg("osv_proxy_environment_is_ignored")
        .env("SENTINEL_OSV_PROXY_CHILD", "1")
        .env("SENTINEL_OSV_TEST_BATCH", &batch)
        .env("SENTINEL_OSV_TEST_VULN", &vuln)
        .env("HTTP_PROXY", &proxy_origin)
        .env("http_proxy", &proxy_origin)
        .env("HTTPS_PROXY", &proxy_origin)
        .env("https_proxy", &proxy_origin)
        .env("ALL_PROXY", &proxy_origin)
        .env("all_proxy", &proxy_origin)
        // Neutralize any ambient exclusion list (CI runners often exclude
        // loopback), so the proxy variables above are the whole story.
        .env("NO_PROXY", "example.invalid")
        .env("no_proxy", "example.invalid")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child must complete its query: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        batch_posts.load(Ordering::SeqCst),
        1,
        "the configured endpoint receives the request"
    );
    assert_eq!(
        proxy_posts.load(Ordering::SeqCst),
        0,
        "no byte may be tunnelled to the proxy"
    );
}

#[test]
fn osv_production_policy_refuses_plain_http_without_any_request() {
    // Pins the decided values: `https_only` must never be quietly dropped,
    // and the proxy/redirect/timeout settings must stay exactly as decided.
    let production = OsvTransportPolicy::production();
    assert_eq!(production.batch_url, "https://api.osv.dev/v1/querybatch");
    assert_eq!(production.vuln_base, "https://api.osv.dev/v1/vulns/");
    assert_eq!(production.timeout, REQUEST_TIMEOUT);
    assert!(production.https_only, "HTTPS-only must stay on");
    assert!(production.proxy.is_none(), "the proxy stays disabled");
    assert_eq!(production.max_redirects, 0, "redirects stay refused");
    // A production-policy client pointed at a plain-HTTP double (test-only
    // endpoint override) must fail before sending anything.
    let (batch, vuln, posts) = osv_stub(OsvRespond::BatchOk);
    let mut probed = OsvTransportPolicy::production();
    probed.batch_url = batch;
    probed.vuln_base = vuln;
    let result = UreqOsvClient::with_policy(probed).query_all(&[osv_query()]);
    assert!(
        result.is_err(),
        "plain HTTP under the production policy must fail: {result:?}"
    );
    assert_eq!(
        posts.load(Ordering::SeqCst),
        0,
        "refused before any byte is sent"
    );
}

#[test]
fn osv_batch_chunks_at_a_thousand_queries() {
    let per = sentinel::ScanBudgets::production().max_pins_per_request;
    assert_eq!(per, 1_000);
    let queries = |n: usize| -> Vec<Query> {
        (0..n)
            .map(|i| Query {
                eco: "npm".into(),
                name: format!("pkg-{i}"),
                ver: "1.0.0".into(),
            })
            .collect()
    };
    let (batch, vuln, posts) = osv_stub(OsvRespond::BatchOk);
    osv_client(&batch, &vuln)
        .query_all(&queries(1_000))
        .unwrap();
    assert_eq!(
        posts.load(Ordering::SeqCst),
        1,
        "exactly 1 000 queries is one request"
    );
    let (batch, vuln, posts) = osv_stub(OsvRespond::BatchOk);
    let (results, _) = osv_client(&batch, &vuln)
        .query_all(&queries(1_001))
        .unwrap();
    assert_eq!(
        posts.load(Ordering::SeqCst),
        2,
        "1 001 queries is two requests"
    );
    assert_eq!(results.len(), 1_001, "shape stays index-aligned");
}
