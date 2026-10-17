//! End-to-end coverage for the bounded HTTP explain adapter through the
//! binary over temporary git repositories (explain-adapter spec: bounded
//! single-attempt request, redacted context, failure codes). A loopback stub
//! HTTP server stands in for the model endpoint: the OSV trait-plus-stub
//! double cannot serve real HTTP through the binary (its hermetic binary
//! tests avoid the network via the seeded cache instead), so these tests use
//! a std-only TCP server and no new dependencies.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

const AWS_KEY: &str = "AKIASYNTHETICKEY1234";
const TOKEN: &str = "sk-synthetic-1234567890";

/// Recorded traffic of one stub endpoint: its URL, explain-request bodies,
/// and the explain-request count (the single-attempt evidence). Only
/// `POST /explain` connections record: anything else on loopback (port
/// probers send `GET /`) is refused without recording, so the count pins
/// this test's scans rather than ambient traffic.
type Recorded = (String, Arc<Mutex<Vec<Vec<u8>>>>, Arc<AtomicUsize>);

/// What the stub endpoint answers every request with.
enum Respond {
    /// One `{"id", "text"}` entry per requested finding id.
    Echo,
    /// A fixed status code and body.
    Fixed(u16, &'static str),
}

/// Spawns a loopback stub endpoint. Returns its URL plus the recorded request
/// bodies and the accepted-connection count (the single-attempt evidence).
fn stub_server(mode: Respond) -> Recorded {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/explain",
        listener.local_addr().unwrap().port()
    );
    let bodies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let count = Arc::new(AtomicUsize::new(0));
    let (kept_bodies, kept_count) = (Arc::clone(&bodies), Arc::clone(&count));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let (method, path, body) = read_request(&mut stream);
            if method != "POST" || path != "/explain" {
                refuse(&mut stream);
                continue;
            }
            // Recording precedes the reply, and the child waits for the
            // reply before exiting, so once `output()` returns every
            // legitimate request is already counted: no sleep needed.
            kept_count.fetch_add(1, Ordering::SeqCst);
            kept_bodies.lock().unwrap().push(body.clone());
            let (status, text) = match &mode {
                Respond::Echo => (200, echo_advisories(&body)),
                Respond::Fixed(status, text) => (*status, (*text).to_string()),
            };
            let reason = if status == 200 { "OK" } else { "Error" };
            let reply = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (url, bodies, count)
}

/// Reads one HTTP/1.1 request: its method, path, and `Content-Length` body.
fn read_request(stream: &mut std::net::TcpStream) -> (String, String, Vec<u8>) {
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

/// Refuses a connection that is not an explain request without recording
/// it, so ambient loopback traffic never moves a test's count.
fn refuse(stream: &mut std::net::TcpStream) {
    let _ = stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

/// Builds one advisory entry per requested finding id.
fn echo_advisories(body: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let mut out = Vec::new();
    if let Some(items) = value
        .get("findings")
        .and_then(|findings| findings.as_array())
    {
        for item in items {
            if let Some(id) = item.get("id").and_then(|id| id.as_str()) {
                out.push(serde_json::json!({"id": id, "text": format!("advice for {id}")}));
            }
        }
    }
    serde_json::Value::Array(out).to_string()
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
        .stderr(Stdio::inherit())
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

fn write_tracked(root: &Path, name: &str, contents: &[u8]) {
    std::fs::write(root.join(name), contents).unwrap();
    git(
        root,
        [OsStr::new("add"), OsStr::new("--"), OsStr::new(name)],
    );
}

/// A repository with exactly two secret findings (mirrors `basic/env.example`).
fn secret_repo() -> (TempDir, PathBuf) {
    let (dir, root) = temp_repo();
    let contents = format!("aws_key = \"{AWS_KEY}\"\ntoken = {TOKEN}\n");
    write_tracked(&root, "env.example", contents.as_bytes());
    (dir, root)
}

/// Runs the binary without any explain configuration.
fn scan(root: &Path, args: &[&str]) -> Output {
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.arg("scan")
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", root);
    cmd.args(args);
    cmd.output().unwrap()
}

/// Runs the binary pointed at the stub endpoint.
fn scan_explained(root: &Path, url: &str, args: &[&str]) -> Output {
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.arg("scan")
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", root)
        .env("SENTINEL_EXPLAIN_URL", url)
        .env("SENTINEL_EXPLAIN_API_KEY", "test-key");
    cmd.args(args);
    cmd.output().unwrap()
}

/// Runs the binary pointed at the stub endpoint with extra environment
/// variables (the proxy test points every proxy variable at its double).
fn scan_explained_with_env(
    root: &Path,
    url: &str,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Output {
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.arg("scan")
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", root)
        .env("SENTINEL_EXPLAIN_URL", url)
        .env("SENTINEL_EXPLAIN_API_KEY", "test-key");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.args(args);
    cmd.output().unwrap()
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn advice_lines(stdout: &[u8]) -> Vec<String> {
    text_of(stdout)
        .lines()
        .filter(|line| line.starts_with("  advice: "))
        .map(str::to_string)
        .collect()
}

#[test]
fn configured_adapter_renders_one_advisory_per_finding_after_a_single_request() {
    let (_dir, root) = secret_repo();
    let (url, _bodies, count) = stub_server(Respond::Echo);
    let output = scan_explained(&root, &url, &["--explain"]);
    assert_eq!(output.status.code(), Some(1));
    let advice = advice_lines(&output.stdout);
    assert_eq!(advice.len(), 2, "one advisory line per finding");
    assert!(advice.iter().all(|line| line.contains("advice for ")));
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "exactly one request per scan"
    );
    // The finding lines are unchanged; only the advisory lines are additive.
    let plain = scan(&root, &[]);
    let stripped: String = text_of(&output.stdout)
        .lines()
        .filter(|line| !line.starts_with("  advice: "))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_eq!(stripped, text_of(&plain.stdout));
    assert!(output.stderr.is_empty());
    // Machine output never carries advisory text.
    let explained_json = scan_explained(&root, &url, &["--explain", "--output", "json"]);
    let plain_json = scan(&root, &["--output", "json"]);
    assert_eq!(explained_json.stdout, plain_json.stdout);
    assert!(!text_of(&explained_json.stdout).contains("advice"));
}

#[test]
fn outbound_body_carries_no_raw_secret() {
    let (_dir, root) = secret_repo();
    let (url, bodies, _count) = stub_server(Respond::Echo);
    let output = scan_explained(&root, &url, &["--explain"]);
    assert_eq!(output.status.code(), Some(1));
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1, "exactly one request per scan");
    let body = text_of(&bodies[0]);
    assert!(
        !body.contains(AWS_KEY) && !body.contains(TOKEN),
        "a raw secret value left the process: {body}"
    );
    assert!(
        body.contains("[REDACTED]"),
        "context still describes findings"
    );
    assert!(!text_of(&output.stdout).contains(AWS_KEY));
    assert!(!text_of(&output.stdout).contains(TOKEN));
    assert!(!text_of(&output.stderr).contains(AWS_KEY));
    assert!(!text_of(&output.stderr).contains(TOKEN));
}

#[test]
fn http_500_degrades_to_explain_failed_after_a_single_attempt() {
    let (_dir, root) = secret_repo();
    let (url, _bodies, count) = stub_server(Respond::Fixed(500, "{}"));
    let output = scan_explained(&root, &url, &["--explain"]);
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "failures are never retried"
    );
    assert_eq!(output.status.code(), Some(1), "exit code is untouched");
    assert_eq!(
        output.stdout,
        scan(&root, &[]).stdout,
        "findings are untouched"
    );
    assert!(advice_lines(&output.stdout).is_empty());
    let stderr = text_of(&output.stderr);
    assert_eq!(
        stderr.matches("explain-failed").count(),
        1,
        "stderr: {stderr}"
    );
}

#[test]
fn malformed_body_degrades_to_explain_invalid() {
    let (_dir, root) = secret_repo();
    let (url, _bodies, _count) = stub_server(Respond::Fixed(200, "not json"));
    let output = scan_explained(&root, &url, &["--explain"]);
    assert_eq!(output.status.code(), Some(1), "exit code is untouched");
    assert_eq!(
        output.stdout,
        scan(&root, &[]).stdout,
        "findings are untouched"
    );
    assert!(advice_lines(&output.stdout).is_empty());
    let stderr = text_of(&output.stderr);
    assert_eq!(
        stderr.matches("explain-invalid").count(),
        1,
        "stderr: {stderr}"
    );
}

#[test]
fn no_http_without_flag_or_under_ci_or_offline() {
    let (_dir, root) = secret_repo();
    let (url, _bodies, count) = stub_server(Respond::Echo);
    for args in [&[][..], &["--ci", "--explain"], &["--offline", "--explain"]] {
        let output = scan_explained(&root, &url, args);
        let plain: Vec<&str> = args
            .iter()
            .filter(|arg| **arg != "--explain")
            .copied()
            .collect();
        let expected = scan(&root, &plain);
        assert_eq!(output.status, expected.status, "args {args:?}");
        assert_eq!(output.stdout, expected.stdout, "args {args:?}");
        assert_eq!(output.stderr, expected.stderr, "args {args:?}");
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "forced-off performs no HTTP"
    );
}

#[test]
fn sibling_secrets_on_one_line_are_all_redacted() {
    let (dir, root) = temp_repo();
    let line = format!("aws_key = \"{AWS_KEY}\" token = {TOKEN}\n");
    write_tracked(&root, "env.example", line.as_bytes());
    let (url, bodies, _count) = stub_server(Respond::Echo);
    let output = scan_explained(&root, &url, &["--explain"]);
    assert_eq!(output.status.code(), Some(1));
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1, "exactly one request per scan");
    let body = text_of(&bodies[0]);
    assert!(
        !body.contains(AWS_KEY) && !body.contains(TOKEN),
        "a sibling secret left the process: {body}"
    );
    assert!(
        body.contains("[REDACTED]"),
        "context still describes findings"
    );
    assert!(!text_of(&output.stdout).contains(AWS_KEY));
    assert!(!text_of(&output.stdout).contains(TOKEN));
    assert!(!text_of(&output.stderr).contains(AWS_KEY));
    assert!(!text_of(&output.stderr).contains(TOKEN));
    drop(dir);
}

#[test]
fn secrets_in_file_and_dir_names_are_redacted() {
    let (dir, root) = temp_repo();
    let subdir = format!("dir-{TOKEN}");
    std::fs::create_dir(root.join(&subdir)).unwrap();
    let name = format!("{subdir}/{AWS_KEY}.txt");
    write_tracked(&root, &name, format!("token = {TOKEN}\n").as_bytes());
    let (url, bodies, _count) = stub_server(Respond::Echo);
    let output = scan_explained(&root, &url, &["--explain"]);
    assert_eq!(output.status.code(), Some(1));
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1, "exactly one request per scan");
    let body = text_of(&bodies[0]);
    assert!(
        !body.contains(AWS_KEY) && !body.contains(TOKEN),
        "a secret in a path left the process: {body}"
    );
    assert!(
        body.contains("[REDACTED].txt"),
        "the redacted path stays useful to a reader: {body}"
    );
    assert!(!text_of(&output.stdout).contains(AWS_KEY));
    assert!(!text_of(&output.stdout).contains(TOKEN));
    assert!(!text_of(&output.stderr).contains(AWS_KEY));
    assert!(!text_of(&output.stderr).contains(TOKEN));
    drop(dir);
}

#[test]
fn userinfo_endpoint_is_refused_without_any_request() {
    let (_dir, root) = secret_repo();
    let (url, _bodies, count) = stub_server(Respond::Echo);
    let port = url
        .strip_prefix("http://127.0.0.1:")
        .unwrap()
        .strip_suffix("/explain")
        .unwrap();
    // The userinfo prefix looks loopback while the authority is not a
    // bare loopback host; the real host here is the stub itself, so an
    // accepted URL would arrive as a request.
    let evil = format!("http://127.0.0.1:9@127.0.0.1:{port}/explain");
    let output = scan_explained(&root, &evil, &["--explain"]);
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "a URL with userinfo must never be requested"
    );
    assert!(advice_lines(&output.stdout).is_empty());
    assert_eq!(output.stdout, scan(&root, &[]).stdout);
    let stderr = text_of(&output.stderr);
    assert_eq!(
        stderr.matches("explain-skipped").count(),
        1,
        "a refused endpoint degrades to explain-skipped: {stderr}"
    );
}

#[test]
fn proxy_environment_is_ignored() {
    let (_dir, root) = secret_repo();
    let (endpoint_url, _endpoint_bodies, endpoint_count) = stub_server(Respond::Echo);
    let (proxy_url, _proxy_bodies, proxy_count) = stub_server(Respond::Echo);
    let proxy_env = [
        ("HTTP_PROXY", proxy_url.as_str()),
        ("HTTPS_PROXY", proxy_url.as_str()),
        ("ALL_PROXY", proxy_url.as_str()),
        ("http_proxy", proxy_url.as_str()),
        ("https_proxy", proxy_url.as_str()),
        ("all_proxy", proxy_url.as_str()),
        ("NO_PROXY", "example.invalid"),
        ("no_proxy", "example.invalid"),
    ];
    let output = scan_explained_with_env(&root, &endpoint_url, &["--explain"], &proxy_env);
    assert_eq!(
        endpoint_count.load(Ordering::SeqCst),
        1,
        "the configured endpoint still receives the single request"
    );
    assert_eq!(
        proxy_count.load(Ordering::SeqCst),
        0,
        "no byte may be tunnelled to the proxy"
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(advice_lines(&output.stdout).len(), 2);
}

#[test]
fn redirect_is_a_failure_without_a_second_request() {
    let (_dir, root) = secret_repo();
    let (target_url, _target_bodies, target_count) = stub_server(Respond::Echo);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let redirect_url = format!(
        "http://127.0.0.1:{}/explain",
        listener.local_addr().unwrap().port()
    );
    let redirect_count = Arc::new(AtomicUsize::new(0));
    let kept = Arc::clone(&redirect_count);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let (method, path, _) = read_request(&mut stream);
            if method != "POST" || path != "/explain" {
                refuse(&mut stream);
                continue;
            }
            kept.fetch_add(1, Ordering::SeqCst);
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    let output = scan_explained(&root, &redirect_url, &["--explain"]);
    assert_eq!(
        redirect_count.load(Ordering::SeqCst),
        1,
        "the single attempt reaches the endpoint"
    );
    assert_eq!(
        target_count.load(Ordering::SeqCst),
        0,
        "the redirect target is never contacted"
    );
    assert_eq!(output.status.code(), Some(1), "exit code is untouched");
    assert_eq!(
        output.stdout,
        scan(&root, &[]).stdout,
        "findings are untouched"
    );
    assert!(advice_lines(&output.stdout).is_empty());
    let stderr = text_of(&output.stderr);
    assert_eq!(
        stderr.matches("explain-failed").count(),
        1,
        "a redirect degrades like any other non-success: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Path-redaction sweep: no secret in a file or directory name may leave the
// process through any exit (terminal, stderr, report files, payloads).
// ---------------------------------------------------------------------------

/// Seeds one OSV cache record at the exact `src/cache.rs` layout under
/// `$XDG_CACHE_HOME/sentinel/...`, mirroring `tests/dependency.rs` so the
/// dependency review answers from cache without touching the network.
fn seed_cache(xdg: &Path, eco: &str, pkg: &str, ver_enc: &str, bytes: &[u8]) {
    let path = xdg
        .join("sentinel")
        .join("osv")
        .join("v1")
        .join(eco)
        .join(pkg)
        .join(format!("{ver_enc}.json"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
}

const SEEDED_ADVISORY: &[u8] = br#"[{"id":"GHSA-SEED1","summary":"seeded advisory","severity":[{"type":"CVSS_V3","score":"9.8"}]}]"#;

/// A manifest pinning a secret as the package name, plus a seeded cache hit
/// for that pin, so the dependency review emits a finding for it.
fn secret_coordinate_repo() -> (TempDir, PathBuf, TempDir) {
    let (dir, root) = temp_repo();
    write_tracked(
        &root,
        "requirements.txt",
        format!("{TOKEN}==1.0.0\n").as_bytes(),
    );
    let xdg = TempDir::new().unwrap();
    seed_cache(
        xdg.path(),
        "PyPI",
        "sk%2Dsynthetic%2D1234567890",
        "1%2E0%2E0",
        SEEDED_ADVISORY,
    );
    (dir, root, xdg)
}

/// A manifest under a secret-bearing directory plus a seeded cache hit, so
/// the dependency review emits one finding deterministically and offline.
fn secret_manifest_repo() -> (TempDir, PathBuf, TempDir) {
    let (dir, root) = temp_repo();
    let rel = format!("deps/{AWS_KEY}/requirements.txt");
    std::fs::create_dir_all(root.join(format!("deps/{AWS_KEY}"))).unwrap();
    write_tracked(&root, &rel, b"flask==2.3.3\n");
    let xdg = TempDir::new().unwrap();
    seed_cache(xdg.path(), "PyPI", "flask", "2%2E3%2E3", SEEDED_ADVISORY);
    (dir, root, xdg)
}

/// Runs the binary with a hermetic OSV cache and no explain configuration.
fn scan_cached(root: &Path, xdg: &TempDir, args: &[&str]) -> Output {
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.arg("scan")
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", root)
        .env("XDG_CACHE_HOME", xdg.path());
    cmd.args(args);
    cmd.output().unwrap()
}

/// Runs the binary pointed at the stub endpoint with a hermetic OSV cache.
fn scan_explained_cached(root: &Path, url: &str, xdg: &TempDir, args: &[&str]) -> Output {
    scan_explained_with_env(
        root,
        url,
        args,
        &[("XDG_CACHE_HOME", xdg.path().to_str().unwrap())],
    )
}

#[test]
fn manifest_path_secret_never_leaves_stdout_stderr_or_payload() {
    let (dir, root, xdg) = secret_manifest_repo();
    let (url, bodies, count) = stub_server(Respond::Echo);
    let output = scan_explained_cached(&root, &url, &xdg, &["--explain", "--output", "json"]);
    let blob = text_of(&output.stdout)
        + &text_of(&output.stderr)
        + &text_of(&bodies.lock().unwrap().concat());
    assert!(!blob.contains(AWS_KEY), "{blob}");
    assert_eq!(count.load(Ordering::SeqCst), 1);
    drop(dir);
}

#[test]
fn skipped_large_path_is_redacted_on_stderr() {
    let (dir, root) = temp_repo();
    let name = format!("{AWS_KEY}.bin");
    let path = root.join(&name);
    std::fs::File::create(&path)
        .unwrap()
        .set_len(10 * 1024 * 1024)
        .unwrap();
    // Discovery enumerates the index (`ls-files`), so staging is what makes the
    // file tracked; a commit would need an identity this helper strips.
    git(&root, ["add", "--", name.as_str()]);
    let output = scan(&root, &[]);
    assert!(
        !text_of(&output.stderr).contains(AWS_KEY),
        "{}",
        text_of(&output.stderr)
    );
    assert!(text_of(&output.stderr).contains("skipped-large"));
    drop(dir);
}

#[test]
fn dependency_finding_path_is_redacted_on_terminal() {
    let (dir, root, xdg) = secret_manifest_repo();
    let output = scan_cached(&root, &xdg, &[]);
    assert_eq!(output.status.code(), Some(1), "the finding still reports");
    let stdout = text_of(&output.stdout);
    let stderr = text_of(&output.stderr);
    assert!(
        !stdout.contains(AWS_KEY) && !stderr.contains(AWS_KEY),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("OSV-GHSA-SEED1"), "stdout: {stdout}");
    assert!(stdout.contains("[REDACTED]"), "stdout: {stdout}");
    drop(dir);
}

#[test]
fn dependency_finding_path_is_redacted_in_sarif() {
    let (dir, root, xdg) = secret_manifest_repo();
    let output = scan_cached(&root, &xdg, &["--output", "sarif"]);
    assert_eq!(output.status.code(), Some(1), "the finding still reports");
    let stdout = text_of(&output.stdout);
    assert!(!stdout.contains(AWS_KEY), "{stdout}");
    assert!(stdout.contains("REDACTED"), "{stdout}");
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    drop(dir);
}

#[test]
fn dependency_finding_path_is_redacted_in_report_file() {
    let (dir, root, xdg) = secret_manifest_repo();
    let output = scan_cached(&root, &xdg, &["--output", "json", "--report", "out.json"]);
    assert_eq!(output.status.code(), Some(1), "the finding still reports");
    assert!(output.stdout.is_empty(), "stdout stays empty with --report");
    let report = text_of(&std::fs::read(root.join("out.json")).unwrap());
    assert!(!report.contains(AWS_KEY), "{report}");
    assert!(report.contains("OSV-GHSA-SEED1"), "{report}");
    assert!(report.contains("[REDACTED]"), "{report}");
    drop(dir);
}

#[test]
fn offline_cache_miss_path_is_redacted_on_stderr() {
    let (dir, root) = temp_repo();
    let rel = format!("deps/{AWS_KEY}/requirements.txt");
    std::fs::create_dir_all(root.join(format!("deps/{AWS_KEY}"))).unwrap();
    write_tracked(&root, &rel, b"flask==2.3.3\n");
    let xdg = TempDir::new().unwrap();
    let output = scan_cached(&root, &xdg, &["--offline"]);
    let stderr = text_of(&output.stderr);
    assert!(stderr.contains("osv-unavailable"), "stderr: {stderr}");
    assert!(!stderr.contains(AWS_KEY), "stderr: {stderr}");
    assert!(stderr.contains("[REDACTED]"), "stderr: {stderr}");
    drop(dir);
}

#[test]
fn manifest_parse_diagnostics_are_redacted_on_stderr() {
    let (dir, root) = temp_repo();
    let subdir = format!("deps/{AWS_KEY}");
    std::fs::create_dir_all(root.join(&subdir)).unwrap();
    write_tracked(
        &root,
        &format!("{subdir}/requirements.txt"),
        b"flask>=2.0\n",
    );
    write_tracked(&root, &format!("{subdir}/package-lock.json"), b"{ invalid");
    let output = scan(&root, &[]);
    let stderr = text_of(&output.stderr);
    assert!(
        stderr.contains("version-unpinned-skipped"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("manifest-parse-failed"), "stderr: {stderr}");
    assert!(!stderr.contains(AWS_KEY), "stderr: {stderr}");
    drop(dir);
}

#[test]
fn corrupt_cache_entry_path_is_redacted_on_stderr() {
    let (dir, root) = temp_repo();
    let rel = format!("deps/{AWS_KEY}/requirements.txt");
    std::fs::create_dir_all(root.join(format!("deps/{AWS_KEY}"))).unwrap();
    write_tracked(&root, &rel, b"flask==2.3.3\n");
    let xdg = TempDir::new().unwrap();
    seed_cache(xdg.path(), "PyPI", "flask", "2%2E3%2E3", b"{ not json");
    let output = scan_cached(&root, &xdg, &["--offline"]);
    let stderr = text_of(&output.stderr);
    assert!(stderr.contains("cache-entry-corrupt"), "stderr: {stderr}");
    assert!(!stderr.contains("osv-unavailable"), "stderr: {stderr}");
    assert!(!stderr.contains(AWS_KEY), "stderr: {stderr}");
    drop(dir);
}

#[test]
fn fatal_error_path_is_redacted_on_stderr() {
    let outer = TempDir::new().unwrap();
    let cwd = outer.path().join(format!("not-a-repo-{AWS_KEY}"));
    std::fs::create_dir_all(&cwd).unwrap();
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.arg("scan")
        .current_dir(&cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", &cwd);
    let output = cmd.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = text_of(&output.stderr);
    assert!(stderr.contains("not inside a git repository"), "{stderr}");
    assert!(!stderr.contains(AWS_KEY), "{stderr}");
}

#[test]
fn usage_error_echoes_no_raw_secret() {
    let (dir, root) = temp_repo();
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.arg("scan")
        .arg(format!("deps/{AWS_KEY}/x"))
        .current_dir(&root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", &root);
    let output = cmd.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = text_of(&output.stderr);
    assert!(!stderr.contains(AWS_KEY), "{stderr}");
    drop(dir);
}

#[test]
fn package_coordinate_secret_never_leaves_the_payload() {
    // A secret used as a package name travels in the dependency finding's
    // snippet and message, past every per-field redaction: only a safety
    // net over the serialized wire body can keep the absolute promise.
    let (dir, root, xdg) = secret_coordinate_repo();
    let (url, bodies, count) = stub_server(Respond::Echo);
    let output = scan_explained_cached(&root, &url, &xdg, &["--explain"]);
    assert_eq!(count.load(Ordering::SeqCst), 1, "one finding, one request");
    assert_eq!(output.status.code(), Some(1), "the findings still report");
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1, "exactly one request per scan");
    let body = text_of(&bodies[0]);
    assert!(
        !body.contains(TOKEN),
        "a raw coordinate left the process: {body}"
    );
    drop(dir);
}

#[test]
fn package_coordinate_secret_is_redacted_on_every_display_surface() {
    // The coordinate travels in the dependency finding's snippet and message,
    // so the display surfaces — terminal, JSON, SARIF, report file — must be
    // proven, not just the payload.
    let (dir, root, xdg) = secret_coordinate_repo();
    for args in [&[][..], &["--output", "json"], &["--output", "sarif"]] {
        let output = scan_cached(&root, &xdg, args);
        assert_eq!(output.status.code(), Some(1), "args {args:?}");
        let blob = text_of(&output.stdout) + &text_of(&output.stderr);
        assert!(!blob.contains(TOKEN), "args {args:?}: {blob}");
        assert!(blob.contains("OSV-GHSA-SEED1"), "args {args:?}: {blob}");
    }
    let output = scan_cached(&root, &xdg, &["--output", "json", "--report", "out.json"]);
    assert!(output.stdout.is_empty(), "stdout stays empty with --report");
    let report = text_of(&std::fs::read(root.join("out.json")).unwrap());
    assert!(!report.contains(TOKEN), "{report}");
    assert!(report.contains("[REDACTED]"), "{report}");
    // Digest and dedupe are untouched: two findings survive with the id's
    // pre-display digest suffix byte for byte.
    let value: serde_json::Value = serde_json::from_str(&report).unwrap();
    let findings = value["findings"].as_array().unwrap().clone();
    assert_eq!(findings.len(), 2, "{report}");
    let dep = findings
        .iter()
        .find(|f| f["rule_id"] == "OSV-GHSA-SEED1")
        .unwrap();
    assert!(
        dep["id"]
            .as_str()
            .unwrap()
            .ends_with("/d9888187af254602e6c0048f38635eff17af6eb62cfbc6695372975eb66fcea2"),
        "{}",
        dep["id"]
    );
    drop(dir);
}

#[test]
fn redacted_payload_keeps_valid_json_shape_the_endpoint_parses() {
    // Redacting a serialized document is only safe if the structure
    // survives: the body must still parse with the same envelope, and the
    // endpoint must still answer one advisory per requested finding.
    let (dir, root, xdg) = secret_manifest_repo();
    let (url, bodies, count) = stub_server(Respond::Echo);
    let output = scan_explained_cached(&root, &url, &xdg, &["--explain"]);
    assert_eq!(count.load(Ordering::SeqCst), 1, "one finding, one request");
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1, "exactly one request per scan");
    let value: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
    let items = value
        .get("findings")
        .and_then(|findings| findings.as_array())
        .unwrap();
    assert!(!items.is_empty(), "the budgeted finding still travels");
    for item in items {
        for key in [
            "id", "rule_id", "severity", "path", "line", "column", "snippet", "message", "evidence",
        ] {
            assert!(item.get(key).is_some(), "entry lost {key}: {item}");
        }
    }
    assert_eq!(advice_lines(&output.stdout).len(), items.len());
    drop(dir);
}

#[test]
fn rule_fallback_path_stays_redacted_on_stderr() {
    let (dir, root) = temp_repo();
    let name = format!("{AWS_KEY}.js");
    write_tracked(&root, &name, b"function broken( {\n");
    let output = scan(&root, &[]);
    let stderr = text_of(&output.stderr);
    assert!(stderr.contains("rule-fallback"), "stderr: {stderr}");
    assert!(!stderr.contains(AWS_KEY), "stderr: {stderr}");
    drop(dir);
}

#[test]
fn outbound_body_never_exceeds_the_byte_cap() {
    // One maximal finding: its entry alone fits the entries-only budget,
    // but entries plus the envelope exceed 4096 bytes on the wire.
    let (dir, root) = temp_repo();
    let line = format!("{} {AWS_KEY}\n", "x".repeat(3780));
    write_tracked(&root, "env.example", line.as_bytes());
    let (url, bodies, _count) = stub_server(Respond::Echo);
    let output = scan_explained(&root, &url, &["--explain"]);
    assert_eq!(output.status.code(), Some(1), "the finding still reports");
    assert!(text_of(&output.stdout).contains("SECRET-aws-access-key"));
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1, "exactly one request per scan");
    assert!(
        bodies[0].len() <= 4096,
        "on-wire body is {} bytes, over the cap",
        bodies[0].len()
    );
    drop(dir);
}
