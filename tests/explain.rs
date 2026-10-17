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
use std::time::{Duration, Instant};

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

const AWS_KEY: &str = "AKIASYNTHETICKEY1234";
const TOKEN: &str = "sk-synthetic-1234567890";

/// Recorded traffic of one stub endpoint: its URL, request bodies, and the
/// accepted-connection count (the single-attempt evidence).
type Recorded = (String, Arc<Mutex<Vec<Vec<u8>>>>, Arc<AtomicUsize>);

/// What the stub endpoint answers every request with.
enum Respond {
    /// One `{"id", "text"}` entry per requested finding id.
    Echo,
    /// A fixed status code and body.
    Fixed(u16, &'static str),
    /// Accept the request, then stall past the client timeout.
    Stall,
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
            kept_count.fetch_add(1, Ordering::SeqCst);
            let body = read_body(&mut stream);
            kept_bodies.lock().unwrap().push(body.clone());
            if matches!(mode, Respond::Stall) {
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }
            let (status, text) = match &mode {
                Respond::Echo => (200, echo_advisories(&body)),
                Respond::Fixed(status, text) => (*status, (*text).to_string()),
                Respond::Stall => unreachable!("handled above"),
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

/// Reads one HTTP/1.1 request head plus its `Content-Length` body.
fn read_body(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 65536 {
        let Ok(1) = stream.read(&mut byte) else { break };
        head.push(byte[0]);
    }
    let length = String::from_utf8_lossy(&head)
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
    body
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
    std::thread::sleep(std::time::Duration::from_millis(100));
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
fn stalled_endpoint_is_bounded_by_the_ten_second_timeout() {
    let (_dir, root) = secret_repo();
    let (url, _bodies, count) = stub_server(Respond::Stall);
    let started = Instant::now();
    let output = scan_explained(&root, &url, &["--explain"]);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(10),
        "the full timeout runs: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(25),
        "the stall is bounded: {elapsed:?}"
    );
    assert_eq!(output.status.code(), Some(1), "exit code is untouched");
    assert_eq!(
        output.stdout,
        scan(&root, &[]).stdout,
        "findings are untouched"
    );
    let stderr = text_of(&output.stderr);
    assert_eq!(
        stderr.matches("explain-failed").count(),
        1,
        "stderr: {stderr}"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "timeouts are never retried"
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
    std::thread::sleep(std::time::Duration::from_millis(100));
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
    std::thread::sleep(std::time::Duration::from_millis(200));
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
    std::thread::sleep(std::time::Duration::from_millis(200));
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
            kept.fetch_add(1, Ordering::SeqCst);
            let _ = read_body(&mut stream);
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    let output = scan_explained(&root, &redirect_url, &["--explain"]);
    std::thread::sleep(std::time::Duration::from_millis(200));
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
