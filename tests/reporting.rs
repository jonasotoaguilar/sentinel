//! Black-box integration tests for machine-readable reporting (PR2): SARIF
//! 2.1.0 output validates offline against the pinned official schema fixture,
//! RFC 3986 URI encoding, redaction, run-twice determinism, and reviewable
//! goldens. (Specs: machine-readable-reporting; cli-scan report routing.)

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use tempfile::TempDir;

use sentinel::run as scan_seam;

/// The two named synthetic values the fixture corpus may contain.
const AWS_KEY: &str = "AKIASYNTHETICKEY1234";
const TOKEN: &str = "sk-synthetic-1234567890";

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

fn write_tracked(root: &Path, name: &OsStr, contents: &[u8]) {
    let path = Path::new(name);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(root.join(parent)).unwrap();
    }
    std::fs::write(root.join(path), contents).unwrap();
    git(root, [OsStr::new("add"), OsStr::new("--"), name]);
}

fn track_fixture(root: &Path, fixture_rel: &str, repo_rel: &str) {
    write_tracked(root, OsStr::new(repo_rel), &fixture_bytes(fixture_rel));
}

fn golden_repo() -> (TempDir, PathBuf) {
    let (dir, root) = temp_repo();
    track_fixture(&root, "golden/config.env", "config.env");
    track_fixture(&root, "golden/settings/app.conf", "settings/app.conf");
    track_fixture(&root, "golden/doc/README.md", "doc/README.md");
    (dir, root)
}

fn scan(args: &[&str], cwd: &Path) -> (ExitCode, Vec<u8>, Vec<u8>) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    (scan_seam(&args, cwd, &mut out, &mut err), out, err)
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The pinned official SARIF 2.1.0 schema (Draft 7, self-contained fixture).
fn sarif_schema() -> serde_json::Value {
    serde_json::from_slice(&fixture_bytes("sarif-2.1.0.schema.json")).unwrap()
}

/// Validates `bytes` as a SARIF log against the pinned schema, offline.
fn validate_against_pinned_schema(bytes: &[u8]) -> Result<(), String> {
    let instance: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    jsonschema::draft7::new(&sarif_schema())
        .expect("pinned schema must compile")
        .validate(&instance)
        .map_err(|error| error.to_string())
}

#[test]
fn sarif_output_is_schema_valid_against_pinned_fixture() {
    let (_dir, root) = golden_repo();
    let (code, stdout, stderr) = scan(&["scan", "--output", "sarif"], &root);
    assert_eq!(code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(
        validate_against_pinned_schema(&stdout).is_ok(),
        "SARIF output must validate offline against the pinned schema"
    );
}

#[test]
fn sarif_output_is_schema_valid_for_an_empty_scan() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "clean/README.md", "README.md");
    let (code, stdout, stderr) = scan(&["scan", "--output", "sarif"], &root);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(validate_against_pinned_schema(&stdout).is_ok());
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(report["runs"][0]["results"], serde_json::json!([]));
}

#[test]
fn sarif_uris_are_rfc3986_encoded_and_raw_secrets_absent() {
    let (_dir, root) = temp_repo();
    // Space, '#', '%', and non-ASCII in the tracked path.
    track_fixture(&root, "basic/env.example", "a b#c%d/é.txt");
    let (code, stdout, _) = scan(&["scan", "--output", "sarif"], &root);
    assert_eq!(code, ExitCode::from(1));
    let text = text_of(&stdout);
    assert!(
        text.contains("a%20b%23c%25d/%C3%A9.txt"),
        "path must be RFC 3986 percent-encoded: {text}"
    );
    assert!(!text.contains(AWS_KEY) && !text.contains(TOKEN));
}

#[test]
fn repeated_sarif_runs_are_byte_identical() {
    let (_dir, root) = golden_repo();
    let first = scan(&["scan", "--output", "sarif"], &root);
    let second = scan(&["scan", "--output", "sarif"], &root);
    assert_eq!(first.0, second.0);
    assert_eq!(
        first.1, second.1,
        "sarif bytes must be identical across runs"
    );
    assert_eq!(first.2, second.2);
}

#[test]
fn sarif_golden_matches_reviewable_snapshot() {
    let (_dir, root) = golden_repo();
    let (code, stdout, _) = scan(&["scan", "--output", "sarif"], &root);
    assert_eq!(code, ExitCode::from(1));
    insta::assert_snapshot!("sarif_golden_corpus", text_of(&stdout));
}

#[test]
fn json_golden_matches_reviewable_snapshot() {
    let (_dir, root) = golden_repo();
    let (code, stdout, _) = scan(&["scan", "--output", "json"], &root);
    assert_eq!(code, ExitCode::from(1));
    insta::assert_snapshot!("json_golden_corpus", text_of(&stdout));
}
