//! Black-box integration tests (PR4): the CLI surface, git discovery, stream
//! separation, redaction, and determinism are exercised over temporary git
//! repositories built from the committed synthetic fixture corpus
//! (`tests/fixtures`, audited by `fixture_corpus_is_synthetic_only`).
//!
//! Specs under test: cli-scan (command surface, exit codes, hermetic/read
//! boundary), git-discovery (nested cwd, NUL-safe names, git missing), and
//! terminal-rendering (stdout/stderr contract, redacted output, byte-identical
//! repeated runs). The golden test compares one Rayon thread against several
//! and requires byte-identical stdout.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::UNIX_EPOCH;

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

use sentinel::run as scan_seam;

/// The two named synthetic values the fixture corpus may contain. The audit
/// test below fails on any other secret-like token (task 4.1).
const AWS_KEY: &str = "AKIASYNTHETICKEY1234";
const TOKEN: &str = "sk-synthetic-1234567890";

// ---------------------------------------------------------------------------
// Fixture and repository helpers
// ---------------------------------------------------------------------------

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn fixture_bytes(rel: &str) -> Vec<u8> {
    std::fs::read(fixture_root().join(rel))
        .unwrap_or_else(|error| panic!("cannot read fixture {rel}: {error}"))
}

/// Runs git inside `cwd` with a hermetic config environment (no system/global
/// config, no user home), mirroring the unit-test helper.
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

/// Creates an empty temp git repository (initialized, no commits).
fn temp_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    git(&root, ["init", "-q"]);
    (dir, root)
}

/// Writes bytes into the repository and stages them as a tracked file.
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

/// Tracks a committed fixture into the repository under `repo_rel`.
fn track_fixture(root: &Path, fixture_rel: &str, repo_rel: &str) {
    write_tracked(root, OsStr::new(repo_rel), &fixture_bytes(fixture_rel));
}

/// A repository over the three-file golden corpus (`tests/fixtures/golden/`):
/// two files with findings plus one clean file.
fn golden_repo() -> (TempDir, PathBuf) {
    let (dir, root) = temp_repo();
    track_fixture(&root, "golden/config.env", "config.env");
    track_fixture(&root, "golden/settings/app.conf", "settings/app.conf");
    track_fixture(&root, "golden/doc/README.md", "doc/README.md");
    (dir, root)
}

/// The scan binary with a hermetic git environment; callers may override
/// cwd, HOME, or PATH.
fn scan_bin(cwd: &Path) -> AssertCommand {
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.arg("scan")
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", cwd);
    cmd
}

/// Runs the scan pipeline in-process over `cwd`; returns (exit, stdout,
/// stderr) without spawning a process.
fn scan_seam_in(args: &[&str], cwd: &Path) -> (ExitCode, Vec<u8>, Vec<u8>) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    (
        scan_seam(&args, cwd, &mut stdout, &mut stderr),
        stdout,
        stderr,
    )
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Recursively lists files under `root`, sorted for deterministic traversal.
fn walk_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), files);
            } else {
                files.push(entry.path());
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &mut files);
    files.sort();
    files
}

/// (path, len, mtime-nanos) for every entry under `root` — the read-boundary
/// snapshot (cli-scan spec: paths and mtimes unchanged after a scan).
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

/// Root bypasses permission bits; a write probe into a 0o555 directory tells
/// us whether the chmod-based tests are meaningful on this host.
#[cfg(unix)]
fn running_as_root() -> bool {
    use std::os::unix::fs::PermissionsExt;
    let probe = TempDir::new().unwrap();
    std::fs::set_permissions(probe.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    std::fs::write(probe.path().join("probe"), b"x").is_ok()
}

// ---------------------------------------------------------------------------
// cli-scan: command surface, exit codes, hermetic/read boundary
// ---------------------------------------------------------------------------

#[test]
fn unsupported_arguments_and_missing_subcommand_write_stderr_only_and_exit_2() {
    let dir = TempDir::new().unwrap(); // not a repository: usage fails before discovery
    for args in [
        Vec::new(),
        vec!["--explain"],
        vec!["scan", "--explain"],
        vec!["scan", "--output", "json"],
        vec!["scan", "--ci"],
        vec!["scan", "file.txt"],
    ] {
        let (code, stdout, stderr) = scan_seam_in(&args, dir.path());
        assert_eq!(code, ExitCode::from(2), "args {args:?}");
        assert!(stdout.is_empty(), "args {args:?}: stdout must stay empty");
        assert!(
            !stderr.is_empty(),
            "args {args:?}: stderr must carry the usage error"
        );
    }
}

#[test]
fn binary_writes_usage_error_to_stderr_with_empty_stdout_and_exit_2() {
    let dir = TempDir::new().unwrap();
    let output = scan_bin(dir.path())
        .arg("scan")
        .arg("--explain")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(text_of(&output.stderr).contains("unexpected argument"));
}

#[test]
fn clean_repo_exits_zero_with_empty_stdout_and_stderr() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "clean/README.md", "README.md");
    let output = scan_bin(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn empty_repo_exits_zero_with_no_output() {
    let (_dir, root) = temp_repo(); // initialized, no commits, nothing tracked
    let output = scan_bin(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn findings_exit_one_with_redacted_report() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "basic/env.example", "env.example");
    let output = scan_bin(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = text_of(&output.stdout);
    assert!(
        stdout.contains(
            "env.example:2:12: critical SECRET-aws-access-key: AWS access key ID detected"
        )
    );
    assert!(stdout.contains(
        "env.example:3:9: medium SECRET-synthetic-token: synthetic secret token detected"
    ));
    assert!(stdout.contains("  aws_key = \"[REDACTED]\""));
    assert!(stdout.contains("  evidence: [REDACTED]"));
    assert!(
        output.stderr.is_empty(),
        "no diagnostics expected: {:?}",
        output.stderr
    );
    // Redaction at the process boundary: raw values appear in neither stream.
    assert!(!text_of(&output.stdout).contains(AWS_KEY));
    assert!(!text_of(&output.stdout).contains(TOKEN));
    assert!(!text_of(&output.stderr).contains(AWS_KEY));
    assert!(!text_of(&output.stderr).contains(TOKEN));
}

#[test]
fn nested_cwd_scans_the_enclosing_repository_with_root_relative_paths() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "basic/env.example", "env.example");
    let nested = root.join("nested").join("sub");
    std::fs::create_dir_all(&nested).unwrap();
    let output = scan_bin(&nested).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = text_of(&output.stdout);
    assert!(
        stdout.contains("env.example:2:12:"),
        "paths must be root-relative: {stdout}"
    );
    assert!(
        !stdout.contains("nested"),
        "path must not leak the nested cwd: {stdout}"
    );
}

#[test]
fn not_a_repo_exits_two_with_a_stderr_diagnostic() {
    let dir = TempDir::new().unwrap();
    let output = scan_bin(dir.path()).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(text_of(&output.stderr).contains("not inside a git repository"));
}

#[test]
fn git_missing_on_path_exits_two_with_a_stderr_diagnostic() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "basic/env.example", "env.example");
    let empty_path = TempDir::new().unwrap(); // a PATH directory containing no git
    let output = scan_bin(&root)
        .env("PATH", empty_path.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(text_of(&output.stderr).contains("git is required"));
}

#[cfg(unix)]
#[test]
fn unreadable_tracked_file_warns_on_stderr_and_scan_continues() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        eprintln!("skipping unreadable-file test: running as root");
        return;
    }
    let (_dir, root) = temp_repo();
    track_fixture(&root, "basic/env.example", "env.example");
    let contents = format!("token = {TOKEN}\n");
    write_tracked(&root, OsStr::new("locked.conf"), contents.as_bytes());
    let locked = root.join("locked.conf");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let output = scan_bin(&root).output().unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "scan must complete despite the read failure"
    );
    let stdout = text_of(&output.stdout);
    assert!(
        stdout.contains("env.example:2:12:"),
        "remaining files still scanned: {stdout}"
    );
    assert!(
        !stdout.contains("sentinel:"),
        "diagnostics must not leak into stdout: {stdout}"
    );
    let stderr = text_of(&output.stderr);
    assert!(
        stderr.contains("sentinel: read-failed: locked.conf"),
        "stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// git-discovery: NUL-safe names, repeated determinism
// ---------------------------------------------------------------------------

#[test]
fn file_names_with_spaces_and_newlines_are_preserved_byte_exact() {
    let (_dir, root) = temp_repo();
    let spaced = format!("token = {TOKEN}\n");
    write_tracked(&root, OsStr::new("name with spaces.txt"), spaced.as_bytes());
    let newlined = format!("token = {TOKEN}\n");
    write_tracked(&root, OsStr::new("line\nbreak.txt"), newlined.as_bytes());
    let output = scan_bin(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = text_of(&output.stdout);
    assert!(stdout.contains("name with spaces.txt:1:9: medium SECRET-synthetic-token"));
    assert!(stdout.contains("line\nbreak.txt:1:9: medium SECRET-synthetic-token"));
}

#[test]
fn repeated_binary_runs_are_byte_identical() {
    let (_dir, root) = golden_repo();
    let first = scan_bin(&root).output().unwrap();
    let second = scan_bin(&root).output().unwrap();
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(second.status.code(), first.status.code());
    assert_eq!(
        first.stdout, second.stdout,
        "stdout must be byte-identical across runs"
    );
    assert_eq!(
        first.stderr, second.stderr,
        "stderr must be byte-identical across runs"
    );
}

// ---------------------------------------------------------------------------
// terminal-rendering: goldens, 1-vs-N threads, hermetic read boundary
// ---------------------------------------------------------------------------

#[test]
fn golden_output_is_identical_for_one_and_multiple_rayon_threads() {
    let (_dir, root) = golden_repo();
    let single = scan_bin(&root)
        .env("RAYON_NUM_THREADS", "1")
        .output()
        .unwrap();
    let multi = scan_bin(&root)
        .env("RAYON_NUM_THREADS", "4")
        .output()
        .unwrap();
    assert_eq!(single.status.code(), Some(1));
    assert_eq!(multi.status.code(), Some(1));
    assert_eq!(
        single.stdout, multi.stdout,
        "scheduling (1 vs N threads) must never control output"
    );
    assert!(single.stderr.is_empty() && multi.stderr.is_empty());
    insta::assert_snapshot!("golden_corpus_scan", text_of(&multi.stdout));
}

#[cfg(unix)]
#[test]
fn read_only_home_yields_identical_output() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        eprintln!("skipping read-only-home test: running as root");
        return;
    }
    let (_dir, root) = golden_repo();
    let control = scan_bin(&root).output().unwrap();
    let ro_home = TempDir::new().unwrap();
    std::fs::set_permissions(ro_home.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let isolated = scan_bin(&root)
        .env("HOME", ro_home.path())
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), control.status.code());
    assert_eq!(isolated.stdout, control.stdout);
    assert_eq!(isolated.stderr, control.stderr);
}

#[test]
fn scan_leaves_repo_paths_and_mtimes_unchanged() {
    let (_dir, root) = golden_repo();
    let before = snapshot_tree(&root);
    let output = scan_bin(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let after = snapshot_tree(&root);
    assert_eq!(
        before, after,
        "scan must not write, modify, or create files"
    );
}

// ---------------------------------------------------------------------------
// Fixture corpus audit (task 4.1; secrets-detection "Fixture corpus is
// synthetic"): every committed fixture carries the synthetic banner and may
// contain only the two named synthetic tokens; any other secret-like value
// fails loudly with the offending file and token.
// ---------------------------------------------------------------------------

#[test]
fn fixture_corpus_is_synthetic_only() {
    let mut audited = 0;
    for path in walk_files(&fixture_root()) {
        audited += 1;
        let text = text_of(&std::fs::read(&path).unwrap());
        assert!(
            text.contains("SYNTHETIC FIXTURE"),
            "{}: missing synthetic banner",
            path.display()
        );
        for line in text.lines() {
            assert!(
                !line.contains("PRIVATE KEY"),
                "{}: private-key material is not synthetic: {line:?}",
                path.display()
            );
            if line.contains("AKIA") {
                assert!(
                    line.contains(AWS_KEY),
                    "{}: non-synthetic AWS key shape: {line:?}",
                    path.display()
                );
            }
            if line.contains("sk-") {
                assert!(
                    line.contains(TOKEN),
                    "{}: non-synthetic token shape: {line:?}",
                    path.display()
                );
            }
        }
    }
    assert!(
        audited >= 4,
        "fixture corpus is unexpectedly small ({audited} files)"
    );
}
