//! Black-box discovery regression tests (discovery-hardening PR4 / Slice D):
//! hermetic `--ci` isolation, ignore precedence, nested repositories,
//! symlinks, size and unreadable diagnostics, and byte-identical determinism
//! are exercised through the real binary over temporary git repositories
//! built from the committed synthetic discovery fixture corpus
//! (`tests/fixtures/discovery`, audited by `fixture_corpus_is_synthetic_only`).
//!
//! Specs under test: cli-scan (hermetic CI mode, scenarios S13–S15) and
//! git-discovery (untracked/ignore/size/unreadable/determinism requirements).
//! The determinism test runs the scan repeatedly and concurrently and requires
//! byte-identical stdout/stderr plus an unchanged `snapshot_tree` (S11, S12).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::UNIX_EPOCH;

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

/// The two named synthetic values the fixture corpus may contain (task 4.1).
const AWS_KEY: &str = "AKIASYNTHETICKEY1234";
const TOKEN: &str = "sk-synthetic-1234567890";
const TEN_MIB: u64 = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Fixture and repository helpers
// ---------------------------------------------------------------------------

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("discovery")
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

/// Writes bytes into the repository without staging them (untracked).
fn write_untracked(root: &Path, name: &OsStr, contents: &[u8]) {
    let path = Path::new(name);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(root.join(parent)).unwrap();
    }
    std::fs::write(root.join(path), contents).unwrap();
}

/// Tracks a committed discovery fixture into the repository under `repo_rel`.
fn track_fixture(root: &Path, fixture_rel: &str, repo_rel: &str) {
    write_tracked(root, OsStr::new(repo_rel), &fixture_bytes(fixture_rel));
}

/// Commits the staged changes with a hermetic test identity.
fn commit_all(root: &Path, message: &str) {
    git(
        root,
        [
            OsStr::new("-c"),
            OsStr::new("user.name=Sentinel Test"),
            OsStr::new("-c"),
            OsStr::new("user.email=sentinel@test.invalid"),
            OsStr::new("commit"),
            OsStr::new("-qm"),
            OsStr::new(message),
        ],
    );
}

/// The scan binary with a hermetic git environment: no system/global config,
/// no XDG global gitignore, and HOME pointing at the repository, so Local
/// mode has no ambient sources beyond the repository itself. Callers may
/// override cwd, HOME, or GIT_CONFIG_GLOBAL to plant an ambient ignore.
fn scan_bin(cwd: &Path) -> AssertCommand {
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.arg("scan")
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("XDG_CONFIG_HOME", "")
        .env("HOME", cwd);
    cmd
}

/// Spawns a scan process without waiting (for concurrent determinism runs).
fn spawn_scan(cwd: &Path) -> std::process::Child {
    Command::new(assert_cmd::cargo::cargo_bin("sentinel"))
        .arg("scan")
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("XDG_CONFIG_HOME", "")
        .env("HOME", cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A repository with tracked and untracked findings plus a 10 MiB untracked
/// file, so both stdout (findings) and stderr (`skipped-large`) are
/// non-trivial and deterministic.
fn discovery_repo() -> (TempDir, PathBuf) {
    let (dir, root) = temp_repo();
    track_fixture(&root, "secrets/env.example", "env.example");
    track_fixture(&root, "clean/main.rs", "src/main.rs");
    write_untracked(
        &root,
        OsStr::new(".env"),
        format!("token = {TOKEN}\n").as_bytes(),
    );
    let huge = root.join("huge.bin");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(TEN_MIB)
        .unwrap();
    (dir, root)
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
// cli-scan: hermetic CI mode (S13 ambient disabled, S14 local git-natural, S15
// identical findings/exit without ambient differences)
// ---------------------------------------------------------------------------

#[test]
fn ci_mode_scans_files_omitted_by_ambient_global_ignore() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "clean/main.rs", "src/main.rs");
    write_untracked(
        &root,
        OsStr::new("ambient.env"),
        format!("token = {TOKEN}\n").as_bytes(),
    );

    // A planted ambient global gitignore (git `core.excludesFile`) that omits
    // `ambient.env` — the same mechanism a developer machine global gitignore
    // uses.
    let ambient = TempDir::new().unwrap();
    let ignore_file = ambient.path().join("global-ignore");
    std::fs::write(&ignore_file, b"ambient.env\n").unwrap();
    let global_config = ambient.path().join("gitconfig");
    std::fs::write(
        &global_config,
        format!("[core]\n\texcludesfile = {}\n", ignore_file.display()),
    )
    .unwrap();

    // S14: local mode stays git-natural — the ambient global gitignore applies
    // and the file is omitted (exit 0, empty streams).
    let local = scan_bin(&root)
        .env("GIT_CONFIG_GLOBAL", &global_config)
        .env("HOME", ambient.path())
        .output()
        .unwrap();
    assert_eq!(local.status.code(), Some(0), "stderr: {:?}", local.stderr);
    assert!(local.stdout.is_empty(), "stdout: {:?}", local.stdout);
    assert!(local.stderr.is_empty(), "stderr: {:?}", local.stderr);

    // S13: --ci disables ambient sources and scans the file as untracked.
    let ci = scan_bin(&root)
        .arg("--ci")
        .env("GIT_CONFIG_GLOBAL", &global_config)
        .env("HOME", ambient.path())
        .output()
        .unwrap();
    assert_eq!(ci.status.code(), Some(1), "stderr: {:?}", ci.stderr);
    let stdout = text_of(&ci.stdout);
    assert!(stdout.contains("ambient.env:1:"), "stdout: {stdout}");
    assert!(stdout.contains("SECRET-synthetic-token"));
    assert!(!stdout.contains(TOKEN));
}

#[test]
fn local_and_ci_produce_identical_findings_and_exit_without_ambient_ignores() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "secrets/env.example", "env.example");
    track_fixture(&root, "clean/main.rs", "src/main.rs");

    let local = scan_bin(&root).output().unwrap();
    let ci = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(local.status.code(), Some(1));
    assert_eq!(ci.status.code(), Some(1));
    assert_eq!(
        local.stdout, ci.stdout,
        "--ci must not change the findings report"
    );
    assert_eq!(local.stderr, ci.stderr, "--ci must not change diagnostics");
    let stdout = text_of(&local.stdout);
    assert!(stdout.contains("env.example:2:12: critical SECRET-aws-access-key"));
    assert!(stdout.contains("env.example:3:9: medium SECRET-synthetic-token"));
    assert!(!stdout.contains(AWS_KEY) && !stdout.contains(TOKEN));
    assert!(local.stderr.is_empty());
}

// ---------------------------------------------------------------------------
// git-discovery: ignore precedence and regressions (S2–S7, commit state)
// ---------------------------------------------------------------------------

#[test]
fn gitignored_untracked_files_and_directories_are_excluded() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "clean/main.rs", "src/main.rs");
    write_untracked(
        &root,
        OsStr::new(".gitignore"),
        &fixture_bytes("gitignore/basic.txt"),
    );
    write_untracked(
        &root,
        OsStr::new("ignored.env"),
        format!("token = {TOKEN}\n").as_bytes(),
    );
    write_untracked(
        &root,
        OsStr::new("secret-dir/inner.txt"),
        format!("aws_key = \"{AWS_KEY}\"\n").as_bytes(),
    );
    write_untracked(&root, OsStr::new("visible.txt"), b"clean");

    let output = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    assert!(output.stderr.is_empty(), "stderr: {:?}", output.stderr);
}

#[test]
fn force_added_tracked_file_is_retained_despite_gitignore() {
    let (_dir, root) = temp_repo();
    write_untracked(
        &root,
        OsStr::new(".gitignore"),
        &fixture_bytes("gitignore/basic.txt"),
    );
    write_untracked(
        &root,
        OsStr::new("forced.env"),
        format!("token = {TOKEN}\n").as_bytes(),
    );
    git(
        &root,
        [
            OsStr::new("add"),
            OsStr::new("-f"),
            OsStr::new("--"),
            OsStr::new("forced.env"),
        ],
    );

    let output = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = text_of(&output.stdout);
    assert!(stdout.contains("forced.env:1:"), "stdout: {stdout}");
    assert!(stdout.contains("SECRET-synthetic-token"));
    assert!(!stdout.contains(TOKEN));
}

#[test]
fn sentinelignore_excludes_tracked_and_untracked_files() {
    let (_dir, root) = temp_repo();
    write_tracked(
        &root,
        OsStr::new("tracked.secret"),
        format!("token = {TOKEN}\n").as_bytes(),
    );
    write_tracked(&root, OsStr::new("tracked.keep"), b"no secrets");
    write_untracked(
        &root,
        OsStr::new("untracked.secret"),
        format!("aws_key = \"{AWS_KEY}\"\n").as_bytes(),
    );
    write_untracked(&root, OsStr::new("untracked.keep"), b"no secrets");
    write_untracked(
        &root,
        OsStr::new(".sentinelignore"),
        &fixture_bytes("sentinelignore/secret-glob.txt"),
    );

    let output = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    assert!(output.stderr.is_empty(), "stderr: {:?}", output.stderr);
}

#[test]
fn sentinelignore_directory_pattern_excludes_whole_subtree() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "clean/main.rs", "src/main.rs");
    write_tracked(
        &root,
        OsStr::new("build/out.txt"),
        format!("token = {TOKEN}\n").as_bytes(),
    );
    write_untracked(
        &root,
        OsStr::new("build/gen.txt"),
        format!("aws_key = \"{AWS_KEY}\"\n").as_bytes(),
    );
    write_untracked(
        &root,
        OsStr::new(".sentinelignore"),
        &fixture_bytes("sentinelignore/build.txt"),
    );

    let output = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    assert!(output.stderr.is_empty(), "stderr: {:?}", output.stderr);
}

#[test]
fn nested_git_repository_is_skipped() {
    let (_dir, root) = temp_repo();
    write_tracked(&root, OsStr::new("top.txt"), b"clean");
    let nested = root.join("vendor/inner");
    std::fs::create_dir_all(&nested).unwrap();
    git(&nested, ["init", "-q"]);
    write_untracked(
        &nested,
        OsStr::new("inner-secret.env"),
        format!("token = {TOKEN}\n").as_bytes(),
    );

    let output = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    assert!(output.stderr.is_empty(), "stderr: {:?}", output.stderr);
}

#[cfg(unix)]
#[test]
fn symlink_outside_repo_is_not_followed() {
    use std::os::unix::fs::symlink;
    let (_dir, root) = temp_repo();
    write_tracked(&root, OsStr::new("target.txt"), b"clean");
    let outside = TempDir::new().unwrap();
    let outside_secret = outside.path().join("outside-secret.txt");
    std::fs::write(&outside_secret, format!("token = {TOKEN}\n")).unwrap();
    symlink(&outside_secret, root.join("link-out")).unwrap();

    let output = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    assert!(output.stderr.is_empty(), "stderr: {:?}", output.stderr);
}

#[test]
fn untracked_c_like_file_is_scanned_as_a_file() {
    let (_dir, root) = temp_repo();
    write_untracked(
        &root,
        OsStr::new("-C"),
        format!("token = {TOKEN}\n").as_bytes(),
    );

    let output = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = text_of(&output.stdout);
    assert!(
        stdout.contains("-C:1:") && stdout.contains("SECRET-synthetic-token"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains(TOKEN));
}

#[test]
fn empty_index_repo_still_discovers_untracked_secrets() {
    let (_dir, root) = temp_repo(); // initialized, no commits
    write_untracked(
        &root,
        OsStr::new("fresh.env"),
        format!("token = {TOKEN}\n").as_bytes(),
    );

    let output = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = text_of(&output.stdout);
    assert!(stdout.contains("fresh.env:1:"), "stdout: {stdout}");
    assert!(!stdout.contains(TOKEN));
}

#[test]
fn committed_files_are_retained_after_commit_all() {
    let (_dir, root) = temp_repo();
    write_tracked(
        &root,
        OsStr::new("committed.env"),
        format!("token = {TOKEN}\n").as_bytes(),
    );
    commit_all(&root, "initial");

    let output = scan_bin(&root).arg("--ci").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = text_of(&output.stdout);
    assert!(stdout.contains("committed.env:1:"), "stdout: {stdout}");
    assert!(!stdout.contains(TOKEN));
}

// ---------------------------------------------------------------------------
// git-discovery: size guard (S8) and unreadable files (S10)
// ---------------------------------------------------------------------------

#[test]
fn oversized_untracked_file_is_skipped_without_changing_exit() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "secrets/env.example", "env.example");
    let huge = root.join("huge.bin");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(TEN_MIB)
        .unwrap();

    let output = scan_bin(&root).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "the size guard must not change the exit status"
    );
    let stdout = text_of(&output.stdout);
    assert!(
        stdout.contains("env.example:2:12:"),
        "remaining files still scanned: {stdout}"
    );
    assert!(
        !stdout.contains("huge.bin"),
        "oversized file must be excluded: {stdout}"
    );
    let stderr = text_of(&output.stderr);
    assert!(
        stderr.contains("sentinel: skipped-large: huge.bin"),
        "stderr: {stderr}"
    );
}

#[test]
fn oversized_untracked_file_on_clean_repo_exits_zero() {
    let (_dir, root) = temp_repo();
    track_fixture(&root, "clean/main.rs", "src/main.rs");
    let huge = root.join("huge.bin");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(TEN_MIB)
        .unwrap();

    let output = scan_bin(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let stderr = text_of(&output.stderr);
    assert!(
        stderr.contains("sentinel: skipped-large: huge.bin"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn unreadable_untracked_file_warns_and_scan_continues() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        eprintln!("skipping unreadable-file test: running as root");
        return;
    }
    let (_dir, root) = temp_repo();
    track_fixture(&root, "secrets/env.example", "env.example");
    write_untracked(
        &root,
        OsStr::new("locked.env"),
        format!("token = {TOKEN}\n").as_bytes(),
    );
    let locked = root.join("locked.env");
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
        !stdout.contains("locked.env"),
        "unreadable file must be skipped: {stdout}"
    );
    let stderr = text_of(&output.stderr);
    assert!(
        stderr.contains("sentinel: read-failed: locked.env"),
        "stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// git-discovery: repeated + concurrent determinism (S11, S12)
// ---------------------------------------------------------------------------

#[test]
fn repeated_and_concurrent_runs_are_byte_identical() {
    let (_dir, root) = discovery_repo();
    let before = snapshot_tree(&root);

    let first = scan_bin(&root).output().unwrap();
    let second = scan_bin(&root).output().unwrap();
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(second.status.code(), first.status.code());
    assert_eq!(
        first.stdout, second.stdout,
        "repeated stdout must be byte-identical"
    );
    assert_eq!(
        first.stderr, second.stderr,
        "repeated stderr must be byte-identical"
    );

    let concurrent: Vec<_> = (0..2).map(|_| spawn_scan(&root)).collect();
    let results: Vec<_> = concurrent
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    assert_eq!(results[0].status.code(), Some(1));
    assert_eq!(results[1].status.code(), results[0].status.code());
    assert_eq!(
        results[0].stdout, results[1].stdout,
        "concurrent stdout must be byte-identical"
    );
    assert_eq!(
        results[0].stderr, results[1].stderr,
        "concurrent stderr must be byte-identical"
    );
    assert_eq!(
        results[0].stdout, first.stdout,
        "concurrent runs must match serial output"
    );
    assert_eq!(
        results[0].stderr, first.stderr,
        "concurrent stderr must match serial output"
    );

    let after = snapshot_tree(&root);
    assert_eq!(
        before, after,
        "scan must not write, modify, or create files"
    );
}
