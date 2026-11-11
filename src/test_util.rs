//! Test-only helpers: isolated temporary git repositories. Compiled only in
//! test builds (integration tests exercise the built binary).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Creates a temp git repository with a hermetic config environment
/// (no system/global config, no user home) and returns it with its root.
pub fn temp_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    // Canonicalised because that is the path git reports back: on macOS the
    // temporary directory lives under /var, which is a symlink to /private/var,
    // so a test comparing the discovered root against the raw temporary path
    // fails on macOS and passes everywhere else. The TempDir keeps the original
    // path for cleanup.
    let root = dir.path().canonicalize().unwrap();
    git(&root, ["init", "-q"]);
    (dir, root)
}

/// Writes a file into the repository and stages it as a tracked file.
pub fn write_tracked(root: &Path, name: &OsStr, contents: &[u8]) {
    let path = root.join(name);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, contents).unwrap();
    git(root, [OsStr::new("add"), OsStr::new("--"), name]);
}

/// Writes a file into the repository without staging it (untracked).
pub fn write_untracked(root: &Path, name: &OsStr, contents: &[u8]) {
    let path = root.join(name);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, contents).unwrap();
}

/// Commits the staged changes with a hermetic test identity.
pub fn commit_all(root: &Path, message: &str) {
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

/// Runs git inside `cwd` with a hermetic config environment. Path-like
/// arguments are passed as `OsStr` so option-looking names stay verbatim.
pub fn git<I, S>(cwd: &Path, args: I)
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
