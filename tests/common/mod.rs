//! Shared helpers for the integration test targets (`tests/*.rs`).
//!
//! Pattern: each target declares `mod common;` and imports only what it
//! uses. Cargo compiles every `tests/*.rs` file as its own crate, so `mod
//! common;` resolves here once per target: no new dependency, no public
//! library module (test helpers must not widen the shipped API, and
//! `#[cfg(test)]` items in `src/` are unreachable from integration targets).
//!
//! Scope is the intersection every including target uses: a helper only
//! some targets need would be dead code in the rest, which fails `clippy
//! -- -D warnings` with no `#[allow]` permitted. Helpers with divergent
//! roots, environments or signatures stay per-file; `completions.rs` keeps
//! its own `text_of` for the same reason (its only shared helper).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

/// The two named synthetic values the fixture corpus may contain.
pub const AWS_KEY: &str = "AKIASYNTHETICKEY1234";
/// The two named synthetic values the fixture corpus may contain.
pub const TOKEN: &str = "sk-synthetic-1234567890";

/// Runs git inside `cwd` with a hermetic config environment (no system/global
/// config, no user home), mirroring the unit-test helper.
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

/// Creates an empty temp git repository (initialized, no commits).
pub fn temp_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    git(&root, ["init", "-q"]);
    (dir, root)
}

pub fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
