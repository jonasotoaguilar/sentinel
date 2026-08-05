//! Typed operational errors and the CLI exit-code contract.
//!
//! `thiserror` owns the domain error types (design: "thiserror 0/1/2");
//! `anyhow` is reserved for binary-orchestration context. Every variant maps
//! to exit code 2 (operational failure) per the cli-scan spec. Messages never
//! embed run-derived data such as timestamps or git's stderr, so diagnostics
//! stay byte-identical across runs.

use std::io;
use std::path::PathBuf;

/// Exit code for operational failures: usage errors, invalid cwd, git
/// missing, or not a repository. Findings (1) and clean scans (0) are
/// returned as `ExitCode::SUCCESS` / `ExitCode::from(1)` by `crate::run`
/// once the secrets engine lands (PR3).
pub const EXIT_OPERATIONAL: u8 = 2;

/// Hard failures that abort the scan. All variants are deterministic.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The working directory does not exist or is not a directory.
    #[error("working directory is not a directory: {path}")]
    InvalidWorkingDirectory { path: PathBuf },

    /// The git executable could not be found or run.
    #[error("git is required but could not be run: {program}")]
    GitUnavailable { program: String },

    /// The working directory is not inside a git repository.
    #[error("not inside a git repository: {path}")]
    NotARepository { path: PathBuf },

    /// A git invocation exited unsuccessfully.
    #[error("git {command} failed with exit status {status}")]
    GitCommandFailed { command: String, status: i32 },

    /// A git invocation could not be spawned for a non-NotFound reason.
    #[error("cannot run git {command}: {source}")]
    GitSpawnFailed { command: String, source: io::Error },

    /// A git invocation succeeded but produced output that cannot be
    /// interpreted (e.g. an empty `--show-toplevel` for a bare repository).
    #[error("git {command} produced invalid output: {reason}")]
    InvalidGitOutput { command: String, reason: String },
}
