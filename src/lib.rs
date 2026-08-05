//! Sentinel — a deterministic Git secrets scanner. Bootstrap public seam: the
//! binary forwards argv, cwd, and locked stdio; the pipeline placeholder
//! exits cleanly until CLI and discovery wiring land in PR2.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// Runs the scan pipeline and returns the process exit code. Bootstrap state:
/// every invocation exits cleanly with no output.
pub fn run(
    _args: &[String],
    _cwd: &Path,
    _stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> ExitCode {
    ExitCode::SUCCESS
}
