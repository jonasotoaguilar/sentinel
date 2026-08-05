//! Sentinel — a deterministic Git secrets scanner. The public seam is [`run`]:
//! the binary forwards argv, cwd, and locked stdio.

mod cli;
mod discovery;
mod errors;
mod finding;
#[cfg(test)]
mod test_util;

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use cli::Command;

/// Runs the scan pipeline and returns the process exit code. Usage errors and
/// operational failures map to exit 2; a completed scan exits 0. The report is
/// the only stdout content; diagnostics go to stderr.
pub fn run(
    args: &[String],
    cwd: &Path,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cli = match cli::parse(args) {
        Ok(cli) => cli,
        Err(usage) => {
            let _ = write!(stderr, "{usage}");
            return ExitCode::from(errors::EXIT_OPERATIONAL);
        }
    };
    let Command::Scan = cli.command;

    // Detection (the secrets engine) lands in PR3; this increment wires CLI
    // validation and git-backed discovery, so clean and empty scans exit 0
    // and usage/operational failures exit 2.
    match discovery::Git::new().discover(cwd) {
        Ok(_discovered) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(stderr, "sentinel: {error}");
            ExitCode::from(errors::EXIT_OPERATIONAL)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::test_util::{temp_repo, write_tracked};
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::ExitCode;
    use tempfile::TempDir;

    fn run_scan(args: &[&str], cwd: &Path) -> (ExitCode, Vec<u8>, Vec<u8>) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        (run(&args, cwd, &mut out, &mut err), out, err)
    }

    #[test]
    fn clean_and_empty_repos_exit_zero_with_empty_streams() {
        for tracked in [Some(("ok.txt", "no secrets here")), None] {
            let (_dir, root) = temp_repo();
            if let Some((name, contents)) = tracked {
                write_tracked(&root, OsStr::new(name), contents.as_bytes());
            }
            let (code, out, err) = run_scan(&["scan"], &root);
            assert_eq!(code, ExitCode::SUCCESS);
            assert!(out.is_empty());
            assert!(err.is_empty());
        }
    }

    #[test]
    fn non_repo_exits_two_with_stderr_diagnostic() {
        let dir = TempDir::new().unwrap();

        let (code, out, err) = run_scan(&["scan"], dir.path());
        assert_eq!(code, ExitCode::from(2));
        assert!(out.is_empty());
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("not inside a git repository")
        );
    }

    #[test]
    fn invalid_cwd_exits_two() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("gone");

        let (code, out, err) = run_scan(&["scan"], &missing);
        assert_eq!(code, ExitCode::from(2));
        assert!(out.is_empty());
        assert!(!err.is_empty());
    }

    #[test]
    fn unsupported_flag_writes_usage_to_stderr_and_exits_two() {
        for args in [
            &["scan", "--explain"][..],
            &["scan", "--output", "json"],
            &["scan", "--ci"],
            &["scan", "file.txt"],
            &["scan", "--help"],
            &["scan", "--version"],
        ] {
            let (code, out, err) = run_scan(args, Path::new("."));
            assert_eq!(code, ExitCode::from(2), "args {args:?}");
            assert!(out.is_empty(), "stdout must stay empty for {args:?}");
            assert!(
                String::from_utf8(err)
                    .unwrap()
                    .contains("unexpected argument"),
                "args {args:?}"
            );
        }
    }

    #[test]
    fn missing_subcommand_writes_usage_to_stderr_and_exits_two() {
        let (code, out, err) = run_scan(&[], Path::new("."));
        assert_eq!(code, ExitCode::from(2));
        assert!(out.is_empty());
        assert!(String::from_utf8(err).unwrap().contains("Usage"));
    }
}
