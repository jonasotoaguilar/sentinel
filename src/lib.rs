//! Sentinel — a deterministic Git secrets scanner. The public seam is [`run`]:
//! the binary forwards argv, cwd, and locked stdio.

mod cli;
mod discovery;
mod engine;
mod errors;
mod finding;
mod normalize;
mod render;
#[cfg(test)]
mod test_util;

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use rayon::prelude::*;

use cli::{Command, OutputFormat};
use discovery::Discovered;
use engine::secrets::SecretsEngine;
use finding::Diagnostic;

/// Runs the scan pipeline and returns the process exit code. Usage errors and
/// operational failures map to exit 2; a completed scan exits 1 with findings
/// and 0 otherwise. The report is the only stdout content; diagnostics go to
/// stderr.
pub fn run(
    args: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    run_inner(&SecretsEngine::new(), args, cwd, stdout, stderr)
}

/// The pipeline over an explicit engine; tests inject engines containing a
/// failing rule (task 3.3). Reads and detection run in parallel and are
/// collected in file order; normalization sorts by (fingerprint, path, line).
fn run_inner(
    engine: &SecretsEngine,
    args: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cli = match cli::parse(args) {
        Ok(cli) => cli,
        Err(usage) => {
            let _ = write!(stderr, "{usage}");
            return ExitCode::from(errors::EXIT_OPERATIONAL);
        }
    };
    let Command::Scan { ci, output, report } = cli.command;
    let mode = if ci {
        discovery::Mode::Ci
    } else {
        discovery::Mode::Local
    };

    let discovered = match discovery::Git::new().discover(cwd, mode) {
        Ok(discovered) => discovered,
        Err(error) => {
            let _ = writeln!(stderr, "sentinel: {error}");
            return ExitCode::from(errors::EXIT_OPERATIONAL);
        }
    };
    let Discovered {
        root,
        files,
        diagnostics: discovery_diagnostics,
    } = discovered;

    // Engine-local rule failures warn once and never abort the scan;
    // discovery diagnostics (skipped-large, walk-failed, invalid-path, ...)
    // merge before the deterministic renderer.
    let mut diagnostics = engine.init_diagnostics().to_vec();
    diagnostics.extend(discovery_diagnostics);

    let scans = files
        .par_iter()
        .map(|path| {
            let path_text = path.to_string_lossy().replace('\\', "/");
            let bytes = std::fs::read(root.join(path))
                .map_err(|error| Diagnostic::read_failed(&path_text, &error))?;
            Ok((path_text, engine.scan(&bytes)))
        })
        .collect::<Vec<_>>();

    let mut findings = Vec::new();
    for scan in scans {
        match scan {
            Ok((path, candidates)) => findings.extend(normalize::to_findings(&path, candidates)),
            Err(diagnostic) => diagnostics.push(diagnostic),
        }
    }
    let findings = normalize::dedupe_and_sort(findings);

    let _ = stderr.write_all(&render::render_diagnostics(&diagnostics));

    // Report formats render first, then write to stdout or the requested file.
    let report_bytes = match output {
        OutputFormat::Terminal => render::render_findings(&findings),
        OutputFormat::Json | OutputFormat::Sarif => {
            let rendered = match output {
                OutputFormat::Json => render::render_json(&findings),
                OutputFormat::Sarif => render::render_sarif(&findings),
                OutputFormat::Terminal => unreachable!(),
            };
            match rendered {
                Ok(bytes) => bytes,
                Err(error) => {
                    let _ = writeln!(stderr, "sentinel: cannot render scan report: {error}");
                    return ExitCode::from(errors::EXIT_OPERATIONAL);
                }
            }
        }
    };

    let written = match report.as_deref().map(|path| cwd.join(path)) {
        Some(path) => std::fs::write(path, &report_bytes),
        None => stdout.write_all(&report_bytes),
    };
    if let Err(error) = written {
        let _ = writeln!(stderr, "sentinel: cannot write scan report: {error}");
        return ExitCode::from(errors::EXIT_OPERATIONAL);
    }

    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::{run, run_inner};
    use crate::engine::secrets::{RuleSpec, SecretsEngine};
    use crate::finding::Severity;
    use crate::test_util::{temp_repo, write_tracked, write_untracked};
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use tempfile::TempDir;

    const AWS_KEY: &str = "AKIASYNTHETICKEY1234";
    const SYNTHETIC_TOKEN: &str = "sk-synthetic-1234567890";

    fn run_scan(args: &[&str], cwd: &Path) -> (ExitCode, Vec<u8>, Vec<u8>) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        (run(&args, cwd, &mut out, &mut err), out, err)
    }

    fn secret_repo() -> (TempDir, PathBuf) {
        let (dir, root) = temp_repo();
        let contents = format!("aws_key = \"{AWS_KEY}\"\ntoken = {SYNTHETIC_TOKEN}\n");
        write_tracked(&root, OsStr::new("env.example"), contents.as_bytes());
        (dir, root)
    }

    /// A writer whose `write` always fails, for the broken-stdout path.
    struct FailWriter;

    impl std::io::Write for FailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic write failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// An engine whose first rule cannot compile; the remaining rules fire.
    fn broken_rule_engine() -> SecretsEngine {
        let broken = RuleSpec {
            id: "SECRET-broken",
            deprecated_ids: &[],
            severity: Severity::High,
            message: "broken rule",
            pattern: "[",
        };
        SecretsEngine::from_specs(&[broken, crate::engine::secrets::RULE_SPECS[0]])
    }

    #[test]
    fn synthetic_secrets_render_redacted_stdout_and_exit_one() {
        let (_dir, root) = secret_repo();
        let (code, out, err) = run_scan(&["scan"], &root);
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        let err_text = String::from_utf8(err).unwrap();
        let ids = ["SECRET-aws-access-key", "SECRET-synthetic-token"];
        assert!(ids.iter().all(|id| out_text.contains(id)));
        assert!(out_text.contains("[REDACTED]") && !out_text.contains('\u{1b}'));
        assert!(!out_text.contains(AWS_KEY) && !out_text.contains(SYNTHETIC_TOKEN));
        assert!(!err_text.contains(AWS_KEY) && !err_text.contains(SYNTHETIC_TOKEN));
    }

    #[test]
    fn failing_rule_diagnostic_stays_on_stderr_and_out_of_the_report_file() {
        let (_dir, root) = secret_repo();
        let report = root.join("out.json");
        let args: Vec<String> = ["scan", "--output", "json", "--report", "out.json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_inner(&broken_rule_engine(), &args, &root, &mut out, &mut err);
        assert_eq!(code, ExitCode::from(1));
        assert!(out.is_empty(), "stdout stays empty with --report");
        let err_text = String::from_utf8(err).unwrap();
        assert!(err_text.contains("rule-failed") && err_text.contains("SECRET-broken"));
        let report_text = String::from_utf8(std::fs::read(&report).unwrap()).unwrap();
        assert!(
            !report_text.contains("rule-failed"),
            "diagnostic must never enter report bytes"
        );
        assert!(report_text.contains("SECRET-aws-access-key"));
    }

    #[test]
    fn broken_stdout_maps_to_exit_two_with_stderr_diagnostic() {
        let (_dir, root) = secret_repo();
        let args = vec!["scan".to_string()];
        let mut err = Vec::new();
        let code = run(&args, &root, &mut FailWriter, &mut err);
        assert_eq!(code, ExitCode::from(2));
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("cannot write scan report")
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_failure_warns_and_scan_continues() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("unreadable.txt"), b"x");
        let path = root.join("unreadable.txt");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&path).is_ok() {
            return; // root may still read the file
        }
        let (code, out, err) = run_scan(&["scan"], &root);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(out.is_empty());
        assert!(String::from_utf8(err).unwrap().contains("read-failed"));
    }

    #[test]
    fn clean_and_empty_repos_exit_zero_with_empty_streams() {
        for tracked in [Some(("ok.txt", b"no secrets here")), None] {
            let (_dir, root) = temp_repo();
            if let Some((name, contents)) = tracked {
                write_tracked(&root, OsStr::new(name), contents);
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
    fn ci_flag_is_accepted_and_runs_the_pipeline() {
        let (_dir, root) = temp_repo();
        let (code, out, err) = run_scan(&["scan", "--ci"], &root);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[test]
    fn untracked_secret_is_scanned_locally_and_under_ci() {
        for args in [&["scan"][..], &["scan", "--ci"]] {
            let (_dir, root) = temp_repo();
            write_tracked(&root, OsStr::new("clean.txt"), b"no secrets");
            write_untracked(
                &root,
                OsStr::new(".env"),
                b"token = sk-synthetic-1234567890\n",
            );

            let (code, out, err) = run_scan(args, &root);
            assert_eq!(code, ExitCode::from(1), "args {args:?}");
            let out_text = String::from_utf8(out).unwrap();
            let err_text = String::from_utf8(err).unwrap();
            assert!(out_text.contains(".env:1:"), "args {args:?}: {out_text}");
            assert!(out_text.contains("SECRET-synthetic-token"));
            assert!(!out_text.contains(SYNTHETIC_TOKEN));
            assert!(!err_text.contains(SYNTHETIC_TOKEN));
        }
    }

    #[test]
    fn oversized_untracked_file_warns_without_changing_exit() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("clean.txt"), b"no secrets");
        let big = root.join("big.bin");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(10 * 1024 * 1024)
            .unwrap();

        let (code, out, err) = run_scan(&["scan"], &root);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(out.is_empty());
        let err_text = String::from_utf8(err).unwrap();
        assert!(
            err_text.contains("sentinel: skipped-large: big.bin"),
            "stderr: {err_text}"
        );
    }

    #[test]
    fn missing_subcommand_writes_usage_to_stderr_and_exits_two() {
        let (code, out, err) = run_scan(&[], Path::new("."));
        assert_eq!(code, ExitCode::from(2));
        assert!(out.is_empty());
        assert!(String::from_utf8(err).unwrap().contains("Usage"));
    }
}
