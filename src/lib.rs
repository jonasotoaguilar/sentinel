//! Sentinel — a deterministic Git secrets scanner. The public seam is [`run`]:
//! the binary forwards argv, cwd, and locked stdio.

mod cache;
mod cli;
mod config;
mod discovery;
mod engine;
mod errors;
pub mod explain;
mod finding;
mod normalize;
pub mod osv;
mod render;
#[cfg(test)]
mod test_util;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, error::ErrorKind};
use rayon::prelude::*;

use cli::{Command, FailUnder, OutputFormat};
use discovery::Discovered;
use engine::secrets::SecretsEngine;
use explain::{DisabledExplainer, ExplainError, Explainer};
use finding::Diagnostic;
use finding::Finding;
pub use finding::ScanBudgets;

/// Runs the requested command and returns the process exit code. Usage errors
/// and operational failures map to exit 2; a completed scan exits 1 when its
/// findings reach the `--fail-under` policy (by default, any finding) and 0
/// otherwise. The report (or the completion script) is the
/// only stdout content; diagnostics go to stderr.
pub fn run(
    args: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    // Production routing: the user-level config comes from the live process
    // environment (`SENTINEL_CONFIG`, else the XDG lookup). Tests bypass
    // `run` for `run_inner` with an explicit choice, so no in-process test
    // depends on the developer's home directory.
    run_inner(
        &SecretsEngine::new(),
        args,
        cwd,
        stdout,
        stderr,
        config::user_path(),
    )
}

/// Runs the requested command with the user level of the configuration
/// skipped entirely.
///
/// The production entry point reads the user level from the live process
/// environment, which an in-process test cannot control without racing other
/// tests over `HOME`. Tests that scan in-process use this instead, so that a
/// developer's own `~/.config/sentinel/config.toml` cannot change what a test
/// scans. Project-level configuration is still read, because it belongs to
/// the repository under test.
pub fn run_without_user_config(
    args: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    run_inner(&SecretsEngine::new(), args, cwd, stdout, stderr, None)
}

/// The pipeline over an explicit engine; tests inject engines containing a
/// failing rule. Reads and detection run in parallel and are
/// collected in file order; normalization sorts by (fingerprint, path, line).
/// `user_config` is the explicit user-level routing: `Some(path)` reads that
/// file, `None` skips the user level entirely (hermetic tests).
fn run_inner(
    engine: &SecretsEngine,
    args: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    user_config: Option<PathBuf>,
) -> ExitCode {
    // The HTTP adapter is built once per scan from the environment;
    // without both variables the disabled explainer keeps the skip path.
    let http = explain::http::HttpExplainer::from_env();
    let disabled = DisabledExplainer;
    let explainer: &dyn Explainer = match &http {
        Some(adapter) => adapter,
        None => &disabled,
    };
    run_with_deps(engine, explainer, args, cwd, stdout, stderr, user_config)
}

/// Enforces the file budget on discovery output: the leading files up to
/// the cap are scanned and the rest is left out with exactly one diagnostic
/// carrying the omitted count. Discovery order is deterministic, so the kept
/// prefix — and the report — is byte-identical across reruns.
pub(crate) fn apply_file_budget(
    files: Vec<PathBuf>,
    budgets: &ScanBudgets,
) -> (Vec<PathBuf>, Option<Diagnostic>) {
    if files.len() <= budgets.max_files {
        return (files, None);
    }
    let omitted = files.len() - budgets.max_files;
    let kept: Vec<PathBuf> = files.into_iter().take(budgets.max_files).collect();
    let kept_count = kept.len();
    (
        kept,
        Some(Diagnostic::scan_files_truncated(kept_count, omitted)),
    )
}

/// Splits ordered per-file byte lengths into a kept prefix and the omitted
/// tail: leading entries whose running total fits the cap are scanned, the
/// rest is left out. Returns the kept prefix length, the kept bytes, and
/// the omitted bytes; the omitted file count is `lens.len() - kept`.
pub(crate) fn byte_budget_split(lens: &[u64], cap: u64) -> (usize, u64, u64) {
    let mut total = 0u64;
    let mut kept = 0usize;
    for len in lens {
        match total.checked_add(*len) {
            Some(next) if next <= cap => {
                total = next;
                kept += 1;
            }
            _ => break,
        }
    }
    let omitted = lens[kept..]
        .iter()
        .fold(0u64, |sum, len| sum.saturating_add(*len));
    (kept, total, omitted)
}

/// Enforces the findings budget after dedupe and sort: the leading findings
/// are reported and the rest is left out with exactly one diagnostic
/// carrying the omitted count. Dedupe and sort are untouched, so order and
/// rerun identity are unchanged — only the tail is missing, and disclosed.
pub(crate) fn apply_findings_budget(
    findings: Vec<Finding>,
    budgets: &ScanBudgets,
) -> (Vec<Finding>, Option<Diagnostic>) {
    if findings.len() <= budgets.max_findings {
        return (findings, None);
    }
    let omitted = findings.len() - budgets.max_findings;
    let mut kept = findings;
    kept.truncate(budgets.max_findings);
    let kept_count = kept.len();
    (
        kept,
        Some(Diagnostic::scan_findings_truncated(kept_count, omitted)),
    )
}

/// Whether these args request an offline scan. Lets [`run_with_deps`] skip
/// building the OSV client entirely on the offline path; pure arg peek, so
/// the pipeline below keeps the single parse that owns error reporting.
fn is_offline_scan(args: &[String]) -> bool {
    matches!(
        cli::parse(args),
        Ok(cli) if matches!(cli.command, Command::Scan { offline: true, .. })
    )
}

/// The production entry over an explicit engine and explainer (tests inject
/// both): builds exactly the dependency client an online scan uses — and no
/// client at all for `--offline` — then delegates to [`run_with_dep_client`],
/// so policy and exit codes cannot drift between the two paths.
/// `user_config` is the explicit user-level routing: `Some(path)` reads that
/// file, `None` skips the user level entirely (hermetic tests).
pub fn run_with_deps(
    engine: &SecretsEngine,
    explainer: &dyn Explainer,
    args: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    user_config: Option<PathBuf>,
) -> ExitCode {
    // `None` means offline: the offline branch constructs zero OSV clients,
    // and the online path receives exactly the client built today.
    let osv: Option<Box<dyn crate::osv::client::OsvApi>> = if is_offline_scan(args) {
        None
    } else {
        Some(match crate::osv::client::UreqOsvClient::maybe_new(false) {
            Some(client) => Box::new(client),
            None => Box::new(crate::osv::client::StubOsv::new(vec![])),
        })
    };
    run_with_dep_client(
        engine,
        explainer,
        ScanDeps { osv, user_config },
        args,
        cwd,
        stdout,
        stderr,
    )
}

/// The per-scan dependencies the caller injects instead of the pipeline
/// reading them itself: the online path's OSV client (`None` means offline)
/// and the user-config routing (`None` skips the user level entirely).
/// Tests stage unreachable endpoints and hostile configs through this struct,
/// so no in-process test depends on the network or the developer's home
/// directory.
pub(crate) struct ScanDeps {
    pub osv: Option<Box<dyn crate::osv::client::OsvApi>>,
    pub user_config: Option<PathBuf>,
}

/// The dependency-client seam: the caller injects [`ScanDeps`] — the online
/// path's OSV client (`None` means offline) and the user-config routing — so
/// the unreachable-endpoint contract and the hostile-config contract are both
/// testable without a network dial or touching the process environment.
/// [`run_with_deps`] is the single production caller; production behaviour is
/// unchanged — same client, same routing, same policy, same exit codes.
///
/// The pipeline over an explicit engine and explainer (tests inject the stub,
/// so no test touches the network). The explainer runs at most once per scan:
/// only when `--explain` was requested, allowed, and configured.
pub(crate) fn run_with_dep_client(
    engine: &SecretsEngine,
    explainer: &dyn Explainer,
    deps: ScanDeps,
    args: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let ScanDeps { osv, user_config } = deps;
    let cli = match cli::parse(args) {
        Ok(cli) => cli,
        Err(usage) => {
            // `--help`/`--version` are display requests, not usage errors:
            // their text goes to stdout and the process exits 0.
            if matches!(
                usage.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = write!(stdout, "{}", usage.render());
                return ExitCode::SUCCESS;
            }
            // Usage errors echo the rejected argument, which may be a path.
            let _ = write!(
                stderr,
                "{}",
                SecretsEngine::redact_production(&usage.to_string())
            );
            return ExitCode::from(errors::EXIT_OPERATIONAL);
        }
    };
    // `completions` is a pure side command: the script is generated from the
    // live command definition and written to the injected stdout writer
    // without entering the scan pipeline, so no discovery, cache, network,
    // or repository access happens.
    if let Command::Completions { shell } = &cli.command {
        let mut cmd = cli::Cli::command();
        clap_complete::generate(*shell, &mut cmd, "sentinel", stdout);
        return ExitCode::SUCCESS;
    }
    let Command::Scan {
        ci,
        offline,
        output,
        report,
        explain,
        exclude,
        fail_under,
    } = cli.command
    else {
        unreachable!("`Completions` returns above, so only `Scan` reaches here");
    };
    let mode = if ci {
        discovery::Mode::Ci
    } else {
        discovery::Mode::Local
    };

    let discovered = match discovery::Git::new().discover(cwd, mode) {
        Ok(discovered) => discovered,
        Err(error) => {
            // Fatal errors carry the invocation directory, which may itself
            // hold a secret; only the form leaving the process is redacted.
            let _ = writeln!(
                stderr,
                "sentinel: {}",
                SecretsEngine::redact_production(&error.to_string())
            );
            return ExitCode::from(errors::EXIT_OPERATIONAL);
        }
    };
    let Discovered {
        root,
        files,
        diagnostics: discovery_diagnostics,
    } = discovered;
    // Layered configuration (T1/T2): CLI values, then the project
    // `sentinel.toml`, then the user-level file at the caller-chosen path —
    // `None` skips it, which keeps hermetic tests immune to the developer's
    // home directory. Excludes union across levels while `fail_under`
    // overrides; the same merged excludes apply in both modes, so `--ci`
    // stays hermetic.
    let (configured, config_diagnostics) =
        config::resolve_full_with(&root, &exclude, fail_under, user_config);
    let configured_excludes = configured.excludes;
    // Exit policy (S3): the winning `fail_under`, or the default (any
    // finding fails) when no level set it.
    let policy = configured.fail_under.unwrap_or_default();
    let (files, exclude_diagnostics) =
        discovery::apply_excludes(&root, files, &configured_excludes);
    // Total budgets (S7): production values from one documented value.
    // Each breach degrades through diagnostics; exit codes stay 0/1 and
    // truncation is never silent.
    let budgets = ScanBudgets::production();
    let (files, files_diag) = apply_file_budget(files, &budgets);

    // Engine-local rule failures warn once and never abort the scan;
    // discovery diagnostics (skipped-large, walk-failed, invalid-path, ...)
    // merge before the deterministic renderer.
    let mut diagnostics = engine.init_diagnostics().to_vec();
    diagnostics.extend(discovery_diagnostics);
    diagnostics.extend(config_diagnostics);
    diagnostics.extend(exclude_diagnostics);
    diagnostics.extend(files_diag);
    // The code-rules engine runs per file after secrets; its rule
    // failures merge into the same diagnostics vector.
    let rules_engine = crate::engine::rules::RulesEngine::new();
    diagnostics.extend(rules_engine.init_diagnostics().to_vec());

    let scans = files
        .par_iter()
        .map(|path| {
            // Paths travel into finding ids, snippets of payloads, and
            // terminal output, so a secret in a file or directory name is
            // redacted with the production table while the path stays
            // readable; the finding digest never covers the path.
            let raw = path.to_string_lossy().replace('\\', "/");
            let path_text = SecretsEngine::redact_production(&raw);
            let bytes = match discovery::read_scan_bytes(&root.join(path)) {
                Ok(bytes) => bytes,
                Err(discovery::BoundedReadError::TooLarge(len)) => {
                    return Err(Diagnostic {
                        code: "skipped-large",
                        path: path_text,
                        rule: String::new(),
                        message: format!("{len} bytes exceeds the 10 MiB scan limit"),
                    });
                }
                Err(discovery::BoundedReadError::Io(error)) => {
                    return Err(Diagnostic::read_failed(&path_text, &error));
                }
            };
            // Manifest bytes travel with the scan, so the dependency review
            // below parses these same bytes instead of opening each file
            // a second time.
            let byte_len = bytes.len() as u64;
            let shared = if raw.ends_with("package-lock.json") || raw.ends_with("requirements.txt")
            {
                Some((raw, bytes.clone()))
            } else {
                None
            };
            let (rule_candidates, rule_diagnostics) =
                rules_engine.scan_with_diagnostics(&path_text, &bytes);
            Ok((
                path_text,
                byte_len,
                engine.scan(&bytes),
                rule_candidates,
                rule_diagnostics,
                shared,
            ))
        })
        .collect::<Vec<_>>();

    // Byte budget over leading files in deterministic file order: reads that
    // failed carry no bytes and always keep their diagnostic; successful
    // reads past the cap leave their findings out and are counted.
    let ok_lens: Vec<u64> = scans
        .iter()
        .filter_map(|scan| scan.as_ref().ok().map(|ok| ok.1))
        .collect();
    let (mut kept_ok, kept_bytes, omitted_bytes) =
        byte_budget_split(&ok_lens, budgets.max_scanned_bytes);
    let omitted_files = ok_lens.len() - kept_ok;
    if omitted_files > 0 {
        diagnostics.push(Diagnostic::scan_bytes_truncated(
            kept_bytes,
            omitted_bytes,
            omitted_files,
        ));
    }
    let mut findings = Vec::new();
    let mut manifests: Vec<(String, Vec<u8>)> = Vec::new();
    for scan in scans {
        match scan {
            Ok((path, _, secret_candidates, rule_candidates, rule_diagnostics, shared)) => {
                if kept_ok == 0 {
                    continue;
                }
                kept_ok -= 1;
                diagnostics.extend(rule_diagnostics);
                if let Some(entry) = shared {
                    manifests.push(entry);
                }
                findings.extend(normalize::to_findings(&path, secret_candidates));
                findings.extend(normalize::to_findings_for(
                    crate::engine::ENGINE_RULES,
                    &path,
                    rule_candidates,
                ));
            }
            Err(diagnostic) => diagnostics.push(diagnostic),
        }
    }

    // Dependency review: after secrets, merge with dedupe_and_sort. OSV/cache
    // failures degrade to diagnostics (0/1), never Exit 2.
    let dep_cache = cache::XdgCache::new();
    let dep_engine = if offline {
        crate::engine::dependency::DependencyEngine::offline(dep_cache)
    } else {
        match osv {
            Some(client) => crate::engine::dependency::DependencyEngine::online(dep_cache, client),
            // Unreachable through the single caller, which always provides
            // the client for online scans; degrade offline rather than
            // invent network I/O.
            None => crate::engine::dependency::DependencyEngine::offline(dep_cache),
        }
    };
    // The review reads through the original file list, so what is read,
    // cached, and looked up stays byte-identical; only the finding's display
    // forms (location path, snippet, message, rule id, evidence, and the
    // fingerprint's path segment) are redacted here, at the single point every
    // dependency finding crosses. Snippet and message need the same treatment
    // because a secret used as a package coordinate travels in them; rule id
    // and evidence need it because advisory text is content-derived. Secrets and
    // rule findings arrive already redacted from the scan loop above, so terminal,
    // JSON, SARIF, report files, and the explain payload that all render from
    // these findings can no longer carry a raw value, and neither can
    // advisory text keyed by finding id. Digests and dedupe keys are
    // computed from pre-display values inside the engines and are untouched.
    let (dep_findings, dep_diags) = dep_engine.review_bytes(&manifests);
    diagnostics.extend(dep_diags);
    findings.extend(dep_findings.into_iter().map(|mut finding| {
        finding.location.path = SecretsEngine::redact_production(&finding.location.path);
        finding.location.snippet = SecretsEngine::redact_production(&finding.location.snippet);
        finding.message = SecretsEngine::redact_production(&finding.message);
        finding.rule_id = SecretsEngine::redact_production(&finding.rule_id);
        finding.evidence = SecretsEngine::redact_production(&finding.evidence);
        finding.id = SecretsEngine::redact_production(&finding.id);
        finding
    }));
    let findings = normalize::dedupe_and_sort(findings);
    let (findings, findings_diag) = apply_findings_budget(findings, &budgets);
    diagnostics.extend(findings_diag);

    // Opt-in advisories: silent under `--ci`/`--offline` (byte-identical to no
    // flag); one `explain-skipped` when unconfigured; else a single call whose
    // text only reaches terminal output.
    let mut advisories: BTreeMap<String, String> = BTreeMap::new();
    if explain && !ci && !offline {
        if explainer.is_configured() {
            // One attempt: transport failures and malformed bodies degrade
            // to warnings, never to a retry or an exit change.
            match explainer.explain(&findings) {
                Ok(explanations) => {
                    for explanation in explanations {
                        if findings.iter().any(|f| f.id == explanation.finding_id) {
                            advisories
                                .entry(explanation.finding_id)
                                .or_insert(explanation.text);
                        }
                    }
                }
                Err(ExplainError::Failed(message)) => {
                    diagnostics.push(Diagnostic::explain_failed(&message));
                }
                Err(ExplainError::Invalid(message)) => {
                    diagnostics.push(Diagnostic::explain_invalid(&message));
                }
            }
        } else {
            diagnostics.push(Diagnostic::explain_skipped(
                "no explain endpoint configured",
            ));
        }
    }

    let _ = stderr.write_all(&render::render_diagnostics(&diagnostics));

    // Report formats render first, then write to stdout or the requested file.
    // Machine formats carry an incompleteness signal only when something
    // actually degraded: explain advisories are terminal-only, so their
    // failures never mark the findings incomplete.
    let incomplete = diagnostics.iter().any(|d| !d.code.starts_with("explain-"));
    let report_bytes = match output {
        // Without advisories the original renderer runs, so those bytes are
        // identical by construction, not just by delegation.
        OutputFormat::Terminal if advisories.is_empty() => render::render_findings(&findings),
        OutputFormat::Terminal => render::render_findings_with_advisories(&findings, &advisories),
        OutputFormat::Json | OutputFormat::Sarif => {
            let rendered = match output {
                // The complete path keeps the original renderer, so clean
                // bytes are identical by construction, not just by delegation.
                OutputFormat::Json if !incomplete => render::render_json(&findings),
                OutputFormat::Json => render::render_json_with_status(&findings, true),
                OutputFormat::Sarif if !incomplete => render::render_sarif(&findings),
                OutputFormat::Sarif => render::render_sarif_with_status(&findings, true),
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

    // Exit policy (S3): only findings at or above the threshold fail the
    // build; `none` is report-only. Scans that did not run already returned
    // exit 2 above, and diagnostics never reach this decision.
    if findings_fail_build(&findings, policy) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Whether a completed scan's findings fail the build under `policy`: at
/// least one finding at or above the threshold severity. Severity ordering
/// comes from [`finding::Severity`]'s `Ord`, so the comparison cannot drift
/// from the finding model; `None` (report-only) never fails.
fn findings_fail_build(findings: &[Finding], policy: FailUnder) -> bool {
    match policy.threshold() {
        Some(minimum) => findings.iter().any(|finding| finding.severity >= minimum),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{ScanDeps, run_inner, run_with_deps};
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
        // Hermetic by construction: no user-level config, so the developer's
        // home directory can never change what a scan sees.
        let code = run_inner(&SecretsEngine::new(), &args, cwd, &mut out, &mut err, None);
        (code, out, err)
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
    fn rules_engine_findings_flow_through_scan() {
        let (_dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("app.js"),
            b"const h = crypto.createHash('md5');\n",
        );
        let (code, out, err) = run_scan(&["scan"], &root);
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("RULE-weak-hash"), "stdout: {out_text}");
        assert!(out_text.contains("app.js:1:"), "stdout: {out_text}");
        assert!(
            String::from_utf8(err).unwrap().is_empty(),
            "rules findings warn nothing on stderr"
        );
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
        let code = run_inner(
            &broken_rule_engine(),
            &args,
            &root,
            &mut out,
            &mut err,
            None,
        );
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
        let code = run_inner(
            &SecretsEngine::new(),
            &args,
            &root,
            &mut FailWriter,
            &mut err,
            None,
        );
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
        // `--help`/`--version` intentionally excluded: they render to stdout
        // and exit 0 (covered below), so only genuinely unknown input stays
        // a usage error.
        for args in [&["scan", "file.txt"][..], &["scan", "--nope"][..]] {
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
    fn help_and_version_write_to_stdout_and_exit_zero() {
        // Pins the S2 crate rename (`sentinel-scan`) against the binary users
        // type (`sentinel`): help/version output must never show the crate name.
        let version = format!("sentinel {}", env!("CARGO_PKG_VERSION"));
        for args in [
            &["--help"][..],
            &["--version"][..],
            &["scan", "--help"][..],
            &["completions", "--help"][..],
        ] {
            let (code, out, err) = run_scan(args, Path::new("."));
            assert_eq!(code, ExitCode::SUCCESS, "args {args:?}");
            let text = String::from_utf8(out).unwrap();
            assert!(
                !text.is_empty(),
                "args {args:?}: stdout must carry the text"
            );
            assert!(!text.contains("sentinel-scan"), "args {args:?}: {text:?}");
            assert!(err.is_empty(), "args {args:?}: stderr must stay empty");
        }
        let (_, out, _) = run_scan(&["--version"], Path::new("."));
        assert!(
            String::from_utf8(out).unwrap().starts_with(&version),
            "version must start with {version:?}"
        );
        let (_, out, _) = run_scan(&["--help"], Path::new("."));
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("scan"),
            "help must list subcommands: {text:?}"
        );
        assert!(
            text.contains("completions"),
            "help must list subcommands: {text:?}"
        );
    }

    use crate::explain::{Explanation, StubExplainer};

    fn run_explained(
        args: &[&str],
        cwd: &Path,
        stub: &StubExplainer,
    ) -> (ExitCode, Vec<u8>, Vec<u8>) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_with_deps(
            &SecretsEngine::new(),
            stub,
            &args,
            cwd,
            &mut out,
            &mut err,
            None,
        );
        (code, out, err)
    }

    #[test]
    fn explain_stays_off_unless_requested_and_allowed() {
        let (_dir, root) = secret_repo();
        for extra in [&["scan"][..], &["scan", "--ci"], &["scan", "--offline"]] {
            let stub = StubExplainer::per_finding("advice ");
            let mut flagged = extra.to_vec();
            flagged.push("--explain");
            let explained = run_explained(&flagged, &root, &stub);
            let plain = run_scan(extra, &root);
            if extra.len() == 1 {
                assert_eq!(stub.calls(), 1, "requested and allowed: one call");
                assert_eq!((explained.0, explained.2), (plain.0, plain.2));
            } else {
                assert_eq!(stub.calls(), 0, "forced off under {extra:?}");
                assert_eq!(explained, plain);
            }
        }
        let stub = StubExplainer::per_finding("advice ");
        assert_eq!(
            run_explained(&["scan"], &root, &stub),
            run_scan(&["scan"], &root)
        );
        assert_eq!(stub.calls(), 0, "off by default");
    }

    #[test]
    fn explain_advisories_are_additive_on_terminal_only() {
        let (_dir, root) = secret_repo();
        let stub = StubExplainer::per_finding("advice for ");
        let (code, out, err) = run_explained(&["scan", "--explain"], &root, &stub);
        let (plain_code, plain_out, plain_err) = run_scan(&["scan"], &root);
        assert_eq!(code, plain_code);
        assert_eq!(err, plain_err);
        let text = String::from_utf8(out).unwrap();
        let plain = String::from_utf8(plain_out).unwrap();
        let advice: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("  advice: "))
            .collect();
        assert_eq!(advice.len(), 2, "one advisory line per finding");
        let stripped: String = text
            .lines()
            .filter(|line| !line.starts_with("  advice: "))
            .map(|line| format!("{line}\n"))
            .collect();
        assert_eq!(stripped, plain, "finding lines unchanged");
    }

    #[test]
    fn explain_hostile_stub_text_is_contained() {
        let (_dir, root) = secret_repo();
        let prefix =
            "first\nforged shape env.example:9:9: critical SECRET-forged: x\u{1b}[31mred\t";
        let stub = StubExplainer::per_finding(&format!("{prefix}{}", "y".repeat(600)));
        let (code, out, _) = run_explained(&["scan", "--explain"], &root, &stub);
        assert_eq!(code, ExitCode::from(1));
        let text = String::from_utf8(out).unwrap();
        let advice: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("  advice: "))
            .collect();
        assert_eq!(advice.len(), 2);
        for line in &advice {
            assert!(!line.contains('\u{1b}'), "no escapes: {line:?}");
            let body = line.strip_prefix("  advice: ").unwrap_or("");
            assert_eq!(body.chars().count(), 500, "capped at exactly 500");
        }
        assert!(
            text.lines()
                .all(|line| !line.contains("SECRET-forged") || line.starts_with("  advice: ")),
            "forged text can never stand as its own line"
        );
        let (_, json_out, _) =
            run_explained(&["scan", "--explain", "--output", "json"], &root, &stub);
        assert!(!String::from_utf8(json_out).unwrap().contains("advice:"));
        // Unknown ids never render: the advisory map is keyed by finding id.
        let ghost = StubExplainer::fixed(vec![Explanation {
            finding_id: "no/such:1:1/id".to_string(),
            text: "ghost".to_string(),
        }]);
        assert_eq!(
            run_explained(&["scan", "--explain"], &root, &ghost),
            run_scan(&["scan"], &root)
        );
        assert_eq!(ghost.calls(), 1);
    }

    #[test]
    fn explain_keeps_machine_formats_and_reports_byte_identical() {
        let (_dir, root) = secret_repo();
        let stub = StubExplainer::per_finding("advice ");
        for output in ["json", "sarif"] {
            let flagged = ["scan", "--output", output, "--explain"];
            let plain = ["scan", "--output", output];
            assert_eq!(
                run_explained(&flagged, &root, &stub).1,
                run_scan(&plain, &root).1
            );
        }
        let report = ["scan", "--output", "json", "--report", "r.json"];
        let explained = run_explained(&report, &root, &stub);
        let explained_bytes = std::fs::read(root.join("r.json")).unwrap();
        let plain = run_scan(&report, &root);
        assert_eq!(explained.0, plain.0);
        assert_eq!(explained.1, plain.1);
        assert_eq!(explained_bytes, std::fs::read(root.join("r.json")).unwrap());
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
    fn offline_is_hermetic() {
        let (_dir, root) = temp_repo();
        let (c, o, e) = run_scan(&["scan", "--offline"], &root);
        assert_eq!(c, ExitCode::SUCCESS);
        assert!(o.is_empty() && e.is_empty());
        let (c, o, e) = run_scan(&["scan", "--ci", "--offline"], &root);
        assert_eq!(c, ExitCode::SUCCESS);
        assert!(o.is_empty() && e.is_empty());
        let (_dir, root) = secret_repo();
        let (c, o, _) = run_scan(&["scan", "--offline"], &root);
        assert_eq!(c, ExitCode::from(1));
        assert!(
            String::from_utf8(o)
                .unwrap()
                .contains("SECRET-synthetic-token")
        );
    }

    /// Runs inside the re-execed child (see below): the same test binary, but
    /// the child owns a private `XDG_CACHE_HOME`, so the cold cache is
    /// hermetic without racing parallel tests over process environment. Also
    /// proves the offline path constructs zero OSV clients.
    fn cold_cache_child_main() {
        use crate::explain::DisabledExplainer;
        use crate::osv::client::{OsvApi, Query, ureq_client_constructions};
        // Why: the contract "network or cache degradation never exits 2" had
        // no test for online plus a cold cache with OSV unreachable, and the
        // endpoint is a constant, so only the injected-client seam can stage it.
        struct FailOsv;
        impl OsvApi for FailOsv {
            fn query_all(
                &self,
                _qs: &[Query],
            ) -> Result<
                (
                    Vec<Vec<crate::osv::validate::Advisory>>,
                    Vec<crate::finding::Diagnostic>,
                ),
                String,
            > {
                Err("synthetic network failure".into())
            }
            fn vuln(&self, _id: &str) -> Result<crate::osv::validate::Advisory, String> {
                Err("synthetic network failure".into())
            }
        }
        let before = ureq_client_constructions();
        // Offline first: this path must build no OSV client at all.
        let (_dir, offline_root) = temp_repo();
        write_tracked(
            &offline_root,
            OsStr::new("requirements.txt"),
            b"sentinel-synthetic-miss==9.9.9\n",
        );
        let offline_args = vec!["scan".to_string(), "--offline".to_string()];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = super::run_with_deps(
            &SecretsEngine::new(),
            &DisabledExplainer,
            &offline_args,
            &offline_root,
            &mut out,
            &mut err,
            None,
        );
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "an offline miss degrades, never exits 2"
        );
        assert_eq!(
            ureq_client_constructions(),
            before,
            "an --offline scan constructs zero OSV clients"
        );
        // Then online with a cold cache and an unreachable OSV: exit 1,
        // findings intact, and the reason on stderr.
        let (_dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("requirements.txt"),
            b"sentinel-synthetic-miss==9.9.9\n",
        );
        write_tracked(
            &root,
            OsStr::new("env.example"),
            b"token = sk-synthetic-1234567890\n",
        );
        let args = vec!["scan".to_string()];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = super::run_with_dep_client(
            &SecretsEngine::new(),
            &DisabledExplainer,
            ScanDeps {
                osv: Some(Box::new(FailOsv)),
                user_config: None,
            },
            &args,
            &root,
            &mut out,
            &mut err,
        );
        assert_eq!(code, ExitCode::from(1), "a degraded scan exits 1, never 2");
        let stdout = String::from_utf8(out).unwrap();
        assert!(
            stdout.contains("SECRET-synthetic-token"),
            "findings survive degradation: {stdout}"
        );
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("osv-unavailable"),
            "the scan says why: {stderr}"
        );
    }

    #[test]
    fn online_cold_cache_failure_degrades_without_exit_two() {
        // Mutating process environment from a parallel test is a race, so the
        // child process below owns its environment instead (the proxy
        // isolation in tests/dependency.rs): a fresh `XDG_CACHE_HOME` makes
        // the cold cache hermetic, and the parent asserts the child ran.
        if std::env::var("SENTINEL_COLD_CACHE_CHILD").is_ok() {
            cold_cache_child_main();
            return;
        }
        let xdg = TempDir::new().unwrap();
        let exe = std::env::current_exe().unwrap();
        let output = std::process::Command::new(exe)
            .arg("--exact")
            .arg("tests::online_cold_cache_failure_degrades_without_exit_two")
            .env("SENTINEL_COLD_CACHE_CHILD", "1")
            .env("XDG_CACHE_HOME", xdg.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child must complete its scans: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the child ran its scan assertions: {}",
            String::from_utf8_lossy(&output.stdout)
        );
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

    #[test]
    fn production_budgets_carry_the_decided_values() {
        let budgets = crate::finding::ScanBudgets::production();
        assert_eq!(budgets.max_files, 100_000);
        assert_eq!(budgets.max_scanned_bytes, 1024 * 1024 * 1024);
        assert_eq!(budgets.max_findings, 10_000);
        assert_eq!(budgets.max_pins_per_request, 1_000);
    }

    #[test]
    fn file_budget_truncates_with_one_counted_diagnostic() {
        let budgets = crate::finding::ScanBudgets {
            max_files: 2,
            max_scanned_bytes: u64::MAX,
            max_findings: usize::MAX,
            max_pins_per_request: 1_000,
        };
        let files = vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")];
        let (kept, diagnostic) = super::apply_file_budget(files, &budgets);
        assert_eq!(kept.len(), 2);
        let diagnostic = diagnostic.expect("a file-cap breach must warn");
        assert_eq!(diagnostic.code, "scan-files-truncated");
        assert!(
            diagnostic.message.contains("1 files omitted"),
            "omitted count must travel: {}",
            diagnostic.message
        );
    }

    #[test]
    fn byte_budget_split_counts_omitted_bytes_and_files() {
        let budgets = crate::finding::ScanBudgets {
            max_files: usize::MAX,
            max_scanned_bytes: 25,
            max_findings: usize::MAX,
            max_pins_per_request: 1_000,
        };
        let (kept, kept_bytes, omitted_bytes) =
            super::byte_budget_split(&[10, 10, 10], budgets.max_scanned_bytes);
        assert_eq!(kept, 2);
        assert_eq!(kept_bytes, 20);
        assert_eq!(omitted_bytes, 10);
        let diagnostic =
            crate::finding::Diagnostic::scan_bytes_truncated(kept_bytes, omitted_bytes, 1);
        assert_eq!(diagnostic.code, "scan-bytes-truncated");
        assert!(
            diagnostic.message.contains("10"),
            "omitted bytes must travel: {}",
            diagnostic.message
        );
    }

    #[test]
    fn findings_budget_truncates_with_one_counted_diagnostic() {
        use crate::finding::{Finding, Location, Severity};
        let budgets = crate::finding::ScanBudgets {
            max_files: usize::MAX,
            max_scanned_bytes: u64::MAX,
            max_findings: 2,
            max_pins_per_request: 1_000,
        };
        let finding = |id: &str| Finding {
            id: id.to_string(),
            engine: "secrets".to_string(),
            rule_id: "SECRET-x".to_string(),
            severity: Severity::Medium,
            location: Location {
                path: "a.txt".to_string(),
                line: 1,
                column: 1,
                snippet: "[REDACTED]".to_string(),
            },
            message: "m".to_string(),
            evidence: "[REDACTED]".to_string(),
        };
        let findings = vec![finding("c"), finding("a"), finding("b")];
        let (kept, diagnostic) = super::apply_findings_budget(findings, &budgets);
        assert_eq!(kept.len(), 2);
        let diagnostic = diagnostic.expect("a findings-cap breach must warn");
        assert_eq!(diagnostic.code, "scan-findings-truncated");
        assert!(
            diagnostic.message.contains("1 findings omitted"),
            "omitted count must travel: {}",
            diagnostic.message
        );
    }

    /// Two secret-bearing files, one excluded by flag: only the kept file
    /// reports, and the exit stays 1 because a finding remains.
    #[test]
    fn exclude_flag_removes_matching_file_from_scan() {
        let (_dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("keep.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        write_tracked(
            &root,
            OsStr::new("skip.log"),
            b"token = sk-synthetic-1234567890\n",
        );
        let (code, out, err) = run_scan(&["scan", "--exclude", "*.log"], &root);
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("keep.env:1:"), "stdout: {out_text}");
        assert!(!out_text.contains("skip.log"), "excluded: {out_text}");
        assert!(
            !String::from_utf8(err).unwrap().contains(SYNTHETIC_TOKEN),
            "no raw secret on stderr"
        );
    }

    /// The repo-local ignore file removes files through the full pipeline:
    /// a tracked secret covered by `.sentinelignore` never reports.
    #[test]
    fn sentinelignore_removes_matching_file_through_scan() {
        let (_dir, root) = temp_repo();
        write_untracked(&root, OsStr::new(".sentinelignore"), b"*.secret\n");
        write_tracked(
            &root,
            OsStr::new("tracked.secret"),
            b"token = sk-synthetic-1234567890\n",
        );
        write_tracked(&root, OsStr::new("clean.txt"), b"no secrets here");
        let (code, out, err) = run_scan(&["scan"], &root);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    /// The project config is the first consumer of the config file: an
    /// `exclude` there removes the file with no CLI flag involved.
    #[test]
    fn project_config_exclude_removes_matching_file() {
        let (_dir, root) = temp_repo();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"exclude = [\"*.log\"]\n",
        );
        write_tracked(
            &root,
            OsStr::new("keep.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        write_tracked(
            &root,
            OsStr::new("skip.log"),
            b"token = sk-synthetic-1234567890\n",
        );
        let (code, out, _) = run_scan(&["scan"], &root);
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("keep.env:1:"), "stdout: {out_text}");
        assert!(!out_text.contains("skip.log"), "excluded: {out_text}");
    }

    /// CLI and project levels combine: each removes its own file in one scan.
    #[test]
    fn cli_and_project_excludes_combine_through_scan() {
        let (_dir, root) = temp_repo();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"exclude = [\"*.log\"]\n",
        );
        write_tracked(
            &root,
            OsStr::new("keep.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        write_tracked(
            &root,
            OsStr::new("skip.log"),
            b"token = sk-synthetic-1234567890\n",
        );
        write_tracked(
            &root,
            OsStr::new("skip.tmp"),
            b"token = sk-synthetic-1234567890\n",
        );
        let (code, out, _) = run_scan(&["scan", "--exclude", "*.tmp"], &root);
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("keep.env:1:"), "stdout: {out_text}");
        assert!(
            !out_text.contains("skip.log"),
            "config excluded: {out_text}"
        );
        assert!(!out_text.contains("skip.tmp"), "CLI excluded: {out_text}");
    }

    /// A hostile user config must not leak into the hermetic scan path: with
    /// an explicit "no user config" the scan reports everything, and only
    /// an explicitly passed user file suppresses anything.
    #[test]
    fn hostile_user_config_leaves_hermetic_scan_unaffected() {
        let (_dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("keep.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        write_tracked(
            &root,
            OsStr::new("skip.log"),
            b"token = sk-synthetic-1234567890\n",
        );
        // A hostile user-level config: excludes the only other secret-bearing
        // file, so any leak of the environment into the scan hides a finding.
        let xdg = TempDir::new().unwrap();
        let hostile = xdg.path().join("config.toml");
        std::fs::write(&hostile, b"exclude = [\"*.log\"]\n").unwrap();
        let scan_with = |user: Option<PathBuf>| {
            let args = vec!["scan".to_string()];
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run_inner(
                &SecretsEngine::new(),
                &args,
                &root,
                &mut out,
                &mut err,
                user,
            );
            (code, out, err)
        };
        // Hermetic: both findings report, nothing warns on stderr.
        let (code, out, err) = scan_with(None);
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("keep.env:1:"), "stdout: {out_text}");
        assert!(out_text.contains("skip.log:1:"), "stdout: {out_text}");
        assert!(String::from_utf8(err).unwrap().is_empty());
        // Explicit: the same hostile file really excludes `skip.log` —
        // proving the config is effective, so the hermetic assertion above
        // is meaningful rather than vacuous.
        let (code, out, _) = scan_with(Some(hostile));
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("keep.env:1:"), "stdout: {out_text}");
        assert!(!out_text.contains("skip.log"), "excluded: {out_text}");
    }

    /// A repository with no config file carries no config diagnostics, and an
    /// empty config is byte-identical to no config at all.
    #[test]
    fn no_config_scan_is_silent_and_empty_config_is_identical() {
        let (_dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("env.example"),
            b"token = sk-synthetic-1234567890\n",
        );
        let plain = run_scan(&["scan"], &root);
        assert!(String::from_utf8(plain.2.clone()).unwrap().is_empty());
        write_untracked(&root, OsStr::new("sentinel.toml"), b"exclude = []\n");
        let with_empty = run_scan(&["scan"], &root);
        assert_eq!(plain, with_empty, "empty config must change nothing");
    }

    /// PRESERVE: a non-matching `--exclude` leaves the scan byte-identical
    /// to the same scan without the flag — the plain path still reports the
    /// same findings, exit, and (empty) diagnostics.
    #[test]
    fn non_matching_exclude_leaves_scan_byte_identical() {
        let (_dir, root) = secret_repo();
        let plain = run_scan(&["scan"], &root);
        let filtered = run_scan(&["scan", "--exclude", "*.nomatch"], &root);
        assert_eq!(plain, filtered);
        assert_eq!(plain.0, ExitCode::from(1));
        assert!(
            String::from_utf8(plain.1.clone())
                .unwrap()
                .contains("SECRET-aws-access-key")
        );
    }

    /// PRESERVE: the `--ci` hermetic path is untouched — an untracked secret
    /// is still found in both modes with the exclude wiring in place, and a
    /// matching `--exclude` removes it in both modes alike.
    #[test]
    fn ci_hermetic_scan_still_holds_with_exclude_wiring() {
        for extra in [&["scan"][..], &["scan", "--ci"]] {
            let (_dir, root) = temp_repo();
            write_tracked(&root, OsStr::new("clean.txt"), b"no secrets");
            write_untracked(
                &root,
                OsStr::new(".env"),
                b"token = sk-synthetic-1234567890\n",
            );
            let found = run_scan(extra, &root);
            assert_eq!(found.0, ExitCode::from(1), "args {extra:?}");
            assert!(
                String::from_utf8(found.1.clone())
                    .unwrap()
                    .contains(".env:1:"),
                "args {extra:?}"
            );
            let mut excluded: Vec<&str> = extra.to_vec();
            excluded.push("--exclude");
            excluded.push(".env");
            let hidden = run_scan(&excluded, &root);
            assert_eq!(hidden.0, ExitCode::SUCCESS, "args {excluded:?}");
            assert!(hidden.1.is_empty(), "args {excluded:?}");
        }
    }
    /// Exit-policy helpers (S3): hermetic in-process scan over an explicit
    /// user config, plus single-severity fixture repositories.
    fn run_scan_with_user(
        args: &[&str],
        cwd: &Path,
        user: Option<PathBuf>,
    ) -> (ExitCode, Vec<u8>, Vec<u8>) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_inner(&SecretsEngine::new(), &args, cwd, &mut out, &mut err, user);
        (code, out, err)
    }
    /// A repository whose only finding is medium severity: below `high`, at
    /// `medium`, above `low` — the threshold boundary probe.
    fn medium_only_repo() -> (TempDir, PathBuf) {
        let (dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("token.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        (dir, root)
    }
    /// A repository whose only finding is critical severity.
    fn critical_only_repo() -> (TempDir, PathBuf) {
        let (dir, root) = temp_repo();
        let contents = format!("aws_key = \"{AWS_KEY}\"\n");
        write_tracked(&root, OsStr::new("env.example"), contents.as_bytes());
        (dir, root)
    }
    /// A finding below the threshold exits 0, but the finding still reports:
    /// the policy gates the exit code, never the report.
    #[test]
    fn finding_below_threshold_exits_zero_but_still_reports() {
        let (_dir, root) = medium_only_repo();
        let (code, out, err) = run_scan(&["scan", "--fail-under", "high"], &root);
        assert_eq!(code, ExitCode::SUCCESS, "medium is below high");
        let out_text = String::from_utf8(out).unwrap();
        assert!(
            out_text.contains("SECRET-synthetic-token"),
            "the finding still reports: {out_text}"
        );
        assert!(
            String::from_utf8(err).unwrap().is_empty(),
            "no diagnostics on this path"
        );
    }
    /// A finding at or above the threshold exits 1, from either side of the
    /// boundary: medium at `medium`, critical above `high`.
    #[test]
    fn finding_at_or_above_threshold_exits_one() {
        let (_dir, root) = medium_only_repo();
        let (code, _, _) = run_scan(&["scan", "--fail-under", "medium"], &root);
        assert_eq!(code, ExitCode::from(1), "medium is at medium");
        let (_dir, root) = critical_only_repo();
        let (code, out, _) = run_scan(&["scan", "--fail-under", "high"], &root);
        assert_eq!(code, ExitCode::from(1), "critical is above high");
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("SECRET-aws-access-key")
        );
    }
    /// `none` is report-only: findings present, report intact, exit 0.
    #[test]
    fn fail_under_none_is_report_only() {
        let (_dir, root) = secret_repo();
        let (code, out, _) = run_scan(&["scan", "--fail-under", "none"], &root);
        assert_eq!(code, ExitCode::SUCCESS, "report-only never fails");
        let out_text = String::from_utf8(out).unwrap();
        for id in ["SECRET-aws-access-key", "SECRET-synthetic-token"] {
            assert!(out_text.contains(id), "still reported: {out_text}");
        }
    }
    /// The default preserves today's behaviour exactly: any finding exits 1,
    /// even the lowest severity in the system.
    #[test]
    fn default_policy_is_any_finding_exits_one() {
        let (_dir, root) = medium_only_repo();
        let (code, out, _) = run_scan(&["scan"], &root);
        assert_eq!(code, ExitCode::from(1), "no flag means any finding fails");
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("SECRET-synthetic-token")
        );
    }
    /// The CLI flag wins over the project config value.
    #[test]
    fn cli_fail_under_overrides_project_config() {
        let (_dir, root) = medium_only_repo();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"fail_under = \"high\"\n",
        );
        let (code, _, _) = run_scan(&["scan"], &root);
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "project high ignores the medium finding"
        );
        let (code, _, _) = run_scan(&["scan", "--fail-under", "low"], &root);
        assert_eq!(code, ExitCode::from(1), "CLI low replaces project high");
    }
    /// The project value wins over the user one — and the user level is
    /// proven effective first, so the override assertion is meaningful.
    #[test]
    fn project_fail_under_overrides_user_config() {
        let (_dir, root) = medium_only_repo();
        let xdg = TempDir::new().unwrap();
        let user_file = xdg.path().join("config.toml");
        std::fs::write(&user_file, b"fail_under = \"low\"\n").unwrap();
        let (code, _, _) = run_scan_with_user(&["scan"], &root, Some(user_file.clone()));
        assert_eq!(
            code,
            ExitCode::from(1),
            "user low fails on the medium finding"
        );
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"fail_under = \"high\"\n",
        );
        let (code, _, _) = run_scan_with_user(&["scan"], &root, Some(user_file));
        assert_eq!(code, ExitCode::SUCCESS, "project high replaces user low");
    }
    /// `none` must not weaken the operational exits: a scan that did not run
    /// still exits 2.
    #[test]
    fn fail_under_none_leaves_operational_exits_untouched() {
        let dir = TempDir::new().unwrap();
        let (code, out, err) = run_scan(&["scan", "--fail-under", "none"], dir.path());
        assert_eq!(
            code,
            ExitCode::from(2),
            "no scan ran, so report-only cannot apply"
        );
        assert!(out.is_empty());
        assert!(!err.is_empty());
    }
    /// Diagnostics still never affect the exit code under a policy: a bad
    /// config warns once, the finding still reports, and the threshold alone
    /// decides the code.
    #[test]
    fn diagnostics_still_never_affect_the_exit_code() {
        let (_dir, root) = medium_only_repo();
        write_tracked(&root, OsStr::new("sentinel.toml"), b"exclude = [oops\n");
        let (code, out, err) = run_scan(&["scan", "--fail-under", "high"], &root);
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "medium is below high; the warning changes nothing"
        );
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("SECRET-synthetic-token"),
            "the finding still reports"
        );
        assert!(
            String::from_utf8(err).unwrap().contains("config-invalid"),
            "the warning is still disclosed"
        );
    }
}
