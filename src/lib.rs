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
use std::collections::BTreeSet;
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
/// unaccepted findings reach the `--fail-under` policy (by default, any
/// finding) and 0 otherwise — accepted baseline entries never fail the
/// build. The report (or the completion script) is the
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

/// The `cache` side command (S6): prints or deletes inside the resolved XDG
/// cache without entering the scan pipeline. `path` only prints; `clear`
/// and `prune` resolve the location first, refuse when the process stands
/// inside it, then delete only inside it — and every success reports the
/// entry count and reclaimed bytes, so a destructive command never runs
/// silent. Refusals and I/O failures exit 2 with the reason on stderr.
fn run_cache(
    action: &cli::CacheAction,
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let verb = match action {
        cli::CacheAction::Path => "path",
        cli::CacheAction::Clear => "clear",
        cli::CacheAction::Prune { .. } => "prune",
    };
    let Some(cache) = cache::XdgCache::new() else {
        let _ = writeln!(
            stderr,
            "sentinel: cannot {verb} cache: no cache directory is available on this system"
        );
        return ExitCode::from(errors::EXIT_OPERATIONAL);
    };
    if matches!(action, cli::CacheAction::Path) {
        // `location` is `Some` whenever `new` is — this branch only
        // prints, so there is nothing to refuse or delete.
        let location = cache.location().unwrap_or_default();
        if writeln!(stdout, "{}", location.display()).is_err() {
            let _ = writeln!(stderr, "sentinel: cannot write cache path");
            return ExitCode::from(errors::EXIT_OPERATIONAL);
        }
        return ExitCode::SUCCESS;
    }
    // Never remove the directory the process is standing in or anything
    // above it: a cache root containing the invoking cwd refuses instead
    // of emptying a directory the user is working in. The destructive
    // methods below re-check containment per entry; this guards the root.
    if let Some(location) = cache.location() {
        let root = location.canonicalize().unwrap_or_else(|_| location.clone());
        let here = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
        if here.starts_with(&root) {
            let _ = writeln!(
                stderr,
                "sentinel: cannot {verb} cache: refusing to delete inside the current working directory ({})",
                here.display()
            );
            return ExitCode::from(errors::EXIT_OPERATIONAL);
        }
    }
    let result = match action {
        cli::CacheAction::Path => unreachable!("returned above"),
        cli::CacheAction::Clear => cache.clear(),
        cli::CacheAction::Prune { older_than } => cache.prune(std::time::Duration::from_secs(
            older_than.saturating_mul(24 * 3600),
        )),
    };
    let stats = match result {
        Ok(stats) => stats,
        Err(error) => {
            let _ = writeln!(stderr, "sentinel: cannot {verb} cache: {error}");
            return ExitCode::from(errors::EXIT_OPERATIONAL);
        }
    };
    let noun = if stats.entries == 1 {
        "entry"
    } else {
        "entries"
    };
    let root = cache.location().unwrap_or_default();
    let report = match action {
        cli::CacheAction::Path => unreachable!("returned above"),
        cli::CacheAction::Clear => format!(
            "cleared {} {noun} ({} bytes) from {}",
            stats.entries,
            stats.bytes,
            root.display()
        ),
        cli::CacheAction::Prune { older_than } => format!(
            "pruned {} {noun} older than {older_than} days ({} bytes) from {}",
            stats.entries,
            stats.bytes,
            root.display()
        ),
    };
    if writeln!(stdout, "{report}").is_err() {
        let _ = writeln!(stderr, "sentinel: cannot write cache {verb} report");
        return ExitCode::from(errors::EXIT_OPERATIONAL);
    }
    ExitCode::SUCCESS
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
    // `cache` is a side command beside `scan`: it never enters the scan
    // pipeline, so no discovery, network, or repository access happens.
    if let Command::Cache { action } = &cli.command {
        return run_cache(action, cwd, stdout, stderr);
    }
    let Command::Scan {
        ci,
        offline,
        output,
        report,
        explain,
        exclude,
        fail_under,
        baseline,
        update_baseline,
        no_cache,
        path,
    } = cli.command
    else {
        unreachable!("`Completions` returns above, so only `Scan` reaches here");
    };
    let mode = if ci {
        discovery::Mode::Ci
    } else {
        discovery::Mode::Local
    };

    // Scan target (S4): the positional PATH resolves against the invoking
    // cwd and becomes the discovery root. Everything repository-relative —
    // the Git top level, the project `sentinel.toml`, `.sentinelignore`,
    // and `--ci` hermeticity — therefore roots at the *target* checkout,
    // never the caller's. With the default `.` the target is the cwd, so
    // today's command is unchanged. `--report` below stays resolved against
    // the invoking cwd, preserving its existing routing.
    let target = cwd.join(&path);
    let discovered = match discovery::Git::new().discover(&target, mode) {
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
    // Layered configuration (T1/T2/T4): CLI values, then the project
    // `sentinel.toml`, then the user-level file at the caller-chosen path —
    // `None` skips it, which keeps hermetic tests immune to the developer's
    // home directory. Excludes union across levels while `fail_under` and
    // `baseline` override; the same merged excludes apply in both modes, so
    // `--ci` stays hermetic.
    let (configured, config_diagnostics) =
        config::resolve_full_with(&root, &exclude, fail_under, baseline, user_config, cwd);
    let configured_excludes = configured.excludes;
    // The winning baseline path (T4), if any level named one: CLI over
    // project over user, resolved per level (project against the target
    // root, CLI and user against the invoking directory).
    let baseline_path = configured.baseline;
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
    // failures degrade to diagnostics (0/1), never Exit 2. `--no-cache`
    // opts out of every cache read and write by handing the engine no
    // cache at all, so a no-cache scan reports the same findings as a
    // warm-cache scan (both consult the network) while touching nothing.
    let dep_cache = if no_cache {
        None
    } else {
        cache::XdgCache::new()
    };
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

    // Baseline of accepted findings (S5): keys are location-independent
    // (`Finding::baseline_key`), so moves and renames stay accepted while
    // changed content reports fresh. Accepted findings still render —
    // marked per format — but never fail the build; stale entries warn.
    // `--update-baseline` rewrites the file from this scan's findings
    // first and reports against it, so the same run already shows the
    // state it wrote; it is the only write this tool performs besides
    // the XDG cache.
    let mut accepted: BTreeSet<String> = BTreeSet::new();
    if update_baseline {
        let Some(path) = baseline_path else {
            let _ = writeln!(
                stderr,
                "sentinel: cannot update baseline: no baseline file given (pass --baseline <PATH> or set the `baseline` key)"
            );
            return ExitCode::from(errors::EXIT_OPERATIONAL);
        };
        let keys: BTreeSet<String> = findings.iter().map(|f| f.baseline_key()).collect();
        let ordered: Vec<String> = keys.iter().cloned().collect();
        match config::write_baseline(&path, &ordered) {
            Ok(count) => {
                diagnostics.push(Diagnostic::baseline_updated(
                    &path.display().to_string(),
                    count,
                ));
                accepted = keys;
            }
            Err(reason) => {
                let _ = writeln!(
                    stderr,
                    "sentinel: cannot write baseline {}: {reason}",
                    path.display()
                );
                return ExitCode::from(errors::EXIT_OPERATIONAL);
            }
        }
    } else if let Some(path) = baseline_path {
        let (known, invalid) = config::load_baseline(&path, &root);
        diagnostics.extend(invalid);
        let current: BTreeSet<String> = findings.iter().map(|f| f.baseline_key()).collect();
        for stale in known.difference(&current) {
            diagnostics.push(Diagnostic::baseline_stale(stale));
        }
        accepted = known.intersection(&current).cloned().collect();
    }

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
        // Without advisories or acceptance the original renderer runs, so those bytes are
        // identical by construction, not just by delegation.
        OutputFormat::Terminal if advisories.is_empty() && accepted.is_empty() => {
            render::render_findings(&findings)
        }
        OutputFormat::Terminal => render::render_terminal(&findings, &advisories, &accepted),
        OutputFormat::Json | OutputFormat::Sarif => {
            let rendered = match output {
                // The complete path keeps the original renderer, so clean
                // bytes are identical by construction, not just by delegation.
                OutputFormat::Json if !incomplete && accepted.is_empty() => {
                    render::render_json(&findings)
                }
                OutputFormat::Json => {
                    render::render_json_with_status_and_accepted(&findings, incomplete, &accepted)
                }
                OutputFormat::Sarif if !incomplete && accepted.is_empty() => {
                    render::render_sarif(&findings)
                }
                OutputFormat::Sarif => {
                    render::render_sarif_with_status_and_accepted(&findings, incomplete, &accepted)
                }
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

    // Exit policy (S3) with baseline acceptance (S5): only *unaccepted*
    // findings at or above the threshold fail the build — accepting a
    // finding quiets it without hiding it; `none` is report-only. Scans
    // that did not run already returned exit 2 above, and diagnostics
    // (including `baseline-stale`) never reach this decision.
    if findings_fail_build(&findings, policy, &accepted) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Whether a completed scan's findings fail the build under `policy`: at
/// least one *unaccepted* finding at or above the threshold severity.
/// Baseline-accepted findings still report, but they never count here —
/// otherwise accepting would be pointless. Severity ordering comes from
/// [`finding::Severity`]'s `Ord`, so the comparison cannot drift from the
/// finding model; `None` (report-only) never fails.
fn findings_fail_build(
    findings: &[Finding],
    policy: FailUnder,
    accepted: &BTreeSet<String>,
) -> bool {
    match policy.threshold() {
        Some(minimum) => findings.iter().any(|finding| {
            !accepted.contains(&finding.baseline_key()) && finding.severity >= minimum
        }),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{ScanDeps, run_inner, run_with_dep_client, run_with_deps};
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
        // a usage error. A bare positional is NOT unknown: since S4
        // `scan [PATH]` scans that directory, `scan file.txt` is a scan
        // target (covered by the S4 path tests), and only unknown flags
        // stay usage errors here.
        let (code, out, err) = run_scan(&["scan", "--nope"], Path::new("."));
        assert_eq!(code, ExitCode::from(2));
        assert!(out.is_empty(), "stdout must stay empty");
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("unexpected argument")
        );
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

    /// `cache path` prints the resolved location and nothing else: the
    /// only state the tool keeps becomes visible without touching it.
    #[test]
    fn cache_path_prints_the_resolved_location() {
        let Some(cache) = crate::cache::XdgCache::new() else {
            let (code, out, err) = run_scan(&["cache", "path"], Path::new("."));
            assert_eq!(code, ExitCode::from(2));
            assert!(out.is_empty());
            assert!(!err.is_empty());
            return;
        };
        let expected = format!("{}\n", cache.location().unwrap().display());
        let (code, out, err) = run_scan(&["cache", "path"], Path::new("."));
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(String::from_utf8(out).unwrap(), expected);
        assert!(err.is_empty(), "printing the path warns about nothing");
    }

    /// `--no-cache` under `--offline` degrades instead of refusing: the
    /// cache is the only advisory source offline, so every pin warns as
    /// `osv-unavailable` while secrets findings still report and fail the
    /// build. The pin is synthetic-unique, so no real cache could satisfy
    /// it — the miss proves nothing was read.
    #[test]
    fn no_cache_offline_scan_degrades_with_warning() {
        let (_dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("requirements.txt"),
            b"sentinel-nocache-probe==9.9.9\n",
        );
        write_tracked(
            &root,
            OsStr::new("env.example"),
            b"token = sk-synthetic-1234567890\n",
        );
        let (code, out, err) = run_scan(&["scan", "--offline", "--no-cache"], &root);
        assert_eq!(
            code,
            ExitCode::from(1),
            "secrets findings still fail the build"
        );
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("SECRET-synthetic-token")
        );
        assert!(
            String::from_utf8(err).unwrap().contains("osv-unavailable"),
            "the missing advisory source is disclosed, never silent"
        );
    }

    /// Runs inside the re-execed child (see below): a private
    /// `XDG_CACHE_HOME` makes the cache hermetic without racing parallel
    /// tests over process environment. Two phases share the one re-exec:
    /// the `cache` CLI rules (`path` prints, empty `prune` succeeds,
    /// `clear` removes and reports, standing inside refuses), then the
    /// `--no-cache` rules (no reads, no writes, findings match the
    /// warm-cache scan, default still reads the cache).
    fn cache_s6_child_main() {
        let expected = format!(
            "{}\n",
            crate::cache::XdgCache::new()
                .unwrap()
                .location()
                .unwrap()
                .display()
        );
        let run = |args: &[&str], cwd: &Path| {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run_inner(&SecretsEngine::new(), &args, cwd, &mut out, &mut err, None);
            (code, out, err)
        };
        let here = std::env::current_dir().unwrap();
        let (code, out, err) = run(&["cache", "path"], &here);
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(String::from_utf8(out).unwrap(), expected);
        assert!(err.is_empty());
        // Prune with nothing to remove is a success, not an error.
        let (code, out, err) = run(&["cache", "prune"], &here);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            String::from_utf8(out).unwrap().contains("pruned 0"),
            "an empty prune reports zero"
        );
        assert!(err.is_empty());
        // Seed one entry, then clear removes it and says what it removed.
        let cache = crate::cache::XdgCache::new().unwrap();
        let payload = br#"{"id":"GHSA-1234","summary":"t"}"#.to_vec();
        assert!(cache.put("npm", "lodash", "4.17.20", &payload).unwrap());
        let entry_dir = cache
            .location()
            .unwrap()
            .join("osv")
            .join("v1")
            .join("npm")
            .join("lodash");
        assert!(entry_dir.exists());
        let (code, out, err) = run(&["cache", "clear"], &here);
        assert_eq!(code, ExitCode::SUCCESS);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("cleared 1 entry") && text.contains(&payload.len().to_string()),
            "clear reports the entry count and bytes: {text:?}"
        );
        assert!(err.is_empty());
        assert!(!entry_dir.exists(), "the entry is gone");
        assert!(
            cache.location().unwrap().exists(),
            "clear empties the root, never removes it"
        );
        // Clearing from inside the cache refuses instead of deleting.
        assert!(cache.put("npm", "lodash", "4.17.20", &payload).unwrap());
        let inside = cache.location().unwrap();
        let (code, out, err) = run(&["cache", "clear"], &inside);
        assert_eq!(code, ExitCode::from(2), "standing inside refuses");
        assert!(out.is_empty());
        assert!(
            String::from_utf8(err).unwrap().contains("refusing"),
            "the refusal says why"
        );
        assert!(entry_dir.exists(), "the refused clear deletes nothing");
        // Phase two: the injected OSV client counts its own calls. Seeds
        // one warm entry, then proves `--no-cache` performs no reads (the
        // warm entry is ignored — the network is consulted once) and no
        // writes (the entry bytes are unchanged), while reporting
        // byte-identical findings to the warm-cache scan.
        use crate::explain::DisabledExplainer;
        use crate::osv::client::{OsvApi, Query};
        use crate::osv::validate::Advisory;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountOsv {
            calls: std::sync::Arc<AtomicUsize>,
        }
        impl OsvApi for CountOsv {
            fn query_all(
                &self,
                _qs: &[Query],
            ) -> Result<(Vec<Vec<Advisory>>, Vec<crate::finding::Diagnostic>), String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok((
                    vec![vec![Advisory {
                        id: "GHSA-NOCACHE-PROBE-1".to_string(),
                        summary: "synthetic probe advisory".to_string(),
                        severity: crate::finding::Severity::Critical,
                    }]],
                    vec![],
                ))
            }
            fn vuln(&self, _id: &str) -> Result<Advisory, String> {
                Err("no detail".into())
            }
        }
        let (_dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("package-lock.json"),
            r#"{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#.as_bytes(),
        );
        let cache = crate::cache::XdgCache::new().unwrap();
        let seed = br#"[{"id":"GHSA-NOCACHE-PROBE-1","summary":"synthetic probe advisory","severity":[{"type":"CVSS_V3","score":"9.8"}]}]"#.to_vec();
        assert!(cache.put("npm", "lodash", "4.17.20", &seed).unwrap());
        let entry = cache
            .location()
            .unwrap()
            .join("osv")
            .join("v1")
            .join("npm")
            .join("lodash")
            .join("4%2E17%2E20.json");
        let run_scan_with = |args: &[&str], osv: CountOsv| {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run_with_dep_client(
                &SecretsEngine::new(),
                &DisabledExplainer,
                ScanDeps {
                    osv: Some(Box::new(osv)),
                    user_config: None,
                },
                &args,
                &root,
                &mut out,
                &mut err,
            );
            (code, out, err)
        };
        // The stub is moved into the seam, so each probe shares its call
        // counter through an `Arc` that outlives the move.
        let warm_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let (warm_code, warm_out, warm_err) = run_scan_with(
            &["scan"],
            CountOsv {
                calls: warm_calls.clone(),
            },
        );
        assert_eq!(
            warm_code,
            ExitCode::from(1),
            "the advisory finding fails the build"
        );
        assert!(warm_err.is_empty(), "a warm hit warns about nothing");
        assert_eq!(
            warm_calls.load(Ordering::SeqCst),
            0,
            "the warm scan serves the entry from cache without dialing out"
        );
        let before = std::fs::read(&entry).unwrap();
        let cold_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let (cold_code, cold_out, cold_err) = run_scan_with(
            &["scan", "--no-cache"],
            CountOsv {
                calls: cold_calls.clone(),
            },
        );
        assert_eq!(
            cold_calls.load(Ordering::SeqCst),
            1,
            "the no-cache scan ignores the warm entry and consults the network once"
        );
        assert_eq!((cold_code, cold_err), (warm_code, warm_err.clone()));
        assert_eq!(
            cold_out, warm_out,
            "no-cache findings match the warm-cache scan byte for byte"
        );
        assert_eq!(
            std::fs::read(&entry).unwrap(),
            before,
            "the no-cache scan writes nothing back"
        );
        // PRESERVE: the scan without the new flag still serves the warm
        // cache — the opt-out changed nothing about the default path.
        let default_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let (default_code, default_out, default_err) = run_scan_with(
            &["scan"],
            CountOsv {
                calls: default_calls.clone(),
            },
        );
        assert_eq!(
            (default_code, default_out, default_err),
            (warm_code, warm_out, warm_err)
        );
        assert_eq!(
            default_calls.load(Ordering::SeqCst),
            0,
            "the default scan still reads the cache"
        );
    }

    #[test]
    fn cache_management_shares_one_isolated_child() {
        if std::env::var("SENTINEL_CACHE_CHILD").is_ok() {
            cache_s6_child_main();
            return;
        }
        let xdg = TempDir::new().unwrap();
        let exe = std::env::current_exe().unwrap();
        let output = std::process::Command::new(exe)
            .arg("--exact")
            .arg("tests::cache_management_shares_one_isolated_child")
            .env("SENTINEL_CACHE_CHILD", "1")
            .env("XDG_CACHE_HOME", xdg.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child must complete its cache assertions: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the child ran its assertions: {}",
            String::from_utf8_lossy(&output.stdout)
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

    /// Scan-target helpers (S4): a secret-bearing repository scanned from a
    /// different cwd. The observable is always a finding appearing or
    /// disappearing, never a file name in the output (L6).
    fn secret_target_repo() -> (TempDir, PathBuf) {
        let (dir, root) = temp_repo();
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
        (dir, root)
    }

    /// A positional PATH scans the target repository instead of the cwd:
    /// invoked from a clean repository, the target's findings report.
    #[test]
    fn scan_path_argument_scans_the_target_repository() {
        let (_caller_dir, caller_root) = temp_repo();
        write_tracked(&caller_root, OsStr::new("clean.txt"), b"no secrets");
        let (_target_dir, target_root) = secret_target_repo();
        let target = target_root.to_str().unwrap();
        let (code, out, err) = run_scan(&["scan", target], &caller_root);
        assert_eq!(code, ExitCode::from(1), "target findings fail the build");
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("keep.env:1:"), "stdout: {out_text}");
        assert!(out_text.contains("skip.log:1:"), "stdout: {out_text}");
        assert!(
            String::from_utf8(err).unwrap().is_empty(),
            "no diagnostics on this path"
        );
    }

    /// A relative PATH resolves against the invoking cwd: from the parent
    /// directory, naming the target directory scans that checkout.
    #[test]
    fn scan_relative_path_resolves_against_the_invoking_cwd() {
        let parent = TempDir::new().unwrap();
        let target_dir = parent.path().join("target");
        std::fs::create_dir_all(&target_dir).unwrap();
        crate::test_util::git(&target_dir, ["init", "-q"]);
        write_tracked(
            &target_dir,
            OsStr::new("keep.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        let (code, out, _) = run_scan(&["scan", "target"], parent.path());
        assert_eq!(code, ExitCode::from(1));
        assert!(
            String::from_utf8(out).unwrap().contains("keep.env:1:"),
            "relative PATH must resolve against the invoking cwd"
        );
    }

    /// The default is unchanged: with no PATH, the scan covers the cwd — a
    /// clean caller stays clean even when a secret-bearing checkout exists
    /// next to it.
    #[test]
    fn scan_without_path_still_scans_the_cwd() {
        let (_caller_dir, caller_root) = temp_repo();
        write_tracked(&caller_root, OsStr::new("clean.txt"), b"no secrets");
        let (_target_dir, _target_root) = secret_target_repo();
        let (code, out, err) = run_scan(&["scan"], &caller_root);
        assert_eq!(code, ExitCode::SUCCESS, "clean cwd means exit 0");
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    /// A PATH outside any repository fails exactly like a non-repository
    /// cwd: exit 2, a clear stderr message, empty stdout.
    #[test]
    fn scan_non_repository_path_fails_like_non_repository_cwd() {
        let plain_dir = TempDir::new().unwrap();
        let (plain_code, plain_out, plain_err) = run_scan(&["scan"], plain_dir.path());
        assert_eq!(plain_code, ExitCode::from(2));
        assert!(plain_out.is_empty());
        let plain_err = String::from_utf8(plain_err).unwrap();
        assert!(plain_err.contains("not inside a git repository"));

        let (_dir, root) = temp_repo();
        let outside = TempDir::new().unwrap();
        let outside_str = outside.path().to_str().unwrap();
        let (code, out, err) = run_scan(&["scan", outside_str], &root);
        assert_eq!(code, ExitCode::from(2), "same exit as a non-repo cwd");
        assert!(out.is_empty(), "stdout must stay empty");
        let err_text = String::from_utf8(err).unwrap();
        assert!(
            err_text.contains("not inside a git repository"),
            "same shape of error: {err_text}"
        );
    }

    /// The target's project config applies when scanned from elsewhere: a
    /// `sentinel.toml` in the target excluding a file hides its finding.
    #[test]
    fn scan_applies_the_target_project_config() {
        let (_caller_dir, caller_root) = temp_repo();
        let (_target_dir, target_root) = secret_target_repo();
        write_untracked(
            &target_root,
            OsStr::new("sentinel.toml"),
            b"exclude = [\"*.log\"]\n",
        );
        let target = target_root.to_str().unwrap();
        let (code, out, _) = run_scan(&["scan", target], &caller_root);
        assert_eq!(code, ExitCode::from(1), "one finding remains");
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("keep.env:1:"), "stdout: {out_text}");
        assert!(
            !out_text.contains("skip.log"),
            "target config excluded: {out_text}"
        );
    }

    /// The caller's project config must not leak into the target scan: a
    /// repository without config reports every finding even when the
    /// invoking cwd excludes the same pattern.
    #[test]
    fn scan_ignores_the_caller_project_config() {
        let (_caller_dir, caller_root) = temp_repo();
        write_untracked(
            &caller_root,
            OsStr::new("sentinel.toml"),
            b"exclude = [\"*.log\"]\n",
        );
        let (_target_dir, target_root) = secret_target_repo();
        let target = target_root.to_str().unwrap();
        let (code, out, err) = run_scan(&["scan", target], &caller_root);
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("keep.env:1:"), "stdout: {out_text}");
        assert!(
            out_text.contains("skip.log:1:"),
            "caller config must not hide target findings: {out_text}"
        );
        assert!(
            String::from_utf8(err).unwrap().is_empty(),
            "the caller config contributes no diagnostics either"
        );
    }

    /// The target's `.sentinelignore` applies, and the caller's does not: a
    /// target-side ignore hides its file while a caller-side ignore naming
    /// the kept file is ignored.
    #[test]
    fn scan_applies_the_target_sentinelignore_not_the_caller_one() {
        let (_caller_dir, caller_root) = temp_repo();
        write_untracked(&caller_root, OsStr::new(".sentinelignore"), b"keep.env\n");
        let (_target_dir, target_root) = temp_repo();
        write_untracked(&target_root, OsStr::new(".sentinelignore"), b"*.secret\n");
        write_tracked(
            &target_root,
            OsStr::new("keep.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        write_tracked(
            &target_root,
            OsStr::new("skipped.secret"),
            b"token = sk-synthetic-1234567890\n",
        );
        let target = target_root.to_str().unwrap();
        let (code, out, _) = run_scan(&["scan", target], &caller_root);
        assert_eq!(code, ExitCode::from(1), "one finding remains");
        let out_text = String::from_utf8(out).unwrap();
        assert!(
            out_text.contains("keep.env:1:"),
            "caller ignore must not apply: {out_text}"
        );
        assert!(
            !out_text.contains("skipped.secret"),
            "target ignore applies: {out_text}"
        );
    }

    /// `--ci` hermeticity is evaluated at the target: the target's
    /// `.git/info/exclude` hides an untracked secret locally but not under
    /// `--ci`, however the scan is invoked.
    #[test]
    fn scan_ci_hermeticity_applies_to_the_target() {
        let (_caller_dir, caller_root) = temp_repo();
        let (_target_dir, target_root) = temp_repo();
        write_tracked(
            &target_root,
            OsStr::new("keep.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        let untracked = target_root.join("skipped.env");
        std::fs::write(&untracked, b"token = sk-synthetic-1234567890\n").unwrap();
        let info = target_root.join(".git").join("info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(info.join("exclude"), b"skipped.env\n").unwrap();
        let target = target_root.to_str().unwrap();
        let (code, out, _) = run_scan(&["scan", target], &caller_root);
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("keep.env:1:"), "stdout: {out_text}");
        assert!(
            !out_text.contains("skipped.env"),
            "local mode honors the target info/exclude: {out_text}"
        );
        let (code, out, _) = run_scan(&["scan", "--ci", target], &caller_root);
        assert_eq!(code, ExitCode::from(1));
        let out_text = String::from_utf8(out).unwrap();
        assert!(
            out_text.contains("skipped.env:1:"),
            "--ci disables the target info/exclude: {out_text}"
        );
    }

    /// Baseline helpers (S5): the baseline file lives outside the scanned
    /// repository, so its own bytes never enter the scan, in exactly the
    /// format `--update-baseline` writes.
    fn baseline_outside_repo() -> (TempDir, PathBuf, String) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("accepted.json");
        let arg = path.to_str().unwrap().to_string();
        (dir, path, arg)
    }

    /// A repository whose only finding is the medium synthetic token.
    fn token_only_repo() -> (TempDir, PathBuf) {
        let (dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("token.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        (dir, root)
    }

    /// Accepts every current finding by regenerating the baseline, and
    /// asserts the update run already reports against what it wrote.
    fn accept_all(root: &Path, baseline_arg: &str) {
        let (code, out, err) = run_scan(
            &["scan", "--baseline", baseline_arg, "--update-baseline"],
            root,
        );
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "the update run reports against the baseline it just wrote"
        );
        assert!(
            String::from_utf8(out).unwrap().contains("[accepted]"),
            "the update run marks what it accepted"
        );
        assert!(
            String::from_utf8(err).unwrap().contains("baseline-updated"),
            "the update reports what it wrote"
        );
    }

    /// The semantic heart (S5): a repository whose only finding is accepted
    /// exits 0 under the default policy — accepting must actually quiet the
    /// build — and stops exiting 0 when the baseline is removed.
    #[test]
    fn accepted_finding_does_not_fail_the_build_but_resurfaces_without_baseline() {
        let (_dir, root) = token_only_repo();
        let plain = run_scan(&["scan"], &root);
        assert_eq!(
            plain.0,
            ExitCode::from(1),
            "unaccepted finding fails the build"
        );
        let plain_text = String::from_utf8(plain.1).unwrap();
        assert!(plain_text.contains("SECRET-synthetic-token"));
        assert!(
            !plain_text.contains("SECRET-aws-access-key"),
            "exactly one finding: {plain_text}"
        );
        let (_outside, baseline, bl) = baseline_outside_repo();
        accept_all(&root, &bl);
        assert!(baseline.exists(), "the update writes the file it is given");
        let (code, out, err) = run_scan(&["scan", "--baseline", &bl], &root);
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "an accepted finding must not fail the build"
        );
        let out_text = String::from_utf8(out).unwrap();
        assert!(
            out_text.contains("SECRET-synthetic-token"),
            "accepted findings are still reported: {out_text}"
        );
        assert!(
            out_text.contains("[accepted]"),
            "acceptance is visible: {out_text}"
        );
        assert!(
            String::from_utf8(err).unwrap().is_empty(),
            "no diagnostics on the accepted path"
        );
        std::fs::remove_file(&baseline).unwrap();
        let (code, out, err) = run_scan(&["scan", "--baseline", &bl], &root);
        assert_eq!(
            code,
            ExitCode::from(1),
            "without the baseline the same finding fails again"
        );
        assert!(
            String::from_utf8(err).unwrap().contains("baseline-invalid"),
            "the missing file warns once instead of vanishing silently"
        );
        assert!(
            !String::from_utf8(out).unwrap().contains("[accepted]"),
            "nothing is marked without a baseline"
        );
    }

    /// Accepted and unaccepted findings report side by side: the baseline
    /// built in a token-only repository accepts the token everywhere, while
    /// the unknown key still fails the build unmarked.
    #[test]
    fn accepted_and_unaccepted_findings_report_side_by_side() {
        let (_d1, r1) = token_only_repo();
        let (_outside, _baseline, bl) = baseline_outside_repo();
        accept_all(&r1, &bl);
        let (_d2, r2) = secret_repo();
        let (code, out, _) = run_scan(&["scan", "--baseline", &bl], &r2);
        assert_eq!(
            code,
            ExitCode::from(1),
            "the unaccepted key still fails the build"
        );
        let text = String::from_utf8(out).unwrap();
        let token_lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("SECRET-synthetic-token"))
            .collect();
        assert_eq!(token_lines.len(), 1, "one token finding: {text:?}");
        assert!(
            token_lines[0].contains("[accepted]"),
            "the known token is marked: {text:?}"
        );
        let key_lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("SECRET-aws-access-key"))
            .collect();
        assert_eq!(key_lines.len(), 1, "one key finding: {text:?}");
        assert!(
            !key_lines[0].contains("[accepted]"),
            "the unknown key stays unmarked: {text:?}"
        );
    }

    /// A rename must not resurrect an accepted finding (L4): the baseline
    /// key carries no location, so moving the file keeps it accepted.
    #[test]
    fn accepted_finding_survives_a_file_rename() {
        let (_dir, root) = temp_repo();
        write_tracked(
            &root,
            OsStr::new("a.env"),
            b"token = sk-synthetic-1234567890\n",
        );
        let (_outside, _baseline, bl) = baseline_outside_repo();
        accept_all(&root, &bl);
        crate::test_util::git(&root, ["mv", "a.env", "b.env"]);
        let (code, out, err) = run_scan(&["scan", "--baseline", &bl], &root);
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "a rename must not resurrect an accepted finding"
        );
        let out_text = String::from_utf8(out).unwrap();
        assert!(
            out_text.contains("b.env:1:"),
            "the finding moved: {out_text}"
        );
        assert!(
            !out_text.contains("a.env"),
            "the old path is gone: {out_text}"
        );
        assert!(
            out_text.contains("[accepted]"),
            "still accepted: {out_text}"
        );
        assert!(String::from_utf8(err).unwrap().is_empty());
    }

    /// A stale entry — a fingerprint matching no current finding — is
    /// reported on stderr, and it never fails the build in either
    /// direction: accepted-only still exits 0, unaccepted still exits 1.
    #[test]
    fn stale_baseline_entries_are_reported_without_failing_the_build() {
        let (_dir, root) = token_only_repo();
        let (_outside, baseline, bl) = baseline_outside_repo();
        accept_all(&root, &bl);
        let stale = "secrets/SECRET-synthetic-token/".to_string() + &"0".repeat(64);
        let text = std::fs::read_to_string(&baseline).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["fingerprints"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::String(stale.clone()));
        std::fs::write(&baseline, serde_json::to_vec(&value).unwrap()).unwrap();
        let (code, out, err) = run_scan(&["scan", "--baseline", &bl], &root);
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "stale entries never fail the build"
        );
        let err_text = String::from_utf8(err).unwrap();
        assert!(err_text.contains("baseline-stale"), "reported: {err_text}");
        assert!(err_text.contains(&stale), "names the entry: {err_text}");
        assert!(
            String::from_utf8(out).unwrap().contains("[accepted]"),
            "the live finding stays accepted"
        );
        // A baseline of only the stale entry: the finding is unaccepted.
        std::fs::write(
            &baseline,
            serde_json::json!({"schema_version": "1.0.0", "fingerprints": [stale]}).to_string(),
        )
        .unwrap();
        let (code, out, err) = run_scan(&["scan", "--baseline", &bl], &root);
        assert_eq!(code, ExitCode::from(1), "unaccepted finding still fails");
        assert!(
            String::from_utf8(err).unwrap().contains("baseline-stale"),
            "stale still reported"
        );
        assert!(
            !String::from_utf8(out).unwrap().contains("[accepted]"),
            "nothing marked without a live entry"
        );
    }

    /// A baseline that is not JSON warns exactly once and the scan
    /// continues with nothing accepted — a typo never silently passes.
    #[test]
    fn malformed_baseline_warns_once_and_scan_continues() {
        let (_dir, root) = token_only_repo();
        let (_outside, baseline, bl) = baseline_outside_repo();
        std::fs::write(&baseline, b"not json{{").unwrap();
        let (code, out, err) = run_scan(&["scan", "--baseline", &bl], &root);
        assert_eq!(
            code,
            ExitCode::from(1),
            "nothing accepted means the finding fails"
        );
        let err_text = String::from_utf8(err).unwrap();
        assert_eq!(
            err_text.matches("baseline-invalid").count(),
            1,
            "exactly one diagnostic: {err_text}"
        );
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("SECRET-synthetic-token"));
        assert!(!out_text.contains("[accepted]"));
    }

    /// Regenerating without a baseline path is an operational error: there
    /// is no file the tool could honestly claim to have written.
    #[test]
    fn update_baseline_without_a_path_is_an_operational_error() {
        let (_dir, root) = token_only_repo();
        let (code, out, err) = run_scan(&["scan", "--update-baseline"], &root);
        assert_eq!(code, ExitCode::from(2), "no file to write means exit 2");
        assert!(out.is_empty(), "stdout must stay empty");
        assert!(
            String::from_utf8(err).unwrap().contains("baseline"),
            "the error names the missing baseline"
        );
    }

    /// The `baseline` config key flows end to end: the project file accepts
    /// the finding with no flag, and the CLI flag wins over the project key.
    #[test]
    fn project_config_baseline_accepts_and_cli_wins_over_it() {
        let (_dir, root) = token_only_repo();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"baseline = \"accepted.json\"\n",
        );
        // No flag: the project key selects the file, relative to the repo.
        let (code, _, _) = run_scan(&["scan", "--update-baseline"], &root);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            root.join("accepted.json").exists(),
            "config-relative writes root at the repository"
        );
        let (code, out, _) = run_scan(&["scan"], &root);
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "the configured baseline accepts the finding"
        );
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("[accepted]"));
        assert!(
            !out_text.contains("accepted.json"),
            "the baseline file itself adds no findings: {out_text}"
        );
        // CLI points at an empty baseline: the project key loses.
        let (_outside, empty, empty_arg) = baseline_outside_repo();
        std::fs::write(
            &empty,
            serde_json::json!({"schema_version": "1.0.0", "fingerprints": []}).to_string(),
        )
        .unwrap();
        let (code, _, err) = run_scan(&["scan", "--baseline", &empty_arg], &root);
        assert_eq!(
            code,
            ExitCode::from(1),
            "CLI --baseline wins over the project key"
        );
        assert!(String::from_utf8(err).unwrap().is_empty());
    }

    /// The target's project baseline applies when scanning another checkout
    /// (S4): the config value roots at the target, never the caller.
    #[test]
    fn scan_applies_the_target_project_baseline() {
        let (_caller_dir, caller_root) = temp_repo();
        write_tracked(&caller_root, OsStr::new("clean.txt"), b"no secrets");
        let (_target_dir, target_root) = token_only_repo();
        write_untracked(
            &target_root,
            OsStr::new("sentinel.toml"),
            b"baseline = \"accepted.json\"\n",
        );
        let target = target_root.to_str().unwrap();
        let (code, _, _) = run_scan(&["scan", target, "--update-baseline"], &caller_root);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            target_root.join("accepted.json").exists(),
            "the update lands in the target checkout"
        );
        let (code, out, err) = run_scan(&["scan", target], &caller_root);
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "the target baseline accepts the finding"
        );
        assert!(String::from_utf8(out).unwrap().contains("[accepted]"));
        assert!(String::from_utf8(err).unwrap().is_empty());
    }

    /// An empty baseline file is neutral: the scan is byte-identical to
    /// having no baseline at all (stdout, stderr, and exit code).
    #[test]
    fn empty_baseline_file_leaves_the_scan_unchanged() {
        let (_dir, root) = secret_repo();
        let plain = run_scan(&["scan"], &root);
        assert_eq!(plain.0, ExitCode::from(1));
        let (_outside, empty, empty_arg) = baseline_outside_repo();
        std::fs::write(
            &empty,
            serde_json::json!({"schema_version": "1.0.0", "fingerprints": []}).to_string(),
        )
        .unwrap();
        let with_empty = run_scan(&["scan", "--baseline", &empty_arg], &root);
        assert_eq!(plain, with_empty, "an empty baseline changes nothing");
    }

    /// Accepted findings do not count toward `--fail-under`: with the
    /// critical finding accepted, a lone unaccepted medium cannot fail
    /// `high` — yet it still fails the default policy on its own merit.
    #[test]
    fn accepted_findings_do_not_count_toward_fail_under() {
        let (_d1, r1) = critical_only_repo();
        let (_outside, _baseline, bl) = baseline_outside_repo();
        accept_all(&r1, &bl);
        let (_d2, r2) = secret_repo();
        let (code, out, _) = run_scan(&["scan", "--baseline", &bl, "--fail-under", "high"], &r2);
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "the accepted critical must not reach the threshold"
        );
        let out_text = String::from_utf8(out).unwrap();
        assert!(out_text.contains("SECRET-aws-access-key"));
        assert!(out_text.contains("SECRET-synthetic-token"));
        let (code, _, _) = run_scan(&["scan", "--baseline", &bl], &r2);
        assert_eq!(
            code,
            ExitCode::from(1),
            "the unaccepted medium still fails the default policy"
        );
    }

    /// Machine formats mark acceptance without changing shape: JSON gains
    /// `"accepted": true` on accepted findings only, SARIF the standard
    /// external suppression — and both still exit 0 when all is accepted.
    #[test]
    fn accepted_findings_are_marked_in_json_and_sarif_reports() {
        let (_dir, root) = token_only_repo();
        let (_outside, _baseline, bl) = baseline_outside_repo();
        accept_all(&root, &bl);
        let (code, out, _) = run_scan(&["scan", "--output", "json", "--baseline", &bl], &root);
        assert_eq!(code, ExitCode::SUCCESS);
        let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(report["schema_version"], "1.0.0");
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["accepted"], true);
        let (code, out, _) = run_scan(&["scan", "--output", "sarif", "--baseline", &bl], &root);
        assert_eq!(code, ExitCode::SUCCESS);
        let log: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let results = log["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]["suppressions"],
            serde_json::json!([{"kind": "external", "status": "accepted"}])
        );
    }

    /// Acceptance holds under `--ci` and `--offline`: neither mode changes
    /// what the baseline accepts or how it reports.
    #[test]
    fn baseline_acceptance_holds_under_ci_and_offline() {
        let (_dir, root) = token_only_repo();
        let (_outside, _baseline, bl) = baseline_outside_repo();
        accept_all(&root, &bl);
        for extra in [&["--ci"][..], &["--offline"][..]] {
            let mut args = vec!["scan", "--baseline", &bl];
            args.extend(extra.iter());
            let (code, out, err) = run_scan(&args, &root);
            assert_eq!(code, ExitCode::SUCCESS, "mode {extra:?}");
            assert!(
                String::from_utf8(out).unwrap().contains("[accepted]"),
                "mode {extra:?}"
            );
            assert!(String::from_utf8(err).unwrap().is_empty(), "mode {extra:?}");
        }
    }
}
