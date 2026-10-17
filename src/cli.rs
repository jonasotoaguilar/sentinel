//! Command-line surface: exactly three commands, `sentinel scan`,
//! `sentinel cache <path|clear|prune>`, and `sentinel completions <shell>`.
//!
//! clap owns parsing; every rejected invocation is a usage error (stderr
//! diagnostics, empty stdout, exit 2). `--ci`, `--offline`, `--output`,
//! `--report`, `--exclude`, `--fail-under`, `--baseline`,
//! `--update-baseline`, `--no-cache`, and the advisory-only `--explain`
//! are the only supported scan options; anything else is rejected, so
//! positional arguments and unknown flags cannot silently become no-ops. `completions` accepts only
//! the shells clap_complete generates for this crate.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::finding::Severity;

/// Sentinel — deterministic secrets scanner for Git repositories.
#[derive(Debug, Parser)]
#[command(name = "sentinel", about, version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// The three commands (cli-scan spec: command surface, plus S6 cache
/// management): `scan` does the work, `cache` exposes the only state the
/// tool keeps, and `completions` prints shell scripts.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect and empty the XDG advisory cache — the only state this tool
    /// keeps. Every destructive subcommand deletes only inside the resolved
    /// cache directory (resolved first, containment-checked, then deleted),
    /// never follows symlinks out of it, and reports what it removed.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Print the shell completion script for `<shell>` to stdout.
    ///
    /// A pure side command: no discovery, no scan, no network, no cache,
    /// so it works outside a Git repository.
    Completions {
        /// Shell to generate the completion script for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Scan the Git repository at `[PATH]` for secrets (default: the cwd).
    Scan {
        /// Directory to scan: resolved against the invoking cwd, then the
        /// enclosing Git repository is scanned. The project `sentinel.toml`
        /// and `.sentinelignore` come from the target's top level, never
        /// the caller's, and `--ci` hermeticity applies to the target walk.
        /// Defaults to `.`, so `sentinel scan` scans the cwd unchanged.
        #[arg(default_value = ".", value_name = "PATH")]
        path: PathBuf,
        /// Run with hermetic (CI) ignore sources: parent, global, and
        /// `.git/info/exclude` ambient ignores are disabled.
        #[arg(long)]
        ci: bool,
        /// Disable network and cache writes; use any-age cache only.
        #[arg(long)]
        offline: bool,
        /// Show one advisory line per finding on terminal output.
        /// Advisory-only: never changes findings, severity, ordering, or the
        /// exit code, and is forced off under `--ci` and `--offline`.
        #[arg(long)]
        explain: bool,
        /// Report format: terminal, json, or sarif (default terminal).
        #[arg(long, value_enum, default_value = "terminal")]
        output: OutputFormat,
        /// Exclude files matching a glob from the scan. Repeatable;
        /// patterns use `.gitignore` semantics and are matched against
        /// repo-relative paths after `.sentinelignore` and config excludes.
        #[arg(long, value_name = "GLOB")]
        exclude: Vec<String>,
        /// Write the machine-readable report to a file instead of stdout.
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
        /// Lowest severity that makes a completed scan exit 1: `critical`,
        /// `high`, `medium`, `low`, or `none` for report-only (a completed
        /// scan always exits 0). Defaults to `low`, so any finding exits 1 —
        /// today's behaviour. Also settable as the `fail_under` config key;
        /// the flag wins over project config, which wins over user config.
        /// Diagnostics, and scans that did not run (exit 2), are unaffected.
        #[arg(long, value_enum)]
        fail_under: Option<FailUnder>,
        /// Path to a JSON baseline file listing accepted finding fingerprints
        /// (see `--update-baseline` for the format). Findings whose baseline
        /// key is listed still report — marked `[accepted]` on terminal,
        /// `"accepted": true` in JSON, and an external accepted suppression
        /// in SARIF — but never count toward `--fail-under`. A fingerprint
        /// in the file matching no current finding warns once as
        /// `baseline-stale`. Also settable as the `baseline` config key;
        /// the flag wins over project config, which wins over user config.
        /// Relative project-config values resolve against the repository
        /// root, the flag against the invoking directory. Absent entirely,
        /// the scan behaves exactly as today.
        #[arg(long, value_name = "PATH")]
        baseline: Option<PathBuf>,
        /// Skip the XDG cache entirely: perform no cache reads and no cache
        /// writes. Findings are the same as a scan with a warm cache. Under
        /// `--offline` the cache is the only source of advisory data, so a
        /// no-cache offline scan degrades to `osv-unavailable` warnings for
        /// every dependency pin while secrets findings still report — the
        /// combination is allowed and never exits 2 on its own.
        #[arg(long)]
        no_cache: bool,
        /// Regenerate the baseline file from this scan's findings and report
        /// against it: the file the `--baseline` flag or the `baseline`
        /// config key names is rewritten with every current finding's
        /// fingerprint (sorted, deduplicated), stale entries pruned. The
        /// write is reported as `baseline-updated` on stderr; without any
        /// baseline path the scan exits 2. This is the only write the tool
        /// performs besides the XDG cache.
        #[arg(long)]
        update_baseline: bool,
    },
}

/// The `cache` subcommands (S6): the XDG advisory cache is the only state
/// the tool keeps, and these are how a user sees it and clears it. `path`
/// only prints; `clear` and `prune` delete only inside the resolved cache
/// directory and report the entry count and bytes they removed — a prune
/// that removes nothing still exits 0.
#[derive(Debug, Subcommand)]
pub enum CacheAction {
    /// Print the resolved cache location to stdout, so the cache can be
    /// inspected. Reads nothing and deletes nothing.
    Path,
    /// Empty the cache directory and report what was removed: the entry
    /// count and the reclaimed bytes. Clearing an empty or missing cache
    /// succeeds and reports zero. Refuses rather than guesses when the
    /// resolved location looks wrong (empty, the filesystem root, or the
    /// current working directory).
    Clear,
    /// Remove cache entries not used since the given age and report what
    /// was removed. Last use is approximated by the entry's modification
    /// time. A prune that removes nothing succeeds and reports zero.
    Prune {
        /// Remove entries whose last use is older than this many days.
        /// Defaults to 30: recent advisory data survives while stale
        /// entries are reclaimed.
        #[arg(long, default_value_t = 30, value_name = "DAYS")]
        older_than: u64,
    },
}

/// The accepted `--output` values (cli-scan spec: exactly these three).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
}

/// The `--fail-under` exit policy (exit-policy spec S3): the lowest severity
/// that makes a completed scan exit 1. `None` is report-only: a completed
/// scan always exits 0. Both the flag and the config key are absent by
/// default, which resolves to `Low` — any finding exits 1, today's
/// behaviour exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailUnder {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl Default for FailUnder {
    /// Absence means today's behaviour: any finding fails the build.
    fn default() -> Self {
        Self::Low
    }
}

impl FailUnder {
    /// The minimum severity that fails the build, or `None` for report-only.
    /// The ordering reuses [`Severity`]'s `Ord` (`critical > high > medium >
    /// `low`), so no parallel ranking exists that could drift from the
    /// finding model.
    pub fn threshold(self) -> Option<Severity> {
        match self {
            Self::Critical => Some(Severity::Critical),
            Self::High => Some(Severity::High),
            Self::Medium => Some(Severity::Medium),
            Self::Low => Some(Severity::Low),
            Self::None => None,
        }
    }
}

/// Parses the raw argument list. Usage errors return a clap error that the
/// caller renders to stderr and maps to exit code 2. The report/target
/// conflict is a post-parse check so clap keeps owning the error shape.
pub fn parse(args: &[String]) -> Result<Cli, clap::Error> {
    let cli =
        Cli::try_parse_from(std::iter::once("sentinel").chain(args.iter().map(String::as_str)))?;
    if let Command::Scan {
        output: OutputFormat::Terminal,
        report: Some(_),
        ..
    } = &cli.command
    {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::ArgumentConflict,
            "the argument '--report <PATH>' cannot be used with '--output terminal'",
        ));
    }
    Ok(cli)
}

#[cfg(test)]
mod tests {
    use super::{CacheAction, Command, FailUnder, parse};
    use clap::error::ErrorKind;
    fn args(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn scan_subcommand_is_accepted() {
        let cli = parse(&args(&["scan"])).unwrap();
        assert!(matches!(cli.command, Command::Scan { ci: false, .. }));
    }
    #[test]
    fn ci_flag_parses_to_scan_with_ci_true() {
        let cli = parse(&args(&["scan", "--ci"])).unwrap();
        assert!(matches!(cli.command, Command::Scan { ci: true, .. }));
    }
    #[test]
    fn offline_is_orthogonal_to_ci() {
        let cli = parse(&args(&["scan", "--offline"])).unwrap();
        assert!(matches!(cli.command, Command::Scan { offline: true, .. }));
        let cli = parse(&args(&["scan", "--ci", "--offline"])).unwrap();
        assert!(matches!(
            cli.command,
            Command::Scan {
                ci: true,
                offline: true,
                ..
            }
        ));
        let cli = parse(&args(&["scan", "--offline", "--ci"])).unwrap();
        assert!(matches!(
            cli.command,
            Command::Scan {
                ci: true,
                offline: true,
                ..
            }
        ));
    }
    #[test]
    fn unsupported_arguments_are_usage_errors() {
        // `--help`/`--version` intentionally excluded: they render and exit 0
        // (covered below), so only genuinely unknown input stays a usage error.
        // A bare positional is NOT unknown: since S4 `scan [PATH]` scans that
        // directory (covered by the path tests below), only unknown flags
        // stay usage errors here.
        let err = parse(&args(&["scan", "--nope"])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }
    #[test]
    fn help_and_version_render_with_exact_program_name() {
        // Pins the S2 crate rename (`sentinel-scan`) against the binary users
        // type (`sentinel`): clap takes the command name from `name`, never
        // the crate name, and these assertions fail if that wiring regresses.
        for tokens in [&["--help"][..], &["-h"][..]] {
            let err = parse(&args(tokens)).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::DisplayHelp, "{tokens:?}");
            let rendered = err.render().to_string();
            assert!(rendered.contains("scan"), "{tokens:?}: {rendered:?}");
            assert!(rendered.contains("completions"), "{tokens:?}: {rendered:?}");
            assert!(
                !rendered.contains("sentinel-scan"),
                "{tokens:?}: {rendered:?}"
            );
        }
        for tokens in [&["--version"][..], &["-V"][..]] {
            let err = parse(&args(tokens)).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::DisplayVersion, "{tokens:?}");
            let rendered = err.render().to_string();
            assert!(
                rendered.starts_with(&format!("sentinel {}", env!("CARGO_PKG_VERSION"))),
                "{tokens:?}: {rendered:?}"
            );
            assert!(
                !rendered.contains("sentinel-scan"),
                "{tokens:?}: {rendered:?}"
            );
        }
    }
    #[test]
    fn subcommand_help_and_version_render() {
        for tokens in [&["scan", "--help"][..], &["completions", "--help"][..]] {
            let err = parse(&args(tokens)).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::DisplayHelp, "{tokens:?}");
            assert!(
                !err.render().to_string().contains("sentinel-scan"),
                "{tokens:?}"
            );
        }
    }
    #[test]
    fn explain_flag_is_accepted() {
        let cli = parse(&args(&["scan", "--explain"])).unwrap();
        assert!(matches!(cli.command, Command::Scan { explain: true, .. }));
    }
    #[test]
    fn missing_subcommand_is_a_usage_error() {
        let err = parse(&[]).unwrap_err();
        assert!(err.use_stderr());
    }
    #[test]
    fn completions_accepts_each_supported_shell() {
        for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
            let cli = parse(&args(&["completions", shell])).unwrap();
            assert!(
                matches!(cli.command, Command::Completions { .. }),
                "shell {shell}"
            );
        }
    }
    #[test]
    fn completions_rejects_other_shells_and_a_missing_shell() {
        for tokens in [
            &["completions", "tcsh"][..],
            &["completions", "nushell"][..],
            &["completions"][..],
        ] {
            let err = parse(&args(tokens)).unwrap_err();
            assert!(err.use_stderr(), "{tokens:?}");
        }
    }
    #[test]
    fn fail_under_flag_parses_each_level_and_defaults_to_absent() {
        let cli = parse(&args(&["scan"])).unwrap();
        assert!(
            matches!(
                cli.command,
                Command::Scan {
                    fail_under: None,
                    ..
                }
            ),
            "absent flag means no CLI policy"
        );
        for (token, level) in [
            ("critical", FailUnder::Critical),
            ("high", FailUnder::High),
            ("medium", FailUnder::Medium),
            ("low", FailUnder::Low),
            ("none", FailUnder::None),
        ] {
            let cli = parse(&args(&["scan", "--fail-under", token])).unwrap();
            assert!(
                matches!(cli.command, Command::Scan { fail_under: Some(found), .. } if found == level),
                "--fail-under {token} parses to {level:?}"
            );
        }
    }
    #[test]
    fn fail_under_rejects_unknown_levels() {
        let err = parse(&args(&["scan", "--fail-under", "bogus"])).unwrap_err();
        assert!(err.use_stderr(), "unknown level is a usage error");
    }
    #[test]
    fn scan_help_documents_the_fail_under_flag() {
        let err = parse(&args(&["scan", "--help"])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
        assert!(
            err.render().to_string().contains("fail-under"),
            "help must document the exit-policy flag"
        );
    }
    #[test]
    fn exclude_flag_is_repeatable_and_defaults_to_empty() {
        let cli = parse(&args(&["scan"])).unwrap();
        assert!(matches!(cli.command, Command::Scan { ref exclude, .. } if exclude.is_empty()));
        let cli = parse(&args(&["scan", "--exclude", "*.log"])).unwrap();
        assert!(
            matches!(cli.command, Command::Scan { ref exclude, .. } if exclude == &["*.log".to_string()])
        );
        let cli = parse(&args(&[
            "scan",
            "--exclude",
            "*.log",
            "--exclude",
            "build/",
        ]))
        .unwrap();
        assert!(
            matches!(cli.command, Command::Scan { ref exclude, .. } if exclude == &["*.log".to_string(), "build/".to_string()])
        );
    }
    #[test]
    fn scan_path_defaults_to_cwd_and_accepts_an_explicit_target() {
        use std::path::PathBuf;
        let cli = parse(&args(&["scan"])).unwrap();
        assert!(
            matches!(cli.command, Command::Scan { ref path, .. } if path == &PathBuf::from(".")),
            "no PATH means the invoking cwd"
        );
        let cli = parse(&args(&["scan", "../other-repo"])).unwrap();
        assert!(
            matches!(cli.command, Command::Scan { ref path, .. } if path == &PathBuf::from("../other-repo")),
            "an explicit PATH is kept verbatim for cwd-relative resolution"
        );
    }
    #[test]
    fn scan_help_documents_the_path_argument() {
        let err = parse(&args(&["scan", "--help"])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
        assert!(
            err.render().to_string().contains("PATH"),
            "help must document the scan target"
        );
    }
    #[test]
    fn baseline_flags_default_to_absent() {
        let cli = parse(&args(&["scan"])).unwrap();
        assert!(
            matches!(
                cli.command,
                Command::Scan {
                    baseline: None,
                    update_baseline: false,
                    ..
                }
            ),
            "no baseline means today's behaviour exactly"
        );
    }
    #[test]
    fn baseline_flag_takes_a_path_and_update_flag_is_boolean() {
        use std::path::PathBuf;
        let cli = parse(&args(&["scan", "--baseline", "accepted.json"])).unwrap();
        assert!(
            matches!(cli.command, Command::Scan { baseline: Some(ref path), update_baseline: false, .. } if path == &PathBuf::from("accepted.json")),
            "--baseline keeps its path verbatim for cwd-relative resolution"
        );
        let cli = parse(&args(&[
            "scan",
            "--baseline",
            "accepted.json",
            "--update-baseline",
        ]))
        .unwrap();
        assert!(
            matches!(cli.command, Command::Scan { baseline: Some(ref path), update_baseline: true, .. } if path == &PathBuf::from("accepted.json")),
            "--update-baseline regenerates the file --baseline names"
        );
        let cli = parse(&args(&["scan", "--update-baseline"])).unwrap();
        assert!(
            matches!(
                cli.command,
                Command::Scan {
                    baseline: None,
                    update_baseline: true,
                    ..
                }
            ),
            "--update-baseline alone relies on the configured baseline path"
        );
    }
    #[test]
    fn cache_subcommands_parse() {
        let cli = parse(&args(&["cache", "path"])).unwrap();
        assert!(
            matches!(
                cli.command,
                Command::Cache {
                    action: CacheAction::Path
                }
            ),
            "cache path prints the resolved location"
        );
        let cli = parse(&args(&["cache", "clear"])).unwrap();
        assert!(
            matches!(
                cli.command,
                Command::Cache {
                    action: CacheAction::Clear
                }
            ),
            "cache clear empties the resolved location"
        );
        let cli = parse(&args(&["cache", "prune"])).unwrap();
        assert!(
            matches!(
                cli.command,
                Command::Cache {
                    action: CacheAction::Prune { older_than: 30 }
                }
            ),
            "prune defaults to entries unused for 30 days"
        );
        let cli = parse(&args(&["cache", "prune", "--older-than", "7"])).unwrap();
        assert!(
            matches!(
                cli.command,
                Command::Cache {
                    action: CacheAction::Prune { older_than: 7 }
                }
            ),
            "the prune age is a flag, not a constant"
        );
    }
    #[test]
    fn cache_requires_a_subcommand() {
        let err = parse(&args(&["cache"])).unwrap_err();
        assert!(err.use_stderr(), "bare `cache` is a usage error");
    }
    #[test]
    fn scan_no_cache_defaults_off_and_parses() {
        let cli = parse(&args(&["scan"])).unwrap();
        assert!(
            matches!(
                cli.command,
                Command::Scan {
                    no_cache: false,
                    ..
                }
            ),
            "scans use the cache unless asked not to"
        );
        let cli = parse(&args(&["scan", "--no-cache"])).unwrap();
        assert!(
            matches!(cli.command, Command::Scan { no_cache: true, .. }),
            "--no-cache opts out of every cache read and write"
        );
    }
    #[test]
    fn top_help_lists_cache_beside_scan_and_completions() {
        let err = parse(&args(&["--help"])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
        let text = err.render().to_string();
        assert!(
            text.contains("cache"),
            "top-level help must list the cache subcommand: {text:?}"
        );
    }
    #[test]
    fn scan_help_documents_no_cache() {
        let err = parse(&args(&["scan", "--help"])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
        assert!(
            err.render().to_string().contains("no-cache"),
            "scan help must document the cache opt-out"
        );
    }
    #[test]
    fn cache_prune_help_documents_the_age_flag() {
        let err = parse(&args(&["cache", "prune", "--help"])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
        assert!(
            err.render().to_string().contains("older-than"),
            "prune help must document the age flag"
        );
    }
    #[test]
    fn scan_help_documents_the_baseline_flags() {
        let err = parse(&args(&["scan", "--help"])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
        let text = err.render().to_string();
        assert!(
            text.contains("--baseline"),
            "help must document the baseline file flag"
        );
        assert!(
            text.contains("--update-baseline"),
            "help must document the baseline regeneration flag"
        );
    }
}
