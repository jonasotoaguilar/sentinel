//! Command-line surface: exactly one command, `sentinel scan`.
//!
//! clap owns parsing; every rejected invocation is a usage error (stderr
//! diagnostics, empty stdout, exit 2). `--ci`, `--offline`, `--output`,
//! `--report`, and the advisory-only `--explain` are the only supported
//! options; anything else is rejected, so positional arguments and unknown
//! flags cannot silently become no-ops.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Sentinel — deterministic secrets scanner for Git repositories.
#[derive(Debug, Parser)]
#[command(
    name = "sentinel",
    about,
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// The single MVP command (cli-scan spec: command surface).
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan the current Git repository for secrets.
    Scan {
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
        /// Write the machine-readable report to a file instead of stdout.
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
    },
}

/// The accepted `--output` values (cli-scan spec: exactly these three).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
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
    use super::{Command, parse};
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
        for tokens in [
            &["scan", "some-file.txt"][..],
            &["scan", "--help"],
            &["scan", "--version"],
        ] {
            let err = parse(&args(tokens)).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::UnknownArgument, "{tokens:?}");
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
}
