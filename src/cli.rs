//! Command-line surface: exactly one command, `sentinel scan`.
//!
//! clap owns parsing; every rejected invocation is a usage error (stderr
//! diagnostics, empty stdout, exit 2). `--ci` is the only supported option;
//! anything else beyond `scan` is rejected, so `--explain`, `--output`, and
//! positional arguments cannot silently become no-ops.

use clap::{Parser, Subcommand};

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
    },
}

/// Parses the raw argument list. Usage errors return a clap error that the
/// caller renders to stderr and maps to exit code 2.
pub fn parse(args: &[String]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once("sentinel").chain(args.iter().map(String::as_str)))
}

#[cfg(test)]
mod tests {
    use super::parse;
    use clap::error::ErrorKind;

    fn args(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn scan_subcommand_is_accepted() {
        assert!(parse(&args(&["scan"])).is_ok());
    }

    #[test]
    fn unsupported_arguments_are_usage_errors() {
        for tokens in [
            &["scan", "--explain"][..],
            &["scan", "--output", "json"],
            &["scan", "some-file.txt"],
            &["scan", "--help"],
            &["scan", "--version"],
        ] {
            let err = parse(&args(tokens)).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::UnknownArgument, "{tokens:?}");
        }
    }

    #[test]
    fn missing_subcommand_is_a_usage_error() {
        let err = parse(&[]).unwrap_err();
        assert!(err.use_stderr());
    }
}
