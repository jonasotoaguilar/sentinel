//! Black-box tests for `sentinel completions <shell>` (issue #39): each
//! supported shell emits its script on stdout with an empty stderr, the
//! script mentions the `scan` subcommand, unsupported shells stay usage
//! errors, and generation never touches repository discovery.

use std::path::Path;

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

/// The sentinel binary with a hermetic git and config environment, like
/// `scan_bin`: the user-level config lookup stays pinned at the
/// repository even though this helper only drives `completions`.
fn sentinel_bin(cwd: &Path, args: &[&str]) -> AssertCommand {
    let mut cmd = AssertCommand::cargo_bin("sentinel").unwrap();
    cmd.args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("XDG_CONFIG_HOME", cwd)
        .env_remove("SENTINEL_CONFIG")
        .env("HOME", cwd);
    cmd
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn each_supported_shell_emits_a_script_on_stdout() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let dir = TempDir::new().unwrap();
        let output = sentinel_bin(dir.path(), &["completions", shell])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "shell {shell}");
        assert!(
            !output.stdout.is_empty(),
            "shell {shell}: stdout must carry the script"
        );
        assert!(
            output.stderr.is_empty(),
            "shell {shell}: stderr must stay empty, got {:?}",
            text_of(&output.stderr)
        );
        assert!(
            text_of(&output.stdout).contains("scan"),
            "shell {shell}: script must mention the scan subcommand"
        );
    }
}

#[test]
fn unsupported_shell_is_a_usage_error() {
    // `nushell` is rejected even though other clap_complete backends exist
    // for it: the accepted set is exactly the five spec shells.
    for shell in ["tcsh", "nushell"] {
        let dir = TempDir::new().unwrap();
        let output = sentinel_bin(dir.path(), &["completions", shell])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "shell {shell}");
        assert!(
            output.stdout.is_empty(),
            "shell {shell}: stdout must stay empty"
        );
        assert!(
            !output.stderr.is_empty(),
            "shell {shell}: stderr must carry the usage error"
        );
    }
}

#[test]
fn completions_work_outside_a_git_repository_without_discovery() {
    let dir = TempDir::new().unwrap(); // never `git init`-ed
    assert!(!dir.path().join(".git").exists());
    let output = sentinel_bin(dir.path(), &["completions", "zsh"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty(), "the script must be emitted");
    let stdout = text_of(&output.stdout);
    let stderr = text_of(&output.stderr);
    for stream in [&stdout, &stderr] {
        assert!(
            !stream.contains("not inside a git repository"),
            "no repository error may appear: {stream:?}"
        );
        assert!(
            !stream.contains("git is required"),
            "no discovery error may appear: {stream:?}"
        );
    }
}

#[test]
fn missing_shell_argument_is_a_usage_error() {
    let dir = TempDir::new().unwrap();
    let output = sentinel_bin(dir.path(), &["completions"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn unknown_subcommand_stays_a_usage_error() {
    let dir = TempDir::new().unwrap();
    let output = sentinel_bin(dir.path(), &["frobnicate"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
