//! Project and user configuration: `sentinel.toml` at the repository root
//! plus a user-level file, merged with CLI flags winning.
//!
//! Precedence is **CLI flag > project config > user config > built-in
//! default**. List-valued keys (like `exclude`) **union** across levels:
//! every level contributes its patterns, concatenated CLI-first with
//! first-seen dedup, so "CLI beats project beats user" is realized as
//! order, not replacement. Scalar-valued keys (the next slice's
//! `fail_under`) **override** instead: CLI wins over project wins over
//! user. The user level itself resolves from `SENTINEL_CONFIG` when set and
//! non-empty, otherwise from the XDG lookup below. A missing file at either
//! level contributes nothing; an unreadable or malformed file contributes
//! exactly one actionable `config-invalid` diagnostic and never aborts the
//! scan.

use std::path::{Path, PathBuf};

use crate::finding::Diagnostic;

/// User-level config file name, resolved under the XDG config home.
const USER_CONFIG_REL: &str = "sentinel/config.toml";

/// Project-level config file name, resolved under the repository root.
pub const PROJECT_CONFIG_NAME: &str = "sentinel.toml";

/// The file-backed knobs T1 reads. Unknown keys are ignored so newer config
/// files stay readable; every key defaults to empty/absent.
#[derive(Debug, Default, serde::Deserialize)]
struct FileConfig {
    /// Glob patterns (`.gitignore` semantics) removing files from the scan.
    #[serde(default)]
    exclude: Vec<String>,
}

/// The project-level config path: always `<root>/sentinel.toml`.
pub fn project_path(root: &Path) -> PathBuf {
    root.join(PROJECT_CONFIG_NAME)
}

/// Resolves the user-level config path from explicit environment values so
/// tests stay hermetic without touching the process environment: an explicit
/// `SENTINEL_CONFIG` file when set and non-empty, otherwise the
/// `XDG_CONFIG_HOME` value when set and non-empty, otherwise
/// `$HOME/.config`. Returns `None` only when no home can be determined.
fn user_path_with(
    sentinel_config: Option<&str>,
    xdg_config_home: Option<&str>,
    home: Option<&str>,
) -> Option<PathBuf> {
    // An explicit file wins over the whole lookup: CI callers pin one file
    // instead of depending on whoever owns the home directory.
    if let Some(path) = sentinel_config.filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path));
    }
    let base = match xdg_config_home {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => {
            let home = home.filter(|dir| !dir.is_empty())?;
            PathBuf::from(home).join(".config")
        }
    };
    Some(base.join(USER_CONFIG_REL))
}

/// The user-level config path from the live process environment: the
/// `SENTINEL_CONFIG` file when set and non-empty, otherwise
/// `$XDG_CONFIG_HOME/sentinel/config.toml`, falling back to
/// `~/.config/sentinel/config.toml` when the variable is unset or empty.
/// Returns `None` only when no home can be determined.
///
/// The single production entry point for user-config location: production
/// scans (`run`) resolve the environment only through here, while tests pass
/// explicit paths to [`resolve_with`], so no in-process test can depend on
/// the developer's home directory.
pub fn user_path() -> Option<PathBuf> {
    user_path_with(
        std::env::var("SENTINEL_CONFIG").ok().as_deref(),
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// Reads one config file: missing files contribute nothing (`Ok(None)`),
/// while unreadable or malformed files report their reason for a single
/// caller-built diagnostic.
fn load_file(path: &Path) -> Result<Option<FileConfig>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot read: {error}")),
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return Err("cannot read: file is not valid UTF-8".to_string()),
    };
    match toml::from_str::<FileConfig>(&text) {
        Ok(config) => Ok(Some(config)),
        Err(error) => Err(format!("cannot parse TOML: {error}")),
    }
}

/// One actionable diagnostic for an unreadable or malformed config file.
/// The message names the file, the reason, and the fix; the scan continues
/// with that level contributing nothing.
fn invalid_diagnostic(path: &Path, root: &Path, reason: &str) -> Diagnostic {
    let display = path
        .strip_prefix(root)
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.display().to_string());
    Diagnostic {
        code: "config-invalid",
        path: display,
        rule: String::new(),
        message: format!(
            "sentinel config {reason}; fix the file or remove it to silence this warning"
        ),
    }
}

/// Merges exclude levels in precedence order — CLI, then project, then user —
/// de-duplicated with first-seen order kept, so every level contributes while
/// the concatenation order records which level won each position.
fn merge_excludes(cli: &[String], project: &[String], user: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    cli.iter()
        .chain(project.iter())
        .chain(user.iter())
        .filter(|pattern| seen.insert((*pattern).clone()))
        .cloned()
        .collect()
}

/// Resolves the effective excludes for a scan rooted at `root` from explicit
/// inputs (the hermetic seam): CLI patterns first, then the project file,
/// then the user file at `user` — or no user level at all with `None`, so a
/// caller (and therefore a test) decides without reading the process
/// environment. Each unreadable or malformed file yields exactly one
/// `config-invalid` diagnostic; missing files are silent.
pub(crate) fn resolve_with(
    root: &Path,
    cli: &[String],
    user: Option<PathBuf>,
) -> (Vec<String>, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let mut project_excludes = Vec::new();
    let project = project_path(root);
    match load_file(&project) {
        Ok(Some(config)) => project_excludes = config.exclude,
        Ok(None) => {}
        Err(reason) => diagnostics.push(invalid_diagnostic(&project, root, &reason)),
    }
    let mut user_excludes = Vec::new();
    if let Some(path) = user {
        match load_file(&path) {
            Ok(Some(config)) => user_excludes = config.exclude,
            Ok(None) => {}
            Err(reason) => diagnostics.push(invalid_diagnostic(&path, root, &reason)),
        }
    }
    diagnostics.sort();
    diagnostics.dedup();
    (
        merge_excludes(cli, &project_excludes, &user_excludes),
        diagnostics,
    )
}

#[cfg(test)]
mod tests {
    use super::{merge_excludes, project_path, resolve_with, user_path_with};
    use crate::test_util::{temp_repo, write_tracked, write_untracked};
    use std::ffi::OsStr;
    use std::path::PathBuf;

    #[test]
    fn project_path_is_sentinel_toml_at_the_root() {
        let (_dir, root) = temp_repo();
        assert_eq!(
            project_path(&root),
            root.join("sentinel.toml"),
            "project config lives at the repository root"
        );
    }

    #[test]
    fn user_path_prefers_xdg_config_home_then_home_dot_config() {
        assert_eq!(
            user_path_with(None, Some("/xdg"), Some("/home/u")),
            Some(PathBuf::from("/xdg/sentinel/config.toml"))
        );
        assert_eq!(
            user_path_with(None, None, Some("/home/u")),
            Some(PathBuf::from("/home/u/.config/sentinel/config.toml"))
        );
    }

    #[test]
    fn empty_xdg_config_home_falls_back_to_home() {
        assert_eq!(
            user_path_with(None, Some(""), Some("/home/u")),
            Some(PathBuf::from("/home/u/.config/sentinel/config.toml")),
            "empty XDG_CONFIG_HOME behaves as unset"
        );
        assert_eq!(user_path_with(None, None, None), None);
    }

    #[test]
    fn sentinel_config_pointing_at_a_file_wins_over_the_xdg_lookup() {
        assert_eq!(
            user_path_with(Some("/ci/sentinel.toml"), Some("/xdg"), Some("/home/u")),
            Some(PathBuf::from("/ci/sentinel.toml")),
            "an explicit SENTINEL_CONFIG file wins over the whole lookup"
        );
    }

    #[test]
    fn empty_sentinel_config_falls_back_to_the_xdg_lookup() {
        assert_eq!(
            user_path_with(Some(""), Some("/xdg"), Some("/home/u")),
            Some(PathBuf::from("/xdg/sentinel/config.toml")),
            "empty SENTINEL_CONFIG behaves as unset"
        );
        assert_eq!(
            user_path_with(Some(""), None, Some("/home/u")),
            Some(PathBuf::from("/home/u/.config/sentinel/config.toml"))
        );
    }

    #[test]
    fn merge_order_is_cli_then_project_then_user_without_duplicates() {
        let merged = merge_excludes(
            &["cli-*.log".to_string(), "shared-*.log".to_string()],
            &["project-*.log".to_string(), "shared-*.log".to_string()],
            &["user-*.log".to_string(), "shared-*.log".to_string()],
        );
        assert_eq!(
            merged,
            vec![
                "cli-*.log".to_string(),
                "shared-*.log".to_string(),
                "project-*.log".to_string(),
                "user-*.log".to_string(),
            ],
            "CLI first, then project, then user; duplicates keep first position"
        );
    }

    #[test]
    fn no_config_means_no_excludes_and_no_diagnostics() {
        let (_dir, root) = temp_repo();
        let (excludes, diagnostics) = resolve_with(&root, &[], None);
        assert!(excludes.is_empty());
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn project_config_supplies_an_exclude_pattern() {
        let (_dir, root) = temp_repo();
        // Untouched by staging: the config file is read from the worktree.
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"exclude = [\"*.log\"]\n",
        );
        let (excludes, diagnostics) = resolve_with(&root, &[], None);
        assert_eq!(excludes, vec!["*.log".to_string()]);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn user_config_supplies_an_exclude_pattern() {
        let (_dir, root) = temp_repo();
        let xdg = tempfile::TempDir::new().unwrap();
        let user_dir = xdg.path().join("sentinel");
        std::fs::create_dir_all(&user_dir).unwrap();
        let user_file = user_dir.join("config.toml");
        std::fs::write(&user_file, b"exclude = [\"*.tmp\"]\n").unwrap();
        let (excludes, diagnostics) = resolve_with(&root, &[], Some(user_file));
        assert_eq!(excludes, vec!["*.tmp".to_string()]);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn cli_project_and_user_combine_in_precedence_order() {
        let (_dir, root) = temp_repo();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"exclude = [\"project-*.log\"]\n",
        );
        let xdg = tempfile::TempDir::new().unwrap();
        let user_dir = xdg.path().join("sentinel");
        std::fs::create_dir_all(&user_dir).unwrap();
        let user_file = user_dir.join("config.toml");
        std::fs::write(&user_file, b"exclude = [\"user-*.log\"]\n").unwrap();
        let cli = vec!["cli-*.log".to_string()];
        let (excludes, diagnostics) = resolve_with(&root, &cli, Some(user_file));
        assert_eq!(
            excludes,
            vec![
                "cli-*.log".to_string(),
                "project-*.log".to_string(),
                "user-*.log".to_string(),
            ]
        );
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn malformed_project_config_warns_once_and_contributes_nothing() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("sentinel.toml"), b"exclude = [oops\n");
        let (excludes, diagnostics) = resolve_with(&root, &["cli-*.log".to_string()], None);
        // The CLI level still applies: one bad file never aborts the scan.
        assert_eq!(excludes, vec!["cli-*.log".to_string()]);
        assert_eq!(diagnostics.len(), 1, "exactly one diagnostic");
        assert_eq!(diagnostics[0].code, "config-invalid");
        assert!(
            diagnostics[0].path.contains("sentinel.toml"),
            "names the file: {:?}",
            diagnostics[0]
        );
        assert!(
            diagnostics[0].message.contains("fix"),
            "actionable: {:?}",
            diagnostics[0]
        );
    }

    #[test]
    fn unreadable_user_config_warns_once_and_scan_continues() {
        let (_dir, root) = temp_repo();
        let xdg = tempfile::TempDir::new().unwrap();
        // A directory where the file should be: the read fails deterministically.
        let user_file = xdg.path().join("config.toml");
        std::fs::create_dir_all(&user_file).unwrap();
        let (excludes, diagnostics) = resolve_with(&root, &[], Some(user_file));
        assert!(excludes.is_empty());
        assert_eq!(diagnostics.len(), 1, "exactly one diagnostic");
        assert_eq!(diagnostics[0].code, "config-invalid");
    }
}
