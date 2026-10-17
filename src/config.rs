//! Project and user configuration: `sentinel.toml` at the repository root
//! plus a user-level file, merged with CLI flags winning.
//!
//! Precedence is **CLI flag > project config > user config > built-in
//! default**. List-valued keys (like `exclude`) **union** across levels:
//! every level contributes its patterns, concatenated CLI-first with
//! first-seen dedup, so "CLI beats project beats user" is realized as
//! order, not replacement. Scalar-valued keys (`fail_under`, `baseline`)
//! **override** instead: CLI wins over project wins over user (see [`override_scalar`],
//! deliberately separate from [`merge_excludes`]). The user level itself resolves from `SENTINEL_CONFIG` when set and
//! non-empty, otherwise from the XDG lookup below. A missing file at either
//! level contributes nothing; an unreadable or malformed file contributes
//! exactly one actionable `config-invalid` diagnostic and never aborts the
//! scan.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::cli::FailUnder;
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
    /// Lowest severity that fails the build; `None` (key absent) falls
    /// through to the next level, it never resets a value set above.
    #[serde(default)]
    fail_under: Option<FailUnder>,
    /// Baseline file listing accepted finding fingerprints; `None` (key
    /// absent) falls through to the next level, it never resets a value
    /// set above. Relative values resolve against the repository root for
    /// the project file, against the invoking directory for the user file.
    #[serde(default)]
    baseline: Option<PathBuf>,
}

/// The effective configuration for one scan: the merged list levels plus the
/// resolved scalar levels.
#[derive(Debug, Default)]
pub(crate) struct ResolvedConfig {
    /// Union of every level's excludes, CLI-first (see [`merge_excludes`]).
    pub excludes: Vec<String>,
    /// The winning `fail_under`, if any level set it; `None` means every
    /// level was silent and the caller default applies.
    pub fail_under: Option<FailUnder>,
    /// The winning `baseline` path, already resolved (relative project
    /// values against the repository root, CLI and user values against
    /// the invoking directory); `None` means no level named one.
    pub baseline: Option<PathBuf>,
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

/// The baseline envelope version. Same `schema_version` convention as the
/// versioned JSON report (`render::json`): field order is the wire order,
/// bytes are compact plus a trailing newline, and readers accept any
/// version with the same shape so a newer writer never bricks an older
/// reader at load time.
pub(crate) const BASELINE_SCHEMA_VERSION: &str = "1.0.0";

/// The baseline file: accepted finding fingerprints (location-independent
/// keys, see [`crate::finding::Finding::baseline_key`]) under a
/// versioned envelope. Unknown fields are ignored on read, so the file
/// stays forward-compatible; `fingerprints` is required — a JSON file
/// without it is not a baseline.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BaselineFile {
    #[serde(default)]
    schema_version: Option<String>,
    #[serde(default)]
    tool: Option<BaselineTool>,
    fingerprints: Vec<String>,
}

/// Provenance carried by the file; informational only, never gated on.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BaselineTool {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

/// Loads the baseline file at `path`: missing, unreadable, or malformed
/// files yield exactly one `baseline-invalid` diagnostic and an empty set,
/// so a typo never silently passes and the scan continues with nothing
/// accepted. `root` only shapes the diagnostic's display path.
pub(crate) fn load_baseline(path: &Path, root: &Path) -> (BTreeSet<String>, Option<Diagnostic>) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                BTreeSet::new(),
                Some(Diagnostic::baseline_invalid(
                    &display_baseline_path(path, root),
                    &format!("cannot read: {error}"),
                )),
            );
        }
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            return (
                BTreeSet::new(),
                Some(Diagnostic::baseline_invalid(
                    &display_baseline_path(path, root),
                    "cannot read: file is not valid UTF-8",
                )),
            );
        }
    };
    match serde_json::from_str::<BaselineFile>(&text) {
        Ok(file) => (file.fingerprints.into_iter().collect(), None),
        Err(error) => (
            BTreeSet::new(),
            Some(Diagnostic::baseline_invalid(
                &display_baseline_path(path, root),
                &format!("cannot parse JSON: {error}"),
            )),
        ),
    }
}

/// Writes the baseline file at `path` with `fingerprints` sorted and
/// deduplicated under the versioned envelope. Returns the stored count.
/// A write failure is the caller's operational error (exit 2), like an
/// unwritable `--report` path — never a diagnostic.
pub(crate) fn write_baseline(path: &Path, fingerprints: &[String]) -> Result<usize, String> {
    let ordered: BTreeSet<&str> = fingerprints.iter().map(String::as_str).collect();
    let stored: Vec<String> = ordered.into_iter().map(str::to_string).collect();
    let count = stored.len();
    let file = BaselineFile {
        schema_version: Some(BASELINE_SCHEMA_VERSION.to_string()),
        tool: Some(BaselineTool {
            name: Some("sentinel".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }),
        fingerprints: stored,
    };
    let mut bytes = serde_json::to_vec(&file).map_err(|error| format!("cannot encode: {error}"))?;
    bytes.push(b'\n');
    std::fs::write(path, &bytes).map_err(|error| format!("cannot write: {error}"))?;
    Ok(count)
}

/// Displays a baseline path repo-relative when it lives under `root`,
/// absolute otherwise — the same readability rule as config diagnostics.
fn display_baseline_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.display().to_string())
}

/// Resolves the effective excludes for a scan rooted at `root` from explicit
/// inputs (the hermetic seam): CLI patterns first, then the project file,
/// then the user file at `user` — or no user level at all with `None`, so a
/// caller (and therefore a test) decides without reading the process
/// environment. Each unreadable or malformed file yields exactly one
/// `config-invalid` diagnostic; missing files are silent.
///
/// Test-only: production resolves through [`resolve_full_with`], which also
/// carries the scalar levels; this wrapper keeps the pre-existing
/// exclude-level tests on their original seam.
#[cfg(test)]
pub(crate) fn resolve_with(
    root: &Path,
    cli: &[String],
    user: Option<PathBuf>,
) -> (Vec<String>, Vec<Diagnostic>) {
    // No baseline level participates here, so the resolution base is
    // irrelevant; `root` keeps the call total without a new parameter.
    let (config, diagnostics) = resolve_full_with(root, cli, None, None, user, root);
    (config.excludes, diagnostics)
}

/// First-set-wins across precedence levels: the CLI value applies when
/// present, otherwise the project file's, otherwise the user file's.
/// `None` at a level means that level is silent — it falls through instead
/// of resetting a value set elsewhere. This is deliberately *not*
/// [`merge_excludes`]: lists union because every pattern excludes, but a
/// scalar names one policy, so levels must replace rather than combine.
fn override_scalar<T: Clone>(cli: Option<T>, project: Option<T>, user: Option<T>) -> Option<T> {
    cli.or(project).or(user)
}

/// Resolves the full effective configuration — merged excludes plus the
/// scalar `fail_under` and `baseline` override chains — from explicit inputs
/// (the hermetic seam): CLI values first, then the project file, then the
/// user file at `user`, or no user level at all with `None`. Each unreadable
/// or malformed file yields exactly one `config-invalid` diagnostic and
/// contributes nothing at any key; missing files are silent. Relative
/// baseline paths resolve against the repository root for the project file
/// (it ships with the checkout, including under `scan [PATH]`) and against
/// the invoking `cwd` for the CLI flag and the user file (both caller-side).
pub(crate) fn resolve_full_with(
    root: &Path,
    cli_excludes: &[String],
    cli_fail_under: Option<FailUnder>,
    cli_baseline: Option<PathBuf>,
    user: Option<PathBuf>,
    cwd: &Path,
) -> (ResolvedConfig, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let mut project = FileConfig::default();
    let project_path = project_path(root);
    match load_file(&project_path) {
        Ok(Some(config)) => project = config,
        Ok(None) => {}
        Err(reason) => diagnostics.push(invalid_diagnostic(&project_path, root, &reason)),
    }
    let mut user_config = FileConfig::default();
    if let Some(path) = user {
        match load_file(&path) {
            Ok(Some(config)) => user_config = config,
            Ok(None) => {}
            Err(reason) => diagnostics.push(invalid_diagnostic(&path, root, &reason)),
        }
    }
    diagnostics.sort();
    diagnostics.dedup();
    (
        ResolvedConfig {
            excludes: merge_excludes(cli_excludes, &project.exclude, &user_config.exclude),
            fail_under: override_scalar(cli_fail_under, project.fail_under, user_config.fail_under),
            baseline: override_scalar(
                cli_baseline.map(|path| resolve_against(&path, cwd)),
                project.baseline.map(|path| resolve_against(&path, root)),
                user_config.baseline.map(|path| resolve_against(&path, cwd)),
            ),
        },
        diagnostics,
    )
}

/// Resolves a configured path: absolute values pass through, relative ones
/// root at `base` (`Path::join` would replace on absolute anyway; spelled
/// out so the precedence chain reads without consulting the `join` docs).
fn resolve_against(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        load_baseline, merge_excludes, override_scalar, project_path, resolve_full_with,
        resolve_with, user_path_with, write_baseline,
    };
    use crate::cli::FailUnder;
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
    fn scalar_override_prefers_cli_over_project_over_user() {
        assert_eq!(
            override_scalar(
                Some(FailUnder::Critical),
                Some(FailUnder::High),
                Some(FailUnder::Low)
            ),
            Some(FailUnder::Critical),
            "CLI wins over both files"
        );
        assert_eq!(
            override_scalar(None, Some(FailUnder::High), Some(FailUnder::Low)),
            Some(FailUnder::High),
            "project wins over user"
        );
        assert_eq!(
            override_scalar(None, None, Some(FailUnder::Low)),
            Some(FailUnder::Low),
            "user applies when nothing above it sets the key"
        );
        assert_eq!(
            override_scalar::<FailUnder>(None, None, None),
            None,
            "absence everywhere stays absent, so the caller default applies"
        );
    }
    #[test]
    fn fail_under_resolves_through_config_levels() {
        let (_dir, root) = temp_repo();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"fail_under = \"high\"\n",
        );
        let xdg = tempfile::TempDir::new().unwrap();
        let user_file = xdg.path().join("config.toml");
        std::fs::write(&user_file, b"fail_under = \"low\"\n").unwrap();
        let (config, diagnostics) = resolve_full_with(
            &root,
            &[],
            Some(FailUnder::Critical),
            None,
            Some(user_file.clone()),
            &root,
        );
        assert_eq!(config.fail_under, Some(FailUnder::Critical), "CLI wins");
        assert!(diagnostics.is_empty());
        let (config, _) = resolve_full_with(&root, &[], None, None, Some(user_file.clone()), &root);
        assert_eq!(
            config.fail_under,
            Some(FailUnder::High),
            "project wins over user"
        );
        std::fs::remove_file(root.join("sentinel.toml")).unwrap();
        let (config, _) = resolve_full_with(&root, &[], None, None, Some(user_file), &root);
        assert_eq!(
            config.fail_under,
            Some(FailUnder::Low),
            "user applies alone"
        );
        let (config, diagnostics) = resolve_full_with(&root, &[], None, None, None, &root);
        assert_eq!(config.fail_under, None, "absence stays absent");
        assert!(diagnostics.is_empty());
    }
    #[test]
    fn exclude_unions_while_fail_under_overrides() {
        // The invariant the previous slice warned would break here: lists
        // union across levels while the first scalar key replaces.
        let (_dir, root) = temp_repo();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"exclude = [\"project-*.log\"]\nfail_under = \"high\"\n",
        );
        let xdg = tempfile::TempDir::new().unwrap();
        let user_file = xdg.path().join("config.toml");
        std::fs::write(
            &user_file,
            b"exclude = [\"user-*.log\"]\nfail_under = \"low\"\n",
        )
        .unwrap();
        let cli = vec!["cli-*.log".to_string()];
        let (config, diagnostics) = resolve_full_with(
            &root,
            &cli,
            Some(FailUnder::Medium),
            None,
            Some(user_file),
            &root,
        );
        assert_eq!(
            config.excludes,
            vec![
                "cli-*.log".to_string(),
                "project-*.log".to_string(),
                "user-*.log".to_string(),
            ],
            "every exclude level still contributes"
        );
        assert_eq!(
            config.fail_under,
            Some(FailUnder::Medium),
            "the scalar replaces instead of merging: only the CLI value survives"
        );
        assert!(diagnostics.is_empty());
    }
    #[test]
    fn malformed_fail_under_warns_once_and_contributes_nothing() {
        let (_dir, root) = temp_repo();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"fail_under = \"bogus\"\n",
        );
        let (config, diagnostics) = resolve_full_with(&root, &[], None, None, None, &root);
        assert_eq!(
            config.fail_under, None,
            "a bad value never becomes a policy"
        );
        assert_eq!(diagnostics.len(), 1, "exactly one diagnostic");
        assert_eq!(diagnostics[0].code, "config-invalid");
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

    #[test]
    fn baseline_scalar_resolves_cli_over_project_over_user() {
        // Absolute values pass resolution through, so this test pins only
        // the override order: CLI beats project beats user (never a merge).
        let (_dir, root) = temp_repo();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"baseline = \"/proj/accepted.json\"\n",
        );
        let xdg = tempfile::TempDir::new().unwrap();
        let user_file = xdg.path().join("config.toml");
        std::fs::write(&user_file, b"baseline = \"/user/accepted.json\"\n").unwrap();
        let (config, diagnostics) = resolve_full_with(
            &root,
            &[],
            None,
            Some(PathBuf::from("/cli/accepted.json")),
            Some(user_file.clone()),
            &root,
        );
        assert_eq!(
            config.baseline,
            Some(PathBuf::from("/cli/accepted.json")),
            "CLI wins over both files"
        );
        assert!(diagnostics.is_empty());
        let (config, _) = resolve_full_with(&root, &[], None, None, Some(user_file), &root);
        assert_eq!(
            config.baseline,
            Some(PathBuf::from("/proj/accepted.json")),
            "project wins over user"
        );
    }

    #[test]
    fn baseline_without_any_level_stays_absent() {
        let (_dir, root) = temp_repo();
        let (config, diagnostics) = resolve_full_with(&root, &[], None, None, None, &root);
        assert_eq!(config.baseline, None, "absence stays absent");
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn baseline_paths_resolve_project_against_root_and_cli_against_cwd() {
        // The project file ships with the repository, so its relative
        // values root at the target checkout; the CLI flag is caller-side,
        // so it roots at the invoking directory.
        let (_dir, root) = temp_repo();
        let elsewhere = tempfile::TempDir::new().unwrap();
        write_untracked(
            &root,
            OsStr::new("sentinel.toml"),
            b"baseline = \"base/accepted.json\"\n",
        );
        let (config, _) = resolve_full_with(&root, &[], None, None, None, elsewhere.path());
        assert_eq!(
            config.baseline,
            Some(root.join("base/accepted.json")),
            "project-relative roots at the repository"
        );
        let (config, _) = resolve_full_with(
            &root,
            &[],
            None,
            Some(PathBuf::from("cli.json")),
            None,
            elsewhere.path(),
        );
        assert_eq!(
            config.baseline,
            Some(elsewhere.path().join("cli.json")),
            "CLI-relative roots at the invoking directory"
        );
    }

    #[test]
    fn baseline_file_round_trips_sorted_fingerprints() {
        // The update path writes what the load path reads: sorted, deduped
        // keys under the JSON-report `schema_version` envelope convention.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("accepted.json");
        let keys = vec!["b".to_string(), "a".to_string(), "a".to_string()];
        let count = write_baseline(&path, &keys).expect("write must succeed");
        assert_eq!(count, 2, "duplicates collapse before the write");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.ends_with('\n'),
            "trailing newline like the JSON report"
        );
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["schema_version"], "1.0.0");
        assert_eq!(
            value["fingerprints"],
            serde_json::json!(["a", "b"]),
            "sorted and deduped"
        );
        let (loaded, invalid) = load_baseline(&path, dir.path());
        assert!(invalid.is_none());
        assert_eq!(
            loaded.into_iter().collect::<Vec<_>>(),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn malformed_baseline_warns_once_and_loads_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("accepted.json");
        std::fs::write(&path, b"not json{{").unwrap();
        let (loaded, invalid) = load_baseline(&path, dir.path());
        assert!(loaded.is_empty());
        let diagnostic = invalid.expect("one diagnostic");
        assert_eq!(diagnostic.code, "baseline-invalid");
        let (loaded, invalid) = load_baseline(&dir.path().join("missing.json"), dir.path());
        assert!(loaded.is_empty());
        assert_eq!(
            invalid.expect("missing file warns too").code,
            "baseline-invalid"
        );
    }
}
