//! Git-backed discovery: repository root + tracked files, "the way Git sees
//! it", unioned with an ignore-aware walk of untracked files (git-discovery
//! spec, discovery-hardening design).
//!
//! Git is invoked with separate `Command` arguments, never a shell; the
//! working directory alone selects the repository. `rev-parse
//! --show-toplevel` resolves the root and `ls-files -z` enumerates tracked
//! files as NUL-delimited bytes, so spaces, newlines, and non-ASCII (and
//! invalid-UTF-8 on Unix) are preserved exactly.
//!
//! A serial `ignore` walker covers present untracked files. Tracked
//! membership wins over Git ignores (force-added files stay), a
//! `.sentinelignore` matcher post-filters the full union, and every
//! candidate passes a shared relative-path, regular-file, and 10 MiB size
//! guard. Files and diagnostics are sorted deterministically; recoverable
//! failures (walk, metadata, oversize, invalid path) skip only that path
//! with a stable diagnostic code.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::{DirEntry, WalkBuilder};

use crate::errors::Error;
use crate::finding::Diagnostic;

/// Files at or above this size are skipped with a `skipped-large` diagnostic
/// (git-discovery spec: size guard).
pub const MAX_SCAN_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Discovery mode. `Local` keeps git-natural ambient ignore sources
/// (parent `.gitignore`, global gitignore, `.git/info/exclude`); `Ci`
/// disables all three for repository-local, machine-independent input.
/// Both modes include hidden files, never follow symlinks, require a git
/// repository, and honor `.sentinelignore` files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Local,
    Ci,
}

/// Discovered scan input set: the repository root, its files, and any
/// non-fatal discovery diagnostics (rendered to stderr).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// Absolute repository root (worktree top level).
    pub root: PathBuf,
    /// Validated files, repo-relative, sorted deterministically.
    pub files: Vec<PathBuf>,
    /// Non-fatal warnings emitted during discovery, sorted deterministically.
    pub diagnostics: Vec<Diagnostic>,
}

/// Git-backed discovery. `program` defaults to `git` on PATH; tests inject a
/// path to simulate a missing binary.
#[derive(Debug, Clone)]
pub struct Git {
    program: PathBuf,
}

impl Default for Git {
    fn default() -> Self {
        Self::new()
    }
}

impl Git {
    /// Creates discovery over the `git` executable on PATH.
    pub fn new() -> Self {
        Self {
            program: PathBuf::from("git"),
        }
    }

    /// Resolves the repository root and the validated file set for `cwd`
    /// under `mode`. Every fatal failure is a typed operational error
    /// (exit 2). `ls-files` runs from the resolved root, so emitted paths
    /// are root-relative even when `cwd` is nested inside the repository.
    ///
    /// Order of operations: tracked records (`git ls-files -z`) and walked
    /// untracked candidates are each validated (relative path, regular file,
    /// size), unioned with tracked membership winning, post-filtered by
    /// `.sentinelignore`, then sorted — files and diagnostics alike.
    pub fn discover(&self, cwd: &Path, mode: Mode) -> Result<Discovered, Error> {
        #[cfg(test)]
        pin_test_ambient_env();

        if !cwd.is_dir() {
            return Err(Error::InvalidWorkingDirectory {
                path: cwd.to_path_buf(),
            });
        }
        let root = self.show_toplevel(cwd)?;
        let mut diagnostics = Vec::new();

        // Tracked authority: byte-preserving `git ls-files -z`.
        let mut files: BTreeSet<PathBuf> = BTreeSet::new();
        for record in self.tracked_records(&root)? {
            match self.accept_record(&root, &record) {
                Ok(Some(path)) => {
                    files.insert(path);
                }
                Ok(None) => {}
                Err(diagnostic) => diagnostics.push(diagnostic),
            }
        }

        // Untracked candidates from the configured ignore walker.
        let mut sentinel_ignores = Vec::new();
        for entry in self.walk_untracked(&root, mode) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    continue;
                }
            };
            // The walk root itself is not a scan candidate.
            if entry.depth() == 0 {
                continue;
            }
            // Custom ignore files are consumed as ignore sources, never
            // scanned (unlike `.gitignore`, which the walker yields).
            if entry.file_name() == ".sentinelignore" {
                sentinel_ignores.push(entry.path().to_path_buf());
                continue;
            }
            // Tracked-wins: paths already accepted from `ls-files` are not
            // re-validated (no duplicate diagnostics, no duplicate work).
            let rel = match entry.path().strip_prefix(&root) {
                Ok(rel) => rel,
                Err(_) => {
                    diagnostics.push(Diagnostic {
                        code: "invalid-path",
                        path: entry.path().display().to_string(),
                        rule: String::new(),
                        message: "outside the repository root".into(),
                    });
                    continue;
                }
            };
            if files.contains(rel) {
                continue;
            }
            match self.accept_candidate(&root, entry.path()) {
                Ok(Some(path)) => {
                    files.insert(path);
                }
                Ok(None) => {}
                Err(diagnostic) => diagnostics.push(diagnostic),
            }
        }

        // `.sentinelignore` post-filters the full union and takes precedence
        // over the tracked-beats-ignore rule (S4, S5).
        if let Some(matcher) = sentinel_matcher(&root, &sentinel_ignores, &mut diagnostics) {
            files.retain(|rel| {
                !matcher
                    .matched_path_or_any_parents(root.join(rel), false)
                    .is_ignore()
            });
        }

        diagnostics.sort();
        diagnostics.dedup();
        let files = files.into_iter().collect();
        Ok(Discovered {
            root,
            files,
            diagnostics,
        })
    }

    fn show_toplevel(&self, cwd: &Path) -> Result<PathBuf, Error> {
        let output = match self.run(cwd, &["rev-parse", "--show-toplevel"]) {
            Ok(output) => output,
            // rev-parse fails exactly when the directory is not inside a
            // repository; git-missing/spawn failures pass through unchanged.
            Err(Error::GitCommandFailed { .. }) => {
                return Err(Error::NotARepository {
                    path: cwd.to_path_buf(),
                });
            }
            Err(other) => return Err(other),
        };
        let bytes = strip_line_ending(&output.stdout);
        if bytes.is_empty() {
            return Err(Error::InvalidGitOutput {
                command: "rev-parse --show-toplevel".into(),
                reason: "empty output (bare repository without a worktree)".into(),
            });
        }
        Ok(PathBuf::from(os_string(bytes)))
    }

    fn tracked_records(&self, cwd: &Path) -> Result<Vec<Vec<u8>>, Error> {
        let output = self.run(cwd, &["ls-files", "-z"])?;
        Ok(output
            .stdout
            .split(|&byte| byte == 0)
            .filter(|record| !record.is_empty())
            .map(<[u8]>::to_vec)
            .collect())
    }

    /// Runs git with fixed arguments; `-C`-like pathnames can never be
    /// misinterpreted as options because paths are never passed here.
    fn run(&self, cwd: &Path, args: &[&str]) -> Result<Output, Error> {
        let output = match Command::new(&self.program)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::GitUnavailable {
                    program: self.program.display().to_string(),
                });
            }
            Err(error) => {
                return Err(Error::GitSpawnFailed {
                    command: args.join(" "),
                    source: error,
                });
            }
        };
        if !output.status.success() {
            return Err(Error::GitCommandFailed {
                command: args.join(" "),
                status: output.status.code().unwrap_or(-1),
            });
        }
        Ok(output)
    }

    /// Validates one `ls-files` record against the shared safety and size
    /// guards. Unsafe records warn (`invalid-path`); missing or non-regular
    /// records are silently excluded.
    fn accept_record(&self, root: &Path, record: &[u8]) -> Result<Option<PathBuf>, Diagnostic> {
        if !is_safe_relative(record) {
            return Err(Diagnostic {
                code: "invalid-path",
                path: String::from_utf8_lossy(record).into_owned(),
                rule: String::new(),
                message: "not a safe repository-relative path".into(),
            });
        }
        self.accept_candidate(root, &root.join(os_string(record)))
    }

    /// Validates one walker candidate: strips the root prefix, enforces the
    /// shared repo-relative safety check, requires a regular file via
    /// `symlink_metadata` (links are never followed), and applies the 10 MiB
    /// size guard. Recoverable failures skip only that path with a stable
    /// diagnostic.
    fn accept_candidate(&self, root: &Path, path: &Path) -> Result<Option<PathBuf>, Diagnostic> {
        let rel = match path.strip_prefix(root) {
            Ok(rel) => rel,
            Err(_) => {
                return Err(Diagnostic {
                    code: "invalid-path",
                    path: path.display().to_string(),
                    rule: String::new(),
                    message: "outside the repository root".into(),
                });
            }
        };
        if !is_safe_relative(&record_bytes(rel)) {
            return Err(Diagnostic {
                code: "invalid-path",
                path: display_rel(rel),
                rule: String::new(),
                message: "not a safe repository-relative path".into(),
            });
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                if metadata.len() >= MAX_SCAN_FILE_BYTES {
                    return Err(Diagnostic {
                        code: "skipped-large",
                        path: display_rel(rel),
                        rule: String::new(),
                        message: format!("{} bytes exceeds the 10 MiB scan limit", metadata.len()),
                    });
                }
                Ok(Some(rel.to_path_buf()))
            }
            _ => Ok(None),
        }
    }

    /// Walks the repository for present untracked files (serial, for
    /// deterministic warning order). Both modes include hidden entries and
    /// never follow symlinks; `Ci` drops parent, global, and
    /// `.git/info/exclude` ambient ignore sources. `.git` and any nested
    /// repository are pruned via `filter_entry`; walker failures become
    /// `walk-failed` diagnostics.
    fn walk_untracked(&self, root: &Path, mode: Mode) -> Vec<Result<DirEntry, Diagnostic>> {
        let mut builder = WalkBuilder::new(root);
        builder
            .hidden(false)
            .follow_links(false)
            .require_git(true)
            .add_custom_ignore_filename(".sentinelignore");
        if mode == Mode::Ci {
            builder.parents(false).git_global(false).git_exclude(false);
        }
        builder.filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            if entry.file_name() == ".git" {
                return false;
            }
            if entry
                .file_type()
                .is_some_and(|file_type| file_type.is_dir())
                && entry.path().join(".git").exists()
            {
                return false;
            }
            true
        });

        let mut entries = Vec::new();
        for result in builder.build() {
            match result {
                Ok(entry) => entries.push(Ok(entry)),
                Err(error) => {
                    let path = walk_error_path(&error)
                        .and_then(|path| path.strip_prefix(root).ok())
                        .map(display_rel)
                        .unwrap_or_default();
                    entries.push(Err(Diagnostic {
                        code: "walk-failed",
                        path,
                        rule: String::new(),
                        message: error.to_string(),
                    }));
                }
            }
        }
        entries
    }
}

/// Best-effort path from a walker error; `ignore` 0.4 exposes it only via
/// the `WithPath` variant, so the wrappers are peeled deterministically.
fn walk_error_path(error: &ignore::Error) -> Option<&Path> {
    match error {
        ignore::Error::WithPath { path, .. } => Some(path),
        ignore::Error::WithLineNumber { err, .. } => walk_error_path(err),
        ignore::Error::WithDepth { err, .. } => walk_error_path(err),
        ignore::Error::Partial(errors) => errors.iter().find_map(walk_error_path),
        _ => None,
    }
}

/// Builds a `.sentinelignore` matcher over every ignore file found by the
/// walk, mirroring the walker's nested-file precedence when post-filtering
/// tracked paths. Returns `None` when no `.sentinelignore` exists; unreadable
/// or malformed files produce deterministic `sentinel-ignore-failed`
/// diagnostics and the remaining rules still apply.
fn sentinel_matcher(
    root: &Path,
    sentinel_ignores: &[PathBuf],
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Gitignore> {
    if sentinel_ignores.is_empty() {
        return None;
    }
    let mut builder = GitignoreBuilder::new(root);
    for path in sentinel_ignores {
        if let Some(error) = builder.add(path) {
            let rel = path.strip_prefix(root).unwrap_or(path);
            diagnostics.push(Diagnostic {
                code: "sentinel-ignore-failed",
                path: display_rel(rel),
                rule: String::new(),
                message: error.to_string(),
            });
        }
    }
    match builder.build() {
        Ok(matcher) => Some(matcher),
        Err(error) => {
            diagnostics.push(Diagnostic {
                code: "sentinel-ignore-failed",
                path: ".sentinelignore".into(),
                rule: String::new(),
                message: error.to_string(),
            });
            None
        }
    }
}

/// Repo-relative path text with forward slashes on every platform, matching
/// how git emits records and how the renderer displays findings.
fn display_rel(rel: &Path) -> String {
    rel.to_string_lossy().replace('\\', "/")
}

/// Converts a stripped relative path to the shared `/`-separated record byte
/// form used by [`is_safe_relative`].
#[cfg(unix)]
fn record_bytes(rel: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    rel.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn record_bytes(rel: &Path) -> Vec<u8> {
    rel.to_string_lossy().replace('\\', "/").into_bytes()
}

/// Rejects absolute, parent-traversing, and empty-interior path records.
/// git emits `/`-separated records even on Windows, so components are split
/// on `/`; a Windows drive-letter prefix is rejected when present.
fn is_safe_relative(record: &[u8]) -> bool {
    if record.starts_with(b"/") || is_absolute_windows(record) {
        return false;
    }
    record
        .split(|&byte| byte == b'/')
        .all(|part| !part.is_empty() && part != b"..")
}

/// Test-only: pins ambient-ignore environment so in-process walkers are
/// hermetic. The `ignore` crate resolves global gitignore sources
/// ($HOME/.gitconfig, XDG config, /etc/gitconfig) from the process
/// environment at walk time; without pinning, a developer machine's global
/// gitignore could change Local-mode test results. Runs once per test
/// process; every in-process discovery call passes through it.
#[cfg(test)]
fn pin_test_ambient_env() {
    use std::sync::Once;
    static PINNED: Once = Once::new();
    PINNED.call_once(|| {
        let home = std::env::temp_dir().join(format!("sentinel-test-home-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        // SAFETY: test-only, executed once before any walker is built, and
        // no other code in the test binary reads these variables. Empty
        // values are treated as unset by the ignore crate; HOME points at a
        // scratch directory without git configuration.
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", "");
            std::env::set_var("GIT_CONFIG_SYSTEM", "sentinel-missing-system-config");
            std::env::set_var("XDG_CONFIG_HOME", "");
            std::env::set_var("HOME", &home);
        }
    });
}

#[cfg(windows)]
fn is_absolute_windows(record: &[u8]) -> bool {
    record.starts_with(b"\\") || (record.len() >= 2 && record[1] == b':')
}

#[cfg(not(windows))]
fn is_absolute_windows(_record: &[u8]) -> bool {
    false
}

/// Strips one trailing LF (and a preceding CR for CRLF) from git stdout.
fn strip_line_ending(bytes: &[u8]) -> &[u8] {
    if let Some(stripped) = bytes.strip_suffix(b"\r\n") {
        stripped
    } else if let Some(stripped) = bytes.strip_suffix(b"\n") {
        stripped
    } else {
        bytes
    }
}

/// Converts a git output record to an `OsString`, byte-exact on Unix.
#[cfg(unix)]
fn os_string(bytes: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(bytes.to_vec())
}

/// Converts a git output record to an `OsString`. Windows paths are UTF-16,
/// so invalid UTF-8 bytes convert lossily (platform capability).
#[cfg(windows)]
fn os_string(bytes: &[u8]) -> OsString {
    use std::os::windows::ffi::OsStringExt;
    let text = String::from_utf8_lossy(bytes);
    OsString::from_wide(&text.encode_utf16().collect::<Vec<u16>>())
}

#[cfg(test)]
mod tests {
    use super::{Git, Mode, is_safe_relative};
    use crate::errors::Error;
    use crate::finding::Diagnostic;
    use crate::test_util::{commit_all, git, temp_repo, write_tracked, write_untracked};
    use std::ffi::OsStr;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const TEN_MIB: u64 = 10 * 1024 * 1024;

    fn skipped_large(path: &str) -> Diagnostic {
        Diagnostic {
            code: "skipped-large",
            path: path.to_string(),
            rule: String::new(),
            message: format!("{TEN_MIB} bytes exceeds the 10 MiB scan limit"),
        }
    }

    // ------------------------------------------------------------------
    // Preserved tracked-only behavior (PR1 regression guard)
    // ------------------------------------------------------------------

    #[test]
    fn root_resolves_from_nested_cwd() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("top.txt"), b"hello");
        let nested = root.join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();

        let discovered = Git::new().discover(&nested, Mode::Ci).unwrap();
        assert_eq!(discovered.root, root);
        assert_eq!(discovered.files, vec![PathBuf::from("top.txt")]);
    }

    #[test]
    fn absolute_cwd_selects_the_repository() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("abs.txt"), b"x");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.root, root);
        assert_eq!(discovered.files, vec![PathBuf::from("abs.txt")]);
    }

    #[test]
    fn c_like_pathname_is_a_file_not_a_flag() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("-C"), b"contents");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("-C")]);
    }

    #[test]
    fn operational_failures_are_typed() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(matches!(
            Git::new().discover(&missing, Mode::Ci).unwrap_err(),
            Error::InvalidWorkingDirectory { .. }
        ));
        assert!(matches!(
            Git::new().discover(dir.path(), Mode::Ci).unwrap_err(),
            Error::NotARepository { .. }
        ));
        let (_dir, root) = temp_repo();
        let git = Git {
            program: PathBuf::from("/definitely/not/git"),
        };
        assert!(matches!(
            git.discover(&root, Mode::Ci).unwrap_err(),
            Error::GitUnavailable { .. }
        ));
    }

    #[test]
    fn paths_with_spaces_newlines_and_non_ascii_are_preserved() {
        let (_dir, root) = temp_repo();
        let names = [
            OsStr::new("sp ace.txt"),
            OsStr::new("line\nbreak.txt"),
            OsStr::new("café-ünïcode.txt"),
        ];
        for name in names {
            write_tracked(&root, name, b"payload");
        }

        let mut expected: Vec<PathBuf> = names.iter().map(PathBuf::from).collect();
        expected.sort();
        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, expected);
    }

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_path_is_preserved_byte_exact() {
        use std::os::unix::ffi::OsStrExt;
        let (_dir, root) = temp_repo();
        let name = OsStr::from_bytes(b"bad-\xff-name.txt");
        write_tracked(&root, name, b"payload");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from(name)]);
    }

    #[cfg(unix)]
    #[test]
    fn tracked_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let (_dir, root) = temp_repo();
        std::fs::write(root.join("target.txt"), b"secret").unwrap();
        symlink("target.txt", root.join("link.txt")).unwrap();
        crate::test_util::git(&root, ["add", "--", "target.txt", "link.txt"]);

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("target.txt")]);
    }

    #[test]
    fn record_safety_matrix_is_enforced() {
        for record in [b"/absolute".as_slice(), b"../up", b"a/../b", b"a//b"] {
            assert!(!is_safe_relative(record), "should reject {record:?}");
        }
        for record in [
            b"a/b.txt".as_slice(),
            b"-C",
            b"sp ace\nx.txt",
            b"caf\xc3\xa9.txt",
        ] {
            assert!(is_safe_relative(record), "should accept {record:?}");
        }
    }

    // ------------------------------------------------------------------
    // 2.1: untracked + hidden (S1), .gitignore (S2), nested repo (S6), symlink (S7)
    // ------------------------------------------------------------------

    #[test]
    fn untracked_hidden_env_files_are_scanned_in_both_modes() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("tracked.txt"), b"x");
        write_untracked(&root, OsStr::new(".env"), b"token = secret\n");
        write_untracked(&root, OsStr::new(".hidden/secret.txt"), b"x");

        for mode in [Mode::Local, Mode::Ci] {
            let discovered = Git::new().discover(&root, mode).unwrap();
            assert_eq!(
                discovered.files,
                vec![
                    PathBuf::from(".env"),
                    PathBuf::from(".hidden/secret.txt"),
                    PathBuf::from("tracked.txt"),
                ],
                "mode {mode:?} must include untracked hidden files"
            );
            assert!(discovered.diagnostics.is_empty(), "mode {mode:?}");
        }
    }

    #[test]
    fn gitignored_untracked_files_and_directories_are_excluded() {
        let (_dir, root) = temp_repo();
        write_untracked(&root, OsStr::new(".gitignore"), b"*.log\nsecret-dir/\n");
        write_untracked(&root, OsStr::new("notes.log"), b"x");
        write_untracked(&root, OsStr::new("notes.txt"), b"x");
        write_untracked(&root, OsStr::new("secret-dir/inner.txt"), b"x");
        write_untracked(&root, OsStr::new("visible/ok.txt"), b"x");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(
            discovered.files,
            vec![
                PathBuf::from(".gitignore"),
                PathBuf::from("notes.txt"),
                PathBuf::from("visible/ok.txt"),
            ]
        );
    }

    #[test]
    fn nested_git_repository_is_skipped() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("top.txt"), b"x");
        let nested = root.join("vendor/inner");
        std::fs::create_dir_all(&nested).unwrap();
        git(&nested, ["init", "-q"]);
        write_untracked(&nested, OsStr::new("inner-secret.txt"), b"x");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("top.txt")]);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_outside_repo_is_not_followed() {
        use std::os::unix::fs::symlink;
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("target.txt"), b"x");
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"token = secret\n").unwrap();
        symlink(outside.path().join("secret.txt"), root.join("link-out")).unwrap();

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("target.txt")]);
    }

    // ------------------------------------------------------------------
    // 2.2: tracked-wins (S3), .sentinelignore (S4, S5), commit-state matrix
    // ------------------------------------------------------------------

    #[test]
    fn force_added_tracked_file_is_retained_despite_gitignore() {
        let (_dir, root) = temp_repo();
        write_untracked(&root, OsStr::new(".gitignore"), b"*.env\n");
        let name = OsStr::new("forced.env");
        std::fs::write(root.join(name), b"x").unwrap();
        git(
            &root,
            [OsStr::new("add"), OsStr::new("-f"), OsStr::new("--"), name],
        );

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(
            discovered.files,
            vec![PathBuf::from(".gitignore"), PathBuf::from("forced.env")]
        );
    }

    #[test]
    fn sentinelignore_excludes_tracked_and_untracked_entries() {
        let (_dir, root) = temp_repo();
        write_untracked(&root, OsStr::new(".sentinelignore"), b"*.secret\n");
        write_tracked(&root, OsStr::new("tracked.secret"), b"x");
        write_tracked(&root, OsStr::new("tracked.keep"), b"x");
        write_untracked(&root, OsStr::new("untracked.secret"), b"x");
        write_untracked(&root, OsStr::new("untracked.keep"), b"x");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(
            discovered.files,
            vec![
                PathBuf::from("tracked.keep"),
                PathBuf::from("untracked.keep"),
            ]
        );
    }

    #[test]
    fn sentinelignore_directory_pattern_excludes_whole_subtree() {
        let (_dir, root) = temp_repo();
        write_untracked(&root, OsStr::new(".sentinelignore"), b"build/\n");
        write_tracked(&root, OsStr::new("build/out.txt"), b"x");
        write_untracked(&root, OsStr::new("build/gen.txt"), b"x");
        write_tracked(&root, OsStr::new("src/main.rs"), b"x");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("src/main.rs")]);
    }

    #[test]
    fn empty_index_repo_still_finds_untracked_files() {
        let (_dir, root) = temp_repo(); // initialized, no commits
        write_untracked(&root, OsStr::new("fresh.env"), b"token = secret\n");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("fresh.env")]);
    }

    #[test]
    fn committed_file_is_retained_after_commit_all() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("committed.txt"), b"x");
        commit_all(&root, "initial");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("committed.txt")]);
    }

    // ------------------------------------------------------------------
    // 2.3: size guard (S8), invalid path (S9), `-C` file, cwd equivalence
    // ------------------------------------------------------------------

    #[test]
    fn oversized_files_are_skipped_with_a_diagnostic() {
        let (_dir, root) = temp_repo();
        let big = root.join("big.bin");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(TEN_MIB)
            .unwrap();
        let ok = root.join("ok.bin");
        std::fs::File::create(&ok)
            .unwrap()
            .set_len(TEN_MIB - 1)
            .unwrap();
        write_tracked(&root, OsStr::new("tracked-big.bin"), b"x");
        let tracked_big = root.join("tracked-big.bin");
        std::fs::File::create(&tracked_big)
            .unwrap()
            .set_len(TEN_MIB)
            .unwrap();

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("ok.bin")]);
        assert_eq!(
            discovered.diagnostics,
            vec![skipped_large("big.bin"), skipped_large("tracked-big.bin")]
        );
    }

    #[test]
    fn invalid_records_warn_and_are_excluded() {
        let (_dir, root) = temp_repo();
        let git = Git::new();
        for record in [b"/absolute".as_slice(), b"../up", b"a/../b"] {
            let diagnostic = git.accept_record(&root, record).unwrap_err();
            assert_eq!(diagnostic.code, "invalid-path", "record {record:?}");
        }
        // A valid record for an absent file is silently excluded.
        assert!(git.accept_record(&root, b"missing.txt").unwrap().is_none());
        // A valid present file is accepted.
        write_tracked(&root, OsStr::new("ok.txt"), b"x");
        assert_eq!(
            git.accept_record(&root, b"ok.txt").unwrap(),
            Some(PathBuf::from("ok.txt"))
        );
    }

    #[test]
    fn c_like_untracked_file_is_scanned_as_a_file() {
        let (_dir, root) = temp_repo();
        write_untracked(&root, OsStr::new("-C"), b"contents");

        let discovered = Git::new().discover(&root, Mode::Ci).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("-C")]);
    }

    #[test]
    fn nested_and_absolute_cwd_discover_identically() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("top.txt"), b"x");
        write_untracked(&root, OsStr::new(".env"), b"x");
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();

        let git = Git::new();
        let from_root = git.discover(&root, Mode::Ci).unwrap();
        let from_nested = git.discover(&nested, Mode::Ci).unwrap();
        assert_eq!(from_root, from_nested);
    }

    // ------------------------------------------------------------------
    // 2.4: repeated + parallel determinism (S11, S12)
    // ------------------------------------------------------------------

    #[test]
    fn repeated_discovery_is_byte_identical_with_diagnostics() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("b.txt"), b"1");
        write_untracked(&root, OsStr::new(".env"), b"x");
        let big = root.join("big.bin");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(TEN_MIB)
            .unwrap();

        let git = Git::new();
        let first = git.discover(&root, Mode::Ci).unwrap();
        let second = git.discover(&root, Mode::Ci).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.files,
            vec![PathBuf::from(".env"), PathBuf::from("b.txt")]
        );
        assert_eq!(first.diagnostics, vec![skipped_large("big.bin")]);
    }

    #[test]
    fn parallel_discovery_is_byte_identical() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("a.txt"), b"1");
        write_untracked(&root, OsStr::new("z.env"), b"2");

        let results: Vec<_> = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..2 {
                let root = root.clone();
                handles.push(scope.spawn(move || Git::new().discover(&root, Mode::Ci).unwrap()));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        assert_eq!(results[0], results[1]);
    }
}
