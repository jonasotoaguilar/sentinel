//! Git-backed discovery: repository root + tracked files, "the way Git sees
//! it" (git-discovery spec).
//!
//! Git is invoked with separate `Command` arguments, never a shell; the
//! working directory alone selects the repository. `rev-parse
//! --show-toplevel` resolves the root and `ls-files -z` enumerates tracked
//! files as NUL-delimited bytes, so spaces, newlines, and non-ASCII (and
//! invalid-UTF-8 on Unix) are preserved exactly. Records that are absolute,
//! parent-traversing, empty-interior, symlinks, or non-regular files are
//! rejected before they enter the scan input set.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::errors::Error;

/// Discovered scan input set: the repository root and its tracked files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// Absolute repository root (worktree top level).
    pub root: PathBuf,
    /// Validated tracked files, repo-relative, sorted deterministically.
    pub files: Vec<PathBuf>,
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

    /// Resolves the repository root and the validated tracked file set for
    /// `cwd`. Every failure is a typed operational error (exit 2). `ls-files`
    /// runs from the resolved root, so emitted paths are root-relative even
    /// when `cwd` is nested inside the repository.
    pub fn discover(&self, cwd: &Path) -> Result<Discovered, Error> {
        if !cwd.is_dir() {
            return Err(Error::InvalidWorkingDirectory {
                path: cwd.to_path_buf(),
            });
        }
        let root = self.show_toplevel(cwd)?;
        let records = self.tracked_records(&root)?;
        let mut files: Vec<PathBuf> = records
            .iter()
            .filter_map(|record| self.accept_record(&root, record))
            .collect();
        files.sort();
        Ok(Discovered { root, files })
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

    /// Validates one `ls-files` record and rejects unsafe or non-regular
    /// paths (symlinks, submodule gitlinks, deleted files).
    fn accept_record(&self, root: &Path, record: &[u8]) -> Option<PathBuf> {
        if !is_safe_relative(record) {
            return None;
        }
        let path = PathBuf::from(os_string(record));
        match fs::symlink_metadata(root.join(&path)) {
            Ok(metadata) if metadata.file_type().is_file() => Some(path),
            _ => None,
        }
    }
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
    use super::{Git, is_safe_relative};
    use crate::errors::Error;
    use crate::test_util::{temp_repo, write_tracked};
    use std::ffi::OsStr;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn root_resolves_from_nested_cwd() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("top.txt"), b"hello");
        let nested = root.join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();

        let discovered = Git::new().discover(&nested).unwrap();
        assert_eq!(discovered.root, root);
        assert_eq!(discovered.files, vec![PathBuf::from("top.txt")]);
    }

    #[test]
    fn absolute_cwd_selects_the_repository() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("abs.txt"), b"x");

        let discovered = Git::new().discover(&root).unwrap();
        assert_eq!(discovered.root, root);
        assert_eq!(discovered.files, vec![PathBuf::from("abs.txt")]);
    }

    #[test]
    fn c_like_pathname_is_a_file_not_a_flag() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("-C"), b"contents");

        let discovered = Git::new().discover(&root).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("-C")]);
    }

    #[test]
    fn operational_failures_are_typed() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(matches!(
            Git::new().discover(&missing).unwrap_err(),
            Error::InvalidWorkingDirectory { .. }
        ));
        assert!(matches!(
            Git::new().discover(dir.path()).unwrap_err(),
            Error::NotARepository { .. }
        ));
        let (_dir, root) = temp_repo();
        let git = Git {
            program: PathBuf::from("/definitely/not/git"),
        };
        assert!(matches!(
            git.discover(&root).unwrap_err(),
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
        let discovered = Git::new().discover(&root).unwrap();
        assert_eq!(discovered.files, expected);
    }

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_path_is_preserved_byte_exact() {
        use std::os::unix::ffi::OsStrExt;
        let (_dir, root) = temp_repo();
        let name = OsStr::from_bytes(b"bad-\xff-name.txt");
        write_tracked(&root, name, b"payload");

        let discovered = Git::new().discover(&root).unwrap();
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

        let discovered = Git::new().discover(&root).unwrap();
        assert_eq!(discovered.files, vec![PathBuf::from("target.txt")]);
    }

    #[test]
    fn repeated_discovery_is_identical() {
        let (_dir, root) = temp_repo();
        write_tracked(&root, OsStr::new("b.txt"), b"1");
        write_tracked(&root, OsStr::new("a.txt"), b"2");

        let git = Git::new();
        let first = git.discover(&root).unwrap();
        let second = git.discover(&root).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.files,
            vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")]
        );
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
}
