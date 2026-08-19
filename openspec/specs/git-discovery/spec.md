# Git Discovery Specification

## Purpose

Discovery produces the scan input set "the way Git sees it": the repository root and its tracked files, using `git` itself as the source of truth. The output is a deterministic, NUL-safe list of repo-relative paths (PRD KPI 2).

## Requirements

### Requirement: Repository root resolution

Discovery MUST resolve the current repository root from the working directory using `git rev-parse --show-toplevel`. Reported paths MUST be relative to that root and MUST use forward slashes regardless of platform.

#### Scenario: Root resolved from a subdirectory

- GIVEN a working directory nested inside a git repository
- WHEN discovery runs
- THEN the repository root is resolved and all emitted paths are relative to it

### Requirement: Tracked-file discovery

Discovery MUST enumerate tracked files with `git ls-files -z`, consuming NUL-delimited output so paths containing spaces, newlines, or non-ASCII characters are preserved exactly.

#### Scenario: Paths with spaces and newlines

- GIVEN tracked files whose names contain spaces and a newline character
- WHEN discovery runs
- THEN every such file is present in the file set, byte-exact, and not split at whitespace

### Requirement: Empty repository behavior

An empty repository (initialized, no commits) MUST yield an empty file set. The scan then proceeds normally and exits 0; it MUST NOT be treated as an operational failure.

#### Scenario: Empty repo scans clean

- GIVEN a git repository with no commits
- WHEN discovery runs
- THEN the file set is empty and the pipeline continues without error

### Requirement: Operational failure modes

Discovery MUST fail the scan with a clear stderr diagnostic and exit code 2 when the working directory is not inside a git repository, or when `git` is not available on PATH. The `git` dependency MUST be verified up front, before any scanning.

#### Scenario: Not a repository

- GIVEN a directory that is not inside a git repository
- WHEN `sentinel scan` runs
- THEN a clear error is written to stderr and the exit code is 2

#### Scenario: git missing

- GIVEN an environment where `git` is absent from PATH
- WHEN `sentinel scan` runs in a repository
- THEN a clear error is written to stderr and the exit code is 2

### Requirement: Determinism of the file set

For an identical repository state, discovery MUST produce a byte-identical file set on every invocation, including concurrent invocations, and MUST emit entries in deterministic sorted order.

#### Scenario: Repeated discovery

- GIVEN an unchanged repository
- WHEN discovery runs twice
- THEN both file sets are identical

#### Scenario: Parallel discovery

- GIVEN an unchanged repository
- WHEN discovery runs twice concurrently
- THEN both file sets are byte-identical

### Requirement: Untracked-file discovery

Discovery MUST include untracked files (hidden files and directories included), MUST NOT follow symbolic links, MUST only run inside a git repository, and MUST exclude the `.git` directory.

#### Scenario: Untracked and hidden files scanned

- GIVEN a repo with an untracked `.env` and a hidden file under a hidden directory
- WHEN discovery runs
- THEN both files are present in the file set

#### Scenario: Ignored untracked files excluded

- GIVEN untracked files ignored by `.gitignore` file and directory patterns
- WHEN discovery runs
- THEN every ignored file and ignored directory subtree is absent from the file set

### Requirement: Ignore precedence and .sentinelignore

Union entries MUST be deduplicated. Tracked files MUST be retained even when Git ignores them. A root `.sentinelignore` MUST exclude every matching entry in the full union — tracked and untracked — whole subtrees included, and MUST take precedence over the tracked-beats-ignore rule.

#### Scenario: Tracked-ignored files retained

- GIVEN a file force-added with `git add -f` while matching `.gitignore`
- WHEN discovery runs
- THEN the file remains in the file set

#### Scenario: Sentinelignore excludes both classes

- GIVEN a `.sentinelignore` pattern matching a tracked and an untracked file
- WHEN discovery runs
- THEN both files are absent from the file set

#### Scenario: Full-file scope

- GIVEN a `.sentinelignore` directory pattern
- WHEN discovery runs
- THEN the entire matching subtree is absent from the file set

### Requirement: Nested repositories and symlinks

Discovery MUST skip any nested git repository, and MUST NOT follow symlinks.

#### Scenario: Nested repository excluded

- GIVEN a subdirectory that is itself a git repository
- WHEN discovery runs
- THEN no file under the nested repository appears in the file set

#### Scenario: Symlink target not traversed

- GIVEN a symlink pointing outside the repository
- WHEN discovery runs
- THEN the symlink is not followed and its target files are absent from the file set

### Requirement: Size guard

Discovery MUST skip any file at or above 10 MiB and MUST emit a deterministic `skipped-large` diagnostic on stderr without changing exit status.

#### Scenario: Oversized file skipped

- GIVEN a 10 MiB file in the file set
- WHEN discovery runs
- THEN the file is skipped, a `skipped-large` diagnostic appears on stderr, and the exit status is unchanged

### Requirement: Invalid path handling

Union entries that fail path validation MUST be excluded deterministically with a stderr warning and MUST NOT fail the scan.

#### Scenario: Invalid path excluded

- GIVEN a union entry that is not a valid repo-relative path
- WHEN discovery runs
- THEN the entry is excluded with a warning and the scan continues

### Requirement: Unreadable file handling

A file in the file set that cannot be read MUST produce a warning on stderr and MUST NOT abort the scan or change exit status.

#### Scenario: Unreadable file warned

- GIVEN a file in the file set without read permission
- WHEN discovery runs
- THEN a warning appears on stderr, the file is skipped, and the scan continues with exit status unchanged
