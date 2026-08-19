# Delta for git-discovery

## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Determinism of the file set

For an identical repository state, discovery MUST produce a byte-identical file set on every invocation, including concurrent invocations, and MUST emit entries in deterministic sorted order.
(Previously: an identical file set per invocation, with no explicit byte-identical, parallel-run, or ordering guarantee.)

#### Scenario: Repeated discovery

- GIVEN an unchanged repository
- WHEN discovery runs twice
- THEN both file sets are identical

#### Scenario: Parallel discovery

- GIVEN an unchanged repository
- WHEN discovery runs twice concurrently
- THEN both file sets are byte-identical

## Preserved contracts

`Repository root resolution`, `Tracked-file discovery`, `Empty repository behavior`, and `Operational failure modes` (non-repo/git-missing exit 2) are unchanged.
