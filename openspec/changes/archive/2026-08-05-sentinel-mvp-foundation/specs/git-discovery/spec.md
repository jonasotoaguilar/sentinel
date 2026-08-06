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

For an identical repository state, discovery MUST produce an identical file set on every invocation.

#### Scenario: Repeated discovery

- GIVEN an unchanged repository
- WHEN discovery runs twice
- THEN both file sets are identical
