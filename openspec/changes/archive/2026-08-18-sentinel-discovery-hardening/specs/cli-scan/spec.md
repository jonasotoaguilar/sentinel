# Delta for cli-scan

## ADDED Requirements

### Requirement: Hermetic CI mode

`sentinel scan --ci` MUST ignore parent, global, and `.git/info/exclude` ambient ignore sources, using repository-local sources only. Local mode MUST keep git-natural behavior. `--ci` MUST NOT change blocking policy or exit-code behavior; exit codes remain exactly 0, 1, or 2.

#### Scenario: Ambient ignores disabled under CI

- GIVEN a file ignored only by a parent or global gitignore
- WHEN `sentinel scan --ci` runs
- THEN the file is scanned as untracked

#### Scenario: Local mode stays git-natural

- GIVEN the same repository without `--ci`
- WHEN `sentinel scan` runs
- THEN the ambient-ignored file is omitted

#### Scenario: Exit codes unchanged under CI

- GIVEN a repo with an untracked synthetic-secret fixture
- WHEN `sentinel scan --ci` runs
- THEN redacted findings and exit code 1, identical to a local run

## MODIFIED Requirements

### Requirement: Command surface

The CLI MUST expose exactly one command, `sentinel scan`, with `--ci` as its only supported option; other options, flags, or stubs MUST fail as usage errors (stderr diagnostics, empty stdout).
(Previously: no options, flags, or stubs; `--ci` was rejected as unsupported.)

#### Scenario: Minimal invocation

- GIVEN a git repo at the working directory
- WHEN `sentinel scan` runs
- THEN pipeline runs; exit 0 (no findings) or 1 (findings)

#### Scenario: CI flag accepted

- GIVEN a git repo at the working directory
- WHEN `sentinel scan --ci` runs
- THEN the pipeline runs with hermetic ignores; exit 0 (no findings) or 1 (findings)

#### Scenario: Unsupported argument rejected

- GIVEN `--explain`, `--output json`, or a positional argument appended to `sentinel scan`
- WHEN it runs
- THEN usage error on stderr, empty stdout, exit code 2

#### Scenario: Missing subcommand

- GIVEN `sentinel` with no subcommand
- WHEN it runs
- THEN usage on stderr, exit code 2

## Preserved contracts

`Exit-code contract` (0/1/2), `No network, no persistence, no telemetry`, and `Delivery acceptance and CI quality gates` are unchanged; finding, fingerprint, normalization, and rendering behavior is out of scope.
