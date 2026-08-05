# CLI Scan Specification

## Purpose

`sentinel scan` is the sole MVP command: a fixed pipeline (discovery → engines → normalize → render), mapped to exit codes 0/1/2; no network I/O, no persistent state.

## Requirements

### Requirement: Command surface

The CLI MUST expose exactly one command, `sentinel scan`, no options, flags, or stubs; other invocations MUST fail as usage errors (stderr diagnostics, empty stdout).

#### Scenario: Minimal invocation

- GIVEN a git repo at the working directory
- WHEN `sentinel scan` runs
- THEN pipeline runs; exit 0 (no findings) or 1 (findings)

#### Scenario: Unsupported argument rejected

- GIVEN `--explain`, `--output json`, `--ci`, or a positional argument appended to `sentinel scan`
- WHEN it runs
- THEN usage error on stderr, empty stdout, exit code 2

#### Scenario: Missing subcommand

- GIVEN `sentinel` with no subcommand
- WHEN it runs
- THEN usage on stderr, exit code 2

### Requirement: Exit-code contract

`sentinel scan` MUST exit 0 (no findings), 1 (findings), or 2 (operational failure); empty repos exit 0; no others.

#### Scenario: Clean repository exits 0

- GIVEN a git repo whose tracked files contain no secrets
- WHEN `sentinel scan` runs
- THEN no findings, exit code 0

#### Scenario: Findings exit 1

- GIVEN a repo whose tracked files contain a synthetic-secret fixture
- WHEN `sentinel scan` runs
- THEN redacted findings, exit code 1

#### Scenario: Empty repository exits 0

- GIVEN an initialized git repository with no commits
- WHEN `sentinel scan` runs
- THEN zero findings and exit code 0

### Requirement: No network, no persistence, no telemetry

A scan MUST perform no network I/O, MUST NOT write, modify, or create files, MUST NOT read or write caches or persistent state, and MUST NOT collect or transmit telemetry; reads are limited to tracked files and `git` output, all other state in memory.

#### Scenario: Hermetic offline execution

- GIVEN a network-disabled environment and a read-only home
- WHEN `sentinel scan` runs on a repo with findings
- THEN output and exit code match a normal run

#### Scenario: Read boundary leaves filesystem untouched

- GIVEN a repo with findings and a pre-run snapshot of paths and mtimes
- WHEN `sentinel scan` runs
- THEN findings reported, snapshot identical, no file written, modified, or created

### Requirement: Delivery acceptance and CI quality gates

Once the manifest lands, CI MUST pass `cargo fmt -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny check`, `cargo audit`, and the test suite. Delivery MUST be four ordered stacked-to-main work units (below), each ≤ 800 lines with the accepted size exception; the 400-line gate stays repository policy, and the exception MUST appear on every PR (no PR above 400 lines is compliant without it).

| PR | Unit | Acceptance |
|----|------|------------|
| 1 | manifest/green crate | gates green |
| 2 | CLI/errors/discovery/model | exits 0/2 |
| 3 | engine/normalize/render | redacted findings, exit 1 |
| 4 | fixtures/integration/final gates | goldens, byte-compare |

#### Scenario: PR 1 acceptance boundary

- GIVEN PR 1 (manifest, green crate) ≤ 800 lines, exception accepted
- WHEN CI runs
- THEN manifest lands green; gates and tests pass

#### Scenario: PR 2 acceptance boundary

- GIVEN PR 2 (CLI, errors, git discovery, finding model) ≤ 800 lines, exception accepted
- WHEN CI runs
- THEN clean repo exits 0, non-repo/git-missing exit 2, gates green

#### Scenario: PR 3 acceptance boundary

- GIVEN PR 3 (secrets engine, normalization, renderer) ≤ 800 lines, exception accepted
- WHEN CI runs the fixture suite
- THEN redacted findings, exit 1, gates green

#### Scenario: PR 4 acceptance boundary

- GIVEN PR 4 (fixtures, integration, final gates) ≤ 800 lines, exception accepted
- WHEN CI runs the fixture suite twice and byte-compares
- THEN redacted findings, exit 1, both runs byte-identical, gates green
