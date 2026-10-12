# CLI Scan Specification

## Purpose

`sentinel scan` is the sole MVP command: a fixed pipeline (discovery → engines → normalize → render), mapped to exit codes 0/1/2. Unless `--offline`, it MAY call `api.osv.dev` and write the XDG OSV advisory cache; it MUST NOT modify the repository or emit telemetry.

## Requirements

### Requirement: Command surface

The CLI MUST expose exactly one command, `sentinel scan`, with options `--ci`, `--offline`, `--output <terminal|json|sarif>` (default `terminal`), and `--report <path>`; all other options MUST fail as usage errors (stderr, empty stdout). `--offline` MUST be orthogonal to `--ci`.

#### Scenario: Minimal invocation

- GIVEN a git repo at the working directory
- WHEN `sentinel scan` runs
- THEN pipeline runs; exit 0 or 1

#### Scenario: Accepted flags

- GIVEN `--ci`, `--offline`, `--ci --offline`, or `--output json|sarif` with optional `--report`
- WHEN `sentinel scan` runs
- THEN the flag is honored (`--ci` hermetic; `--offline` zero HTTP); exit 0 or 1

#### Scenario: Usage errors

- GIVEN `--explain`, a positional, `--output yaml`, or no subcommand
- WHEN it runs
- THEN usage on stderr, empty stdout, exit 2

### Requirement: Exit-code contract

`sentinel scan` MUST exit 0 (no findings), 1 (findings from any engine), or 2 (operational failure); empty repos exit 0. Network or cache degradation MUST NOT exit 2.

#### Scenario: Clean or empty exits 0

- GIVEN a clean repo or an empty initialized repo
- WHEN `sentinel scan` runs
- THEN no findings, exit 0

#### Scenario: Findings exit 1

- GIVEN a synthetic-secret fixture
- WHEN `sentinel scan` runs
- THEN redacted findings, exit 1

#### Scenario: Dependency degrade does not exit 2

- GIVEN OSV unreachable after retries and no cache
- WHEN `sentinel scan` runs
- THEN warn, skip dependency findings, secrets still report, exit 0 or 1

### Requirement: Network, cache, and telemetry policy

Unless `--offline`, a scan MAY call only `api.osv.dev` `/v1/querybatch` and `/v1/vulns/{id}` and MAY write only the XDG advisory cache; it MUST NOT modify the repo or emit telemetry. With `--offline`, a scan MUST do zero HTTP and MUST NOT write the cache; reads are tracked files, `git` output, and the cache.

#### Scenario: Hermetic offline execution

- GIVEN a network-disabled environment and a read-only home
- WHEN `sentinel scan --offline` runs on a repo with findings
- THEN output and exit match a normal offline run

#### Scenario: Online I/O bounds

- GIVEN a findings repo with a path/mtime snapshot and an endpoint stub
- WHEN `sentinel scan` runs online
- THEN only OSV batch/detail are contacted; repo snapshot is unchanged; only the XDG cache is written

### Requirement: Delivery acceptance and CI quality gates

Once the manifest lands, CI MUST pass `cargo fmt -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny check`, `cargo audit`, and the test suite. Delivery MUST be four ordered stacked-to-main work units (below), each ≤ 800 lines with the accepted size exception; the 400-line gate stays repository policy, and the exception MUST appear on every PR (no PR above 400 lines is compliant without it).

| PR | Unit                             | Acceptance                |
| -- | -------------------------------- | ------------------------- |
| 1  | manifest/green crate             | gates green               |
| 2  | CLI/errors/discovery/model       | exits 0/2                 |
| 3  | engine/normalize/render          | redacted findings, exit 1 |
| 4  | fixtures/integration/final gates | goldens, byte-compare     |

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

### Requirement: Report file output

With `--output json|sarif`, `--report <path>` MUST write the report to the file (deterministic overwrite) while stdout stays empty; `--report` with `--output terminal` MUST be a usage error. An unwritable report path MUST emit `cannot write scan report` on stderr and exit 2. Diagnostics MUST always go to stderr; `--report` MUST NOT capture them.

#### Scenario: Report written to file

- GIVEN a repo with findings and `--output json --report out.json`
- WHEN `sentinel scan` runs
- THEN `out.json` contains the report, stdout is empty, exit 1

#### Scenario: Report with terminal output rejected

- GIVEN `--output terminal --report out.json`
- WHEN it runs
- THEN usage error on stderr, empty stdout, exit code 2

#### Scenario: Unwritable report path exits 2

- GIVEN `--output sarif --report /unwritable/out.sarif`
- WHEN it runs
- THEN stderr shows `cannot write scan report`, exit code 2

#### Scenario: Diagnostics stay on stderr

- GIVEN `--output json --report out.json` and a rule-failed diagnostic
- WHEN `sentinel scan` runs
- THEN the diagnostic appears on stderr only, never in `out.json`
