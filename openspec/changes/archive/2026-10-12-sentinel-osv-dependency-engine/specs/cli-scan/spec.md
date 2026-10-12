# Delta for cli-scan

## MODIFIED Requirements

### Requirement: Command surface

The CLI MUST expose exactly one command, `sentinel scan`, with options `--ci`, `--offline`, `--output <terminal|json|sarif>` (default `terminal`), and `--report <path>`; all other options MUST fail as usage errors (stderr, empty stdout). `--offline` MUST be orthogonal to `--ci`.

(Previously: no `--offline`; that flag was a usage error.)

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

(Previously: 0/1/2 only; degrade-vs-2 was undefined.)

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

(Previously: no network, no writes, no caches, no telemetry.)

#### Scenario: Hermetic offline execution

- GIVEN a network-disabled environment and a read-only home
- WHEN `sentinel scan --offline` runs on a repo with findings
- THEN output and exit match a normal offline run

#### Scenario: Online I/O bounds

- GIVEN a findings repo with a path/mtime snapshot and an endpoint stub
- WHEN `sentinel scan` runs online
- THEN only OSV batch/detail are contacted; repo snapshot is unchanged; only the XDG cache is written

## RENAMED Requirements

### Requirement: No network, no persistence, no telemetry → Network, cache, and telemetry policy

(Reason: bounded OSV HTTP and XDG cache writes unless `--offline`.)
(Migration: retarget docs/tests to the new name; behavior is the MODIFIED block above.)
