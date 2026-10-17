# Delta for cli-scan

## MODIFIED Requirements

### Requirement: Command surface

The CLI MUST expose exactly one command, `sentinel scan`, with options `--ci`, `--offline`, `--explain`, `--output <terminal|json|sarif>` (default `terminal`), and `--report <path>`; all other options MUST fail as usage errors (stderr, empty stdout). `--offline` MUST be orthogonal to `--ci`, and `--explain` MUST be orthogonal to both: it is an advisory-only switch that never changes findings, severity, ordering, or the exit code, and it is inert under `--ci` and `--offline`.
(Previously: `--explain` was listed as a usage error; the accepted surface was `--ci`, `--offline`, `--output`, and `--report`.)

#### Scenario: Minimal invocation

- GIVEN a git repo at the working directory
- WHEN `sentinel scan` runs
- THEN pipeline runs; exit 0 or 1

#### Scenario: Accepted flags

- GIVEN `--ci`, `--offline`, `--ci --offline`, or `--output json|sarif` with optional `--report`
- WHEN `sentinel scan` runs
- THEN the flag is honored (`--ci` hermetic; `--offline` zero HTTP); exit 0 or 1

#### Scenario: Explain flag accepted and inert under CI and offline

- GIVEN `--explain`, `--explain --ci`, and `--explain --offline`
- WHEN `sentinel scan` runs
- THEN the same findings, severity, ordering and exit code are produced as without
  `--explain`, and no explanation request is issued in the `--ci` or `--offline` runs

#### Scenario: Usage errors

- GIVEN a positional, `--output yaml`, or no subcommand
- WHEN it runs
- THEN usage on stderr, empty stdout, exit 2
