# Delta for cli-scan

## MODIFIED Requirements

### Requirement: Command surface

The CLI MUST expose exactly one command, `sentinel scan`, with options `--ci`, `--output <terminal|json|sarif>` (default `terminal`), and `--report <path>`; all other options, flags, or stubs MUST fail as usage errors (stderr diagnostics, empty stdout).
(Previously: no options except `--ci`; `--output`/`--report` were rejected as unsupported.)

#### Scenario: Minimal invocation

- GIVEN a git repo at the working directory
- WHEN `sentinel scan` runs
- THEN pipeline runs; exit 0 (no findings) or 1 (findings)

#### Scenario: CI flag accepted

- GIVEN a git repo at the working directory
- WHEN `sentinel scan --ci` runs
- THEN the pipeline runs with hermetic ignores; exit 0 (no findings) or 1 (findings)

#### Scenario: Output and report flags accepted

- GIVEN `--output json` or `--output sarif`, optionally with `--report <path>`
- WHEN `sentinel scan` runs
- THEN the chosen report is emitted; exit codes 0/1 unchanged

#### Scenario: Unsupported argument rejected

- GIVEN `--explain` or a positional argument appended to `sentinel scan`
- WHEN it runs
- THEN usage error on stderr, empty stdout, exit code 2

#### Scenario: Invalid output value rejected

- GIVEN `--output yaml`
- WHEN it runs
- THEN usage error on stderr, empty stdout, exit code 2

#### Scenario: Missing subcommand

- GIVEN `sentinel` with no subcommand
- WHEN it runs
- THEN usage on stderr, exit code 2

## ADDED Requirements

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

## Preserved contracts

`Exit-code contract` (0/1/2), `No network, no persistence, no telemetry`, and `Delivery acceptance and CI quality gates` are unchanged; terminal output remains byte-identical (existing goldens untouched).
