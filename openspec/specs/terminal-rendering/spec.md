# Terminal Rendering Specification

## Purpose

The terminal renderer converts normalized findings into the human-readable report written to stdout, while all diagnostics go to stderr. Rendering is a pure function of the scan result, so repeated scans are byte-identical (PRD KPI 2 / AC3).

## Requirements

### Requirement: stdout/stderr contract

Rendering MUST write the findings report to stdout and all diagnostics (tracing, warnings, errors) to stderr. stdout MUST contain only report content; diagnostic logging MUST NOT appear on stdout.

#### Scenario: Findings on stdout, diagnostics on stderr

- GIVEN a scan producing findings and at least one warning
- WHEN the report is captured
- THEN stdout contains the findings report and stderr contains the warning

### Requirement: Redacted output

Rendered output MUST NOT contain raw secret values; only redacted evidence may appear (PRD KPI 4).

#### Scenario: No raw secrets in report

- GIVEN a scan of a synthetic-secret fixture
- WHEN stdout and stderr are captured
- THEN neither stream contains the raw secret value

### Requirement: Exit-code mapping

The renderer MUST NOT alter the exit code: findings present → exit 1, no findings → exit 0. A rendering/output failure MUST map to exit code 2 (operational failure).

#### Scenario: Findings map to exit 1

- GIVEN a scan with findings
- WHEN the process exits
- THEN the exit code is 1

#### Scenario: Rendering failure maps to exit 2

- GIVEN a rendering failure (e.g., unwritable stdout destination)
- WHEN the process exits
- THEN the exit code is 2 and a diagnostic is written to stderr

### Requirement: Advisory text is display-only and terminal-exclusive

When `--explain` produces advisory text for a finding, the terminal renderer MUST
print it on one line associated with that finding, after the finding's existing
lines, and MUST NOT alter any other line. The line MUST be sanitized: control
characters removed, newlines and tabs collapsed to single spaces, at most 500
characters. Advisory text MUST NOT appear in the `json` or `sarif` reports, and
the finding block MUST be byte-identical to a scan without `--explain` when no
advisory text exists for that finding.

#### Scenario: Advisory line is additive

- GIVEN a scan with `--explain` where the adapter returns text for one finding
- WHEN terminal output is rendered
- THEN that finding's existing lines are unchanged and exactly one advisory line
  follows them

#### Scenario: Machine formats exclude advisory text

- GIVEN the same scan with `--output json` and `--output sarif`
- WHEN the reports are rendered
- THEN neither report contains any advisory text and both are byte-identical to a
  scan without `--explain`

#### Scenario: Sanitization holds under hostile text

- GIVEN advisory text containing a newline, an ANSI escape sequence, and a line
  shaped like a finding
- WHEN terminal output is rendered
- THEN the text occupies a single line with no escape characters

### Requirement: Byte-identical repeated runs

Rendered output MUST contain no timestamps or run-derived fields. For an identical repository and environment, repeated scans MUST produce byte-identical stdout and stderr.

#### Scenario: Determinism gate

- GIVEN an unchanged repository with findings
- WHEN `sentinel scan` runs twice and the outputs are byte-compared
- THEN stdout and stderr from both runs are identical
