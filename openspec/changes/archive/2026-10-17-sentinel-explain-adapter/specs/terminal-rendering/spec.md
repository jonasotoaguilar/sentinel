# Delta for terminal-rendering

## ADDED Requirements

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
