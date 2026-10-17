# Explain Adapter Specification

## Purpose

Adds advisory-only context to findings through an opt-in `Explainer` seam that can
never influence severity, blocking, ordering, or the exit code.

## Requirements

### Requirement: Opt-in, forced-off activation

The adapter MUST run only when `--explain` is given AND neither `--ci` nor
`--offline` is set AND an endpoint with a credential is configured. Under `--ci`
or `--offline` the adapter MUST NOT be invoked at all: zero HTTP requests and zero
explanation work, observable through the injected explainer's call count. When
`--explain` is given without a usable configuration the scan MUST emit exactly one
`explain-skipped` diagnostic and MUST NOT attempt a request.

#### Scenario: Disabled by default

- GIVEN a repo with findings and a configured adapter
- WHEN `sentinel scan` runs without `--explain`
- THEN the adapter is invoked zero times and no advisory line is rendered

#### Scenario: Enabled only on request

- GIVEN the same repo
- WHEN `sentinel scan --explain` runs
- THEN the adapter is invoked exactly once for the scan

#### Scenario: CI and offline force it off

- GIVEN `--explain` combined with `--ci`, and separately with `--offline`
- WHEN the scan runs
- THEN the adapter is invoked zero times, `--offline` issues zero HTTP, and the
  exit code is unchanged

#### Scenario: Missing configuration degrades

- GIVEN `--explain` with no endpoint or credential configured
- WHEN the scan runs
- THEN one `explain-skipped` diagnostic is emitted, no request is attempted, and
  findings and exit code are unchanged

### Requirement: Bounded single-attempt request

The adapter MUST make at most one request per scan, carrying every finding's
redacted summary in that single request, subject to a fixed budget: at most 20
findings ordered by the canonical finding order, and at most 4096 bytes of context.
Each request MUST have a timeout of at most 10 seconds and MUST NOT be retried.
Exceeding the budget MUST truncate the request to the budget, never reorder or
split it into further requests.

#### Scenario: One request, bounded content

- GIVEN a scan with 50 findings
- WHEN the adapter runs
- THEN exactly one request is issued and its context covers the first 20 findings
  in canonical order within the byte budget

#### Scenario: Timeout and error are not retried

- GIVEN an adapter that times out, then one that returns HTTP 500
- WHEN the scan runs
- THEN each issues exactly one attempt, emits one `explain-failed` diagnostic, and
  the scan still completes with unchanged findings and exit code

### Requirement: Advisory-only guarantee

Explainer output MUST NOT be able to influence severity, the finding set, dedupe,
ordering, exit code, fingerprints, or any machine-readable output. JSON and SARIF
bytes MUST be identical with and without `--explain`, for the same repository
state. Advisory text MUST appear only in terminal output.

#### Scenario: Differential scan is identical

- GIVEN the same repo, an adapter returning text for every finding, and a second
  scan without `--explain`
- WHEN both run
- THEN exit codes match, the finding lines match, and `--output json` bytes are
  byte-identical between the two runs

#### Scenario: Machine formats stay clean

- GIVEN `--explain --output json` and `--explain --output sarif`
- WHEN the scan runs
- THEN no advisory text appears in either report

### Requirement: Redacted context and sanitized output

The context sent to the adapter MUST be built from the normalized, already-redacted
findings; raw values MUST NOT be reachable. Responses are untrusted: text MUST be
sanitized before rendering — control characters removed, newlines and tabs
collapsed to single spaces, length capped at 500 characters — so response text
cannot forge a finding line or break line-oriented output. A response that is not
an array of `{id, text}` objects MUST emit one `explain-invalid` diagnostic and
degrade to no advisories; entries whose `id` does not match a finding MUST be
ignored.

#### Scenario: No raw value reaches the adapter or the output

- GIVEN a fixture whose finding line contains a synthetic secret
- WHEN `--explain` runs with a recording stub
- THEN the recorded payload, stdout, stderr, and any report file contain no raw
  value, and each raw occurrence is `[REDACTED]`

#### Scenario: Secrets in file and directory names stay inside the process

- GIVEN a manifest under `deps/<secret>/` with a seeded offline cache hit,
  and a tracked oversized file named `<secret>.bin`
- WHEN the scan runs with `--explain` and `--output json`
- THEN no finding `id`, `path`, diagnostic, report file, or outbound payload
  field carries the raw value; each raw occurrence is `[REDACTED]`, while
  reading, caching, and lookup still use the real path

#### Scenario: Hostile response text is contained

- GIVEN a response whose text contains newlines, ANSI escapes, and a line that
  looks like a finding
- WHEN it is rendered
- THEN the advisory occupies one line with no escape characters and cannot be
  mistaken for a finding line

#### Scenario: Malformed response degrades

- GIVEN a response that is not an array of objects, and one that is valid JSON but
  has unknown ids
- WHEN the scan runs
- THEN the first emits exactly one `explain-invalid` diagnostic with no advisories,
  and the second emits no diagnostic and no advisory for the unknown id
