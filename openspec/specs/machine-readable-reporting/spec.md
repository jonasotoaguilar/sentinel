# Machine-Readable Reporting Specification

## Purpose

Emit versioned JSON and SARIF 2.1.0 reports from the existing redacted, deterministically ordered findings, enabling CI ingestion. Pure renderers; no network, no timestamps, no run-derived fields.

## Requirements

### Requirement: Versioned JSON envelope

The JSON report MUST use `schema_version: "1.0.0"`, tool `name` `sentinel` and build-time `version` (`CARGO_PKG_VERSION`), and a `findings` array sorted by (fingerprint, path, line). Each finding MUST include `id`, `engine`, `rule_id`, `severity`, `location` (`path` repo-relative forward-slash, `line`, `column`, `snippet`), `message`, and `evidence`. Fields MUST evolve additively; `rule_id` values MUST remain stable; no timestamps or run-derived fields.

#### Scenario: Full scan emits complete envelope

- GIVEN a repo with redacted findings
- WHEN `sentinel scan --output json` runs
- THEN stdout is valid JSON with all listed fields and findings sorted

#### Scenario: Empty findings emit empty array

- GIVEN a clean repo
- WHEN `sentinel scan --output json` runs
- THEN `findings` is `[]` and exit 0

#### Scenario: Special characters in messages

- GIVEN a finding whose message or snippet contains quotes or newlines
- WHEN the JSON report is emitted
- THEN the report remains valid JSON (escaped)

### Requirement: Lowercase JSON severity

JSON `severity` MUST serialize as lowercase (`low`, `medium`, `high`, `critical`).

#### Scenario: All severities lowercased

- GIVEN findings at all four severities
- WHEN `--output json` runs
- THEN severity values are exactly `low`/`medium`/`high`/`critical`

### Requirement: SARIF 2.1.0 envelope

The SARIF report MUST declare `$schema` (2.1.0 URI) and `version: "2.1.0"`, with `runs[].tool.driver` carrying `name`, `version`, and `rules[]` sorted by `rule_id` so `rule.index` stays stable as rules are added. Each result MUST include `ruleId`, `rule.index`, `level`, `message.text`, and `locations[].physicalLocation` with `artifactLocation.uri` (repo-relative, forward slashes, RFC 3986 percent-encoded) and `region` (`startLine`, `startColumn`, 1-based). No timestamps.

| Severity | `level` |
|---|---|
| LOW | `note` |
| MEDIUM | `warning` |
| HIGH / CRITICAL | `error` |

#### Scenario: Full scan emits valid log

- GIVEN a repo with redacted findings
- WHEN `sentinel scan --output sarif` runs
- THEN stdout is a schema-valid 2.1.0 log with sorted rules and indexed results

#### Scenario: Empty findings valid log

- GIVEN a clean repo
- WHEN `--output sarif` runs
- THEN `results` is `[]` and exit 0

#### Scenario: Severity mapping

- GIVEN findings at all four severities
- WHEN `--output sarif` runs
- THEN levels match the table (HIGH and CRITICAL both `error`)

#### Scenario: Special path characters

- GIVEN a finding whose path contains a space, `#`, `%`, or non-ASCII bytes
- WHEN `--output sarif` runs
- THEN the URI is percent-encoded per RFC 3986

### Requirement: Redacted bytes

JSON and SARIF bytes MUST NOT contain raw secret values.

#### Scenario: Raw secrets absent from both formats

- GIVEN fixtures containing raw secret strings
- WHEN JSON and SARIF reports are emitted
- THEN neither report's bytes contain a raw secret

### Requirement: Deterministic output

Repeated scans MUST produce byte-identical JSON and SARIF. Serializers MUST use structs (declaration order), never maps.

#### Scenario: Run-twice byte comparison

- GIVEN the same repo
- WHEN `--output json` and `--output sarif` each run twice
- THEN each format's two runs are byte-identical

### Requirement: Hermetic schema validation

Tests MUST validate SARIF output against a pinned copy of the official SARIF 2.1.0 JSON schema under `tests/fixtures/`, with no network access.

#### Scenario: Pinned-schema validation

- GIVEN the pinned schema fixture
- WHEN the SARIF report is validated in tests
- THEN validation passes without network access
