# Secrets Detection Specification

## Purpose

The secrets engine scans tracked file bytes with a curated set of regular-expression rules and emits findings whose evidence is redacted. Raw secret values never leave the engine boundary (PRD KPI 4; ADR-0003).

## Requirements

### Requirement: Curated regex rule set

The engine MUST apply a static, curated table of regex rules for API keys, tokens, and credentials over file bytes. Rules MUST NOT be loaded from user input or external configuration in the MVP.

#### Scenario: Known secret detected

- GIVEN a tracked fixture file containing a synthetic AWS access key
- WHEN the secrets engine scans the file
- THEN a finding is emitted referencing the matching rule ID

### Requirement: Rule-ID stability

Every rule MUST have a stable ID of the form `SECRET-<KEBAB-NAME>`. IDs MUST remain stable across releases; when a rule is renamed, the old ID MUST remain resolvable through a `deprecated_ids` alias.

#### Scenario: Renamed rule keeps old ID resolvable

- GIVEN a rule renamed from `SECRET-OLD` to `SECRET-NEW` with `deprecated_ids: ["SECRET-OLD"]`
- WHEN output references the rule
- THEN findings reference `SECRET-NEW` and `SECRET-OLD` remains resolvable to the same rule

### Requirement: Redaction at the engine boundary

The engine MUST replace matched secret values with a redaction placeholder before any finding leaves the engine. Raw secret values MUST NOT appear in findings, rendered output, logs, or stderr.

#### Scenario: Raw value never crosses the boundary

- GIVEN a tracked file containing the raw value `sk-synthetic-1234567890`
- WHEN the scan completes and stdout, stderr, and the rendered report are collected
- THEN the raw value is absent from all of them, and a redacted placeholder is present instead

### Requirement: Engine-local failure containment

A failure within the secrets engine (e.g., a failing rule) MUST produce a warning and MUST NOT abort the scan or change the exit code.

#### Scenario: Failing rule warns and continues

- GIVEN a rule that fails at runtime during a scan
- WHEN the scan runs
- THEN a warning is written to stderr, the scan completes, and the remaining rules still produce findings

### Requirement: Synthetic-only fixtures

Test fixtures MUST contain only synthetic secret values; they MUST NOT contain real credentials.

#### Scenario: Fixture corpus is synthetic

- GIVEN the committed fixture corpus
- WHEN fixtures are audited
- THEN every secret-like value is synthetic and clearly non-credential
