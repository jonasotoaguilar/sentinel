# Finding Normalization Specification

## Purpose

Normalization collapses raw engine output into the canonical `Finding` model: stable fingerprints, deduplication of duplicate detections across runs, and a deterministic output order that never depends on execution order (PRD edge case; ARCHITECTURE invariants).

## Requirements

### Requirement: Finding schema and location semantics

Every finding MUST carry a stable fingerprint `id`, `engine`, `rule_id`, `severity`, `location` (repo-relative path, line, column, snippet), `message`, and redacted `evidence`. Location paths MUST be repo-relative with forward slashes on all platforms.

#### Scenario: Schema complete

- GIVEN a finding produced from a fixture
- WHEN its fields are inspected
- THEN all required fields are present, the path is repo-relative, and the evidence is redacted

### Requirement: Stable fingerprints

The fingerprint MUST be computed from canonical fields only — engine, rule ID, normalized location, and the pre-redaction BLAKE3 digest of canonicalized matched content — and MUST exclude timestamps, absolute paths, and run order. Only the fixed digest crosses the engine boundary; raw values never leave it. Identical findings MUST produce identical fingerprints; findings with distinct evidence MUST produce distinct fingerprints.

#### Scenario: Same content, same fingerprint

- GIVEN two runs over identical repository content
- WHEN fingerprints are computed
- THEN each matching finding has an identical fingerprint in both runs

#### Scenario: Distinct evidence, distinct fingerprint

- GIVEN two findings that differ only in evidence content
- WHEN fingerprints are computed
- THEN the fingerprints differ

### Requirement: Deduplication

Findings with the same fingerprint MUST collapse to a single finding: normalized output MUST contain exactly one finding per distinct fingerprint. Because the fingerprint includes engine, rule ID, and normalized location, deduplication applies only to duplicate raw detections of the same rule at the same location.

#### Scenario: Duplicate fingerprint collapsed to one

- GIVEN raw engine output containing two detections with the same fingerprint (same engine, rule ID, and normalized location)
- WHEN normalization runs
- THEN exactly one finding is emitted for that fingerprint

#### Scenario: Distinct fingerprints retained

- GIVEN the same secret matched by two different rules at the same location
- WHEN normalization runs
- THEN two findings are emitted, one per distinct fingerprint

### Requirement: Full-field redaction

Every field of a finding — including the location snippet and evidence — MUST be redacted before a finding leaves normalization, so a raw secret value MUST NOT reappear in any finding field after the secrets engine boundary.

#### Scenario: Raw value absent from every finding field

- GIVEN a fixture file containing the raw value `sk-synthetic-1234567890` detected by a rule
- WHEN every field of the normalized finding (id, engine, rule_id, severity, path, line, column, snippet, message, evidence) is inspected
- THEN no field contains the raw value, and the snippet and evidence fields contain the redaction placeholder instead

### Requirement: Canonical ordering independent of parallelism

Normalized findings MUST be ordered by (fingerprint, path, line). Ordering MUST NOT depend on engine execution order, and path separators and line endings MUST be canonicalized before comparison.

#### Scenario: Parallel execution does not affect order

- GIVEN a fixture set producing multiple findings
- WHEN two scans run with different engine scheduling (1 thread vs N threads)
- THEN the final ordered finding lists are byte-identical

### Requirement: Normalization determinism

For identical inputs, normalization MUST produce byte-identical ordered output on every invocation.

#### Scenario: Repeated normalization

- GIVEN the same raw finding set
- WHEN normalization runs twice
- THEN both outputs are byte-identical
