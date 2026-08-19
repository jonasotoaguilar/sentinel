# Proposal: Machine-Readable JSON and SARIF Outputs

## Intent

Close the CI-owner gap in PRD §2 and §5: Sentinel currently emits terminal text only, so scan results cannot enter standard automation or code-scanning workflows.

## Scope

### In Scope
- Add `--output terminal|json|sarif` (default `terminal`) and `--report`.
- Emit versioned JSON and SARIF 2.1.0 from the existing redacted, ordered findings.
- Add hermetic schema, golden, redaction, determinism, and CLI integration coverage.

### Out of Scope
- Dependency/OSV, offline/cache, explain, rules engines, exclusion globs, completions, severity gating, or docs rewrite.
- Findings, fingerprint, ordering, terminal, discovery, or exit-code changes.
- Renderer traits, registries, or other speculative abstractions; network or persisted state.

## Capabilities

### New Capabilities
- `machine-readable-reporting`: Versioned JSON and SARIF 2.1.0 report contracts, file output, safety, and determinism.

### Modified Capabilities
- `cli-scan`: Accept output/report flags and validate their combinations while preserving exits 0/1/2.

## Product Rules

1. Output values are exactly `terminal`, `json`, `sarif`; unknown values exit 2.
2. `--report` requires JSON/SARIF; write failure reports `cannot write scan report` and exits 2.
3. JSON uses `schema_version: "1.0.0"`, build-time tool metadata, the complete finding fields, additive-only evolution, stable rule IDs, and no run-derived fields.
4. SARIF uses 2.1.0 schema/version, sorted rules and stable indices; LOW→note, MEDIUM→warning, HIGH/CRITICAL→error; empty results are valid.
5. JSON severity is lowercase.
6. SARIF artifact URIs use RFC 3986 percent-encoding; design pins the encoder.
7. Tests validate against a pinned official SARIF schema without network access.
8. Raw secrets remain absent from JSON and SARIF bytes.
9. Repeated outputs are byte-identical; serializers use structs, not maps.

## Approach

Add pure JSON/SARIF renderer modules at the existing render boundary using `serde`/`serde_json`; design confirms `jsonschema`. Route CLI output in `src/lib.rs` without changing terminal behavior.

## Affected Areas

| Area | Impact | Description |
|---|---|---|
| `src/cli.rs`, `src/lib.rs` | Modified | Parse, validate, route, and write reports |
| `src/render*` | New/Modified | Pure JSON and SARIF serializers |
| `tests/`, `tests/fixtures/` | Modified | Schema, goldens, and regressions |
| `Cargo.toml`, `Cargo.lock` | Modified | Serialization and schema-test dependencies |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| SARIF incompatibility | Medium | Pinned-schema validation and goldens |
| Redaction/determinism regression | Medium | Raw-secret assertions and run-twice byte comparison |
| 800-line overrun | Medium | Two ≤400-line stacked PRs; count authored tests explicitly |

## Rollback Plan

Revert PR2, then PR1, restoring byte-identical terminal-only behavior and rejection of the new flags.

## Dependencies

- Two stacked-to-main PRs: JSON/CLI first, SARIF/integration second.
- An approved GitHub issue is required; publication is blocked because the repository mandates an interactive Issue Form and subsequent maintainer approval.

## Success Criteria

- [ ] JSON and SARIF are well-formed, schema-valid, redacted, and byte-identical across repeated scans.
- [ ] Empty/finding scans preserve exits 0/1; invalid flags or report writes exit 2.
- [ ] Terminal output remains byte-identical and each PR stays within 400 changed lines, total ≤800.
