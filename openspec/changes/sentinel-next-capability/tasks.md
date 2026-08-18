# Tasks: Machine-Readable JSON and SARIF Outputs

## Review Workload Forecast

| Field                   | Value                                                                   |
| ----------------------- | ----------------------------------------------------------------------- |
| Estimated changed lines | 700–850 authored (tests 1:1; pinned schema, lockfile, goldens excluded) |
| 400-line budget risk    | High                                                                    |
| Chained PRs recommended | Yes                                                                     |
| Suggested split         | PR 1 (JSON + CLI) → PR 2 (SARIF + schema)                               |
| Delivery strategy       | auto-chain                                                              |
| Chain strategy          | stacked-to-main                                                         |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal                                                    | Likely PR        | Focused test command              | Runtime harness                                                                                     | Rollback boundary                                       |
| ---- | ------------------------------------------------------- | ---------------- | --------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| 1    | CLI flags/routing + JSON renderer + regressions         | PR 1 (base main) | `cargo test --all-features json`  | `sentinel scan --output json --report out.json` on fixture repo: file written, stdout empty, exit 1 | Revert PR 1: new flags rejected, terminal-only restored |
| 2    | SARIF renderer + URI mapping + pinned-schema validation | PR 2 (base PR 1) | `cargo test --all-features sarif` | `sentinel scan --output sarif` on repo with space/`#` path; validate offline vs pinned schema       | Revert PR 2: SARIF flag rejected, JSON/terminal intact  |

## Phase 1: CLI surface — RED then production (PR 1)

- [x] 1.1 RED `tests/cli.rs`: `--output yaml` → usage error on stderr, empty stdout, exit 2
- [x] 1.2 RED `tests/cli.rs`: `--output terminal --report out.json` → usage error, exit 2
- [x] 1.3 RED `tests/cli.rs`: `--output sarif --report /unwritable/x.sarif` → stderr `cannot write scan report`, empty stdout, exit 2
- [x] 1.4 RED `tests/cli.rs`: rule-failed diagnostic on stderr only, absent from report bytes
- [x] 1.5 GREEN `src/cli.rs`: add `OutputFormat` ValueEnum (`terminal|json|sarif`, default terminal), `--output`, `--report`; keep `--ci`
- [x] 1.6 GREEN `src/cli.rs`: post-parse conflict check `terminal+--report` → usage error; drop `--output json` from existing rejected-args tests

## Phase 2: JSON renderer + routing (PR 1)

- [x] 2.1 `Cargo.toml`/lock: add `serde` (derive), `serde_json` (lockfile excluded from authored budget)
- [x] 2.2 RED `src/render/json.rs` units: envelope fields/order, lowercase severities, empty `[]`, escaping, redacted bytes
- [x] 2.3 GREEN `src/render/json.rs`: borrowed `#[derive(Serialize)]` DTOs in wire order; `render_json(&[Finding]) -> Result<Vec<u8>, serde_json::Error>`; compact + newline
- [x] 2.4 RED `tests/reporting.rs`: `--output json` full envelope, sorted findings; clean repo `[]` exit 0; `--report` file written, stdout empty, exit 1
- [x] 2.5 GREEN `src/lib.rs`: `run_inner` routes by format to stdout or `fs::write` (render first); serde failure → `cannot render scan report` exit 2; diagnostics stay stderr; exits 0/1 unchanged
- [x] 2.6 `tests/reporting.rs`: run-twice byte-identical JSON

## Phase 3: SARIF renderer + URI (PR 2)

- [x] 3.1. `Cargo.toml`/lock: add `percent-encoding = "2"`, dev `jsonschema = { version = "0.49", default-features = false }`
- [x] 3.2. RED `src/render/sarif.rs` units: 2.1.0 envelope, sorted unique rules + matching `rule.index`, severity map LOW→note/MEDIUM→warning/HIGH+CRITICAL→error, empty results valid
- [x] 3.3. RED `src/render/sarif.rs` units: RFC 3986 percent-encoding of space, `#`, `%`, non-ASCII; `/` preserved
- [x] 3.4. GREEN `src/render/sarif.rs`: URI encoder via `percent-encoding = "2"` (pass `/` + unreserved)
- [x] 3.5. GREEN `src/render/sarif.rs`: DTOs, sorted rule vector, binary-search index; `render_sarif(&[Finding]) -> Result<Vec<u8>, serde_json::Error>`; no I/O
- [x] 3.6. GREEN `src/lib.rs` + `src/render.rs`: route `--output sarif`; re-export renderers; terminal bytes byte-identical

## Phase 4: Hermetic schema, goldens, verification (PR 2)

- [x] 4.1. Add `tests/fixtures/sarif-2.1.0.schema.json`: minified pinned official OASIS 2.1.0 schema (fixture, excluded from authored budget)
- [x] 4.2. `tests/reporting.rs`: validate SARIF via `jsonschema::draft7::new` (resolution disabled) → offline pass; run-twice byte-identical
- [x] 4.3. Add `tests/snapshots/reporting__*.snap` JSON/SARIF insta goldens; leave `cli__golden_corpus_scan.snap` untouched
- [x] 4.4. Verify: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo deny check`; terminal golden unchanged

## Notes

`sentinel-discovery-hardening` (apply halted after Slice A, unarchived) must be resolved before final spec archive — not mutated by this phase. `rule_id` "stable" = deterministic per emitted log (design open question). Schema fixture, lockfile, goldens are generated evidence, excluded from authored budget.
