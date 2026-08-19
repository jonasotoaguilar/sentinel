# Exploration: sentinel-next-capability — Machine-readable outputs (versioned JSON + SARIF 2.1.0)

> Phase: sdd-explore · Store: hybrid (OpenSpec + Engram) · Date: 2026-08-06 · Change: `sentinel-next-capability`
> Session preflight: execution mode Automatic · artifact store hybrid · delivery strategy `auto-chain` (stacked-to-main) · review budget 800 changed lines.
> Status of this document: analysis and scope recommendation for `sdd-propose`. No implementation.
> Branch: feature branch (never `main`). CI per-PR cap 400 lines (`pr-check.yml`); PRs must reference an approved (`status:approved`) issue.

## Current State

`main` at `74a2cee` (2026-08-06) ships two SDD changes:

1. **`sentinel-mvp-foundation`** (archived) — crate bootstrap, CLI, tracked-file discovery, secrets engine, normalize/fingerprint/dedupe, terminal renderer, exit-code contract 0/1/2.
2. **`sentinel-discovery-hardening`** (PRs #7–#11, merged) — hybrid git-aware discovery (`git ls-files -z` + `ignore` walker), `.sentinelignore`, hermetic `--ci`, 10 MiB size guard, deterministic diagnostics.

Pipeline today: `sentinel scan [--ci]` → discovery (`Mode::{Local,Ci}`) → Rayon parallel read + secrets scan (redaction at engine boundary) → normalize (stable fingerprint `engine/rule/path:line:col/digest`, BTreeMap dedupe, sort by (fingerprint, path, line)) → terminal render (stdout) + sorted diagnostics (stderr) → exit 0/1/2.

CLI surface: **only `--ci` is accepted**; `--output`, `--report`, `--explain`, and positionals are rejected as usage errors (`src/cli.rs`). The findings model is complete and redacted: `id`, `engine`, `rule_id` (stable IDs with a `deprecated_ids` aliasing precedent in `src/engine/secrets.rs`), `severity` (LOW/MEDIUM/HIGH/CRITICAL), `location` (repo-relative path, line, column, snippet), `message`, `evidence`. **No `serde`/`serde_json` in the dependency set yet.**

### Contract gap vs. documented product contract

| Contract (PRD / ARCHITECTURE) | Shipped today |
|---|---|
| PRD §2 user story: "As a CI pipeline owner, I want SARIF 2.1.0 output, so that findings land in my existing review workflow" | ❌ terminal text only |
| PRD §3 in scope: "Renderers: terminal, versioned JSON, SARIF 2.1.0" | ❌ terminal only |
| PRD §5 AC: "Terminal, versioned JSON, and SARIF 2.1.0 outputs are produced and well-formed; SARIF is ingestible by standard SARIF consumers" | ❌ |
| ARCHITECTURE.md Renderers component + Appendix (versioned JSON envelope contract + SARIF 2.1.0 contract) | ❌ fully specified, unimplemented |
| ARCHITECTURE.md CLI/Orchestrator: "`--output json\|sarif` + `--report` file output" | ❌ rejected flags |

**User-visible consequence**: a CI pipeline owner running the now-hermetic `sentinel scan --ci` still cannot ingest results into code-scanning dashboards, review workflows, or SARIF consumers — the second primary user story (PRD §2) is entirely unmet. This is the largest remaining MVP acceptance gap that one bounded change can close, and it is the only remaining gap whose full contract is already written in `ARCHITECTURE.md` with zero open design decisions.

## Scope of this change (focus)

Versioned JSON envelope + SARIF 2.1.0 renderers with `--output`/`--report` CLI flags, SARIF schema validation, insta goldens, and determinism/redaction regressions on the new surfaces. **Explicitly not expanded into**: dependency/OSV engine, `--explain`, `--offline` (no XDG cache exists yet), Tree-sitter/rules engines, CLI exclusion globs, CI severity-gating/blocking policy, shell completions, docs.

## Approaches

### 1. Additive renderer modules on the existing pure-render boundary — *recommended*

Add `serde`/`serde_json`; implement versioned JSON and SARIF 2.1.0 as pure functions from the existing `&[Finding]` (+ tool metadata) into bytes, following the `ARCHITECTURE.md` Appendix contracts verbatim; extend `cli.rs` with `--output <terminal|json|sarif>` (default `terminal`) and `--report <path>`; route in `lib.rs`; `--report` file writes mirror the existing broken-stdout error path (diagnostic to stderr, exit 2). Tests: unit purity; `assert_cmd` integration (flags accepted, exit contract 0/1/2 unchanged, stdout/stderr separation, redaction on both new formats, run-twice byte-compare determinism); insta goldens for both formats; SARIF validated in tests against a **pinned copy** of the official SARIF 2.1.0 JSON schema committed under `tests/fixtures/` (hermetic — no network; recommend dev-dep `jsonschema`, pure Rust MIT/Apache-2.0 — confirm at design).

- Pros: zero open design decisions (the Appendix is the contract); no network or trust-surface change; the findings model is already redacted and deterministically ordered, so redaction and byte-identity fall out of the existing invariants; unblocks CI adoption immediately; smallest of the remaining MVP pillars; no engine/topology change.
- Cons: new deps (`serde`, `serde_json` — pure Rust, MIT/Apache-2.0, allowed by `deny.toml`); SARIF schema conformance must be proven by tests; needs 2 chained PRs to respect the 400-line CI cap.
- Effort: Medium (~700–850 authored lines incl. tests; goldens + schema fixture excluded from authored counts per the hardening precedent).

### 2. Full output abstraction (trait + registry) now — rejected

Introduce an output trait/registry "to prepare" for future formats.

- Pros: none material — only two formats exist and both fit one module family; the architecture already fixes the renderer boundary (pure functions).
- Cons: violates the project's no-speculative-abstraction rule (module-design: a trait is a hypothetical seam until a second consumer exists — the same reasoning the foundation exploration applied to the engine trait); consumes budget with zero behavior.
- Effort: Low (abstraction) + Medium (renderers) — strictly worse than Approach 1.

### 3. Ship SARIF only (or JSON only), defer the other — rejected

- Pros: marginally smaller single PR.
- Cons: PRD AC names both formats; the `--output` enum would be extended twice (double CLI/test churn); the second format then needs its own full SDD change for a fraction of the budget. Both formats are ~equal size; no sequencing benefit.
- Effort: Medium twice — worse total.

### 4. Follow the archived roadmap literally: dependency engine next, outputs later — deferred to follow-up

The archived foundation follow-up sequence orders `sentinel-dependency-engine` (item 2) before `sentinel-renderers-json-sarif` (item 4).

- Pros: "vulnerable dependencies" is half the product's stated purpose; roadmap continuity.
- Cons: (a) the dependency engine's **minimal valuable slice** (manifest resolution for npm/PyPI + OSV client with pagination/detail fetches + XDG cache with TTL/atomic writes/corruption tolerance + offline degrade + stub-server seam + untrusted-data validation) is realistically **1500+ authored lines — ~double this session's 800-line review budget**; the roadmap itself flags "may split: client+cache, then engine", and even the client+cache half exceeds one change's budget; (b) it carries the heaviest new dependency surface (ureq + TLS backend, `directories`, `toml`, `serde_json`) through deny/audit; (c) it has **open product decisions** this exploration cannot resolve from evidence (cache TTL knob — ADR-0002 action item; manifest file set; ecosystem/version mapping); (d) its findings would still be **undeliverable to CI until SARIF/JSON exist**.
- Verdict: correct as the named follow-up change *after* this one; not the highest-value next slice under the stated budget and review constraints.

## Recommendation

**Approach 1: versioned JSON + SARIF 2.1.0 outputs (`--output`, `--report`)** as change `sentinel-next-capability`, delivered as **2 chained PRs** (PR1: deps + CLI flags + versioned JSON envelope + unit/goldens; PR2: SARIF 2.1.0 renderer + schema validation + integration regressions). Evidence: PRD §2 CI-owner user story and §5 acceptance criteria are explicit; `ARCHITECTURE.md` Appendix already pins both output contracts (field sets, stability rules, SARIF shape, no-timestamps determinism); the discovery-hardening chain just made CI scans hermetic — machine-readable output is the immediate, fully specified next step; no other remaining MVP pillar fits the 800-line session budget with zero open decisions. The dependency engine (roadmap item 2) is the recommended follow-up change once SARIF/JSON exist to carry its findings into CI.

## First Slice / Non-Goals

### In scope

- `src/cli.rs`: `Scan` gains `--output <terminal|json|sarif>` (default `terminal`) and `--report <path>`; unsupported flags remain usage errors (exit 2).
- Versioned JSON renderer per Appendix (Business Rules 3).
- SARIF 2.1.0 renderer per Appendix (Business Rules 4), validated against the pinned schema in tests.
- `--report` writes the report file for `json`/`sarif`; unwritable path → stderr diagnostic + exit 2.
- Build deps `serde`/`serde_json`; dev-dep `jsonschema` (design confirms); pinned SARIF 2.1.0 schema fixture.
- Tests: renderer unit tests; `assert_cmd` integration (flags accepted, exit contract unchanged, redaction on both formats, determinism gate, unsupported args still usage errors); insta goldens (JSON + SARIF); SARIF schema validation test; empty-findings validity tests.

### Non-Goals (explicit)

- Dependency/OSV engine, XDG cache, `--offline`, `--explain` (later slices; untouched here).
- Tree-sitter/rules engines, exclusion globs, `clap_complete`, CI severity-gating/blocking policy (SARIF `level` is informational only).
- Changes to the findings model, fingerprint format, ordering contract, terminal renderer, exit-code contract, or discovery.
- README/docs rewrite (the top-level README still claims "no implementation exists" — a docs-updater chore, not this change).
- No speculative abstraction: renderers stay pure functions; no trait/registry.
- No network, no persisted state.

## Product / Business Rules and Decisions to Pin at Proposal

1. **`--output` values** are exactly `terminal` (default), `json`, `sarif`; unknown value → usage error, exit 2 (existing unsupported-arg contract).
2. **`--report`** is valid only with `--output json|sarif` (ARCHITECTURE: terminal → stdout; JSON/SARIF → stdout or file); `--report` with terminal output → usage error. Unwritable path → exit 2 with a `cannot write scan report` diagnostic (mirrors the broken-stdout path in `src/lib.rs`).
3. **Versioned JSON envelope** (Appendix contract; pin initial `schema_version: "1.0.0"`): top-level `schema_version` (string, semver), tool `name` (`sentinel`) and `version` (`env!("CARGO_PKG_VERSION")` — build-time constant, not run-derived → determinism preserved), `findings` array sorted by (fingerprint, path, line) — the existing `dedupe_and_sort` order. Per finding: `id`, `engine`, `rule_id`, `severity`, `location` (`path` repo-relative forward-slash, `line`, `column`, `snippet`), `message`, `evidence`. Stability: additive-only fields; no timestamps/run-derived fields; `rule_id` values stable (renames use the `deprecated_ids` precedent already in the secrets engine).
4. **SARIF 2.1.0** (Appendix contract): `$schema` (SARIF 2.1.0 URI), `version: "2.1.0"`, `runs[].tool.driver` with `name`, `version`, and `rules[]` (one reportingDescriptor per distinct `rule_id`, deterministic order — recommend sorted by rule_id so `rule.index` stays stable as rules are added); `results[]` with `ruleId`, `rule.index` (index into `rules[]`), `level` (severity mapping: LOW→note, MEDIUM→warning, HIGH→error, CRITICAL→error), `message.text`, and `locations[].physicalLocation` with `artifactLocation.uri` (repo-relative, forward slashes, URI-encoded per pinned policy) and `region` (`startLine`, `startColumn`, 1-based). No timestamps → byte-identical reruns. Empty findings → valid log with `results: []`, exit 0.
5. **JSON severity serialization**: lowercase (`low`/`medium`/`high`/`critical`) — matches the terminal renderer; stable enum-to-string mapping.
6. **URI encoding policy** for `artifactLocation.uri`: percent-encode per RFC 3986 (spaces, `#`, `%`, non-ASCII) — exact encoder pinned at design.
7. **Schema validation**: commit a pinned copy of the official SARIF 2.1.0 JSON schema under `tests/fixtures/`; validate every SARIF output in tests (dev-dep `jsonschema`, confirm at design). No network in tests.
8. **Redaction**: renderers consume only the redacted model; extend the existing integration assertions so raw secret strings are absent from JSON and SARIF bytes (PRD KPI 4).
9. **Determinism**: extend the determinism gate pattern — run twice, byte-compare for `--output json` and `--output sarif` (PRD KPI 2). Use structs (field order = declaration order), never maps, for stable key order.

## Edge Cases

- Empty findings → valid JSON envelope (`findings: []`) and valid SARIF log (`results: []`); exit 0 unchanged.
- CRITICAL and HIGH both map to SARIF `error` (3 SARIF levels for 4 severities) — no ambiguity; pin the mapping in a table test.
- Non-UTF-8 / space / `#` / `%` / non-ASCII paths → already lossy-canonicalized forward-slash text in `lib.rs`; JSON control chars handled by serde_json escaping; URI encoding per rule 6.
- `--report` to an existing file → deterministic overwrite (single process); to a directory/unwritable path → exit 2 diagnostic.
- `--output json --report` with Windows-style paths → the report path is a local OS path (not URI-encoded); finding paths are already forward-slashed pre-render.
- Newlines/quotes in `message`/`snippet` → serde_json escaping; SARIF `message.text` likewise.
- Diagnostics stay on stderr in all modes; `--report` never captures diagnostics.
- `rule.index` stability: `rules[]` sorted by id; adding a rule id is additive, existing indices unchanged (pin with a unit test).
- Terminal output byte-identical to today (existing goldens untouched).

## Dependencies

- **Build**: `serde` (derive) + `serde_json` — pure Rust, MIT/Apache-2.0, allowed by `deny.toml`; `cargo deny check` + `cargo audit` must be green on the PR that adds them (manifest-change precedent from the foundation bootstrap).
- **Dev**: `jsonschema` (recommended; design confirms) for SARIF schema validation; pinned SARIF 2.1.0 schema fixture under `tests/fixtures/`.
- **Runtime**: none — no network, no cache, no new trust surface.
- **Process**: archive `sentinel-discovery-hardening` (its `state.yaml` still reports `phase: apply`; change artifacts are untracked on `main`) before or alongside this change; the auto-chain PR flow requires a GitHub issue labelled `status:approved` (`pr-check.yml`) — none open today; the proposal phase must create it (issue-creation skill).

## Review-Size Implications

- Forecast **~700–850 authored lines** including tests (goldens + the SARIF schema fixture excluded from authored counts, per the hardening `apply-progress.md` precedent). Exceeds the 400-line CI per-PR cap → **2 chained PRs, stacked-to-main**, within the 800-line session budget but tight: `sdd-tasks` must count test lines against scenarios 1:1 (the hardening PR1 overran its forecast 415 → 831 authored lines for the same reason).
- **PR1**: `Cargo.toml`/`Cargo.lock` + `src/cli.rs` flags + `src/lib.rs` routing + versioned JSON renderer + unit tests + JSON goldens.
- **PR2**: SARIF 2.1.0 renderer + schema fixture + validation tests + integration regressions (redaction, determinism, exit contract) + goldens.
- **Rollback**: revert PR2 then PR1 → terminal-only output with `--output`/`--report` rejected, byte-identical to today's behavior.

## Risks

- **SARIF non-conformance** → the ingestibility acceptance criterion fails; mitigated by pinned-schema validation in tests + insta golden.
- **Determinism regression** (run-derived field sneaks in; map-ordered JSON) → mitigated by struct-ordered serialization and the run-twice byte-compare gate on both formats.
- **Redaction regression surface doubles** (JSON + SARIF) → existing "raw secret absent from outputs" assertions extended to both formats.
- **Budget overrun** (hardening precedent: 415 → 831) → tasks phase counts per-task authored lines; two PRs planned; escalate only via `size:exception` if unavoidable.
- **README/docs staleness** persists (out of scope) — flag a docs chore slice to the user.

## Ready for Proposal

**Yes.** Recommended scope: versioned JSON + SARIF 2.1.0 outputs with `--output`/`--report`, delivered as 2 chained PRs within the 800-line budget. The proposal must pin the nine business rules above (notably: `--report` restricted to json/sarif, SARIF level mapping, JSON severity casing, URI encoding policy, and the `jsonschema` dev-dep confirmation) and create the approved GitHub issue. The dependency engine (OSV + XDG cache + offline) is the named follow-up change.
