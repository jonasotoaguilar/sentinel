# Proposal: Sentinel Code Rules Engine

## Intent

PRD §3 in-scope: "Deterministic regex and Tree-sitter AST rules for initial
JavaScript/TypeScript and Python". Today a JS/TS/Python source file is scanned
only by the two credential regexes, so `eval(userInput)`,
`child_process.exec` built by interpolation, `subprocess.run(..., shell=True)`,
`hashlib.md5(` and `pickle.loads(` are invisible. Add a third detector engine,
`code-rules`, that emits the same normalized findings through the unchanged
terminal/JSON/SARIF renderers and keeps the exit 0/1/2 contract.

## Scope

### In Scope

- A new `rules` engine: Tree-sitter AST matching for JavaScript/TypeScript and
  Python, redacting at its own boundary like every other engine.
- Language detection by file extension; other languages skipped silently.
- Six rules with stable ids and CWE-based severity: `RULE-weak-hash`,
  `RULE-dynamic-code`, `RULE-shell-injection`, `RULE-weak-hash-python`,
  `RULE-shell-injection-python`, `RULE-unsafe-deserialization-python`.
- AST-required precision: a literal argument is never reported.
- An unparseable file is skipped and said so: no rule finding for that file,
  exactly one `rule-fallback` diagnostic; never a scan abort,
  never an invented finding.
- Determinism: byte-identical reruns; ordering independent of parallelism.
- Reuse of the existing redaction pass so no raw value reaches a finding.

### Out of Scope

- oxc-based JS/TS analysis (PRD §7 staged future work, not an MVP commitment).
- Any language other than JavaScript/TypeScript/Python, and any rule outside the
  six pinned ids.
- Type resolution, dataflow, taint analysis, dependency resolution, auto-fix.
- Rule query files (`.scm`) or a rule DSL.
- Renderer, fingerprint, ordering, exit-code, or CLI-surface changes.

## Capabilities

### New Capabilities

- `code-rules`: language detection, the six pinned AST rules, the redaction
  boundary, the parse-failure skip with its diagnostic, and deterministic engine-local behavior.

### Modified Capabilities

- None. The engine plugs into the existing `finding-normalization` and renderer
  contracts unchanged, and adds no CLI flag.

## Approach

One engine module `src/engine/rules/` behind the same shape as the other
engines: `scan(&[u8]) -> Vec<Candidate>` reusing `engine::secrets::Candidate`
(rule id, severity, message, location, redacted snippet, evidence, digest), so
normalization, fingerprinting and dedupe need no new code. Matching walks the
Tree-sitter tree directly and reads node text; no query files. Extension maps to
a grammar; an unparseable or unsupported file takes the documented path.
Severity follows CWE convention (327 → Medium, 78/95 → Critical, 502 → High).

## Affected Areas

- `Cargo.toml` / `Cargo.lock`: `tree-sitter`, `tree-sitter-javascript`,
  `tree-sitter-typescript`, `tree-sitter-python`.
- `src/engine/rules/{mod.rs,rules.rs}` (new);
  `src/engine/rules/lang.rs`.
- `src/engine/mod.rs`: engine id constant `ENGINE_RULES`.
- `src/engine/secrets.rs`: extract the redaction pass as a reusable seam.
- `src/normalize.rs`: engine-parameterized conversion, secret path unchanged.
- `src/lib.rs`: run the rules engine after secrets, before dependency review.
- `src/finding.rs`: one new diagnostic constructor (`rule-fallback`).
- `tests/rules.rs` (new) plus rule fixtures under `tests/fixtures/rules/`.

## Risks

- Grammar crates compile C sources; the workspace gains `cc` at build time
  (Med — CI runner has a toolchain; verify with a clean `cargo build`).
- `Cargo.lock` growth consumes part of the 400-line PR budget (Med — measured
  before slicing; dependency landing may be its own PR).
- False positives would make the engine unusable in CI (Med — the pinned
  non-finding cases are RED tests, not comments).
- Skipped coverage for unparseable files (Med — no finding is reported for
  such a file, so nothing can be invented; the `rule-fallback` diagnostic
  discloses the gap and coverage returns once the syntax is repaired).

## Rollback / Stop Conditions

The engine is additive: reverting the slice that introduced it restores the
two-engine pipeline with no data migration and no contract change. Gates red →
fix or revert before the next slice.

## Dependencies

`git` on PATH (inherited). No network, no cache, no new runtime service.

## Success Criteria

- Each of the six rules fires on its fixture with the exact pinned id and
  severity, and each pinned literal case reports nothing.
- An unparseable file reports no finding, warns once with `rule-fallback`,
  and never exits 2.
- Two consecutive scans of the same fixture tree are byte-identical.
- Raw secret values are absent from findings, diagnostics, and report bytes.

## Delivery Decision

Stacked-to-main work units, each within the repository's 400-line review budget
and each referencing issue #37. No `size:exception` unless the dependency
landing alone cannot fit (measured, then split rather than exempted).
