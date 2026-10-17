# Proposal: Sentinel Explain Adapter

## Intent

PRD §3/§4: `--explain` adds LLM context to findings and can never set severity or
blocking behaviour; it is disabled by default and forced off in CI and offline
mode (KPI 3, ADR-0003). ADR-0003 is accepted and `ARCHITECTURE.md` specifies the
adapter, but no code exists and the live `cli-scan` contract still rejects
`--explain` as a usage error. Implement the approved boundary instead of the
contradiction.

## Scope

### In Scope

- `sentinel scan --explain` is accepted; it stops being a usage error.
- New `explain-adapter` capability: an `Explainer` seam with a real HTTP adapter
  and a test stub, one bounded batch request per scan, single attempt, no retries,
  fixed context budget.
- Forced off under `--ci` and `--offline`; off when no endpoint/key is configured.
- Advisory text is display-only, terminal-only; JSON and SARIF stay byte-identical.
- Degradation to warnings only: never exit 2, never change severity or ordering.
- Context is built from already-redacted findings; raw values are unreachable
  because the adapter sits downstream of the engine boundary.

### Out of Scope

- Explaining findings in JSON/SARIF output.
- Retries, caching, streaming, per-finding requests, or multi-provider support.
- Any LLM influence on severity, blocking, exit code, fingerprint, or ordering.
- Changing finding, normalization, or renderer contracts beyond adding advisory
  lines to terminal output.

## Capabilities

### New Capabilities

- `explain-adapter`: the `Explainer` seam, context budget, forced-off rules,
  degradation policies, and advisory-only guarantee.

### Modified Capabilities

- `cli-scan`: `--explain` becomes an accepted option of `sentinel scan`; the
  network policy gains the explainable-endpoint case while `--offline` keeps
  zero HTTP.
- `terminal-rendering`: terminal output MAY carry one advisory line per finding
  when `--explain` is active; machine formats are excluded.

## Approach

A new `src/explain/` module: `Explainer` trait, `HttpExplainer` (ureq), and a
recording `StubExplainer` for tests. `run_inner` gains an injected explainer so
tests never touch the network; the binary path builds it from the environment and
returns a disabled explainer when nothing is configured. Findings are already
redacted when the adapter sees them, so the redaction invariant is structural,
not a second implementation.

## Affected Areas

- `src/explain/{mod.rs,http.rs,stub.rs}` (new).
- `src/cli.rs`: `--explain` option; usage-error test list updated.
- `src/lib.rs`: explainer injection, batch call after dedupe, advisory map.
- `src/render.rs`: advisory-aware terminal rendering; `render_findings` unchanged.
- `src/finding.rs`: diagnostic constructors for `explain-skipped`,
  `explain-failed`, `explain-invalid`.
- `tests/explain.rs` (new).

## Risks

- A model response could forge finding-looking output (Med — advisory text is
  sanitized to a single line, control characters stripped, length capped, and it
  never enters a machine format).
- Accidental HTTP in CI or offline mode (Med — forced-off is a RED test with a
  recording stub, plus the zero-HTTP `--offline` invariant).
- Exit-code or severity drift (Med — differential test compares both runs).

## Rollback / Stop Conditions

The feature is additive; removing the slices restores the rejecting CLI. Gates
red → fix or revert before the next slice.

## Dependencies

`ureq` (already present). No new crate, no cache, no database.

## Success Criteria

- Exit code, finding set, severity, and order are identical with and without
  `--explain`, including under every degrading adapter outcome.
- `--ci` and `--offline` invoke the adapter zero times.
- No raw value from a fixture reaches the adapter payload or any output stream.
- JSON and SARIF bytes are identical with and without `--explain`.

## Delivery Decision

Stacked-to-main work units within the 400-line review budget, each referencing
issue #38. The `cli-scan` and `terminal-rendering` deltas are recorded here and
archived in `openspec/specs/` at the archive slice, in predecessor-first order
relative to any later change that modifies the same requirement.
