# Tasks: Sentinel Explain Adapter

## Review Workload Forecast

Estimated lines: 600-800 authored.
Split: PR5→PR6.
Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: Medium

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
| ---- | ---- | --------- | -------------------- | --------------- | ----------------- |
| 1 | Flag, seam, stub, forced-off, terminal advisory rendering, differential test | PR 5 | `cargo test --lib` | `cargo test --test cli` | `src/explain/{mod,stub}.rs`, `src/cli.rs`, `src/lib.rs`, `src/render.rs`, `src/finding.rs` |
| 2 | HTTP adapter, budget, timeout, sanitization, malformed response | PR 6 | `cargo test --lib explain` | `cargo test --test explain` | `src/explain/http.rs`, `tests/explain.rs` |

## Task list

- **5.1 (RED)** — Update the tests that assert `--explain` is a usage error
  (`src/cli.rs`, `src/lib.rs`, `tests/cli.rs`) so they now assert acceptance, and
  add failing tests for: the `Explainer` seam, forced-off under `--ci`/`--offline`
  by stub call count, the `explain-skipped` diagnostic, advisory rendering lines,
  JSON/SARIF byte-identity with and without `--explain`, and the differential exit
  code. Observe RED before implementing.
- **5.2** — Add `src/explain/mod.rs` (`Explainer`, `Explanation`, disabled
  explainer) and `src/explain/stub.rs` (recording stub with injectable outcome).
- **5.3** — Add the `--explain` option in `src/cli.rs` and the `explain-skipped`
  diagnostic constructor in `src/finding.rs`.
- **5.4** — Add `run_with_deps` in `src/lib.rs` with the forced-off decision and
  the advisory map; keep `run` and `run_inner` signatures intact.
- **5.5** — Add `render_findings_with_advisories` in `src/render.rs`; make
  `render_findings` delegate with an empty map so existing bytes and goldens hold.
- **5.6 (GREEN)** — Focused suite plus `cargo fmt --all -- --check` and
  `cargo clippy --all-targets --all-features -- -D warnings`.

- **6.1 (RED)** — Add failing tests for the HTTP adapter's contract: one request
  for 50 findings truncated to 20 within 4096 bytes, exactly one attempt on
  timeout and on HTTP 500 with `explain-failed`, 10-second timeout configuration,
  HTTPS-only, sanitization of hostile text, `explain-invalid` for a malformed
  envelope, unknown ids ignored, and the redaction assertion over the recorded
  payload.
- **6.2** — Implement `src/explain/http.rs` against the `Explainer` trait, reusing
  the existing `ureq` configuration idiom.
- **6.3** — Add `tests/explain.rs` end-to-end coverage through the binary using a
  local stub HTTP server or an injected stub explainer, whichever keeps the test
  hermetic.
- **6.4 (GREEN)** — Full suite, clippy, fmt, `cargo deny check`, `cargo audit`.

## Evidence requirements

Each task reports the exact command and observed result; RED is reported with the
failing assertion text. `--ci`/`--offline` forced-off evidence is a call count, and
the redaction evidence is the recorded payload, never a paraphrase.
