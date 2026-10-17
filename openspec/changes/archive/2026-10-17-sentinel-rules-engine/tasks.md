# Tasks: Sentinel Code Rules Engine

## Review Workload Forecast

Estimated lines: 900-1200 authored, plus `Cargo.lock` growth.
Split: PR1→PR2→PR3→PR4 (PR1 may split into a dependency-only PR if the lock
delta alone pushes the unit past 400).
Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
| ---- | ---- | --------- | -------------------- | --------------- | ----------------- |
| 1 | Deps + engine skeleton + language detection + one rule | PR 1 | `cargo test --lib engine::rules` | N/A parse-only | `Cargo.toml`+`Cargo.lock`, `src/engine/rules/*`, `src/engine/mod.rs`, `src/finding.rs`, `src/normalize.rs`, `src/lib.rs` |
| 2 | JS/TS dynamic-code and shell-injection rules | PR 2 | `cargo test --lib engine::rules` | N/A parse-only | `src/engine/rules/rules.rs`, fixtures |
| 3 | Python rules | PR 3 | `cargo test --lib engine::rules` | N/A parse-only | `src/engine/rules/rules.rs`, fixtures |
| 4 | Unparseable-file skip + `rule-fallback` + E2E | PR 4 | `cargo test --lib engine::rules` | `cargo test --test rules` | `src/engine/rules/mod.rs`, `tests/rules.rs`, fixtures |

## Task list

- **1.1 (RED)** — Add failing tests: extension→language detection for all listed
  extensions, silent skip for `main.rs`/`README.md`/`Makefile`/extensionless,
  case-insensitive extension, and `RULE-weak-hash` firing with id/severity on a
  fixture. Observe RED before any engine code exists.
- **1.2** — Add the four dependencies and the `rules` engine id constant.
- **1.3** — Add `src/engine/rules/lang.rs` (extension map, TSX variant split) and
  the lazily compiled grammar holders.
- **1.4** — Add `src/engine/rules/mod.rs` with `RulesEngine::scan` returning the
  shared `Candidate`, rule-table construction with `rule-failed` containment,
  and `init_diagnostics`.
- **1.5** — Add the shared redaction seam in `secrets.rs` and the
  engine-parameterized `normalize::to_findings_for`.
- **1.6** — Wire the engine into `run_inner` after secrets; keep the existing
  two engines untouched.
- **1.7 (GREEN)** — `cargo test --lib` plus `cargo clippy --all-targets
  --all-features -- -D warnings` and `cargo fmt --all -- --check` pass; measure
  the changed-line count and decide whether the dependency landing is its own PR.

- **2.1 (RED)** — Add failing tests for `RULE-dynamic-code` and
  `RULE-shell-injection`, including the literal non-findings
  (`eval("print(1)")`, `new Function("return 1")`) and the bare-identifier
  non-finding.
- **2.2** — Implement both rules over the tree; `GREEN` with the full suite.

- **3.1 (RED)** — Add failing tests for the three Python rules, including
  `shell=False`, `Loader=yaml.SafeLoader`, `yaml.safe_load` and
  `pickle.loads(data, encoding=...)` non-findings.
- **3.2** — Implement the three Python rules; `GREEN` with the full suite.

- **4.1 (RED)** — Add failing tests for the parse-failure skip in both
  directions (an unparseable file reports nothing; its repaired twin still
  reports), the `rule-fallback` diagnostic, and
  a two-run byte-identical JSON comparison.
- **4.2** — Implement the skip: a file the grammar cannot fully parse
  produces no findings and exactly one `rule-fallback` diagnostic.
- **4.3** — Add `tests/rules.rs` end-to-end coverage through the binary and the
  fixture tree under `tests/fixtures/rules/`.
- **4.4 (GREEN)** — Full suite, clippy, fmt, `cargo deny check`, `cargo audit`.

## Evidence requirements

Each task reports the exact command and its observed result; RED is reported
with the failing assertion text, never paraphrased. Every completed unit records
its commit hash in `odd/tasks/sentinel-roadmap-completion.md`.
