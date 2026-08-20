# Archive Report: Sentinel Discovery Hardening

**Status**: Archived — SDD cycle complete. 2026-08-18.
**Archive path**: `openspec/changes/archive/2026-08-18-sentinel-discovery-hardening/`
**Store**: openspec (filesystem). This file is the terminal OpenSpec record in the archived audit trail.

## Final State

The change shipped as implemented and verified: ignore-aware, hermetic, deterministic git discovery (untracked + hidden files, `.sentinelignore`, nested-repo/symlink exclusion, 10 MiB size guard, invalid/unreadable path handling) and a CLI surface that accepts `sentinel scan --ci` while preserving the 0/1/2 exit contract. Verdict at close: **PASS WITH WARNINGS** (blockers 0; critical findings 0). Native task truth is 17/17 complete.

| Metric                      | Final value                                                                                                        |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Tasks                       | 17/17 complete, 0 unchecked (tasks.md)                                                                             |
| Requirements                | 9/9 evidenced (7 git-discovery + 2 cli-scan delta blocks)                                                          |
| Scenarios                   | 19/19 evaluated — 18 fully compliant, 1 partial, 0 failing/untested                                                |
| Tests                       | 97 passed / 0 failed (`cargo test --all-features`, exit 0)                                                         |
| Build                       | `cargo build --all-features` exit 0                                                                                |
| fmt / clippy / deny / audit | PASS (fmt `--check` exit 0; clippy `-D warnings` exit 0; deny; audit)                                              |
| Verdict                     | `pass_with_warnings` — evidence_revision `sha256:696fc898d0c287ee5a59e0a6af89929541e2392ce46e38066af60080da75f885` |

## Specs Synced to Source of Truth

Both main specs existed; delta specs were merged into them. Both deltas contained only ADDED and MODIFIED requirements — no REMOVED requirements — so no destructive merge occurred (`rules.archive` warning requirement satisfied: nothing removed or rewritten). The `(Previously: …)` annotations in the delta MODIFIED blocks are change-history metadata and were not carried into the source-of-truth specs (matching the repo convention; no prior main spec contains such annotations).

| Domain        | Action  | Delta requirements merged                                                                                                                                                                                                                                                |
| ------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| cli-scan      | Updated | 1 MODIFIED (`Command surface` — `--ci` now the only supported option) + 1 ADDED (`Hermetic CI mode`)                                                                                                                                                                     |
| git-discovery | Updated | 1 MODIFIED (`Determinism of the file set` — byte-identical + concurrent + sorted) + 6 ADDED (`Untracked-file discovery`, `Ignore precedence and .sentinelignore`, `Nested repositories and symlinks`, `Size guard`, `Invalid path handling`, `Unreadable file handling`) |

Merged main specs verified structurally: `cli-scan` = 5 requirements / 16 scenarios; `git-discovery` = 11 requirements / 17 scenarios. Unrelated requirements in each main spec were preserved; the three unrelated main specs (`finding-normalization`, `secrets-detection`, `terminal-rendering`) were not touched.

## Stale Snapshot Note (state.yaml)

The change folder's `state.yaml` is a **stale intermediate snapshot** from `2026-08-05` (apply phase): it records `tasks_progress.completed` = [1.1 … 3.2] (11 tasks) and `verify_report: false`. It does NOT reflect the final state. The authoritative final task truth is the persisted `tasks.md` (17/17, all `[x]`) and the final `verify-report.md` (present, `pass_with_warnings`). Per the Final-State Authority hierarchy, `tasks.md` and `verify-report.md` outrank `state.yaml`; the stale `11/17` figure is recorded here explicitly and must NOT be reported as the change's final task state. The addendum in `apply-progress.md` (dated 2026-08-18, batch `reconcile-hardening-tasks-4.1-5.1`) reconciles tasks 4.1–5.1 to the final 17/17 state; its only docs change was the README `sentinel scan --ci` usage block — no production source change.

## Final Warnings (preserved at close)

1. **One partial scenario** (`Unsupported argument rejected`, cli-scan): `--explain` and positional arguments still fail as usage errors with empty stdout and exit 2, but the scenario's `--output json` example is accepted in this worktree because the later stacked change `sentinel-next-capability` added `--output`/`--report`. That is a later authorized delta, not a missing hardening implementation — the merged cli-scan spec records the scenario text as of this change's close; the successor change will amend it when archived.
2. **Mutation testing** (`cargo-mutants`) is typed `unavailable` (tool not installed); recorded as a warning, not fabricated as a PASS.
3. **Coverage** (`llvm-cov`) is unavailable locally; no coverage PASS is claimed. CI remains the authoritative place for the coverage gate.

## Review Delivery

Receipt-driven development: `reviewGate` was **structurally absent** from structured status for this candidate — no review was ever started — and `reviewOffer` was present only as an optional invitation. Ordinary repository policy applied; the invitation was not acted on (declining is proceeding without acting, not a verb). No review transaction, ledger, or receipt exists for this change, and none was required or invoked at archive. Do not reconstruct a review story from this absence.

## Final Evidence Identifiers

- `evidence_revision`: `sha256:696fc898d0c287ee5a59e0a6af89929541e2392ce46e38066af60080da75f885`
- `test_output_hash`: `sha256:e71ad7d1f286339f74a202762a95c16e177b4f9915aa394ea794126fa61d41bc` (97 tests, exit 0)
- `build_output_hash`: `sha256:736e2582f563605dd272e5fb977840b0c0767377d27b6940c440caf75eec7157` (exit 0)
- `critical_findings`: 0

## Source-of-Truth Notes

Per the Final-State Authority hierarchy, final numbers above come from the native `verify-report.md` and the persisted `tasks.md` (the highest-ranked sources covering them). No later work modified verify counts; the only post-verify activity was the apply reconciliation batch, which completed tasks 4.1–5.1 (17/17) and made no production source change. The one contradiction recorded — `state.yaml` (11/17, stale) vs `tasks.md`/`verify-report.md` (17/17, final) — is resolved in favor of the higher-ranked persisted artifacts and noted explicitly above. Archived history is untouched except for the addition of this terminal record and the preceding spec merges into `openspec/specs/`.
