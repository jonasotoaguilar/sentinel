# Archive Report: Sentinel MVP Foundation

**Status**: Archived — SDD cycle complete. 2026-08-05.
**Archive path**: `openspec/changes/archive/2026-08-05-sentinel-mvp-foundation/`
**Store**: hybrid (OpenSpec filesystem + Engram). This file is the terminal OpenSpec record; the Engram record lives at topic `sdd/sentinel-mvp-foundation/archive-report`.

## Final State

The change shipped as planned, implemented, and verified: a single-crate Rust Edition-2024 CLI (`sentinel scan`) with git discovery, regex secrets engine with engine-boundary redaction, deterministic normalization, and terminal rendering. Verdict at close: **PASS WITH WARNINGS** (strict envelope `pass`; blockers 0; critical findings 0). No work occurred after verification, so verify-report counts are current as of archive.

| Metric | Final value |
|--------|-------------|
| Tasks | 21/21 complete, 0 unchecked (tasks.md, 511 words) |
| Requirements | 24/24 implemented |
| Scenarios | 36/36 evaluated — 32 fully compliant, 4 partial, 0 failing/untested |
| Tests | 44 passed / 0 failed (`cargo test --all-features`, exit 0) |
| Build | `cargo build --all-features` exit 0 |
| fmt / clippy | PASS (`--check` exit 0 / `-D warnings` exit 0) |
| Independent harness | 17 checks passed |
| Coverage threshold | Not claimed (llvm-cov unavailable locally) |

## Specs Synced to Source of Truth

Main spec directory was empty before this archive; all five delta specs were full (non-delta) specs, so each was copied verbatim as a new main spec. No destructive merge occurred (`rules.archive` warning requirement satisfied: nothing removed or rewritten).

| Domain | Action | Requirements | Scenarios |
|--------|--------|-------------:|----------:|
| cli-scan | Created | 4 | 12 |
| git-discovery | Created | 5 | 6 |
| secrets-detection | Created | 5 | 5 |
| finding-normalization | Created | 6 | 8 |
| terminal-rendering | Created | 4 | 5 |
| **Total** | 5 created | **24** | **36** |

Main specs verified byte-identical to the archived delta specs (`cmp` 5/5). Unrelated main specs: none existed; none altered.

## Final Warnings (preserved at close)

1. `cargo-deny`, `cargo-audit`, and `cargo-llvm-cov` are unavailable locally; no tools were installed. CI remains the authoritative place for those gates. These tools are NOT claimed to have run.
2. The independent external read-failure harness could not drop privileges from UID 1000; the in-process read-failure test passed and supplies runtime evidence.
3. The four historical stacked-PR acceptance boundaries cannot be reconstructed from the uncommitted working tree; final behavior and available gates were re-run independently. The four PR acceptance-boundary scenarios are recorded partial for this reason — preserved as warnings, not resolved claims.

**SUGGESTION (carried from verify)**: Run the unavailable dependency-policy/audit/coverage gates in CI and retain their results with the final delivery evidence.

## Review Delivery

Receipt-driven development was globally disabled: `delivery: disabled/unmanaged`; no review lineage, transaction, ledger, or receipt exists for this change, and none was required or invoked at archive. Structured status reported `reviewGate.result: invalidated` (no governing review), and the archive proceeded via the status-owned disabled/unmanaged path. Do not reconstruct a review story from this absence.

## Engram Observation IDs (traceability)

| Artifact | Engram observation | Topic |
|----------|-------------------|-------|
| proposal | #4776 | `sdd/sentinel-mvp-foundation/proposal` |
| spec cli-scan | #4780 | `sdd/sentinel-mvp-foundation/spec/cli-scan` |
| spec git-discovery | #4781 | `sdd/sentinel-mvp-foundation/spec/git-discovery` |
| spec secrets-detection | #4782 | `sdd/sentinel-mvp-foundation/spec/secrets-detection` |
| spec finding-normalization | #4783 | `sdd/sentinel-mvp-foundation/spec/finding-normalization` |
| spec terminal-rendering | #4784 | `sdd/sentinel-mvp-foundation/spec/terminal-rendering` |
| design | #4799 | `sdd/sentinel-mvp-foundation/design` |
| tasks | #4807 | `sdd/sentinel-mvp-foundation/tasks` |
| apply-progress | #4851 | `sdd/sentinel-mvp-foundation/apply-progress` |
| verify-report | #4899 | `sdd/sentinel-mvp-foundation/verify-report` |
| archive-report | (this archive; Engram topic `sdd/sentinel-mvp-foundation/archive-report`) | — |

## Final Evidence Identifiers

- Validator-admitted verify-report file hash: `sha256:c4ff2908fb6056b6569e817f3d8b8ec8bebc1b1b7962ac384fd4bfdc9f734367`
- `evidence_revision`: `sha256:ed828f13454245a872b21bdb249e99d4a37e7f6e6702db713e7b31ad347fb17b`
- `test_output_hash`: `sha256:fe678669ebf66df64a58088cf00aa3249af503d729065398ff928a6e5cd8d70d` (44 tests, exit 0)
- `build_output_hash`: `sha256:a13905646e2aed93ec6ea9ed6ac91490a4e01f91af0215c3965279a910612149` (exit 0)
- Golden stdout hash: `sha256:9215a540488939b2edc50a65887777f497580b11dcd74c5c57449879f35d21e5`

## Source-of-Truth Notes

Per the Final-State Authority hierarchy, final numbers above come from the native verify-report (obs #4899, validator-admitted, persisted identically to both stores) and the persisted tasks artifact (obs #4807 / tasks.md), which are the highest-ranked sources covering them. No later work modified any claim; no snapshot vs. final contradiction exists. Archived history is untouched except for the addition of this terminal record.
