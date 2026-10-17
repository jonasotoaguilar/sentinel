# Archive Report: sentinel-explain-adapter

**Status**: Archived — SDD cycle complete. 2026-10-17.
**Archive path**: `openspec/changes/archive/2026-10-17-sentinel-explain-adapter/`
**Store**: openspec (filesystem). This file is the terminal OpenSpec record in the archived audit trail.

- **Change**: `sentinel-explain-adapter`
- **Archived**: `openspec/changes/archive/2026-10-17-sentinel-explain-adapter/`
- **Date**: 2026-10-17
- **Artifact store**: openspec
- **Branch**: `docs/archive-2-explain-specs` (non-main)
- **Delivery strategy**: `auto-chain` / `stacked-to-main`
- **GitHub issue**: #38; **delivery PRs**: #47, #48, #49; **redaction follow-ups**: #51, #52

## Final State

`sentinel scan --explain` is accepted and advisory-only: the `Explainer` seam
runs at most once per scan (20 findings, 4096 bytes, 10 s timeout, no retry),
forced off under `--ci`/`--offline` by call count, degrading to
`explain-skipped`/`explain-failed`/`explain-invalid` warnings that never touch
findings, severity, ordering, or exit codes. Advisory text renders only on the
terminal (sanitized, one line, ≤500 chars); JSON and SARIF stay byte-identical.
Two recorded deviations: D7 accepts plain HTTP for loopback hosts only (so the
contract is exercisable without TLS infrastructure), and every path leaving the
process is redacted (#51, #52).

| Metric | Final value |
| --- | --- |
| Tasks | 10/10 delivered (5.1–5.6 seam/forced-off/rendering, 6.1–6.4 HTTP/budget/E2E) |
| Requirements | 4/4 evidenced (`explain-adapter` delta spec) |
| Tests | full suite green at each landing; redaction proven over the wire payload |
| CI | green on #47/#48/#49/#51/#52, including `cargo deny` + `cargo audit` |

## Follow-on Slice

This slice archives the three spec deltas, promotes the new `explain-adapter`
capability, and records this report. The `cli-scan` scenario and the
`terminal-rendering` requirement merge into the durable specs in the next slice
(`docs/archive-3-explain-artifacts`), which also moves proposal/design/tasks.

## Commits

Each hash below was verified with `git cat-file -t` (each returned `commit`):

- `5f9c9d0` — flag, seam, stub, forced-off, terminal rendering (#47).
- `ee942c8` — bounded single-attempt HTTP adapter (#48).
- `ece56c1` — end-to-end coverage through the binary (#49).
- `e1ab545`, `e06ab9d`, `cf2e93a` — path/payload redaction, test hermeticity (#51, #52).

## Specs Synced

- **`explain-adapter` (created at `openspec/specs/explain-adapter/spec.md`)**:
  the delivered delta promoted verbatim — purpose, four requirements, nine
  scenarios. Promotion was mechanical: shell copy plus `diff` readback, and the
  promoted file diffs empty against the delta source.

## Artifacts Archived

- specs/cli-scan/spec.md, specs/explain-adapter/spec.md,
  specs/terminal-rendering/spec.md (shell moves, content unchanged)
- archive-report.md (this file, additive)
- proposal.md, design.md, tasks.md follow in the next slice

## Quality Gates and Mutation Testing

`cargo-mutants` is not installed: mutation testing is **unavailable**, not a pass. No PASS was fabricated.
