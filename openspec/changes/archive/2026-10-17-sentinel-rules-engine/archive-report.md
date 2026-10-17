# Archive Report: sentinel-rules-engine

**Status**: Archived — SDD cycle complete. 2026-10-17.
**Archive path**: `openspec/changes/archive/2026-10-17-sentinel-rules-engine/`
**Store**: openspec (filesystem). This file is the terminal OpenSpec record in the archived audit trail.

- **Change**: `sentinel-rules-engine`
- **Archived**: `openspec/changes/archive/2026-10-17-sentinel-rules-engine/`
- **Date**: 2026-10-17
- **Artifact store**: openspec
- **Branch**: `docs/archive-4-rules-specs` (non-main)
- **Delivery strategy**: `auto-chain` / `stacked-to-main`
- **GitHub issue**: #37; **delivery PRs**: #40, #41, #42, #43, #44, #45, #46

## Final State

The change shipped as implemented and verified: a third detector engine
(`rules`) matching six pinned AST rules over Tree-sitter JavaScript/TypeScript
and Python — `RULE-weak-hash`, `RULE-dynamic-code`, `RULE-shell-injection`,
`RULE-weak-hash-python`, `RULE-shell-injection-python`,
`RULE-unsafe-deserialization-python` — with extension-based language detection,
literal-argument non-findings, redaction through the shared secrets seam, and
byte-identical reruns. The parse-failure contract was corrected during delivery:
an unparseable file is skipped with exactly one `rule-fallback` diagnostic and
no findings, after independent verification falsified both a regex fallback
table (inventions inside comments and string literals) and recovery-region
restriction (parser-promoted phantom nodes). Matching stays name-based with no
type or import resolution, by contract.

| Metric | Final value |
| --- | --- |
| Tasks | 15/15 delivered (1.1–1.7 skeleton, 2.1–2.2 JS rules, 3.1–3.2 Python, 4.1–4.4 skip + E2E) |
| Requirements | 6/6 evidenced (`code-rules` delta spec) |
| Scenarios | 11/11 (`code-rules` delta spec) |
| Tests | full suite green at each landing, incl. `tests/rules.rs` through the binary |
| CI | green across the chain, including `cargo deny` + `cargo audit` |

## Follow-on Slice

This slice archives the `code-rules` delta, promotes the new capability, and
records this report. Proposal, design, and tasks move in the next slice
(`docs/archive-5-rules-artifacts`), which also updates `README.md`/`PRD.md`.

## Commits

Each hash below was verified with `git cat-file -t` (each returned `commit`):

- `ed0bbe3`, `7141581`, `f01c5ba` — seams, engine + wiring, weak-hash rule (#40, #41, #42).
- `b72ff0a` — JS/TS dynamic-code and shell-injection rules (#43).
- `8400553` — Python shell, hash, and deserialization rules (#44).
- `5855a15`, `d833d78` — superseded fallback table and E2E tests (#45, #46 bases).
- `b25d7e2`, `6e55e4c`, `7a2cae2` — the corrected skip contract that landed.

## Specs Synced

- **`code-rules` (created at `openspec/specs/code-rules/spec.md`)**: the
  delivered delta promoted verbatim — purpose, six requirements, eleven
  scenarios. Promotion was mechanical: shell copy plus `diff` readback, and the
  promoted file diffs empty against the delta source. No other durable spec is
  modified: the engine plugs into the existing normalization and renderer
  contracts unchanged and adds no CLI flag.

## Artifacts Archived

- specs/code-rules/spec.md (shell move, content unchanged)
- archive-report.md (this file, additive)
- proposal.md, design.md, tasks.md follow in the next slice

## Quality Gates and Mutation Testing

`cargo-mutants` is not installed: mutation testing is **unavailable**, not a pass. No PASS was fabricated.
