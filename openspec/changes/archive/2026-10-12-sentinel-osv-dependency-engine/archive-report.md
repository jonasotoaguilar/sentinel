# Archive Report: sentinel-osv-dependency-engine

**Status**: Archived — SDD cycle complete. 2026-10-12.
**Archive path**: `openspec/changes/archive/2026-10-12-sentinel-osv-dependency-engine/`
**Store**: openspec (filesystem). This file is the terminal OpenSpec record in the archived audit trail.

- **Change**: `sentinel-osv-dependency-engine`
- **Archived**: `openspec/changes/archive/2026-10-12-sentinel-osv-dependency-engine/`
- **Date**: 2026-10-12
- **Artifact store**: openspec
- **Branch**: `docs/sdd-archive` (non-main)
- **Delivery strategy**: `auto-chain` / `stacked-to-main`
- **GitHub issue**: #19; **chain of nine PRs**: #20–#28

## Final State

The change shipped as implemented and verified: pinned npm/PyPI manifest parsing, OSV v1 batch/detail querying with boundary validation, schema-versioned XDG cache with 24 h online TTL, `--offline` orthogonal to `--ci`, and degrade-never-2 wiring through the existing terminal/JSON/SARIF renderers.

| Metric | Final value |
| --- | --- |
| Tasks | 18/18 checked in persisted `tasks.md` |
| Requirements | 5/5 evidenced (`dependency-review` delta spec) |
| Scenarios | 7/7 (`dependency-review` delta spec) |
| Tests | 110, then 113, then 120, then 129 passing across the chain |
| fmt / clippy | `cargo fmt --check` clean; `clippy --all-targets --all-features -- -D warnings` clean |
| CI | green, including `cargo deny` + `cargo audit` |

Tasks note: the persisted `tasks.md` records `- [x]` for all 18 items. The Phase 5 boxes (5.1 fixtures, 5.2 end-to-end `--offline`/`--ci --offline`, JSON/SARIF twice, online I/O bounds and secrets still reporting, 5.3 ADR-0002 confirmation) were checked at archive time so the record matches the delivered and verified Phase 5 instead of leaving an administrative lag: every artifact they name exists in commit `9a7cf8a`. The 129-pass count and the fmt/clippy cleanliness at that commit were re-executed by the independent verification of the candidate; 110, 113 and 120 come from the parent's runs at the earlier chain commits, and the CI statement comes from the GitHub check runs on the nine PRs. Nothing was re-executed while writing this report (archive constraints: no cargo, no network, no gh).

## Independent Verification

An early verification at commit `563858e` returned one blocking finding and one uncertain item: the boundary-validation requirement S6 was only partly implemented, and there was no joint proof that degradation exits 0/1 while secrets still report. The final verification at commit `9a7cf8a` returned verdict "merge this candidate": S6 was closed with wire-shaped tests and an independently computed scope-changed CVSS vector, the degrade-with-secrets item was closed with the end-to-end offline-miss test, and no panic was found reachable from untrusted JSON. The verifying agent re-ran the full suite and the fmt/clippy gates at that commit; the narratives themselves are recorded here from the delivery record, and no verify-report artifact exists in the change folder to re-read under archive constraints.

## Non-blocking Follow-ups

- Online batch entries that fail both the detail fetch and summary validation are skipped without an `advisory-invalid` diagnostic.
- The trailing `last.unwrap()` in `do_post`/`vuln_with_deadline` is dead code.

## Empirical OSV Wire Facts

These live-wire observations shaped the delivered validation rules:

- A querybatch summary entry is `{"id","modified"}` with no severity or affected, so detail fetch is conditional on missing mapping fields.
- `severity[].score` is a CVSS vector string, not a number, so severity derivation parses the vector.
- One advisory's `affected[]` legitimately mixes `npm` with other ecosystems, so ecosystem matching is per-entry, not per-advisory.

## Commits

Each hash below was verified to exist in this repository with `git cat-file -t` (each returned `commit`) and `git log --all` before being cited:

- `1d8bab3` — feat(engine): wire dependency review with offline transport (dependency review wiring and offline transport).
- `563858e` — fix(osv): correlate batch advisories per pin and bound the scan (per-pin batch correlation and one shared network deadline).
- `d7a3f7b` — fix(deps): bump rustls to 0.23.45 for RUSTSEC-2026-0285 (first branch of the chain).
- `296c2d8` — fix(deps): bump rustls to 0.23.45 for RUSTSEC-2026-0285 (second branch of the chain).
- `970b086` — fix(osv): validate OSV wire shapes, derive CVSS severity and report unreadable cache entries (boundary validation, CVSS v3.1 severity derivation, cache-read corruption reporting).
- `9a7cf8a` — test(dependency): cover offline, cache and report behavior end to end (end-to-end suite; HEAD of `docs/sdd-archive` in this worktree).
- `87aaaa4` — docs(sdd): promote the delivered dependency review specs (spec promotion; present in this repository on `docs/spec-promotion`).

## Specs Synced

- **`dependency-review` (created at `openspec/specs/dependency-review/spec.md`, delivered by PR #27 of the same chain)**: the delivered delta promoted verbatim — purpose, five requirements, seven scenarios. Promotion was mechanical: shell copy plus `diff` readback, and the promoted file diffs empty against the delta source.
- **`cli-scan` (updated by PR #27 of the same chain)**: gains `--offline` in `Command surface`, the degrade clause (`Network or cache degradation MUST NOT exit 2`) in `Exit-code contract`, and the renamed `Network, cache, and telemetry policy` (replacing the no-network rule), plus a corrected purpose line. Every other requirement is untouched. The promotion diff is confined to the three requirements plus the purpose line.
- **Purpose-line correction**: the purpose line previously claimed "no network I/O, no persistent state", which the same file now contradicts by requiring bounded `api.osv.dev` calls and XDG cache writes unless `--offline`. The promoted purpose states the scan MAY call `api.osv.dev` and write the XDG OSV advisory cache unless `--offline`.

## Artifacts Archived

- proposal.md (byte-identical shell copy, `diff` exit 0)
- tasks.md (byte-identical shell copy, `diff` exit 0; records 18/18)
- specs/cli-scan/spec.md (byte-identical shell copy of the delta, `diff` exit 0)
- specs/dependency-review/spec.md (byte-identical shell copy of the delta, `diff` exit 0)
- archive-report.md (this file, additive)

`design.md`, `exploration.md`, and `apply-progress.md` are deliberately not archived: the repository's PR review gate fails above 400 changed lines and this archive must not delete documents to fit; the report records their outcomes instead. Their outcomes are preserved above (wire facts, validation rules, severity table, cache layout, commit history) and in the synced specs.

## Quality Gates and Mutation Testing

`cargo-mutants` is not installed, so mutation testing is **unavailable**, not a pass, and no substitute campaign was run. This does not contradict any spec scenario and is not treated as an implementation failure. No PASS was fabricated.
