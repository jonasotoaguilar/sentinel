# Archive Report: sentinel-shell-completions

**Status**: Archived — SDD cycle complete. 2026-10-17.
**Archive path**: `openspec/changes/archive/2026-10-17-sentinel-shell-completions/`
**Store**: openspec (filesystem). This file is the terminal OpenSpec record in the archived audit trail.

- **Change**: `sentinel-shell-completions`
- **Archived**: `openspec/changes/archive/2026-10-17-sentinel-shell-completions/`
- **Date**: 2026-10-17
- **Artifact store**: openspec
- **Branch**: `docs/archive-1-shell-completions` (non-main)
- **Delivery strategy**: `auto-chain` / `stacked-to-main`
- **GitHub issue**: #39; **delivery PR**: #50

## Final State

The change shipped as implemented and verified: `sentinel completions <shell>`
for exactly the five shells `clap_complete 4.6.11`'s `Shell` enum provides
(`bash`, `zsh`, `fish`, `powershell`, `elvish`), so no hand-maintained shell
list was needed. The script is generated from the live command definition via
`clap_complete::generate` into the injected stdout writer, and dispatch returns
before discovery is constructed, so the command touches no repository. The
outside-a-repo test asserts the absence of a discovery error in both streams,
not merely a zero exit. `sentinel scan` behaviour and every existing test and
golden are unchanged.

| Metric | Final value |
| --- | --- |
| Tasks | 5/5 delivered (7.1 RED tests, 7.2 dependency, 7.3 variant + dispatch, 7.4 README line, 7.5 gates) |
| Requirements | 2/2 evidenced (`cli-scan` delta spec: modified Command surface, added Completion generation) |
| Scenarios | 6/6 (`cli-scan` delta spec) |
| Tests | full suite green on the delivery branch; every `scan` golden unchanged |
| fmt / clippy | `cargo fmt --check` clean; `clippy --all-targets --all-features -- -D warnings` clean |
| CI | green on #50, including `cargo deny` + `cargo audit` |

## Ordering Note

This change's own proposal records that it is archived after
`sentinel-explain-adapter`, because both modify the same `cli-scan` →
`Command surface` requirement and the successor must be authored against the
post-predecessor surface. Its delta was therefore authored against the
post-explain surface (`--explain` already accepted), and it is promoted here
verbatim in that form; the follow-up archive slice layers the explain-adapter
scenarios onto it. The transient state (this slice) already describes the
delivered binary exactly: `--explain` is accepted on `main`, and this spec says so.

## Commits

Each hash below was verified to exist in this repository with `git cat-file -t` (each returned `commit`) before being cited:

- `3a289e4` — feat(cli): add the completions subcommand (delivery; HEAD of the `feat/sentinel-completions` branch).
- `835797a` — Merge pull request #50 from `feat/sentinel-completions` (landing on `main`; closes #39).

## Specs Synced

- **`cli-scan` (updated by this slice)**: `Command surface` gains the
  `completions` subcommand alongside `scan` (exactly two subcommands; the five
  shells; the purity clause: no discovery, scan, network, or cache; works
  outside a Git repository), and the new `Completion generation` requirement
  pins stdout/exit-0 emission, generation from the live command definition, and
  the unsupported-shell usage error. The `(Previously: …)` annotation from the
  delta was dropped at promotion; every other requirement is untouched.
- **Leftover wording fixes landed with this slice** (deferred by the roadmap
  task log L22): `src/finding.rs`'s `rule_fallback` rustdoc now states the
  delivered contract (unparseable file skipped, exactly one diagnostic naming
  the path, no findings); `ARCHITECTURE.md`'s engine failure-mode line no
  longer describes a `fallback/warn` mechanism; `PRD.md`'s risk line no longer
  claims regex fallbacks. `PRD.md`'s stale bootstrap status line now states the
  MVP is implemented.

## Artifacts Archived

- proposal.md (shell move, content unchanged)
- design.md (shell move, content unchanged)
- tasks.md (shell move, content unchanged)
- specs/cli-scan/spec.md (shell move of the delta, content unchanged)
- archive-report.md (this file, additive)

## Quality Gates and Mutation Testing

`cargo-mutants` is not installed, so mutation testing is **unavailable**, not a pass, and no substitute campaign was run. This does not contradict any spec scenario and is not treated as an implementation failure. No PASS was fabricated.
