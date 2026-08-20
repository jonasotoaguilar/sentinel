# Proposal: Sentinel Discovery Hardening

## Intent

Sentinel scans only `git ls-files`, so fresh `.env` or scratch files can evade pre-commit/CI checks. Implement PRD §§3–6 discovery rules for relevant untracked files, ignore policy, and deterministic local-first scans.

## Users and Product Outcome

- Developers catch untracked secrets without ignored-tree noise.
- CI owners get machine-independent repository-local input under `--ci`.
- Reviewers retain stable paths/warnings and the 0/1/2 exit contract.

## Current-State Gap and Business Rules

- `src/discovery.rs` lacks untracked walking, ignores, `.sentinelignore`, `--ci`, and a size guard.
- Use pinned `git ls-files -z` + `ignore` walker with mandatory `hidden(false)`, `follow_links(false)`, and `require_git(true)`.
- Union/deduplicate/validate/sort; tracked entries beat Git ignores; `.sentinelignore` applies to the full union.
- Local mode is git-natural. `--ci` disables parent, global, and `.git/info/exclude` sources; it changes no blocking or exit policy.
- Skip `.git` and nested repositories. Guard files at 10 MiB; emit deterministic `skipped-large` on stderr without changing exit status.

## Scope

### In Scope

- Ignore-aware untracked discovery, safe unioning, nested-repository exclusion, and deterministic ordering.
- Hermetic `--ci`, full-file `.sentinelignore`, and the 10 MiB diagnostic guard.
- Fixtures cover hidden/forced-tracked files, ambient ignores, symlinks, empty repositories, determinism, and warnings.

### Out of Scope / Non-Goals

Dependency/OSV scanning, JSON/SARIF, `--explain`, Tree-sitter, CLI exclusion globs, findings model, fingerprints, renderers, blocking/exit-policy changes, migrations, and docs rewrites are unchanged.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `git-discovery`: add untracked, ignore-aware, hermetic, bounded discovery.
- `cli-scan`: accept `--ci` while preserving unsupported-argument and 0/1/2 behavior.

## Approach, Impact, and Migration

Extend `src/discovery.rs` with the architecture’s `git ls-files`/`ignore` union; update CLI parsing, diagnostics, manifest/lockfile, and fixtures. This follows `ARCHITECTURE.md`. Untracked files may add findings; `--ci` becomes supported. No persisted-state migration is needed.

## Acceptance Direction

Scan untracked/hidden files, omit ignored/nested-repository files, retain forced-tracked files, and apply `.sentinelignore` to both classes. Symlinks are not followed; empty repositories proceed normally; unreadable files warn and continue. CI ambient ignores have no effect; repeated/parallel runs are byte-identical; oversized files warn without changing exit status; non-repo failures remain exit 2.

## Risks, Delivery, and Open Decisions

- Risks: walker/Git divergence, hidden-file regressions, `.sentinelignore` precedence, dependency review, and behavior surprise. Mitigate with fixtures, `cargo deny`/audit, and migration messaging.
- Forecast: two automatic chained PRs—core discovery/CLI, then hermetic/diagnostic fixtures—targeting the 400-line CI cap and 800-line review budget.
- Unresolved decisions: None; recommendations above are pinned.

## Rollback Plan

Revert the two implementation PRs in reverse order to restore tracked-only discovery and rejected `--ci`; findings and persisted state remain untouched.

## Success Criteria

- [ ] Acceptance scenarios pass with deterministic output and warnings.
- [ ] `--ci` is hermetic while exit codes remain exactly 0/1/2.
- [ ] Quality gates and dependency checks pass.
