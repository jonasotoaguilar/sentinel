# Design: Sentinel Discovery Hardening

## Technical Approach

Extend the existing synchronous discovery module (ADR-0001) without changing engines, findings, renderers, or exit policy. Keep byte-preserving `git ls-files -z` as tracked authority and add an `ignore` walker for present untracked files. Discovery validates, unions, deduplicates, size-filters, and sorts repository-relative paths before the existing Rayon scan stage.

## Architecture Decisions

| Option | Tradeoff | Decision and rationale |
|---|---|---|
| Git only / walker only / hybrid | Git misses untracked files; walker cannot preserve forced-tracked files | Hybrid. Tracked membership wins over Git ignores; `.sentinelignore` post-filters both sources. |
| Ambient / hermetic ignores | Ambient rules match developer Git behavior but vary by machine | `Local` keeps Git-natural defaults. `Ci` sets `parents(false)`, `git_global(false)`, and `git_exclude(false)`; both set `hidden(false)`, `follow_links(false)`, `require_git(true)`, and `add_custom_ignore_filename(".sentinelignore")`. |
| Parallel / serial discovery | Parallel walking complicates warning order for little gain before Rayon | Use the serial walker, then deterministic sort. The 50k-file scan remains subject to the existing ≤60 s NFR. |
| Silent / diagnostic size limit | Silent filtering hides coverage gaps | Apply a 10 MiB (`10 * 1024 * 1024`) post-union metadata guard to tracked and untracked files; emit sorted `skipped-large` diagnostics without affecting exit status. |

**Default trap:** `ignore::WalkBuilder` hides dotfiles by default. `hidden(false)` is mandatory, and RED tests place an untracked secret in `.env` in both modes; either omission or a future default regression fails them.

## Data Flow

```text
CLI `scan [--ci]` -> DiscoveryMode -> repo root
  -> `git ls-files -z` tracked ----\
  -> configured ignore walker -----+-> sentinel-ignore filter
                                      -> tracked-wins union -> path/type/size validation
                                      -> sorted files + sorted diagnostics -> existing scan/render
```

A sentinel-ignore matcher stack mirrors the walker's nested-file precedence when post-filtering tracked paths. Walker pruning rejects `.git` and any non-root directory containing a `.git` file/directory. Every candidate must strip the root prefix, contain no absolute/parent components, and pass `symlink_metadata().file_type().is_file()`; links are never followed.

## Interfaces / Contracts

- `cli::Command::Scan { ci: bool }` accepts only `--ci`; other unsupported arguments remain usage errors.
- `discovery::Mode::{Local, Ci}` is a small explicit enum passed to `Git::discover(&Path, Mode)`.
- `Discovered` adds discovery diagnostics beside `root` and sorted `files`; `lib.rs` merges them with engine diagnostics before the unchanged deterministic renderer.
- Fatal root/Git/process failures remain typed `Error` values and exit 2. Recoverable walk, metadata, read, and oversize failures skip only that path and use stable codes, repository-relative paths, and deterministic messages. Findings still determine only exits 0/1.

## File Changes

| File | Action | Description |
|---|---|---|
| `Cargo.toml`, `Cargo.lock` | Modify | Add crates.io `ignore = "0.4"` and lock transitives. The crate is MIT OR Unlicense; existing MIT allowance applies. `cargo deny`/`cargo audit` verify the complete graph; no license waiver is planned. |
| `src/cli.rs`, `src/lib.rs` | Modify | Parse and pass `--ci`; merge discovery diagnostics. |
| `src/discovery.rs` | Modify | Implement mode-aware hybrid discovery and focused unit tests. |
| `tests/discovery_cli.rs`, `tests/fixtures/discovery/` | Create | Black-box repositories/fixtures for ignores, warnings, and determinism. |

## Testing Strategy

Unit tests cover NUL paths, union precedence, `.sentinelignore`, hidden files, nested repos, symlinks, validation, and 10 MiB boundaries. CLI integration tests cover local ambient ignores; CI parent/global/info-exclude isolation; unreadable/empty repositories; deterministic stdout/stderr across repeated and parallel runs; and unchanged 0/1/2 behavior. Tests use `tempfile`, `assert_cmd`, synthetic secrets, and hermetic Git config.

## Threat Matrix

| Boundary | Applicability | Safe/failure behavior | Planned RED tests |
|---|---|---|---|
| Documentation-like paths | N/A — no executable classification or execution | Ordinary scan input | None |
| Git repository selection | Applicable | `current_dir` selects the root; no shell or `git -C`; invalid/non-repo paths exit 2 | Untracked `-C` is a file; nested-relative and absolute cwd resolve identically |
| Commit state | Applicable | Read index/worktree only; never mutate Git state | Staged ignored file retained; empty index finds untracked file; post-`commit -a` tracked file retained |
| Push state | N/A — no push/ref resolution | No behavior | None |
| PR commands | N/A — no PR command composition | No behavior | None |

## Migration / Rollout

No persisted-state migration or feature flag. Local scans may newly find untracked secrets and exit 1; `--ci` becomes valid but changes only ignore provenance. Deliver two chained PRs, each forecast below the 400-line CI cap and together below 800 authored lines: (1) local hybrid discovery, validation, size diagnostics, and unit coverage; (2) hermetic `--ci`, black-box fixtures, and determinism/security regressions. Roll back PR2 then PR1 to restore tracked-only discovery and rejected `--ci`.

## Open Questions

None.
