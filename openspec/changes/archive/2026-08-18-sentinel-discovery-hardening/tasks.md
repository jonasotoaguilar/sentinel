# Tasks: Sentinel Discovery Hardening

## Review Workload Forecast

Measured: 992 native; 831 authored excl. `Cargo.lock` (+64); Slice A ≈427 (>400). Ledger `sha256:9c5fc195b1533605d7cf7cac0edce1edf3cbe0e208e085f4e1cffe1662b2b098`: **maintainer-approved `size:exception`, A/PR1 only** — "small size exception for Slice A (~430 lines) so required discovery test compile fixes stay in the same green unit." Decision=No holds ONLY because this exception is authorized; sdd-apply/PR don't re-ask. B–D ≤400.

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Slice Map (`Cargo.lock` +64 identity in A)

- **A / PR1 (≈427, size:exception)** — Cargo.toml, cli.rs, lib.rs, discovery.rs prod + deferred test compile fixes (`pin_test_ambient_env`, `Mode`), tests/cli.rs (−1). Test: `cargo test --all-features`. Runtime: `sentinel scan --ci` `.env` → exit 1. Rollback: revert PR1 (tracked-only; `--ci` rejected).
- **B / PR2 (322, −31)** — discovery.rs test module + test_util.rs. Test: `cargo test --lib discovery` (23). Runtime: N/A (in-process). Rollback: revert PR2 → PR1 intact.
- **C / PR3 (82)** — cli.rs parser, lib.rs 3 tests + import, tests/cli.rs 2. Test: `cargo test --all-features`. Runtime: `sentinel scan --ci` golden → exit 1. Rollback: revert PR3 → tests only.
- **D / PR4 (pending)** — hermetic black-box: tests/fixtures/discovery/, tests/discovery_cli.rs. Test: `cargo test --test discovery_cli`. Runtime: `sentinel scan --ci` fixtures. Rollback: revert PR4 (PR1–3 intact).

**Staging (no revert)**: worktree untouched; `git add -p`, `--cached --stat` ≈ slice, each green. Stacked: PR1→main, rebase, PR2→main, rebase, PR3→main, PR4.

## Phase 1: Foundation

- [x] 1.1 RED `src/cli.rs`: `scan --ci` → `Scan { ci: true }`; drop `--ci` from unsupported-args unit.
- [x] 1.2 GREEN `src/cli.rs`: `Scan { ci: bool }` via `#[arg(long)]`; other args usage errors (S16–S19).
- [x] 1.3 `Cargo.toml`/`Cargo.lock`: add `ignore = "0.4"`; `cargo deny check` + `cargo audit` pass.

## Phase 2: Core Discovery

- [x] 2.1 RED unit: untracked `.env` + hidden-dir scanned (S1); `.gitignore` ignored (S2); nested repo skipped (S6); symlink-out unfollowed (S7).
- [x] 2.2 RED unit: force-added tracked retained (S3); `.sentinelignore` excludes tracked+untracked, whole subtree (S4,S5); staged-ignored/empty-index/post-`commit -a` retained.
- [x] 2.3 RED unit: 10 MiB skipped, `skipped-large`, exit unchanged (S8); invalid path warned+excluded (S9); `-C` file as file; cwd variants identical.
- [x] 2.4 RED unit: repeated + concurrent runs byte-identical (S11,S12).
- [x] 2.5 GREEN `src/discovery.rs`: `Mode::{Local,Ci}`; `discover(&Path, Mode)`; walker hidden(false)/follow_links(false)/require_git(true)/`.sentinelignore`; Ci disables parents/global/exclude; tracked-wins union; prune `.git`/nested; safe-relative+is_file(); 10 MiB guard; `Discovered{root,files,diagnostics}`.
- [x] 2.6 REFACTOR: share `is_safe_relative`; sort files+diagnostics deterministically.

## Phase 3: Pipeline Wiring

- [x] 3.1 GREEN `src/lib.rs`: `Scan{ci}` → Mode; `discover(cwd, mode)`; merge diagnostics.
- [x] 3.2 Update `src/lib.rs`/`tests/cli.rs` tests for new `Command` shape; preserved contracts green.

## Phase 4: Black-box & Regressions (PR4)

- [x] 4.1 Create `tests/fixtures/discovery/`: gitignores, `.sentinelignore`, nested repo, symlink-out, 10 MiB, unreadable, synthetic secrets.
- [x] 4.2 RED `tests/discovery_cli.rs`: ambient-ignored scanned under `--ci`, omitted locally (S13,S14); findings+exit 1 match local (S15).
- [x] 4.3 RED regressions: `.sentinelignore` subtree, nested repo, symlink, `-C` file, commit-state matrix (S4–S7).
- [x] 4.4 RED determinism: concurrent + repeated runs byte-identical via `snapshot_tree` (S11,S12).
- [x] 4.5 RED: 10 MiB `skipped-large`, exit unchanged (S8); unreadable untracked file warns, continues (S10, root-gated).

## Phase 5: Cleanup (PR4)

- [x] 5.1 Quality gates green (fmt, clippy, test); update docs.
