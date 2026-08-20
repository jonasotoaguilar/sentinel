# Apply Progress: Sentinel Discovery Hardening — PR1 (tasks 1.1–3.2)

Change: `sentinel-discovery-hardening`
Branch: `feat/discovery-hardening` (even with `main` at `54c0d1b`)
Store: hybrid (OpenSpec + Engram)
Mode: standard (strict TDD inactive — `openspec/config.yaml` `testing.strict_tdd: false`)
Delivery: `auto-chain` / `stacked-to-main`, review budget 800 lines
Slice: PR1 — Phase 1 (Foundation), Phase 2 (Core Discovery), Phase 3 (Pipeline Wiring)
Prior apply-progress: none found (first batch); this artifact is cumulative.

> Retry delivery note (2026-08-05): PR1 was re-sliced for review size. The maintainer
> granted a `size:exception` for **Slice A** (~427 authored lines) so the API compile
> fixes remain in the green unit; Slice B (new unit/integration tests + `test_util`
>
> - discovery test-module deletion) follows unstaged. See "Slice A Delivery" below.

## Completed Tasks (cumulative)

- [x] 1.1 RED `src/cli.rs` unit: `scan --ci` → `Command::Scan { ci: true }`; drop `--ci` from `unsupported_arguments_are_usage_errors`.
- [x] 1.2 GREEN `src/cli.rs`: `Scan { ci: bool }` via `#[arg(long)]`; other args remain usage errors (S16–S19).
- [x] 1.3 `Cargo.toml`/`Cargo.lock`: add `ignore = "0.4"` (resolved `ignore 0.4.33`); `cargo deny check` + `cargo audit` pass.
- [x] 2.1 RED unit (`test_util::{temp_repo,git}`): untracked `.env` + hidden-dir file scanned (S1); `.gitignore` file/dir ignored (S2); nested repo skipped (S6); symlink-out unfollowed (S7).
- [x] 2.2 RED unit: force-added tracked retained (S3); `.sentinelignore` excludes tracked+untracked, whole subtree (S4,S5); staged-ignored/empty-index/post-`commit -a` retained (threat matrix).
- [x] 2.3 RED unit: 10 MiB skipped, `skipped-large` stderr, exit unchanged (S8); invalid path warned+excluded (S9); `-C` file scanned as file; nested vs absolute cwd identical (threat matrix).
- [x] 2.4 RED unit: repeated + concurrent discovery byte-identical (S11,S12).
- [x] 2.5 GREEN `src/discovery.rs`: `Mode::{Local,Ci}`; `discover(&Path, Mode)`; walker `hidden(false)`, `follow_links(false)`, `require_git(true)`, `add_custom_ignore_filename(".sentinelignore")`; `Ci` → `parents/git_global/git_exclude(false)`; serial walk; tracked-wins union+dedupe; prune `.git`/nested repos; root-strip+`is_safe_relative`+`symlink_metadata().is_file()`; 10 MiB guard; `Discovered{root,files,diagnostics}`.
- [x] 2.6 REFACTOR: share `is_safe_relative`; sort files+diagnostics deterministically.
- [x] 3.1 GREEN `src/lib.rs`: map `Command::Scan{ci}` → Mode; `discover(cwd, mode)`; merge `discovered.diagnostics` pre-`render_diagnostics`.
- [x] 3.2 Update `src/lib.rs`/`tests/cli.rs` tests for new `Command` shape; S16–S19 + preserved contracts green.

Status: 11/17 tasks complete; PR1 slice complete.

## Work Unit Evidence (PR1)

| Evidence                                          | Required value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Focused test command and exact result             | `cargo test --all-features` → **64 passed (4 suites, 0.06s)**. RED phase: `cargo test --lib discovery` → 14 passed / 9 failed (all 9 new untracked/ignore/size/determinism tests); `cargo test --lib cli::tests` → compile error (RED 1.1), then 4 passed (GREEN 1.2).                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Runtime harness command/scenario and exact result | Binary on temp repos (`target/debug/sentinel scan [--ci]` in demo repos): untracked `scratch.env.txt` with synthetic AWS key → **Local exit 1 and `--ci` exit 1**, redacted finding `scratch.env.txt:1:11: critical SECRET-aws-access-key`, raw key absent from both streams. Untracked `.env` → Local exit 0 (omitted — git-natural: developer machine global gitignore `~/.config/git/.gitignore` contains `.env`), `--ci` exit 1 (hermetic finds it; S13/S14 semantics — full differential coverage lands in PR2 task 4.2). Untracked 10 MiB `huge.bin` → stderr `sentinel: skipped-large: huge.bin: 10485760 bytes exceeds the 10 MiB scan limit`, exit unchanged (0 clean / 1 findings). `scan --explain` still exit 2 with empty stdout. |
| Rollback boundary                                 | Revert this PR1 slice → `git checkout` of `src/cli.rs`, `src/discovery.rs`, `src/lib.rs`, `src/test_util.rs`, `tests/cli.rs`, `Cargo.toml`, `Cargo.lock` restores tracked-only discovery and rejected `--ci`; findings/engines/renderers/fingerprints untouched; no persisted state exists to migrate. PR2 (tasks 4.1–5.1, not implemented) builds on top.                                                                                                                                                                                                                                                                                                                                                                                     |

## Files Changed

| File                                                              | Action   | What Was Done                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Cargo.toml`                                                      | Modified | Added `ignore = "0.4"` (MIT OR Unlicense; existing MIT allowance).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `Cargo.lock`                                                      | Modified | Locked `ignore 0.4.33` + transitives (`globset`, `log`, `same-file`, `walkdir`, `winapi-util`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `src/cli.rs`                                                      | Modified | `Command::Scan { ci: bool }` via `#[arg(long)]`; docs updated; tests accept `--ci`, others still usage errors.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `src/discovery.rs`                                                | Modified | Hybrid discovery: `Mode::{Local,Ci}`, `discover(&Path, Mode)`, serial ignore walker (`hidden(false)`, `follow_links(false)`, `require_git(true)`, `.sentinelignore` custom ignore filename; Ci disables parents/global/exclude), `filter_entry` pruning of `.git` + nested repos, tracked-wins BTreeSet union, `.sentinelignore` matcher (GitignoreBuilder) post-filter, shared relative-path guard, `symlink_metadata().is_file()` type check, 10 MiB size guard, sorted `files` + sorted/deduped `diagnostics` (`skipped-large`, `invalid-path`, `walk-failed`, `sentinel-ignore-failed`); 23 unit tests. |
| `src/lib.rs`                                                      | Modified | `Command::Scan { ci }` → `Mode::{Local,Ci}`; diagnostics merged pre-renderer; tests updated + new pipeline tests (untracked secret local/CI, `--ci` accepted, oversized warning without exit change).                                                                                                                                                                                                                                                                                                                                                                                                       |
| `src/test_util.rs`                                                | Modified | Added `write_untracked`, `commit_all`; `write_tracked` creates parent dirs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `tests/cli.rs`                                                    | Modified | `--ci` removed from unsupported-args list; added `ci_flag_is_accepted_and_scans_the_repository`, `ci_flag_on_clean_repo_exits_zero_with_empty_streams`.                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `openspec/changes/sentinel-discovery-hardening/tasks.md`          | Modified | Checkboxes `[x]` for tasks 1.1–3.2.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `openspec/changes/sentinel-discovery-hardening/apply-progress.md` | Created  | This artifact (hybrid filesystem side).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

## Deviations from Design

None in behavior — implementation matches `design.md`. Two implementation details worth recording:

1. `.sentinelignore` files are consumed by the ignore walker as ignore sources and are **not** scan candidates (the walker yields `.gitignore`/`.ignore` but not registered custom ignore filenames). Tests assert this; module docs note it.
2. `ignore::Error` in 0.4.33 exposes no `path()` accessor; a small `walk_error_path` peels the public `WithPath`/wrapper variants deterministically for `walk-failed` diagnostics.

## Issues Found / Risks

- **PR1 changed lines exceed the forecast**: 831 authored lines (additions + deletions, excl. `Cargo.lock`; lockfile +64) vs. the tasks forecast of ~450–650 for the whole change and the 400-line per-PR cap. The forecast under-estimated test volume (23 discovery + 4 pipeline + 2 integration tests map 1:1 to tasks/scenarios). Recommendation: split PR1 at creation time (e.g., PR1a = Phases 1–2, PR1b = Phase 3) or record an explicit `size:exception` for PR1; PR2 then needs its own budget accounting (its fixtures are excluded from authored counts but snapshot identity includes them).
- **Ambient-ignore machine dependence**: Local mode is git-natural by design; on machines with a global gitignore matching test names (e.g., `.env`), in-process Local-mode unit tests are protected by the test-only ambient-env pin in `discovery.rs` (`pin_test_ambient_env`), which runs once per test process. PR2's black-box tests (4.2) will exercise Local-vs-Ci differentially with full process env control.
- Remaining PR2 work is untouched: tasks 4.1–4.5, 5.1 (fixtures, `tests/discovery_cli.rs`, hermetic `--ci` regressions, determinism via `snapshot_tree`, cleanup gates/docs).

## Verification Summary

- `cargo test --all-features` → 64 passed (4 suites)
- `cargo fmt --all -- --check` → clean
- `cargo clippy --all-targets --all-features -- -D warnings` → no issues
- `cargo deny check` → advisories ok, bans ok, licenses ok, sources ok
- `cargo audit` → exit 0, 88 crates, 0 vulnerabilities

## Workload / PR Boundary

- Mode: stacked PR slice (auto-chain / stacked-to-main); no PR created in this phase.
- Current work unit: PR1 — CLI `--ci` + hybrid discovery + pipeline wiring + unit coverage.
- Boundary: starts from tracked-only discovery with rejected `--ci` (HEAD `54c0d1b`); ends with hybrid discovery (Local + Ci), `--ci` accepted, 11 tasks complete, full suite green.
- Estimated review budget impact: ~831 authored changed lines (see risk above).

## Slice A Delivery — size:exception (2026-08-05)

Retry of the PR1 delivery. The maintainer authorized `size:exception` at **~427 authored lines** because the API compile fixes must remain in the green unit. Native runtime acquire returned `state: proceed`; parent settlement bound `sha256:5d024a1264679c3edb36205279d7ff7c1631e9cb6c0a6c0f8b00974e3f6f8989`. No PR opened; deterministic non-interactive patch staging (`git apply --cached`) used — the worktree was never modified.

**Commit**: `fa00c35` (`feat(discovery): add ignore-aware discovery foundation`) on `feat/discovery-hardening`, no Co-Authored-By.

| Path                        | Staged content                                                                                                                                                                                                                                   |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Cargo.toml` / `Cargo.lock` | `ignore = "0.4"`; lock +64 (generated)                                                                                                                                                                                                           |
| `src/cli.rs`                | Production parser (`Scan { ci: bool }`, module docs) + existing unsupported-list adjustment (drop `--ci`) — not the new parser test                                                                                                              |
| `src/discovery.rs`          | Production portion (`Mode`, hybrid discover, walker, guards, diagnostics, `pin_test_ambient_env`) + required compile fixes in the existing test module (`Mode` import, `Mode::Ci` on old call sites, retained `repeated_discovery_is_identical`) |
| `src/lib.rs`                | Minimal production wiring (`Scan{ci}`→Mode, `discover(cwd, mode)`, diagnostics merge) + existing unsupported-list adjustment — not new pipeline tests                                                                                            |
| `tests/cli.rs`              | Existing unsupported-list deletion only — not the new `--ci` tests                                                                                                                                                                               |

**Deliberately not staged** (preserved unstaged for Slice B): `src/test_util.rs`; the complete new discovery unit-test module (2.1–2.4 + `TEN_MIB`/`skipped_large`/new imports + `repeated_discovery_is_identical` deletion); cli.rs new `ci_flag_parses_to_scan_with_ci_true` and modified `scan_subcommand_is_accepted`; new lib.rs pipeline tests; new tests/cli.rs `--ci` tests; all `openspec/` artifacts.

**Staged line counts** (numstat): Cargo.lock +64/-0 · Cargo.toml +1/-0 · src/cli.rs +8/-4 · src/discovery.rs +341/-39 · src/lib.rs +16/-5 · tests/cli.rs +0/-1 → **430 insertions / 49 deletions**; authored (excl. Cargo.lock) = **415** changed lines (≈427 exception, Δ 12 / 2.8%).

**Slice A work-unit evidence**:

- Focused test command/result: `cargo test --all-features` on a clean temp worktree at `fa00c35` → **44 passed (4 suites, 0.07s)** — 29 lib unit (incl. retained `repeated_discovery_is_identical`) + 15 integration (no new `--ci` tests); exit 0.
- Runtime harness command/result: temp repo (`git init`, tracked `clean.txt`, untracked `.env` = `token = sk-synthetic-1234567890`), `sentinel scan --ci` with hermetic env → **exit 1**; stdout `.env:1:9: medium SECRET-synthetic-token` with `[REDACTED]`; raw `sk-synthetic-1234567890` / `AKIASYNTHETICKEY1234` absent from both streams; stderr empty.
- Rollback boundary: commit `fa00c35` is a pure index/HEAD operation (worktree bytes untouched), so `git reset --mixed fa00c35~1` returns HEAD to `54c0d1b` with ALL final-state changes (Slice A + Slice B remainder) still in the worktree — nothing is lost.

**Independent verification (clean temp worktree at `fa00c35`)**: `cargo fmt --all -- --check` PASS · `cargo clippy --all-targets --all-features -- -D warnings` PASS (exit 0) · `cargo test --all-features` PASS (44 passed) · runtime harness PASS (exit 1, untracked synthetic secret found, redacted-only output).

**Scope note**: measured authored lines 415 vs the ~427 exception — within the approval (not broadened). Only discretionary additions beyond production code are the existing-test adjustments required to keep the green unit green (reject-list deletions in cli.rs/lib.rs/tests/cli.rs; `Mode::Ci` on the 11 retained old discovery call sites; `pin_test_ambient_env`).

**Remaining worktree status (final-state, all unstaged)**: `M src/cli.rs` · `M src/discovery.rs` · `M src/lib.rs` · `M src/test_util.rs` · `M tests/cli.rs` · `?? openspec/changes/sentinel-discovery-hardening/` (untracked planning artifacts). Tasks 1.1–3.2 remain complete; **tasks 4.1–5.1 NOT marked complete**.

---

# Apply Progress Addendum — PR4 / Slice D (tasks 4.1–5.1), reconciliation batch

Batch: 2026-08-18 (reconcile-hardening-tasks-4.1-5.1) · worktree `feat/sentinel-sarif-output`
Mode: standard (strict TDD inactive per `openspec/config.yaml`) · delivery `auto-chain` / `stacked-to-main`
Runtime attempt: parent-owned, token `sha256:0bb148e5…cfae8cb8`; this batch does NOT acquire or settle.
Scope: tasks 4.1–4.5 + 5.1 were implemented and merged in PRs #10 (`8b52c2b`) and #11 (`74a2cee`) on this branch.
This batch reconciles each task against concrete repository + runtime evidence, applies the smallest durable
docs fix (README `--ci`), and updates tasks/apply-progress to the final truthful state.

## Completed Tasks (cumulative — 17/17)

- [x] 1.1–3.2 — as recorded in the PR1 section above (11 tasks).
- [x] 4.1 `tests/fixtures/discovery/` committed corpus: `clean/main.rs`, `gitignore/basic.txt`, `secrets/env.example`, `sentinelignore/build.txt`, `sentinelignore/secret-glob.txt`; synthetic-only audited by `fixture_corpus_is_synthetic_only` (tests/cli.rs:587). Nested-repo/symlink-out/10 MiB/unreadable states are built at runtime in `tests/discovery_cli.rs` (a committed 10 MiB fixture would bloat the repo; symlink targets must live outside the repo).
- [x] 4.2 `ci_mode_scans_files_omitted_by_ambient_global_ignore` (S13 hermetic + S14 git-natural, planted `core.excludesFile` global gitignore) and `local_and_ci_produce_identical_findings_and_exit_without_ambient_ignores` (S15, byte-identical stdout/stderr + exit 1).
- [x] 4.3 `gitignored_untracked_files_and_directories_are_excluded` (S2), `force_added_tracked_file_is_retained_despite_gitignore` (S3), `sentinelignore_excludes_tracked_and_untracked_files` (S4), `sentinelignore_directory_pattern_excludes_whole_subtree` (S5), `nested_git_repository_is_skipped` (S6), `symlink_outside_repo_is_not_followed` (S7, unix), commit-state matrix: `untracked_c_like_file_is_scanned_as_a_file` (`-C`), `empty_index_repo_still_discovers_untracked_secrets`, `committed_files_are_retained_after_commit_all`.
- [x] 4.4 `repeated_and_concurrent_runs_are_byte_identical` — serial ×2 + 2 concurrent children, byte-identical stdout/stderr, serial==concurrent, `snapshot_tree` before/after equal (read-only scan) (S11, S12).
- [x] 4.5 `oversized_untracked_file_is_skipped_without_changing_exit` (S8, exit 1 preserved) + `oversized_untracked_file_on_clean_repo_exits_zero` (S8, exit 0 preserved); `unreadable_untracked_file_warns_and_scan_continues` (S10, root-gated via `running_as_root` skip).
- [x] 5.1 Quality gates green (evidence below); docs updated: README usage block now documents `sentinel scan --ci` (hermetic). ARCHITECTURE.md already specified hermetic CI + ignore-walker discovery (written at design time) and matches the shipped implementation — no edit needed.

## Work Unit Evidence (PR4 reconciliation)

| Evidence                                          | Required value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Focused test command and exact result             | `cargo test --test discovery_cli` → **15 passed (1 suite, 0.05s)**. Full suite: `cargo test --all-features` → **97 passed (6 suites, 0.20s)**.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Runtime harness command/scenario and exact result | Real binary over `/tmp/opencode/sd-harness` (fixture-derived: tracked `env.example`/`src-main.rs`, untracked `.env` + `ambient.env`, 10 MiB `huge.bin`, planted global gitignore). Local: exit 1, 3 SECRET findings, `ambient.env` omitted (S14 git-natural). `--ci`: exit 1, 4 SECRET findings incl. `ambient.env` (S13 hermetic); raw `sk-synthetic-1234567890`/`AKIASYNTHETICKEY1234` absent from both streams (redaction). stderr both modes: `sentinel: skipped-large: huge.bin: 10485760 bytes exceeds the 10 MiB scan limit`. Determinism: repeated stdout/stderr identical; concurrent stdout/stderr identical; concurrent == serial. |
| Rollback boundary                                 | Revert README.md edit (5.1 docs) → tests/implementation untouched. Revert PR4 commits (`74a2cee`, `cf2b806`, `8b52c2b`, `269cabb`) → PR1–3 intact; fixtures/tests are additive, no production code in PR4.                                                                                                                                                                                                                                                                                                                                                                                                                                    |

## Files Changed (this batch)

| File                                                              | Action   | What Was Done                                                                                                                                            |
| ----------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `README.md`                                                       | Modified | Added `sentinel scan --ci` usage example + clarified the plain-scan comment (untracked, ignore-aware discovery). Smallest durable docs fix for task 5.1. |
| `openspec/changes/sentinel-discovery-hardening/tasks.md`          | Modified | Checkboxes `[x]` for tasks 4.1–4.5 and 5.1 (17/17).                                                                                                      |
| `openspec/changes/sentinel-discovery-hardening/apply-progress.md` | Modified | This addendum (merged with prior PR1 progress).                                                                                                          |

Changed lines this batch: README +4/-1 (5 changed) — well inside the 400-line review budget; no production code added (reconciliation only).

## Verification Summary (this batch)

- `cargo test --test discovery_cli` → 15 passed · `cargo test --all-features` → 97 passed (6 suites)
- `cargo fmt --all -- --check` → clean · `cargo clippy --all-targets --all-features -- -D warnings` → no issues
- `cargo deny check` → advisories/bans/licenses/sources ok · `cargo audit` → exit 0 (171 crate deps, 0 vulnerabilities)

## Status

**17/17 tasks complete.** No deviations from design; no new risks. Remaining: parent rebase + chained-PR delivery, then sdd-verify and archive (both currently blocked on apply in native status).
