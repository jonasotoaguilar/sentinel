```yaml
schema: gentle-ai.verify-result/v1
evidence_revision: sha256:696fc898d0c287ee5a59e0a6af89929541e2392ce46e38066af60080da75f885
verdict: pass_with_warnings
blockers: 0
critical_findings: 0
requirements: 9/9
scenarios: 19/19
test_command: cargo test --all-features
test_exit_code: 0
test_output_hash: sha256:e71ad7d1f286339f74a202762a95c16e177b4f9915aa394ea794126fa61d41bc
build_command: cargo build --all-features
build_exit_code: 0
build_output_hash: sha256:736e2582f563605dd272e5fb977840b0c0767377d27b6940c440caf75eec7157
```

## Verification Report

**Change**: sentinel-discovery-hardening
**Version**: N/A
**Mode**: Standard (Strict TDD inactive; `openspec/config.yaml` `testing.strict_tdd: false`)
**Review delivery**: structurally absent (`reviewGate` not present); ordinary policy, no receipt required
**Runtime authority**: parent-owned attempt `sha256:1940619a299b4f1fe84443d0ab97fd8a1a0169e96de7202bbb7d9bfbbf285ba8`; work unit `final-hardening-verification`; this actor did not acquire or settle
**Artifact store**: openspec
**Workspace**: `/home/jona/projects/sentinel-worktrees/sentinel-sarif-output` (`feat/sentinel-sarif-output`)

### Completeness

| Metric                       | Value                                                                |
| ---------------------------- | -------------------------------------------------------------------- |
| Tasks total                  | 17                                                                   |
| Tasks complete               | 17                                                                   |
| Tasks incomplete             | 0                                                                    |
| Requirements total           | 9 (counted from retrieved delta specs: 7 git-discovery + 2 cli-scan) |
| Requirements complete        | 9                                                                    |
| Scenarios total              | 19 (12 git-discovery + 7 cli-scan)                                   |
| Scenarios evaluated          | 19                                                                   |
| Scenarios fully compliant    | 18                                                                   |
| Scenarios partial            | 1                                                                    |
| Scenarios failing / untested | 0 / 0                                                                |

All 17 task markers (`1.1`–`5.1`) are checked in `tasks.md`. Native status reports `taskProgress.completed: 17`, `allComplete: true`, `dependencies.verify: ready`. Proposal, both delta specs, design, tasks, and apply-progress were read before judging. `state.yaml` still records the stale apply-slice snapshot (`completed: 1.1–3.2`, `pending: 4.1–5.1`); it is not task truth and is not repeated as 11/17 here.

### Build & Tests Execution

**Build**: ✅ Passed

```text
cargo build --all-features
exit 0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.03s
build_output_hash: sha256:736e2582f563605dd272e5fb977840b0c0767377d27b6940c440caf75eec7157 (72 bytes)
```

**Tests**: ✅ 97 passed / 0 failed / 0 ignored

```text
cargo test --all-features
exit 0
lib unit (src/lib.rs): 53 passed
bin unit (src/main.rs): 0 tests
tests/cli.rs: 23 passed
tests/discovery_cli.rs: 15 passed
tests/reporting.rs: 6 passed
doc-tests: 0
test_output_hash: sha256:e71ad7d1f286339f74a202762a95c16e177b4f9915aa394ea794126fa61d41bc (7772 bytes)
```

**Coverage**: ➖ Not available — `cargo llvm-cov` is not installed; configured threshold is 0; no coverage claim made.

| Check             | Command                                                    | Exit | Result                                                                                                              |
| ----------------- | ---------------------------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------- |
| Format            | `cargo fmt --all -- --check`                               | 0    | ✅ PASS — empty output `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`                    |
| Lint              | `cargo clippy --all-targets --all-features -- -D warnings` | 0    | ✅ PASS — `sha256:8c233a54790c4800d3dd585436af679aa838da259bfdb129412e2d51cdb75cdc`                                 |
| Dependency policy | `cargo deny check`                                         | 0    | ✅ PASS — advisories/bans/licenses/sources ok; unused ISC/Zlib allowances and duplicate `syn` 2.x/3.x warnings only |
| Dependency audit  | `cargo audit`                                              | 0    | ✅ PASS — 171 crate dependencies, 0 vulnerabilities                                                                 |
| Mutation          | `cargo mutants --version`                                  | 101  | ⚠️ UNAVAILABLE — `cargo-mutants` not installed; no install attempted                                                |

### Spec Compliance Matrix

| Requirement                                           | Scenario                             | Test                                                                                                                                                                                                                                   | Result       |
| ----------------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| git-discovery / Untracked-file discovery              | Untracked and hidden files scanned   | `src/discovery.rs > untracked_hidden_env_files_are_scanned_in_both_modes`                                                                                                                                                              | ✅ COMPLIANT |
| git-discovery / Untracked-file discovery              | Ignored untracked files excluded     | `src/discovery.rs > gitignored_untracked_files_and_directories_are_excluded`; `tests/discovery_cli.rs > gitignored_untracked_files_and_directories_are_excluded`                                                                       | ✅ COMPLIANT |
| git-discovery / Ignore precedence and .sentinelignore | Tracked-ignored files retained       | `src/discovery.rs > force_added_tracked_file_is_retained_despite_gitignore`; `tests/discovery_cli.rs > force_added_tracked_file_is_retained_despite_gitignore`                                                                         | ✅ COMPLIANT |
| git-discovery / Ignore precedence and .sentinelignore | Sentinelignore excludes both classes | `src/discovery.rs > sentinelignore_excludes_tracked_and_untracked_entries`; `tests/discovery_cli.rs > sentinelignore_excludes_tracked_and_untracked_files`                                                                             | ✅ COMPLIANT |
| git-discovery / Ignore precedence and .sentinelignore | Full-file scope                      | `src/discovery.rs > sentinelignore_directory_pattern_excludes_whole_subtree`; `tests/discovery_cli.rs > sentinelignore_directory_pattern_excludes_whole_subtree`                                                                       | ✅ COMPLIANT |
| git-discovery / Nested repositories and symlinks      | Nested repository excluded           | `src/discovery.rs > nested_git_repository_is_skipped`; `tests/discovery_cli.rs > nested_git_repository_is_skipped`                                                                                                                     | ✅ COMPLIANT |
| git-discovery / Nested repositories and symlinks      | Symlink target not traversed         | `src/discovery.rs > symlink_outside_repo_is_not_followed`; `tests/discovery_cli.rs > symlink_outside_repo_is_not_followed`                                                                                                             | ✅ COMPLIANT |
| git-discovery / Size guard                            | Oversized file skipped               | `src/discovery.rs > oversized_files_are_skipped_with_a_diagnostic`; `tests/discovery_cli.rs > oversized_untracked_file_is_skipped_without_changing_exit`; `tests/discovery_cli.rs > oversized_untracked_file_on_clean_repo_exits_zero` | ✅ COMPLIANT |
| git-discovery / Invalid path handling                 | Invalid path excluded                | `src/discovery.rs > invalid_records_warn_and_are_excluded`                                                                                                                                                                             | ✅ COMPLIANT |
| git-discovery / Unreadable file handling              | Unreadable file warned               | `tests/discovery_cli.rs > unreadable_untracked_file_warns_and_scan_continues`; `tests/cli.rs > unreadable_tracked_file_warns_on_stderr_and_scan_continues`                                                                             | ✅ COMPLIANT |
| git-discovery / Determinism of the file set           | Repeated discovery                   | `src/discovery.rs > repeated_discovery_is_byte_identical_with_diagnostics`; `tests/discovery_cli.rs > repeated_and_concurrent_runs_are_byte_identical`                                                                                 | ✅ COMPLIANT |
| git-discovery / Determinism of the file set           | Parallel discovery                   | `src/discovery.rs > parallel_discovery_is_byte_identical`; `tests/discovery_cli.rs > repeated_and_concurrent_runs_are_byte_identical`                                                                                                  | ✅ COMPLIANT |
| cli-scan / Hermetic CI mode                           | Ambient ignores disabled under CI    | `tests/discovery_cli.rs > ci_mode_scans_files_omitted_by_ambient_global_ignore` (`--ci` branch)                                                                                                                                        | ✅ COMPLIANT |
| cli-scan / Hermetic CI mode                           | Local mode stays git-natural         | `tests/discovery_cli.rs > ci_mode_scans_files_omitted_by_ambient_global_ignore` (local branch)                                                                                                                                         | ✅ COMPLIANT |
| cli-scan / Hermetic CI mode                           | Exit codes unchanged under CI        | `tests/discovery_cli.rs > local_and_ci_produce_identical_findings_and_exit_without_ambient_ignores`                                                                                                                                    | ✅ COMPLIANT |
| cli-scan / Command surface                            | Minimal invocation                   | `src/cli.rs > scan_subcommand_is_accepted`; `tests/cli.rs > clean_repo_exits_zero_with_empty_stdout_and_stderr`                                                                                                                        | ✅ COMPLIANT |
| cli-scan / Command surface                            | CI flag accepted                     | `src/cli.rs > ci_flag_parses_to_scan_with_ci_true`; `tests/cli.rs > ci_flag_is_accepted_and_scans_the_repository`                                                                                                                      | ✅ COMPLIANT |
| cli-scan / Command surface                            | Unsupported argument rejected        | `src/cli.rs > unsupported_arguments_are_usage_errors`; `tests/cli.rs > unsupported_arguments_and_missing_subcommand_write_stderr_only_and_exit_2`                                                                                      | ⚠️ PARTIAL   |
| cli-scan / Command surface                            | Missing subcommand                   | `src/cli.rs > missing_subcommand_is_a_usage_error`; `tests/cli.rs > unsupported_arguments_and_missing_subcommand_write_stderr_only_and_exit_2`                                                                                         | ✅ COMPLIANT |

**Compliance summary**: 18/19 scenarios fully compliant; 1/19 partial (`Unsupported argument rejected`). `--explain` and positional arguments still fail as usage errors with empty stdout and exit 2. The scenario's `--output json` example is accepted in this worktree because later change `sentinel-next-capability` added `--output`/`--report`. That is a later authorized delta, not a missing hardening test.

### Correctness (Static Evidence)

| Requirement                           | Status                          | Notes                                                                                                                  |
| ------------------------------------- | ------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Untracked-file discovery              | ✅ Implemented                  | Hybrid `git ls-files -z` + `ignore` walker; `hidden(false)`, `follow_links(false)`, `require_git(true)`; `.git` pruned |
| Ignore precedence and .sentinelignore | ✅ Implemented                  | Tracked-wins union; `.sentinelignore` post-filters the full union via `sentinel_matcher`                               |
| Nested repositories and symlinks      | ✅ Implemented                  | `filter_entry` skips nested `.git`; `symlink_metadata().is_file()` never follows links                                 |
| Size guard                            | ✅ Implemented                  | `MAX_SCAN_FILE_BYTES = 10 * 1024 * 1024`; `skipped-large` diagnostic; findings still own exit 0/1                      |
| Invalid path handling                 | ✅ Implemented                  | `is_safe_relative` rejects absolute/`..` records with `invalid-path`; scan continues                                   |
| Unreadable file handling              | ✅ Implemented                  | Engine read failure emits `read-failed` and continues; covering tests passed as uid 1000 (not root)                    |
| Determinism of the file set           | ✅ Implemented                  | `BTreeSet` union, sorted diagnostics, serial walker; repeated and concurrent tests passed                              |
| Hermetic CI mode                      | ✅ Implemented                  | `Mode::Ci` sets `parents(false)`, `git_global(false)`, `git_exclude(false)`; local keeps git-natural defaults          |
| Command surface                       | ✅ Implemented (later extended) | `--ci` parsed and mapped to `Mode`; later stacked change also accepts `--output`/`--report`                            |

### Coherence (Design)

| Decision                                | Followed?         | Notes                                                                                       |
| --------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------- |
| Hybrid ls-files + ignore walker         | ✅ Yes            | Tracked authority plus untracked walker; tracked membership wins over Git ignores           |
| Local git-natural / Ci hermetic         | ✅ Yes            | Ci disables parent/global/exclude; both set hidden/follow_links/require_git/.sentinelignore |
| Serial walker then deterministic sort   | ✅ Yes            | `builder.build()` serial walk; files collected via `BTreeSet`; diagnostics sorted/deduped   |
| 10 MiB diagnostic size guard            | ✅ Yes            | Post-union metadata guard; does not change exit status                                      |
| `hidden(false)` mandatory               | ✅ Yes            | Walker config and hidden `.env` tests in both modes                                         |
| `Scan { ci: bool }` accepts only `--ci` | ⚠️ Later extended | Current `src/cli.rs` also has `--output` and `--report` from `sentinel-next-capability`     |
| Merge discovery diagnostics in `lib.rs` | ✅ Yes            | `run_inner` extends engine diagnostics with `discovered.diagnostics` before render          |

### Mutation Testing Evidence

```json
{
  "schema": "gentle-ai.mutation-evidence/v1",
  "change_name": "sentinel-discovery-hardening",
  "campaign_id": "cam-20260818T230300Z-2cba60f2",
  "campaign_type": "full",
  "generated_at": "2026-08-18T23:03:00Z",
  "candidate_fingerprint": "sha256:9d24c09c37d7f811c07df32370723d64946f66ac2416a282cd81c4db865f9dda",
  "candidate_binding_strength": "strong",
  "scope_fingerprint": "sha256:83287a733d0cb13e99b4c69eb600089943ee6910bbef2e241e6822762f12b938",
  "baseline_suite_hash": "sha256:e71ad7d1f286339f74a202762a95c16e177b4f9915aa394ea794126fa61d41bc",
  "baseline_hash_kind": "opaque",
  "tool": { "name": "cargo-mutants", "version": "unavailable" },
  "config_fingerprint": "sha256:7695f979d80efc61f4746d7004afe09c468b2996e15699c4e908930f7d29cf6d",
  "repro": {
    "cwd": ".",
    "command": "cargo mutants --version",
    "seed": null,
    "timeout_seconds": 30
  },
  "counts": {
    "total": 0,
    "killed": 0,
    "survived": 0,
    "timeout": 0,
    "error": 0
  },
  "counts_source": "executed",
  "survivors": [],
  "selected_mutant_ids": [],
  "incremental_eligible": false,
  "prior_evidence_revision": null,
  "cache_manifest": [],
  "invalidation_reasons": [],
  "status": "unavailable",
  "error": "error: no such command: `mutants`\n\nhelp: view all installed commands with `cargo --list`\nhelp: find a package to install `mutants` with `cargo search cargo-mutants`\n"
}
```

Framework decision: prior verify-report was not delivered, so the reuse matrix selected a full campaign. `cargo-mutants` is not installed and was not installed. Typed `unavailable`; this evidence is not a phase PASS.

### Issues Found

**CRITICAL**: None

**WARNING**:

1. Command-surface scenario `Unsupported argument rejected` is PARTIAL in this worktree: `--explain` and positionals still fail, but `--output json` is now a supported flag from later change `sentinel-next-capability`.
2. `openspec/changes/sentinel-discovery-hardening/state.yaml` is stale (11/17 snapshot from 2026-08-05). Task truth is `tasks.md` 17/17 and native status 17/17.
3. Mutation testing is typed `unavailable` (`cargo-mutants` missing). Evidence only; not treated as a spec failure.
4. Coverage tool `cargo llvm-cov` is unavailable; threshold is 0 so this does not fail the gate.

**SUGGESTION**:

1. Proposal success-criteria checkboxes remain unchecked; they are not implementation tasks and were not used as completeness truth.

### Verdict

PASS WITH WARNINGS

Seventeen completed tasks, nine requirements, and nineteen scenarios are evidenced by this run: 97 tests passed, build/fmt/clippy/deny/audit are green, and the one partial scenario is the later stacked CLI-surface extension rather than a missing hardening implementation.
