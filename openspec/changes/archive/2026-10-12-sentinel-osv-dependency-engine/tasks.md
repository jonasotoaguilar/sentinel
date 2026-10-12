# Tasks: Sentinel OSV Dependency Engine

## Review Workload Forecast

Estimated lines: 1400–1800 authored (+goldens).
Split: PR1→PR2→PR3→PR4→PR5.
Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

Stacked-to-main; no size:exception. PR3/4 near 400. Delivery strategy: auto-chain.

| Unit | Goal                       | Likely PR | Focused test command                                       | Runtime harness                | Rollback boundary                                                                                   |
| ---- | -------------------------- | --------- | ---------------------------------------------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------- |
| 1    | Parse+identity             | PR 1      | `cargo test --lib engine::dependency`                      | N/A parse-only                 | `src/engine/dependency/*`, `src/engine/mod.rs`                                                      |
| 2    | XDG cache                  | PR 2      | `cargo test --lib cache`                                   | N/A tempfile                   | `src/cache.rs`; `Cargo.toml`+`Cargo.lock` `directories`                                             |
| 3    | OSV+validate+stub          | PR 3      | `cargo test --lib osv`                                     | N/A `StubOsv`                  | `src/osv/*`; `Cargo.toml`+`Cargo.lock` `ureq`                                                       |
| 4    | Engine+offline+`run_inner` | PR 4      | `cargo test --lib`                                         | `cargo test --test cli`        | `src/{cli,lib,finding}.rs`, `src/engine/dependency/mod.rs`                                          |
| 5    | Fixtures/goldens/ADR       | PR 5      | `cargo test --test dependency --test cli --test reporting` | `cargo test --test dependency` | fixtures+`tests/{dependency,cli,reporting}.rs`+ADR-0002; generated `tests/snapshots/*` not authored |

PR1 start=`main` no parsers end=`Pin` tests parent=none. PR2 start=no cache end=v1 get/put parent=PR1. PR3 start=no HTTP end=stub/validate parent=PR2. PR4 start=unwired end=degrade 0/1 parent=PR3. PR5 start=no fixtures end=JSON/SARIF×2+ADR parent=PR4.

## Prep

- [x] 0.1 Issue-first: create/approve scoped issue. No `gh` this phase.

## Phase 1: Parsers (PR 1)

- [x] 1.1 RED `src/engine/dependency/parse.rs`: unpinned/malformed skip path+line; reject `<script>`/`../`/`nan`; no raw leak (Unpinned or malformed skipped).
- [x] 1.2 GREEN lockfile v1–v3 exact `version`; `requirements.txt` `name==ver`→`Pin`; ignore other manifests; >10MiB=`skipped-large`.
- [x] 1.3 `Pin`+fingerprint `src/engine/dependency/map.rs`; `ENGINE_DEPENDENCY` in `src/engine/mod.rs`. Tests: Pinned npm/PyPI queried (`lodash@4.17.20`, `flask==2.3.3`).

## Phase 2: Cache (PR 2)

- [x] 2.1 Verify `directories = "6"` types (`ProjectDirs::from("", "", "sentinel")?.cache_dir()`). Add `Cargo.toml`+`Cargo.lock` (two files).
- [x] 2.2 RED `src/cache.rs`: corrupt/stale/wrong-schema miss+no rewrite; 26h miss online; traversal key rejected.
- [x] 2.3 GREEN `XdgCache`; frozen `now`; v1 `{eco}/{pct(name)}/{pct(ver)}.json`; temp+rename; `ProjectDirs` None→skip. Tests: Cache fresh, stale, corrupt.

## Phase 3: OSV (PR 3)

- [x] 3.1 Verify `ureq = "3"` types (`timeout_global(10s)`, `https_only(true)`). Add `Cargo.toml`+`Cargo.lock` (two files).
- [x] 3.2 RED `src/osv/validate.rs`: >1MiB miss; invalid IDs; `<script>`/`../`/`nan` rejected; no raw leak; withdrawn none; CVSS 9.8/7.5/5.0/2.1/missing→C/H/M/L/H.
- [x] 3.3 RED `src/osv/client.rs`: 4xx no retry; transient exhaustion ≤3 (`100ms·2^n`+jitter ≤1s); no 4th page; `NETWORK_BUDGET = 30s`.
- [x] 3.4 GREEN `OsvApi`+`StubOsv`+`UreqOsvClient`. Offline MUST NOT construct a Ureq agent. Tests: Pagination, detail, and retry.

## Phase 4: Wire (PR 4)

- [x] 4.1 RED: offline 0 HTTP / never construct `UreqOsvClient`; `--offline`/`--ci --offline` accepted (Accepted flags; Hermetic offline execution).
- [x] 4.2 `--offline` on `src/cli.rs` `Scan`; orthogonal to `--ci`. `src/finding.rs`: `version-unpinned-skipped`, `manifest-parse-failed`, `osv-degraded`, `osv-unavailable`, `cache-entry-corrupt`, `advisory-invalid`.
- [x] 4.3 `DependencyEngine::review` `src/engine/dependency/mod.rs`; `Transport::Offline` (no Agent/socket/DNS/TLS; no cache write).
- [x] 4.4 `src/lib.rs` `run_inner`: after secrets, `review`+merge+`dedupe_and_sort`; OSV/cache diagnostics (0/1). Tests: Offline and degrade; Dependency degrade does not exit 2.

## Phase 5: E2E (PR 5)

- [x] 5.1 Fixtures `tests/fixtures/dependency/*`.
- [x] 5.2 E2E `tests/dependency.rs`+`tests/{cli,reporting}.rs`: `--offline`/`--ci --offline`; JSON/SARIF twice (Byte-identical reports); Online I/O bounds; secrets still report.
- [x] 5.3 Confirm `docs/adr/0002-osv-cache-offline-policy.md` 24h TTL, no env knob.
