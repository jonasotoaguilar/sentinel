# Proposal: Sentinel OSV Dependency Engine

## Intent

PRD §3/§5: secrets-only scans miss known-vulnerable pinned npm/PyPI packages. Add a `dependency` engine with deterministic findings through existing terminal/JSON/SARIF; keep exit 0/1/2.

## Scope

### In Scope

- npm `package-lock.json` exact versions; PyPI `requirements.txt` `==` pins; unpinned/range/marker: diagnostic + skip.
- OSV v1 `POST /v1/querybatch` (≤1000) + bounded per-query `nextPageToken` and `GET /v1/vulns/{id}`; validate at the untrusted boundary.
- Schema-versioned XDG cache; 24h online TTL; `--offline` ignores TTL, zero HTTP; corruption = miss; atomic writes; advisory JSON only.
- `engine="dependency"`, `ruleId="OSV-<id>"`.
- `--offline` orthogonal to `--ci`; warn+stale or warn+skip; never exit 2.
- Sync `ureq`; no Tokio/DB/LLM (ADR-0001/0002/0003).

### Out of Scope

- `pyproject.toml`, `poetry.lock`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `Cargo.lock`, `go.mod`.
- Range/transitive resolution, fix advice, `--fail-on`, ETag/quota, TTL env, `clap_complete`.

## Capabilities

> Contract for `sdd-spec`.

### New Capabilities

- `dependency-review`: npm lockfile + PyPI `==` parse, OSV batch/detail, XDG cache, dependency findings, degrade/offline.

### Modified Capabilities

- `cli-scan`: Allow OSV HTTP + XDG cache except `--offline` (zero HTTP); keep 0/1/2; degrade never exit 2.

## Approach

Exploration Approach 1: one engine; `OsvApi` (`UreqOsvClient` + stub); `XdgCache` `v1`; ecosystems `npm`/`PyPI`; missing severity → `High`; `BTreeMap` then `dedupe_and_sort`; boundary validation; `Result`, no production `unwrap`.

## Affected Areas

| Area                                                                                  | Impact       | Description                           |
| ------------------------------------------------------------------------------------- | ------------ | ------------------------------------- |
| `Cargo.toml`                                                                          | Modified     | Add `ureq`, `directories`             |
| `src/cli.rs`                                                                          | Modified     | `--offline`                           |
| `src/engine/dependency/`, `src/osv/`, `src/cache/`                                    | New          | Engine, adapter, cache                |
| `src/finding.rs`, `src/normalize.rs`, `src/lib.rs`, `src/discovery.rs`, `src/render/` | Modified     | Wiring, tracked files, goldens        |
| `openspec/specs/dependency-review`, `cli-scan`                                        | New/Modified | Full spec + network/cache/`--offline` |
| `docs/adr/0002-osv-cache-offline-policy.md`                                           | Modified     | Confirm 24h TTL                       |

## Risks

| Risk                     | Likelihood | Mitigation                            |
| ------------------------ | ---------- | ------------------------------------- |
| Ecosystem sprawl         | High       | First slice only                      |
| OSV drift / cache poison | Med        | Validate at boundary; miss on corrupt |
| 24h staleness            | Med        | Warn+stale; ignore TTL offline only   |
| Degrade vs exit 2        | Med        | Never operational 2                   |
| >400-line PRs            | High       | auto-chain                            |

## Rollback Plan

Revert the PR chain. Flag and crates are additive. Delete unused `$XDG_CACHE_HOME/sentinel/osv/`; no migration. Secrets scan and 0/1/2 remain.

## Dependencies

OSV API v1; `ureq`, `directories`; ADR-0001/0002/0003; existing pipeline.

## Success Criteria

- [ ] Pinned npm/PyPI fixtures emit deterministic `dependency` findings (PRD §5).
- [ ] Unpinned: diagnostic, skipped, not queried.
- [ ] Online: batch+detail, 24h TTL, atomic writes.
- [ ] `--offline`: zero HTTP, ignore TTL, hits used, miss warn+skip.
- [ ] Degrade never exit 2; secrets/JSON/SARIF and 0/1/2 unchanged.
- [ ] No Tokio, database, or LLM.
