# ADR-0001: Single synchronous process, no database

## Status
Proposed

## Date
2026-08-04

## Deciders
Jonathan Soto (architecture owner); PRD owner sign-off via review.

## Context
Sentinel is a pre-commit and CI security scanner: a short-lived CLI that scans a Git repository, reports findings, and exits. The PRD fixes the runtime shape as "cross-platform, single-crate Rust (Edition 2024); sync/stdio architecture; no Tokio; no SQL/NoSQL" and lists no server, daemon, or background mode as explicit non-goals. The product needs deterministic, reproducible scans (KPI 2), sub-minute scans (KPI 1), local-first operation with offline capability, and trivially distributable tooling for developers and CI pipelines. The only state that must survive a run is advisory data for offline scans — everything else is ephemeral.

## Decision
Ship one binary crate as a modular monolith with an in-process, synchronous pipeline: CLI → git-aware discovery (`std::process::Command`) → parallel detector engines (Rayon, CPU-bound only) → normalize/fingerprint/dedupe → renderers. No daemon, no server, no database of any kind (SQL/NoSQL); the only persistent state is a TTL'd filesystem cache of OSV advisory data under the XDG cache directory. No Tokio in the MVP — I/O is sequential and batched; CPU parallelism is Rayon's job. Module boundaries inside the crate are enforced by convention and by tests against public interfaces, not by crate seams.

## Consequences

### Positive
- Single artifact to build, sign, and distribute; trivial installation for pre-commit hooks and CI images.
- Determinism is structurally easy: one process, no shared state, output order fixed after normalization.
- Cross-platform portability without service managers, runtimes, or database drivers.
- No operational surface: nothing to host, patch, or monitor; no data to back up.
- Offline behavior falls out of the cache design, not a separate sync mechanism.

### Negative
- No cross-run state beyond the advisory cache: future features that need history (e.g., baseline/regression reporting) must add storage deliberately.
- I/O concurrency is limited (sequential HTTP, batched); mitigated by request batching and caching — the scan budget is CPU-bound detection, not network.
- Extracting a module into a separate service later requires real rework; mitigated by keeping module boundaries honest now.

### Neutral
- Rayon is the only concurrency mechanism — threads inside one process, no IPC.
- The team (or future contributors) must respect module boundaries by discipline; no tooling enforces them in the MVP.

## Options Considered

### Option A: Single synchronous process, modular monolith (chosen)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low |
| Cost | Lowest — one artifact, no infra |
| Scalability | None needed (single-invocation CLI) |
| Team familiarity | Low barrier — plain Rust |
| Ecosystem / Tooling | Clap, Rayon, ureq, ignore — all crate-level |
| Operational overhead | Zero |

**Pros:**
- Matches the product lifecycle exactly (one scan, then exit).
- Deterministic output is the default, not an achievement.

**Cons:**
- Future cross-run state and module extraction require deliberate work.

### Option B: Client + daemon with local database
| Dimension | Assessment |
|-----------|------------|
| Complexity | High — process supervision, DB schema, upgrade paths |
| Cost | Medium — installer/updater, DB runtime |
| Scalability | Irrelevant for the workload |
| Team familiarity | Low — operational concerns for a CLI product |
| Ecosystem / Tooling | SQLite or similar, service management per-OS |
| Operational overhead | High — daemon lifecycle, crash recovery, cache invalidation |

**Pros:**
- Persistent cross-run state (baselines, caches) becomes natural.

**Cons:**
- Violates three PRD non-goals (no server, no DB, no daemon/watch) and adds failure modes at 3 AM (stale daemon, locked DB, zombie processes) for zero product value in the MVP.

### Option C: Async runtime pipeline (Tokio)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium — runtime, tasks, cancellation |
| Cost | Same artifacts, more code |
| Scalability | Overkill — no sustained I/O concurrency need |
| Team familiarity | Medium |
| Ecosystem / Tooling | Tokio + hyper/reqwest |
| Operational overhead | Low |

**Pros:**
- Concurrent HTTP could shave network-phase latency.

**Cons:**
- The only real parallelism need is CPU-bound detection (Rayon); batched OSV queries and the cache already bound the network phase under the 30 s budget. Tokio adds a runtime and async hygiene burden with no NFR it satisfies.

## Trade-off Analysis
The deciding force is lifecycle: the product runs once, prints, and exits. Everything a daemon or database would provide (persistent state, reuse, background scanning) is either explicitly out of scope or served by the small advisory cache. Option A wins on every axis that matters — determinism, distribution, offline behavior, and MVP speed — while B and C add complexity that only pays off for workloads this product does not have. The retained risk (future stateful features, module extraction) is deferred by design and mitigated by clean boundaries, which the module-design rules already require for testability.

## Action Items
1. [ ] Confirm the exit-code contract values (0/1/2) against product rules during implementation planning.

## References
- PRD §3 MVP Scope (in scope / non-goals), §5 Acceptance Criteria
- ARCHITECTURE.md — Architecture Pattern, Key Decisions
- design-architecture references: architecture-patterns.md (modular monolith guardrails), module-design.md (boundaries)
