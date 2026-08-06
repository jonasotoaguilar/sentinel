# ADR-0002: OSV cache and offline policy

## Status
Proposed

## Date
2026-08-04

## Deciders
Jonathan Soto (architecture owner); PRD owner sign-off via review.

## Context
The dependency engine reviews declared dependencies against the OSV API v1 (`POST /v1/querybatch`, paginated, plus `GET /v1/vulns/{id}` detail fetches — pagination and detail-fetch behavior are documented research constraints in the PRD). The product requires: offline scans that "degrade gracefully" (warn/skip, never hard-fail), sub-minute scans even with a cold cache, no SQL/NoSQL (ADR-0001), deterministic results, and no phone-home beyond explicit queries. OSV advisory data is external and must be treated as untrusted (validated before use). Without caching, every scan re-fetches; without a TTL, offline scans serve unboundedly stale data; without corruption tolerance, one bad write breaks all future scans.

## Decision
Cache OSV querybatch results and advisory details in a filesystem cache under the XDG cache directory (via the `directories` crate: `$XDG_CACHE_HOME`, `~/Library/Caches`, `%LOCALAPPDATA%`), in a **schema-versioned subdirectory** (cache format changes invalidate the whole subtree cleanly), keyed by canonical `(ecosystem, package, version)` triples, stored as JSON with **atomic writes** (temp file + rename). Default TTL: **24 hours** in online mode; **offline mode ignores the TTL** and serves whatever the cache holds. Online refresh policy: read-through on TTL expiry; on network failure serve stale entries with a warning, or warn-and-skip dependency findings when no entry exists — the scan never fails on advisory unavailability. All cached content is validated against the adapter's expected response shape at the trust boundary before it is used or re-stored; corrupt entries are treated as cache misses (warn + refetch). No locks in the MVP: atomic rename gives last-writer-wins, and duplicate refreshes from concurrent scans are harmless. The cache never contains secret material — only advisory JSON.

## Consequences

### Positive
- Offline mode works by construction: cache is the only dependency.
- Warm-cache scans are near-instant on the network phase; cold-cache scans stay within the 30 s network budget via batched queries.
- No database, per ADR-0001: a versioned directory of JSON files is all the persistent state the product has.
- Corruption is self-healing (miss → refetch), and TTL bounds staleness to a declared window.

### Negative
- Staleness window up to 24 h in online mode: an advisory fixed minutes ago can still be served until TTL expiry.
- Cache poisoning surface: if the OSV API or a MITM delivered malformed data, it could be cached — mitigated by validation at the boundary and HTTPS-only transport.
- No shared warm cache across machines: every new checkout starts cold (one-time cost, bounded by batching).

### Neutral
- Users can delete the cache at any time; the next scan refetches. No cache-repair tooling needed.

## Options Considered

### Option A: XDG filesystem cache + TTL + offline degrade (chosen)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low — files + atomic rename |
| Cost | Disk footprint of advisory JSON only |
| Scalability | Single process, single directory |
| Team familiarity | High — no new technology |
| Ecosystem / Tooling | `directories` crate only |
| Operational overhead | None (user-deletable) |

**Pros:**
- Satisfies offline product rule, staleness bound, no-DB constraint, and sub-minute NFR with one mechanism.

**Cons:**
- Staleness window; per-machine cold starts.

### Option B: No cache (online-only)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Lowest |
| Cost | Network per scan |
| Scalability | N/A |
| Team familiarity | High |
| Ecosystem / Tooling | None |
| Operational overhead | None |

**Pros:**
- Always-fresh data; simplest possible client.

**Cons:**
- Violates the offline product rule outright; every scan pays network latency and rate-limit risk; CI with blocked egress loses the dependency engine entirely.

### Option C: Full local advisory database (SQLite)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium-High — schema, migrations, queries |
| Cost | DB runtime + sync logic |
| Scalability | Overkill for the data volume |
| Team familiarity | Medium |
| Ecosystem / Tooling | SQLite or sled/redb |
| Operational overhead | Schema evolution, corruption handling |

**Pros:**
- Rich queries, incremental sync, durable indexing.

**Cons:**
- Conflicts with the no-DB non-goal (ADR-0001), and the full OSV dataset is far larger than the MVP's per-scan needs — a query-time cache is the right granularity.

### Option D: Infinite cache (no TTL)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low |
| Cost | None |
| Scalability | N/A |
| Team familiarity | High |
| Ecosystem / Tooling | None |
| Operational overhead | Stale data forever |

**Pros:**
- Maximal offline coverage.

**Cons:**
- Unbounded staleness degrades the product's core promise (correct vulnerable-dependency detection) — unacceptable without a freshness mechanism.

## Trade-off Analysis
The product rule "offline serves from cache and warns/skips gracefully" forces a cache; the no-DB non-goal forces a filesystem shape; the correctness promise forces a staleness bound. Option A is the only option satisfying all three, and its costs (staleness window, cold starts) are bounded and user-visible. The validation-at-the-boundary rule and HTTPS-only transport address the poisoning risk of C's richer model at a fraction of the complexity.

## Action Items
1. [ ] Confirm the 24 h TTL default during implementation planning (configurable knob if product wants it).

## References
- PRD §3 (OSV API v1 in scope), §4 (offline product rule), §6 (pagination/detail-fetch research constraint)
- ARCHITECTURE.md — XDG Advisory Cache, OSV API v1 Client, Data Architecture, Failure Modes
- design-architecture references: architecture-patterns.md (caching decisions: source of truth, staleness, stampede, failure behavior), resilience-patterns.md (dependency failure budget)
