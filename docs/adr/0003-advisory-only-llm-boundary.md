# ADR-0003: Advisory-only LLM boundary

## Status
Proposed

## Date
2026-08-04

## Deciders
Jonathan Soto (architecture owner); PRD owner sign-off via review.

## Context
The PRD makes three unconditional product rules about the optional `--explain` LLM feature: (1) output is **advisory only** — it never sets severity, blocking, or pass/fail decisions, in any mode; (2) secret values are **redacted before they enter LLM context**, with context limited to the minimum necessary; (3) `--explain` is **disabled by default** and never invoked in CI mode or offline mode. LLM responses are external content and must be treated as **untrusted**. The acceptance criteria make this testable: severity and blocking outcomes with `--explain` are byte-identical to the same scan without it, and secret values never appear in LLM context payloads. The failure mode this guards against is the industry pattern where an LLM gets to decide outcome — which the product explicitly rejects.

## Decision
The explainer is an **isolated module** behind an `Explainer` interface with two real adapters (production HTTP via ureq; a stub server in tests). Its boundaries are enforced by construction, not by policy:

- **Redaction by construction**: the detector engines redact secret values at the engine boundary, so raw values are structurally unreachable by any downstream component — including the explainer. LLM context is built exclusively from the redacted `Finding` model (message, rule ID, redacted evidence, path) within a fixed context budget (per-finding and per-scan character caps).
- **Advisory-only data flow**: the explainer consumes findings and returns display-only text. Severity, blocking policy, and exit code are immutable after normalization; there is no code path — successful or failed — from explainer output into those structures.
- **Untrusted response handling**: responses are length-capped, stripped of control characters, and never parsed into structured fields. Sanitization happens at the trust boundary (the adapter), not downstream.
- **Failure behavior**: one synchronous attempt per finding, no retries, bounded timeout; any failure (network, timeout, configuration) emits a warning and the scan continues with output identical to a non-explain run.
- **Defaults**: opt-in only (`--explain`); forced off in CI mode and offline mode; no telemetry of prompts or responses.

## Consequences

### Positive
- The PRD hard rule is testable and structurally enforced: differential tests (with/without `--explain`) assert byte-identical findings, severity, and exit codes.
- Redaction happens once, at the engine boundary, protecting every downstream consumer (renderers, logs, cache, explainer) — not just the LLM path.
- Explainer failure can never block a scan or distort results: worst case is a missing advisory paragraph.
- Untrusted content cannot reach analysis or output structures.

### Negative
- Per-finding synchronous calls cost latency when enabled — bounded by the context/attempt policy, and paid only by users who opt in.
- A fourth-party (LLM provider) sees redacted finding summaries when enabled — a privacy consideration the user accepts explicitly by opting in; no secrets leave the machine regardless.

### Neutral
- The interface seam (HTTP + stub) follows the two-real-adapters rule, giving the test surface without speculative abstraction.
- Future richer explanation modes (PRD staged work) must respect the same boundary — the ADR is the standing contract.

## Options Considered

### Option A: Isolated adapter, redacted context, advisory-only output (chosen)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low-Medium — one module, one seam |
| Cost | Only when opted in (calls, latency) |
| Scalability | N/A (per-invocation) |
| Team familiarity | High |
| Ecosystem / Tooling | ureq (already in stack) |
| Operational overhead | None — failure is a warning |

**Pros:**
- Satisfies every PRD product rule with testable, structural guarantees.

**Cons:**
- Feature surface exists only for advisory value; latency when enabled.

### Option B: LLM-in-the-loop severity/blocking
| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium — severity arbitration logic |
| Cost | Unbounded latency; provider cost on every scan |
| Scalability | N/A |
| Team familiarity | High |
| Ecosystem / Tooling | Same stack |
| Operational overhead | High — provider availability becomes a correctness dependency |

**Pros:**
- Potentially "smarter" triage.

**Cons:**
- Directly violates the PRD's central non-goal ("`--explain` influencing severity, blocking, or pass/fail decisions — ever"); makes CI outcomes depend on a third-party model's availability and judgment; unreviewable and non-deterministic. Rejected on product grounds, not technical ones.

### Option C: No explainer in the MVP
| Dimension | Assessment |
|-----------|------------|
| Complexity | Lowest |
| Cost | None |
| Scalability | N/A |
| Team familiarity | High |
| Ecosystem / Tooling | None |
| Operational overhead | None |

**Pros:**
- Smallest surface; zero privacy questions.

**Cons:**
- The PRD lists `--explain` in MVP scope with explicit acceptance criteria — dropping it is a product decision outside the architecture's authority.

## Trade-off Analysis
The product's differentiator is trust: deterministic, auditable, local-first scanning, and an explainer that "adds context without ever dictating severity." Option A makes that contract structural — the data flow literally cannot feed decision structures — which is strictly stronger than a runtime policy check. B maximizes model utility at the cost of the product's core promise and deterministic CI, and is rejected by the PRD itself; C ignores the PRD's stated scope. A's costs (latency when opted in, provider visibility of redacted summaries) are opt-in and bounded.

## Action Items
1. [ ] Confirm the context-budget caps (per-finding and per-scan) and endpoint configuration surface during implementation planning.

## References
- PRD §1 (KPI 3), §3 (in scope / non-goal), §4 (product rules), §5 (acceptance criteria), §7 (risk register)
- ARCHITECTURE.md — Explain Adapter, Key Decisions, Failure Modes
- design-architecture references: module-design.md (seam rule), nfr-checklist.md (trust boundaries), api-design.md (validate at trust boundaries)
