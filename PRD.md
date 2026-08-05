# PRD: Sentinel — Pre-commit & CI Security Scanner

Sentinel is a planned cross-platform Rust CLI that scans Git repositories for secrets and vulnerable dependencies before commit or in CI. It gives developers and pipelines a deterministic, reviewable security check with no server, no database, and no mandatory third-party calls — and an opt-in LLM explainer that can add context without ever dictating severity.

> **Status: MVP specification (bootstrap).** No implementation exists yet. This document is the product source of truth for the MVP and the staging ground for later phases; nothing here is shipped functionality.

## Quick Path

1. Confirm the problem and target situations.
2. Review MVP scope and explicit non-goals.
3. Verify product rules (especially `--explain` constraints and offline behavior).
4. Review acceptance criteria before implementation planning.

## Details

| Topic | Decision |
|-------|----------|
| Primary user | Developers and CI pipeline owners who want security review before code lands |
| Problem | Secrets and vulnerable dependencies ship because pre-commit/CI checks are heavy, noisy, or centralized |
| Outcome | A fast, deterministic, local-first CLI that surfaces secrets and vulnerable dependencies with reviewable output |
| Success measure | Correct findings, zero `--explain` influence on severity/blocking, sub-minute scans on typical repos |

## 1. Executive Summary

- **Problem Statement**: Secrets and vulnerable dependencies frequently reach commits because existing checks are centralized (server/daemon), noisy, or lack deterministic rules — and when LLM assistance is added, it often gets to decide outcomes.
- **Proposed Solution**: A single-crate Rust CLI (`sentinel scan`) that scans a repository in memory using git-aware discovery, parallel detector engines (secrets, OSV dependency review, regex/Tree-sitter rules for JS/TS and Python), stable fingerprinting/deduplication, and terminal/JSON/SARIF 2.1.0 output. Optional `--explain` adds LLM context over HTTP with strict guardrails.
- **Success Criteria**:
  - KPI 1: Scan completes in under a minute on a typical repository (tens of thousands of files) on a mid-range machine.
  - KPI 2: Findings are deterministic and deduplicated via stable fingerprints; identical scans produce identical results.
  - KPI 3: `--explain` never changes severity or blocking outcomes in any configuration.
  - KPI 4: Secret values never appear in outputs or in LLM context (redaction enforced at the engine boundary).

## 2. User Experience & Functionality

### Target Users & Situations

- **Pre-commit developer**: wants a fast local scan before pushing; offline-capable; suspicious of anything that phones home.
- **CI pipeline owner**: wants machine-readable output (SARIF) merged into existing dashboards, hermetic/reproducible scans, and no surprise network policy violations.
- **Security-conscious reviewer**: wants deterministic rules and stable fingerprints so findings are reproducible and attributable.

### User Stories

- As a **developer**, I want to scan my repository locally without a server, so that I can find secrets and vulnerable dependencies before committing.
- As a **CI pipeline owner**, I want SARIF 2.1.0 output, so that findings land in my existing review workflow.
- As a **developer**, I want to run in offline mode, so that scans work without network access and degrade gracefully.
- As a **developer**, I want `--explain` to add context to findings, so that I understand them — while being certain it can never set severity or block my CI.
- As a **developer**, I want deterministic rules for JavaScript/TypeScript and Python, so that results are reproducible and auditable.

## 3. MVP Scope

### In Scope

- Git-aware discovery of repository files (via `git`, `std::process::Command`).
- Secret/credential detection engine.
- Vulnerable dependency review against the OSV API v1 (batch query + detail fetches; results cached in XDG cache).
- Deterministic regex and Tree-sitter AST rules for initial JavaScript/TypeScript and Python.
- Parallel execution of detector engines (Rayon).
- Stable fingerprinting and deduplication of findings across engines and runs.
- Renderers: terminal, versioned JSON, SARIF 2.1.0.
- CLI with Clap + clap_complete (shell completions).
- Optional `--explain` LLM adapter over synchronous HTTP (ureq).
- Offline mode: serve from cache, warn/skip when unavailable.
- Cross-platform, single-crate Rust (Edition 2024); sync/stdio architecture; no Tokio; no SQL/NoSQL.

### Explicit Non-Goals

- Auto-fix or remediation of findings.
- Interactive mode, daemon, watch mode, or background scanning.
- Rule sets beyond JavaScript/TypeScript and Python in the MVP.
- Any hosted backend, server, or telemetry service.
- Async runtime (Tokio) in the MVP.
- Any database (SQL/NoSQL); the only persistent state is the XDG cache.
- `--explain` influencing severity, blocking, or pass/fail decisions — ever.

## 4. Business & Product Rules

- `--explain` output is **advisory only**; it never sets severity or blocking behavior, in any mode.
- Secret values are **redacted** before they enter LLM context; context is limited to the minimum necessary.
- `--explain` is **disabled by default** in CI mode and offline mode.
- Scans run entirely in memory; the XDG cache is the only persistent state.
- External advisory and LLM content is **untrusted**: sanitized before reaching analysis or output.
- Offline mode uses the cache and warns/skips gracefully when data is unavailable.
- In CI, ignore-file handling must disable global/parent ignore sources (hermetic scans — no ambient developer `.gitignore` files influencing results).

## 5. Acceptance Criteria

- [ ] `sentinel scan` on a clean repository produces no findings and exits successfully.
- [ ] Known secrets and known vulnerable dependencies (fixture corpus) are detected and reported.
- [ ] Identical scans produce identical, deduplicated findings (stable fingerprints).
- [ ] Terminal, versioned JSON, and SARIF 2.1.0 outputs are produced and well-formed; SARIF is ingestible by standard SARIF consumers.
- [ ] `--explain` runs only when explicitly enabled; CI mode and offline mode never invoke the LLM adapter.
- [ ] With `--explain`, severity and blocking outcomes are byte-identical to the same scan without it.
- [ ] Secret values never appear in any output or in LLM context payloads.
- [ ] Offline mode completes a scan using only the cache and warns/skips for missing data.
- [ ] A scan completes in under a minute on a repository with tens of thousands of files.
- [ ] Clippy, fmt, and the full test suite (assert_cmd/insta/tempfile) pass in CI.

## 6. Edge Cases & Constraints

- **OSV querybatch is paginated**: batch responses may span pages and may need per-advisory detail fetches; caching must respect this (documented research constraint).
- **Hermetic CI ignores**: global/parent ignore sources must be disabled so scan results don't depend on an individual machine's ignore configuration.
- **Offline degradation**: without network, advisory data comes only from cache; missing data produces warnings and skips, never a hard failure.
- **Untrusted third-party data**: OSV advisory content and LLM responses must be sanitized before use or display.
- **Determinism**: parallel engine execution must not affect output ordering; fingerprints, not run order, drive deduplication.
- **Redaction boundaries**: secrets must be redacted at the engine boundary, before any renderer or the LLM adapter sees them.

## 7. Risks & Roadmap

### Technical Risks

- OSV API pagination/detail-fetch behavior changes (mitigated by cache + tolerant fetch logic).
- Tree-sitter grammar coverage gaps for real-world JS/TS and Python (mitigated by regex fallbacks and a curated fixture corpus).
- LLM adapter cost/latency (mitigated by opt-in default, strict context limits, and no severity influence).
- Ignore-file variance across machines (mitigated by hermetic CI behavior).

### Staged Future Work (not MVP commitments)

These are candidate directions for later phases, explicitly not part of the MVP:

- **Deeper JS/TS analysis** via oxc-based parsing, superseding/augmenting initial regex/Tree-sitter rules.
- **More ecosystems**: additional languages, package managers, and advisory sources.
- **Optional LLM enhancements**: richer explanation modes and source-aware context — still governed by the rule that the LLM never sets severity or blocking.

Each phase is gated on MVP acceptance criteria passing and its own scope decision; nothing above is promised by the MVP.

## Checklist

- [ ] Problem is stated before solution detail.
- [ ] Success criteria are measurable.
- [ ] Non-goals are explicit and reviewed.
- [ ] Product rules (`--explain`, redaction, offline) are unambiguous.
- [ ] Future work is staged and labeled as non-commitments.

## Next Step

Design and architecture work (ARCHITECTURE.md, ADRs, system/API decisions) belongs to `design-architecture`; this PRD is its source of truth. Implementation planning starts only after MVP scope and acceptance criteria are approved.
