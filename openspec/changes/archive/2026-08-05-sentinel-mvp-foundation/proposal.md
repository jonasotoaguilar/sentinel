# Proposal: Sentinel MVP Foundation

## Intent

Bootstraps the crate and delivers the vertical slice: `sentinel scan` on Git-tracked files → regex secrets engine → redacted findings → deterministic dedupe → exit 0/1/2, offline-tested (PRD §5 AC1/2/3/7/10; KPIs 2, 4).

## Scope

**In**: `Cargo.toml`/`Cargo.lock` (2024, committed); `sentinel scan` (clap, no stubs); git discovery (`rev-parse` + `ls-files -z`); regex secrets engine (redaction at engine boundary); model/fingerprint/dedupe, order (fingerprint, path, line); terminal renderer; tracing; rayon; tests (unit/assert_cmd/insta); synthetic fixtures.

**Out**: ignore-walker/untracked/`.sentinelignore`; OSV/network/cache; Tree-sitter; JSON/SARIF; `--explain`/`--ci`/`--output`/`--report`; `clap_complete`; size guard; CLI exclusions; engine trait.

## Decisions (pinned)

1. Exit 0/1/2; empty repo → 0 (AC1). CI blocking deferred.
2. Rule IDs `SECRET-<KEBAB-NAME>`, static, stable; renames alias via `deprecated_ids`.
3. `clap_complete` deferred; `.sentinelignore` pinned.
4. Full-field redaction: only redacted fields + pre-redaction BLAKE3 digest leave the engine boundary (KPI 4). Deterministic order; no write/cache/persistence/network/telemetry; synthetic offline tests.

## Delivery Decision (explicit; authoritative)

**Size exception accepted by the maintainer.** The committed `Cargo.lock` makes the 400-line gate irreducible for a manifest-bearing green PR (662/76 → ~697 pre-source; minimal 382/44 → 412; gates fail without `Cargo.toml`; lock cannot land partially; no green ≤ 400). The 400-line gate stays repository policy; this change uses the explicit `size:exception` and is never compliant without it. Apply: `exception-ok`; chain: `stacked-to-main`.

Stacked units (each ≤ 800 lines; every PR `size:exception`): PR1 manifest/green crate (gates green) → PR2 CLI/errors/discovery/model (exits 0/2) → PR3 engine/normalize/render (exit 1) → PR4 fixtures/integration/final gates (fixtures, goldens, byte-compare).

`sdd-tasks` may refine boundaries; no apply until proposal/spec/design/tasks agree.

## Capabilities

**New**: `cli-scan` · `git-discovery` · `secrets-detection` · `finding-normalization` · `terminal-rendering`. **Modified**: None.

## Approach

Hard failures → 2; engine-local failures warn; redaction at engine boundary. Stacked-to-main per Delivery Decision.

## Affected Areas

All New: `Cargo.toml`, `Cargo.lock`, `src/{main,lib,cli,errors,discovery,finding,normalize,render}.rs`, `src/engine/{mod,secrets}.rs`, `tests/cli.rs`, `tests/fixtures/`.

## Risks

- CI gates activate with PR1 manifest (Med) — pre-verify; license-clean deps
- Stacked-chain diff pollution (Med) — rebase; chain context
- Rayon ordering regression (Low) — collect at stage boundary; byte-compare
- Redaction regression (Low) — secrets absent from outputs asserted

## Rollback / Stop Conditions

Gates red → fix/revert before next PR. Pre-merge: delete chain. Post-merge: revert head→base; gates deactivate with manifest removal (PR1).

## Dependencies

`git` on PATH (hard). Deps: clap, regex, rayon, anyhow, thiserror, tracing, tracing-subscriber, blake3; dev: assert_cmd, predicates, insta, tempfile. No network/DB/Tokio.

## Success Criteria

- Clean repo → no findings, exit 0 (AC1)
- Synthetic secrets → redacted findings, exit 1 (AC2; KPI 4)
- Non-repo/git missing → exit 2
- Repeated runs byte-identical (KPI 2; AC3)
- stdout findings-only, stderr diagnostics (AC10)
- Four stacked PRs ≤ 800 authored lines, each with the approved size exception

## Follow-ups

`discovery-hardening` → `dependency-engine` → `rules-engine` → `renderers-json-sarif` → `explain-adapter`.
