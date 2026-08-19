# Archive Report: sentinel-next-capability

- **Change**: `sentinel-next-capability`
- **Archived**: `openspec/changes/archive/2026-08-18-sentinel-next-capability/`
- **Date**: 2026-08-18
- **Artifact store**: openspec
- **Branch**: `feat/sentinel-sarif-output` (non-main)

## Final State (at close)

- **Verify verdict**: `pass_with_warnings`, evidence revision `sha256:f8e5ccf3228c22029d378f7679ce3e8c99c4ec2404f9845e7f545eb3b6cd5494`
- **Tasks**: 22/22 complete (verified against persisted `tasks.md` — zero unchecked implementation tasks)
- **Requirements**: 8/8; **Scenarios**: 21/21; **Tests passed**: 97
- **Quality gates**: build, fmt, clippy (`-D warnings`), deny, audit all green
- **Blockers**: 0; **Critical findings**: 0

### Mutation testing

Typed mutation testing is **unavailable**, not a pass: `cargo-mutants` is not installed on `PATH`, not present as `cargo mutants`, and not documented in the crate. No manual substitute was performed. The bounded campaign could not execute; this does not contradict any spec scenario (all 21 covering tests passed) and is not treated as an implementation failure. No PASS was fabricated.

## Deliverable Conditions (authorized delivery facts, not failures)

- Planning PR size (~700–850 authored lines; 400-line budget risk high) was reviewed and the size exception authorized.
- Standalone JSON-core Clippy and the SARIF-core size exception are authorized delivery facts.
- Delivery strategy: `auto-chain`, stacked-to-main, two PRs (JSON+CLI → SARIF+schema).

## Native Review Receipt Gate

`reviewGate` was **structurally absent** in the authoritative structured status — receipt-driven development does not exist for this candidate, so no review code ran and there is nothing to read or block on. `reviewOffer` was present only as an optional post-verify invitation; declining it is proceeding to archive, not a recorded verb. No review receipt, transaction, or ledger exists for this candidate. Archive proceeded under ordinary repository policy.

## Archive-Order Concern — RESOLVED

The verify-report at verification time recorded that `sentinel-discovery-hardening` remained unarchived as an archive-order concern. **That statement was true at verification time and is now stale.** `sentinel-discovery-hardening` was archived FIRST at `openspec/changes/archive/2026-08-18-sentinel-discovery-hardening/` with its deltas already synced into main `openspec/specs/cli-scan/spec.md` and `openspec/specs/git-discovery/spec.md` (Hermetic CI mode, `--ci`-only predecessor command surface, untracked discovery, size guard — confirmed by structural readback). This change's successor delta layered onto the post-hardening command surface, preserving `--ci` while adding `--output` and `--report`. No blocker or risk remains.

## Specs Synced

### `cli-scan` (merged into `openspec/specs/cli-scan/spec.md`)

- **MODIFIED** `Command surface`: replaced to accept `--ci`, `--output <terminal|json|sarif>` (default `terminal`), and `--report <path>`; added scenarios `Output and report flags accepted` and `Invalid output value rejected`; removed `--output json` from the `Unsupported argument rejected` scenario (now supported). Final surface preserves `--ci` from the hardening predecessor.
- **ADDED** `Report file output`: with `--output json|sarif`, `--report <path>` writes the report file with empty stdout; `--report` with `--output terminal` is a usage error; unwritable path → `cannot write scan report` + exit 2; diagnostics stay on stderr.
- **Preserved** (unchanged): `Exit-code contract`, `No network, no persistence, no telemetry`, `Delivery acceptance and CI quality gates`, and hardening's `Hermetic CI mode` (with all its scenarios).

### `machine-readable-reporting` (created at `openspec/specs/machine-readable-reporting/spec.md`)

Main spec did not exist; the delta spec is the full spec. Copied byte-identically via mechanical shell copy (`cp` → `diff -r` exit 0 → `mv`), then verified by `diff -r` against the delta source (empty diff, exit 0). Requirements: Versioned JSON envelope, Lowercase JSON severity, SARIF 2.1.0 envelope, Redacted bytes, Deterministic output, Hermetic schema validation.

## Mechanical Copy Verification

- **machine-readable-reporting main spec**: `diff -r <delta source> <main spec>` → **empty, exit 0** (byte-identical).
- **Archive move**: pre-move recursive snapshot `diff -r $snapshot_root/source <archived folder>` → **empty, exit 0** (byte-identical); source confirmed absent from `openspec/changes/`.

All archive copy/move operations used shell-native `cp`/`git mv`; no artifact bytes passed through model Read→Write.

## Artifacts Archived

- proposal.md ✅
- specs/cli-scan/spec.md ✅ (delta)
- specs/machine-readable-reporting/spec.md ✅ (delta)
- design.md ✅
- exploration.md ✅
- tasks.md ✅ (22/22 complete)
- verify-report.md ✅
- archive-report.md ✅ (this file, additive)

## Intentional-with-warnings

None. No destructive delta (no REMOVED/RENAMED requirements) was merged; no partial-archive override was requested. The only verification warning (unavailable mutation campaign) is environmental and non-blocking; the archive-order concern was resolved by the prior hardening archive. This is a clean archive under ordinary repository policy.
