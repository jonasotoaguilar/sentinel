# Exploration: sentinel-mvp-foundation

> Phase: sdd-explore · Store: hybrid (OpenSpec + Engram) · Date: 2026-08-05 · Change: `sentinel-mvp-foundation`
> Status of this document: analysis and scope recommendation for `sdd-propose`. No implementation.

## Current State

Sentinel is in **bootstrap state**: no `Cargo.toml`, `Cargo.lock`, or `src/` exists. Working branch is
`chore/bootstrap-sentinel` (never `main`); `core.hooksPath=.githooks`; `.gitignore` already ignores
`/target/` and generated reports. CI (`ci.yml`: test/coverage, dependency-security, code-scan) and the
pre-commit hook contain a **bootstrap gate that activates automatically when `Cargo.toml` lands** — no
workflow edits are required by this change. `pr-check.yml` enforces a **400-line per-PR review budget**
(with `size:exception` label escape), an issue reference + `status:approved`, and a single `type:*` label.

The product and architecture are fully specified but unimplemented:

- **PRD.md** fixes MVP scope: git-aware discovery, secrets engine, OSV dependency review, regex +
  Tree-sitter rules for JS/TS and Python, Rayon parallelism, stable fingerprint/dedupe, terminal /
  versioned-JSON / SARIF 2.1.0 renderers, Clap CLI with completions, opt-in advisory-only `--explain`,
  offline mode. Explicit non-goals: no auto-fix, no daemon/watch, no server, no Tokio, no SQL/NoSQL.
  KPIs: sub-minute scans, byte-identical deterministic runs, `--explain` never influences severity/blocking,
  secrets never appear in outputs or LLM context.
- **ARCHITECTURE.md** fixes the shape: single-crate modular monolith, synchronous pipeline
  CLI → discovery → parallel engines (Rayon) → normalize/fingerprint/dedupe (BTreeMap by fingerprint,
  order = fingerprint/path/line) → renderers; XDG cache as the only persistent state; exit-code contract
  0 (clean) / 1 (findings) / 2 (operational failure); redaction at the engine boundary; test strategy
  (assert_cmd / insta / tempfile, fixture corpus, determinism gate running scans twice byte-compared).
- **ADR-0001/0002/0003** lock: single sync process no DB; OSV XDG cache with 24 h TTL, atomic writes,
  offline degrade (warn/skip, never fail); advisory-only LLM boundary enforced by construction.
- **openspec/config.yaml** records SDD rules and that all test commands are configured but **not
  executable until the manifest exists**; `deny.toml` (license allow-list, `wildcards=deny`,
  `unknown-registry=deny`) and `rust-toolchain.toml` (stable, clippy+rustfmt) are ready.
- **Engram** holds `sdd-init/sentinel` (#4750) and `sdd/sentinel/testing-capabilities` (#4751);
  no `sdd/sentinel-mvp-foundation/*` artifacts exist yet. SDD pipeline is empty (`openspec/specs/` and
  `openspec/changes/` have no content).

**Delivery constraints**: SDD review budget **800 changed lines** (authored text, goldens excluded) with
`auto-chain` delivery; CI caps each PR at **400 changed lines**. The full MVP cannot fit one slice — it
must be delivered as a sequence of chained SDD changes, each ≤ the per-PR budget. This exploration scopes
the **first** change only.

## 1. Product outcome the first slice must prove

The first end-to-end slice must prove the **core product loop**, not any individual subsystem:

> `sentinel scan` on a Git repository → discovers tracked files the way Git sees them → a real secrets
> detector finds known credentials → findings are normalized, fingerprinted and deduplicated → rendered
> to terminal → the process exits `0` (no findings) / `1` (findings) / `2` (operational error) — with
> output byte-identical across runs and raw secret values never printed.

That loop proves PRD KPIs 2 (determinism) and 4 (redaction), acceptance criterion 1 (clean repo → no
findings, exit 0) and the secrets half of criterion 2 (known secrets detected from the fixture corpus) —
and it exercises every stage of the fixed architecture with no network, no database, and no third-party
dependencies, so the slice is fully testable offline in CI. Vulnerable-dependency detection, additional
renderers, AST rules and `--explain` are provable in later slices (see §5).

## 2. Narrowest valuable scope (recommended first slice)

**Crate bootstrap + CLI + git-aware discovery (tracked files) + regex secrets engine + findings
model + fingerprint/dedupe + terminal renderer + exit-code contract + test scaffolding.**

| In scope (slice 1) | Deferred (later slices) |
|---|---|
| `Cargo.toml`/`Cargo.lock` (edition 2024, stable; lockfile committed) | `ignore`-walker worktree traversal, untracked files, custom ignore file |
| `sentinel scan` (Clap derive; runs from repo root) | Hermetic `--ci` mode (parents/global/exclude off) |
| Discovery via `git ls-files` (tracked files) via `std::process::Command` | `--output json\|sarif` + `--report` file output |
| Regex secrets engine (curated starter rule set, redaction at engine boundary) | Tree-sitter rules engine (JS/TS + Python, regex fallback) |
| Rayon parallel engine stage with deterministic collection | OSV client + XDG cache + dependency engine (npm/PyPI) |
| `Finding`/`Location`/`Severity` model + stable fingerprint + dedupe + sort | `--explain` LLM adapter |
| Terminal renderer (stdout); diagnostics on stderr | `clap_complete` shell completions (if budget is tight) |
| Exit codes 0/1/2; git-missing/non-repo → clear error, exit 2 | Max-file-size guard, explicit CLI exclusions |
| Unit tests (rules, fingerprint determinism, normalize) + assert_cmd integration tests (exit contract, redaction, stdout/stderr) + insta terminal golden | SARIF schema validation, determinism gate in CI |

Deliberate exclusions for slice 1: **no flags that don't work yet** (only `sentinel scan` is exposed —
no `--output`, `--report`, `--explain`, `--ci` stubs that would mislead), **no engine trait** (one
implementation now; the trait is a hypothetical seam until a second engine exists — deletion test per
module-design), **no network** (OSV/LLM adapters are entirely later slices).

## 3. Requirements, safety constraints, non-goals, unresolved decisions

**Requirements the slice must honor** (source: PRD §3–§5, ARCHITECTURE.md, ADR-0001):
- Single-crate Rust, Edition 2024, stable toolchain; no Tokio, no DB.
- Deterministic, byte-identical output (no timestamps/run-derived fields); order = (fingerprint, path, line).
- Redaction at the engine boundary: raw secret values must be unreachable by renderers/logs (KPI 4).
- `git` on PATH is a hard dependency; not a repo / git missing → exit 2 with a clear stderr error.
- stdout reserved for findings; diagnostics/tracing to stderr (`RUST_LOG`).
- Cargo.lock committed; clippy `-D warnings`, `fmt --check`, `cargo deny check`, `cargo audit` green in CI.
- Exit-code contract 0/1/2 per ARCHITECTURE.md.

**Safety constraints**: secrets never in outputs, logs, or cache; external data (none in slice 1) treated
as untrusted at trust boundaries; no telemetry/phone-home. **Non-goals for slice 1**: auto-fix, daemon,
watch, server, DB, Tokio, async, non-JS/TS/Python ecosystems, and anything the PRD lists as non-goal.

**Unresolved decisions to pin in the proposal** (ADR/architecture action items):
1. Exit-code semantics detail: confirm 0 = no findings, 1 = findings present (blocking policy for CI
   comes later), 2 = operational error — and that a scan with zero findings on an empty repo is 0.
2. Rule-ID naming convention for secrets rules (stable IDs are part of the versioned output contract).
3. Whether `clap_complete` ships in slice 1 or defers (budget-dependent).
4. Custom ignore filename (e.g. `.sentinelignore`) — deferred, but decide the name at proposal time so
   discovery-hardening can reuse it.
5. OSV cache TTL knob and explain context caps — deferred to their slices; no decision needed now.

## 4. Module boundaries, executable flow, input/output contract, test seams

```
src/main.rs          thin entry: parse → sentinel::run() → exit code (std::process::exit)
src/lib.rs           mod declarations + run(): orchestrates the fixed pipeline; anyhow composition
src/cli.rs           Clap derive: Sentinel { command: Scan }; thin controller, no business logic
src/errors.rs        thiserror domain errors (DiscoveryError, EngineError, RenderError); exit-code mapping
src/discovery.rs     discover_tracked_files(&Path) -> Result<Vec<PathBuf>> via `git ls-files -z` +
                     `git rev-parse --show-toplevel`; non-repo/git-missing → typed error → exit 2
src/finding.rs       Finding { id, engine, rule_id, severity, location(path,line,column,snippet),
                     message, evidence: RedactedEvidence }; Location path repo-relative, forward slashes
src/engine/mod.rs    dispatch over file set with rayon par_iter; collects into plain Vec (no shared state)
src/engine/secrets.rs regex rule table (static, curated); scan_bytes -> Vec<Finding>; raw values never
                     leave this module (redacted evidence only)
src/normalize.rs     stable fingerprint (hash over canonical fields, no timestamps/abs paths) →
                     BTreeMap<Fingerprint, Finding> dedupe → deterministic sort (fingerprint, path, line)
src/render.rs        terminal renderer: pure fn render(&ScanResult) -> String; no I/O
src/main.rs (tracing) tracing + tracing-subscriber to stderr only; spans per stage
tests/cli.rs        assert_cmd: exit contract (clean→0, findings→1, non-repo→2), stdout/stderr separation,
                    redaction (raw secret absent from all output), determinism (run twice, byte-compare)
tests/fixtures/     synthetic secrets corpus (never real credentials); small git repos built in tempdirs
```

**Flow**: `main` → `cli` parse → `run()`: `discovery` → `engine` (rayon, parallel) → `normalize`
(fingerprint/dedupe/sort) → `render` (terminal) → exit code. Any stage hard-failing → exit 2;
engine-local failures contained (warn) and never abort the scan.

**Input/output contract (slice 1)**: input = current repo root (cwd) as Git sees it (tracked files).
Output = terminal report to stdout; diagnostics to stderr; exit 0/1/2. No files written, no network,
no persistent state (XDG cache arrives with the OSV slice).

**Test seams**: none introduced speculatively. Integration tests exercise the binary through
`assert_cmd` with real `git` in `tempfile` repos (discovery is local-substitutable — no seam needed);
unit tests exercise engine rules and normalize/fingerprint purity through public interfaces; insta
goldens pin the terminal renderer. A second real adapter appears only with OSV/explain (stub servers),
per the two-real-adapters rule.

## 5. Risks, dependencies, follow-up sequence

**Risks**
- **Budget**: the slice as scoped likely lands at ~700–800 authored lines (goldens excluded). CI caps
  each PR at 400 lines → the change must ship as **2 chained PRs** (e.g. #1 crate + model + CLI +
  discovery + errors; #2 secrets engine + normalize + terminal renderer + tests), or trim `clap_complete`
  / rayon out of slice 1 to fit one PR. `auto-chain` delivery is the standing strategy.
- **CI activation**: the first PR containing `Cargo.toml` turns the bootstrap gates on for real —
  clippy/fmt/test/deny/audit must be green on that PR itself; the lockfile must satisfy `deny.toml`
  (chosen deps — clap, clap_complete, regex, rayon, anyhow, thiserror, tracing, tracing-subscriber,
  dev: assert_cmd, predicates, insta, tempfile — are all MIT/Apache-2.0 allowed).
- **Determinism**: parallelism must never affect ordering; normalize must canonicalize path separators
  and line endings (cross-platform CI intent).
- **Redaction regressions**: the secrets engine boundary is the single chokepoint; integration tests
  must assert raw secret strings are absent from every output surface.
- **`git` availability**: hard dependency verified up front; non-repo → exit 2 (tested).

**Dependencies**: `git` executable (runtime); crates listed above (build); CI gates activate on the
manifest. No network, no OSV, no cache in this slice.

**Follow-up sequence** (each a separate SDD change after `sentinel-mvp-foundation`):
1. `sentinel-discovery-hardening` — `ignore`-walker (untracked + repo-local ignore), `.sentinelignore`,
   hermetic `--ci` mode, max-file-size guard, explicit exclusions.
2. `sentinel-dependency-engine` — manifest resolution (npm/PyPI) → OSV client (ureq) → XDG cache
   (directories, atomic write, 24 h TTL) → offline degrade. (May split: client+cache, then engine.)
3. `sentinel-rules-engine` — Tree-sitter JS/TS + Python with per-file regex fallback (oxc is staged,
   non-MVP).
4. `sentinel-renderers-json-sarif` — versioned JSON envelope + SARIF 2.1.0 (+ `--report`), schema
   validation, insta goldens.
5. `sentinel-explain-adapter` — advisory-only LLM adapter (HTTP + stub), context budget, differential
   tests (with/without `--explain` byte-identical).

## 6. Recommended SDD change scope for sdd-propose

Change **`sentinel-mvp-foundation`**: bootstrap the crate and deliver the vertical slice defined in §2 —
terminal-only, secrets-only, tracked-files-only — proving the full pipeline loop with exit-code contract,
redaction, and determinism, fully tested offline, activating CI/pre-commit gates. Proposal must pin the
§3 unresolved decisions (exit-code semantics, rule-ID convention, completions in/out) and a chained-PR
plan (2 PRs ≤ 400 lines each) per the auto-chain strategy.

## Approaches Considered

1. **Vertical slice — git ls-files + secrets engine only (recommended, §2)** — smallest honest loop;
   every stage real; no network; fits (barely) the 800-line budget when chained.
   - Pros: proves the product loop end-to-end; deterministic and offline-testable; leaves no stub surfaces.
   - Cons: needs 2 chained PRs to stay within the 400-line CI budget; tracked-files-only until the
     discovery-hardening slice.
   - Effort: Medium.
2. **Full skeleton — all engines/renderers/adapters as shells** — broad coverage, nothing finished.
   - Pros: maps the whole module map early.
   - Cons: violates the "working vertical slice over broad unfinished subsystems" rule; stub flags
     mislead users; review budget blown immediately; deletion-test failures everywhere.
   - Effort: High (and mostly waste).
3. **Slice 1 + ignore-walker + hermetic CI** — richer discovery from day one.
   - Pros: discovery semantics complete sooner; hermetic CI behavior early.
   - Cons: adds a dense, test-heavy subsystem (ignore semantics) that alone approaches the 400-line PR
     budget; forces a 3+ PR chain and delays the provable product loop; hermetic CI needs `--ci` mode
     which also implies exclusion/ignore config decisions.
   - Effort: High.

### Recommendation

Approach 1 — the vertical slice in §2, delivered as **2 chained PRs** under the 400-line CI budget.
It proves the fixed pipeline (discovery → engine → normalize → render → exit code) with the two KPIs
that are cheapest to regress (determinism, redaction) and leaves every deferred subsystem as an
unambiguous, separately-reviewable change. `sdd-propose` should adopt this scope, pin the §3 decisions,
and commit the chained-PR plan.

### Ready for Proposal

**Yes.** The orchestrator should tell the user: exploration completed; recommended first change is
`sentinel-mvp-foundation` (crate bootstrap + terminal-only secrets vertical slice, ~2 chained PRs);
three product-level decisions must be confirmed at proposal time — exit-code semantics, secrets
rule-ID naming, and whether shell completions ship in this slice or next.
