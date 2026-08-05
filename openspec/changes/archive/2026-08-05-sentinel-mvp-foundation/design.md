# Design: Sentinel MVP Foundation

## Technical Approach

Build one Rust Edition-2024 binary crate. `main.rs` passes arguments, cwd, and locked stdio to the public seam, `sentinel::run(args, cwd, stdout, stderr) -> ExitCode`; private modules implement discovery → secrets → normalization → terminal rendering. Scan only Git-tracked worktree bytes; no writes, cache/persistence, network, or telemetry. Exclude speculative traits, future flags, completions, ignore walker, OSV, Tree-sitter, JSON/SARIF, and LLM paths.

## Architecture Decisions

| Option | Tradeoff | Decision / rationale |
|---|---|---|
| Workspace vs single crate | Extra crate seams | Modular single crate, per ADR-0001. |
| Traits vs concrete calls | Unjustified indirection | Concrete private modules. |
| Text vs byte regex | Byte positions need deterministic display escaping | `regex::bytes::Regex` preserves binary/invalid UTF-8 inputs. |
| Default hash vs BLAKE3 | Extra dependency | Specified digest gives stable cross-release fingerprints. |
| Parallel emission vs staged collection | Collection uses memory | Collect, normalize, sort, then render; scheduling never controls output. |

Runtime dependencies: `clap 4`, `regex 1`, `rayon 1`, `anyhow 1`, `thiserror 2`, `tracing 0.1`, `tracing-subscriber 0.3`, `blake3 1`; dev-only: `assert_cmd 2`, `predicates 3`, `insta 1`, `tempfile 3`. `thiserror` owns domain errors; `anyhow` adds binary-orchestration context. Disable unnecessary defaults, add nothing else, and commit the complete lockfile.

## Data Flow and Contracts

```text
CLI -> git rev-parse / ls-files -z -> validated tracked-byte reads (Rayon)
    -> secret rules -> redacted candidates + digest -> normalize/dedupe/sort
    -> complete stdout/stderr buffers -> exit 0/1/2
```

Invoke Git with `Command` arguments, never a shell; cwd is repository authority. Parse NUL records as bytes; reject absolute, parent-traversing, empty-interior, symlink, and non-regular paths. Read failures become sorted warnings.

Inside `engine::secrets`, compute BLAKE3 over length-prefixed canonical matched bytes **before** replacing the full match. Only redacted fields and the fixed digest cross the engine boundary. Normalize `/` paths and LF; fingerprint `(engine, rule, normalized location, digest)`, deduplicate, then sort `(fingerprint,path,line)`. Sort diagnostics `(code,path,rule)` and disable tracing timestamps/ANSI/targets/thread IDs. Clean/empty → 0; findings → 1; usage, Git, or output failure → 2.

## File Changes

Create `Cargo.toml`, `Cargo.lock`; `src/{main,lib,cli,errors,discovery,finding,normalize,render}.rs`; `src/engine/{mod,secrets}.rs`; `tests/cli.rs`, `tests/fixtures/`, `tests/snapshots/`. No CI/tooling change: manifest activates fmt, clippy, tests, deny, audit, coverage, and code-scan gates.

## Testing Strategy

Unit tests cover NUL/traversal paths, invalid bytes, rule aliases/failures, digest/redaction, fingerprints, dedupe, and shuffled order. Integration tests use temporary Git repositories for usage, nested cwd, exits, Git/read/output failures, stream separation, read-only home, and unchanged paths/mtimes. Synthetic named goldens run with one and multiple Rayon threads; repeated stdout/stderr are byte-compared and raw values rejected across every finding field and stream.

## Threat Matrix

| Boundary | Applicability | Safe/failure behavior and planned RED tests |
|---|---|---|
| Documentation-like paths | N/A | Content is scanned, never classified or executed. |
| Git repository selection | Applicable | Safe: cwd alone selects the repository and `-C` is a separate argument. Failure: invalid cwd/repository exits 2. RED: nested relative cwd, absolute cwd, and `-C`-like pathname. |
| Commit state | N/A | Tracked worktree bytes, not index/commit transitions, are authoritative. |
| Push state | N/A | No push integration. |
| PR commands | N/A | Delivery is manual workflow; no PR-command automation changes. |

## Delivery and Rollback

Delivery is `exception-ok` with four ordered `stacked-to-main` units. **Every forecast exceeds the repository's 400-line policy and every PR must carry the explicitly accepted `size:exception`; none is compliant without it.** Authored forecasts count additions plus deletions; generated goldens are excluded only from authored totals and remain reviewable artifacts.

| PR | Owned files / green boundary | Focused evidence | Rollback | Forecast |
|---|---|---|---|---|
| 1 | Complete `Cargo.toml`/`Cargo.lock`, minimal `src/{main,lib}.rs`; crate builds and all activated gates pass. | `cargo fmt --all -- --check`, clippy, test, deny, audit, build | Remove crate foundation; bootstrap hold returns. | ≤780 |
| 2 | Add `cli`, `errors`, `discovery`, `finding`; wire `main/lib`; clean/empty exits 0, usage/non-repo/Git-missing exits 2. | Discovery units plus focused CLI runtime harness | Revert PR2; PR1 remains green. | ≤700 |
| 3 | Add `engine`, `normalize`, `render`; wire exit 1 and digest-only redaction boundary. | Unit/in-memory pipeline tests for leakage, dedupe, order, exits | Revert PR3; PR2's 0/2 scanner remains green. | ≤780 |
| 4 | Add `tests/cli.rs`, synthetic fixtures/snapshots and final evidence. | Full gates, goldens, 1/N-thread and twice-run byte comparison, read-only snapshot | Revert test/evidence layer; PR3 behavior remains green. | ≤750 |

PR1 targets `main`; each later branch starts from its predecessor. Each PR includes Chain Context (position, base/dependency, follow-up, full diagram, scope, green evidence, rollback, forecast, exception rationale). After each parent merges, rebase/retarget the next PR to `main` and verify its diff contains only that unit. Stop on polluted diffs or red gates. No migration required; open questions: none.
