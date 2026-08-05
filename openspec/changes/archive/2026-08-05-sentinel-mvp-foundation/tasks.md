# Tasks: Sentinel MVP Foundation

## Review Workload Forecast

~3,010 native-accounted lines (lock/snapshots counted; goldens never authored; excluded from risk, kept in identity+receipt). Risk: High; every PR: `size:exception`; unit ≤800. exception-ok (user-accepted); stacked-to-main. Uncertainty: lock/snapshot/test drift; no hidden scope.

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

| # | Goal | Est | PR | Test | Runtime | Rollback |
|---|---|---|---|---|---|---|
| 1 | Manifest + full lock + green crate | 780 | PR1 | `cargo test --all-features` +gates | temp repo; `scan` → 0 | revert head→base; bootstrap hold |
| 2 | CLI/errors/discovery/finding; exits 0/2 | 700 | PR2 | `cargo test --all-features` | temp repo → 0; non-repo/git-missing → 2 | revert PR2; PR1 green |
| 3 | Engine/digest/redaction/normalize/render; exit 1 | 780 | PR3 | `cargo test --all-features` (insta) | fixture scan → redacted, exit 1 | revert PR3; PR2 0/2 green |
| 4 | Fixtures/integration/goldens/determinism/gates | 750 | PR4 | `cargo test --all-features` | twice-run + 1-vs-N `cmp`; read-only $HOME | revert PR4; PR3 green |

Every PR: `size:exception` + Chain Context (position/base/dependency/follow-up/diagram/scope/evidence/rollback/forecast/exception); rebase post-parent; diff = unit only.

## PR1: Manifest/Green Crate

- [x] 1.1 Create `Cargo.toml` (Edition 2024; runtime+dev deps per design; trimmed defaults) + full `Cargo.lock`
- [x] 1.2 Create `src/{main,lib}.rs` with `sentinel::run(args,cwd,stdout,stderr)` seam; clean exit 0; no stubs/flags
- [x] 1.3 Gates green: fmt, clippy -D warnings, `cargo test --all-features`, deny, audit, build
- [x] 1.4 Evidence: harness result, lock accounting, rollback proof (revert)

## PR2: CLI/Errors/Discovery/Model

- [x] 2.1 RED (cli-scan Unsupported arg/Missing subcommand): `--explain`/`--output json`/`--ci`/positional → usage stderr, empty stdout, 2
- [x] 2.2 RED (TM repo selection): nested/absolute cwd, `-C`-like pathname, invalid cwd → 2
- [x] 2.3 RED (git-discovery spaces/newlines; Determinism): NUL-safe parse; repeated discovery identical
- [x] 2.4 Create `src/{cli,errors,discovery,finding}.rs`: clap scan-only; thiserror 0/1/2; `rev-parse --show-toplevel`, `ls-files -z`; reject abs/`..`/empty-interior/symlink/non-regular; git-missing/non-repo → 2
- [x] 2.5 Wire `src/{main,lib}.rs`; GREEN 2.1–2.3: clean/empty→0, non-repo/git-missing→2

## PR3: Engine/Normalize/Render

- [x] 3.1 RED (Known secret; Renamed rule): AWS key → `SECRET-aws-access-key`; `deprecated_ids` alias resolves
- [x] 3.2 RED (Boundary; Full-field): `sk-synthetic-1234567890` absent all fields/streams; BLAKE3 length-prefixed pre-redaction; digest-only crosses engine
- [x] 3.3 RED (Failing rule): failure → stderr warning, scan completes, rest fire
- [x] 3.4 Create `src/engine/{mod,secrets}.rs`: static `SECRET-<KEBAB>` `regex::bytes` table; redact at boundary; failure → warn
- [x] 3.5 RED (Schema/Fingerprints/Dedupe/Order/Determinism): fp excludes ts/abs/order; same→same, distinct→distinct; dup collapsed; sort (fp,path,line); `/`+LF
- [x] 3.6 Create `src/{normalize,render}.rs`: BTreeMap dedupe/sort; pure-bytes render (no ts/ANSI/threads); RED (stdout/stderr; Exit): findings→stdout, diag→stderr; broken stdout→2
- [x] 3.7 Wire `lib.rs`: discovery→rayon→normalize→render; findings→1, clean→0; GREEN 3.1–3.6

## PR4: Fixtures/Integration/Gates

- [x] 4.1 Create `tests/fixtures/` synthetic-only corpus; audit: no real credentials
- [x] 4.2 Create `tests/cli.rs`: temp repos; usage/nested cwd/exits/git-read-failure/stream separation (cli-scan, git-discovery, terminal-rendering)
- [x] 4.3 insta goldens `tests/snapshots/`: named synthetic files, 1 vs N threads → byte-identical (Parallel)
- [x] 4.4 Determinism (Hermetic/Read-boundary): twice-run `cmp` stdout+stderr; read-only $HOME; paths+mtimes unchanged
- [x] 4.5 Final gates+evidence: fmt, clippy, deny, audit, tests, goldens, byte-compare receipt, Chain Context + `size:exception` rationale

Next step: sdd-verify
