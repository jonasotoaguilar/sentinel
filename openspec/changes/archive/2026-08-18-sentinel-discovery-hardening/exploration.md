# Exploration: sentinel-discovery-hardening

> Phase: sdd-explore · Store: hybrid (OpenSpec + Engram) · Date: 2026-08-05 · Change: `sentinel-discovery-hardening`
> Status of this document: analysis and scope recommendation for `sdd-propose`. No implementation.
> Branch: `feat/discovery-hardening` (never `main`). Session delivery: automatic chaining; review budget 800 changed lines; CI per-PR cap 400 lines.

## Current State

The MVP foundation is **shipped and archived** (`2026-08-05-sentinel-mvp-foundation`, 24 requirements / 36 scenarios, 44 tests, PASS). The scan pipeline is: `sentinel scan` (only command) → `src/discovery.rs` `Git::discover()` → Rayon per-file read → secrets engine (redaction at engine boundary) → normalize/fingerprint/dedupe → terminal render → exit 0/1/2. `--ci`, `--output`, `--explain` are rejected as usage errors.

Discovery today is **tracked-files-only** (`src/discovery.rs`, 330 lines):

- `git rev-parse --show-toplevel` resolves the root; `git ls-files -z` enumerates tracked files as NUL-delimited bytes (spaces/newlines/non-ASCII and invalid-UTF-8 on Unix preserved byte-exact).
- `accept_record` validates every record: `is_safe_relative` rejects absolute, parent-traversing (`..`), and empty-interior paths; `symlink_metadata` accepts regular files only (tracked symlinks and non-regular entries rejected).
- `files.sort()` gives deterministic ordering; repeated discovery is byte-identical.
- Empty repo (no commits) → empty file set → exit 0. Non-repo / git missing → typed error → exit 2.

The **entire deferred discovery-hardening surface is unimplemented** (archived explore §2 "Deferred (later slices)" and follow-up #1): no untracked-file discovery, no ignore behavior, no `--ci`, no `.sentinelignore`, no max-file-size guard, no explicit exclusions.

### Contract gap vs. documented product contract

| Contract (PRD / ARCHITECTURE) | Shipped today |
|---|---|
| PRD §3: "Git-aware discovery of repository files (via `git`, `std::process::Command`)" | ✅ tracked files via `git ls-files` |
| ARCHITECTURE Discovery: "tracked files via `git ls-files` **plus worktree traversal for untracked-but-present files**" | ❌ untracked files invisible to the scan |
| ARCHITECTURE Discovery: "honoring repository-local ignore rules" | ❌ none (no untracked candidates, so no ignore application) |
| ARCHITECTURE Discovery: hermetic CI — `parents(false)`, `git_global(false)`, `git_exclude(false)`, `require_git(true)`; PRD §4: "In CI, ignore-file handling must disable global/parent ignore sources" | ❌ no `--ci` flag at all |
| ARCHITECTURE Discovery: repo-local custom ignore file `add_custom_ignore_filename` (`.sentinelignore` name pinned in foundation proposal decision 3) | ❌ absent |
| ARCHITECTURE Discovery: "A maximum-file-size guard bounds pathological inputs" (Failure Modes: "Pathological inputs (huge single file, huge repo)") | ❌ absent |
| PRD KPI 2 determinism; §6 "Ignored/untracked files must not break determinism" | ✅ for tracked set only |

**User-visible consequence of the gap**: a developer who stages a commit but leaves a secret in an untracked file (e.g. a fresh `.env`, a scratch script, an un-ignored build artifact) gets a clean scan — the exact failure mode the product exists to prevent.

## Scope of this change (focus)

Git-aware worktree discovery, repository-local ignore behavior, hermetic CI behavior, path safety, deterministic ordering, and graceful handling of untracked/ignored files. **Explicitly not expanded into**: dependency/OSV scanning, JSON/SARIF output, `--explain`, explicit CLI exclusion globs (deferred — archived follow-up listed them with this change, but they are out of the current focus; see Non-Goals), Tree-sitter/rules engines, completions.

## Approaches

### 1. Hybrid — keep `git ls-files` (tracked) + add `ignore` crate walker (untracked, ignore-aware) — *the pinned architecture*

`src/discovery.rs` keeps the existing git path for tracked files and adds a worktree walk for untracked candidates. Walker configuration per ARCHITECTURE.md: `require_git(true)`, `parents(false)`, `git_global(false)`, `git_exclude(false)` in CI mode; `follow_links(false)`; `max_filesize(Some(...))`; `add_custom_ignore_filename(".sentinelignore")`. **Critically, `hidden(false)` is REQUIRED** — the `ignore` crate's default skips hidden (dot-prefixed) files, whereas git does not ignore untracked dotfiles unless pattern-matched; with the default, untracked `.env` files would silently vanish from a secrets scan (verified against ignore crate docs, 2026-08-05). File set = union(ls-files, walker entries) → dedupe → validate through the existing `accept_record` safety logic → sort.

- Pros:
  - Matches the pinned ARCHITECTURE.md contract 1:1 (Discovery component, diagram, Key Decisions table) — zero architecture churn.
  - `.sentinelignore` via `add_custom_ignore_filename` is first-class, with higher precedence than all other ignore files (sensible for a tool-owned exclusion list).
  - `max_filesize` guard is built into the walker (one line).
  - Parallel walk (`build_parallel`) scales on very large trees; no per-file subprocess.
  - BurntSushi's gitignore engine is the ecosystem standard (ripgrep's), well-tested semantics (negation, `**`, anchoring).
  - The tracked-ignored case (`git add -f` of an ignored file) is handled correctly by the ls-files side (tracked always wins over ignore, matching git).
- Cons:
  - New dependency (`ignore` 0.4.x, MIT — allowed by deny.toml) plus its small transitive set (walkdir, globset, regex-automata, same-file, log, crossbeam-channel); must pass `cargo deny`/`audit` review.
  - Two sources of truth that must be reconciled (union/dedupe), with divergence surface: nested git repos (walker descends; git collapses them), `.git` directory contents (must verify the crate never yields them once `hidden(false)` is set — an explicit test is mandatory), case-sensitivity on Windows.
  - The `hidden(false)` requirement is a silent-correctness trap: easy to omit, no compiler help, only a test catches it.
  - `.sentinelignore` precedence (highest) differs from what a git-native implementation would give (`core.excludesFile` is lowest) — pin with a test.
- Effort: Medium-High.

### 2. Extend Git-only — one command for the whole file set

Replace the `ls-files` call with `git ls-files -z --cached --others --exclude-standard` (tracked + untracked-non-ignored, NUL-delimited, individual files — no directory collapsing). Hermetic CI variant: `git -c core.excludesFile=/dev/null ls-files -z --cached --others --exclude-per-directory=.gitignore` (git never reads parent-dir ignore files at all — hermetic by construction for parents; `-c core.excludesFile=/dev/null` disables the global; dropping `--exclude-standard` in favor of `--exclude-per-directory` disables `.git/info/exclude`). `.sentinelignore` participates via `-c core.excludesFile=<root>/.sentinelignore` (or `--exclude-from`) — verified behavior in design. Same record validation and sort as today.

- Pros:
  - Zero new dependencies; git remains the single source of truth — "the way Git sees it" by construction: untracked dotfiles included (git does not ignore them), tracked-ignored included (ignore never applies to tracked), nested repos collapsed, per-directory `.gitignore` honored, no `.git`-contents risk ever.
  - Reuses the existing NUL-safe parsing and `accept_record` validation verbatim — smallest diff.
  - Determinism is trivial: one sorted output, no union.
  - Fast: git's C-level worktree walk (tens of ms on 50k files) — KPI 1 unaffected.
  - Less test surface than the hybrid (no semantic reconciliation tests).
- Cons:
  - Diverges from the pinned architecture's literal implementation note ("+ ignore walker") — needs an ARCHITECTURE.md note/ADR touch by design-architecture (the architecture's *rationale* — "use git itself, don't re-invent git" — is actually served better by this approach; only the literal text changes).
  - `.sentinelignore` with git-native precedence sits at the *low* end (core.excludesFile) — or command-line precedence via `--exclude-from`; precedence vs. `.gitignore` differs from the hybrid and must be pinned by a test.
  - If `.sentinelignore` must also exclude **tracked** files (git ignore rules never apply to tracked), a post-union filter is needed (matcher over the final file set) — this requirement erodes B's simplicity advantage.
  - No built-in size guard; keep the guard in the read path (`lib.rs`), which is arguably better anyway because it can emit a deterministic `skipped-large` diagnostic instead of the walker's silent skip.
- Effort: Low-Medium.

### 3. Pure walker (drop `git ls-files`) — rejected

A filesystem walker has no index concept: forced-tracked-ignored files (`git add -f`) would silently disappear from the file set, violating "the way Git sees it", the pinned architecture, and the empty-repo/nested-repo semantics that git gives for free. No advantage over Approach 1.

### Recommendation

**Approach 1 (hybrid, as pinned in ARCHITECTURE.md)**, with the mandatory `hidden(false)` setting, union-with-ls-files (tracked wins), and three explicit policy tests: `.git` never walked, nested repos skipped, `.sentinelignore` precedence pinned. It avoids architecture churn, delivers the intended custom-ignore precedence and built-in size guard, and the ls-files side guarantees tracked-file correctness.

**Approach 2 (git-only extension) is the strong alternative** and materially cheaper (no new dependency, smallest diff, strictest git semantics). The deciding factors for the proposal: (a) whether the `ignore` dependency is acceptable to the maintainer; (b) whether `.sentinelignore` must be able to exclude tracked files (if yes, B needs a matcher and loses most of its simplicity advantage); (c) tolerance for a small ARCHITECTURE.md note if B is chosen. Both are viable; sdd-propose/design should pin one, not mix.

## Product / Business Rules and Decisions to Pin at Proposal

1. **`.sentinelignore` scope**: does it apply to the full file set (tracked + untracked) or only untracked candidates? Recommendation: full set — a tool-owned exclusion list should let a user exclude a tracked fixture file; both approaches can implement it, A more naturally. Pinned name `.sentinelignore` (foundation proposal decision 3).
2. **Default (non-CI) ignore behavior**: git-natural (`--exclude-standard` semantics: global + info/exclude + per-directory) vs. always-hermetic (repo-local only). Recommendation: git-natural locally, hermetic under `--ci` — matches PRD wording ("hermetic scans" are the CI property) and keeps local scans least-surprising. Determinism caveat: two developers with different global excludes can get different file sets locally; CI is the authoritative gate and is hermetic.
3. **Hidden files**: untracked dotfiles MUST be scanned (git parity) — `hidden(false)`. No opt-out flag in this change.
4. **Nested git repos** (submodules or plain nested repos): skip the whole directory (git treats them as opaque units; a per-repo scanner should not double-scan). Requires a walker-side policy + test in Approach 1.
5. **Max-file-size guard value**: default (e.g. 10 MiB, consistent with "bounded traversal") — skip with a deterministic `skipped-large` diagnostic on stderr, exit code unaffected (mirrors the existing `read-failed` pattern).
6. **`--ci` semantics**: adds hermetic ignore behavior; must NOT imply CI-blocking/exit-policy changes (blocking is a later slice; exit 0/1/2 unchanged).
7. **Explicit CLI exclusions** (glob patterns): deferred out of this change (see Non-Goals) — the archived follow-up listed them here, but the current focus does not; keeping them out keeps the slice inside budget.

## Edge Cases

- Untracked file in an ignored directory (e.g. `node_modules/`, `build/`) → must not be scanned.
- Forced-tracked ignored file (`git add -f .env`) → must be scanned (tracked wins over ignore).
- Untracked hidden file (`.env`) not matching any ignore pattern → must be scanned.
- Empty repo with untracked files → scanned normally; exit 0/1 by findings; never an operational error.
- Nested git repo directory → excluded (policy above).
- Symlinked files/dirs → not followed / rejected (existing `accept_record` logic reused); walker must not escape the root.
- `.git` directory contents → never yielded (mandatory test in Approach 1).
- Invalid-UTF-8 / non-ASCII / newline / space paths in untracked files → preserved (NUL-safe records from git; OsString from walker).
- Ignored directory that is itself a tracked path (e.g. a tracked file inside an ignored dir added with `-f`) → tracked side wins.
- `.sentinelignore` precedence vs. `.gitignore` negation (`!`) → pinned by a test per approach.
- Broken symlink or unreadable untracked file → warn + continue (existing diagnostic pattern), exit unaffected.

## Testable Acceptance Candidates

1. Untracked non-ignored file containing a synthetic secret → finding reported, exit 1 (the core gap closure).
2. Untracked file matching the repo `.gitignore` → not scanned (no finding, clean exit).
3. Untracked file inside an ignored directory → not scanned.
4. Untracked hidden file `.env` not matching any pattern → scanned (git parity; catches the `hidden(false)` trap).
5. Forced-tracked ignored file (`git add -f`) → scanned.
6. `.sentinelignore` at repo root excluding a path → excluded per the pinned scope decision (tracked/untracked/both).
7. `--ci`: global excludes (`core.excludesFile`), `.git/info/exclude`, and a parent-dir `.gitignore` above the root have **no effect**; same scan without `--ci` shows the pinned default behavior.
8. Nested git repo directory → excluded (no findings from inside it).
9. Repeated scans byte-identical (existing determinism gate extended to untracked/ignored mixes); 1-vs-N Rayon threads byte-identical.
10. Oversized file (> guard) → skipped, deterministic `skipped-large` stderr diagnostic, exit code unaffected.
11. Symlink / broken-symlink entries → not scanned, no crash, scan completes.
12. Empty repo with untracked files → scan proceeds, correct exit.
13. Non-repo / git missing → exit 2 unchanged.
14. `--ci` accepted (removed from the rejected-args lists in `src/lib.rs` and `tests/cli.rs`); other unsupported flags still rejected with usage error, exit 2.

## Performance Implications

- Approach 1: parallel walk of the worktree + one git spawn; stat cost is inherent; `max_filesize` check is per-entry; comfortably inside the sub-minute KPI on 50k files. Approach 2: one git subprocess; `ls-files --others` is a C-level index+worktree walk (~tens of ms at 50k files). Neither approach risks KPI 1; the read + detection phase dominates either way.
- Determinism is preserved by collecting then sorting the file set (existing `files.sort()` pattern); Rayon parallelism lives only in the read/detect stage, never in enumeration.

## Migration & Compatibility

- **Behavior change (intended)**: previously-invisible untracked files are now scanned — scans can surface new findings (e.g. local scratch files not yet gitignored). This is the product intent; call it out in the proposal and PR description.
- `--ci` changes from a rejected flag to a supported flag — three existing tests assert it is a usage error and MUST be updated (deliberate, in-scope test changes).
- No change to the findings model, fingerprint format, ordering contract, renderers, or exit-code contract; existing goldens are unaffected (golden repos are fully tracked).
- README.md is stale at the top level ("bootstrap/planned", "no Cargo.toml") — a docs-updater concern for a later slice, NOT this change (docs untouched by exploration).
- No migration of persisted state (none exists beyond the future XDG cache).

## Risks

- **Hidden-file trap (Approach 1)**: the `ignore` crate's `hidden(true)` default silently excludes untracked dotfiles — the single most dangerous silent behavior in this change; mitigated by mandatory `hidden(false)` + acceptance candidate 4.
- **Walker/git semantic divergence (Approach 1)**: `.git` contents, nested repos, Windows case-insensitivity; mitigated by explicit policy tests (candidates 4, 8, plus a `.git`-never-walked test).
- **New dependency review (Approach 1)**: `ignore` + transitive crates must pass `cargo deny check` (MIT/Apache-2.0 allowed) and `cargo audit`; small, established, BurntSushi-maintained.
- **`.sentinelignore` precedence ambiguity** across approaches — pin with a test before implementation.
- **Budget**: Medium-High effort; realistic forecast 700–900 authored lines including tests → exceeds the 400-line CI per-PR cap → expected **2 chained PRs** (e.g. #1 discovery expansion + `--ci` + unit tests; #2 integration/hermetic/`.sentinelignore`/size-guard tests + fixtures) within the 800-line session budget. Exact forecast belongs to sdd-tasks.
- **Behavior change surprise**: untracked files now produce findings — users of the current tracked-only behavior may see new output; addressed by the proposal/PR messaging (Migration section).

## Non-Goals (explicit)

- Dependency/OSV scanning, JSON/SARIF output, `--report`, `--explain` (later slices; untouched here).
- Explicit CLI exclusion globs (`--exclude`-style flags) — deferred; keeping this slice tight.
- Tree-sitter/rules engines, clap_complete, blocking/CI exit-policy changes.
- Any change to the findings model, fingerprint format, ordering contract, or exit-code contract.
- Docs/README rewrites (docs-updater owns; out of scope for exploration and for this change).
- No speculative abstractions: no new traits, no config plumbing beyond `--ci`.

## Ready for Proposal

**Yes.** The orchestrator should tell the user: exploration completed for `sentinel-discovery-hardening`; recommended scope is untracked + ignore-aware worktree discovery, `--ci` hermetic mode, `.sentinelignore`, and the max-file-size guard, delivered as ~2 chained PRs; the two approach options are the pinned hybrid (ignore crate walker + ls-files) vs. a cheaper git-only extension — the proposal must pin one, plus the three product decisions: `.sentinelignore` scope (recommend full file set), default non-CI ignore behavior (recommend git-natural), and nested-repo policy (recommend skip).
