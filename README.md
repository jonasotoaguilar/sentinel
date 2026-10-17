# Sentinel

Sentinel is a cross-platform Rust CLI that scans Git repositories for secrets and vulnerable dependencies before commit or in CI.

> **Status: MVP implemented.** Sentinel scans Git repositories for secrets, vulnerable dependencies, and code-rule violations. The commands below are shipped functionality; the roadmap (rules engine, explain adapter, shell completions) is delivered on `main`.

## What Is This?

Sentinel runs a scan over a Git repository and reports findings in a reviewable form:

- **Secrets & credentials** — detection of API keys, tokens, and other credentials in tracked files.
- **Vulnerable dependencies** — review of declared dependencies against the OSV API v1 advisory database.
- **Deterministic rules** — Tree-sitter AST rules for JavaScript/TypeScript and Python.
- **Multiple outputs** — human-friendly terminal output, versioned JSON, and SARIF 2.1.0 for CI integrations.
- **Optional `--explain`** — an opt-in LLM adapter that adds context to findings. It is advisory only: it never sets severity or blocking, redacts secrets, limits context size, and is disabled by default in CI and offline mode.

## MVP Capabilities

- Git-aware discovery: scans the repository the way Git sees it (via `git` itself).
- Parallel detector engines (secrets, dependency review, rule-based analysis).
- Stable fingerprinting and deduplication of findings across runs and engines.
- In-memory scan with an XDG cache; no database.
- CLI: Clap with shell completions.
- Output: terminal, versioned JSON, SARIF 2.1.0.

### Non-Goals (MVP)

- Auto-fixing or remediating findings.
- Interactive/daemon mode or background watching.
- Languages beyond the initial JavaScript/TypeScript and Python rule sets.
- Any network service, server, or hosted backend.

## Install

You do not need a Rust toolchain or a clone to use Sentinel. Pick one of these:

### Release archive (no Rust toolchain needed)

Download the archive for your platform from [the latest release](https://github.com/jonasotoaguilar/sentinel/releases/latest), unpack it, and put the `sentinel` binary on your `PATH`. Each release publishes one archive per supported platform plus a checksums file:

- `sentinel-<tag>-x86_64-unknown-linux-gnu.tar.gz` → `sentinel` (Linux x86_64)
- `sentinel-<tag>-aarch64-apple-darwin.tar.gz` → `sentinel` (macOS Apple silicon)
- `sentinel-<tag>-x86_64-pc-windows-msvc.zip` → `sentinel.exe` (Windows x86_64)
- `sentinel-<tag>-checksums.txt` — sha256 checksums for the archives
- `sentinel-<tag>-sbom.json` — a CycloneDX 1.3 SBOM of the build

Verify a download before running it. The checksums catch a corrupted transfer,
and the attestation proves the file was built by this repository's release
workflow rather than merely uploaded somewhere:

```bash
sha256sum -c sentinel-<tag>-checksums.txt

# needs GitHub CLI 2.49 or newer
gh attestation verify sentinel-<tag>-x86_64-unknown-linux-gnu.tar.gz \
  --repo jonasotoaguilar/sentinel
```

The provenance is keyless: it is bound to the release workflow's own identity
through OpenID Connect, so there is no signing key to distribute or trust
separately, and nothing for this project to keep secret. The SBOM is generated
at release time and describes the dependency view of the publishing runner,
which is the trade a single SBOM per release makes.

### From crates.io (needs a Rust toolchain)

```bash
cargo install sentinel-scan
```

The package is called `sentinel-scan` because the name `sentinel` is already taken on crates.io by an unrelated project; the binary it installs is still named `sentinel`, so every `sentinel ...` command below works as written.

## First scan

From inside any Git repository:

```bash
sentinel scan
```

To check a different checkout without leaving the current directory, pass its path (default `.`, so the command above is unchanged):

```bash
sentinel scan ../other-repo
```

The scan obeys the *target's* checkout: its `sentinel.toml`, its `.sentinelignore`, and `--ci` hermeticity all apply at the target, never at the invoking directory.

On a clean checkout the scan reports nothing and exits 0. When there are findings, each one prints as a location line plus its redacted evidence:

```text
env.example:1:11: high SECRET-synthetic-token: synthetic test token
  [REDACTED]
  evidence: [REDACTED]
```

Secret values are always shown as `[REDACTED]`; what you see is where the finding is, not the secret itself.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | The scan completed and no finding reached the failure threshold. |
| 1 | The scan completed and reported a finding at or above the failure threshold. |
| 2 | The scan did not run: a usage error (unknown flag, `--report` with terminal output, missing subcommand), neither the cwd nor the `[PATH]` target inside a Git repository, `git` unavailable, or the report could not be rendered or written. |

The failure threshold is set with `--fail-under <critical|high|medium|low|none>` (or the `fail_under` key in `sentinel.toml` / the user config; the flag wins over project config, which wins over user config). It names the lowest severity that exits 1: `--fail-under high` fails on high and critical findings and ignores medium and low; `none` is report-only and exits 0 whenever the scan completed. The default is `low`, so any finding exits 1 — today's behaviour.

Findings listed in a [baseline](#baseline-of-accepted-findings) still report, but they never count toward the threshold: accepting a finding quiets the build without hiding the finding.

Diagnostics (warnings such as skipped files or degraded advisory data) go to stderr and never change these codes: a completed scan exits 1 with unaccepted findings at or above the threshold and 0 otherwise, however many warnings were printed.

## Output formats

- **terminal** (the default): human-friendly output for reading in a terminal, one block per finding. Only stdout content is the report; diagnostics go to stderr, so the report can be redirected safely.
- **json** (`--output json`): versioned JSON (`schema_version` plus tool name/version and the findings list) for scripts and other tooling to consume.
- **sarif** (`--output sarif`): SARIF 2.1.0 for CI ingestion, e.g. uploading to GitHub code scanning.

Add `--report <PATH>` (with `json` or `sarif`) to write the machine-readable report to a file instead of stdout.

## Baseline of accepted findings

A repository can accept findings it has decided to live with, so adoption is incremental without editing code:

```bash
# Accept every current finding: writes the file, then reports against it
sentinel scan --baseline sentinel-accepted.json --update-baseline

# Later scans still report the accepted findings (marked `[accepted]`),
# but they never count toward --fail-under
sentinel scan --baseline sentinel-accepted.json
```

The file is JSON under the same `schema_version` envelope as the JSON report:

```json
{"schema_version":"1.0.0","tool":{"name":"sentinel","version":"0.1.0"},"fingerprints":["secrets/SECRET-synthetic-token/9f2c…"]}
```

Entries are keyed on finding fingerprints with the location removed (engine, rule id, content digest), so a renamed or moved file stays accepted while changed content reports fresh. The same file is selectable as the `baseline` key in `sentinel.toml` (or the user config); the flag wins over project config, which wins over user config. A fingerprint in the file matching no current finding warns once as `baseline-stale` on stderr — a baseline that only grows is a baseline nobody prunes. `--update-baseline` rewrites the file it is given (pruning stale entries) and reports what it wrote as `baseline-updated`; it is the only write the tool performs besides the XDG cache. An unreadable or malformed file warns once as `baseline-invalid` and the scan continues with nothing accepted.

## Cache management

The XDG advisory cache is the only state Sentinel keeps. It is visible and manageable:

- `sentinel cache path` prints the resolved location, so the cache can be inspected.
- `sentinel cache clear` empties it and reports the removed entry count and reclaimed bytes; clearing an empty or missing cache succeeds and reports zero.
- `sentinel cache prune` removes entries not used since `--older-than <DAYS>` days (default 30, last use approximated by modification time) and reports what it removed; a prune that removes nothing succeeds and reports zero.
- `sentinel scan --no-cache` skips the cache entirely — no reads, no writes — and reports the same findings as a scan with a warm cache.

Safety: destructive commands delete only inside the resolved cache directory (resolved first, containment-checked, then deleted), never follow symlinks out of it, never remove the directory the process is standing in or anything above it, and refuse with a clear error when the resolved location looks wrong (empty, the filesystem root, or unavailable).

Under `--offline` the cache is the only source of advisory data, so `sentinel scan --offline --no-cache` degrades to `osv-unavailable` warnings for every dependency pin while secrets findings still report — the combination is allowed and never fails the scan on its own.

## Quick Start (from source)

Build and run from this repository (`cargo run -- <args>`); the usage below is shipped:

```bash
# Scan the current repository (git-aware discovery: tracked + untracked files, ignore-aware)
sentinel scan

# Scan a different checkout (its own sentinel.toml and .sentinelignore apply)
sentinel scan ../other-repo

# Hermetic CI scan: ignores parent/global gitignore sources; repository-local rules only
sentinel scan --ci

# Exclude files by glob (repeatable; `.gitignore` semantics, repo-relative paths)
sentinel scan --exclude '*.log' --exclude 'build/'

# Fail the build only on high or critical findings (`none` is report-only;
# default `low` means any finding exits 1). Accepted baseline findings never
# count toward the threshold, whatever the level.
sentinel scan --fail-under high

# Accept every current finding, then enforce the baseline on later scans
sentinel scan --baseline sentinel-accepted.json --update-baseline
sentinel scan --baseline sentinel-accepted.json

# The same excludes live in `sentinel.toml` at the repository root
# (`exclude = ["*.log"]`), with a user-level file at
# `$XDG_CONFIG_HOME/sentinel/config.toml` — or `SENTINEL_CONFIG` to pin
# an explicit file instead (e.g. in CI); precedence is CLI flag >
# project config > user config > built-in default, and exclude lists
# union across levels while scalar keys (`fail_under`, `baseline`) override.
# A bad config warns once and never aborts.

# Write SARIF 2.1.0 for CI ingestion
sentinel scan --output sarif --report sentinel.sarif

# Versioned JSON for tooling
sentinel scan --output json

# Opt-in LLM context for findings (never sets severity; redacted; off in CI/offline)
sentinel scan --explain

# Offline: cache only, warns/skips when advisory data is unavailable
sentinel scan --offline

# See and manage the XDG advisory cache (the only state Sentinel keeps)
sentinel cache path
sentinel cache prune --older-than 7
sentinel cache clear

# Skip the cache entirely: same findings as a warm-cache scan, no reads, no writes
sentinel scan --no-cache

# Shell completions (bash, zsh, fish, powershell, elvish)
eval "$(sentinel completions bash)"
```

## Security & Privacy Guarantees

- `--explain` output is **advisory only**: it never sets severity or blocking decisions.
- Secret values are **redacted** before any LLM context is sent; context is limited to the minimum needed.
- `--explain` is **disabled by default** in CI and offline mode.
- Scans run in memory (no SQL/NoSQL); the only persistent state is the XDG cache.
- External data (OSV advisories, LLM responses) is treated as **untrusted** and sanitized before it reaches output or analysis.
- Offline mode serves from cache and warns/skips gracefully when data is unavailable.

## Developer Commands

```bash
cargo test          # unit + integration (assert_cmd / insta / tempfile)
cargo clippy -- -D warnings
cargo fmt --check
cargo audit         # advisory scan of Sentinel's own dependencies
cargo deny          # license / dependency policy check
```

Releases are **not signed with a long-lived key**, deliberately: provenance comes from a keyless attestation bound to the release workflow's identity, which is verifiable with `gh attestation verify` (GitHub CLI 2.49+). Every release ships three platform archives, a checksums file, and a CycloneDX SBOM, and all five files carry the attestation.

## Stack

| Area | Choice |
|------|--------|
| Language | Rust (Edition 2024), single crate |
| CLI | Clap + clap_complete |
| Concurrency | Rayon (parallel detector engines) |
| Files | ignore, regex, Tree-sitter |
| HTTP (sync) | ureq |
| Data | serde / serde_json / toml; XDG cache; no database |
| Errors / logging | thiserror; diagnostics on stderr, no logging framework |
| Testing | cargo test, assert_cmd, insta, tempfile |
| CI / releases | GitHub Actions, upload-sarif, cargo-audit/cargo-deny, signed/checksummed/SBOM artifacts |

## Details

| Topic | Decision |
|-------|----------|
| Audience | Developers and CI pipelines that want pre-commit and in-CI security review |
| Runtime | Cross-platform Rust binary (single crate) |
| Architecture intent | Git-aware discovery → parallel detector engines → stable fingerprint/dedupe → renderers; sync/stdio; `git` invoked via `std::process::Command` |
| Deep docs | [PRD](./PRD.md) · [ARCHITECTURE.md](./ARCHITECTURE.md) |

## License

MIT — see [LICENSE](./LICENSE) for details.
