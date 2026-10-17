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

Verify a download before running it:

```bash
sha256sum -c sentinel-<tag>-checksums.txt
```

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
| 0 | The scan completed and found nothing. |
| 1 | The scan completed and reported findings. |
| 2 | The scan did not run: a usage error (unknown flag, `--report` with terminal output, missing subcommand), not inside a Git repository, `git` unavailable, or the report could not be rendered or written. |

Diagnostics (warnings such as skipped files or degraded advisory data) go to stderr and never change these codes: a completed scan exits 1 with findings and 0 without them, however many warnings were printed.

## Output formats

- **terminal** (the default): human-friendly output for reading in a terminal, one block per finding. Only stdout content is the report; diagnostics go to stderr, so the report can be redirected safely.
- **json** (`--output json`): versioned JSON (`schema_version` plus tool name/version and the findings list) for scripts and other tooling to consume.
- **sarif** (`--output sarif`): SARIF 2.1.0 for CI ingestion, e.g. uploading to GitHub code scanning.

Add `--report <PATH>` (with `json` or `sarif`) to write the machine-readable report to a file instead of stdout.

## Quick Start (from source)

Build and run from this repository (`cargo run -- <args>`); the usage below is shipped:

```bash
# Scan the current repository (git-aware discovery: tracked + untracked files, ignore-aware)
sentinel scan

# Hermetic CI scan: ignores parent/global gitignore sources; repository-local rules only
sentinel scan --ci

# Write SARIF 2.1.0 for CI ingestion
sentinel scan --output sarif --report sentinel.sarif

# Versioned JSON for tooling
sentinel scan --output json

# Opt-in LLM context for findings (never sets severity; redacted; off in CI/offline)
sentinel scan --explain

# Offline: cache only, warns/skips when advisory data is unavailable
sentinel scan --offline

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

Releases are planned to be signed, checksummed, and shipped with an SBOM.

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
