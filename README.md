# Sentinel

Sentinel is a planned cross-platform Rust CLI that scans Git repositories for secrets and vulnerable dependencies before commit or in CI.

> **Status: bootstrap / planned.** This repository currently contains no implementation. Sentinel is an MVP specification; every command and behavior below is the **intended interface**, not shipped functionality. Nothing is installable yet.

## What Is This?

Sentinel runs a scan over a Git repository and reports findings in a reviewable form:

- **Secrets & credentials** — detection of API keys, tokens, and other credentials in tracked files.
- **Vulnerable dependencies** — review of declared dependencies against the OSV API v1 advisory database.
- **Deterministic rules** — regex and Tree-sitter AST rules for an initial set of JavaScript/TypeScript and Python.
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

## Quick Start (placeholder)

Sentinel is **not yet installable** — there is no published crate and no `Cargo.toml` in this repository. Installation instructions will live here once the binary crate exists. The intended usage looks like this:

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
```

These examples describe the planned interface only. They will not run until the MVP is built.

## Security & Privacy Guarantees

- `--explain` output is **advisory only**: it never sets severity or blocking decisions.
- Secret values are **redacted** before any LLM context is sent; context is limited to the minimum needed.
- `--explain` is **disabled by default** in CI and offline mode.
- Scans run in memory (no SQL/NoSQL); the only persistent state is the XDG cache.
- External data (OSV advisories, LLM responses) is treated as **untrusted** and sanitized before it reaches output or analysis.
- Offline mode serves from cache and warns/skips gracefully when data is unavailable.

## Planned Developer Commands

Once the crate exists:

```bash
cargo test          # unit + integration (assert_cmd / insta / tempfile)
cargo clippy -- -D warnings
cargo fmt --check
cargo audit         # advisory scan of Sentinel's own dependencies
cargo deny          # license / dependency policy check
```

Releases are planned to be signed, checksummed, and shipped with an SBOM.

## Planned Stack

| Area | Choice |
|------|--------|
| Language | Rust (Edition 2024), single crate |
| CLI | Clap + clap_complete |
| Concurrency | Rayon (parallel detector engines) |
| Files | ignore, regex, Tree-sitter |
| HTTP (sync) | ureq |
| Data | serde / serde_json / toml; XDG cache; no database |
| Errors / logging | anyhow / thiserror / tracing |
| Testing | cargo test, assert_cmd, insta, tempfile |
| CI / releases | GitHub Actions, upload-sarif, cargo-audit/cargo-deny, signed/checksummed/SBOM artifacts |

## Details

| Topic | Decision |
|-------|----------|
| Audience | Developers and CI pipelines that want pre-commit and in-CI security review |
| Runtime | Cross-platform Rust binary (single crate) |
| Architecture intent | Git-aware discovery → parallel detector engines → stable fingerprint/dedupe → renderers; sync/stdio; `git` invoked via `std::process::Command` |
| Deep docs | [PRD](./PRD.md) · [ARCHITECTURE.md](./ARCHITECTURE.md) (implementation still planned) |

## License

MIT — see [LICENSE](./LICENSE) for details.
