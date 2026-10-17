# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The versioning policy below is the project's single versioning policy: no other
versioning or release policy exists in this repository (`.github/workflows/release.yml`
documents release mechanics — archive layout and checksums — not versioning).

## [0.2.0] - 2026-10-17

Adoption controls and a release you can verify. Nothing about scanning changed
in this release; what changed is what you can tell Sentinel to do and what you
can prove about the binary you downloaded.

### Added

- **Configuration files.** `sentinel.toml` in the repository and a user config
  under `$XDG_CONFIG_HOME/sentinel/config.toml`, resolved as
  CLI > project > user > default. List keys union across levels; scalar keys
  override. `$SENTINEL_CONFIG` names an explicit file.
- **`--exclude <GLOB>` (repeatable) and `.sentinelignore`**, so files a project
  does not consider its own can be left out of the scan.
- **`--fail-under <critical|high|medium|low|none>`**, so a pipeline decides
  which severities block it. The default, `low`, is the previous behaviour:
  any finding exits 1.
- **`scan [PATH]`**, so a scan can target another checkout without changing
  directory, with that target's own config, ignore file and CI mode applied.
- **`--baseline <PATH>` and `--update-baseline`.** Accepted findings are
  recorded by content (engine, rule and digest), so acceptance survives a
  rename, a move or a shifted line. They are still reported — marked
  `[accepted]`, `"accepted": true` in JSON, and as SARIF suppressions — but they
  no longer fail the build. The documented trade: the same value and rule is
  accepted everywhere it appears.
- **`cache path`, `cache clear`, `cache prune [--older-than <DAYS>]` and
  `scan --no-cache`.** The only destructive command states its safety model:
  the root is validated, every candidate is checked for containment, symlinks
  are unlinked rather than followed, the cache root itself is never removed, and
  the command refuses to run when the working directory is inside the cache.
- **Verifiable releases.** Every release now carries a keyless build-provenance
  attestation and a CycloneDX SBOM attestation, verifiable with
  `gh attestation verify`. No signing key exists to rotate or leak.
- **Repository hygiene:** Dependabot updates grouped by week, a code of conduct,
  and a dependency policy in `SECURITY.md` that points at `deny.toml` as the
  enforced source of truth.

### Fixed

- `SECURITY.md` no longer claims that no releases have been published.

## [0.1.0]

First installable release. Sentinel is a cross-platform, single-crate Rust CLI
that scans a Git repository for secrets and vulnerable dependencies before commit
or in CI, with no server and no database.

- Git-aware discovery of repository files (tracked plus untracked, ignore-aware;
  hermetic ignore handling under `--ci`).
- Secret and credential detection with secret values always shown as `[REDACTED]`.
- Vulnerable-dependency review against the OSV API v1, served through an XDG
  cache; `--offline` runs from cache only and warns/skips when data is missing.
- Deterministic Tree-sitter AST rules for JavaScript/TypeScript and Python.
- Stable fingerprinting and deduplication of findings across engines and runs.
- Outputs: human-friendly terminal (the default), versioned JSON for tooling,
  and SARIF 2.1.0 for CI ingestion; diagnostics go to stderr.
- CLI: `sentinel scan` and `sentinel completions <shell>` (bash, zsh, fish,
  powershell, elvish); `--help` and `--version` print and exit 0.
- Optional `--explain`: an opt-in LLM adapter that adds one advisory line per
  finding on terminal output only. It never sets severity or blocking, is
  forced off under `--ci`/`--offline`, and leaves JSON/SARIF byte-identical.
- Exit codes: 0 for a clean scan, 1 when findings are reported, 2 when the
  scan did not run (usage error, not a repository, `git` unavailable, or an
  unwritable report).
- Installable two ways: per-platform release archives with sha256 checksums
  from [the `v0.1.0` release](https://github.com/jonasotoaguilar/sentinel/releases/tag/v0.1.0),
  or `cargo install sentinel-scan` (the binary is still named `sentinel`).

### Versioning policy

- This project follows semantic versioning (`MAJOR.MINOR.PATCH`).
- For this CLI, a **breaking change** — one that raises the major version —
  is any of: a removed or renamed flag, subcommand, or shell-completion target;
  a changed exit code; a changed machine-readable output format (the JSON
  `schema_version` envelope or the SARIF shape); or a raised MSRV
  (`rust-version` in `Cargo.toml`).
- New detections, new rules, and new diagnostics are not breaking: they add
  findings or stderr lines within the existing contract.
- **`1.0.0` will mean the CLI contract is stable**: flags, subcommands, exit
  codes, and output schemas keep working as documented, and later releases
  stay compatible with them. Until then, `0.x` releases may still adjust the
  surface, always recorded here.

[Unreleased]: https://github.com/jonasotoaguilar/sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jonasotoaguilar/sentinel/releases/tag/v0.1.0
