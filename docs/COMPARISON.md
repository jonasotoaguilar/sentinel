# Comparison

How Sentinel differs from tools a reader has heard of. No benchmarks
were run for this page; the differences below are design facts, not
measurements.

## Secret scanners: Gitleaks, TruffleHog, git-secrets

These scan for credentials, each with its own strength: Gitleaks is a
fast, widely-adopted pattern scanner; TruffleHog verifies credentials
against live services and digs history; git-secrets hooks into Git
workflows to stop secrets before they land. Sentinel covers the same
secret-scanning ground with curated patterns and mandatory redaction
(values never appear in output), but it is not a history digger and it
does not verify credentials against third parties: findings are local
and deterministic.

## Dependency auditing: cargo-audit, cargo-deny, Dependabot, OSV-Scanner

cargo-audit and cargo-deny audit Rust dependencies (advisories, licenses,
bans) inside the Cargo ecosystem; Dependabot and Renovate open update
pull requests on a schedule; OSV-Scanner queries the same OSV database
Sentinel uses, across ecosystems. Sentinel's dependency review is the
OSV-backed check without the updater: it reports pinned manifests
(`package-lock.json`, `requirements.txt`) against OSV over the network
or from its local cache, degrades to warnings instead of refusing when
data is unavailable, and skips unpinned entries with a named diagnostic
rather than guessing.

## Pattern and SAST tools: Semgrep, CodeQL

Semgrep expresses custom code rules portably; CodeQL performs deep
whole-program analysis, typically in CI on a schedule. Sentinel's
Tree-sitter rules are the opposite trade: a small built-in set for
JavaScript/TypeScript and Python (weak hashes, dynamic code execution,
shell injection, unsafe deserialization), no custom rule language, no
whole-program model. They catch known-dangerous shapes deterministically
and cheaply, and they never decide the build alone: severity and the
`--fail-under` policy do.

## What Sentinel adds by combining them

One binary, one invocation, three engines, one fingerprint space:
a secret, a vulnerable pin, and a risky call pattern in the same
repository produce one report (terminal, versioned JSON, or SARIF 2.1.0)
with one exit-code contract. Around that sit the adoption pieces:
a baseline of accepted findings so teams go incremental without hiding
anything, layered configuration (flag over project over user) with
unioning excludes, a visible XDG cache with an opt-out, hermetic `--ci`
scans, and an advisory-only `--explain` that can never set severity or
flip an exit code.
