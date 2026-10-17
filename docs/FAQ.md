# Frequently asked questions

## What does Sentinel scan?

Tracked and untracked files the way Git sees them, across three engines:
secret patterns (API keys, tokens, credentials), dependency review of
pinned manifests against OSV advisories, and deterministic Tree-sitter
rules for JavaScript/TypeScript and Python. Findings are deduplicated by
stable fingerprint and reported once.

## Does it need the network?

Only dependency review does, to query OSV. Secrets and rule findings are
fully local. `--offline` serves advisory data from the XDG cache and
warns (`osv-unavailable`) where the cache has no entry; secrets findings
still report and still fail the build.

## Does it upload my code anywhere?

No. Scans run in memory; the only persistent state is the local XDG
advisory cache. Dependency review sends package names and pinned versions
to OSV (that is what an advisory lookup is); secret values are never
sent anywhere and render only as `[REDACTED]`.

## What does `--explain` send to the LLM?

Opt-in advisory context only: finding identifiers and bounded,
redacted excerpts, never raw secret values. The output is one sanitized
terminal line per finding, capped in length; it never sets severity or
the exit code, and it is forced off under `--ci` and `--offline`. Without
a configured endpoint the scan warns once (`explain-skipped`) and
continues.

## Why did the build fail on a medium finding?

The default policy is `--fail-under low`: any finding exits 1. Raise the
threshold (`--fail-under high`, or `fail_under` in `sentinel.toml`), or
accept the finding into a baseline so it reports without failing. See
[Usage](USAGE.md) and `examples/baseline`.

## How do I quiet a finding without hiding it?

Put it in a baseline: accepted findings keep reporting (marked
`[accepted]`) but never count toward `--fail-under`. Use `--exclude`
only for files that should never be scanned (generated code, vendored
trees), not for findings you have reviewed.

## Which platforms and toolchains are supported?

Linux and macOS and Windows archives ship per release; `cargo install
sentinel-scan` needs a Rust toolchain. Shell completions cover bash,
zsh, fish, powershell, and elvish (`sentinel completions <shell>`).

## Where are the man pages?

Generated from the CLI itself with `clap_mangen` and committed under
`man/man1` (`sentinel.1`, `sentinel-scan.1`, and one per subcommand).
After a CLI change, `cargo test --test man_pages -- --ignored`
regenerates them, and the drift test fails until they are committed.

## Does Sentinel fix findings?

No. It reports; remediation stays with the developer. There is no
interactive mode, no daemon, and no hosted backend.
