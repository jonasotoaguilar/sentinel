# Usage

Install, first scan, output formats, exit codes, configuration, excludes,
baseline, and cache. For CI wiring see [CI](CI.md); for problems see
[FAQ](FAQ.md) and [Troubleshooting](TROUBLESHOOTING.md).

## Install

No Rust toolchain is needed. Download the archive for your platform from
[the latest release](https://github.com/jonasotoaguilar/sentinel/releases/latest),
verify it, and put the `sentinel` binary on your `PATH`:

```bash
sha256sum -c sentinel-<tag>-checksums.txt

# needs GitHub CLI 2.49 or newer; proves the archive was built by this
# repository's release workflow rather than merely uploaded somewhere
gh attestation verify sentinel-<tag>-x86_64-unknown-linux-gnu.tar.gz \
  --repo jonasotoaguilar/sentinel
```

With a Rust toolchain installed, `cargo install sentinel-scan` installs
the same binary (named `sentinel`; the package name differs because
`sentinel` is taken on crates.io).

Reference pages generated from the CLI itself live in `man/man1`
(`man sentinel`, `man sentinel-scan` once installed to the man path),
and copy-paste starters live in `examples/`.

## First scan

From inside any Git repository:

```bash
sentinel scan
sentinel scan ../other-repo   # scan another checkout without leaving this one
```

The scan obeys the *target's* checkout: its `sentinel.toml`, its
`.sentinelignore`, and `--ci` hermeticity all apply at the target, never
at the invoking directory. On a clean checkout the scan reports nothing
and exits 0. Each finding prints as a location line plus redacted evidence:

```text
token.env:1:24: medium SECRET-synthetic-token: synthetic secret token detected
  SENTINEL_EXAMPLE_TOKEN=[REDACTED]
  evidence: [REDACTED]
```

Secret values always render as `[REDACTED]`; what you see is where the
finding is, never the value. Try it on `examples/basic-scan` (copy its
files into a fresh `git init` checkout first).

## Output formats

- **terminal** (default): one block per finding, for reading. Only the
  report goes to stdout; diagnostics go to stderr, so the report can be
  redirected safely.
- **json** (`--output json`): versioned envelope (`schema_version`, tool
  name and version, finding list) for scripts and other tooling.
- **sarif** (`--output sarif`): SARIF 2.1.0 for CI ingestion, for example
  uploading to GitHub code scanning.

Add `--report <PATH>` (with `json` or `sarif`, never with `terminal`)
to write the machine-readable report to a file instead of stdout.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | The scan completed and no finding reached the failure threshold. |
| 1 | The scan completed and reported a finding at or above the threshold. |
| 2 | The scan did not run: a usage error, not inside a Git repository, `git` unavailable, or the report could not be rendered or written. |

`--fail-under <critical|high|medium|low|none>` names the lowest severity
that exits 1 (`none` is report-only; default `low`, so any finding exits 1).
Baseline-accepted findings still report but never count toward the threshold.
Diagnostics (skipped files, degraded advisory data) go to stderr and never
change these codes.

## Configuration

`sentinel.toml` at the repository root, plus a user file at
`$XDG_CONFIG_HOME/sentinel/config.toml` (or the file `SENTINEL_CONFIG`
points at, for example in CI). Precedence is flag over project config
over user config over built-in default. Lists union across levels while
scalar keys override:

| Key / flag | Kind | Effect |
|------------|------|--------|
| `exclude` / `--exclude <GLOB>` | union | Skip files matching a `.gitignore`-style glob against repo-relative paths. Repeatable on the CLI. |
| `fail_under` / `--fail-under` | override | Exit policy; see above. |
| `baseline` / `--baseline <PATH>` | override | Accepted-findings file; see below. |

A malformed file warns once and never aborts. Start from
`examples/sentinel-toml/sentinel.toml`. Repository-local ignore rules
also live in `.sentinelignore`; `--ci` additionally disables parent,
global, and `.git/info/exclude` ambient ignores for hermetic CI runs.

## Baseline of accepted findings

Accept what the repository has decided to live with instead of editing
code to quiet the build:

```bash
sentinel scan --baseline sentinel-accepted.json --update-baseline
sentinel scan --baseline sentinel-accepted.json
```

The first command rewrites the file with every current finding's
fingerprint (sorted, deduplicated, stale entries pruned) and reports
`baseline-updated` on stderr; it is the only write the tool performs
besides the cache. Accepted findings keep reporting (marked `[accepted]`,
`"accepted": true`, or a SARIF suppression) but never fail the build.
Entries are content digests without the location, so a renamed file stays
accepted while changed content reports fresh. A file entry matching no
current finding warns once as `baseline-stale`. Full workflow and starter
file: `examples/baseline`.

## Cache

The XDG advisory cache is the only state Sentinel keeps:

- `sentinel cache path` prints the resolved location.
- `sentinel cache clear` empties it and reports entries and bytes reclaimed.
- `sentinel cache prune --older-than <DAYS>` (default 30) removes entries
  unused since the given age; a prune that removes nothing still exits 0.
- `sentinel scan --no-cache` skips the cache entirely with identical
  findings; under `--offline` it degrades dependency review to
  `osv-unavailable` warnings while secrets findings still report.

Destructive commands delete only inside the resolved cache directory,
never follow symlinks out of it, and refuse rather than guess when the
location looks wrong.
