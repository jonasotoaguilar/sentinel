# Troubleshooting

Every entry is `symptom` → `cause` → `fix`. Diagnostics go to stderr;
the report on stdout is never polluted by them, and diagnostics never
change the exit code of a completed scan (0 or 1). Exit 2 always means
the scan did not run.

## `not inside a git repository` (exit 2)

Sentinel scans the Git repository enclosing the target, not arbitrary
directories. Run inside a checkout, or pass a path inside one
(`sentinel scan ../other-repo`). Nested repositories are skipped: the
outermost enclosing repository wins.

## `git` unavailable (exit 2)

Discovery shells out to `git`. Install it and ensure it is on `PATH`;
there is no fallback discovery.

## `--report` with terminal output (exit 2)

`--report <PATH>` needs `--output json` or `--output sarif`; terminal
output is stdout by design. Either drop `--report` or add a
machine-readable `--output`.

## `--update-baseline` without a path (exit 2)

The command needs a file to rewrite: pass `--baseline <PATH>` or set the
`baseline` key in `sentinel.toml`. It is the only write the tool
performs besides the cache.

## `baseline-invalid` warning

The baseline file cannot be read or parsed. The scan continues with
nothing accepted, so a typo never silently passes. Fix the JSON or
remove the file (or the `baseline` key) to silence the warning.

## `baseline-stale` warning

A fingerprint in the file matches no current finding. Re-run with
`--update-baseline` to prune it; a baseline that only grows is a
baseline nobody prunes.

## `osv-unavailable` warnings

No advisory data for a pin: offline without a cached entry, or
`--no-cache` under `--offline`. Secrets findings still report. Seed the
cache with one online scan, or accept that ephemeral offline runners
cannot review dependencies.

## `advisory-invalid` / degraded advisories

Live OSV data the validator refuses is skipped with a warning and the
affected pin reports nothing rather than something wrong. The scan still
exits 0 or 1; only the missing finding is lost, and the warning says so.

## `version-unpinned-skipped`

Unpinned dependencies (ranges, bare names) carry nothing to look up, so
they are skipped with a path and line. Pin the dependency to review it.

## `skipped-large` / `read-failed`

Files over the 10 MiB scan limit are skipped, not truncated; unreadable
files warn and the scan continues. Both name the path (redacted when it
looks secret-bearing).

## Malformed `sentinel.toml` warns once, scan continues

Configuration never aborts a scan: the offending level contributes
nothing and the warning names the file. Validate the TOML and the
`exclude` / `fail_under` / `baseline` keys.

## Cache refuses to clear or prune

Destructive cache commands delete only inside the resolved directory and
refuse when it looks wrong (empty, the filesystem root, or containing the
current working directory). Run from another directory, or inspect with
`sentinel cache path` first.

## `explain-skipped` / `explain-failed`

No endpoint configured, or the single request failed or returned a bad
body: advisories are terminal-only extras, so machine formats and the
exit code are unaffected. Configure the endpoint or drop `--explain`;
note it is forced off under `--ci` and `--offline` by design.

## Report file cannot be written (exit 2)

The parent directory must exist and be writable. Stdout stays empty with
`--report`; check stderr for the reason.
