# Baseline workflow example

Accept the findings a repository has decided to live with, so adoption
is incremental: accepted findings still report (marked `[accepted]`)
but never count toward `--fail-under`. Start from the starter file in
this directory or let the tool write it; entries are content digests,
so a renamed file stays accepted while changed content reports fresh.

```bash
# 1. Accept every current finding: writes the file, then reports against it.
sentinel scan --baseline sentinel-accepted.json --update-baseline
# stderr: sentinel: baseline-updated: wrote 1 fingerprint to sentinel-accepted.json
# stdout: token.env:1:24: medium SECRET-synthetic-token: synthetic secret token detected [accepted]
#           SENTINEL_EXAMPLE_TOKEN=[REDACTED]
#           evidence: [REDACTED]
# exit 0: the only accepted finding no longer fails the build.

# 2. Later scans enforce the baseline: new findings still exit 1.
sentinel scan --baseline sentinel-accepted.json

# 3. Prune entries that match nothing anymore (a baseline that only grows
#    is a baseline nobody prunes): re-running --update-baseline rewrites
#    the file with only current findings.
# 4. A fingerprint matching no current finding warns once on stderr as
#    `baseline-stale`; an unreadable file warns once as `baseline-invalid`
#    and the scan continues with nothing accepted.
```

The same file is selectable as the `baseline` key in `sentinel.toml`
(see `../sentinel-toml`); the flag wins over project config, which wins
over user config. `--update-baseline` is the only write the tool
performs besides the XDG cache. Never commit a real secret into this
file: it holds only fingerprints, never values.
