# Continuous integration

Run Sentinel where code lands: GitHub Actions, GitLab CI, pre-commit, or
any container. Every setup below uses the hermetic `--ci` scan (parent,
global, and `.git/info/exclude` ignores disabled) and fails the job on
findings through the normal exit codes (0 clean, 1 findings, 2 did not
run). For what those codes and the output formats mean, see
[Usage](USAGE.md).

## GitHub Actions

Use the reusable action in `.github/actions/sentinel-scan`: it resolves a
release, verifies the download against the release checksums (and the
attestation when `gh` is available), scans with
`sentinel scan --ci --output sarif`, uploads the SARIF to code scanning,
and exposes the result as outputs. Copy
`examples/github-actions/scan.yml` to `.github/workflows/sentinel.yml`:

```yaml
- id: scan
  name: Scan with Sentinel
  uses: jonasotoaguilar/sentinel/.github/actions/sentinel-scan@v0.2.0
  with:
    version: latest
    fail-on-findings: true
    upload-sarif: true
```

Inputs are `version` (a tag or `latest`), `fail-on-findings`
(`false` still reports and uploads but passes the job; exit 2 always
fails), and `upload-sarif` (needs `security-events: write` on the job).
Outputs are `exit-code`, `findings-count`, and `sarif-file` for later
steps, for example a summary comment. The workflow example reports all
three with `if: always()` so the outcome is visible even on failure.

## GitLab CI

Include the documented template (GitLab 16.11 or newer for `include`
inputs; 15.0 or newer for the SARIF report):

```yaml
include:
  - remote: https://raw.githubusercontent.com/jonasotoaguilar/sentinel/main/ci/gitlab/sentinel.gitlab-ci.yml
    inputs:
      fail_under: high
```

Inputs are `stage`, `path`, `fail_under`, `version`, and `job_name`
(defaults: `test`, `.`, `low`, `latest`, `sentinel`). The job downloads
the release archive for the runner, checks it against the release
checksums, runs `sentinel scan --ci --output sarif`, and always exposes
`sentinel.sarif` as an artifact and a SARIF report so findings render in
merge requests.

## Pre-commit

`.pre-commit-hooks.yaml` ships the `sentinel` hook (`language: rust`,
`entry: sentinel scan --ci`): it scans the whole repository rather than
the staged filenames, so it passes no filenames and always runs. Enable
it with a Rust toolchain on the machine that commits:

```yaml
repos:
  - repo: https://github.com/jonasotoaguilar/sentinel
    rev: v0.2.0
    hooks:
      - id: sentinel
```

The hook runs the same hermetic scan as CI; accept findings through a
committed baseline (`examples/baseline`) rather than excludes when the
goal is incremental adoption.

## Docker and other pipelines

A Docker image published per release covers pipeline users who do not
want to install anything. Until a release pins the image name, any OCI
runner can execute the verified release archive directly, which is all
the image wraps:

```bash
curl -fsSL -o sentinel.tar.gz \
  https://github.com/jonasotoaguilar/sentinel/releases/download/<tag>/sentinel-<tag>-x86_64-unknown-linux-gnu.tar.gz
curl -fsSL -o sentinel-checksums.txt \
  https://github.com/jonasotoaguilar/sentinel/releases/download/<tag>/sentinel-<tag>-checksums.txt
grep " ${ASSET}$" sentinel-checksums.txt | sha256sum -c --strict -
tar xzf sentinel.tar.gz && install -m 0755 sentinel /usr/local/bin/sentinel
sentinel scan --ci --output sarif --report sentinel.sarif
```

Set `SENTINEL_CONFIG` to pin the user config level to an explicit file
in ephemeral runners instead of relying on `$XDG_CONFIG_HOME`, and use
`--offline` only with a pre-seeded cache (see [Usage](USAGE.md)): without
one, dependency review degrades to `osv-unavailable` warnings by design.
