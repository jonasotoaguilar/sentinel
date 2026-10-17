# Sentinel scan action

A reusable GitHub Action that downloads a verified Sentinel release, scans
the workspace, uploads the SARIF report to code scanning, and maps the scan
exit policy. See [`action.yml`](./action.yml) for the implementation and
[`examples/github-actions/scan.yml`](../../examples/github-actions/scan.yml)
for a complete workflow.

## Usage

```yaml
jobs:
  sentinel:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # required for the SARIF upload
    steps:
      - uses: actions/checkout@v7
      - uses: jonasotoaguilar/sentinel/.github/actions/sentinel-scan@v0.2.0
        with:
          version: latest
```

## Permissions

The calling job needs:

| Permission           | Why                                              |
| -------------------- | ------------------------------------------------ |
| `contents: read`     | Check out the repository (standard).             |
| `security-events: write` | Upload the SARIF report to code scanning.    |

No `id-token` permission is needed: attestation verification only reads the
release attestation through the GitHub API.

## Inputs

| Input              | Description                                                        | Default  |
| ------------------ | ------------------------------------------------------------------ | -------- |
| `version`          | Release tag to scan with (for example `v0.2.0`), or `latest` to resolve the newest release through the GitHub API on `jonasotoaguilar/sentinel`. | `latest` |
| `fail-on-findings` | Fail the workflow when the scan reports findings (exit 1). `false` still reports and uploads, but the job passes. A scan that did not run (exit 2) always fails. | `true`   |
| `upload-sarif`     | Upload the SARIF report to GitHub code scanning.                   | `true`   |

## Outputs

| Output           | Description                                                              |
| ---------------- | ------------------------------------------------------------------------ |
| `sarif-file`     | Absolute path of the SARIF report written by the scan.                   |
| `exit-code`      | Raw sentinel exit code: `0` clean, `1` findings reported, `2` scan did not run. |
| `findings-count` | Number of results in the SARIF report (`0` when the scan did not run).   |

## Verification before running

The action never executes a download it has not checked:

1. The release archive is checked against the release's checksums file
   (`sentinel-<tag>-checksums.txt`, the same file `sha256sum -c` verifies).
2. When the runner's `gh` CLI supports it, the build-provenance attestation
   is verified with `gh attestation verify`. A missing `gh`, a `gh` older
   than 2.49, or an unknown `attestation` subcommand degrades to a warning —
   never a silent skip — because `gh` on GitHub-hosted runners may be older
   than 2.49. A failed verification on a capable `gh` fails the step.

## Exit policy

| Sentinel exit | Meaning              | Action behaviour                                      |
| ------------- | -------------------- | ----------------------------------------------------- |
| `0`           | Clean scan           | Passes.                                               |
| `1`           | Findings reported    | Fails when `fail-on-findings` is `true`, else warns and passes. |
| `2`           | Scan did not run     | Always fails with a clear message.                    |

The scan step itself never fails the job: it records the raw exit code and
the findings count as outputs, and the policy step after the SARIF upload
decides the outcome, so findings are uploaded even when they fail the build.

## Supported runners

Linux X64, macOS ARM64, and Windows X64 — the triples Sentinel releases
ship. Any other `RUNNER_OS`/`RUNNER_ARCH` combination fails with a clear
message instead of downloading the wrong binary.

## Only GitHub-owned and official steps

The action runs as a composite action: shell steps plus
`github/codeql-action/upload-sarif`, which is GitHub's own action and the
only supported way to put SARIF into code scanning. No third-party actions.
