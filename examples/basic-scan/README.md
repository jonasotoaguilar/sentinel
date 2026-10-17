# Basic scan example

A minimal repository a reader can copy to try every output format. Every
value is synthetic: `sk-synthetic-1234567890` matches the documented
example pattern and `requests==2.31.0` is an ordinary pinned dependency.
Copy the two data files out of this repository, make a Git checkout, and scan:

```bash
mkdir demo && cp token.env requirements.txt demo/ && cd demo
git init -q . && git add -A && git commit -qm demo
sentinel scan
```

Terminal output (stdout; exit 1 because findings reach the default
`low` threshold):

```text
requirements.txt:1:1: medium OSV-PYSEC-2026-1872: PyPI requests@2.31.0 is affected by OSV-PYSEC-2026-1872
  requests==2.31.0
  evidence: Requests vulnerable to .netrc credentials leak via malicious URLs
...
token.env:1:24: medium SECRET-synthetic-token: synthetic secret token detected
  SENTINEL_EXAMPLE_TOKEN=[REDACTED]
  evidence: [REDACTED]
```

Advisory identifiers and counts come from live OSV data and change over
time; the elided lines above are further `requirements.txt` findings in
the same shape. Diagnostics (for example degraded-advisory warnings)
go to stderr and never change the exit code. The secret value itself is
never printed: only its redacted location and rule name appear.

Machine-readable reports keep the same findings with a versioned envelope:

```bash
sentinel scan --output json --report findings.json   # exit 1, stdout stays empty
sentinel scan --output sarif --report sentinel.sarif  # exit 1, stdout stays empty
```

`findings.json` carries `schema_version`, the tool name and version, and
the finding list:

```json
{"schema_version":"1.0.0","tool":{"name":"sentinel","version":"0.2.0"},"findings":[{"id":"secrets/SECRET-synthetic-token/token.env:1:24/fe84…","engine":"secrets","rule_id":"SECRET-synthetic-token","severity":"medium","location":{"path":"token.env","line":1,"column":24,"snippet":"SENTINEL_EXAMPLE_TOKEN=[REDACTED]"},"message":"synthetic secret token detected","evidence":"[REDACTED]"}, …]}
```

`sentinel.sarif` is SARIF 2.1.0 for CI ingestion (for example uploading
to GitHub code scanning); rule ids, severities mapped to SARIF levels,
and file locations match the JSON report finding for finding.
