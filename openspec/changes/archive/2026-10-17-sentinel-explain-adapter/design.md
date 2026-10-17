# Design: Sentinel Explain Adapter

## Context

The pipeline ends at `run_inner`: discovery → per-file engines → `dedupe_and_sort`
→ renderer, with `render_findings(&[Finding]) -> Vec<u8>` writing the only stdout
content. ADR-0003 fixes the boundary: redacted findings in, advisory text out, no
edge back to severity or the exit code. The existing `OsvApi` trait plus its
`UreqOsvClient`/`StubOsv` pair is the in-repo precedent for a seam with one real
adapter and one recording stub, and `UreqOsvClient::maybe_new` is the precedent for
"configured or absent".

## Decisions

### D1 — `Explainer` seam with injection, not a global

```rust
pub trait Explainer {
    fn explain(&self, findings: &[Finding]) -> Result<Vec<Explanation>, String>;
}
pub struct Explanation { pub finding_id: String, pub text: String }
```

`run` (the public seam) builds the explainer from the environment; `run_inner`
keeps its current signature and calls a new `run_with_deps(secrets_engine,
explainer, args, cwd, stdout, stderr)` with a disabled explainer. Tests call
`run_with_deps` with `StubExplainer`. This keeps every existing `run_inner` test
compiling untouched while making every explainer outcome testable without network.
Rejected: reading the environment inside the adapter (untestable), and a
thread-local/global (hidden state, parallel test flakiness).

### D2 — One request per scan

The adapter receives the whole finding slice and decides its own batching; the
pinned contract is one request, findings in canonical order, at most 20 findings
and at most 4096 bytes of context. Existing code already calls `dedupe_and_sort`
before rendering, so the order the adapter sees is the canonical order, and the
response map is keyed by finding id rather than by position — a reordering or a
partial response can never mis-attribute text.

### D3 — Forced-off is a pipeline decision, not an adapter one

`run_with_deps` decides whether to call the explainer at all: `--explain` present,
`--ci` false, `--offline` false, and an explainer that reports itself configured.
The adapter cannot re-enable itself, so the forced-off rule is testable by call
count on the stub. A disabled or unconfigured explainer produces exactly one
`explain-skipped` diagnostic when `--explain` was requested.

### D4 — Advisory map, terminal-only rendering

The pipeline collects `BTreeMap<finding_id, String>` and passes it to a new
`render_findings_with_advisories(findings, &advisories)`. The existing
`render_findings` becomes that function with an empty map, so its bytes and every
golden stay identical. JSON and SARIF renderers are untouched and never receive
the map — the machine contracts cannot drift by construction.

### D5 — Sanitization at the trust boundary

Response text is untrusted input, so it is validated where it enters: the response
must be a JSON array of objects with string `id` and `text`; unknown ids are
dropped; text is sanitized by stripping control characters, collapsing `\n`/`\t`
runs to one space, trimming, and truncating to 500 characters. The advisory line
is prefixed so it can never be confused with a finding line. A malformed envelope
yields `explain-invalid` and no advisories for the whole response.

### D6 — Redaction is structural

The adapter's input type is `&[Finding]`, and findings are only ever constructed
after the engine boundary; there is no code path that gives it engine candidates
or file bytes. The RED test asserts this empirically by scanning a fixture whose
line contains a synthetic secret and grepping the stub's recorded payload.

Paths are redacted at two choke points, never per producer. Dependency findings
are redacted where the review returns in `run_with_deps`: the review still reads
through the original file list, so cache keys and OSV lookups keep the real path
and only the finding's display forms (location path, fingerprint path segment)
are redacted. Every diagnostic is redacted where it renders in
`render_diagnostics` for the same reason: discovery, reading, scanning,
dependency review, cache, and explain all flow through that one exit, so
producers present and future are covered and in-memory diagnostics keep the
real path. Secrets and rule findings were already redacted in the scan loop, so
the explain payload and the JSON/SARIF renderers need no change: they are pure
functions of findings. Usage errors and fatal errors echo invocation paths, so
both strings are redacted at their `stderr` write sites in `run_with_deps`.
Defence in depth for the absolute promise: `HttpExplainer::body` passes the
fully serialized document through the production table just before the send, so
fields per-field redaction cannot see (package coordinates, future fields) still
cannot leave the process; matches are longer than the placeholder, so the byte
budget and the JSON shape survive the pass.

### D7 — Configuration and failure codes

`SENTINEL_EXPLAIN_URL` and `SENTINEL_EXPLAIN_API_KEY` are read once in `run`.
Missing either → disabled explainer (skip diagnostic, no HTTP). Request failure,
timeout, or non-2xx → `explain-failed`. Unparseable or wrongly shaped body →
`explain-invalid`. All three are warnings: the exit code and findings are
untouched, matching the `osv-degraded` precedent. HTTPS-only — plain HTTP
is accepted solely for loopback hosts so hermetic tests run without TLS —
single attempt,
10-second timeout, no retries.

## Threat matrix

| Threat | Mitigation | Alternative rejected |
| ------ | ---------- | -------------------- |
| Model text forging a finding or breaking line structure | D5 single-line sanitization, capped length, prefixed line | Trusting the provider's formatting |
| Secret material in the outbound payload | D6 structural redaction plus an empirical RED test | Re-redacting findings inside the adapter |
| Accidental network in hermetic runs | D3 forced-off before the adapter is reached; `--offline` zero-HTTP invariant retained | Adapter-side `--ci` check |
| Latency or cost blowup on a large scan | One request, 20 findings, 4096 bytes, 10 s, no retries | Per-finding requests |
| Exit-code or severity drift | Differential test on exit code, finding lines, and JSON bytes | Review-only reasoning |

## Test strategy

RED first: flag acceptance and the updated usage-error list; forced-off call counts
for `--ci` and `--offline`; missing-configuration skip; one-request and budget
truncation; timeout and HTTP-500 degradation; differential exit/severity/JSON
byte comparison; adversarial response text; malformed envelope and unknown ids;
redaction assertion over the recorded payload.
