# Dependency Review Specification

## Purpose

Detects known-vulnerable pinned npm/PyPI packages via OSV API v1 and XDG cache.

## Requirements

### Requirement: Pinned manifest ingestion

The engine MUST ingest only `package-lock.json` exact versions and `requirements.txt` `==` pins. Unpinned, range, marker, extras, option, or malformed items MUST emit a skip/parse diagnostic (path+line) and MUST NOT be queried. Files >10 MiB MUST skip as oversized. Other manifests (`pyproject.toml`, `poetry.lock`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `Cargo.lock`, `go.mod`) MUST NOT be parsed; ranges and transitives MUST NOT be resolved.

#### Scenario: Pinned npm and PyPI queried

- GIVEN `package-lock.json` pin `lodash@4.17.20` and `requirements.txt` pin `flask==2.3.3` with advisories
- WHEN `sentinel scan` runs online
- THEN one `dependency` finding per advisory emits at each pin

#### Scenario: Unpinned or malformed skipped

- GIVEN `requests>=2.0` beside `flask==2.3.3`, or invalid `package-lock.json`
- WHEN `sentinel scan` runs
- THEN only pins are queried; skip/parse diagnostics name path+line; exit is not 2

### Requirement: Bounded OSV querying

Online scans MUST `POST https://api.osv.dev/v1/querybatch` (≤1000 queries), follow per-query `nextPageToken` ≤3 pages, and `GET /v1/vulns/{id}` only when a batch entry lacks mapping fields. Each request MUST time out ≤10 s; the network phase MUST stay ≤30 s. Retries MUST be ≤3, transient-only (connection, 429, 5xx); other 4xx MUST NOT retry.

#### Scenario: Pagination, detail, and retry

- GIVEN page 1 with `nextPageToken`, a token after 3 pages, a batch entry whose detail is CVSS 9.8, and 429 forever
- WHEN the engine queries
- THEN both pages emit, no 4th request, detail severity used, ≤3 retries then degrade

### Requirement: Untrusted validation and severity

Responses and cache reads MUST be validated at the boundary: id ≤128 matching the OSV pattern; ecosystem `npm` or `PyPI`; RFC3339 timestamps; `severity[]`/`affected[]` shapes. Invalid advisories MUST skip with a diagnostic; valid siblings MUST emit. Strings MUST be display-only (evidence ≤4 KiB); raw payload MUST NOT reach reports, diagnostics, or cache. `withdrawn` MUST suppress the finding and SARIF rule. Severity MUST be total: CVSS ≥9.0 Critical; ≥7.0 High; ≥4.0 Medium; >0 Low; else High.

#### Scenario: Malformed, untrusted, withdrawn, severity

- GIVEN one valid + one malformed advisory, a `<script>`/traversal/`nan` payload, a withdrawn advisory, and CVSS 9.8/7.5/5.0/2.1 plus missing severity
- WHEN findings map
- THEN valid emits; malformed and withdrawn do not; no raw bytes leak; severities Critical/High/Medium/Low/High

### Requirement: Deterministic findings

Findings MUST use `engine="dependency"`, `ruleId="OSV-<id>"`, and the pin location. Advisories MUST sort by id and dedupe via shared fingerprints. Identical inputs and cache MUST yield byte-identical JSON and SARIF.

#### Scenario: Byte-identical reports

- GIVEN a warm cache, mixed findings, and a stub that reorders advisories
- WHEN `--output json` and `--output sarif` each run twice
- THEN each pair is byte-identical

### Requirement: Cache, offline, and degrade

Cache MUST live at `$XDG_CACHE_HOME/sentinel/osv/<schema>/`, keyed `(ecosystem, package, version)`, advisory JSON only. Online entries <24 h MUST serve without HTTP; older MUST refetch. Writes MUST be atomic (temp+rename), last-writer-wins. Corrupt or schema-mismatched entries MUST miss: warn, refetch online, skip offline, never rewrite offline. `--offline` MUST do zero HTTP (no socket, DNS, or TLS), ignore TTL, and serve any-age cache; uncached packages MUST warn+skip. After online retry exhaustion, stale cache MUST emit with a warning, else warn+skip. Degradation MUST NOT exit 2; secrets MUST still run.

#### Scenario: Cache fresh, stale, corrupt

- GIVEN a 1 h entry, a 26 h entry with a reachable API, and a corrupt or wrong-schema file
- WHEN an online scan runs
- THEN fresh avoids HTTP, stale refetches atomically, and corrupt is a miss with a diagnostic

#### Scenario: Offline and degrade

- GIVEN a 2-month cache vs empty cache, a counting stub, 429 with a 26 h entry, or no cache and no API
- WHEN `sentinel scan --offline` or an online scan runs
- THEN offline hit serves with 0 requests; miss or no-cache warns+skips; stale emits with a warning; secrets still report; exit is 0 or 1
