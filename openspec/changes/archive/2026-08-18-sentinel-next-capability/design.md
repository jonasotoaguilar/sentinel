# Design: Machine-Readable JSON and SARIF Outputs

## Technical Approach

At `main` `74a2cee`, `src/lib.rs` already produces redacted `Vec<Finding>` values through `normalize::dedupe_and_sort`, writes diagnostics separately, and delegates terminal bytes to `src/render.rs`. Keep that pipeline unchanged. Add two pure renderer submodules that borrow the ordered findings, build explicit serialization structs, and return bytes. Extend Clap parsing and make `run_inner` select a renderer and one destination only. Discovery, detection, normalization, redaction, ordering, terminal bytes, and exits 0/1/2 remain unchanged.

## Architecture Decisions

| Decision | Choice | Alternatives / trade-off | Rationale |
|---|---|---|---|
| Wire models | Private borrowed `#[derive(Serialize)]` structs in each renderer, declared in wire-field order | Serializing `Finding` couples domain and wire contracts; `Value`/maps weaken order | Preserves the existing shared kernel and deterministic field order without clones or speculative traits. |
| Serialization | `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`; compact `to_vec` plus one newline | Hand-written JSON risks escaping defects | Matches project major-version manifests; Serde derives explicit structs and `serde_json::to_vec` returns valid bytes. |
| URI encoding | `percent-encoding = "2"`; pass `/` and RFC 3986 unreserved bytes, encode all others from the normalized UTF-8 path | A custom encoder duplicates standard logic; `url` is broader | Produces relative SARIF URIs with spaces, `#`, `%`, and UTF-8 bytes encoded while retaining path separators. |
| Schema validation | Dev dependency `jsonschema = { version = "0.49", default-features = false }`; validate with `draft7::new` | Defaults permit HTTP/file resolution | The official OASIS schema is Draft 7; disabling resolvers makes validation hermetic. |
| CLI/file failures | Clap `ValueEnum` plus post-parse `terminal + --report` conflict; `fs::write` overwrites only after successful rendering | Parent creation/atomic staging adds unspecified behavior | Existing usage errors remain Clap stderr/exit 2; write failures contain `cannot write scan report`, leave stdout empty, and exit 2. |

## Data Flow

```mermaid
sequenceDiagram
  participant C as Clap
  participant P as Existing scan pipeline
  participant R as Selected renderer
  participant D as stdout or report file
  C->>P: ci, output, report
  P->>P: discover → detect → redact → normalize/order
  P->>R: &[Finding]
  R-->>D: deterministic bytes
  P-->>C: diagnostics on stderr; exit 0/1/2
```

## File Changes

| File | Action | Description |
|---|---|---|
| `Cargo.toml`, `Cargo.lock` | Modify | Add serialization, URI, and test-only schema dependencies. |
| `src/cli.rs` | Modify | Add `OutputFormat`, `--output`, `--report`, and combination validation. |
| `src/lib.rs` | Modify | Route ordered findings, preserve diagnostics, write stdout/file, map failures. |
| `src/render.rs` | Modify | Keep terminal renderer byte-identical; declare/re-export JSON/SARIF renderers. |
| `src/render/json.rs` | Create | Versioned JSON DTOs and pure renderer. |
| `src/render/sarif.rs` | Create | SARIF DTOs, rule/index construction, severity and URI mapping. |
| `tests/cli.rs`, `tests/reporting.rs` | Modify/Create | CLI, stream separation, file, redaction, deterministic and schema tests. |
| `tests/fixtures/sarif-2.1.0.schema.json` | Create | Minified pinned copy of the official OASIS 2.1.0 schema. |
| `tests/snapshots/reporting__*.snap` | Create | Reviewable JSON/SARIF goldens; existing terminal golden is untouched. |

## Interfaces / Contracts

- JSON order: `schema_version`, `tool { name, version }`, `findings`; finding fields follow the spec. Severity uses lowercase strings.
- SARIF uses the versioned OASIS schema URI. Build a unique lexicographically sorted rule-ID vector, emit `{id}` descriptors, and resolve each result's `rule.index` by binary search in that same vector. Results retain incoming finding order.
- `render_json(&[Finding])` and `render_sarif(&[Finding])` return `Result<Vec<u8>, serde_json::Error>`. No renderer performs I/O.
- Serialization failures exit 2 as `cannot render scan report`; destination failures use the required write diagnostic. Diagnostics never enter report bytes.

## Testing Strategy

| Layer | Planned coverage |
|---|---|
| Unit | DTO field/severity mapping, escaping, URI cases, sorted unique rules and matching indices, empty reports. |
| Integration | Clap errors; stdout/file routing; overwrite/unwritable paths; exits; diagnostics separation; raw-secret absence; run-twice equality. |
| Contract | Parse output and validate SARIF against the local Draft 7 fixture with all external resolution disabled; retain the terminal snapshot unchanged. |

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED tests |
|---|---|---|---|
| CLI output routing | Applicable — `--output`/`--report` choose a destination | Safe: report bytes reach only stdout or the requested file and diagnostics stay on stderr. Failure: invalid combinations or writes produce empty stdout and exit 2. | Invalid value, terminal+report, unwritable path, and diagnostic/report separation; carry unchanged into tasks. |
| Documentation-like paths | N/A — no executable classification changes | Existing discovery only | None |
| Git repository selection | N/A — cwd authority is unchanged | Existing `Git::discover` contract | None |
| Commit state | N/A — no index semantics change | — | None |
| Push state | N/A — no push integration | — | None |
| PR commands | N/A — delivery slicing adds no VCS automation | — | None |

## Migration / Rollout

No data migration. PR1 (base `main`, under 400 review-budget changed lines) adds JSON, CLI validation/routing, report writing, and regressions. PR2 (base PR1, under 400 review-budget changed lines) adds SARIF, URI encoding, pinned-schema validation, and SARIF goldens. The minified official schema and generated lock/snapshots are tracked evidence, not authored-line budget. Merge PR1 then PR2; rollback PR2 then PR1.

## Open Questions / Risks

- **Archive order**: `sentinel-discovery-hardening` remains unarchived and main `cli-scan` is stale. Archive/resolve it before final spec archive; this phase does not mutate that change.
- Sorted rule IDs guarantee deterministic indices for a fixed rule set, but adding an earlier-sorting ID shifts later indices. Before archive, clarify that “stable” means deterministic per emitted log, or add an append-only rule-ID constraint.
- Scope remains reporting only: no dependency/OSV/cache/offline/explain/rules/docs work.
