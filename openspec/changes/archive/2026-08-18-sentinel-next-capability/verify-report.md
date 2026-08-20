```yaml
schema: gentle-ai.verify-result/v1
evidence_revision: sha256:f8e5ccf3228c22029d378f7679ce3e8c99c4ec2404f9845e7f545eb3b6cd5494
verdict: pass_with_warnings
blockers: 0
critical_findings: 0
requirements: 8/8
scenarios: 21/21
test_command: cargo test --all-features
test_exit_code: 0
test_output_hash: sha256:d578c2cd9d4740bab9f2d2398339ae9672b1a4b973dd2aebc42f3a5145f6a102
build_command: cargo build --all-features
build_exit_code: 0
build_output_hash: sha256:7374edd1620e3cee7f2f581285ccaa3e77796ad226a1618d7c3e117d8edfd6e3
```

## Verification Report

**Change**: `sentinel-next-capability`
**Version**: N/A (delta change; JSON schema_version `1.0.0`, SARIF `2.1.0`)
**Mode**: Standard
**Candidate**: worktree `/home/jona/projects/sentinel-worktrees/sentinel-sarif-output`, branch `feat/sentinel-sarif-output`, HEAD `d08070b`

Independent final requirements/runtime verification of the complete candidate. Proposal, both specs, design, and tasks were read before judgment. Strict TDD is inactive (`openspec/config.yaml` `strict_tdd: false`); RDD is disabled. No prior verify-report existed.

### Completeness

| Metric                                               | Value |
| ---------------------------------------------------- | ----- |
| Tasks total                                          | 22    |
| Tasks complete                                       | 22    |
| Tasks incomplete                                     | 0     |
| Requirements (cli-scan + machine-readable-reporting) | 8     |
| Scenarios                                            | 21    |

All 22 tasks in `openspec/changes/sentinel-next-capability/tasks.md` are checked. Full verification was therefore allowed to run.

### Build & Tests Execution

**Build**: ✅ Passed

```text
cargo build --all-features
exit 0
hash sha256:7374edd1620e3cee7f2f581285ccaa3e77796ad226a1618d7c3e117d8edfd6e3
Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.51s
```

**Tests**: ✅ 97 passed / ❌ 0 failed / ⚠️ 0 skipped

```text
cargo test --all-features
exit 0
hash sha256:d578c2cd9d4740bab9f2d2398339ae9672b1a4b973dd2aebc42f3a5145f6a102
lib unit: 53 passed
cli integration: 23 passed
discovery_cli: 15 passed
reporting: 6 passed
bin/doc: 0 tests
```

**Coverage**: ➖ Not available / threshold: 0% → not required

**Quality gates** (config `verify.quality`; not envelope commands):

| Command                                                    | Exit | Output hash                                                             |
| ---------------------------------------------------------- | ---- | ----------------------------------------------------------------------- |
| `cargo fmt --all -- --check`                               | 0    | sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| `cargo clippy --all-targets --all-features -- -D warnings` | 0    | sha256:8c233a54790c4800d3dd585436af679aa838da259bfdb129412e2d51cdb75cdc |
| `cargo deny check`                                         | 0    | sha256:561e56aeb4d3ce24a2ec5bb4c1afcefb316c8bb12a60545c26ed50f99a6868ce |
| `cargo audit`                                              | 0    | sha256:562d035a98669fbe26677ac3e5960da6ea0708f8f60b8275857eaee70a1b8f0f |

Descendant full tree at `d08070b` is fmt/clippy/deny/audit clean. Standalone JSON-core Clippy exception and planning/SARIF-core size exceptions are delivery conditions, not runtime failures of this candidate.

Terminal golden `tests/snapshots/cli__golden_corpus_scan.snap` is unchanged across `74a2cee..d08070b`.

### Spec Compliance Matrix

| Requirement                | Scenario                             | Test                                                                                                                                                                                                           | Result       |
| -------------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| Command surface            | Minimal invocation                   | `tests/cli.rs > clean_repo_exits_zero_with_empty_stdout_and_stderr`, `findings_exit_one_with_redacted_report`                                                                                                  | ✅ COMPLIANT |
| Command surface            | CI flag accepted                     | `tests/cli.rs > ci_flag_is_accepted_and_scans_the_repository`                                                                                                                                                  | ✅ COMPLIANT |
| Command surface            | Output and report flags accepted     | `tests/cli.rs > json_output_emits_complete_envelope_with_sorted_findings`, `report_file_is_written_with_empty_stdout_and_exit_one`; `tests/reporting.rs > sarif_output_is_schema_valid_against_pinned_fixture` | ✅ COMPLIANT |
| Command surface            | Unsupported argument rejected        | `tests/cli.rs > unsupported_arguments_and_missing_subcommand_write_stderr_only_and_exit_2`                                                                                                                     | ✅ COMPLIANT |
| Command surface            | Invalid output value rejected        | `tests/cli.rs > invalid_output_or_terminal_with_report_is_a_usage_error` (`--output yaml`)                                                                                                                     | ✅ COMPLIANT |
| Command surface            | Missing subcommand                   | `tests/cli.rs > unsupported_arguments_and_missing_subcommand_write_stderr_only_and_exit_2`; `src/cli.rs > missing_subcommand_is_a_usage_error`                                                                 | ✅ COMPLIANT |
| Report file output         | Report written to file               | `tests/cli.rs > report_file_is_written_with_empty_stdout_and_exit_one`                                                                                                                                         | ✅ COMPLIANT |
| Report file output         | Report with terminal output rejected | `tests/cli.rs > invalid_output_or_terminal_with_report_is_a_usage_error`                                                                                                                                       | ✅ COMPLIANT |
| Report file output         | Unwritable report path exits 2       | `tests/cli.rs > unwritable_report_path_exits_two_with_write_diagnostic`                                                                                                                                        | ✅ COMPLIANT |
| Report file output         | Diagnostics stay on stderr           | `src/lib.rs > failing_rule_diagnostic_stays_on_stderr_and_out_of_the_report_file`                                                                                                                              | ✅ COMPLIANT |
| Versioned JSON envelope    | Full scan emits complete envelope    | `tests/cli.rs > json_output_emits_complete_envelope_with_sorted_findings`; `tests/reporting.rs > json_golden_matches_reviewable_snapshot`                                                                      | ✅ COMPLIANT |
| Versioned JSON envelope    | Empty findings emit empty array      | `tests/cli.rs > clean_repo_emits_empty_findings_array_and_exit_zero`                                                                                                                                           | ✅ COMPLIANT |
| Versioned JSON envelope    | Special characters in messages       | `src/render/json.rs > escaping_keeps_bytes_valid_and_secrets_redacted`                                                                                                                                         | ✅ COMPLIANT |
| Lowercase JSON severity    | All severities lowercased            | `src/render/json.rs > envelope_wire_order_and_lowercase_severities`                                                                                                                                            | ✅ COMPLIANT |
| SARIF 2.1.0 envelope       | Full scan emits valid log            | `tests/reporting.rs > sarif_output_is_schema_valid_against_pinned_fixture`; `src/render/sarif.rs > envelope_is_210_with_sorted_unique_rules_and_matching_indices`                                              | ✅ COMPLIANT |
| SARIF 2.1.0 envelope       | Empty findings valid log             | `tests/reporting.rs > sarif_output_is_schema_valid_for_an_empty_scan`                                                                                                                                          | ✅ COMPLIANT |
| SARIF 2.1.0 envelope       | Severity mapping                     | `src/render/sarif.rs > severity_maps_to_sarif_levels`                                                                                                                                                          | ✅ COMPLIANT |
| SARIF 2.1.0 envelope       | Special path characters              | `src/render/sarif.rs > uris_percent_encode_space_hash_percent_and_non_ascii_but_keep_slashes`; `tests/reporting.rs > sarif_uris_are_rfc3986_encoded_and_raw_secrets_absent`                                    | ✅ COMPLIANT |
| Redacted bytes             | Raw secrets absent from both formats | `src/render/json.rs > escaping_keeps_bytes_valid_and_secrets_redacted`; `tests/reporting.rs > sarif_uris_are_rfc3986_encoded_and_raw_secrets_absent`                                                           | ✅ COMPLIANT |
| Deterministic output       | Run-twice byte comparison            | `tests/cli.rs > repeated_json_runs_are_byte_identical`; `tests/reporting.rs > repeated_sarif_runs_are_byte_identical`; `tests/cli.rs > repeated_binary_runs_are_byte_identical`                                | ✅ COMPLIANT |
| Hermetic schema validation | Pinned-schema validation             | `tests/reporting.rs > sarif_output_is_schema_valid_against_pinned_fixture` (`jsonschema::draft7::new` on `tests/fixtures/sarif-2.1.0.schema.json`)                                                             | ✅ COMPLIANT |

**Compliance summary**: 21/21 scenarios compliant

### Correctness (Static Evidence)

| Requirement                | Status         | Notes                                                                                                                                                     |
| -------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Command surface            | ✅ Implemented | `OutputFormat` ValueEnum `terminal\|json\|sarif`; `--output`/`--report` on `Command::Scan`; unknown args remain clap usage errors (exit 2)                |
| Report file output         | ✅ Implemented | Post-parse `terminal + --report` conflict; `run_inner` renders first then `fs::write`/`stdout`; write failures emit `cannot write scan report` and exit 2 |
| Versioned JSON envelope    | ✅ Implemented | `src/render/json.rs` borrowed Serialize DTOs in wire order; `schema_version` `1.0.0`; compact `to_vec` + newline                                          |
| Lowercase JSON severity    | ✅ Implemented | Custom `serialize_severity` emits `low`/`medium`/`high`/`critical`                                                                                        |
| SARIF 2.1.0 envelope       | ✅ Implemented | `src/render/sarif.rs`: `$schema` + `version` `2.1.0`; unique lex-sorted rules + binary-search `ruleIndex`; HIGH/CRITICAL → `error`                        |
| Redacted bytes             | ✅ Implemented | Renderers serialize already-redacted `Finding` values; tests assert raw synthetic secrets are absent                                                      |
| Deterministic output       | ✅ Implemented | No maps/timestamps; run-twice JSON/SARIF/terminal bytes asserted identical                                                                                |
| Hermetic schema validation | ✅ Implemented | Dev-dep `jsonschema = { version = "0.49.9", default-features = false }`; pinned OASIS fixture; no HTTP/file resolvers                                     |

### Coherence (Design)

| Decision                                                                       | Followed? | Notes                                              |
| ------------------------------------------------------------------------------ | --------- | -------------------------------------------------- |
| Wire models: private borrowed Serialize structs in declaration order           | ✅ Yes    | `src/render/json.rs`, `src/render/sarif.rs`        |
| Serialization: serde derive + compact `to_vec` + newline                       | ✅ Yes    | Both renderers                                     |
| URI encoding: `percent-encoding = "2"`; pass `/` + unreserved                  | ✅ Yes    | `SARIF_URI_SET`                                    |
| Schema validation: `jsonschema` 0.49 `default-features = false`, `draft7::new` | ✅ Yes    | Confirmed in `Cargo.toml` and `tests/reporting.rs` |
| CLI/file failures: ValueEnum + post-parse conflict; render then write          | ✅ Yes    | `src/cli.rs` `parse`, `src/lib.rs` `run_inner`     |
| Shared kernel / terminal bytes unchanged                                       | ✅ Yes    | Terminal golden untouched                          |
| Rule-id index: sorted unique vector + binary search                            | ✅ Yes    | Deterministic per emitted log                      |

### Mutation Testing Evidence

One bounded availability campaign. No prior verify-report mutation block was delivered. Recommended Rust framework is `cargo-mutants`. It is not installed, not on `PATH`, not present as `cargo mutants`, and not documented in this crate (`Cargo.toml`, no `mutants.toml`). No install and no manual substitute were performed.

Preserved probe error (`cargo mutants --version`, exit 101, hash sha256:4377b390db43ddec7fcce57909ac790697cf993187ba4672470519e3678f26e3):

```text
error: no such command: `mutants`

help: view all installed commands with `cargo --list`
help: find a package to install `mutants` with `cargo search cargo-mutants`
```

```json
{
  "schema": "gentle-ai.mutation-evidence/v1",
  "change_name": "sentinel-next-capability",
  "campaign_id": "cam-20260818T221940Z-0fefba97",
  "campaign_type": "full",
  "generated_at": "2026-08-18T22:19:40Z",
  "candidate_fingerprint": "sha256:c0f4c54092681b573693b688b5e514f16daecaa315975ba278e61c27b82ed5ef",
  "candidate_binding_strength": "strong",
  "scope_fingerprint": "sha256:c0390fa80b9cf5a6d7cacd96918b03bf851651636679ee88fec4d4eb2b68edff",
  "baseline_suite_hash": "sha256:d578c2cd9d4740bab9f2d2398339ae9672b1a4b973dd2aebc42f3a5145f6a102",
  "baseline_hash_kind": "opaque",
  "tool": { "name": "cargo-mutants", "version": "unavailable" },
  "config_fingerprint": "sha256:09ddf15d65c023714c40d926dbd9ab25fe9ed2cc21093666f48b5d68b674ad51",
  "repro": {
    "cwd": ".",
    "command": "cargo mutants --version",
    "seed": null,
    "timeout_seconds": 30
  },
  "counts": {
    "total": 0,
    "killed": 0,
    "survived": 0,
    "timeout": 0,
    "error": 0
  },
  "counts_source": "executed",
  "survivors": [],
  "selected_mutant_ids": [],
  "incremental_eligible": false,
  "prior_evidence_revision": null,
  "cache_manifest": [],
  "invalidation_reasons": [],
  "status": "unavailable"
}
```

### Issues Found

**CRITICAL**: None

**WARNING**:

- Mutation testing is `unavailable`: `cargo-mutants` is not installed or documented in this repository. The required bounded campaign could not execute mutants. This does not contradict a spec scenario (all 21 covering tests passed) and was not treated as an implementation failure.

**SUGGESTION**:

- Tasks 2.4/2.6 covering tests live in `tests/cli.rs` rather than the task-named `tests/reporting.rs`. Coverage is equivalent; `tests/reporting.rs` now holds the SARIF schema/golden suite.
- `openspec/config.yaml` still records bootstrap-era `test_runner.executable: false` and a stale `strict_tdd_reason`. Tests are executable at this candidate.
- Unarchived `sentinel-discovery-hardening` remains an archive-order concern, not a verify blocker.

Delivery conditions recorded, not counted as implementation failures:

- Planning PR #13: maintainer-authorized 535-line policy exception
- JSON-core PR #14: maintainer-authorized standalone Clippy exception; this descendant tree is Clippy-clean
- SARIF-core `8c4808a`: maintainer-authorized `size:exception` (raw 1066 including generated lockfile; authored 297)
- Schema/golden `d08070b`: normal policy (202 raw)

### Verdict

PASS WITH WARNINGS

All 8 requirements and 21 scenarios have passing runtime covering tests. Build, tests, and quality gates are green at `d08070b`. The only verification warning is the unavailable mutation campaign.
