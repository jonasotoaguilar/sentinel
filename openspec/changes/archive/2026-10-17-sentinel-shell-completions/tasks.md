# Tasks: Sentinel Shell Completions

## Review Workload Forecast

Estimated lines: 150-250 authored.
Split: one PR.
Decision needed before apply: No
Chained PRs recommended: No (single unit; it still travels in the chain after the
explain adapter, because it modifies the same `Command surface` requirement)
Chain strategy: stacked-to-main
400-line budget risk: Low

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
| ---- | ---- | --------- | -------------------- | --------------- | ----------------- |
| 1 | `completions` subcommand, dependency, tests, README line | PR 7 | `cargo test --lib cli` | `cargo test --test cli` | `Cargo.toml`, `Cargo.lock`, `src/cli.rs`, `src/lib.rs`, `tests/cli.rs`, `README.md` |

## Task list

- **7.1 (RED)** — Add failing tests: per-shell acceptance through the binary
  (exit 0, non-empty stdout, empty stderr, script mentions the `scan`
  subcommand), `sentinel completions tcsh` as a usage error with empty stdout and
  exit 2, a non-repository working directory succeeding, and an extended
  unknown-subcommand usage error. Move the existing `--explain`-is-a-usage-error
  expectations to their post-explain shape if the explain adapter already landed.
- **7.2** — Add the `clap_complete` dependency at the existing `clap` major
  version.
- **7.3** — Add the `Completions { shell }` variant in `src/cli.rs` and the dispatch
  in `run` that writes the generated script to the injected stdout writer without
  entering the pipeline.
- **7.4** — Add the README completion installation line under the existing usage
  section.
- **7.5 (GREEN)** — `cargo test --all-features`, `cargo fmt --all -- --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny check`,
  `cargo audit`; confirm every `scan` golden and snapshot is unchanged.

## Evidence requirements

Each task reports the exact command and its observed result; RED is reported with
the failing assertion text. The non-repository case must show the absence of a
discovery error, not merely a zero exit code.
