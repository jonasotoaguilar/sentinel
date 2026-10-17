# Design: Sentinel Shell Completions

## Context

`src/cli.rs` defines one clap `Command` enum with a single `Scan` variant, and
`parse` rejects anything else. `cli-scan` currently requires "exactly one command",
so adding a subcommand is a contract modification, not an additive detail. The
`scan` path owns discovery, the exit-code contract, and report writing; completion
generation owns none of that.

## Decisions

### D1 — `clap_complete`'s `Shell` as the value enum

The `completions` argument uses `clap_complete::Shell` directly as a `ValueEnum`.
That makes an unsupported shell a clap usage error (same shape as `--output yaml`),
and it guarantees the generated script covers exactly the shells clap_complete
supports for this crate rather than a hand-maintained list.

### D2 — Generation is a pure side command dispatched before any pipeline work

`run` inspects the parsed command: `Scan` enters the existing pipeline untouched;
`Completions` writes the script to the injected `stdout` writer and returns success
without touching discovery, cache, or network. Writing through the injected writer
(not `io::stdout()`) keeps the seam testable and keeps `run`'s
`Result`-typed streams contract.

### D3 — `clap_complete::generate` with the real command definition

`generate(shell, &mut Cli::command(), "sentinel", &mut writer)` uses
`clap::CommandFactory`, so the script can never drift from the accepted surface.
The same value covers `scan`, `completions`, and every option.

### D4 — Rejected alternatives

- A `--completions` flag on `scan` would make a scan-shaped command produce a
  non-scan artifact, and would keep the "exactly one subcommand" fiction.
- Writing the scripts at build time into the repository would commit generated
  files that drift silently and cannot know the user's shell.
- Hand-written scripts duplicate clap's knowledge of the command tree.

## Threat matrix

| Threat | Mitigation | Alternative rejected |
| ------ | ---------- | -------------------- |
| A required new subcommand breaks existing invocation handling | Existing CLI tests are part of the RED set; a bare `sentinel`, an unknown subcommand, and every rejected option are re-asserted | Adjusting tests after the fact |
| Generated output leaking into stderr or the report path | Output goes to the injected stdout writer only; tests assert empty stderr and exit 0 | `println!` and global stdout |
| Completion generation doing accidental work in a non-repository | Dispatch happens before discovery; a non-repository cwd test proves it | Early `git rev-parse` |

## Test strategy

RED first: per-shell acceptance through the binary (exit 0, non-empty stdout, empty
stderr, and script content mentioning the `scan` subcommand), the unsupported-shell
usage error with empty stdout, and a non-repository cwd case. Existing
usage-error tests are extended rather than replaced.
