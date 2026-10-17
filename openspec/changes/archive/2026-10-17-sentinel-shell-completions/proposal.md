# Proposal: Sentinel Shell Completions

## Intent

PRD §3 lists the CLI as "Clap + clap_complete (shell completions)" and
`ARCHITECTURE.md:174` assigns completion generation to the command module, but
nothing implements it: `clap_complete` is absent from `Cargo.toml`, no requirement
mentions completions, and the MVP-foundation proposal deferred it into a follow-up
list that never picked it up. Honor the promise with one small, pure side command.

## Scope

### In Scope

- `sentinel completions <shell>` for the shells `clap_complete` provides for this
  crate: `bash`, `zsh`, `fish`, `powershell`, `elvish`.
- Completion script on stdout, exit 0; unsupported shell is a usage error on
  stderr with empty stdout and exit 2.
- Pure side command: no discovery, no scan, no network, no cache, works outside a
  Git repository.
- README installation line.

### Out of Scope

- Changing `sentinel scan`, its flags, its exit codes, or its output.
- Writing completion files to disk, auto-installing them, or per-distro packaging.
- Hand-written completion scripts or a completion framework.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `cli-scan`: `Command surface` gains the `completions` subcommand alongside the
  unchanged `scan` command.

## Approach

Add the `clap_complete` dependency and a `Completions { shell: Shell }` variant to
`Command`, generated with `clap_complete::generate` into the process stdout. `Shell`
comes from clap_complete's own `ValueEnum`, so an unsupported value is a clap usage
error like every other rejected invocation, and the generated script always matches
the real surface because clap is the single source of truth.

## Affected Areas

- `Cargo.toml` / `Cargo.lock`: `clap_complete`.
- `src/cli.rs`: new subcommand variant and its parsing tests.
- `src/main.rs` or `src/lib.rs`: dispatch for the non-scanning command.
- `tests/cli.rs`: end-to-end checks per shell and the usage error.
- `README.md`: completion installation line.

## Risks

- Adding a required subcommand must not disturb `scan`'s parser or the
  "exactly one command" assumptions in existing tests (Med — the CLI tests that
  enumerate rejected invocations are part of the RED set).
- One more dependency reaches `cargo deny` (Low — `clap_complete` is MIT/Apache-2.0
  and already a clap-family crate).

## Rollback / Stop Conditions

Single additive slice; reverting it restores the single-command CLI with no data or
contract impact. Gates red → fix or revert.

## Dependencies

`clap_complete` (matches the existing `clap` major version).

## Success Criteria

- Every supported shell produces a non-empty script on stdout with an empty stderr
  and exit 0, from a working directory that is not a Git repository.
- An unsupported shell exits 2 with usage on stderr and empty stdout.
- `sentinel scan` behaviour and every existing test and golden are unchanged.

## Delivery Decision

One stacked-to-main work unit within the 400-line review budget, referencing issue
#39. Archived after `sentinel-explain-adapter`, because both modify the same
`cli-scan` → `Command surface` requirement and the successor must be authored
against the post-predecessor surface.
