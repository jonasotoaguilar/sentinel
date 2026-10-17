# Delta for cli-scan

## MODIFIED Requirements

### Requirement: Command surface

The CLI MUST expose exactly two subcommands: `sentinel scan` with options `--ci`, `--offline`, `--explain`, `--output <terminal|json|sarif>` (default `terminal`), and `--report <path>`; and `sentinel completions <shell>` where `<shell>` is one of `bash`, `zsh`, `fish`, `powershell`, `elvish`. All other options, values, positionals, or subcommands MUST fail as usage errors (stderr, empty stdout, exit 2). `--offline` MUST be orthogonal to `--ci`, and `--explain` MUST remain advisory-only and inert under `--ci` and `--offline`. `sentinel completions` MUST NOT perform discovery, scanning, or any network or cache access, and MUST work outside a Git repository.
(Previously: exactly one subcommand, `sentinel scan`; every other subcommand or option was a usage error.)

#### Scenario: Minimal invocation

- GIVEN a git repo at the working directory
- WHEN `sentinel scan` runs
- THEN pipeline runs; exit 0 or 1

#### Scenario: Accepted flags

- GIVEN `--ci`, `--offline`, `--ci --offline`, `--explain`, or `--output json|sarif` with optional `--report`
- WHEN `sentinel scan` runs
- THEN the flag is honored (`--ci` hermetic; `--offline` zero HTTP; `--explain` advisory-only); exit 0 or 1

#### Scenario: Usage errors

- GIVEN a positional, `--output yaml`, an unknown subcommand, or no subcommand
- WHEN it runs
- THEN usage on stderr, empty stdout, exit 2

## ADDED Requirements

### Requirement: Completion generation

`sentinel completions <shell>` MUST write the completion script for the requested shell to stdout, with an empty stderr and exit 0, and MUST NOT read or write anything else: no repository discovery, no scan, no network, no cache. The script MUST be generated from the live command definition, so it reflects every accepted subcommand, option, and value. An unsupported shell MUST be a usage error (stderr, empty stdout, exit 2) and MUST NOT write anything to stdout.

#### Scenario: Each supported shell emits a script

- GIVEN a working directory that is not a Git repository
- WHEN `sentinel completions bash`, `zsh`, `fish`, `powershell`, and `elvish` each run
- THEN each exits 0, writes a non-empty script to stdout, and writes nothing to stderr

#### Scenario: Unsupported shell is a usage error

- GIVEN `sentinel completions tcsh`
- WHEN it runs
- THEN usage on stderr, empty stdout, exit 2

#### Scenario: No discovery outside a repository

- GIVEN a directory that is not a Git repository
- WHEN `sentinel completions zsh` runs
- THEN no repository error is reported and the script is emitted
