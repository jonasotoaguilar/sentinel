# Contributing

Thanks for your interest. Please follow the process below.

## Before you start

1. Open or find an issue for your change.
2. Ensure the issue carries the `status:approved` label — this signals maintainer approval before writing code.

## Local setup

Sentinel is a cross-platform Rust CLI (single crate, Edition 2024, stable toolchain). See the README for setup instructions. The pinned toolchain and components live in `rust-toolchain.toml`; run `rustup show` to verify your local toolchain matches.

## Development

1. Branch from `main` with a focused scope. Never commit or push directly to `main`.
2. Make your changes.
3. Run the checks below and fix all failures:

| Check | Command |
|-------|---------|
| Lint | `cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings` |
| Tests | `cargo test --all-features` |

> Bootstrap note: until `Cargo.toml` exists, these commands cannot run and the repo-local pre-commit hook (`.githooks/pre-commit`, activated via `core.hooksPath`) exits without checks. The hook activates automatically once the crate manifest lands.

## Pull request

- Reference the issue: `Closes #N`, `Fixes #N`, or `Resolves #N`.
- Apply exactly one type label from the accepted set: `type:bug`, `type:feature`, `type:refactor`, `type:docs`, `type:chore`, `type:breaking-change`.
- Keep the diff at **≤400 lines**. If it must exceed that, add `size:exception` with a brief justification.
- All merges go through pull requests — no direct pushes to `main`.

## Commit conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/) format (e.g. `feat:`, `fix:`, `chore:`).
- Do not add `Co-Authored-By` or AI attribution trailers.

## Pre-PR checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --all-features` passes
- [ ] Documentation updated if the change affects docs (README, PRD, ARCHITECTURE)
- [ ] No secrets, credentials, or real API keys in the diff
