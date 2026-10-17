# Sentinel

Sentinel scans a Git repository for secrets and known-vulnerable dependencies,
before a commit or in CI. It is a single Rust binary with no server and no
database.

This site renders the user documentation. The repository's
[README](https://github.com/jonasotoaguilar/sentinel#readme) is the place to
start for what the tool is and how to install it, and these pages answer the
questions that come after adoption:

- **[Usage](USAGE.md)** — install, first scan, output formats, exit codes, configuration, excludes, baseline, cache.
- **[CI](CI.md)** — GitHub Actions, GitLab CI, pre-commit, Docker.
- **[FAQ](FAQ.md)** — the questions that come up first.
- **[Troubleshooting](TROUBLESHOOTING.md)** — when something does not behave as documented.
- **[Comparison](COMPARISON.md)** — how Sentinel differs from the scanners you have already heard of.

Runnable examples live in the repository's
[`examples/`](https://github.com/jonasotoaguilar/sentinel/tree/main/examples)
directory, and generated man pages in
[`man/man1`](https://github.com/jonasotoaguilar/sentinel/tree/main/man/man1).
