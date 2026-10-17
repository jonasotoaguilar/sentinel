# Security

## Reporting a vulnerability

Do **not** open a public issue. Report privately:

- **GitHub private reporting**: Use the repository's private vulnerability reporting form at https://github.com/jonasotoaguilar/sentinel/security/advisories/new.
- **Contact**: If unavailable, contact `@jonasotoaguilar` with the details below.

## What to include

- Affected project and version.
- Vulnerability description and impact.
- Reproduction steps.
- Proof of concept (if available).

## Response timeline

| Step | Expected timeframe |
|------|--------------------|
| Acknowledgment | 2 business days |
| Triage & assessment | 7 calendar days |
| Fix release | 30 calendar days |

## Supported versions

| Version | Supported |
|---------|-----------|
| `v0.1.0` (latest release) | ✅ — security fixes ship in the next release |
| `main` (unreleased) | ✅ — security fixes land here first |

Only the latest minor line receives security fixes. Older lines are not
patched; the fix is to upgrade.

## Dependency policy

This project's dependencies are part of its security surface: the scanner
parses untrusted input, so an outdated crate is a vulnerability in the tool
that reports vulnerabilities. The policy is **enforced rather than described**:

- `deny.toml` is the policy. It denies yanked crates, wildcard version
  requirements, unknown registries and unknown git sources, and it carries an
  explicit license allow-list.
- `cargo deny check` and `cargo audit` run on every pull request and every push
  to `main`, so a violation fails CI instead of being noticed later.
- Dependencies are updated by Dependabot on a weekly schedule, with minor and
  patch updates grouped so the review cost stays proportionate.

A change to this policy belongs in `deny.toml`, not in this document: if the
two disagree, the file wins.
