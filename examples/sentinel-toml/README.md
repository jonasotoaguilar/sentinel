# Project configuration example

Copy this file to `sentinel.toml` at the repository root to exclude
generated files from every scan and to fail the build only on serious
findings. Scalar keys (`fail_under`) override across levels while
`exclude` lists union; the CLI flag always wins over this file.

```toml
# Files never worth scanning: build output, vendored code, local env files.
# Patterns use `.gitignore` semantics against repo-relative paths.
exclude = ["dist/", "vendor/", "*.log", ".env.local"]

# Lowest severity that exits 1: critical, high, medium, low, or none for
# report-only. With "high", the medium findings in `../basic-scan` report
# but the scan exits 0; `--fail-under low` on the command line still
# restores the default for one run.
fail_under = "high"

# Optional: accept findings listed in this file so they report without
# failing the build. See `../baseline` for the workflow that writes it.
# baseline = "sentinel-accepted.json"
```

Check what the merged configuration does without running a full scan:
`--exclude` on the command line adds to (never replaces) this list, and
a malformed file warns once on stderr instead of aborting the scan.
