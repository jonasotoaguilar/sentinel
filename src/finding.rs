//! The canonical finding and diagnostic model (finding-normalization spec):
//! engines emit raw detections; normalization collapses them into [`Finding`]
//! values with stable fingerprints; [`Diagnostic`] models stderr warnings.

/// Severity assigned by a rule (ARCHITECTURE findings model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        f.write_str(name)
    }
}

/// Source location of a finding; repo-relative with forward slashes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location {
    /// Repo-relative path, forward slashes on every platform.
    pub path: String,
    /// 1-based line number.
    pub line: u64,
    /// 1-based column number.
    pub column: u64,
    /// Redacted snippet of the matching line.
    pub snippet: String,
}

/// A normalized, deduplicated finding; every field is redacted-safe (raw
/// secret values never appear after the engine boundary).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// Stable fingerprint: engine, rule id, normalized location, digest.
    pub id: String,
    /// Engine that produced the detection.
    pub engine: String,
    /// Stable rule id (`SECRET-<KEBAB-NAME>`).
    pub rule_id: String,
    /// Severity assigned by the rule.
    pub severity: Severity,
    /// Repo-relative source location.
    pub location: Location,
    /// Human-readable description.
    pub message: String,
    /// Redacted matched content.
    pub evidence: String,
}

/// A non-fatal warning: the scan continues and the exit code is unaffected.
/// Rendered to stderr, sorted by `(code, path, rule)` (design).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Diagnostic {
    /// Stable code (`read-failed`, `rule-failed`, ...).
    pub code: &'static str,
    /// Repo-relative path; empty when not file-specific.
    pub path: String,
    /// Rule id; empty when not rule-specific.
    pub rule: String,
    /// Deterministic detail.
    pub message: String,
}
/// Bounds a diagnostic message: drops control characters except newline and tab,
/// then caps at 200 chars. Guarantees bounded, control-stripped text; it does
/// not redact secrets and does not make the text single-line.
pub(crate) fn sanitize(m: &str) -> String {
    m.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(200)
        .collect()
}
impl Finding {
    /// The baseline key: engine, rule id, and content digest without the
    /// location segment, so renames, moves, and line shifts keep an
    /// accepted finding accepted while changed content (a new digest) or a
    /// changed rule reports fresh. Falls back to the full fingerprint when
    /// it carries no location segment (defensive: every engine emits one).
    pub fn baseline_key(&self) -> String {
        let segments: Vec<&str> = self.id.split('/').collect();
        if segments.len() > 2 {
            // The path itself may hold slashes, so only the first two
            // segments (engine, rule) and the last (digest) are stable.
            format!(
                "{}/{}/{}",
                segments[0],
                segments[1],
                segments[segments.len() - 1]
            )
        } else {
            self.id.clone()
        }
    }
}

impl Diagnostic {
    /// A tracked file could not be read; the file is skipped.
    pub fn read_failed(path: &str, error: &std::io::Error) -> Self {
        Self {
            code: "read-failed",
            path: path.to_string(),
            rule: String::new(),
            message: error.to_string(),
        }
    }

    /// A rule could not be applied; the rule is skipped.
    pub fn rule_failed(rule: &str, message: String) -> Self {
        Self {
            code: "rule-failed",
            path: String::new(),
            rule: rule.to_string(),
            message,
        }
    }

    /// A file could not be fully parsed, so the file is skipped: no rule
    /// finding is reported for it, and the gap is disclosed with this one
    /// diagnostic naming the path.
    pub fn rule_fallback(path: &str, message: &str) -> Self {
        Self {
            code: "rule-fallback",
            path: path.to_string(),
            rule: String::new(),
            message: sanitize(message),
        }
    }
    /// `--explain` reached a configured adapter but the request failed,
    /// timed out, or returned a non-success status; the scan continues.
    pub fn explain_failed(message: &str) -> Self {
        Self {
            code: "explain-failed",
            path: String::new(),
            rule: String::new(),
            message: sanitize(message),
        }
    }
    /// `--explain` received a body that is not an array of `{id, text}`
    /// objects; the scan continues with no advisories.
    pub fn explain_invalid(message: &str) -> Self {
        Self {
            code: "explain-invalid",
            path: String::new(),
            rule: String::new(),
            message: sanitize(message),
        }
    }
    /// `--explain` was requested but no explainer is configured; the scan
    /// continues without advisory text and the exit code is unchanged.
    pub fn explain_skipped(message: &str) -> Self {
        Self {
            code: "explain-skipped",
            path: String::new(),
            rule: String::new(),
            message: sanitize(message),
        }
    }
    pub fn version_unpinned_skipped(path: &str, line: u64) -> Self {
        Self {
            code: "version-unpinned-skipped",
            path: path.to_string(),
            rule: String::new(),
            message: format!("unpinned at {path}:{line}"),
        }
    }
    pub fn manifest_parse_failed(path: &str, msg: &str) -> Self {
        Self {
            code: "manifest-parse-failed",
            path: path.to_string(),
            rule: String::new(),
            message: sanitize(msg),
        }
    }
    pub fn osv_degraded(msg: &str) -> Self {
        Self {
            code: "osv-degraded",
            path: String::new(),
            rule: String::new(),
            message: sanitize(msg),
        }
    }
    pub fn osv_unavailable(path: &str, msg: &str) -> Self {
        Self {
            code: "osv-unavailable",
            path: path.to_string(),
            rule: String::new(),
            message: sanitize(msg),
        }
    }
    pub fn cache_entry_corrupt(path: &str, msg: &str) -> Self {
        Self {
            code: "cache-entry-corrupt",
            path: path.to_string(),
            rule: String::new(),
            message: sanitize(msg),
        }
    }
    pub fn advisory_invalid(msg: &str) -> Self {
        Self {
            code: "advisory-invalid",
            path: String::new(),
            rule: String::new(),
            message: sanitize(msg),
        }
    }
    /// A cache write failed; the scan continues without the entry.
    pub fn cache_write_failed(msg: &str) -> Self {
        Self {
            code: "cache-write-failed",
            path: String::new(),
            rule: String::new(),
            message: sanitize(msg),
        }
    }
    /// A detail fetch failed so the finding keeps a default severity;
    /// the guess is disclosed by naming the advisory.
    pub fn advisory_severity_fallback(msg: &str) -> Self {
        Self {
            code: "advisory-severity-fallback",
            path: String::new(),
            rule: String::new(),
            message: sanitize(msg),
        }
    }
    /// The page cap was reached with more results pending; output is truncated.
    pub fn osv_truncated(msg: &str) -> Self {
        Self {
            code: "osv-truncated",
            path: String::new(),
            rule: String::new(),
            message: sanitize(msg),
        }
    }
    /// The file budget was exceeded; only the first `kept` files were
    /// scanned and `omitted` files were left out.
    pub fn scan_files_truncated(kept: usize, omitted: usize) -> Self {
        Self {
            code: "scan-files-truncated",
            path: String::new(),
            rule: String::new(),
            message: format!("file budget exceeded: scanned {kept} files, {omitted} files omitted"),
        }
    }
    /// The scanned-content budget was exceeded; leading files fitting within
    /// `kept_bytes` were scanned and `omitted_files` files carrying
    /// `omitted_bytes` bytes were left out.
    pub fn scan_bytes_truncated(kept_bytes: u64, omitted_bytes: u64, omitted_files: usize) -> Self {
        Self {
            code: "scan-bytes-truncated",
            path: String::new(),
            rule: String::new(),
            message: format!(
                "byte budget exceeded: scanned {kept_bytes} bytes, {omitted_bytes} bytes across {omitted_files} files omitted"
            ),
        }
    }
    /// The findings budget was exceeded; only the first `kept` findings
    /// were reported and `omitted` findings were left out.
    pub fn scan_findings_truncated(kept: usize, omitted: usize) -> Self {
        Self {
            code: "scan-findings-truncated",
            path: String::new(),
            rule: String::new(),
            message: format!(
                "finding budget exceeded: reported {kept} findings, {omitted} findings omitted"
            ),
        }
    }
    /// A baseline file could not be read or parsed; the scan continues
    /// with an empty baseline, so a typo never silently passes.
    pub fn baseline_invalid(path: &str, reason: &str) -> Self {
        Self {
            code: "baseline-invalid",
            path: path.to_string(),
            rule: String::new(),
            message: format!(
                "baseline {reason}; fix the file or remove it to silence this warning"
            ),
        }
    }
    /// A baseline entry matches no current finding: worth pruning, never
    /// worth failing the build over.
    pub fn baseline_stale(fingerprint: &str) -> Self {
        Self {
            code: "baseline-stale",
            path: String::new(),
            rule: String::new(),
            message: format!(
                "baseline entry matches no finding: {fingerprint}; remove it to silence this warning"
            ),
        }
    }
    /// `--update-baseline` rewrote the baseline file; reports what it
    /// wrote, since a silent write is indistinguishable from a lost one.
    pub fn baseline_updated(path: &str, count: usize) -> Self {
        Self {
            code: "baseline-updated",
            path: String::new(),
            rule: String::new(),
            message: if count == 1 {
                format!("wrote 1 fingerprint to {path}")
            } else {
                format!("wrote {count} fingerprints to {path}")
            },
        }
    }
}

/// Total scan budgets (S7). The production values were decided in L10, and
/// the reasoning travels with them so a reader never has to guess: a scan
/// that has read a gibibyte of source has outlived any report a human will
/// read; a ten-thousand-finding report is not a report; a hundred thousand
/// files bounds the walk before memory follows; and a thousand queries per
/// request keeps one request small enough that a failure loses little and
/// re-chunking is cheap. Every breach degrades through [`Diagnostic`] and
/// never changes the exit-code contract. Tests construct this struct with
/// tiny limits instead of building hundred-thousand-file trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanBudgets {
    /// Maximum files scanned per run; the rest is left out with one
    /// `scan-files-truncated` diagnostic.
    pub max_files: usize,
    /// Maximum scanned content bytes per run; the rest is left out with one
    /// `scan-bytes-truncated` diagnostic.
    pub max_scanned_bytes: u64,
    /// Maximum findings reported per run; the rest is left out with one
    /// `scan-findings-truncated` diagnostic.
    pub max_findings: usize,
    /// Maximum OSV queries per batch request; more pins are sent as
    /// additional requests, never left out.
    pub max_pins_per_request: usize,
}

impl ScanBudgets {
    /// Production budgets: 100 000 files, 1 GiB of scanned content,
    /// 10 000 findings, 1 000 pins per batch request.
    pub fn production() -> Self {
        Self {
            max_files: 100_000,
            max_scanned_bytes: 1024 * 1024 * 1024,
            max_findings: 10_000,
            max_pins_per_request: 1_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding_with_id(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            engine: "secrets".to_string(),
            rule_id: "SECRET-synthetic-token".to_string(),
            severity: Severity::Medium,
            location: Location {
                path: "token.env".to_string(),
                line: 1,
                column: 1,
                snippet: "[REDACTED]".to_string(),
            },
            message: "synthetic test token".to_string(),
            evidence: "[REDACTED]".to_string(),
        }
    }

    #[test]
    fn baseline_key_drops_the_location_segment() {
        // Same content and rule, different paths and lines: one key, so a
        // rename, a move, or a line shift keeps the finding accepted (L4).
        let digest = "9f".repeat(32);
        let renamed = finding_with_id(&format!(
            "secrets/SECRET-synthetic-token/renamed.env:9:4/{digest}"
        ));
        let original = finding_with_id(&format!(
            "secrets/SECRET-synthetic-token/token.env:1:1/{digest}"
        ));
        assert_eq!(renamed.baseline_key(), original.baseline_key());
        assert_eq!(
            original.baseline_key(),
            format!("secrets/SECRET-synthetic-token/{digest}")
        );
    }

    #[test]
    fn baseline_key_keeps_engine_rule_and_digest() {
        let digest = "ab".repeat(32);
        let base = finding_with_id(&format!(
            "secrets/SECRET-synthetic-token/token.env:1:1/{digest}"
        ));
        // A changed secret (new digest) reports fresh, even at the same path.
        let changed = finding_with_id(&format!(
            "secrets/SECRET-synthetic-token/token.env:1:1/{}",
            "cd".repeat(32)
        ));
        assert_ne!(base.baseline_key(), changed.baseline_key());
        // Same digest under another rule is another key.
        let other_rule = finding_with_id(&format!("secrets/SECRET-other/token.env:1:1/{digest}"));
        assert_ne!(base.baseline_key(), other_rule.baseline_key());
        // Dependency fingerprints project the same way: pin location
        // dropped, advisory and content hash kept.
        let dep = finding_with_id(&format!(
            "dependency/OSV-GHSA-abc/package-lock.json:3:7/{digest}"
        ));
        assert_eq!(
            dep.baseline_key(),
            format!("dependency/OSV-GHSA-abc/{digest}")
        );
    }

    #[test]
    fn baseline_diagnostics_name_their_subject() {
        let invalid = Diagnostic::baseline_invalid("accepted.json", "cannot read: gone");
        assert_eq!(invalid.code, "baseline-invalid");
        assert!(invalid.message.contains("cannot read"), "{invalid:?}");
        let stale = Diagnostic::baseline_stale("secrets/SECRET-x/00");
        assert_eq!(stale.code, "baseline-stale");
        assert!(stale.message.contains("secrets/SECRET-x/00"), "{stale:?}");
        let updated = Diagnostic::baseline_updated("accepted.json", 2);
        assert_eq!(updated.code, "baseline-updated");
        assert!(updated.message.contains('2'), "{updated:?}");
    }
}
