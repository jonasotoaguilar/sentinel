//! The canonical finding and diagnostic model (finding-normalization spec):
//! engines emit raw detections; normalization collapses them into [`Finding`]
//! values with stable fingerprints; [`Diagnostic`] models stderr warnings.

/// Severity assigned by a rule (ARCHITECTURE findings model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)] // Low is reserved for future rules.
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
pub(crate) fn sanitize(m: &str) -> String {
    m.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(200)
        .collect()
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
}
