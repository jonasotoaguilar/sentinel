//! The canonical finding and diagnostic model (finding-normalization spec):
//! engines emit raw detections; normalization collapses them into [`Finding`]
//! values with stable fingerprints; [`Diagnostic`] models stderr warnings.
//!
//! PR2 creates the model; the secrets engine, normalization, and renderer that
//! consume it land in PR3, so the model is still dead code in this increment.

#![expect(dead_code)]

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
}
