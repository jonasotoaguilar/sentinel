//! Pure deterministic rendering: findings → stdout bytes, diagnostics →
//! stderr bytes (terminal-rendering spec). No timestamps, ANSI escapes,
//! targets, or thread ids — pure functions of the scan result.
//!
//! `json` (PR1) and `sarif` (PR2) are pure sub-renderers at the same
//! boundary; terminal rendering below stays byte-identical.
use std::collections::BTreeMap;
use std::io::Write;

use crate::finding::{Diagnostic, Finding};

mod json;
mod sarif;
pub use json::render_json;
pub use sarif::render_sarif;

/// Renders the findings report with one advisory line per finding that has
/// one. Findings without advisory text render exactly as [`render_findings`]
/// does; advisory text is sanitized, single-line, and terminal-exclusive.
pub fn render_findings_with_advisories(
    findings: &[Finding],
    advisories: &BTreeMap<String, String>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for finding in findings {
        let _ = writeln!(
            out,
            "{}:{}:{}: {} {}: {}",
            finding.location.path,
            finding.location.line,
            finding.location.column,
            finding.severity,
            finding.rule_id,
            finding.message
        );
        let _ = writeln!(out, "  {}", finding.location.snippet);
        let _ = writeln!(out, "  evidence: {}", finding.evidence);
        if let Some(text) = advisories.get(&finding.id) {
            let _ = writeln!(out, "  advice: {}", crate::explain::sanitize_advisory(text));
        }
    }
    out
}

/// Renders the findings report; the only content ever written to stdout.
pub fn render_findings(findings: &[Finding]) -> Vec<u8> {
    render_findings_with_advisories(findings, &BTreeMap::new())
}

/// Renders diagnostics to stderr, sorted by `(code, path, rule)`.
pub fn render_diagnostics(diagnostics: &[Diagnostic]) -> Vec<u8> {
    let mut sorted: Vec<&Diagnostic> = diagnostics.iter().collect();
    sorted.sort();
    let mut out = Vec::new();
    for diagnostic in sorted {
        let mut parts = vec![format!("sentinel: {}", diagnostic.code)];
        if !diagnostic.path.is_empty() {
            parts.push(diagnostic.path.clone());
        }
        if !diagnostic.rule.is_empty() {
            parts.push(format!("rule {}", diagnostic.rule));
        }
        parts.push(diagnostic.message.clone());
        let _ = writeln!(out, "{}", parts.join(": "));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Location, Severity};

    fn finding(path: &str, line: u64) -> Finding {
        Finding {
            id: format!("secrets/SECRET-aws-access-key/{path}:{line}:1/digest"),
            engine: "secrets".to_string(),
            rule_id: "SECRET-aws-access-key".to_string(),
            severity: Severity::Critical,
            location: Location {
                path: path.to_string(),
                line,
                column: 1,
                snippet: "[REDACTED]".to_string(),
            },
            message: "AWS access key ID detected".to_string(),
            evidence: "[REDACTED]".to_string(),
        }
    }

    fn diagnostic(code: &'static str, path: &str, rule: &str, message: &str) -> Diagnostic {
        Diagnostic {
            code,
            path: path.to_string(),
            rule: rule.to_string(),
            message: message.to_string(),
        }
    }

    #[test]
    fn findings_render_deterministically_without_ansi_or_timestamps() {
        let text = String::from_utf8(render_findings(&[finding("env.example", 2)])).unwrap();
        assert!(text.contains(
            "env.example:2:1: critical SECRET-aws-access-key: AWS access key ID detected"
        ));
        assert!(text.contains("  [REDACTED]") && text.contains("  evidence: [REDACTED]"));
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn advisories_append_one_sanitized_line_per_finding() {
        use std::collections::BTreeMap;
        let findings = vec![finding("env.example", 2)];
        let plain = render_findings(&findings);
        assert_eq!(
            render_findings_with_advisories(&findings, &BTreeMap::new()),
            plain
        );
        let advisories = BTreeMap::from([
            (findings[0].id.clone(), "ok advice".to_string()),
            ("ghost".to_string(), "ignored".to_string()),
        ]);
        let text =
            String::from_utf8(render_findings_with_advisories(&findings, &advisories)).unwrap();
        assert!(text.starts_with(&String::from_utf8(plain).unwrap()));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "exactly one advisory line: {text:?}");
        assert_eq!(lines[3], "  advice: ok advice");
    }

    #[test]
    fn diagnostics_render_sorted_by_code_path_rule() {
        let diagnostics = vec![
            diagnostic("read-failed", "z.txt", "", "first"),
            diagnostic("read-failed", "a.txt", "", "second"),
            diagnostic("rule-failed", "", "SECRET-b", "third"),
            diagnostic("rule-failed", "", "SECRET-a", "fourth"),
        ];
        let text = String::from_utf8(render_diagnostics(&diagnostics)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("read-failed") && lines[0].contains("a.txt"));
        assert!(lines[1].contains("read-failed") && lines[1].contains("z.txt"));
        assert!(lines[2].contains("rule-failed") && lines[2].contains("rule SECRET-a"));
        assert!(lines[3].contains("rule-failed") && lines[3].contains("rule SECRET-b"));
    }
}
