//! Pure deterministic rendering: findings → stdout bytes, diagnostics →
//! stderr bytes (terminal-rendering spec). No timestamps, ANSI escapes,
//! targets, or thread ids — pure functions of the scan result.
//!
//! `json` and `sarif` are pure sub-renderers at the same
//! boundary; terminal rendering below stays byte-identical.
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Write;

use crate::engine::secrets::SecretsEngine;
use crate::finding::{Diagnostic, Finding};

mod json;
mod sarif;
pub use json::{render_json, render_json_with_status_and_accepted};
pub use sarif::{render_sarif, render_sarif_with_status_and_accepted};

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

/// Renders the terminal report with baseline acceptance: accepted findings
/// (members of `accepted`, keyed by [`crate::finding::Finding::baseline_key`])
/// carry a trailing `[accepted]` marker on their header line. Findings
/// without advisory text or acceptance render exactly as [`render_findings`]
/// does, so a scan with no baseline is byte-identical by construction.
pub fn render_terminal(
    findings: &[Finding],
    advisories: &BTreeMap<String, String>,
    accepted: &BTreeSet<String>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for finding in findings {
        // Accepted findings stay in the report: the header carries the
        // marker, so acceptance is visible in every diff of the output.
        let marker = if accepted.contains(&finding.baseline_key()) {
            " [accepted]"
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "{}:{}:{}: {} {}: {}{}",
            finding.location.path,
            finding.location.line,
            finding.location.column,
            finding.severity,
            finding.rule_id,
            finding.message,
            marker
        );
        let _ = writeln!(out, "  {}", finding.location.snippet);
        let _ = writeln!(out, "  evidence: {}", finding.evidence);
        if let Some(text) = advisories.get(&finding.id) {
            let _ = writeln!(out, "  advice: {}", crate::explain::sanitize_advisory(text));
        }
    }
    out
}

/// Renders diagnostics to stderr, sorted by `(code, path, rule)`. The path
/// and the message are redacted with the production secret table on the way
/// out: diagnostics are the only stderr exit and every producer (discovery,
/// reading, scanning, dependency review, cache, explain) flows through here,
/// so one render point covers producers present and future. Some messages
/// embed the path (`version-unpinned-skipped`), which is why the message is
/// redacted too; codes and rule ids are stable identifiers and stay exact.
/// In-memory diagnostics keep the real path: nothing else reads them.
pub fn render_diagnostics(diagnostics: &[Diagnostic]) -> Vec<u8> {
    let mut sorted: Vec<&Diagnostic> = diagnostics.iter().collect();
    sorted.sort();
    let mut out = Vec::new();
    for diagnostic in sorted {
        let mut parts = vec![format!("sentinel: {}", diagnostic.code)];
        if !diagnostic.path.is_empty() {
            parts.push(SecretsEngine::redact_production(&diagnostic.path));
        }
        if !diagnostic.rule.is_empty() {
            parts.push(format!("rule {}", diagnostic.rule));
        }
        parts.push(SecretsEngine::redact_production(&diagnostic.message));
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

    #[test]
    fn empty_accepted_set_renders_byte_identical_to_plain() {
        use std::collections::BTreeSet;
        let findings = vec![finding("env.example", 2)];
        assert_eq!(
            render_terminal(&findings, &BTreeMap::new(), &BTreeSet::new()),
            render_findings(&findings),
            "no baseline means today's bytes exactly"
        );
    }

    #[test]
    fn accepted_findings_carry_an_accepted_marker_but_stay_reported() {
        use std::collections::{BTreeMap, BTreeSet};
        // Distinct digests: different accepted content must not leak the
        // marker onto its neighbour.
        let mut first = finding("keep.env", 1);
        first.id = "secrets/SECRET-aws-access-key/keep.env:1:1/aaaa".to_string();
        let mut second = finding("skip.env", 3);
        second.id = "secrets/SECRET-aws-access-key/skip.env:3:1/bbbb".to_string();
        let findings = vec![first.clone(), second.clone()];
        let accepted = BTreeSet::from([first.baseline_key()]);
        let text =
            String::from_utf8(render_terminal(&findings, &BTreeMap::new(), &accepted)).unwrap();
        let header: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("SECRET-aws-access-key"))
            .collect();
        assert_eq!(header.len(), 2, "both findings still report: {text:?}");
        assert!(
            header[0].ends_with("[accepted]"),
            "accepted finding is marked: {text:?}"
        );
        assert!(
            !header[1].contains("[accepted]"),
            "unaccepted finding stays unmarked: {text:?}"
        );
    }

    #[test]
    fn accepted_markers_compose_with_advisories() {
        use std::collections::{BTreeMap, BTreeSet};
        let findings = vec![finding("env.example", 2)];
        let advisories = BTreeMap::from([(findings[0].id.clone(), "ok".to_string())]);
        let accepted = BTreeSet::from([findings[0].baseline_key()]);
        let text = String::from_utf8(render_terminal(&findings, &advisories, &accepted)).unwrap();
        assert!(text.contains("[accepted]"), "acceptance marker: {text:?}");
        assert!(
            text.contains("  advice: ok"),
            "advisory line intact: {text:?}"
        );
    }
}
