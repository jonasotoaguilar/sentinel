//! Normalization: redacted engine candidates → canonical findings with
//! stable fingerprints and deterministic ordering (finding-normalization
//! spec). Fingerprints use canonical fields only — engine, rule id,
//! normalized location, pre-redaction digest; output order is (fingerprint,
//! path, line), independent of engine execution order.

use std::collections::BTreeMap;

use crate::engine;
use crate::engine::secrets::Candidate;
use crate::finding::{Finding, Location};

/// Converts the redacted candidates of one path into findings; raw values
/// are already gone at the engine boundary; only the digest participates.
pub fn to_findings(path: &str, candidates: Vec<Candidate>) -> Vec<Finding> {
    let path = path.replace('\\', "/");
    candidates
        .into_iter()
        .map(|candidate| Finding {
            id: format!(
                "{}/{}/{path}:{}:{}/{}",
                engine::ENGINE,
                candidate.rule_id,
                candidate.line,
                candidate.column,
                candidate.digest
            ),
            engine: engine::ENGINE.to_string(),
            rule_id: candidate.rule_id,
            severity: candidate.severity,
            location: Location {
                path: path.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: candidate.snippet,
            },
            message: candidate.message,
            evidence: candidate.evidence,
        })
        .collect()
}

/// Deduplicates by fingerprint (one finding per distinct detection) and
/// orders by (fingerprint, path, line), independent of execution order.
pub fn dedupe_and_sort(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_fingerprint: BTreeMap<String, Finding> = BTreeMap::new();
    for finding in findings {
        by_fingerprint.entry(finding.id.clone()).or_insert(finding);
    }
    let mut ordered: Vec<Finding> = by_fingerprint.into_values().collect();
    // The fingerprint embeds (path, line), so id order is the spec order
    // (fingerprint, path, line).
    ordered.sort();
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::secrets::{Candidate, REDACTION_PLACEHOLDER};
    use crate::finding::Severity;

    const RAW: &str = "sk-synthetic-1234567890";

    fn candidate(rule_id: &str, digest: &str) -> Candidate {
        Candidate {
            rule_id: rule_id.to_string(),
            severity: Severity::Medium,
            message: "synthetic secret token detected".to_string(),
            line: 3,
            column: 5,
            snippet: format!("token = {REDACTION_PLACEHOLDER}"),
            evidence: "[REDACTED]".to_string(),
            digest: digest.to_string(),
        }
    }

    #[test]
    fn schema_is_complete_and_paths_are_forward_slashed() {
        let finding = &to_findings(
            r"config\env.example",
            vec![candidate("SECRET-synthetic-token", "abc")],
        )[0];
        assert!(!finding.id.is_empty());
        assert_eq!(finding.engine, "secrets");
        assert_eq!(finding.rule_id, "SECRET-synthetic-token");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.location.path, "config/env.example");
        assert_eq!((finding.location.line, finding.location.column), (3, 5));
        assert_eq!(finding.location.snippet, "token = [REDACTED]");
        assert_eq!(finding.message, "synthetic secret token detected");
        assert_eq!(finding.evidence, "[REDACTED]");
        for field in [
            finding.id.as_str(),
            finding.engine.as_str(),
            finding.rule_id.as_str(),
            &finding.location.path,
            &finding.location.snippet,
            &finding.evidence,
            &finding.message,
        ] {
            assert!(!field.contains(RAW), "raw value leaked via {field:?}");
        }
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let same = to_findings("a.txt", vec![candidate("SECRET-synthetic-token", "d1")]);
        let again = to_findings("a.txt", vec![candidate("SECRET-synthetic-token", "d1")]);
        let other = to_findings("a.txt", vec![candidate("SECRET-synthetic-token", "d2")]);
        assert_eq!(same[0].id, again[0].id);
        assert_ne!(same[0].id, other[0].id);
    }

    #[test]
    fn duplicate_fingerprints_collapse_and_order_is_deterministic() {
        let by_fingerprint = |path: &str, rule: &str, digest: &str| {
            to_findings(path, vec![candidate(rule, digest)])
                .pop()
                .unwrap()
        };
        // Duplicate (a/token/d1 twice) collapses; input order is reversed.
        let found = dedupe_and_sort(vec![
            by_fingerprint("b.txt", "SECRET-synthetic-token", "d1"),
            by_fingerprint("a.txt", "SECRET-synthetic-token", "d1"),
            by_fingerprint("a.txt", "SECRET-synthetic-token", "d1"),
            by_fingerprint("a.txt", "SECRET-aws-access-key", "d2"),
        ]);
        let rule_ids: Vec<&str> = found.iter().map(|f| f.rule_id.as_str()).collect();
        let paths: Vec<&str> = found.iter().map(|f| f.location.path.as_str()).collect();
        assert_eq!(
            rule_ids,
            vec![
                "SECRET-aws-access-key",
                "SECRET-synthetic-token",
                "SECRET-synthetic-token"
            ]
        );
        assert_eq!(paths, vec!["a.txt", "a.txt", "b.txt"]);
    }
}
