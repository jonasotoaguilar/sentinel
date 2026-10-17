//! SARIF 2.1.0 report renderer (machine-readable-reporting spec): pure
//! serialization of ordered, redacted findings into compact JSON plus a
//! trailing newline. Rules are a unique, lexicographically sorted rule-ID
//! vector so each result's `ruleIndex` is deterministic; results retain the
//! incoming finding order. No I/O, no timestamps, no maps.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Serialize;

use crate::finding::{Finding, Severity};

/// RFC 3986 path-URI set: ALPHA/DIGIT are never in the set; `- . _ ~` and the
/// path separator `/` pass through; every other byte (space, `#`, `%`,
/// non-ASCII UTF-8, ...) is percent-encoded (design: URI encoding).
const SARIF_URI_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'/');

/// The SARIF log envelope; field order is the wire order.
#[derive(Serialize)]
struct Log<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Run<'a> {
    tool: Tool<'a>,
    results: Vec<SarifResult<'a>>,
    // Absent on a complete scan (bytes unchanged); present with
    // `executionSuccessful: false` plus a notification when degraded, per
    // the SARIF 2.1.0 standard mechanism instead of an invented property.
    #[serde(skip_serializing_if = "Option::is_none")]
    invocations: Option<Vec<Invocation<'a>>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Invocation<'a> {
    execution_successful: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_execution_notifications: Option<Vec<Notification<'a>>>,
}

#[derive(Serialize)]
struct Notification<'a> {
    level: &'static str,
    message: Message<'a>,
}

#[derive(Serialize)]
struct Tool<'a> {
    driver: Driver<'a>,
}

#[derive(Serialize)]
struct Driver<'a> {
    name: &'static str,
    version: &'a str,
    rules: Vec<Rule<'a>>,
}

#[derive(Serialize)]
struct Rule<'a> {
    id: &'a str,
}

/// A standard SARIF suppression: where the acceptance is persisted
/// (`external` = a baseline file, not the source) and its review state.
/// Present only on baseline-accepted results.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Suppression {
    kind: &'static str,
    status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult<'a> {
    rule_id: &'a str,
    rule_index: usize,
    level: &'static str,
    message: Message<'a>,
    locations: Vec<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressions: Option<Vec<Suppression>>,
}

#[derive(Serialize)]
struct Message<'a> {
    text: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: u64,
    start_column: u64,
}

/// Maps a finding severity to a SARIF result `level` (spec: severity table).
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

/// Renders with the incompleteness signal and baseline acceptance:
/// accepted findings (members of `accepted`) carry one external accepted
/// suppression each; the field is absent otherwise, so a scan with no
/// baseline is byte-identical to [`render_sarif_with_status`].
pub fn render_sarif_with_status_and_accepted(
    findings: &[Finding],
    incomplete: bool,
    accepted: &std::collections::BTreeSet<String>,
) -> Result<Vec<u8>, serde_json::Error> {
    render_log(findings, incomplete, accepted)
}

/// Renders the SARIF 2.1.0 log bytes: compact (`serde_json::to_vec`) plus a
/// trailing newline; errors are serialization failures only.
pub fn render_sarif(findings: &[Finding]) -> Result<Vec<u8>, serde_json::Error> {
    render_sarif_with_status(findings, false)
}

/// Renders with the incompleteness signal: no `invocations` when complete
/// (byte-identical to [`render_sarif`]); otherwise one unsuccessful
/// invocation carrying a warning notification.
pub fn render_sarif_with_status(
    findings: &[Finding],
    incomplete: bool,
) -> Result<Vec<u8>, serde_json::Error> {
    render_log(findings, incomplete, &std::collections::BTreeSet::new())
}

/// The single log builder: `accepted` holds baseline-accepted finding keys
/// (see [`crate::finding::Finding::baseline_key`]); an empty set leaves
/// every result without `suppressions`, which is exactly the no-baseline
/// shape, so the older entry points stay byte-identical by construction.
fn render_log(
    findings: &[Finding],
    incomplete: bool,
    accepted: &std::collections::BTreeSet<String>,
) -> Result<Vec<u8>, serde_json::Error> {
    // Unique, lexicographically sorted rule-ID vector; each result's index is
    // its position in this vector via binary search (design).
    let mut rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();

    let rules: Vec<Rule> = rule_ids.iter().map(|&id| Rule { id }).collect();
    let results: Vec<SarifResult> = findings
        .iter()
        .map(|finding| {
            // Every finding's rule id is a member of `rule_ids`, so the search
            // is total by construction.
            let rule_index = rule_ids
                .binary_search(&finding.rule_id.as_str())
                .expect("finding rule id present in sorted rule vector");
            SarifResult {
                rule_id: &finding.rule_id,
                rule_index,
                level: level(finding.severity),
                message: Message {
                    text: &finding.message,
                },
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation {
                            uri: utf8_percent_encode(&finding.location.path, SARIF_URI_SET)
                                .to_string(),
                        },
                        region: Region {
                            start_line: finding.location.line,
                            start_column: finding.location.column,
                        },
                    },
                }],
                suppressions: accepted.contains(&finding.baseline_key()).then(|| {
                    vec![Suppression {
                        kind: "external",
                        status: "accepted",
                    }]
                }),
            }
        })
        .collect();

    let log = Log {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "sentinel",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results,
            invocations: incomplete.then(|| {
                vec![Invocation {
                    execution_successful: false,
                    tool_execution_notifications: Some(vec![Notification {
                        level: "warning",
                        message: Message {
                            text: "scan incomplete: dependency data degraded, results may be missing",
                        },
                    }]),
                }]
            }),
        }],
    };
    let mut bytes = serde_json::to_vec(&log)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Location;

    fn finding(path: &str, line: u64, severity: Severity, rule: &str) -> Finding {
        Finding {
            id: format!("secrets/{rule}/{path}:{line}:1/digest"),
            engine: "secrets".into(),
            rule_id: rule.into(),
            severity,
            location: Location {
                path: path.into(),
                line,
                column: 1,
                snippet: "[REDACTED]".into(),
            },
            message: "synthetic finding".into(),
            evidence: "[REDACTED]".into(),
        }
    }

    fn parse(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap()
    }

    #[test]
    fn envelope_is_210_with_sorted_unique_rules_and_matching_indices() {
        let findings = vec![
            finding("z.txt", 1, Severity::High, "SECRET-zeta"),
            finding("a.txt", 1, Severity::Low, "SECRET-alpha"),
            finding("m.txt", 1, Severity::Medium, "SECRET-alpha"), // duplicate rule
        ];
        let bytes = render_sarif(&findings).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let value = parse(&bytes);
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "sentinel");
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        // Rules are unique and lexicographically sorted.
        let rules = value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "SECRET-alpha");
        assert_eq!(rules[1]["id"], "SECRET-zeta");
        // Results retain incoming order with indices into the sorted vector.
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["ruleId"], "SECRET-zeta");
        assert_eq!(results[0]["ruleIndex"], 1);
        assert_eq!(results[1]["ruleId"], "SECRET-alpha");
        assert_eq!(results[1]["ruleIndex"], 0);
        assert_eq!(results[2]["ruleId"], "SECRET-alpha");
        assert_eq!(results[2]["ruleIndex"], 0);
    }

    #[test]
    fn severity_maps_to_sarif_levels() {
        let sev = [
            (Severity::Low, "note"),
            (Severity::Medium, "warning"),
            (Severity::High, "error"),
            (Severity::Critical, "error"),
        ];
        let findings: Vec<Finding> = sev
            .iter()
            .enumerate()
            .map(|(i, (s, _))| finding("a.txt", i as u64, *s, "SECRET-x"))
            .collect();
        let value = parse(&render_sarif(&findings).unwrap());
        let results = value["runs"][0]["results"].as_array().unwrap();
        for (i, (_, expected)) in sev.iter().enumerate() {
            assert_eq!(results[i]["level"], *expected);
        }
    }

    #[test]
    fn empty_findings_produce_a_valid_empty_log() {
        let value = parse(&render_sarif(&[]).unwrap());
        assert_eq!(value["runs"][0]["results"], serde_json::json!([]));
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"],
            serde_json::json!([])
        );
    }

    #[test]
    fn uris_percent_encode_space_hash_percent_and_non_ascii_but_keep_slashes() {
        let cases = [
            ("dir/name with space.txt", "dir/name%20with%20space.txt"),
            ("hash#file.txt", "hash%23file.txt"),
            ("100%.txt", "100%25.txt"),
            ("café.txt", "caf%C3%A9.txt"),
        ];
        for (path, expected) in cases {
            let value =
                parse(&render_sarif(&[finding(path, 1, Severity::High, "SECRET-x")]).unwrap());
            let uri = value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
                ["artifactLocation"]["uri"]
                .as_str()
                .unwrap();
            assert_eq!(uri, expected, "path {path}");
        }
    }

    #[test]
    fn empty_accepted_set_renders_byte_identical_to_plain() {
        use std::collections::BTreeSet;
        let findings = vec![finding("a.txt", 1, Severity::High, "SECRET-x")];
        assert_eq!(
            render_sarif_with_status_and_accepted(&findings, false, &BTreeSet::new()).unwrap(),
            render_sarif(&findings).unwrap(),
            "no baseline means today's bytes exactly"
        );
        assert_eq!(
            render_sarif_with_status_and_accepted(&findings, true, &BTreeSet::new()).unwrap(),
            render_sarif_with_status(&findings, true).unwrap(),
            "the incompleteness signal is unchanged without a baseline"
        );
    }

    #[test]
    fn accepted_findings_carry_an_external_accepted_suppression() {
        use std::collections::BTreeSet;
        let mut first = finding("a.txt", 1, Severity::High, "SECRET-x");
        first.id = "secrets/SECRET-x/a.txt:1:1/aaaa".to_string();
        let mut second = finding("b.txt", 1, Severity::High, "SECRET-x");
        second.id = "secrets/SECRET-x/b.txt:1:1/bbbb".to_string();
        let findings = vec![first.clone(), second.clone()];
        let accepted = BTreeSet::from([first.baseline_key()]);
        let value =
            parse(&render_sarif_with_status_and_accepted(&findings, false, &accepted).unwrap());
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results[0]["suppressions"],
            serde_json::json!([{"kind": "external", "status": "accepted"}]),
            "accepted finding uses the standard SARIF suppression"
        );
        assert!(
            results[1].get("suppressions").is_none(),
            "unaccepted finding carries no suppression: {}",
            results[1]
        );
    }

    #[test]
    fn accepted_sarif_stays_valid_against_the_pinned_schema() {
        // The suppression is standard SARIF, so the schema the
        // machine-reporting tests pin must still accept the log.
        use std::collections::BTreeSet;
        let mut only = finding("a.txt", 1, Severity::High, "SECRET-x");
        only.id = "secrets/SECRET-x/a.txt:1:1/aaaa".to_string();
        let findings = vec![only.clone()];
        let accepted = BTreeSet::from([only.baseline_key()]);
        let bytes = render_sarif_with_status_and_accepted(&findings, false, &accepted).unwrap();
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/sarif-2.1.0.schema.json"),
            )
            .unwrap(),
        )
        .unwrap();
        jsonschema::draft7::new(&schema)
            .expect("pinned schema must compile")
            .validate(&serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
            .expect("accepted SARIF must stay schema-valid");
    }
}
