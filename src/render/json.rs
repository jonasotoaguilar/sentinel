//! Versioned JSON report renderer (machine-readable-reporting spec): pure
//! serialization of ordered, redacted findings into compact JSON plus a
//! trailing newline; wire structs are declared in field order (deterministic
//! bytes, no I/O, no timestamps, no maps).

use serde::Serialize;

use crate::finding::{Finding, Severity};

/// The report envelope; field order is the wire order.
#[derive(Serialize)]
struct Report<'a> {
    schema_version: &'static str,
    tool: Tool<'a>,
    findings: Vec<FindingReport<'a>>,
}

#[derive(Serialize)]
struct Tool<'a> {
    name: &'static str,
    version: &'a str,
}

/// A single finding; field order is the wire order, severity lowercase.
#[derive(Serialize)]
struct FindingReport<'a> {
    id: &'a str,
    engine: &'a str,
    rule_id: &'a str,
    #[serde(serialize_with = "serialize_severity")]
    severity: Severity,
    location: LocationReport<'a>,
    message: &'a str,
    evidence: &'a str,
}

#[derive(Serialize)]
struct LocationReport<'a> {
    path: &'a str,
    line: u64,
    column: u64,
    snippet: &'a str,
}

impl<'a> From<&'a Finding> for FindingReport<'a> {
    fn from(finding: &'a Finding) -> Self {
        Self {
            id: &finding.id,
            engine: &finding.engine,
            rule_id: &finding.rule_id,
            severity: finding.severity,
            location: LocationReport {
                path: &finding.location.path,
                line: finding.location.line,
                column: finding.location.column,
                snippet: &finding.location.snippet,
            },
            message: &finding.message,
            evidence: &finding.evidence,
        }
    }
}

fn serialize_severity<S>(severity: &Severity, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let name = match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    };
    serializer.serialize_str(name)
}

/// Renders the JSON report bytes: compact (`serde_json::to_vec`) plus a
/// trailing newline; errors are serialization failures only.
pub fn render_json(findings: &[Finding]) -> Result<Vec<u8>, serde_json::Error> {
    let report = Report {
        schema_version: "1.0.0",
        tool: Tool {
            name: "sentinel",
            version: env!("CARGO_PKG_VERSION"),
        },
        findings: findings.iter().map(FindingReport::from).collect(),
    };
    let mut bytes = serde_json::to_vec(&report)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Location;

    const AWS_KEY: &str = "AKIASYNTHETICKEY1234";
    const TOKEN: &str = "sk-synthetic-1234567890";

    fn finding(path: &str, line: u64, severity: Severity, message: &str) -> Finding {
        Finding {
            id: format!("secrets/SECRET-aws-access-key/{path}:{line}:1/digest"),
            engine: "secrets".into(),
            rule_id: "SECRET-aws-access-key".into(),
            severity,
            location: Location {
                path: path.into(),
                line,
                column: 1,
                snippet: "aws_key = \"[REDACTED]\"".into(),
            },
            message: message.into(),
            evidence: "[REDACTED]".into(),
        }
    }

    #[test]
    fn envelope_wire_order_and_lowercase_severities() {
        let sev = [
            (Severity::Low, "low"),
            (Severity::Medium, "medium"),
            (Severity::High, "high"),
            (Severity::Critical, "critical"),
        ];
        let findings: Vec<Finding> = sev
            .iter()
            .enumerate()
            .map(|(l, (s, _))| finding("a.txt", l as u64, *s, "msg"))
            .collect();
        let bytes = render_json(&findings).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        // `serde_json::Value` re-sorts keys, so assert the wire order on raw bytes.
        let text = String::from_utf8(bytes.clone()).unwrap();
        let pos = |n: &str| text.find(n).unwrap();
        assert!(
            pos("\"schema_version\"") < pos("\"tool\"") && pos("\"tool\"") < pos("\"findings\"")
        );
        assert!(pos("\"id\"") < pos("\"severity\"") && pos("\"severity\"") < pos("\"evidence\""));
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema_version"], "1.0.0");
        assert_eq!(value["tool"]["name"], "sentinel");
        assert_eq!(value["tool"]["version"], env!("CARGO_PKG_VERSION"));
        let got = value["findings"].as_array().unwrap();
        assert_eq!(got.len(), 4);
        for (i, (_, expected)) in sev.iter().enumerate() {
            assert_eq!(got[i]["severity"], *expected);
        }
        // Empty findings render an empty array.
        let empty: serde_json::Value = serde_json::from_slice(&render_json(&[]).unwrap()).unwrap();
        assert_eq!(empty["findings"], serde_json::json!([]));
    }

    #[test]
    fn escaping_keeps_bytes_valid_and_secrets_redacted() {
        let bytes = render_json(&[finding(
            "a.txt",
            1,
            Severity::High,
            "quote \" and newline\n",
        )])
        .unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("quote \\\" and newline\\n"));
        assert!(!text.contains(AWS_KEY) && !text.contains(TOKEN));
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
    }
}
