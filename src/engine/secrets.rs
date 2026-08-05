//! Regex secrets engine — a static curated rule table over file bytes with
//! redaction at the engine boundary (secrets-detection spec; ADR-0003).
//! Rules are `regex::bytes` patterns with stable ids `SECRET-<KEBAB-NAME>`;
//! renamed rules stay resolvable via `deprecated_ids`; candidates carry only
//! redacted text plus a fixed BLAKE3 digest — raw values never cross it.

use regex::bytes::Regex;

use crate::finding::{Diagnostic, Severity};

/// Placeholder substituted for every matched secret in snippets and evidence.
pub const REDACTION_PLACEHOLDER: &str = "[REDACTED]";

/// Static rule definition; `deprecated_ids` keeps a renamed rule's old id
/// resolvable to the same rule.
#[derive(Clone, Copy)]
pub struct RuleSpec {
    pub id: &'static str,
    pub deprecated_ids: &'static [&'static str],
    pub severity: Severity,
    pub message: &'static str,
    pub pattern: &'static str,
}

/// The curated production table (single-line patterns by construction); the
/// synthetic-token rule exercises the redaction boundary with a
/// non-credential value (spec fixtures).
pub(crate) const RULE_SPECS: &[RuleSpec] = &[
    RuleSpec {
        id: "SECRET-aws-access-key",
        deprecated_ids: &["SECRET-aws-key-id"],
        severity: Severity::Critical,
        message: "AWS access key ID detected",
        pattern: r"\bAKIA[0-9A-Z]{16}\b",
    },
    RuleSpec {
        id: "SECRET-synthetic-token",
        deprecated_ids: &[],
        severity: Severity::Medium,
        message: "synthetic secret token detected",
        pattern: r"\bsk-synthetic-[0-9]{10}\b",
    },
];

/// A compiled rule.
pub struct Rule {
    pub id: &'static str,
    /// Read only by `resolve`; unused by the pipeline (tests-only surface).
    #[allow(dead_code)]
    pub deprecated_ids: &'static [&'static str],
    pub severity: Severity,
    pub message: &'static str,
    regex: Regex,
}

/// A redacted detection; the digest is the only representation of matched
/// content leaving the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    /// 1-based line, then 1-based byte column of the match.
    pub line: u64,
    pub column: u64,
    /// The matched line, CR normalized to LF, every occurrence of the
    /// matched bytes replaced by the placeholder.
    pub snippet: String,
    /// The redaction placeholder.
    pub evidence: String,
    /// BLAKE3 hex over the length-prefixed canonical matched bytes.
    pub digest: String,
}

/// The secrets engine over a compiled rule table.
pub struct SecretsEngine {
    rules: Vec<Rule>,
    init_diagnostics: Vec<Diagnostic>,
}

impl SecretsEngine {
    /// The engine over the curated production table.
    #[allow(clippy::new_without_default)] // `Default` would hide the table choice.
    pub fn new() -> Self {
        Self::from_specs(RULE_SPECS)
    }

    /// Builds an engine from explicit specs; a spec whose pattern fails to
    /// compile becomes a `rule-failed` diagnostic and the rule is skipped —
    /// the remaining rules still fire (failure containment).
    pub fn from_specs(specs: &[RuleSpec]) -> Self {
        let mut rules = Vec::new();
        let mut init_diagnostics = Vec::new();
        for spec in specs {
            match Regex::new(spec.pattern) {
                Ok(regex) => rules.push(Rule {
                    id: spec.id,
                    deprecated_ids: spec.deprecated_ids,
                    severity: spec.severity,
                    message: spec.message,
                    regex,
                }),
                Err(error) => {
                    init_diagnostics.push(Diagnostic::rule_failed(spec.id, error.to_string()))
                }
            }
        }
        Self {
            rules,
            init_diagnostics,
        }
    }

    /// Rule failures found at construction, warned once per scan.
    pub fn init_diagnostics(&self) -> &[Diagnostic] {
        &self.init_diagnostics
    }

    /// Resolves a rule id or a deprecated alias to its rule.
    #[allow(dead_code)] // Query surface for the renamed-rule scenario; tests.
    pub fn resolve(&self, id: &str) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|rule| rule.id == id || rule.deprecated_ids.contains(&id))
    }

    /// Scans bytes with every rule; candidates carry only redacted text and
    /// the fixed pre-redaction digest.
    pub fn scan(&self, bytes: &[u8]) -> Vec<Candidate> {
        let mut candidates = Vec::new();
        for rule in &self.rules {
            for matched in rule.regex.find_iter(bytes) {
                candidates.push(candidate(rule, bytes, matched));
            }
        }
        candidates
    }
}

/// BLAKE3 hex over the length-prefixed canonical matched bytes (u64 LE
/// length prefix fixes the encoding), computed before redaction.
fn digest_of(matched: &[u8]) -> String {
    let mut input = Vec::with_capacity(8 + matched.len());
    input.extend_from_slice(&(matched.len() as u64).to_le_bytes());
    input.extend_from_slice(matched);
    blake3::hash(&input).to_hex().to_string()
}

fn candidate(rule: &Rule, bytes: &[u8], matched: regex::bytes::Match) -> Candidate {
    let (line, column) = locate(bytes, matched.start());
    Candidate {
        rule_id: rule.id.to_string(),
        severity: rule.severity,
        message: rule.message.to_string(),
        line,
        column,
        snippet: redact_line(bytes, matched),
        evidence: REDACTION_PLACEHOLDER.to_string(),
        digest: digest_of(&bytes[matched.start()..matched.end()]),
    }
}

/// 1-based (line, byte column) of an offset within the input.
fn locate(bytes: &[u8], offset: usize) -> (u64, u64) {
    let line_start = bytes[..offset]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |index| index + 1);
    let line = 1 + bytes[..offset]
        .iter()
        .filter(|&&byte| byte == b'\n')
        .count() as u64;
    (line, (offset - line_start + 1) as u64)
}

/// The line containing the match, CR normalized to LF, with every occurrence
/// of the matched bytes replaced by the placeholder.
fn redact_line(bytes: &[u8], matched: regex::bytes::Match) -> String {
    let line_start = bytes[..matched.start()]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |index| index + 1);
    let line_end = bytes[matched.start()..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(bytes.len(), |index| matched.start() + index);
    let mut line = bytes[line_start..line_end].to_vec();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    let redacted = replace_all(
        &line,
        &bytes[matched.start()..matched.end()],
        REDACTION_PLACEHOLDER.as_bytes(),
    );
    String::from_utf8_lossy(&redacted).into_owned()
}

fn replace_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut rest = haystack;
    while let Some(position) = rest
        .windows(needle.len())
        .position(|window| window == needle)
    {
        out.extend_from_slice(&rest[..position]);
        out.extend_from_slice(replacement);
        rest = &rest[position + needle.len()..];
    }
    out.extend_from_slice(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC: &str = "sk-synthetic-1234567890";

    #[test]
    fn aws_access_key_is_detected_with_stable_id() {
        let found = SecretsEngine::new().scan(b"x\r\naws_key = \"AKIASYNTHETICKEY1234\"\r\n"); // CRLF input
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "SECRET-aws-access-key");
        assert_eq!(
            (found[0].line, found[0].column, found[0].severity),
            (2, 12, Severity::Critical)
        ); // `aws_key = "` is 11 bytes
        assert_eq!(found[0].snippet, "aws_key = \"[REDACTED]\"");
    }

    #[test]
    fn deprecated_alias_resolves_to_the_renamed_rule() {
        let engine = SecretsEngine::new();
        let current = engine.resolve("SECRET-aws-access-key").unwrap();
        assert_eq!(current.id, "SECRET-aws-access-key");
        assert_eq!(engine.resolve("SECRET-aws-key-id").unwrap().id, current.id);
        assert!(engine.resolve("SECRET-unknown").is_none());
    }

    #[test]
    fn raw_value_never_crosses_the_engine_boundary() {
        let line = format!("{SYNTHETIC} and {SYNTHETIC}\n");
        let found = SecretsEngine::new().scan(line.as_bytes());
        // Digest is BLAKE3 over the length-prefixed matched bytes.
        let mut input = (SYNTHETIC.len() as u64).to_le_bytes().to_vec();
        input.extend_from_slice(SYNTHETIC.as_bytes());
        let expected_digest = blake3::hash(&input).to_hex().to_string();
        assert_eq!(found.len(), 2);
        for candidate in &found {
            // All repeats replaced; no field can leak the raw value.
            for field in [
                candidate.rule_id.as_str(),
                &candidate.snippet,
                &candidate.evidence,
                &candidate.digest,
                &candidate.message,
            ] {
                assert!(!field.contains(SYNTHETIC), "raw value leaked via {field:?}");
            }
            assert_eq!(candidate.digest, expected_digest);
            assert_eq!(candidate.snippet, "[REDACTED] and [REDACTED]");
            assert_eq!(candidate.evidence, REDACTION_PLACEHOLDER);
        }
    }
}
