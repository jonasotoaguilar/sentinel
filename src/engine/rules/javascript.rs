//! JavaScript/TypeScript rules for the code-rules engine.
//! Only `RULE-weak-hash` is implemented in this unit; later rules extend
//! this file without touching the generic engine in `super`.

use super::lang::RulesLanguage;
use super::{Hit, RuleDef};
use crate::finding::Severity;

pub(crate) const WEAK_HASH_DEF: RuleDef = RuleDef {
    id: "RULE-weak-hash",
    severity: Severity::Medium,
    message: "weak cryptographic hash (md5 or sha1) detected",
    languages: &[
        RulesLanguage::JavaScript,
        RulesLanguage::TypeScript,
        RulesLanguage::Tsx,
    ],
    matches: match_weak_hash,
};

/// `crypto.createHash(<literal 'md5' or 'sha1'>)`; matching is name-based
/// with no import resolution, so any receiver other than `crypto`, or any
/// non-literal first argument, is ignored.
fn match_weak_hash(source: &[u8], root: tree_sitter::Node) -> Vec<Hit> {
    let mut hits = Vec::new();
    each_call(root, |call| {
        if is_weak_hash_call(source, call) {
            hits.push(Hit {
                start: call.start_byte(),
                end: call.end_byte(),
            });
        }
    });
    hits
}

fn is_weak_hash_call(source: &[u8], call: tree_sitter::Node) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "member_expression" {
        return false;
    }
    let (Some(object), Some(property)) = (
        function.child_by_field_name("object"),
        function.child_by_field_name("property"),
    ) else {
        return false;
    };
    if object.kind() != "identifier" || text_of(source, object) != Some("crypto") {
        return false;
    }
    if property.kind() != "property_identifier" || text_of(source, property) != Some("createHash") {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    if arguments.kind() != "arguments" {
        return false;
    }
    let Some(first) = arguments.named_child(0) else {
        return false;
    };
    let Some(algorithm) = literal_string(source, first) else {
        return false;
    };
    matches!(algorithm.to_ascii_lowercase().as_str(), "md5" | "sha1")
}

/// Visits every `call_expression` in document order with an explicit stack
/// rather than recursion, so hostile nesting cannot overflow the stack.
fn each_call(root: tree_sitter::Node, mut visit: impl FnMut(tree_sitter::Node)) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            visit(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
}

fn text_of<'a>(source: &'a [u8], node: tree_sitter::Node) -> Option<&'a str> {
    node.utf8_text(source).ok()
}

/// Strips one pair of surrounding quotes (single, double, or backtick);
/// anything else is returned unchanged.
fn strip_quotes(text: &str) -> &str {
    let bytes = text.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if first == last && matches!(first, b'\'' | b'"' | b'`') {
            return &text[1..text.len() - 1];
        }
    }
    text
}

/// The compile-time literal text of an argument: a `string` node, or a
/// `template_string` with no interpolation. This literal/non-literal split is
/// what the rule set exists to express, and the dynamic-code rule reuses it.
fn literal_string<'a>(source: &'a [u8], node: tree_sitter::Node) -> Option<&'a str> {
    match node.kind() {
        "string" => text_of(source, node).map(strip_quotes),
        "template_string" if !interpolates(node) => text_of(source, node).map(strip_quotes),
        _ => None,
    }
}

/// Whether a `template_string` interpolates anything (`${...}`).
fn interpolates(node: tree_sitter::Node) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "template_substitution")
}

#[cfg(test)]
mod tests {
    use crate::engine::rules::RulesEngine;
    use crate::finding::Severity;

    #[test]
    fn weak_hash_fires_with_pinned_id_and_severity() {
        let engine = RulesEngine::new();
        assert!(engine.init_diagnostics().is_empty());
        let found = engine.scan("a.js", b"const h = crypto.createHash('md5');");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
        assert_eq!(found[0].severity, Severity::Medium);
    }

    #[test]
    fn weak_hash_fires_for_sha1_and_double_quotes() {
        let found = RulesEngine::new().scan("b.ts", b"crypto.createHash(\"sha1\")");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
        assert_eq!(found[0].severity, Severity::Medium);
    }

    #[test]
    fn weak_hash_ignores_sha256_and_other_receivers() {
        let engine = RulesEngine::new();
        assert!(
            engine
                .scan("a.js", b"crypto.createHash('sha256');")
                .is_empty()
        );
        assert!(engine.scan("a.js", b"other.createHash('md5');").is_empty());
    }

    #[test]
    fn weak_hash_fires_for_a_substitution_free_template_literal() {
        let found = RulesEngine::new().scan("a.js", b"crypto.createHash(`md5`);");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
    }

    #[test]
    fn weak_hash_algorithm_name_is_case_insensitive() {
        let engine = RulesEngine::new();
        assert_eq!(engine.scan("a.js", b"crypto.createHash('MD5');").len(), 1);
        assert_eq!(
            engine.scan("a.js", b"crypto.createHash(\"Sha1\");").len(),
            1
        );
    }

    #[test]
    fn weak_hash_ignores_a_template_literal_with_interpolation() {
        let found = RulesEngine::new().scan("a.js", b"crypto.createHash(`md${5}`);");
        assert!(found.is_empty(), "got {found:?}");
    }
}
